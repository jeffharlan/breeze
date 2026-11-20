package opsign

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/breeze-rmm/agent/internal/config"
	"github.com/breeze-rmm/agent/internal/versionpolicy"
	"github.com/breeze-rmm/agent/internal/wire"
)

// maxIssuedAtSkew is how far ahead of the agent's clock an approval may be
// dated. More than this is not clock drift, it is a forged or broken approval.
const maxIssuedAtSkew = 5 * time.Minute

// Decision is the gate's answer for one command. Code is set whenever the
// command did not pass the checks, including in audit mode where Allow stays
// true so the caller can log it. Mode is the pinned bundle's mode; it is empty
// when there is no pin, when the pin could not be read, and while a trust reset
// waits for its bundle.
type Decision struct {
	Allow  bool
	Mode   Mode
	Code   wire.CommandErrorCode
	Reason string
}

// Gate decides whether a command may run, from the pinned trust bundle and the
// operator approval attached to the command.
type Gate struct {
	Store    *Store
	Identity func() (Identity, error)
}

// DefaultGate is the gate for the agent's own pin store and identity. The
// updater and the watchdog use it, so they read the same pin the heartbeat does.
func DefaultGate() *Gate {
	return &Gate{Store: OpenStore(DefaultStorePath()), Identity: func() (Identity, error) {
		cfg, err := config.Load("")
		if err != nil {
			return Identity{}, err
		}
		return LocalIdentity(cfg.DeviceID, cfg.OrgID)
	}}
}

// decide runs check against the pinned bundle, and turns its refusal code (""
// for a pass) into the Decision for the bundle's mode. Nothing pinned allows
// everything; a pin that cannot be trusted refuses in every mode, and so does a
// trust reset still waiting for its bundle. Otherwise the server could keep the
// device unprotected after a reset simply by never sending that bundle.
func (g *Gate) decide(check func(*Pin, Bundle) (wire.CommandErrorCode, string)) Decision {
	pin, awaiting, err := g.Store.LoadTrust()
	if err != nil {
		return Decision{Code: wire.ErrCodeOpsignPinUnreadable, Reason: err.Error()}
	}
	if pin == nil && awaiting != "" {
		return Decision{Code: wire.ErrCodeOpsignPinUnreadable, Reason: fmt.Sprintf(
			"trust reset is waiting for the operator trust bundle with fingerprint %s; nothing that needs operator approval runs until it is pinned", awaiting)}
	}
	if pin == nil {
		return Decision{Allow: true}
	}
	canonical, err := decodeB64(pin.Bundle.CanonicalB64)
	var bundle Bundle
	if err == nil {
		bundle, err = ParseBundle(canonical)
	}
	if err != nil {
		return Decision{Code: wire.ErrCodeOpsignPinUnreadable, Reason: err.Error()}
	}
	code, reason := check(pin, bundle)
	if code == "" {
		return Decision{Allow: true, Mode: bundle.Mode}
	}
	return Decision{Allow: bundle.Mode == ModeAudit, Mode: bundle.Mode, Code: code, Reason: reason}
}

// Check applies spec section 6. The state file is written (high-water time, the
// used-approval list) only once an approval has passed its signature and issue
// time checks, so a command without one never touches it.
func (g *Gate) Check(commandType string, payload map[string]any, clock time.Time) Decision {
	if TierOf(commandType) != TierA {
		return Decision{Allow: true}
	}
	return g.decide(func(pin *Pin, bundle Bundle) (wire.CommandErrorCode, string) {
		return g.verify(pin, bundle, commandType, payload, clock)
	})
}

// UpdateCheck describes an agent, helper or watchdog install the updater is
// about to make. Manifest is the manifest text whose signature the updater
// just verified, byte for byte. Approval is the operator approval the download
// response carried, if any.
type UpdateCheck struct {
	Version      string
	Manifest     []byte
	VendorSigned bool
	Approval     *Carrier
	Clock        time.Time
}

// agentUpdateType is the command type of an approval for a deployment-signed
// update; its payload hash is AgentUpdatePayloadHash of the manifest.
const agentUpdateType = "agent_update"

// CheckUpdate applies spec section 4. Nothing installs below the pinned
// bundle's minAgentVersion, whoever signed it. An update signed only by a
// deployment key also needs an agent_update approval of its manifest for this
// device. That approval is not spent: one release takes several downloads, and
// a failed download must be retryable without asking the operator again.
func (g *Gate) CheckUpdate(u UpdateCheck) Decision {
	return g.decide(func(pin *Pin, bundle Bundle) (wire.CommandErrorCode, string) {
		if code, reason := belowFloor(bundle, u.Version); code != "" {
			return code, reason
		}
		if u.VendorSigned {
			return "", ""
		}
		if u.Approval == nil {
			return wire.ErrCodeOpsignUpdateUnapproved, "this update is signed by a deployment key and carries no operator approval"
		}
		id, ok := g.identity(pin)
		if !ok {
			return wire.ErrCodeOpsignIdentityChanged, identityChangedReason
		}
		return g.verifyApproval(pin, bundle, id, *u.Approval, agentUpdateType, func() (string, error) { return AgentUpdatePayloadHash(u.Manifest), nil }, u.Clock, false)
	})
}

// CheckFloor is the version-floor part of CheckUpdate alone, for a caller that
// knows the target version before it has the manifest to check.
func (g *Gate) CheckFloor(version string) Decision {
	return g.decide(func(_ *Pin, bundle Bundle) (wire.CommandErrorCode, string) { return belowFloor(bundle, version) })
}

// belowFloor judges version against the bundle's floor like a downgrade: a
// version below it is refused, and one that is not a version at all cannot be
// shown to be above it. A bundle with no floor allows everything.
func belowFloor(bundle Bundle, version string) (wire.CommandErrorCode, string) {
	if bundle.MinAgentVersion != "" && !versionpolicy.Decide(version, bundle.MinAgentVersion, versionpolicy.InstalledComponentCurrent).Allowed {
		return wire.ErrCodeOpsignBelowFloor, "this version is older than the minimum agent version the trust bundle sets"
	}
	return "", ""
}

const identityChangedReason = "this device is not the one its operator trust bundle was pinned under"

// identity returns the live identity, and whether it is the one the bundle was
// pinned under.
func (g *Gate) identity(pin *Pin) (Identity, bool) {
	id, err := g.Identity()
	return id, err == nil && id.DeviceID == pin.DeviceID && id.OrgID == pin.OrgID
}

// verify returns the refusal code and a reason, or "" when the command carries
// a valid, unused approval (which it then marks as used).
func (g *Gate) verify(pin *Pin, bundle Bundle, commandType string, payload map[string]any, clock time.Time) (wire.CommandErrorCode, string) {
	id, ok := g.identity(pin)
	if !ok {
		return wire.ErrCodeOpsignIdentityChanged, identityChangedReason
	}
	raw, ok := payload[PayloadKey]
	if !ok {
		return wire.ErrCodeOpsignNoApproval, "this command needs an operator approval and carries none"
	}
	var c Carrier
	data, err := json.Marshal(raw)
	if err == nil {
		err = json.Unmarshal(data, &c)
	}
	if err != nil {
		c = Carrier{} // verifyApproval refuses a zero carrier as malformed
	}
	return g.verifyApproval(pin, bundle, id, c, commandType, func() (string, error) { return PayloadHash(commandType, payload) }, clock, true)
}

// verifyApproval checks c as an approval of commandType for this device, and
// marks it used when singleUse. approvedHash returns the hash the approval's
// entry for this device must carry; it runs only once the approval names this
// device.
func (g *Gate) verifyApproval(pin *Pin, bundle Bundle, id Identity, c Carrier, commandType string, approvedHash func() (string, error), clock time.Time, singleUse bool) (wire.CommandErrorCode, string) {
	if c.V != 1 {
		return wire.ErrCodeOpsignMalformed, "the operator approval is not a version 1 approval"
	}
	canonical, err := decodeB64(c.CanonicalB64)
	if err == nil {
		_, err = decodeB64(c.SignatureB64)
	}
	if err != nil {
		return wire.ErrCodeOpsignMalformed, err.Error()
	}
	envelope, err := ParseEnvelope(canonical)
	if err != nil {
		return wire.ErrCodeOpsignMalformed, err.Error()
	}
	approval, ok := envelope.(ActionApproval) // the only other kind is a Rule
	if !ok {
		return wire.ErrCodeOpsignRuleUnsupported, "standing-rule approvals are not accepted by this agent"
	}

	i := slices.IndexFunc(bundle.Keys, func(k BundleKey) bool { return k.KeyID == approval.KeyID })
	if i < 0 {
		return wire.ErrCodeOpsignUnknownKey, "the approval was signed by a key that is not in the pinned trust bundle"
	}
	if VerifyES256(bundle.Keys[i].SPKIB64, canonical, c.SignatureB64) != nil {
		return wire.ErrCodeOpsignBadSignature, "the approval's signature does not verify"
	}

	// The device's own hostname, not the pinned one: a rename must void approvals
	// made for the old name.
	e := slices.IndexFunc(approval.Entries, func(e Entry) bool { return e.DeviceID == pin.DeviceID && e.Hostname == id.Hostname })
	if approval.PartnerID != pin.PartnerID || approval.CommandType != commandType || e < 0 {
		return wire.ErrCodeOpsignWrongTarget, "the approval is for another partner, command type or device"
	}
	if hash, err := approvedHash(); err != nil || hash != approval.Entries[e].PayloadHash {
		return wire.ErrCodeOpsignPayloadMismatch, "the command's payload is not the one that was approved"
	}

	if approval.IssuedAt.After(clock.Add(maxIssuedAtSkew)) {
		return wire.ErrCodeOpsignMalformed, "the approval is dated ahead of this device's clock"
	}
	g.Store.ObserveIssuedAt(approval.IssuedAt)
	if !approval.ExpiresAt.After(g.Store.Now(clock)) {
		return wire.ErrCodeOpsignExpired, "the approval has expired"
	}

	if singleUse {
		err = g.Store.ClaimApproval(approval.ApprovalID, approval.ExpiresAt)
	} else {
		err = g.Store.CheckReusable(approval.ExpiresAt)
	}
	switch {
	case err == nil:
		return "", ""
	case errors.Is(err, ErrReplayed):
		return wire.ErrCodeOpsignReplayed, "the approval was already used"
	default:
		return wire.ErrCodeOpsignPinUnreadable, err.Error()
	}
}
