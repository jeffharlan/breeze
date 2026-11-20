package opsign

import (
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/breeze-rmm/agent/internal/wire"
)

// maxIssuedAtSkew is how far ahead of the agent's clock an approval may be
// dated. More than this is not clock drift, it is a forged or broken approval.
const maxIssuedAtSkew = 5 * time.Minute

// Decision is the gate's answer for one command. Code is set whenever the
// command did not pass the checks, including in audit mode where Allow stays
// true so the caller can log it. Mode is the pinned bundle's mode; it is empty
// when there is no pin, or when the pin could not be read.
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

// Check applies spec section 6. The state file is written (high-water time, the
// used-approval list) only once an approval has passed its signature and issue
// time checks, so a command without one never touches it.
func (g *Gate) Check(commandType string, payload map[string]any, clock time.Time) Decision {
	if TierOf(commandType) != TierA {
		return Decision{Allow: true}
	}
	pin, err := g.Store.Load()
	if err != nil {
		return Decision{Code: wire.ErrCodeOpsignPinUnreadable, Reason: err.Error()}
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
	code, reason := g.verify(pin, bundle, commandType, payload, clock)
	if code == "" {
		return Decision{Allow: true, Mode: bundle.Mode}
	}
	return Decision{Allow: bundle.Mode == ModeAudit, Mode: bundle.Mode, Code: code, Reason: reason}
}

// verify returns the refusal code and a reason, or "" when the command carries
// a valid, unused approval (which it then marks as used).
func (g *Gate) verify(pin *Pin, bundle Bundle, commandType string, payload map[string]any, clock time.Time) (wire.CommandErrorCode, string) {
	id, err := g.Identity()
	if err != nil || id.DeviceID != pin.DeviceID || id.OrgID != pin.OrgID {
		return wire.ErrCodeOpsignIdentityChanged, "this device is not the one its operator trust bundle was pinned under"
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
	if err != nil || c.V != 1 {
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
	if hash, err := PayloadHash(commandType, payload); err != nil || hash != approval.Entries[e].PayloadHash {
		return wire.ErrCodeOpsignPayloadMismatch, "the command's payload is not the one that was approved"
	}

	if approval.IssuedAt.After(clock.Add(maxIssuedAtSkew)) {
		return wire.ErrCodeOpsignMalformed, "the approval is dated ahead of this device's clock"
	}
	g.Store.ObserveIssuedAt(approval.IssuedAt)
	if !approval.ExpiresAt.After(g.Store.Now(clock)) {
		return wire.ErrCodeOpsignExpired, "the approval has expired"
	}

	switch err := g.Store.ClaimApproval(approval.ApprovalID, approval.ExpiresAt); {
	case err == nil:
		return "", ""
	case errors.Is(err, ErrReplayed):
		return wire.ErrCodeOpsignReplayed, "the approval was already used"
	default:
		return wire.ErrCodeOpsignPinUnreadable, err.Error()
	}
}
