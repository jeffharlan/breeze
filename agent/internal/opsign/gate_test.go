package opsign

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/breeze-rmm/agent/internal/wire"
)

const (
	gateHost       = "acct-pc_02"
	gateApprovalID = "00112233445566778899aabbccddeeff"
	otherPartner   = "ffffffff-0000-4000-8000-00000000000f"
)

// gateClock is the agent's clock in every gate test: a minute after t0, when
// approvals are issued.
var gateClock = t0.Add(time.Minute)

type gateFixture struct {
	t        *testing.T
	ops      operators
	store    *Store
	path     string
	identity Identity
	gate     *Gate
}

// newGateFixture pins a bundle (admin1 and the approver) in the given mode on
// device A, whose hostname is gateHost.
func newGateFixture(t *testing.T, mode Mode) *gateFixture {
	t.Helper()
	return newGateFixtureWithFloor(t, mode, "")
}

// newGateFixtureWithFloor is newGateFixture with the bundle's minAgentVersion set.
func newGateFixtureWithFloor(t *testing.T, mode Mode, floor string) *gateFixture {
	t.Helper()
	ops := newOperators(t)
	path := statePath(t)
	store := OpenStore(path)
	b := bundleOf(partnerID, 1, 1, ops.admin1, ops.approver)
	b.Mode = mode
	b.MinAgentVersion = floor
	id := Identity{DeviceID: deviceA, OrgID: orgID, Hostname: gateHost}
	if applied, err := ApplyBundle(store, signedBy(t, b, ops.admin1), id, t0); err != nil || !applied {
		t.Fatalf("pin: applied=%v err=%v", applied, err)
	}
	f := &gateFixture{t: t, ops: ops, store: store, path: path, identity: id}
	f.gate = &Gate{Store: store, Identity: func() (Identity, error) { return f.identity, nil }}
	return f
}

// approval is an action approval for payload on device A, valid for an hour
// from t0 and signed by (the key id of) the approver. Tests change fields
// before signing it.
func (f *gateFixture) approval(commandType string, payload map[string]any) ActionApproval {
	f.t.Helper()
	hash, err := PayloadHash(commandType, payload)
	if err != nil {
		f.t.Fatal(err)
	}
	return ActionApproval{
		ApprovalID: gateApprovalID, PartnerID: partnerID, CommandType: commandType,
		Entries:  []Entry{{DeviceID: deviceA, Hostname: gateHost, PayloadHash: hash}},
		IssuedAt: t0, ExpiresAt: t0.Add(time.Hour), KeyID: f.ops.approver.key.KeyID,
	}
}

func (f *gateFixture) sign(a ActionApproval, k testKey) Carrier {
	f.t.Helper()
	canonical, err := a.CanonicalBytes()
	if err != nil {
		f.t.Fatal(err)
	}
	return Carrier{V: 1, CanonicalB64: b64(canonical), SignatureB64: signRaw(f.t, k.priv, canonical)}
}

// attach returns payload carrying c the way a decoded command does: as the
// generic JSON value, not as a Carrier struct.
func attach(t *testing.T, payload map[string]any, c Carrier) map[string]any {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var carrier any
	if err := json.Unmarshal(data, &carrier); err != nil {
		t.Fatal(err)
	}
	out := maps.Clone(payload)
	out[PayloadKey] = carrier
	return out
}

// signedScript is a script payload with a valid approval attached.
func (f *gateFixture) signedScript() map[string]any {
	f.t.Helper()
	p := scriptPayload()
	return attach(f.t, p, f.sign(f.approval("script", p), f.ops.approver))
}

func (f *gateFixture) check(payload map[string]any) Decision {
	return f.gate.Check("script", payload, gateClock)
}

func wantRefused(t *testing.T, d Decision, code wire.CommandErrorCode) {
	t.Helper()
	if d.Allow || d.Code != code || d.Reason == "" {
		t.Fatalf("decision = %+v, want a refusal with code %s and a reason", d, code)
	}
}

func wantAllowed(t *testing.T, d Decision) {
	t.Helper()
	if !d.Allow || d.Code != "" {
		t.Fatalf("decision = %+v, want a plain allow", d)
	}
}

func TestGateTierCAllowed(t *testing.T) {
	f := newGateFixture(t, ModeEnforce)
	for _, typ := range []string{"list_processes", "file_list"} {
		if TierOf(typ) == TierA {
			t.Fatalf("%s is Tier A; pick another read-only command for this test", typ)
		}
		wantAllowed(t, f.gate.Check(typ, map[string]any{}, gateClock))
	}
	// Tier C is decided before the pin is read, so even a broken pin cannot stop it.
	if err := os.WriteFile(f.path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantAllowed(t, f.gate.Check("list_processes", map[string]any{}, gateClock))
}

func TestGateNoPinAllows(t *testing.T) {
	path := statePath(t)
	g := &Gate{Store: OpenStore(path), Identity: func() (Identity, error) {
		return Identity{DeviceID: deviceA, OrgID: orgID, Hostname: gateHost}, nil
	}}
	wantAllowed(t, g.Check("script", scriptPayload(), gateClock))
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a device without a pin must not get a state file from a command: %v", err)
	}
}

func TestGateUnreadablePinRefusesInAudit(t *testing.T) {
	for _, mode := range []Mode{ModeAudit, ModeEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			f := newGateFixture(t, mode)
			if err := os.WriteFile(f.path, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
			wantRefused(t, f.check(f.signedScript()), wire.ErrCodeOpsignPinUnreadable)
		})
	}
}

// After `trust reset` the pin is gone until the named bundle arrives. A server
// that never sends it must not get an ungated device out of the reset.
func TestGateRefusesWhileTrustResetAwaitsItsBundle(t *testing.T) {
	for _, mode := range []Mode{ModeAudit, ModeEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			f := newGateFixtureWithFloor(t, mode, "v0.70.0")
			pin := mustLoad(t, f.store)
			if err := f.store.ClearPin(pin.Fingerprint); err != nil {
				t.Fatal(err)
			}
			if err := f.store.ResetHighWater(gateClock); err != nil {
				t.Fatal(err)
			}

			for name, d := range map[string]Decision{
				"unsigned script":           f.check(scriptPayload()),
				"signed script":             f.check(f.signedScript()),
				"vendor-signed update":      f.gate.CheckUpdate(UpdateCheck{Version: "v1.0.0", VendorSigned: true, Clock: gateClock}),
				"unapproved deployment one": f.gate.CheckUpdate(UpdateCheck{Version: "v0.0.1", Manifest: []byte(manifestA), Clock: gateClock}),
				"floor check":               f.gate.CheckFloor("v1.0.0"),
			} {
				wantRefused(t, d, wire.ErrCodeOpsignPinUnreadable)
				if !strings.Contains(d.Reason, pin.Fingerprint) {
					t.Errorf("%s: reason %q does not name the awaited fingerprint", name, d.Reason)
				}
			}
			for _, typ := range []string{"cancel_reboot", "list_processes"} {
				if TierOf(typ) == TierA {
					t.Fatalf("%s is Tier A", typ)
				}
				wantAllowed(t, f.gate.Check(typ, map[string]any{}, gateClock))
			}

			// The heartbeat offering the awaited bundle lifts it.
			if applied, err := ApplyBundle(f.store, pin.Bundle, f.identity, t0); err != nil || !applied {
				t.Fatalf("re-pin: applied=%v err=%v", applied, err)
			}
			if d := f.check(scriptPayload()); d.Code != wire.ErrCodeOpsignNoApproval {
				t.Fatalf("after the pin landed: %+v, want the normal no-approval result", d)
			}
			wantAllowed(t, f.gate.CheckFloor("v1.0.0"))
		})
	}
}

func TestGateValidScriptApproval(t *testing.T) {
	for name, key := range map[string]func(*operators) testKey{
		"approver": func(o *operators) testKey { return o.approver },
		"admin":    func(o *operators) testKey { return o.admin1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newGateFixture(t, ModeEnforce)
			k := key(&f.ops)
			p := scriptPayload()
			a := f.approval("script", p)
			a.KeyID = k.key.KeyID
			d := f.check(attach(t, p, f.sign(a, k)))
			wantAllowed(t, d)
			if d.Mode != ModeEnforce {
				t.Errorf("mode = %q", d.Mode)
			}
		})
	}
}

func TestGateEachRefusalCode(t *testing.T) {
	type tamper func(f *gateFixture) map[string]any
	// carrierWith signs a valid approval, lets edit change the carrier, and returns the payload.
	carrierWith := func(edit func(c *Carrier)) tamper {
		return func(f *gateFixture) map[string]any {
			p := scriptPayload()
			c := f.sign(f.approval("script", p), f.ops.approver)
			edit(&c)
			return attach(f.t, p, c)
		}
	}
	approvalWith := func(edit func(a *ActionApproval)) tamper {
		return func(f *gateFixture) map[string]any {
			p := scriptPayload()
			a := f.approval("script", p)
			edit(&a)
			return attach(f.t, p, f.sign(a, f.ops.approver))
		}
	}
	cases := []struct {
		name  string
		code  wire.CommandErrorCode
		build tamper
	}{
		{"no approval", wire.ErrCodeOpsignNoApproval, func(*gateFixture) map[string]any { return scriptPayload() }},
		{"carrier version 2", wire.ErrCodeOpsignMalformed, carrierWith(func(c *Carrier) { c.V = 2 })},
		{"carrier version missing", wire.ErrCodeOpsignMalformed, carrierWith(func(c *Carrier) { c.V = 0 })},
		{"canonical not base64", wire.ErrCodeOpsignMalformed, carrierWith(func(c *Carrier) { c.CanonicalB64 = "!!!" })},
		{"signature not base64", wire.ErrCodeOpsignMalformed, carrierWith(func(c *Carrier) { c.SignatureB64 = "!!!" })},
		{"canonical text is not an envelope", wire.ErrCodeOpsignMalformed, carrierWith(func(c *Carrier) { c.CanonicalB64 = b64([]byte("hello")) })},
		{"carrier is not an object", wire.ErrCodeOpsignMalformed, func(*gateFixture) map[string]any {
			p := scriptPayload()
			p[PayloadKey] = "approved"
			return p
		}},
		{"carrier is null", wire.ErrCodeOpsignMalformed, func(*gateFixture) map[string]any {
			p := scriptPayload()
			p[PayloadKey] = nil
			return p
		}},
		{"issued more than 5 minutes ahead of the clock", wire.ErrCodeOpsignMalformed, approvalWith(func(a *ActionApproval) {
			a.IssuedAt = gateClock.Add(5*time.Minute + time.Second)
			a.ExpiresAt = a.IssuedAt.Add(time.Hour)
		})},
		{"rule envelope", wire.ErrCodeOpsignRuleUnsupported, func(f *gateFixture) map[string]any {
			rule := Rule{
				RuleID: gateApprovalID, RuleEpoch: 1, PartnerID: partnerID, ScopeOrgID: orgID,
				CommandType: "script", MatchKind: "payloadHashes", MatchItems: []string{strings.Repeat("a", 64)},
				NotAfter: t0.Add(24 * time.Hour), KeyID: f.ops.approver.key.KeyID,
			}
			canonical, err := rule.CanonicalBytes()
			if err != nil {
				f.t.Fatal(err)
			}
			c := Carrier{V: 1, CanonicalB64: b64(canonical), SignatureB64: signRaw(f.t, f.ops.approver.priv, canonical)}
			return attach(f.t, scriptPayload(), c)
		}},
		{"key not in the bundle", wire.ErrCodeOpsignUnknownKey, func(f *gateFixture) map[string]any {
			p := scriptPayload()
			a := f.approval("script", p)
			a.KeyID = f.ops.outsider.key.KeyID
			return attach(f.t, p, f.sign(a, f.ops.outsider))
		}},
		{"signed by a different key than it names", wire.ErrCodeOpsignBadSignature, func(f *gateFixture) map[string]any {
			p := scriptPayload()
			return attach(f.t, p, f.sign(f.approval("script", p), f.ops.outsider))
		}},
		{"other partner", wire.ErrCodeOpsignWrongTarget, approvalWith(func(a *ActionApproval) { a.PartnerID = otherPartner })},
		{"other command type", wire.ErrCodeOpsignWrongTarget, approvalWith(func(a *ActionApproval) { a.CommandType = "file_write" })},
		{"other device", wire.ErrCodeOpsignWrongTarget, approvalWith(func(a *ActionApproval) { a.Entries[0].DeviceID = deviceB })},
		{"other hostname", wire.ErrCodeOpsignWrongTarget, approvalWith(func(a *ActionApproval) { a.Entries[0].Hostname = "other-pc" })},
		{"payload changed after signing", wire.ErrCodeOpsignPayloadMismatch, func(f *gateFixture) map[string]any {
			p := f.signedScript()
			p["content"] = "rm -rf /"
			return p
		}},
		{"expires exactly now", wire.ErrCodeOpsignExpired, approvalWith(func(a *ActionApproval) { a.ExpiresAt = gateClock })},
		{"already expired", wire.ErrCodeOpsignExpired, approvalWith(func(a *ActionApproval) { a.ExpiresAt = t0.Add(30 * time.Second) })},
		{"used before", wire.ErrCodeOpsignReplayed, func(f *gateFixture) map[string]any {
			p := f.signedScript()
			wantAllowed(f.t, f.check(p))
			return p
		}},
		{"pin file damaged", wire.ErrCodeOpsignPinUnreadable, func(f *gateFixture) map[string]any {
			p := f.signedScript()
			if err := os.WriteFile(f.path, []byte("{not json"), 0o600); err != nil {
				f.t.Fatal(err)
			}
			return p
		}},
		{"claim cannot be written", wire.ErrCodeOpsignPinUnreadable, func(f *gateFixture) map[string]any {
			p := f.signedScript()
			stubRename(f.t, func(string, string) error { return errors.New("disk full") })
			return p
		}},
		{"identity differs from the pin", wire.ErrCodeOpsignIdentityChanged, func(f *gateFixture) map[string]any {
			p := f.signedScript()
			f.identity.DeviceID = deviceB
			return p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixture(t, ModeEnforce)
			d := f.check(tc.build(f))
			wantRefused(t, d, tc.code)
			// An unreadable pin has no mode to report.
			if tc.code != wire.ErrCodeOpsignPinUnreadable && d.Mode != ModeEnforce {
				t.Errorf("mode = %q, want enforce", d.Mode)
			}
		})
	}
}

func TestGateIssuedAtSkewBoundary(t *testing.T) {
	f := newGateFixture(t, ModeEnforce)
	p := scriptPayload()
	a := f.approval("script", p)
	a.IssuedAt = gateClock.Add(5 * time.Minute)
	a.ExpiresAt = a.IssuedAt.Add(time.Hour)
	wantAllowed(t, f.check(attach(t, p, f.sign(a, f.ops.approver))))
}

func TestGateRefusalDoesNotSpendTheApproval(t *testing.T) {
	f := newGateFixture(t, ModeEnforce)
	good := f.signedScript()
	tampered := maps.Clone(good)
	tampered["content"] = "rm -rf /"
	wantRefused(t, f.check(tampered), wire.ErrCodeOpsignPayloadMismatch)
	wantAllowed(t, f.check(good))
	wantRefused(t, f.check(good), wire.ErrCodeOpsignReplayed)
}

func TestGateEarlyRefusalLeavesTheStateFileAlone(t *testing.T) {
	f := newGateFixture(t, ModeEnforce)
	before := fileBytes(t, f.path)
	wantRefused(t, f.check(scriptPayload()), wire.ErrCodeOpsignNoApproval)
	if after := fileBytes(t, f.path); string(after) != string(before) {
		t.Fatal("a command with no approval changed the state file")
	}
}

func TestGateHostnameCaseInsensitive(t *testing.T) {
	old := osHostname
	osHostname = func() (string, error) { return "ACCT-PC_02", nil }
	t.Cleanup(func() { osHostname = old })

	f := newGateFixture(t, ModeEnforce)
	f.gate.Identity = func() (Identity, error) { return LocalIdentity(deviceA, orgID) }
	wantAllowed(t, f.check(f.signedScript()))
}

func TestGateHostnameOutsideApprovalCharsetNeverMatches(t *testing.T) {
	for _, host := range []string{"jeff's mac.local", "pc\x00", ""} {
		f := newGateFixture(t, ModeEnforce)
		p := f.signedScript()
		f.identity.Hostname = host
		wantRefused(t, f.check(p), wire.ErrCodeOpsignWrongTarget)
	}
}

func TestGateIdentityDrift(t *testing.T) {
	cases := map[string]func(*Identity){
		"device": func(id *Identity) { id.DeviceID = deviceB },
		"org":    func(id *Identity) { id.OrgID = "99999999-2222-4333-8444-555555555555" },
	}
	for name, drift := range cases {
		t.Run(name, func(t *testing.T) {
			f := newGateFixture(t, ModeEnforce)
			p := f.signedScript()
			drift(&f.identity)
			wantRefused(t, f.check(p), wire.ErrCodeOpsignIdentityChanged)
		})
	}
	t.Run("identity unavailable", func(t *testing.T) {
		f := newGateFixture(t, ModeEnforce)
		p := f.signedScript()
		f.gate.Identity = func() (Identity, error) { return Identity{}, errors.New("no hostname") }
		wantRefused(t, f.check(p), wire.ErrCodeOpsignIdentityChanged)
	})
}

func TestGateAuditAllowsButReportsCode(t *testing.T) {
	f := newGateFixture(t, ModeAudit)
	d := f.check(scriptPayload())
	if !d.Allow || d.Code != wire.ErrCodeOpsignNoApproval || d.Mode != ModeAudit || d.Reason == "" {
		t.Fatalf("decision = %+v, want allow with code %s in audit", d, wire.ErrCodeOpsignNoApproval)
	}
	p := f.signedScript()
	tampered := maps.Clone(p)
	tampered["content"] = "changed"
	if d := f.check(tampered); !d.Allow || d.Code != wire.ErrCodeOpsignPayloadMismatch {
		t.Fatalf("tampered payload in audit: %+v", d)
	}
	if d := f.check(p); !d.Allow || d.Code != "" || d.Mode != ModeAudit {
		t.Fatalf("valid approval in audit: %+v", d)
	}
	if d := f.check(p); !d.Allow || d.Code != wire.ErrCodeOpsignReplayed {
		t.Fatalf("replay in audit: %+v", d)
	}
}

func TestGateExpiryUsesHighWater(t *testing.T) {
	f := newGateFixture(t, ModeEnforce)
	p := f.signedScript() // valid from 10:00 to 11:00
	f.store.Now(t0.Add(2 * time.Hour))
	wantRefused(t, f.gate.Check("script", p, t0), wire.ErrCodeOpsignExpired)
}

func TestGateReplayAfterRestart(t *testing.T) {
	f := newGateFixture(t, ModeEnforce)
	p := f.signedScript()
	wantAllowed(t, f.check(p))

	f.gate.Store = restart(f.path)
	wantRefused(t, f.check(p), wire.ErrCodeOpsignReplayed)
}

func TestGateUnknownTypeNeedsApproval(t *testing.T) {
	f := newGateFixture(t, ModeEnforce)
	const typ = "some_future_command"
	if _, known := tiers[typ]; known {
		t.Fatalf("%s is classified", typ)
	}
	wantRefused(t, f.gate.Check(typ, map[string]any{}, gateClock), wire.ErrCodeOpsignNoApproval)

	p := map[string]any{"x": "y"}
	wantAllowed(t, f.gate.Check(typ, attach(t, p, f.sign(f.approval(typ, p), f.ops.approver)), gateClock))
}

func TestGateExcludedScriptFieldsDoNotBreakHash(t *testing.T) {
	f := newGateFixture(t, ModeEnforce)
	signed := scriptPayload()
	a := f.approval("script", signed)
	c := f.sign(a, f.ops.approver)

	delivered := maps.Clone(signed)
	delivered["executionId"] = "e-2"
	delivered["batchId"] = "b-9"
	delivered["restorePoint"] = map[string]any{"requestId": "r-1", "validUntil": "2026-11-19T12:00:00Z"}
	delivered["secretEnv"] = map[string]any{"TOKEN": "x"}
	delivered["secretEnvEnvelope"] = "sealed-2"
	wantAllowed(t, f.check(attach(t, delivered, c)))
}
