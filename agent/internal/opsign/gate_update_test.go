package opsign

import (
	"os"
	"testing"
	"time"

	"github.com/breeze-rmm/agent/internal/wire"
)

// manifestA is the update manifest checkUpdate offers; manifestB differs from
// it in one file hash.
var (
	manifestA = `{"version":"0.70.0","component":"agent","checksum":"` + hashA + `"}`
	manifestB = `{"version":"0.70.0","component":"agent","checksum":"` + hashB + `"}`
)

// updateApproval is an agent_update approval of manifest on device A, signed
// by the approver. Tests change fields before signing it.
func (f *gateFixture) updateApproval(manifest string) ActionApproval {
	a := f.approval("agent_update", nil)
	a.Entries[0].PayloadHash = AgentUpdatePayloadHash([]byte(manifest))
	return a
}

func (f *gateFixture) checkUpdate(version string, vendorSigned bool, approval *Carrier) Decision {
	return f.gate.CheckUpdate(UpdateCheck{
		Version: version, Manifest: []byte(manifestA), VendorSigned: vendorSigned, Approval: approval, Clock: gateClock,
	})
}

func TestCheckUpdateFloor(t *testing.T) {
	cases := []struct {
		version string
		refused bool
	}{
		{"v0.69.9", true},
		{"0.69.9", true},
		{"0.70.0-rc1", true},
		{"0.70.0", false},
		{"v0.70.0", false},
		{"1.0.0", false},
		{"garbage", true},
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			f := newGateFixtureWithFloor(t, ModeEnforce, "v0.70.0")
			// Vendor-signed, so only the floor decides.
			d := f.checkUpdate(tc.version, true, nil)
			if tc.refused {
				wantRefused(t, d, wire.ErrCodeOpsignBelowFloor)
			} else {
				wantAllowed(t, d)
			}
		})
	}
}

func TestCheckFloor(t *testing.T) {
	f := newGateFixtureWithFloor(t, ModeEnforce, "v0.70.0")
	wantRefused(t, f.gate.CheckFloor("0.69.9"), wire.ErrCodeOpsignBelowFloor)
	wantRefused(t, f.gate.CheckFloor("garbage"), wire.ErrCodeOpsignBelowFloor)
	wantAllowed(t, f.gate.CheckFloor("0.70.0"))

	audit := newGateFixtureWithFloor(t, ModeAudit, "v0.70.0")
	if d := audit.gate.CheckFloor("0.69.9"); !d.Allow || d.Code != wire.ErrCodeOpsignBelowFloor {
		t.Errorf("audit decision = %+v, want an allow that reports the floor", d)
	}

	g := &Gate{Store: OpenStore(statePath(t))}
	wantAllowed(t, g.CheckFloor("0.0.1"))
}

func TestCheckUpdateFloorAppliesToApprovedDeploymentUpdates(t *testing.T) {
	f := newGateFixtureWithFloor(t, ModeEnforce, "v0.70.0")
	c := f.sign(f.updateApproval(manifestA), f.ops.approver)
	wantRefused(t, f.checkUpdate("0.69.9", false, &c), wire.ErrCodeOpsignBelowFloor)
}

func TestCheckUpdateEmptyFloorMeansNoFloor(t *testing.T) {
	f := newGateFixture(t, ModeEnforce)
	wantAllowed(t, f.checkUpdate("0.0.1", true, nil))
}

func TestCheckUpdateDeploymentKeyNeedsApproval(t *testing.T) {
	cases := []struct {
		name  string
		code  wire.CommandErrorCode
		build func(f *gateFixture) *Carrier
	}{
		{"no approval", wire.ErrCodeOpsignUpdateUnapproved, func(*gateFixture) *Carrier { return nil }},
		{"approval of another manifest", wire.ErrCodeOpsignPayloadMismatch, func(f *gateFixture) *Carrier {
			c := f.sign(f.updateApproval(manifestB), f.ops.approver)
			return &c
		}},
		// The meaning before #12257's review: it left the rest of the manifest,
		// such as a Mac's .pkg hash, unapproved.
		{"approval of the file hash the manifest lists", wire.ErrCodeOpsignPayloadMismatch, func(f *gateFixture) *Carrier {
			a := f.updateApproval(manifestA)
			a.Entries[0].PayloadHash = hashA
			c := f.sign(a, f.ops.approver)
			return &c
		}},
		{"approval for another command type", wire.ErrCodeOpsignWrongTarget, func(f *gateFixture) *Carrier {
			c := f.sign(f.approval("script", scriptPayload()), f.ops.approver)
			return &c
		}},
		{"approval for another device", wire.ErrCodeOpsignWrongTarget, func(f *gateFixture) *Carrier {
			a := f.updateApproval(manifestA)
			a.Entries[0].DeviceID = deviceB
			c := f.sign(a, f.ops.approver)
			return &c
		}},
		{"signature from another key", wire.ErrCodeOpsignBadSignature, func(f *gateFixture) *Carrier {
			c := f.sign(f.updateApproval(manifestA), f.ops.outsider)
			return &c
		}},
		{"expired", wire.ErrCodeOpsignExpired, func(f *gateFixture) *Carrier {
			a := f.updateApproval(manifestA)
			a.ExpiresAt = t0.Add(30 * time.Second)
			c := f.sign(a, f.ops.approver)
			return &c
		}},
		{"expiring at or before the prune floor", wire.ErrCodeOpsignReplayed, func(f *gateFixture) *Carrier {
			st := fileState(f.t, f.path)
			st.PruneFloor = t0.Add(time.Hour)
			writeState(f.t, f.path, st)
			c := f.sign(f.updateApproval(manifestA), f.ops.approver) // expires t0+1h
			return &c
		}},
		{"identity differs from the pin", wire.ErrCodeOpsignIdentityChanged, func(f *gateFixture) *Carrier {
			c := f.sign(f.updateApproval(manifestA), f.ops.approver)
			f.identity.OrgID = otherPartner
			return &c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixtureWithFloor(t, ModeEnforce, "v0.70.0")
			wantRefused(t, f.checkUpdate("0.70.0", false, tc.build(f)), tc.code)
		})
	}

	t.Run("valid approval", func(t *testing.T) {
		f := newGateFixtureWithFloor(t, ModeEnforce, "v0.70.0")
		c := f.sign(f.updateApproval(manifestA), f.ops.approver)
		d := f.checkUpdate("0.70.0", false, &c)
		wantAllowed(t, d)
		if d.Mode != ModeEnforce {
			t.Errorf("mode = %q", d.Mode)
		}
	})
}

// One release takes several downloads, and a failed download must be retryable,
// so an update approval is not spent. Every other check still applies to each use.
func TestCheckUpdateApprovalCanBeUsedAgain(t *testing.T) {
	f := newGateFixtureWithFloor(t, ModeEnforce, "v0.70.0")
	a := f.updateApproval(manifestA)
	c := f.sign(a, f.ops.approver)
	wantAllowed(t, f.checkUpdate("0.70.0", false, &c))
	wantAllowed(t, f.checkUpdate("0.70.0", false, &c))
	if used := fileState(t, f.path).Approvals; len(used) != 0 {
		t.Errorf("an update approval was recorded as used: %v", used)
	}

	wantRefused(t, f.checkUpdate("0.69.9", false, &c), wire.ErrCodeOpsignBelowFloor)
	f.identity.Hostname = "renamed-pc"
	wantRefused(t, f.checkUpdate("0.70.0", false, &c), wire.ErrCodeOpsignWrongTarget)
	f.identity.Hostname = gateHost
	f.store.Now(a.ExpiresAt)
	wantRefused(t, f.checkUpdate("0.70.0", false, &c), wire.ErrCodeOpsignExpired)
}

func TestCheckUpdateVendorSignedNeedsNoApproval(t *testing.T) {
	f := newGateFixtureWithFloor(t, ModeEnforce, "v0.70.0")
	before := fileBytes(t, f.path)
	wantAllowed(t, f.checkUpdate("0.70.0", true, nil))
	if after := fileBytes(t, f.path); string(after) != string(before) {
		t.Fatal("a vendor-signed update changed the state file")
	}
	// Not even a drifted identity matters: nothing in the check reads an approval.
	f.identity.DeviceID = deviceB
	wantAllowed(t, f.checkUpdate("0.70.0", true, nil))
}

func TestCheckUpdateAuditAllows(t *testing.T) {
	f := newGateFixtureWithFloor(t, ModeAudit, "v0.70.0")
	for name, d := range map[string]struct {
		got  Decision
		code wire.CommandErrorCode
	}{
		"below the floor":    {f.checkUpdate("0.69.9", true, nil), wire.ErrCodeOpsignBelowFloor},
		"no approval":        {f.checkUpdate("0.70.0", false, nil), wire.ErrCodeOpsignUpdateUnapproved},
		"malformed approval": {f.checkUpdate("0.70.0", false, &Carrier{V: 2}), wire.ErrCodeOpsignMalformed},
	} {
		if !d.got.Allow || d.got.Code != d.code || d.got.Reason == "" || d.got.Mode != ModeAudit {
			t.Errorf("%s: decision = %+v, want an allow that reports %s", name, d.got, d.code)
		}
	}
}

func TestCheckUpdateNoPinAllows(t *testing.T) {
	path := statePath(t)
	g := &Gate{Store: OpenStore(path), Identity: func() (Identity, error) {
		t.Error("identity must not be read when nothing is pinned")
		return Identity{}, nil
	}}
	wantAllowed(t, g.CheckUpdate(UpdateCheck{Version: "garbage", Manifest: []byte(manifestA), Clock: gateClock}))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a device without a pin must not get a state file from an update check: %v", err)
	}
}

func TestCheckUpdateUnreadablePinRefusesInEveryMode(t *testing.T) {
	for _, mode := range []Mode{ModeAudit, ModeEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			f := newGateFixture(t, mode)
			if err := os.WriteFile(f.path, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
			wantRefused(t, f.checkUpdate("1.0.0", true, nil), wire.ErrCodeOpsignPinUnreadable)
		})
	}
}
