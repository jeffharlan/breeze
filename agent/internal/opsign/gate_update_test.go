package opsign

import (
	"os"
	"testing"
	"time"

	"github.com/breeze-rmm/agent/internal/wire"
)

// updateApproval is an agent_update approval for artifactSHA on device A, signed
// by the approver. Tests change fields before signing it.
func (f *gateFixture) updateApproval(artifactSHA string) ActionApproval {
	a := f.approval("agent_update", nil)
	a.Entries[0].PayloadHash = artifactSHA
	return a
}

func (f *gateFixture) checkUpdate(version string, vendorSigned bool, approval *Carrier) Decision {
	return f.gate.CheckUpdate(UpdateCheck{
		Version: version, ArtifactSHA256: hashA, VendorSigned: vendorSigned, Approval: approval, Clock: gateClock,
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
	c := f.sign(f.updateApproval(hashA), f.ops.approver)
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
		{"approval for another artifact", wire.ErrCodeOpsignPayloadMismatch, func(f *gateFixture) *Carrier {
			c := f.sign(f.updateApproval(hashB), f.ops.approver)
			return &c
		}},
		{"approval for another command type", wire.ErrCodeOpsignWrongTarget, func(f *gateFixture) *Carrier {
			c := f.sign(f.approval("script", scriptPayload()), f.ops.approver)
			return &c
		}},
		{"approval for another device", wire.ErrCodeOpsignWrongTarget, func(f *gateFixture) *Carrier {
			a := f.updateApproval(hashA)
			a.Entries[0].DeviceID = deviceB
			c := f.sign(a, f.ops.approver)
			return &c
		}},
		{"signature from another key", wire.ErrCodeOpsignBadSignature, func(f *gateFixture) *Carrier {
			c := f.sign(f.updateApproval(hashA), f.ops.outsider)
			return &c
		}},
		{"expired", wire.ErrCodeOpsignExpired, func(f *gateFixture) *Carrier {
			a := f.updateApproval(hashA)
			a.ExpiresAt = t0.Add(30 * time.Second)
			c := f.sign(a, f.ops.approver)
			return &c
		}},
		{"already used", wire.ErrCodeOpsignReplayed, func(f *gateFixture) *Carrier {
			c := f.sign(f.updateApproval(hashA), f.ops.approver)
			wantAllowed(f.t, f.checkUpdate("0.70.0", false, &c))
			return &c
		}},
		{"identity differs from the pin", wire.ErrCodeOpsignIdentityChanged, func(f *gateFixture) *Carrier {
			c := f.sign(f.updateApproval(hashA), f.ops.approver)
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
		c := f.sign(f.updateApproval(hashA), f.ops.approver)
		d := f.checkUpdate("0.70.0", false, &c)
		wantAllowed(t, d)
		if d.Mode != ModeEnforce {
			t.Errorf("mode = %q", d.Mode)
		}
		wantRefused(t, f.checkUpdate("0.70.0", false, &c), wire.ErrCodeOpsignReplayed)
	})
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
	wantAllowed(t, g.CheckUpdate(UpdateCheck{Version: "garbage", ArtifactSHA256: hashA, Clock: gateClock}))
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
