package heartbeat

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"path/filepath"
	"testing"
	"time"

	"github.com/breeze-rmm/agent/internal/config"
	"github.com/breeze-rmm/agent/internal/opsign"
	"github.com/breeze-rmm/agent/internal/remote/tools"
	"github.com/breeze-rmm/agent/internal/wire"
)

const opsignTestHost = "acct-pc"

func opsignBundleIn(t *testing.T, admin opsignTestAdmin, mode opsign.Mode) opsign.SignedBundle {
	t.Helper()
	canonical, err := opsign.Bundle{
		PartnerID: opsignTestPartner, Epoch: 1, Mode: mode, Threshold: 1, Keys: []opsign.BundleKey{admin.key},
	}.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return opsign.SignedBundle{
		CanonicalB64: base64.StdEncoding.EncodeToString(canonical),
		Signatures:   []opsign.BundleSig{admin.sign(t, canonical)},
	}
}

// opsignGatedHeartbeat has an admin's bundle pinned in the given mode, and a
// gate that sees this machine as opsignTestHost, so approvals can name it
// whatever the real hostname is.
func opsignGatedHeartbeat(t *testing.T, mode opsign.Mode) (*Heartbeat, opsignTestAdmin) {
	t.Helper()
	admin := newOpsignTestAdmin(t, "admin")
	h, _ := opsignTestHeartbeat(t, opsignTestDevice)
	id := opsign.Identity{DeviceID: opsignTestDevice, OrgID: opsignTestOrg, Hostname: opsignTestHost}
	if applied, err := opsign.ApplyBundle(h.opsignStore, opsignBundleIn(t, admin, mode), id, time.Now()); err != nil || !applied {
		t.Fatalf("pin: applied=%v err=%v", applied, err)
	}
	h.opsignGate = &opsign.Gate{Store: h.opsignStore, Identity: func() (opsign.Identity, error) { return id, nil }}
	return h, admin
}

// opsignSign returns payload with an approval from admin for exactly that
// payload attached, as a decoded command carries it.
func opsignSign(t *testing.T, admin opsignTestAdmin, commandType string, payload map[string]any) map[string]any {
	t.Helper()
	hash, err := opsign.PayloadHash(commandType, payload)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	canonical, err := opsign.ActionApproval{
		ApprovalID: "00112233445566778899aabbccddeeff", PartnerID: opsignTestPartner, CommandType: commandType,
		Entries:  []opsign.Entry{{DeviceID: opsignTestDevice, Hostname: opsignTestHost, PayloadHash: hash}},
		IssuedAt: issued, ExpiresAt: issued.Add(time.Hour), KeyID: admin.key.KeyID,
	}.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(opsign.Carrier{
		V: 1, CanonicalB64: base64.StdEncoding.EncodeToString(canonical), SignatureB64: admin.sign(t, canonical).SignatureB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	var carrier any
	if err := json.Unmarshal(data, &carrier); err != nil {
		t.Fatal(err)
	}
	out := maps.Clone(payload)
	out[opsign.PayloadKey] = carrier
	return out
}

// spyOn replaces the handler for commandType with one that records the payload
// it receives. It mutates handlerRegistry, so its callers must not call t.Parallel().
func spyOn(t *testing.T, commandType string) *[]map[string]any {
	t.Helper()
	orig, hadOrig := handlerRegistry[commandType]
	var seen []map[string]any
	handlerRegistry[commandType] = func(_ *Heartbeat, cmd Command) tools.CommandResult {
		seen = append(seen, maps.Clone(cmd.Payload))
		return tools.CommandResult{Status: "completed"}
	}
	t.Cleanup(func() {
		if hadOrig {
			handlerRegistry[commandType] = orig
		} else {
			delete(handlerRegistry, commandType)
		}
	})
	return &seen
}

func TestDispatchRefusesUnsignedTierACommandUnderEnforce(t *testing.T) {
	h, _ := opsignGatedHeartbeat(t, opsign.ModeEnforce)
	seen := spyOn(t, tools.CmdScript)

	res, handled := h.dispatchCommand(Command{ID: "c1", Type: tools.CmdScript, Payload: map[string]any{"content": "echo hi"}})

	if !handled || res.Status != "failed" || res.ErrorCode != wire.ErrCodeOpsignNoApproval || res.Error == "" {
		t.Fatalf("handled=%v result=%+v, want a failed result coded %s", handled, res, wire.ErrCodeOpsignNoApproval)
	}
	if len(*seen) != 0 {
		t.Fatalf("the script handler ran %d time(s) for a refused command", len(*seen))
	}
}

func TestDispatchRunsSignedScriptWithoutTheApproval(t *testing.T) {
	h, admin := opsignGatedHeartbeat(t, opsign.ModeEnforce)
	seen := spyOn(t, tools.CmdScript)
	payload := opsignSign(t, admin, tools.CmdScript, map[string]any{"content": "echo hi", "executionId": "e-1"})

	res, handled := h.dispatchCommand(Command{ID: "c1", Type: tools.CmdScript, Payload: payload})

	if !handled || res.Status != "completed" || res.ErrorCode != "" {
		t.Fatalf("handled=%v result=%+v, want the command to run", handled, res)
	}
	if len(*seen) != 1 {
		t.Fatalf("script handler ran %d times, want 1", len(*seen))
	}
	if _, present := (*seen)[0][opsign.PayloadKey]; present || (*seen)[0]["content"] != "echo hi" {
		t.Fatalf("handler payload = %v, want the command without %s", (*seen)[0], opsign.PayloadKey)
	}
}

func TestDispatchStripsApprovalFromEveryCommand(t *testing.T) {
	stray := map[string]any{"v": float64(1)}
	t.Run("Tier C command", func(t *testing.T) {
		h, _ := opsignGatedHeartbeat(t, opsign.ModeEnforce)
		seen := spyOn(t, tools.CmdListProcesses)
		res, _ := h.dispatchCommand(Command{ID: "c1", Type: tools.CmdListProcesses, Payload: map[string]any{opsign.PayloadKey: stray, "limit": 5}})
		if res.Status != "completed" || len(*seen) != 1 {
			t.Fatalf("result=%+v handler calls=%d", res, len(*seen))
		}
		if _, present := (*seen)[0][opsign.PayloadKey]; present || (*seen)[0]["limit"] != 5 {
			t.Fatalf("handler payload = %v", (*seen)[0])
		}
	})
	t.Run("refused command", func(t *testing.T) {
		h, _ := opsignGatedHeartbeat(t, opsign.ModeEnforce)
		spyOn(t, tools.CmdScript)
		cmd := Command{ID: "c1", Type: tools.CmdScript, Payload: map[string]any{opsign.PayloadKey: stray}}
		res, _ := h.dispatchCommand(cmd)
		if res.ErrorCode != wire.ErrCodeOpsignMalformed {
			t.Fatalf("result = %+v", res)
		}
		if _, present := cmd.Payload[opsign.PayloadKey]; present {
			t.Fatal("a refused command's payload still holds the approval")
		}
	})
	t.Run("no gate", func(t *testing.T) {
		seen := spyOn(t, tools.CmdListProcesses)
		h := &Heartbeat{}
		h.dispatchCommand(Command{ID: "c1", Type: tools.CmdListProcesses, Payload: map[string]any{opsign.PayloadKey: stray}})
		if len(*seen) != 1 {
			t.Fatalf("handler calls = %d", len(*seen))
		}
		if _, present := (*seen)[0][opsign.PayloadKey]; present {
			t.Fatalf("handler payload = %v", (*seen)[0])
		}
	})
}

func TestDispatchAuditRunsUnsignedCommand(t *testing.T) {
	h, _ := opsignGatedHeartbeat(t, opsign.ModeAudit)
	seen := spyOn(t, tools.CmdScript)

	res, _ := h.dispatchCommand(Command{ID: "c1", Type: tools.CmdScript, Payload: map[string]any{"content": "echo hi"}})

	if res.Status != "completed" || len(*seen) != 1 {
		t.Fatalf("result=%+v handler calls=%d, want audit to let the command run", res, len(*seen))
	}
}

// The gate NewWithVersion builds must read the same store the pin lands in and
// take the device and organization from the agent's config.
func TestNewWithVersionBuildsTheOpsignGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opsign", "state.json")
	orig := opsign.DefaultStorePath
	opsign.DefaultStorePath = func() string { return path }
	t.Cleanup(func() { opsign.DefaultStorePath = orig })

	cfg := &config.Config{AgentID: "agent-1", AuthToken: "token", ServerURL: "http://127.0.0.1:1", DeviceID: opsignTestDevice, OrgID: opsignTestOrg}
	h := NewWithVersion(cfg, "test", nil, nil)
	if h.opsignGate == nil || h.opsignGate.Store != h.opsignStore {
		t.Fatalf("gate = %+v, want one reading the heartbeat's store", h.opsignGate)
	}
	id, err := h.opsignGate.Identity()
	if err != nil || id.DeviceID != opsignTestDevice || id.OrgID != opsignTestOrg {
		t.Fatalf("identity = %+v, %v", id, err)
	}

	if applied, err := opsign.ApplyBundle(h.opsignStore, opsignBundleIn(t, newOpsignTestAdmin(t, "admin"), opsign.ModeEnforce), id, time.Now()); err != nil || !applied {
		t.Fatalf("pin: applied=%v err=%v", applied, err)
	}
	seen := spyOn(t, tools.CmdScript)
	res, _ := h.dispatchCommand(Command{ID: "c1", Type: tools.CmdScript, Payload: map[string]any{"content": "echo hi"}})
	if res.ErrorCode != wire.ErrCodeOpsignNoApproval || len(*seen) != 0 {
		t.Fatalf("result=%+v handler calls=%d, want the pinned enforce bundle to refuse the unsigned script", res, len(*seen))
	}
}
