package heartbeat

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/breeze-rmm/agent/internal/config"
	"github.com/breeze-rmm/agent/internal/opsign"
	"github.com/breeze-rmm/agent/internal/tunnel"
)

const (
	opsignTestPartner = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	opsignTestDevice  = "aaaaaaaa-0000-4000-8000-000000000001"
	opsignTestOrg     = "11111111-2222-4333-8444-555555555555"
)

type opsignTestAdmin struct {
	priv *ecdsa.PrivateKey
	key  opsign.BundleKey
}

func newOpsignTestAdmin(t *testing.T, label string) opsignTestAdmin {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return opsignTestAdmin{priv, opsign.BundleKey{
		KeyID: opsign.KeyIDFromSPKI(der), SPKIB64: base64.StdEncoding.EncodeToString(der), Role: opsign.RoleAdmin, Label: label,
	}}
}

func (a opsignTestAdmin) sign(t *testing.T, canonical []byte) opsign.BundleSig {
	t.Helper()
	digest := sha256.Sum256(canonical)
	r, s, err := ecdsa.Sign(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return opsign.BundleSig{KeyID: a.key.KeyID, SignatureB64: base64.StdEncoding.EncodeToString(raw)}
}

func opsignTestBundle(t *testing.T, epoch uint64, threshold int, signers ...opsignTestAdmin) *opsign.SignedBundle {
	t.Helper()
	b := opsign.Bundle{PartnerID: opsignTestPartner, Epoch: epoch, Mode: opsign.ModeAudit, Threshold: threshold}
	for _, a := range signers {
		b.Keys = append(b.Keys, a.key)
	}
	canonical, err := b.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sb := &opsign.SignedBundle{CanonicalB64: base64.StdEncoding.EncodeToString(canonical)}
	for _, a := range signers {
		sb.Signatures = append(sb.Signatures, a.sign(t, canonical))
	}
	return sb
}

// opsignTestResponse decodes the bundle through HeartbeatResponse's own JSON
// tag, as a real beat does.
func opsignTestResponse(t *testing.T, sb *opsign.SignedBundle) *HeartbeatResponse {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"operatorTrustBundle": sb})
	if err != nil {
		t.Fatal(err)
	}
	var resp HeartbeatResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.OperatorTrustBundle == nil {
		t.Fatal("operatorTrustBundle did not decode into HeartbeatResponse")
	}
	return &resp
}

func opsignTestHeartbeat(t *testing.T, deviceID string) (*Heartbeat, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opsign", "state.json")
	return &Heartbeat{
		config:      &config.Config{DeviceID: deviceID, OrgID: opsignTestOrg},
		opsignStore: opsign.OpenStore(path),
		tunnelMgr:   &tunnel.Manager{},
	}, path
}

func TestOpsignBundleInResponsePinsOnFreshStore(t *testing.T) {
	a1, a2 := newOpsignTestAdmin(t, "one"), newOpsignTestAdmin(t, "two")
	sb := opsignTestBundle(t, 1, 2, a1, a2)
	h, _ := opsignTestHeartbeat(t, opsignTestDevice)

	h.processHeartbeatResponse(opsignTestResponse(t, sb))

	pin, err := h.opsignStore.Load()
	if err != nil || pin == nil {
		t.Fatalf("pin=%v err=%v, want the relayed bundle pinned", pin, err)
	}
	canonical, _ := base64.StdEncoding.DecodeString(sb.CanonicalB64)
	if pin.Fingerprint != opsign.Fingerprint(canonical) || pin.DeviceID != opsignTestDevice || pin.OrgID != opsignTestOrg || pin.PartnerID != opsignTestPartner {
		t.Errorf("pin = %+v", pin)
	}
	if pin.Hostname == "" {
		t.Error("pin has no hostname")
	}
}

func TestOpsignBadBundleLeavesStoreUntouched(t *testing.T) {
	a1, a2, mallory := newOpsignTestAdmin(t, "one"), newOpsignTestAdmin(t, "two"), newOpsignTestAdmin(t, "mallory")
	h, path := opsignTestHeartbeat(t, opsignTestDevice)
	h.processHeartbeatResponse(opsignTestResponse(t, opsignTestBundle(t, 1, 2, a1, a2)))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for name, sb := range map[string]*opsign.SignedBundle{
		"signed by a key the pin does not trust": opsignTestBundle(t, 2, 1, mallory),
		"epoch does not increase":                opsignTestBundle(t, 1, 2, a1, a2),
		"not a bundle":                           {CanonicalB64: "bm9wZQ=="},
	} {
		t.Run(name, func(t *testing.T) {
			h.processHeartbeatResponse(opsignTestResponse(t, sb))
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Error("a bad bundle changed the state file")
			}
		})
	}
}

// An agent that has not enrolled yet has no device ID to pin under. The offer is
// dropped without harm and pinned on a later beat.
func TestOpsignBundleWaitsForDeviceID(t *testing.T) {
	a1 := newOpsignTestAdmin(t, "one")
	sb := opsignTestBundle(t, 1, 1, a1)
	h, _ := opsignTestHeartbeat(t, "")

	h.processHeartbeatResponse(opsignTestResponse(t, sb))
	if pin, err := h.opsignStore.Load(); err != nil || pin != nil {
		t.Fatalf("pin=%v err=%v, want nothing pinned without a device ID", pin, err)
	}

	h.config.DeviceID = opsignTestDevice
	h.processHeartbeatResponse(opsignTestResponse(t, sb))
	if pin, err := h.opsignStore.Load(); err != nil || pin == nil {
		t.Fatalf("pin=%v err=%v, want the bundle pinned once the device ID is known", pin, err)
	}
}

func TestOpsignResponseWithoutBundleDoesNothing(t *testing.T) {
	h, path := opsignTestHeartbeat(t, opsignTestDevice)
	h.processHeartbeatResponse(&HeartbeatResponse{})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("state file stat err=%v, want it absent", err)
	}
}

// The local tick records the device's own clock as trusted time once a bundle
// is pinned, and leaves an unpinned device without a state file.
func TestOpsignTickRaisesStoredTimeOnlyWhenPinned(t *testing.T) {
	h, path := opsignTestHeartbeat(t, opsignTestDevice)
	h.observeOwnClock()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an unpinned device got a state file from the tick (stat err=%v)", err)
	}

	h.processHeartbeatResponse(opsignTestResponse(t, opsignTestBundle(t, 1, 1, newOpsignTestAdmin(t, "one"))))
	before := time.Now()
	h.observeOwnClock()
	if got := h.opsignStore.HighWater(); got.Before(before.Add(-time.Second)) {
		t.Fatalf("stored time after the tick = %v, want at least %v", got, before)
	}
}
