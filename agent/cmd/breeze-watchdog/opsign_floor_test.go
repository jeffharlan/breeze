package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/breeze-rmm/agent/internal/config"
	"github.com/breeze-rmm/agent/internal/opsign"
	"github.com/breeze-rmm/agent/internal/watchdog"
)

// pinFloor pins an enforce-mode trust bundle with the given minAgentVersion in a
// temp store, and makes that the store the watchdog's updater reads.
func pinFloor(t *testing.T, floor string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := opsign.BundleKey{KeyID: opsign.KeyIDFromSPKI(der), SPKIB64: base64.StdEncoding.EncodeToString(der), Role: opsign.RoleAdmin, Label: "admin"}
	canonical, err := opsign.Bundle{
		PartnerID: "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", Epoch: 1, Mode: opsign.ModeEnforce, Threshold: 1,
		MinAgentVersion: floor, Keys: []opsign.BundleKey{key},
	}.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signed := opsign.SignedBundle{
		CanonicalB64: base64.StdEncoding.EncodeToString(canonical),
		Signatures: []opsign.BundleSig{{
			KeyID:        key.KeyID,
			SignatureB64: base64.StdEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)),
		}},
	}

	path := filepath.Join(t.TempDir(), "opsign", "state.json")
	id := opsign.Identity{DeviceID: "aaaaaaaa-0000-4000-8000-000000000001", OrgID: "11111111-2222-4333-8444-555555555555", Hostname: "acct-pc"}
	if applied, err := opsign.ApplyBundle(opsign.OpenStore(path), signed, id, time.Now()); err != nil || !applied {
		t.Fatalf("pin: applied=%v err=%v", applied, err)
	}
	old := opsign.DefaultStorePath
	opsign.DefaultStorePath = func() string { return path }
	t.Cleanup(func() { opsign.DefaultStorePath = old })
}

// The watchdog installs the agent and itself through the updater, so it shares
// the version floor of the pin the agent keeps.
func TestWatchdogUpdatesRefuseVersionsBelowTheFloor(t *testing.T) {
	pinFloor(t, "v0.70.0")
	journal, err := watchdog.NewJournal(t.TempDir(), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	tokens := &tokenHolder{}
	tokens.Replace("tok")

	origTrust := updateTrustConfigFn
	t.Cleanup(func() { updateTrustConfigFn = origTrust })
	updateTrustConfigFn = func() (*config.Config, error) { return &config.Config{}, nil }
	serverURL := func() string { return "https://example.invalid" }

	for name, update := range map[string]func() error{
		"agent":    func() error { return doUpdateAgent("0.69.9", serverURL, tokens, journal) },
		"watchdog": func() error { return doUpdateWatchdog("0.69.9", serverURL, tokens, journal) },
	} {
		if err := update(); err == nil || !strings.Contains(err.Error(), "opsign_below_floor") {
			t.Errorf("%s update to 0.69.9: err = %v, want one naming opsign_below_floor", name, err)
		}
	}
}
