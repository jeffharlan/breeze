package agentapp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/breeze-rmm/agent/internal/config"
	"github.com/breeze-rmm/agent/internal/opsign"
)

const (
	trustTestPartner = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	trustTestDevice  = "aaaaaaaa-0000-4000-8000-000000000001"
	trustTestOrg     = "11111111-2222-4333-8444-555555555555"
)

// signedTrustBundle returns a one-admin epoch-1 bundle signed by that admin.
func signedTrustBundle(t *testing.T) opsign.SignedBundle {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := opsign.KeyIDFromSPKI(der)
	canonical, err := opsign.Bundle{
		PartnerID: trustTestPartner, Epoch: 1, Mode: opsign.ModeAudit, Threshold: 1,
		Keys: []opsign.BundleKey{{KeyID: keyID, SPKIB64: base64.StdEncoding.EncodeToString(der), Role: opsign.RoleAdmin, Label: "admin"}},
	}.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return opsign.SignedBundle{
		CanonicalB64: base64.StdEncoding.EncodeToString(canonical),
		Signatures:   []opsign.BundleSig{{KeyID: keyID, SignatureB64: base64.StdEncoding.EncodeToString(sig)}},
	}
}

func trustTestPaths(t *testing.T) (store *opsign.Store, statePath, filePath string) {
	t.Helper()
	dir := t.TempDir()
	statePath = filepath.Join(dir, "opsign", "state.json")
	return opsign.OpenStore(statePath), statePath, filepath.Join(dir, "operator-trust.json")
}

func writeTrustFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPinOperatorTrustFile(t *testing.T) {
	enrolled := &config.Config{DeviceID: trustTestDevice, OrgID: trustTestOrg}

	t.Run("missing file is not an error and writes nothing", func(t *testing.T) {
		store, statePath, filePath := trustTestPaths(t)
		if err := pinOperatorTrustFile(store, filePath, enrolled); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if _, err := os.Stat(statePath); !os.IsNotExist(err) {
			t.Fatalf("state file stat err = %v, want it absent", err)
		}
	})

	t.Run("a signed bundle is pinned", func(t *testing.T) {
		store, _, filePath := trustTestPaths(t)
		sb := signedTrustBundle(t)
		data, err := json.Marshal(sb)
		if err != nil {
			t.Fatal(err)
		}
		writeTrustFile(t, filePath, data)

		if err := pinOperatorTrustFile(store, filePath, enrolled); err != nil {
			t.Fatal(err)
		}
		pin, err := store.Load()
		if err != nil || pin == nil {
			t.Fatalf("pin=%v err=%v", pin, err)
		}
		if pin.DeviceID != trustTestDevice || pin.OrgID != trustTestOrg || pin.PartnerID != trustTestPartner {
			t.Errorf("pin = %+v", pin)
		}
		if err := pinOperatorTrustFile(store, filePath, enrolled); err != nil {
			t.Errorf("reading the same file again: %v", err)
		}
	})

	t.Run("an agent without a device ID waits", func(t *testing.T) {
		store, statePath, filePath := trustTestPaths(t)
		data, _ := json.Marshal(signedTrustBundle(t))
		writeTrustFile(t, filePath, data)

		err := pinOperatorTrustFile(store, filePath, &config.Config{OrgID: trustTestOrg})
		if !errors.Is(err, opsign.ErrPinIdentityMissing) {
			t.Fatalf("err = %v, want ErrPinIdentityMissing", err)
		}
		if _, err := os.Stat(statePath); !os.IsNotExist(err) {
			t.Fatalf("state file stat err = %v, want it absent", err)
		}
	})

	t.Run("a file that is not a bundle is an error and changes nothing", func(t *testing.T) {
		store, statePath, filePath := trustTestPaths(t)
		before := []byte(`{"pin":null}`)
		if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTrustFile(t, statePath, before)
		for name, raw := range map[string][]byte{
			"not json":        []byte("<xml/>"),
			"unsigned bundle": []byte(`{"canonicalB64":"bm9wZQ==","signatures":[]}`),
		} {
			writeTrustFile(t, filePath, raw)
			if err := pinOperatorTrustFile(store, filePath, enrolled); err == nil {
				t.Errorf("%s: err = nil, want an error", name)
			}
			after, err := os.ReadFile(statePath)
			if err != nil || !bytes.Equal(before, after) {
				t.Errorf("%s: state file changed (err=%v)", name, err)
			}
		}
	})
}
