package updater

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/breeze-rmm/agent/internal/opsign"
)

// The updater now reads the operator trust pin on every install, so no test may
// see the one on the machine running it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "updater-opsign-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	opsign.DefaultStorePath = func() string { return filepath.Join(dir, "state.json") }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

const (
	opsignPartner = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	opsignOrg     = "11111111-2222-4333-8444-555555555555"
	opsignDevice  = "aaaaaaaa-0000-4000-8000-000000000001"
	opsignHost    = "acct-pc"
	deployKeyID   = "deploy-test"
)

// operator is one admin key of the pinned trust bundle; it also approves updates.
type operator struct {
	priv *ecdsa.PrivateKey
	key  opsign.BundleKey
}

func (o operator) sign(t *testing.T, msg []byte) string {
	t.Helper()
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, o.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

// approve returns an agent_update approval of artifactSHA for the test device.
func (o operator) approve(t *testing.T, artifactSHA string) *opsign.Carrier {
	t.Helper()
	issued := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	canonical, err := opsign.ActionApproval{
		ApprovalID: "00112233445566778899aabbccddeeff", PartnerID: opsignPartner, CommandType: "agent_update",
		Entries:  []opsign.Entry{{DeviceID: opsignDevice, Hostname: opsignHost, PayloadHash: artifactSHA}},
		IssuedAt: issued, ExpiresAt: issued.Add(time.Hour), KeyID: o.key.KeyID,
	}.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return &opsign.Carrier{V: 1, CanonicalB64: base64.StdEncoding.EncodeToString(canonical), SignatureB64: o.sign(t, canonical)}
}

// pinOperatorTrust pins a bundle in the given mode and with the given
// minAgentVersion in a temp store, and points the updater's gate at it as the
// device the approvals in these tests name.
func pinOperatorTrust(t *testing.T, mode opsign.Mode, floor string) operator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	op := operator{priv, opsign.BundleKey{
		KeyID: opsign.KeyIDFromSPKI(der), SPKIB64: base64.StdEncoding.EncodeToString(der), Role: opsign.RoleAdmin, Label: "admin",
	}}
	canonical, err := opsign.Bundle{
		PartnerID: opsignPartner, Epoch: 1, Mode: mode, Threshold: 1, MinAgentVersion: floor, Keys: []opsign.BundleKey{op.key},
	}.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	signed := opsign.SignedBundle{
		CanonicalB64: base64.StdEncoding.EncodeToString(canonical),
		Signatures:   []opsign.BundleSig{{KeyID: op.key.KeyID, SignatureB64: op.sign(t, canonical)}},
	}
	store := opsign.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	id := opsign.Identity{DeviceID: opsignDevice, OrgID: opsignOrg, Hostname: opsignHost}
	if applied, err := opsign.ApplyBundle(store, signed, id, time.Now()); err != nil || !applied {
		t.Fatalf("pin: applied=%v err=%v", applied, err)
	}
	old := operatorGate
	operatorGate = func() *opsign.Gate {
		return &opsign.Gate{Store: store, Identity: func() (opsign.Identity, error) { return id, nil }}
	}
	t.Cleanup(func() { operatorGate = old })
	return op
}

// deploymentSignedInfo is a download response whose manifest is signed by a
// deployment key (not the vendor's), and the pinned-key entry that trusts it.
// The caller sets info.URL; the signed manifest names a fixed canonical URL.
func deploymentSignedInfo(t *testing.T, version string, content []byte) (downloadInfo, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := updateManifest{
		Version: version, Component: "agent", Platform: manifestPlatform(), Arch: runtime.GOARCH,
		URL: "https://updates.example.invalid/agent", Checksum: artifactSHA(content), Size: int64(len(content)),
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return downloadInfo{
		Checksum: manifest.Checksum, Manifest: string(payload), SigningKeyID: deployKeyID,
		ManifestSignature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}, deployKeyID + ":" + base64.StdEncoding.EncodeToString(pub)
}

func artifactSHA(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// updateFixture is an updater pointed at a server that offers one artifact, and
// the binary it would replace.
type updateFixture struct {
	u      *Updater
	binary string
}

// unusableBytes has the artifact's length but not its bytes. A test that calls
// UpdateTo serves it, so that if the gate under test ever failed to refuse, the
// download would still die at the checksum check, before the binary is backed
// up or replaced and before the real service restart.
func unusableBytes(content []byte) []byte {
	return bytes.Repeat([]byte{'x'}, len(content))
}

// newUpdateFixture offers info and serves the bytes served as the artifact.
func newUpdateFixture(t *testing.T, info func(host string) downloadInfo, served []byte, cfg Config) updateFixture {
	t.Helper()
	srv := downloadServer(t, info, served, 0, 0)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	binary := filepath.Join(dir, "agent")
	if err := os.WriteFile(binary, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.BinaryPath, cfg.BackupPath, cfg.TempDir = binary, binary+".bak", dir
	return updateFixture{newTestUpdater(t, srv, cfg), binary}
}

// wantUntouched fails when an update that was refused touched the live binary.
func (f updateFixture) wantUntouched(t *testing.T) {
	t.Helper()
	if got, err := os.ReadFile(f.binary); err != nil || string(got) != "original" {
		t.Fatalf("a refused update changed the binary: %q, %v", got, err)
	}
	if _, err := os.Stat(f.binary + ".bak"); !os.IsNotExist(err) {
		t.Fatal("a refused update backed up the binary")
	}
}

func wantRefusal(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), code) {
		t.Fatalf("error = %v, want one naming %s", err, code)
	}
}

func wantDownloaded(t *testing.T, u *Updater, version string) {
	t.Helper()
	path, err := u.DownloadBinary(version)
	if err != nil {
		t.Fatalf("DownloadBinary(%s): %v", version, err)
	}
	removeCleanup(path)
}

func TestDeploymentSignedUpdateNeedsOperatorApproval(t *testing.T) {
	content := []byte("agent 1.2.3 built by the deployment")
	signed, pinnedKey := deploymentSignedInfo(t, "1.2.3", content)
	offer := func(approval *opsign.Carrier) func(string) downloadInfo {
		return func(host string) downloadInfo {
			di := signed
			di.URL, di.OperatorApproval = "http://"+host+"/binary", approval
			return di
		}
	}
	cfg := Config{PinnedManifestPubKeys: []string{pinnedKey}}

	t.Run("refused without an approval, and nothing is replaced", func(t *testing.T) {
		pinOperatorTrust(t, opsign.ModeEnforce, "v1.0.0")
		f := newUpdateFixture(t, offer(nil), unusableBytes(content), cfg)
		err := f.u.UpdateTo("1.2.3")
		wantRefusal(t, err, "opsign_update_unapproved")
		if !IsDeterministicArtifactFailure(err) {
			t.Errorf("%v must back off like any other artifact the device will not install", err)
		}
		f.wantUntouched(t)
	})

	t.Run("accepted with an approval of this artifact, once", func(t *testing.T) {
		op := pinOperatorTrust(t, opsign.ModeEnforce, "v1.0.0")
		f := newUpdateFixture(t, offer(op.approve(t, artifactSHA(content))), content, cfg)
		wantDownloaded(t, f.u, "1.2.3")
		_, err := f.u.DownloadBinary("1.2.3")
		wantRefusal(t, err, "opsign_replayed")
	})

	t.Run("refused when the approval is for another artifact", func(t *testing.T) {
		op := pinOperatorTrust(t, opsign.ModeEnforce, "v1.0.0")
		f := newUpdateFixture(t, offer(op.approve(t, artifactSHA([]byte("something else")))), content, cfg)
		_, err := f.u.DownloadBinary("1.2.3")
		wantRefusal(t, err, "opsign_payload_mismatch")
	})

	t.Run("audit mode lets it through", func(t *testing.T) {
		pinOperatorTrust(t, opsign.ModeAudit, "v1.0.0")
		f := newUpdateFixture(t, offer(nil), content, cfg)
		wantDownloaded(t, f.u, "1.2.3")
	})

	t.Run("no pin lets it through", func(t *testing.T) {
		f := newUpdateFixture(t, offer(nil), content, cfg)
		wantDownloaded(t, f.u, "1.2.3")
	})
}

func TestVendorSignedUpdateNeedsNoApproval(t *testing.T) {
	pinOperatorTrust(t, opsign.ModeEnforce, "v1.0.0")
	content := []byte("agent 1.2.3 from the vendor")
	f := newUpdateFixture(t, func(host string) downloadInfo {
		return signedDownloadInfo(t, "1.2.3", "agent", "http://"+host+"/binary", content)
	}, content, Config{})
	wantDownloaded(t, f.u, "1.2.3")
}

func TestUpdateBelowFloorIsRefusedWhoeverSignedIt(t *testing.T) {
	content := []byte("agent 1.2.3")
	manifests := map[string]func(host string) downloadInfo{
		"single-asset manifest": func(host string) downloadInfo {
			return signedDownloadInfo(t, "1.2.3", "agent", "http://"+host+"/binary", content)
		},
		"release artifact manifest": func(host string) downloadInfo {
			return signedReleaseArtifactDownloadInfo(t, "1.2.3", rollbackAssetName("agent"), "http://"+host+"/binary", content)
		},
	}
	for name, info := range manifests {
		t.Run(name, func(t *testing.T) {
			pinOperatorTrust(t, opsign.ModeEnforce, "v1.2.4")
			var offers atomic.Int32
			f := newUpdateFixture(t, func(host string) downloadInfo {
				offers.Add(1)
				return info(host)
			}, unusableBytes(content), Config{})

			// UpdateTo refuses a version below the floor before it asks the server for anything.
			wantRefusal(t, f.u.UpdateTo("1.2.3"), "opsign_below_floor")
			if offers.Load() != 0 {
				t.Errorf("UpdateTo asked the server for the artifact %d time(s) before refusing", offers.Load())
			}
			// Every other path is stopped once the signed manifest names the version.
			_, err := f.u.DownloadBinary("1.2.3")
			wantRefusal(t, err, "opsign_below_floor")
			f.wantUntouched(t)
		})
	}

	t.Run("a version at the floor is installed", func(t *testing.T) {
		pinOperatorTrust(t, opsign.ModeEnforce, "v1.2.3")
		f := newUpdateFixture(t, manifests["single-asset manifest"], content, Config{})
		wantDownloaded(t, f.u, "1.2.3")
	})
}

func TestStageRollbackArtifactsBelowFloor(t *testing.T) {
	content := map[RollbackComponent][]byte{
		RollbackComponentAgent: []byte("target agent"), RollbackComponentBackup: []byte("target backup"),
	}
	var served atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		_, _ = w.Write(content[RollbackComponent(strings.TrimPrefix(r.URL.Path, "/"))])
	}))
	defer server.Close()
	stage := func() (StagedRollbackSet, error) {
		u := newTestUpdater(t, server, Config{})
		return u.StageRollbackArtifacts(signedRollbackStageRequest(t, server.URL, content))
	}

	pinOperatorTrust(t, opsign.ModeEnforce, "v2.0.0")
	if staged, err := stage(); err == nil {
		staged.Cleanup()
		t.Fatal("rollback to 1.9.0 was staged under a floor of 2.0.0")
	} else {
		wantRefusal(t, err, "opsign_below_floor")
	}
	if served.Load() != 0 {
		t.Fatalf("%d artifact download(s) before the floor check refused the rollback", served.Load())
	}

	pinOperatorTrust(t, opsign.ModeEnforce, "v1.9.0")
	staged, err := stage()
	if err != nil {
		t.Fatalf("rollback to the floor itself: %v", err)
	}
	staged.Cleanup()
}
