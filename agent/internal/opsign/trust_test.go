package opsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type testKey struct {
	priv *ecdsa.PrivateKey
	key  BundleKey
}

func newTestKey(t *testing.T, role Role, label string) testKey {
	t.Helper()
	priv, spki := newKey(t, elliptic.P256())
	der, err := base64.StdEncoding.DecodeString(spki)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv, BundleKey{KeyID: KeyIDFromSPKI(der), SPKIB64: spki, Role: role, Label: label}}
}

func bundleOf(partner string, epoch uint64, threshold int, keys ...testKey) Bundle {
	b := Bundle{PartnerID: partner, Epoch: epoch, Mode: ModeEnforce, Threshold: threshold}
	for _, k := range keys {
		b.Keys = append(b.Keys, k.key)
	}
	return b
}

func sigBy(t *testing.T, k testKey, canonical []byte) BundleSig {
	t.Helper()
	return BundleSig{KeyID: k.key.KeyID, SignatureB64: signRaw(t, k.priv, canonical)}
}

func signedBy(t *testing.T, b Bundle, signers ...testKey) SignedBundle {
	t.Helper()
	canonical, err := b.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sb := SignedBundle{CanonicalB64: b64(canonical)}
	for _, k := range signers {
		sb.Signatures = append(sb.Signatures, sigBy(t, k, canonical))
	}
	return sb
}

func fingerprintOf(t *testing.T, sb SignedBundle) string {
	t.Helper()
	canonical, err := decodeB64(sb.CanonicalB64)
	if err != nil {
		t.Fatal(err)
	}
	return Fingerprint(canonical)
}

var deviceIdentity = Identity{DeviceID: deviceA, OrgID: orgID, Hostname: "srv-01"}

// operators holds the keys the tests sign with: two admins, an approver, and an
// outsider who is in no bundle.
type operators struct{ admin1, admin2, admin3, approver, outsider testKey }

func newOperators(t *testing.T) operators {
	t.Helper()
	return operators{
		admin1:   newTestKey(t, RoleAdmin, "admin one"),
		admin2:   newTestKey(t, RoleAdmin, "admin two"),
		admin3:   newTestKey(t, RoleAdmin, "admin three"),
		approver: newTestKey(t, RoleApprover, "dispatch"),
		outsider: newTestKey(t, RoleAdmin, "outsider"),
	}
}

// pinFirst pins an epoch-1 bundle (admin1, admin2, approver; threshold 2) on a
// fresh store.
func pinFirst(t *testing.T, ops operators) (*Store, string, SignedBundle) {
	t.Helper()
	path := statePath(t)
	s := OpenStore(path)
	first := signedBy(t, bundleOf(partnerID, 1, 2, ops.admin1, ops.admin2, ops.approver), ops.admin1, ops.admin2)
	if applied, err := ApplyBundle(s, first, deviceIdentity, t0); err != nil || !applied {
		t.Fatalf("first pin: applied=%v err=%v", applied, err)
	}
	return s, path, first
}

func mustLoad(t *testing.T, s *Store) *Pin {
	t.Helper()
	pin, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestFirstPin(t *testing.T) {
	ops := newOperators(t)
	s := OpenStore(statePath(t))
	sb := signedBy(t, bundleOf(partnerID, 5, 2, ops.admin1, ops.admin2, ops.approver), ops.admin1, ops.admin2)

	applied, err := ApplyBundle(s, sb, deviceIdentity, t0)
	if err != nil || !applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
	pin := mustLoad(t, s)
	if pin == nil {
		t.Fatal("nothing pinned")
	}
	if pin.Fingerprint != fingerprintOf(t, sb) {
		t.Errorf("fingerprint = %s, want %s", pin.Fingerprint, fingerprintOf(t, sb))
	}
	if pin.DeviceID != deviceA || pin.OrgID != orgID || pin.Hostname != "srv-01" || pin.PartnerID != partnerID {
		t.Errorf("identity = %+v", pin)
	}
	if !pin.PinnedAt.Equal(t0) {
		t.Errorf("PinnedAt = %s, want %s", pin.PinnedAt, t0)
	}
	if pin.Bundle.CanonicalB64 != sb.CanonicalB64 || len(pin.Bundle.Signatures) != 2 {
		t.Errorf("stored bundle = %+v", pin.Bundle)
	}
}

func TestFirstPinNeedsOwnThreshold(t *testing.T) {
	ops := newOperators(t)
	b := bundleOf(partnerID, 5, 2, ops.admin1, ops.admin2, ops.approver)
	canonical, err := b.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]BundleSig{
		"one admin of two":           {sigBy(t, ops.admin1, canonical)},
		"one admin signing twice":    {sigBy(t, ops.admin1, canonical), sigBy(t, ops.admin1, canonical)},
		"admin and approver":         {sigBy(t, ops.admin1, canonical), sigBy(t, ops.approver, canonical)},
		"admin and unknown key":      {sigBy(t, ops.admin1, canonical), sigBy(t, ops.outsider, canonical)},
		"admin and forged signature": {sigBy(t, ops.admin1, canonical), {KeyID: ops.admin2.key.KeyID, SignatureB64: signRaw(t, ops.outsider.priv, canonical)}},
		"no signatures":              nil,
	}
	for name, sigs := range cases {
		t.Run(name, func(t *testing.T) {
			s := OpenStore(statePath(t))
			applied, err := ApplyBundle(s, SignedBundle{CanonicalB64: b64(canonical), Signatures: sigs}, deviceIdentity, t0)
			if applied || !errors.Is(err, ErrBundleRejected) {
				t.Fatalf("applied=%v err=%v, want ErrBundleRejected", applied, err)
			}
			if pin := mustLoad(t, s); pin != nil {
				t.Fatalf("a rejected bundle was pinned: %+v", pin)
			}
		})
	}
}

// One bad extra signature must not sink a bundle that the good ones carry, and
// it must not be stored.
func TestFirstPinIgnoresExtraSignatures(t *testing.T) {
	ops := newOperators(t)
	b := bundleOf(partnerID, 5, 2, ops.admin1, ops.admin2, ops.approver)
	canonical, err := b.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sb := SignedBundle{CanonicalB64: b64(canonical), Signatures: []BundleSig{
		sigBy(t, ops.outsider, canonical),
		sigBy(t, ops.approver, canonical),
		{KeyID: ops.admin1.key.KeyID, SignatureB64: "bm90IGEgc2lnbmF0dXJl"},
		sigBy(t, ops.admin1, canonical),
		sigBy(t, ops.admin2, canonical),
		sigBy(t, ops.admin2, canonical),
	}}
	s := OpenStore(statePath(t))
	if applied, err := ApplyBundle(s, sb, deviceIdentity, t0); err != nil || !applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
	stored := mustLoad(t, s).Bundle.Signatures
	if len(stored) != 2 || stored[0].KeyID != ops.admin1.key.KeyID || stored[1].KeyID != ops.admin2.key.KeyID {
		t.Fatalf("stored signatures = %+v, want one each from the two admins", stored)
	}
}

func TestBundleWithTooManySignaturesRejected(t *testing.T) {
	ops := newOperators(t)
	sb := signedBy(t, bundleOf(partnerID, 5, 2, ops.admin1, ops.admin2), ops.admin1, ops.admin2)
	for len(sb.Signatures) <= maxBundleSignatures {
		sb.Signatures = append(sb.Signatures, sb.Signatures[0])
	}
	s := OpenStore(statePath(t))
	if applied, err := ApplyBundle(s, sb, deviceIdentity, t0); applied || !errors.Is(err, ErrBundleRejected) {
		t.Fatalf("applied=%v err=%v, want ErrBundleRejected", applied, err)
	}
}

func TestPinRefusedWithoutDeviceID(t *testing.T) {
	ops := newOperators(t)
	sb := signedBy(t, bundleOf(partnerID, 5, 2, ops.admin1, ops.admin2), ops.admin1, ops.admin2)
	for name, id := range map[string]Identity{
		"no device": {OrgID: orgID, Hostname: "srv-01"},
		"no org":    {DeviceID: deviceA, Hostname: "srv-01"},
		"no host":   {DeviceID: deviceA, OrgID: orgID},
	} {
		t.Run(name, func(t *testing.T) {
			s := OpenStore(statePath(t))
			applied, err := ApplyBundle(s, sb, id, t0)
			if applied || !errors.Is(err, ErrPinIdentityMissing) {
				t.Fatalf("applied=%v err=%v, want ErrPinIdentityMissing", applied, err)
			}
			if pin := mustLoad(t, s); pin != nil {
				t.Fatalf("pinned without an identity: %+v", pin)
			}
		})
	}
}

func TestFirstPinHonoursExpectFingerprint(t *testing.T) {
	ops := newOperators(t)
	s := OpenStore(statePath(t))
	sb := signedBy(t, bundleOf(partnerID, 5, 2, ops.admin1, ops.admin2), ops.admin1, ops.admin2)

	if err := s.ClearPin(strings.Repeat("0", 32)); err != nil {
		t.Fatal(err)
	}
	if applied, err := ApplyBundle(s, sb, deviceIdentity, t0); applied || !errors.Is(err, ErrUnexpectedBundle) {
		t.Fatalf("applied=%v err=%v, want ErrUnexpectedBundle", applied, err)
	}
	if pin := mustLoad(t, s); pin != nil {
		t.Fatalf("pinned a bundle other than the expected one: %+v", pin)
	}

	if err := s.ClearPin(fingerprintOf(t, sb)); err != nil {
		t.Fatal(err)
	}
	if applied, err := ApplyBundle(s, sb, deviceIdentity, t0); err != nil || !applied {
		t.Fatalf("expected bundle: applied=%v err=%v", applied, err)
	}
	if got := s.ExpectFingerprint(); got != "" {
		t.Errorf("ExpectFingerprint = %q after the pin, want it consumed", got)
	}
}

func TestChangeNeedsPinnedAdmins(t *testing.T) {
	ops := newOperators(t)
	// admin3 is new in the change, so only the new bundle knows it.
	change := bundleOf(partnerID, 2, 2, ops.admin1, ops.admin2, ops.admin3, ops.approver)
	cases := map[string][]testKey{
		"approver and one admin":          {ops.approver, ops.admin1},
		"one admin of a threshold of two": {ops.admin1},
		"one admin and a key only in new": {ops.admin1, ops.admin3},
		"only keys of the new bundle":     {ops.admin3, ops.outsider},
		"one admin twice":                 {ops.admin1, ops.admin1},
		"approver, admin and unknown":     {ops.approver, ops.outsider, ops.admin2},
	}
	for name, signers := range cases {
		t.Run(name, func(t *testing.T) {
			s, path, first := pinFirst(t, ops)
			before := fileBytes(t, path)
			applied, err := ApplyBundle(s, signedBy(t, change, signers...), deviceIdentity, t0.Add(time.Hour))
			if applied || !errors.Is(err, ErrBundleRejected) {
				t.Fatalf("applied=%v err=%v, want ErrBundleRejected", applied, err)
			}
			if !bytes.Equal(before, fileBytes(t, path)) {
				t.Error("a rejected change altered the state file")
			}
			if got := mustLoad(t, s).Fingerprint; got != fingerprintOf(t, first) {
				t.Errorf("pin moved to %s", got)
			}
		})
	}

	t.Run("both pinned admins", func(t *testing.T) {
		s, _, _ := pinFirst(t, ops)
		sb := signedBy(t, change, ops.admin1, ops.admin2)
		if applied, err := ApplyBundle(s, sb, deviceIdentity, t0.Add(time.Hour)); err != nil || !applied {
			t.Fatalf("applied=%v err=%v", applied, err)
		}
		if got := mustLoad(t, s).Fingerprint; got != fingerprintOf(t, sb) {
			t.Errorf("pin = %s, want the new bundle", got)
		}
	})
}

// A change the old admins approve but whose own admins cannot sign would leave a
// bundle nobody can ever change again.
func TestChangeMustMeetOwnThreshold(t *testing.T) {
	ops := newOperators(t)
	s, path, _ := pinFirst(t, ops)
	before := fileBytes(t, path)
	lockOut := bundleOf(partnerID, 2, 2, ops.admin3, ops.outsider, ops.approver)

	applied, err := ApplyBundle(s, signedBy(t, lockOut, ops.admin1, ops.admin2), deviceIdentity, t0)
	if applied || !errors.Is(err, ErrBundleRejected) {
		t.Fatalf("applied=%v err=%v, want ErrBundleRejected", applied, err)
	}
	if !bytes.Equal(before, fileBytes(t, path)) {
		t.Error("a rejected change altered the state file")
	}
}

func TestChangeEpochMustIncrease(t *testing.T) {
	ops := newOperators(t)
	for name, epoch := range map[string]uint64{"same epoch": 1, "lower epoch": 0} {
		t.Run(name, func(t *testing.T) {
			s, path, _ := pinFirst(t, ops)
			before := fileBytes(t, path)
			sb := signedBy(t, bundleOf(partnerID, epoch, 1, ops.admin1, ops.admin2), ops.admin1, ops.admin2)
			if applied, err := ApplyBundle(s, sb, deviceIdentity, t0); applied || !errors.Is(err, ErrBundleRejected) {
				t.Fatalf("applied=%v err=%v, want ErrBundleRejected", applied, err)
			}
			if !bytes.Equal(before, fileBytes(t, path)) {
				t.Error("a rejected change altered the state file")
			}
		})
	}
}

func TestChangePartnerFixed(t *testing.T) {
	ops := newOperators(t)
	s, path, _ := pinFirst(t, ops)
	before := fileBytes(t, path)
	otherPartner := "9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"
	sb := signedBy(t, bundleOf(otherPartner, 2, 2, ops.admin1, ops.admin2), ops.admin1, ops.admin2)

	if applied, err := ApplyBundle(s, sb, deviceIdentity, t0); applied || !errors.Is(err, ErrBundleRejected) {
		t.Fatalf("applied=%v err=%v, want ErrBundleRejected", applied, err)
	}
	if !bytes.Equal(before, fileBytes(t, path)) {
		t.Error("a rejected change altered the state file")
	}
}

func TestChangeKeepsIdentity(t *testing.T) {
	ops := newOperators(t)
	s, _, _ := pinFirst(t, ops)
	elsewhere := Identity{DeviceID: deviceB, OrgID: "22222222-3333-4444-8555-666666666666", Hostname: "other-host"}
	later := t0.Add(48 * time.Hour)
	sb := signedBy(t, bundleOf(partnerID, 2, 2, ops.admin1, ops.admin2, ops.admin3), ops.admin1, ops.admin2)

	if applied, err := ApplyBundle(s, sb, elsewhere, later); err != nil || !applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
	pin := mustLoad(t, s)
	if pin.DeviceID != deviceA || pin.OrgID != orgID || pin.Hostname != "srv-01" || pin.PartnerID != partnerID {
		t.Errorf("identity changed: %+v", pin)
	}
	if pin.Fingerprint != fingerprintOf(t, sb) || pin.Bundle.CanonicalB64 != sb.CanonicalB64 {
		t.Errorf("bundle was not replaced: %+v", pin)
	}
	if !pin.PinnedAt.Equal(later) {
		t.Errorf("PinnedAt = %s, want %s", pin.PinnedAt, later)
	}
}

func TestReapplySameBundleIsNoop(t *testing.T) {
	ops := newOperators(t)
	s, path, first := pinFirst(t, ops)
	before := fileBytes(t, path)

	// Even from a device that is not enrolled, and without signatures.
	for _, offer := range []struct {
		sb SignedBundle
		id Identity
	}{{first, deviceIdentity}, {first, Identity{}}, {SignedBundle{CanonicalB64: first.CanonicalB64}, deviceIdentity}} {
		applied, err := ApplyBundle(s, offer.sb, offer.id, t0.Add(time.Hour))
		if applied || err != nil {
			t.Fatalf("applied=%v err=%v, want a quiet no-op", applied, err)
		}
	}
	if !bytes.Equal(before, fileBytes(t, path)) {
		t.Error("re-applying the pinned bundle rewrote the state file")
	}
}

func TestUnreadablePinIsNeverOverwritten(t *testing.T) {
	ops := newOperators(t)
	path := statePath(t)
	writeRaw(t, path, []byte("{not json"))
	before := fileBytes(t, path)
	sb := signedBy(t, bundleOf(partnerID, 5, 2, ops.admin1, ops.admin2), ops.admin1, ops.admin2)

	applied, err := ApplyBundle(OpenStore(path), sb, deviceIdentity, t0)
	if applied || !errors.Is(err, ErrPinUnreadable) {
		t.Fatalf("applied=%v err=%v, want ErrPinUnreadable", applied, err)
	}
	if !bytes.Equal(before, fileBytes(t, path)) {
		t.Error("an unreadable pin was overwritten by a first pin")
	}
}

func TestNonCanonicalBundleRejected(t *testing.T) {
	ops := newOperators(t)
	canonical, err := bundleOf(partnerID, 5, 2, ops.admin1, ops.admin2, ops.approver).CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(canonical), "\n")
	lines[len(lines)-1], lines[len(lines)-2] = lines[len(lines)-2], lines[len(lines)-1] // keys out of order

	cases := map[string][]byte{
		"keys out of order": []byte(strings.Join(lines, "\n")),
		"trailing newline":  append(append([]byte(nil), canonical...), '\n'),
		"not a bundle":      []byte("breeze-operator-approval-v1\nkind=action"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			s := OpenStore(statePath(t))
			sb := SignedBundle{CanonicalB64: b64(raw), Signatures: []BundleSig{sigBy(t, ops.admin1, raw), sigBy(t, ops.admin2, raw)}}
			if applied, err := ApplyBundle(s, sb, deviceIdentity, t0); applied || !errors.Is(err, ErrBundleRejected) {
				t.Fatalf("applied=%v err=%v, want ErrBundleRejected", applied, err)
			}
			if pin := mustLoad(t, s); pin != nil {
				t.Fatalf("pinned a non-canonical bundle: %+v", pin)
			}
		})
	}

	t.Run("not base64", func(t *testing.T) {
		s := OpenStore(statePath(t))
		if _, err := ApplyBundle(s, SignedBundle{CanonicalB64: "***"}, deviceIdentity, t0); !errors.Is(err, ErrBundleRejected) {
			t.Fatalf("err=%v, want ErrBundleRejected", err)
		}
	})
}

// Two changes judged against the same old pin must not let the older land last.
func TestConcurrentChangesKeepTheHighestEpoch(t *testing.T) {
	ops := newOperators(t)
	newer := signedBy(t, bundleOf(partnerID, 3, 2, ops.admin1, ops.admin2), ops.admin1, ops.admin2)
	older := signedBy(t, bundleOf(partnerID, 2, 2, ops.admin1, ops.admin2), ops.admin1, ops.admin2)
	for i := 0; i < 20; i++ {
		s, _, _ := pinFirst(t, ops)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, sb := range []SignedBundle{older, newer} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, _ = ApplyBundle(s, sb, deviceIdentity, t0)
			}()
		}
		close(start)
		wg.Wait()
		if got := mustLoad(t, s).Fingerprint; got != fingerprintOf(t, newer) {
			t.Fatalf("round %d: pin ended on epoch-2 bundle %s", i, got)
		}
	}
}

func TestLocalIdentityLowercasesHostname(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Skip(err)
	}
	id, err := LocalIdentity(deviceA, orgID)
	if err != nil {
		t.Fatal(err)
	}
	if id.DeviceID != deviceA || id.OrgID != orgID || id.Hostname != strings.ToLower(host) {
		t.Errorf("LocalIdentity = %+v, hostname %q", id, host)
	}
}
