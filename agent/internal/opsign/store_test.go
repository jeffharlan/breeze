package opsign

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

func statePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "opsign", "state.json")
}

// restart simulates an agent restart: the next OpenStore reads the file afresh.
func restart(path string) *Store {
	storesMu.Lock()
	delete(stores, filepath.Clean(path))
	storesMu.Unlock()
	return OpenStore(path)
}

func samplePin(t *testing.T) Pin {
	t.Helper()
	canonical, err := sampleBundle().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return Pin{
		Bundle:      SignedBundle{CanonicalB64: b64(canonical), Signatures: []BundleSig{{KeyID: signerID, SignatureB64: "c2ln"}}},
		Fingerprint: Fingerprint(canonical),
		DeviceID:    deviceA, OrgID: orgID, PartnerID: partnerID, Hostname: "srv-01",
		PinnedAt: t0,
	}
}

func fileState(t *testing.T, path string) state {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func writeState(t *testing.T, path string, st state) {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, path, data)
}

func writeRaw(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadNoFile(t *testing.T) {
	pin, err := OpenStore(statePath(t)).Load()
	if pin != nil || err != nil {
		t.Fatalf("Load = %v, %v; want nil, nil", pin, err)
	}
}

func TestLoadCorruptIsUnreadable(t *testing.T) {
	tamper := func(edit func(*Pin)) []byte {
		p := samplePin(t)
		edit(&p)
		data, err := json.Marshal(state{Pin: &p})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	cases := map[string][]byte{
		"garbage bytes": []byte("\x00\xffnot json"),
		"empty file":    {},
		"bundle edited after pinning": tamper(func(p *Pin) {
			canonical, _ := decodeB64(p.Bundle.CanonicalB64)
			p.Bundle.CanonicalB64 = b64(bytes.Replace(canonical, []byte("epoch=7"), []byte("epoch=8"), 1))
		}),
		"fingerprint edited":     tamper(func(p *Pin) { p.Fingerprint = strings.Repeat("0", 32) }),
		"bundle is not a bundle": tamper(func(p *Pin) { p.Bundle.CanonicalB64 = b64([]byte("hello")) }),
		"bundle is not base64":   tamper(func(p *Pin) { p.Bundle.CanonicalB64 = "!!!" }),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := statePath(t)
			writeRaw(t, path, content)
			pin, err := OpenStore(path).Load()
			if pin != nil || !errors.Is(err, ErrPinUnreadable) {
				t.Fatalf("Load = %v, %v; want nil, ErrPinUnreadable", pin, err)
			}
		})
	}
}

func TestPinRoundTrip(t *testing.T) {
	path := statePath(t)
	want := samplePin(t)
	if err := OpenStore(path).SavePin(want); err != nil {
		t.Fatal(err)
	}
	got, err := restart(path).Load()
	if err != nil || got == nil {
		t.Fatalf("Load = %v, %v", got, err)
	}
	if !got.PinnedAt.Equal(want.PinnedAt) {
		t.Fatalf("PinnedAt = %v, want %v", got.PinnedAt, want.PinnedAt)
	}
	got.PinnedAt = want.PinnedAt
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("pin changed on the way through disk:\n got %+v\nwant %+v", *got, want)
	}
}

func TestSavePinRefusesPinItCouldNotReadBack(t *testing.T) {
	path := statePath(t)
	p := samplePin(t)
	p.Fingerprint = strings.Repeat("0", 32)
	if err := OpenStore(path).SavePin(p); err == nil {
		t.Fatal("SavePin accepted a pin whose fingerprint does not match its bundle")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused pin must not touch the file: %v", err)
	}
}

func TestHighWaterNeverMovesBack(t *testing.T) {
	path := statePath(t)
	s := OpenStore(path)
	if got := s.Now(t0); !got.Equal(t0) {
		t.Fatalf("Now(10:00) = %v", got)
	}
	earlier := t0.Add(-time.Hour)
	if got := s.Now(earlier); !got.Equal(t0) {
		t.Fatalf("Now(09:00) = %v, want 10:00", got)
	}
	if got := restart(path).Now(earlier); !got.Equal(t0) {
		t.Fatalf("after restart Now(09:00) = %v, want 10:00", got)
	}
}

func TestObserveIssuedAtRaisesHighWater(t *testing.T) {
	s := OpenStore(statePath(t))
	s.Now(t0)
	s.ObserveIssuedAt(t0.Add(time.Hour))
	if got := s.Now(t0); !got.Equal(t0.Add(time.Hour)) {
		t.Fatalf("Now = %v, want 11:00", got)
	}
}

func TestHighWaterFlushIsRateLimited(t *testing.T) {
	path := statePath(t)
	s := OpenStore(path)
	s.Now(t0)
	s.Now(t0.Add(30 * time.Second))
	if got := fileState(t, path).HighWater; !got.Equal(t0) {
		t.Fatalf("30s later the file has %v; it should still be 10:00", got)
	}
	s.Now(t0.Add(time.Minute))
	if got := fileState(t, path).HighWater; !got.Equal(t0.Add(time.Minute)) {
		t.Fatalf("a minute later the file has %v", got)
	}
}

func TestClaimWritesHighWaterImmediately(t *testing.T) {
	path := statePath(t)
	s := OpenStore(path)
	s.Now(t0)
	s.Now(t0.Add(20 * time.Second))
	if err := s.ClaimApproval("a", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := fileState(t, path).HighWater; !got.Equal(t0.Add(20 * time.Second)) {
		t.Fatalf("file high-water after a claim = %v", got)
	}
}

func TestReplayRejected(t *testing.T) {
	s := OpenStore(statePath(t))
	if err := s.ClaimApproval("a", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimApproval("a", t0.Add(time.Hour)); !errors.Is(err, ErrReplayed) {
		t.Fatalf("second claim = %v, want ErrReplayed", err)
	}
	if err := s.ClaimApproval("b", t0.Add(time.Hour)); err != nil {
		t.Fatalf("a different approval must still be claimable: %v", err)
	}
}

func TestReplaySurvivesRestart(t *testing.T) {
	path := statePath(t)
	if err := OpenStore(path).ClaimApproval("a", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := restart(path).ClaimApproval("a", t0.Add(time.Hour)); !errors.Is(err, ErrReplayed) {
		t.Fatalf("claim after restart = %v, want ErrReplayed", err)
	}
}

func TestReplayPruned(t *testing.T) {
	path := statePath(t)
	s := OpenStore(path)
	s.Now(t0)
	for id, exp := range map[string]time.Time{
		"expired":     t0.Add(30 * time.Minute),
		"expires-now": t0.Add(time.Hour),
	} {
		if err := s.ClaimApproval(id, exp); err != nil {
			t.Fatal(err)
		}
	}
	s.ObserveIssuedAt(t0.Add(time.Hour))
	if err := s.ClaimApproval("live", t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := fileState(t, path).Approvals
	if len(got) != 1 || got["live"].IsZero() {
		t.Fatalf("approvals on disk = %v; want only \"live\" (entries at or before high-water are dropped)", got)
	}
}

func TestReplayConcurrentClaim(t *testing.T) {
	s := OpenStore(statePath(t))
	var wins, replays atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := s.ClaimApproval("same", t0.Add(time.Hour)); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrReplayed):
				replays.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || replays.Load() != 99 {
		t.Fatalf("wins=%d replays=%d, want 1 and 99", wins.Load(), replays.Load())
	}
}

func TestClearPinKeepsClockAndReplayList(t *testing.T) {
	path := statePath(t)
	s := OpenStore(path)
	if err := s.SavePin(samplePin(t)); err != nil {
		t.Fatal(err)
	}
	s.Now(t0)
	if err := s.ClaimApproval("a", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearPin("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	s = restart(path)
	if pin, err := s.Load(); pin != nil || err != nil {
		t.Fatalf("Load after clear = %v, %v", pin, err)
	}
	if got := s.ExpectFingerprint(); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("ExpectFingerprint = %q", got)
	}
	if got := s.Now(t0.Add(-time.Hour)); !got.Equal(t0) {
		t.Fatalf("clearing the pin moved the clock back to %v", got)
	}
	if err := s.ClaimApproval("a", t0.Add(time.Hour)); !errors.Is(err, ErrReplayed) {
		t.Fatalf("clearing the pin forgot a used approval: %v", err)
	}
}

func TestSavePinConsumesExpectedFingerprint(t *testing.T) {
	s := OpenStore(statePath(t))
	if err := s.ClearPin("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePin(samplePin(t)); err != nil {
		t.Fatal(err)
	}
	if got := s.ExpectFingerprint(); got != "" {
		t.Fatalf("ExpectFingerprint after the pin landed = %q, want empty", got)
	}
}

func TestResetHighWater(t *testing.T) {
	path := statePath(t)
	s := OpenStore(path)
	s.Now(t0)
	back := t0.Add(-2 * time.Hour)
	if err := s.ResetHighWater(back); err != nil {
		t.Fatal(err)
	}
	if got := restart(path).Now(back); !got.Equal(back) {
		t.Fatalf("Now after reset = %v, want %v", got, back)
	}
}

func TestUnreadableFileIsNeverOverwrittenByRoutineWrites(t *testing.T) {
	path := statePath(t)
	corrupt := []byte("not json")
	writeRaw(t, path, corrupt)
	s := OpenStore(path)

	if err := s.ClaimApproval("a", t0.Add(time.Hour)); !errors.Is(err, ErrPinUnreadable) {
		t.Fatalf("ClaimApproval = %v, want ErrPinUnreadable", err)
	}
	if err := s.ResetHighWater(t0); !errors.Is(err, ErrPinUnreadable) {
		t.Fatalf("ResetHighWater = %v, want ErrPinUnreadable", err)
	}
	if got := s.Now(t0); !got.Equal(t0) {
		t.Fatalf("Now = %v", got)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, corrupt) {
		t.Fatalf("a routine write replaced the unreadable file with %q; that would turn \"refuse\" into \"no pin\"", got)
	}

	if err := s.ClearPin("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("ClearPin must be able to repair it: %v", err)
	}
	if pin, err := s.Load(); pin != nil || err != nil {
		t.Fatalf("Load after repair = %v, %v", pin, err)
	}
}

// The `trust reset` command runs in a second process while the agent keeps
// its own copy; the agent must pick up the change, not write its old pin back.
func TestChangeByAnotherProcessIsNotOverwritten(t *testing.T) {
	path := statePath(t)
	agent := OpenStore(path)
	if err := agent.SavePin(samplePin(t)); err != nil {
		t.Fatal(err)
	}
	cli := &Store{path: path}
	if err := cli.ClearPin("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := cli.ResetHighWater(t0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	if pin, err := agent.Load(); pin != nil || err != nil {
		t.Fatalf("agent still sees the cleared pin: %v, %v", pin, err)
	}
	if err := agent.ClaimApproval("a", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	st := fileState(t, path)
	if st.Pin != nil || st.ExpectFingerprint != "0123456789abcdef0123456789abcdef" || !st.HighWater.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("the agent's write undid the other process's change: %+v", st)
	}
}

func TestFileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	path := statePath(t)
	if err := OpenStore(path).SavePin(samplePin(t)); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", p, got, want)
		}
	}
	if _, err := os.Stat(path + ".partial"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file left behind: %v", err)
	}
}

func TestOpenStoreSharesOneStorePerPath(t *testing.T) {
	path := statePath(t)
	if OpenStore(path) != OpenStore(filepath.Join(filepath.Dir(path), ".", "state.json")) {
		t.Fatal("the same path opened twice gave two stores, so their mutexes would not protect each other")
	}
}

func TestDefaultStorePathIsUnderDataDir(t *testing.T) {
	if got := DefaultStorePath(); filepath.Base(got) != "state.json" || filepath.Base(filepath.Dir(got)) != "opsign" {
		t.Fatalf("DefaultStorePath = %q", got)
	}
}
