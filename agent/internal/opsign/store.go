package opsign

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/breeze-rmm/agent/internal/config"
)

var (
	// ErrPinUnreadable means a state file exists but cannot be trusted. The
	// gate refuses Tier A for it in every mode: treating it as "no pin" would let
	// whoever corrupts the file switch the check off.
	ErrPinUnreadable = errors.New("opsign: pin unreadable")
	ErrReplayed      = errors.New("opsign: approval already used")
)

// DefaultStorePath is a var so tests can point the agent at a temp directory.
var DefaultStorePath = func() string {
	return filepath.Join(config.GetDataDir(), "opsign", "state.json")
}

// highWaterFlushEvery is how far trusted time must advance past what is on
// disk before a clock reading alone is written out. Advancing by the clock
// (not by wall time) keeps a stuck or rolled-back clock from causing writes.
const highWaterFlushEvery = time.Minute

// Pin is the trust bundle a device accepted, with the identity it was pinned
// under. Identity comes from the device, never from the bundle.
type Pin struct {
	Bundle      SignedBundle `json:"bundle"`
	Fingerprint string       `json:"fingerprint"`
	DeviceID    string       `json:"deviceId"`
	OrgID       string       `json:"orgId"`
	PartnerID   string       `json:"partnerId"`
	Hostname    string       `json:"hostname"`
	PinnedAt    time.Time    `json:"pinnedAt"`
}

// state is the whole file.
type state struct {
	Pin *Pin `json:"pin,omitempty"`
	// ExpectFingerprint is set by ClearPin: until a pin lands, only the bundle
	// with this fingerprint may be pinned.
	ExpectFingerprint string    `json:"expectFingerprint,omitempty"`
	HighWater         time.Time `json:"highWater"`
	// Approvals maps each used approvalId to its expiry; an entry is dropped
	// once high-water time reaches that expiry.
	Approvals map[string]time.Time `json:"approvals"`
}

var (
	storesMu sync.Mutex
	stores   = map[string]*Store{}
)

// Store keeps the pin, high-water time and used-approval list in one file.
type Store struct {
	path string
	mu   sync.Mutex

	st      state
	loadErr error // non-nil while the file exists but cannot be trusted
	// disk is what the file held when st was last synced with it.
	disk             diskImage
	synced           bool
	flushedHighWater time.Time
}

type diskImage struct {
	present bool
	data    string
}

// OpenStore returns the one Store for path, so every caller in the process
// shares one mutex.
func OpenStore(path string) *Store {
	path = filepath.Clean(path)
	storesMu.Lock()
	defer storesMu.Unlock()
	if s, ok := stores[path]; ok {
		return s
	}
	s := &Store{path: path}
	stores[path] = s
	return s
}

func (p *Pin) check() error {
	canonical, err := decodeB64(p.Bundle.CanonicalB64)
	if err != nil {
		return err
	}
	if _, err := ParseBundle(canonical); err != nil {
		return err
	}
	if Fingerprint(canonical) != p.Fingerprint {
		return errors.New("opsign: pin fingerprint does not match its bundle")
	}
	return nil
}

// refresh re-reads the file when it differs from what this Store last read or
// wrote. `breeze-agent trust reset` runs in another process, and a long-running
// agent must adopt its change instead of writing its older copy back over it.
func (s *Store) refresh() {
	data, err := os.ReadFile(s.path)
	absent := errors.Is(err, fs.ErrNotExist)
	if err != nil && !absent {
		s.fail(err)
		s.synced = false
		return
	}
	img := diskImage{present: !absent, data: string(data)}
	if s.synced && img == s.disk {
		return
	}
	s.disk, s.synced = img, true
	var st state
	if !absent {
		if err := json.Unmarshal(data, &st); err != nil {
			s.fail(err)
			return
		}
		if st.Pin != nil {
			if err := st.Pin.check(); err != nil {
				s.fail(err)
				return
			}
		}
	}
	if st.Approvals == nil {
		st.Approvals = map[string]time.Time{}
	}
	s.st, s.loadErr, s.flushedHighWater = st, nil, st.HighWater
}

// fail marks the file unreadable but keeps the clock and the used-approval
// list this process already holds.
func (s *Store) fail(err error) {
	s.loadErr = fmt.Errorf("%w: %v", ErrPinUnreadable, err)
	s.st = state{HighWater: s.st.HighWater, Approvals: s.st.Approvals}
}

// update applies fn to a copy of the state and writes it. Memory changes only
// when the write succeeded, so it never claims more than the disk holds.
func (s *Store) update(fn func(*state)) error {
	next := s.st
	next.Approvals = make(map[string]time.Time, len(s.st.Approvals)+1)
	maps.Copy(next.Approvals, s.st.Approvals)
	fn(&next)
	if err := s.write(next); err != nil {
		return err
	}
	s.st, s.loadErr = next, nil
	return nil
}

func (s *Store) write(st state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, data, 0o600); err != nil {
		return err
	}
	s.disk, s.synced, s.flushedHighWater = diskImage{present: true, data: string(data)}, true, st.HighWater
	return nil
}

// writeFileAtomic is internal/config's atomicWriteFile minus its Windows
// rename retry: temp file, fsync, rename, so a crash leaves the old file or the
// new one and never a half-written one (which would read as an unreadable pin).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".partial"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, derr := os.Open(filepath.Dir(path)); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Load returns the pin: nil, nil when there is none, ErrPinUnreadable when the
// file exists but cannot be parsed or its bundle no longer matches its fingerprint.
func (s *Store) Load() (*Pin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	if s.st.Pin == nil {
		return nil, nil
	}
	p := *s.st.Pin
	return &p, nil
}

// SavePin replaces the pin, repairing an unreadable file, and consumes the
// fingerprint ClearPin asked for. It refuses a pin Load would later reject,
// which would lock the device out of Tier A.
func (s *Store) SavePin(p Pin) error {
	if err := p.check(); err != nil {
		return fmt.Errorf("opsign: refusing to save an unreadable pin: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return s.update(func(st *state) { st.Pin, st.ExpectFingerprint = &p, "" })
}

// ClearPin removes the pin (and repairs an unreadable file) and records which
// bundle may be pinned next; "" allows any. High-water time and used approvals
// are kept, so clearing a pin cannot revive a spent approval.
func (s *Store) ClearPin(expectFingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return s.update(func(st *state) { st.Pin, st.ExpectFingerprint = nil, expectFingerprint })
}

// ExpectFingerprint is the fingerprint set by ClearPin, or "".
func (s *Store) ExpectFingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return s.st.ExpectFingerprint
}

// raise lifts high-water time to t and writes it out once it is a minute ahead
// of the file. A failed write is retried by the next call, and ClaimApproval
// reports its own write errors.
func (s *Store) raise(t time.Time) {
	if t.After(s.st.HighWater) {
		s.st.HighWater = t.UTC()
	}
	if s.loadErr == nil && s.st.HighWater.Sub(s.flushedHighWater) >= highWaterFlushEvery {
		_ = s.write(s.st)
	}
}

// Now returns the later of the local clock and the high-water time, and raises
// high-water time to it, so winding the clock back cannot revive an approval.
func (s *Store) Now(clock time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	s.raise(clock)
	return s.st.HighWater
}

// ObserveIssuedAt raises high-water time to a verified approval's issuedAt.
func (s *Store) ObserveIssuedAt(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	s.raise(t)
}

// ClaimApproval records an approval as used before its command runs, and
// returns ErrReplayed if it already was. It drops entries high-water time has
// passed, and writes high-water time along with the claim.
func (s *Store) ClaimApproval(approvalID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if s.loadErr != nil {
		return s.loadErr
	}
	if _, used := s.st.Approvals[approvalID]; used {
		return ErrReplayed
	}
	return s.update(func(st *state) {
		maps.DeleteFunc(st.Approvals, func(_ string, exp time.Time) bool { return !exp.After(st.HighWater) })
		st.Approvals[approvalID] = expiresAt.UTC()
	})
}

// ResetHighWater sets high-water time to clock even if that is earlier. It is
// the one way back, for a local administrator recovering from a clock that ran
// far ahead (`trust reset`).
func (s *Store) ResetHighWater(clock time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if s.loadErr != nil {
		return s.loadErr
	}
	return s.update(func(st *state) { st.HighWater = clock.UTC() })
}
