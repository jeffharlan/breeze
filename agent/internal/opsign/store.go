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
	// ErrReplayed covers an approval on the used list and one so old that the
	// list has already forgotten it (see state.PruneFloor).
	ErrReplayed = errors.New("opsign: approval already used")
	// ErrUnexpectedBundle means the bundle offered to SavePin is not the one the
	// administrator named in ClearPin.
	ErrUnexpectedBundle = errors.New("opsign: bundle is not the one the administrator expects")
)

// DefaultStorePath is a var so tests can point the agent at a temp directory.
var DefaultStorePath = func() string {
	return filepath.Join(config.GetDataDir(), "opsign", "state.json")
}

// highWaterFlushEvery is how far trusted time must advance past what is on
// disk before a clock reading alone is written out. Advancing by the clock
// (not by wall time) keeps a stuck or rolled-back clock from causing writes.
const highWaterFlushEvery = time.Minute

const (
	lockWait  = 5 * time.Second
	lockRetry = 10 * time.Millisecond
)

var errLockBusy = errors.New("opsign: state lock is busy")

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
	// PruneFloor is the latest expiry ever dropped from Approvals. It never
	// decreases, so ResetHighWater cannot make a dropped approval claimable
	// again: anything expiring at or before it is refused as replayed.
	PruneFloor time.Time `json:"pruneFloor"`
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
	}
	if st.Approvals == nil {
		st.Approvals = map[string]time.Time{}
	}
	var pinErr error
	if st.Pin != nil {
		if pinErr = st.Pin.check(); pinErr != nil {
			// The clock and used list parsed fine; keep them so a later ClearPin
			// or SavePin cannot write zeros over them.
			st.Pin, st.ExpectFingerprint = nil, ""
		}
	}
	s.st, s.loadErr, s.flushedHighWater = st, nil, st.HighWater
	if pinErr != nil {
		s.loadErr = unreadable(pinErr)
	}
}

func unreadable(err error) error { return fmt.Errorf("%w: %v", ErrPinUnreadable, err) }

// fail marks a file that did not parse unreadable but keeps the clock and the
// used-approval list this process already holds.
func (s *Store) fail(err error) {
	s.loadErr = unreadable(err)
	s.st = state{HighWater: s.st.HighWater, Approvals: s.st.Approvals, PruneFloor: s.st.PruneFloor}
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

// lockFile takes an exclusive advisory lock on a sidecar file, retrying for up
// to wait (0 = one try). Another process (the CLI, the watchdog) doing its own
// read-modify-write would otherwise lose one of the two updates, and a lost
// claim is a replayable approval. Closing the returned handle releases it.
func (s *Store) lockFile(wait time.Duration) (unlock func(), err error) {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := tryLock(f)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, errLockBusy) || !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, err
		}
		time.Sleep(lockRetry)
	}
}

// begin takes the in-process mutex and the file lock, then re-reads the file,
// for a call that reads, changes and writes the state.
func (s *Store) begin() (end func(), err error) {
	s.mu.Lock()
	unlock, err := s.lockFile(lockWait)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.refresh()
	return func() { unlock(); s.mu.Unlock() }, nil
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

// renameFile and renameSleep let tests inject rename failures without waiting.
var (
	renameFile  = os.Rename
	renameSleep = time.Sleep
)

const (
	renameAttempts = 6
	renameBackoff  = 25 * time.Millisecond
)

// renameWithRetry follows internal/config's helper: on Windows a rename onto a
// file another process holds open (antivirus, a reader without share-delete)
// fails until that process lets go. Elsewhere a failure repeats and the retries
// only delay the error by under a second.
func renameWithRetry(from, to string) error {
	var err error
	for attempt := 0; attempt < renameAttempts; attempt++ {
		if attempt > 0 {
			renameSleep(renameBackoff << (attempt - 1))
		}
		if err = renameFile(from, to); err == nil {
			return nil
		}
	}
	return err
}

// writeFileAtomic is internal/config's atomicWriteFile: temp file, fsync,
// rename, so a crash leaves the old file or the new one and never a
// half-written one (which would read as an unreadable pin).
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
		err = renameWithRetry(tmp, path)
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

// SavePin replaces the pin and consumes the fingerprint ClearPin asked for. It
// refuses an unreadable file (ClearPin is the one repair path), a bundle other
// than the expected one, and a pin Load would later reject, which would lock
// the device out of Tier A.
func (s *Store) SavePin(p Pin) error {
	if err := p.check(); err != nil {
		return fmt.Errorf("opsign: refusing to save an unreadable pin: %w", err)
	}
	end, err := s.begin()
	if err != nil {
		return err
	}
	defer end()
	if s.loadErr != nil {
		return s.loadErr
	}
	if want := s.st.ExpectFingerprint; want != "" && p.Fingerprint != want {
		return ErrUnexpectedBundle
	}
	return s.update(func(st *state) { st.Pin, st.ExpectFingerprint = &p, "" })
}

// ClearPin removes the pin (and repairs an unreadable file) and records which
// bundle may be pinned next; "" allows any. High-water time and used approvals
// are kept, so clearing a pin cannot revive a spent approval.
func (s *Store) ClearPin(expectFingerprint string) error {
	end, err := s.begin()
	if err != nil {
		return err
	}
	defer end()
	return s.update(func(st *state) { st.Pin, st.ExpectFingerprint = nil, expectFingerprint })
}

// ExpectFingerprint is the fingerprint set by ClearPin, or "".
func (s *Store) ExpectFingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return s.st.ExpectFingerprint
}

// HighWater is the trusted-time floor on disk, for `trust show`. Unlike Now it
// never writes.
func (s *Store) HighWater() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return s.st.HighWater
}

// raise lifts high-water time to t and writes it out once it is a minute ahead
// of the file, if the file lock is free. A skipped or failed write is retried by
// the next call, and ClaimApproval reports its own write errors.
func (s *Store) raise(t time.Time) {
	if t.After(s.st.HighWater) {
		s.st.HighWater = t.UTC()
	}
	if s.loadErr != nil || s.st.HighWater.Sub(s.flushedHighWater) < highWaterFlushEvery {
		return
	}
	mine := s.st.HighWater
	unlock, err := s.lockFile(0)
	if err != nil {
		return
	}
	defer unlock()
	s.refresh()
	if s.loadErr != nil {
		return
	}
	if mine.After(s.st.HighWater) {
		s.st.HighWater = mine
	}
	_ = s.write(s.st)
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
// returns ErrReplayed if it already was, or if it expires at or before
// PruneFloor. It drops entries high-water time has passed, and writes
// high-water time along with the claim.
func (s *Store) ClaimApproval(approvalID string, expiresAt time.Time) error {
	end, err := s.begin()
	if err != nil {
		return err
	}
	defer end()
	if s.loadErr != nil {
		return s.loadErr
	}
	if _, used := s.st.Approvals[approvalID]; used || !expiresAt.After(s.st.PruneFloor) {
		return ErrReplayed
	}
	return s.update(func(st *state) {
		maps.DeleteFunc(st.Approvals, func(_ string, exp time.Time) bool {
			if exp.After(st.HighWater) {
				return false
			}
			if exp.After(st.PruneFloor) {
				st.PruneFloor = exp
			}
			return true
		})
		st.Approvals[approvalID] = expiresAt.UTC()
	})
}

// ResetHighWater sets high-water time to clock even if that is earlier. It is
// the one way back, for a local administrator recovering from a clock that ran
// far ahead (`trust reset`). It leaves PruneFloor alone, so approvals already
// dropped stay refused.
func (s *Store) ResetHighWater(clock time.Time) error {
	end, err := s.begin()
	if err != nil {
		return err
	}
	defer end()
	if s.loadErr != nil {
		return s.loadErr
	}
	return s.update(func(st *state) { st.HighWater = clock.UTC() })
}
