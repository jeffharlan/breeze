package opsign

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/breeze-rmm/agent/internal/logging"
)

var log = logging.L("opsign")

var (
	// ErrPinIdentityMissing means the agent does not know its own device or org
	// yet (not enrolled). Pinning waits for a later offer; nothing is lost.
	ErrPinIdentityMissing = errors.New("opsign: device identity is not known yet, cannot pin a trust bundle")
	// ErrBundleRejected covers every bundle that is malformed, not signed well
	// enough, or not a valid successor to the pinned one.
	ErrBundleRejected = errors.New("opsign: trust bundle rejected")
)

// Identity is what the device pins about itself. It comes from the agent's own
// config and operating system, never from the bundle.
type Identity struct{ DeviceID, OrgID, Hostname string }

// osHostname is a variable so tests can stand in for the machine's name.
var osHostname = os.Hostname

// LocalIdentity pairs the enrolled device and org with this machine's hostname,
// lower-cased because approvals spell hostnames in lower case.
func LocalIdentity(deviceID, orgID string) (Identity, error) {
	host, err := osHostname()
	if err != nil {
		return Identity{}, fmt.Errorf("opsign: local hostname: %w", err)
	}
	return Identity{DeviceID: deviceID, OrgID: orgID, Hostname: strings.ToLower(host)}, nil
}

// applyMu makes read-pin-then-save one step. The start-up file and a heartbeat
// can offer bundles at the same moment, and two changes judged against the same
// old pin would otherwise let the older bundle land last.
var applyMu sync.Mutex

func rejected(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBundleRejected, fmt.Sprintf(format, args...))
}

// maxBundleSignatures bounds the verification work a relayed bundle can cause.
// A genuine one carries about one signature per admin.
const maxBundleSignatures = 64

// adminSignatures returns the signatures that count towards signer's threshold:
// one per distinct admin key of signer that verifies over canonical. Signatures
// by approvers, unknown keys and bad signatures are skipped, not errors.
func adminSignatures(signer Bundle, canonical []byte, sigs []BundleSig) []BundleSig {
	admins := map[string]string{}
	for _, k := range signer.Keys {
		if k.Role == RoleAdmin {
			admins[k.KeyID] = k.SPKIB64
		}
	}
	var good []BundleSig
	for _, sig := range sigs {
		spki, ok := admins[sig.KeyID]
		if !ok {
			continue
		}
		if VerifyES256(spki, canonical, sig.SignatureB64) == nil {
			good = append(good, sig)
			delete(admins, sig.KeyID)
		}
	}
	return good
}

// ApplyBundle pins sb when nothing is pinned yet, or replaces the pin with sb
// when the pinned bundle's admins signed the change (spec section 2). It
// reports whether the pin changed; offering the pinned bundle again is a quiet
// no-op. An unreadable pin is returned as an error and never treated as "no
// pin", so it cannot be overwritten by a first pin. Only the Pin's bundle
// changes on a replacement: its identity is never rewritten here.
func ApplyBundle(s *Store, sb SignedBundle, id Identity, now time.Time) (applied bool, err error) {
	canonical, err := decodeB64(sb.CanonicalB64)
	if err != nil {
		return false, rejected("%v", err)
	}
	b, err := ParseBundle(canonical)
	if err != nil {
		return false, rejected("%v", err)
	}
	if len(sb.Signatures) > maxBundleSignatures {
		return false, rejected("%d signatures, at most %d are accepted", len(sb.Signatures), maxBundleSignatures)
	}
	fingerprint := Fingerprint(canonical)

	applyMu.Lock()
	defer applyMu.Unlock()
	pin, err := s.Load()
	if err != nil {
		return false, err
	}

	next := Pin{Fingerprint: fingerprint, PinnedAt: now.UTC()}
	var authorising []BundleSig
	logMsg := "operator trust bundle pinned"
	switch {
	case pin == nil:
		if id.DeviceID == "" || id.OrgID == "" || id.Hostname == "" {
			return false, ErrPinIdentityMissing
		}
		authorising = adminSignatures(b, canonical, sb.Signatures)
		if len(authorising) < b.Threshold {
			return false, rejected("%d valid admin signatures, its own threshold is %d", len(authorising), b.Threshold)
		}
		next.DeviceID, next.OrgID, next.Hostname, next.PartnerID = id.DeviceID, id.OrgID, id.Hostname, b.PartnerID
	case pin.Fingerprint == fingerprint:
		return false, nil
	default:
		pinnedCanonical, err := decodeB64(pin.Bundle.CanonicalB64)
		if err != nil {
			return false, unreadable(err)
		}
		pinned, err := ParseBundle(pinnedCanonical)
		if err != nil {
			return false, unreadable(err)
		}
		if b.PartnerID != pinned.PartnerID {
			return false, rejected("partnerId differs from the pinned bundle")
		}
		if b.Epoch <= pinned.Epoch {
			return false, rejected("epoch %d does not exceed the pinned epoch %d", b.Epoch, pinned.Epoch)
		}
		authorising = adminSignatures(pinned, canonical, sb.Signatures)
		if len(authorising) < pinned.Threshold {
			return false, rejected("%d valid signatures from the pinned admins, the pinned threshold is %d", len(authorising), pinned.Threshold)
		}
		// Otherwise a change could pass the old admins and leave a bundle nobody
		// can ever change again.
		if own := adminSignatures(b, canonical, sb.Signatures); len(own) < b.Threshold {
			return false, rejected("%d valid signatures from its own admins, its own threshold is %d", len(own), b.Threshold)
		}
		next.DeviceID, next.OrgID, next.Hostname, next.PartnerID = pin.DeviceID, pin.OrgID, pin.Hostname, pin.PartnerID
		logMsg = "operator trust bundle changed"
	}

	// Only the signatures that authorised the pin are kept, so a relayed bundle
	// cannot make the agent store whatever else it carries.
	next.Bundle = SignedBundle{CanonicalB64: sb.CanonicalB64, Signatures: authorising}
	if err := s.SavePin(next); err != nil {
		return false, err
	}
	log.Info(logMsg, "fingerprint", fingerprint, "epoch", b.Epoch, "mode", string(b.Mode), "partnerId", b.PartnerID)
	return true, nil
}
