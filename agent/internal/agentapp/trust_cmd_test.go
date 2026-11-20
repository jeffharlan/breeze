package agentapp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/breeze-rmm/agent/internal/config"
	"github.com/breeze-rmm/agent/internal/opsign"
)

func asAdministrator(t *testing.T, elevated bool) {
	t.Helper()
	prev := trustIsElevated
	trustIsElevated = func() bool { return elevated }
	t.Cleanup(func() { trustIsElevated = prev })
}

// trustFingerprint is the bundle's fingerprint, taken from its own bytes.
func trustFingerprint(t *testing.T, sb opsign.SignedBundle) string {
	t.Helper()
	canonical, err := base64.StdEncoding.DecodeString(sb.CanonicalB64)
	if err != nil {
		t.Fatal(err)
	}
	return opsign.Fingerprint(canonical)
}

func writeTrustBundleFile(t *testing.T, path string, sb opsign.SignedBundle) {
	t.Helper()
	data, err := json.Marshal(sb)
	if err != nil {
		t.Fatal(err)
	}
	writeTrustFile(t, path, data)
}

// runTrust runs `trust <args>` against store and returns what it printed.
func runTrust(t *testing.T, store *opsign.Store, cfg *config.Config, trustFile string, args ...string) (string, error) {
	t.Helper()
	cmd := newTrustCommand(
		func() *opsign.Store { return store },
		func() (*config.Config, string, error) { return cfg, trustFile, nil },
	)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func enrolledConfig() *config.Config {
	return &config.Config{DeviceID: trustTestDevice, OrgID: trustTestOrg}
}

// pinTrustBundle pins sb into store as an enrolled device.
func pinTrustBundle(t *testing.T, store *opsign.Store, filePath string, sb opsign.SignedBundle) {
	t.Helper()
	writeTrustBundleFile(t, filePath, sb)
	if err := pinOperatorTrustFile(store, filePath, enrolledConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestTrustCommandRegistered(t *testing.T) {
	for _, sub := range []string{"show", "reset"} {
		cmd, _, err := rootCmd.Find([]string{"trust", sub})
		if err != nil || cmd.Name() != sub {
			t.Fatalf("trust %s is not registered", sub)
		}
	}
}

func TestTrustShowNoPin(t *testing.T) {
	asAdministrator(t, true)
	store, statePath, filePath := trustTestPaths(t)
	out, err := runTrust(t, store, enrolledConfig(), filePath, "show")
	if err != nil {
		t.Fatal(err)
	}
	if out != "mode: off\n" {
		t.Fatalf("output = %q", out)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("show wrote a state file (stat err = %v)", err)
	}
}

func TestTrustShowNoPinWithoutDeviceIDSaysWhy(t *testing.T) {
	asAdministrator(t, true)
	store, _, filePath := trustTestPaths(t)
	out, err := runTrust(t, store, &config.Config{OrgID: trustTestOrg}, filePath, "show")
	if err != nil {
		t.Fatal(err)
	}
	want := "mode: off\nthis agent has no device id yet, so it cannot pin a trust bundle until it has one\n"
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestTrustShowPinned(t *testing.T) {
	asAdministrator(t, true)
	store, _, filePath := trustTestPaths(t)
	sb := signedTrustBundle(t)
	pinTrustBundle(t, store, filePath, sb)
	highWater := time.Date(2026, 11, 19, 10, 30, 0, 0, time.UTC)
	if err := store.ResetHighWater(highWater); err != nil {
		t.Fatal(err)
	}

	fp := trustFingerprint(t, sb)
	groups := make([]string, 0, 8)
	for i := 0; i < 32; i += 4 {
		groups = append(groups, fp[i:i+4])
	}
	pin, err := store.Load()
	if err != nil || pin == nil {
		t.Fatalf("pin=%v err=%v", pin, err)
	}
	want := strings.Join([]string{
		"mode: audit",
		"epoch: 1",
		"fingerprint: " + strings.Join(groups, " "),
		"partner: " + trustTestPartner,
		"device: " + trustTestDevice,
		"org: " + trustTestOrg,
		"hostname: " + pin.Hostname,
		"highWater: 2026-11-19T10:30:00Z",
		"key " + sb.Signatures[0].KeyID + " admin admin",
		"",
	}, "\n")

	out, err := runTrust(t, store, enrolledConfig(), filePath, "show")
	if err != nil {
		t.Fatal(err)
	}
	if out != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out, want)
	}
}

// A clock that once ran ahead leaves the stored time ahead, and every approval
// then looks expired; show must say so, or it looks like nothing is wrong.
func TestTrustShowSaysWhenStoredTimeIsAhead(t *testing.T) {
	asAdministrator(t, true)
	store, _, filePath := trustTestPaths(t)
	pinTrustBundle(t, store, filePath, signedTrustBundle(t))

	out, err := runTrust(t, store, enrolledConfig(), filePath, "show")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ahead") {
		t.Fatalf("a stored time that is not ahead was reported: %q", out)
	}
	if err := store.ResetHighWater(time.Now().Add(30 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	out, err = runTrust(t, store, enrolledConfig(), filePath, "show")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ahead of this machine's clock") || !strings.Contains(out, "trust reset") {
		t.Fatalf("output = %q, want the stored time reported ahead with the way out", out)
	}
}

func TestTrustShowUnreadableExit2(t *testing.T) {
	store, statePath, filePath := trustTestPaths(t)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTrustFile(t, statePath, []byte("not json"))

	asAdministrator(t, true)
	out, err := runTrust(t, store, enrolledConfig(), filePath, "show")
	if err == nil || exitCodeFor(err) != 2 {
		t.Fatalf("err = %v (exit %d), want exit 2", err, exitCodeFor(err))
	}
	if out != "" {
		t.Fatalf("an unreadable pin printed %q on stdout", out)
	}
	if strings.Contains(err.Error(), "administrator") {
		t.Fatalf("an elevated run was told to be elevated: %v", err)
	}

	asAdministrator(t, false)
	_, err = runTrust(t, store, enrolledConfig(), filePath, "show")
	if err == nil || exitCodeFor(err) != 2 || !strings.Contains(err.Error(), "administrator") {
		t.Fatalf("a non-elevated run: err = %v (exit %d), want exit 2 and the administrator hint", err, exitCodeFor(err))
	}
}

func TestTrustResetRequiresExpect(t *testing.T) {
	asAdministrator(t, true)
	store, statePath, filePath := trustTestPaths(t)
	pinTrustBundle(t, store, filePath, signedTrustBundle(t))
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runTrust(t, store, enrolledConfig(), filePath, "reset"); err == nil {
		t.Fatal("reset without --expect succeeded")
	}
	after, _ := os.ReadFile(statePath)
	if !bytes.Equal(before, after) {
		t.Fatal("reset without --expect changed the state file")
	}
}

func TestTrustResetRequiresElevation(t *testing.T) {
	asAdministrator(t, false)
	store, statePath, filePath := trustTestPaths(t)
	_, err := runTrust(t, store, enrolledConfig(), filePath, "reset", "--expect", strings.Repeat("ab", 16))
	if err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Fatalf("err = %v, want an administrator refusal", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("a refused reset wrote the state file (stat err = %v)", err)
	}
}

func TestTrustResetNormalizesExpect(t *testing.T) {
	asAdministrator(t, true)
	const fp = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name, in string
		ok       bool
	}{
		{"plain", fp, true},
		{"groups of four with spaces", "0123 4567 89ab cdef 0123 4567 89ab cdef", true},
		{"dashes", "0123-4567-89ab-cdef-0123-4567-89ab-cdef", true},
		{"colons", "0123:4567:89ab:cdef:0123:4567:89ab:cdef", true},
		{"upper case", strings.ToUpper(fp), true},
		{"surrounding whitespace", "  " + fp + "\n", true},
		{"no-break spaces and a non-ASCII dash from a web page", "0123 4567‐89ab cdef" + fp[16:], true},
		{"empty", "", false},
		{"too short", fp[:31], false},
		{"too long", fp + "0", false},
		{"not hex", "0123456789abcdef0123456789abcdeg", false},
		{"a 64 char digest", strings.Repeat(fp, 2), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, statePath, filePath := trustTestPaths(t)
			_, err := runTrust(t, store, enrolledConfig(), filePath, "reset", "--expect", tc.in)
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				if _, got, err := store.LoadTrust(); err != nil || got != fp {
					t.Fatalf("stored expectation = %q (%v), want the normalized %q", got, err, fp)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted a value that is not a 32-hex fingerprint")
			}
			if _, err := os.Stat(statePath); !os.IsNotExist(err) {
				t.Fatalf("a refused value wrote the state file (stat err = %v)", err)
			}
		})
	}
}

func TestTrustResetPinsMatchingFile(t *testing.T) {
	asAdministrator(t, true)
	store, _, filePath := trustTestPaths(t)
	pinTrustBundle(t, store, filePath, signedTrustBundle(t))

	next := signedTrustBundle(t)
	writeTrustBundleFile(t, filePath, next)
	fp := trustFingerprint(t, next)
	out, err := runTrust(t, store, enrolledConfig(), filePath, "reset", "--expect", strings.ToUpper(fp[:16]+" "+fp[16:]))
	if err != nil {
		t.Fatal(err)
	}
	pin, err := store.Load()
	if err != nil || pin == nil {
		t.Fatalf("pin=%v err=%v", pin, err)
	}
	if pin.Fingerprint != fp {
		t.Fatalf("pinned %s, want the file's bundle %s", pin.Fingerprint, fp)
	}
	if _, got, err := store.LoadTrust(); err != nil || got != "" {
		t.Fatalf("the expectation survived the pin: %q, %v", got, err)
	}
	if !strings.Contains(out, "pinned the bundle in "+filePath) {
		t.Fatalf("output = %q", out)
	}
}

func TestTrustResetIgnoresMismatchedFile(t *testing.T) {
	asAdministrator(t, true)
	store, _, filePath := trustTestPaths(t)
	pinTrustBundle(t, store, filePath, signedTrustBundle(t))

	expected := trustFingerprint(t, signedTrustBundle(t))
	writeTrustBundleFile(t, filePath, signedTrustBundle(t))
	out, err := runTrust(t, store, enrolledConfig(), filePath, "reset", "--expect", expected)
	if err != nil {
		t.Fatalf("a file that does not match must not fail the reset: %v", err)
	}
	pin, err := store.Load()
	if err != nil || pin != nil {
		t.Fatalf("pin=%v err=%v, want the pin cleared and nothing pinned", pin, err)
	}
	if _, got, err := store.LoadTrust(); err != nil || got != expected {
		t.Fatalf("expectation = %q (%v), want %q", got, err, expected)
	}
	if !strings.Contains(out, "operator-trust.json was not used") || !strings.Contains(out, "heartbeat") {
		t.Fatalf("output = %q", out)
	}
}

func TestTrustResetWithoutFileWaitsForHeartbeat(t *testing.T) {
	asAdministrator(t, true)
	store, _, filePath := trustTestPaths(t)
	out, err := runTrust(t, store, enrolledConfig(), filePath, "reset", "--expect", strings.Repeat("ab", 16))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "next matching bundle") || !strings.Contains(out, "heartbeat") ||
		!strings.Contains(out, "refuses every command that needs operator approval, and every update") {
		t.Fatalf("output = %q", out)
	}
}

// Until the awaited bundle lands the gate refuses Tier A, so show must not say
// "mode: off".
func TestTrustShowPendingAfterReset(t *testing.T) {
	asAdministrator(t, true)
	store, _, filePath := trustTestPaths(t)
	fp := strings.Repeat("ab", 16)
	if _, err := runTrust(t, store, enrolledConfig(), filePath, "reset", "--expect", fp); err != nil {
		t.Fatal(err)
	}
	out, err := runTrust(t, store, enrolledConfig(), filePath, "show")
	if err != nil {
		t.Fatal(err)
	}
	want := "mode: pending\nawaiting fingerprint: " + groupFingerprint(fp) + "\n" +
		"every command that needs operator approval, and every update, is refused until the bundle with this fingerprint is pinned\n"
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestTrustResetResetsHighWater(t *testing.T) {
	asAdministrator(t, true)
	store, _, filePath := trustTestPaths(t)
	if err := store.ResetHighWater(time.Now().Add(30 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	if _, err := runTrust(t, store, enrolledConfig(), filePath, "reset", "--expect", strings.Repeat("ab", 16)); err != nil {
		t.Fatal(err)
	}
	got := store.HighWater()
	if got.Before(before.Add(-time.Second)) || got.After(time.Now().Add(time.Second)) {
		t.Fatalf("high-water = %v, want the clock at the time of the reset (%v)", got, before)
	}
}

func TestTrustResetRepairsAnUnreadableStateFile(t *testing.T) {
	asAdministrator(t, true)
	store, statePath, filePath := trustTestPaths(t)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTrustFile(t, statePath, []byte("not json"))
	if pin, err := store.Load(); pin != nil || !errors.Is(err, opsign.ErrPinUnreadable) {
		t.Fatalf("setup: pin=%v err=%v, want ErrPinUnreadable", pin, err)
	}

	if _, err := runTrust(t, store, enrolledConfig(), filePath, "reset", "--expect", strings.Repeat("ab", 16)); err != nil {
		t.Fatal(err)
	}
	if pin, err := store.Load(); pin != nil || err != nil {
		t.Fatalf("after reset: pin=%v err=%v, want a readable file with no pin", pin, err)
	}
}

func TestTrustResetHelpNamesTheSideEffects(t *testing.T) {
	reset, _, err := newTrustCommand(nil, nil).Find([]string{"reset"})
	if err != nil {
		t.Fatal(err)
	}
	help := strings.Join(strings.Fields(reset.Long), " ")
	for _, want := range []string{
		"unreadable",
		"zeroes the stored clock, the used-approval list and the prune floor",
		"on or before the old prune floor are refused for up to 24 hours",
		"never decreases",
		"Until then the agent refuses every command that needs operator approval, and every update, in every mode",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("reset help does not say %q", want)
		}
	}
}
