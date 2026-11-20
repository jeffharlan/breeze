package agentapp

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/breeze-rmm/agent/internal/config"
	"github.com/breeze-rmm/agent/internal/opsign"
	"github.com/breeze-rmm/agent/internal/privilege"
	"github.com/spf13/cobra"
)

// trustIsElevated is a variable so tests can run the commands without being root.
var trustIsElevated = privilege.IsRunningAsRoot

// exitCodeTrustUnreadable is what `trust show` exits with when the stored pin
// cannot be read, so a script can tell "no pin" (0, mode off) from "broken".
const exitCodeTrustUnreadable = 2

// loadTrustHost reads what the trust commands need from this machine: the
// agent's identity and the folder an installer leaves operator-trust.json in.
func loadTrustHost() (*config.Config, string, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, "", err
	}
	return cfg, filepath.Join(config.ConfigDir(), "operator-trust.json"), nil
}

// normalizeFingerprint turns what an administrator typed or pasted into the
// form a pin stores: 32 lower-case hex characters. SavePin compares that stored
// form exactly, so anything looser would never match.
func normalizeFingerprint(in string) (string, error) {
	s := strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.Is(unicode.Pd, r) || r == ':' {
			return -1
		}
		return r
	}, in))
	if _, err := hex.DecodeString(s); err != nil || len(s) != 32 {
		return "", errors.New("--expect must be a 32 character hex fingerprint (spaces and dashes between groups are fine)")
	}
	return s, nil
}

// groupFingerprint writes a fingerprint as 8 groups of 4, the way an operator
// compares it with the one on their phone.
func groupFingerprint(fp string) string {
	groups := make([]string, 0, 8)
	for i := 0; i+4 <= len(fp); i += 4 {
		groups = append(groups, fp[i:i+4])
	}
	return strings.Join(groups, " ")
}

// newTrustCommand builds `breeze-agent trust`. store is the pin store and local
// reads this machine's config and the operator-trust.json path; both are
// functions so tests can point them at a temp directory.
func newTrustCommand(store func() *opsign.Store, local func() (*config.Config, string, error)) *cobra.Command {
	group := &cobra.Command{Use: "trust", Short: "Inspect or reset the operator trust bundle this agent has pinned", SilenceUsage: true}
	group.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the pinned operator trust bundle",
		Long: `Print the operator trust bundle this agent has pinned: its mode, epoch, fingerprint,
who it was pinned for, the stored clock and the keys it trusts. Compare the fingerprint
with the one the operator's phone shows. Prints "mode: off" when nothing is pinned, and
"mode: pending" while a trust reset waits for its bundle; the agent then refuses every
command that needs operator approval, and every update, until that bundle is pinned.

Exits 2 when the stored pin cannot be read. The agent then refuses every command that
needs operator approval, in every mode, until "trust reset" repairs it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true // the arguments were fine; a usage dump would bury the error
			out := cmd.OutOrStdout()
			s := store()
			pin, awaiting, err := s.LoadTrust()
			var bundle opsign.Bundle
			if err == nil && pin != nil {
				bundle, err = parsePinnedBundle(pin)
			}
			if err != nil {
				msg := fmt.Sprintf("the stored operator trust pin cannot be read, so every command that needs operator approval is refused on this machine: %v. "+
					"Repair it with: breeze-agent trust reset --expect <fingerprint>", err)
				if !trustIsElevated() {
					msg += " (run as an administrator; a normal user may simply be unable to open the file)"
				}
				return &ExitCodeError{Code: exitCodeTrustUnreadable, Msg: msg}
			}
			if pin == nil && awaiting != "" {
				fmt.Fprintf(out, "mode: pending\nawaiting fingerprint: %s\n"+
					"every command that needs operator approval, and every update, is refused until the bundle with this fingerprint is pinned\n",
					groupFingerprint(awaiting))
				return nil
			}
			if pin == nil {
				fmt.Fprintln(out, "mode: off")
				if cfg, _, err := local(); err == nil && cfg.DeviceID == "" {
					fmt.Fprintln(out, "this agent has no device id yet, so it cannot pin a trust bundle until it has one")
				}
				return nil
			}
			fmt.Fprintf(out, "mode: %s\nepoch: %d\nfingerprint: %s\npartner: %s\ndevice: %s\norg: %s\nhostname: %s\nhighWater: %s\n",
				bundle.Mode, bundle.Epoch, groupFingerprint(pin.Fingerprint), pin.PartnerID, pin.DeviceID, pin.OrgID, pin.Hostname,
				s.HighWater().UTC().Format(time.RFC3339))
			for _, k := range bundle.Keys {
				fmt.Fprintf(out, "key %s %s %s\n", k.KeyID, k.Role, k.Label)
			}
			return nil
		},
	})

	var expect string
	reset := &cobra.Command{
		Use:   "reset --expect <fingerprint>",
		Short: "Clear the pinned trust bundle and accept only the one with this fingerprint",
		Long: `Clear the pinned operator trust bundle and accept only the bundle whose fingerprint you
give with --expect: 32 hex characters, with spaces or dashes between groups if you like.
Run it as an administrator. If operator-trust.json in the agent's config folder holds that
bundle it is pinned at once; otherwise the next matching bundle the server sends with a
heartbeat is pinned. Until then the agent refuses every command that needs operator
approval, and every update, in every mode, so a server that never sends the bundle
cannot leave the device unprotected.

The stored clock is set to this machine's current time, so a clock that once ran far ahead
stops making every approval look expired. Approvals already used stay on the used list, so
a reset cannot make a spent approval usable again. Two things to know:

  - If the state file was unreadable or could not be parsed, reset repairs it, and that
    zeroes the stored clock, the used-approval list and the prune floor (the latest expiry
    the used list has already forgotten).
  - If the reset moves the clock backwards, new approvals that expire on or before the old
    prune floor are refused for up to 24 hours. The floor never decreases.`,
		Example: `  breeze-agent trust reset --expect "0123 4567 89ab cdef 0123 4567 89ab cdef"`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			want, err := normalizeFingerprint(expect)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			if !trustIsElevated() {
				return errors.New("trust reset must be run as an administrator (root, or an elevated prompt on Windows)")
			}
			cfg, trustFile, err := local()
			if err != nil {
				return fmt.Errorf("read the agent config: %w", err)
			}
			s := store()
			if err := s.ClearPin(want); err != nil {
				return fmt.Errorf("clear the pin: %w", err)
			}
			now := time.Now()
			if err := s.ResetHighWater(now); err != nil {
				return fmt.Errorf("reset the stored clock: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "pin cleared; only the bundle with fingerprint %s will be accepted\nstored clock reset to %s\n",
				groupFingerprint(want), now.UTC().Format(time.RFC3339))

			applyErr := pinOperatorTrustFile(s, trustFile, cfg)
			if pin, err := s.Load(); err == nil && pin != nil {
				if pin.Fingerprint != want {
					return fmt.Errorf("another bundle (fingerprint %s) was pinned while this reset ran; run trust reset again", groupFingerprint(pin.Fingerprint))
				}
				fmt.Fprintf(out, "pinned the bundle in %s\n", trustFile)
				return nil
			}
			if applyErr != nil {
				fmt.Fprintf(out, "operator-trust.json was not used: %v\n", applyErr)
			}
			fmt.Fprintln(out, "nothing is pinned yet; the next matching bundle the server sends with a heartbeat will be pinned. "+
				"Until it is, this agent refuses every command that needs operator approval, and every update")
			return nil
		},
	}
	reset.Flags().StringVar(&expect, "expect", "", "Fingerprint of the trust bundle to accept (32 hex characters)")
	_ = reset.MarkFlagRequired("expect")
	group.AddCommand(reset)
	return group
}

// parsePinnedBundle reads the bundle inside a pin. Load already validated it, so
// a failure is not expected; it is reported as an unreadable pin, never skipped.
func parsePinnedBundle(pin *opsign.Pin) (opsign.Bundle, error) {
	canonical, err := base64.StdEncoding.DecodeString(pin.Bundle.CanonicalB64)
	if err != nil {
		return opsign.Bundle{}, err
	}
	return opsign.ParseBundle(canonical)
}
