package heartbeat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/breeze-rmm/agent/internal/opsign"
	"github.com/breeze-rmm/agent/internal/systemrestore"
)

// TestMain points the createRestorePoint seam at an inert fake for the whole
// package, so no test — including a future one that forgets
// installCheckpointRecorder — can create a REAL System Restore point on a
// Windows CI runner. (A missing block on install_patches means legacy-enabled,
// so any test that drives handleInstallPatches would otherwise reach it.)
func TestMain(m *testing.M) {
	createRestorePoint = func(_ context.Context, req systemrestore.Request) systemrestore.Outcome {
		return systemrestore.Outcome{
			Status:    systemrestore.StatusUnsupported,
			RequestID: req.RequestID,
			Message:   "test default: real System Restore is never called from tests",
		}
	}
	// Every patch command schedules a follow-up inventory scan, 5 s later off
	// macOS (#10250). Tests drive installs on bare Heartbeats, so a real scan
	// firing mid-run would scan the CI host and hit nil transports. Tests that
	// care about scheduling swap in their own recorder (captureRescans).
	schedulePostInstallRescan = func(*Heartbeat, time.Duration) {}
	// Localized copy (prompt host, PAM outcome notices #10696) falls back to
	// the machine's UI language; tests never read the CI host's. Tests that
	// care set their own (setOSUILocaleForTest).
	osUILocale = func() string { return "en-US" }
	// Dispatch reads the operator trust pin. On a machine running a real agent
	// its root-only state file reads as an unreadable pin and refuses every
	// Tier A command, so no test may see it.
	dir, err := os.MkdirTemp("", "heartbeat-opsign-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	opsign.DefaultStorePath = func() string { return filepath.Join(dir, "state.json") }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
