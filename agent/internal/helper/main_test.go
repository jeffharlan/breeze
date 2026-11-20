package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/breeze-rmm/agent/internal/opsign"
)

// TestMain keeps the whole package off the developer's machine: Apply runs
// migrateFromLegacyName, which on a host with the legacy-named Helper installed
// would stop its processes and delete the app. Point the legacy path at a
// nonexistent temp location; migrate tests override it per-test and restore it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "helper-test-legacy-")
	if err != nil {
		panic(err)
	}
	legacyBinaryPathFunc = func() string { return filepath.Join(dir, "no-legacy-helper") }
	// Never the machine's real operator trust pin, should anything here reach the updater.
	opsign.DefaultStorePath = func() string { return filepath.Join(dir, "opsign-state.json") }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
