package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/breeze-rmm/agent/internal/opsign"
)

// The watchdog installs through the updater, which reads the operator trust
// pin. On a machine running a real agent its root-only state file reads as an
// unreadable pin and refuses every update, so no test may see it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "watchdog-opsign-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	opsign.DefaultStorePath = func() string { return filepath.Join(dir, "state.json") }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
