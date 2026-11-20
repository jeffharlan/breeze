//go:build !darwin && !linux && !windows

package opsign

import "os"

// No agent runs on these platforms; the in-process mutex is all that guards the file.
func tryLock(*os.File) error { return nil }
