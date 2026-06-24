//go:build linux

package platform

import "os"

// RunningUnderService reports whether this process is running as a systemd unit
// (as opposed to an interactive shell).
func RunningUnderService() bool {
	// INVOCATION_ID is set for all processes started by systemd.
	return os.Getenv("INVOCATION_ID") != ""
}