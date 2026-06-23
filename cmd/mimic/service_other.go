//go:build !windows

package main

// maybeRunAsService is a no-op off Windows: Linux uses systemd (see install.go),
// which runs the binary as a normal foreground process under ExecStart.
func maybeRunAsService() bool { return false }
