//go:build !windows

package platform

import (
	"os"
	"syscall"
)

// ProcessAlive reports whether pid is a live process.
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}