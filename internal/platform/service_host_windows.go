//go:build windows

package platform

import "golang.org/x/sys/windows/svc"

// RunningUnderService reports whether this process was launched by the Windows
// Service Control Manager (as opposed to an interactive shell).
func RunningUnderService() bool {
	isSvc, err := svc.IsWindowsService()
	return err == nil && isSvc
}