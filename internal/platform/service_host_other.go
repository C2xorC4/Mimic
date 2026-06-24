//go:build !linux && !windows

package platform

// RunningUnderService is false on platforms without a supported service manager.
func RunningUnderService() bool {
	return false
}