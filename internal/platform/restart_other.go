//go:build !linux && !windows

package platform

import "errors"

// ScheduleRestart is unavailable on this platform.
func ScheduleRestart(parentPID int, cfgFile string, viaService bool) error {
	return errors.New("restart not supported on this platform")
}

// PerformPendingRestart is unavailable on this platform.
func PerformPendingRestart(cfgFile string, viaService bool) error {
	return errors.New("restart not supported on this platform")
}