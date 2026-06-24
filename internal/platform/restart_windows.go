//go:build windows

package platform

import (
	"fmt"
	"os"
	"strconv"
)

// ScheduleRestart spawns a detached restart-pending helper that will bring Mimic
// back after the current process exits. viaService mirrors RunningUnderService()
// from the calling instance so interactive dev runs respawn mimic run instead of
// invoking SCM when a service unit happens to be registered.
func ScheduleRestart(parentPID int, cfgFile string, viaService bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"restart-pending", "--parent-pid", strconv.Itoa(parentPID)}
	if viaService {
		args = append(args, "--via-service")
	}
	if cfgFile != "" {
		args = append(args, "-c", cfgFile)
	}
	return startHiddenDetached(exe, args...)
}

// PerformPendingRestart starts Mimic again after the parent process has exited.
func PerformPendingRestart(cfgFile string, viaService bool) error {
	if viaService {
		if out, err := hiddenCmd("sc", "start", MimicServiceName).CombinedOutput(); err != nil {
			return fmt.Errorf("sc start %s: %s: %w", MimicServiceName, out, err)
		}
		return nil
	}
	return spawnDetachedRun(cfgFile)
}

func spawnDetachedRun(cfgFile string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"run"}
	if cfgFile != "" {
		args = append(args, "-c", cfgFile)
	}
	return startDetachedRun(exe, args...)
}