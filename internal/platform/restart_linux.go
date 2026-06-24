//go:build linux

package platform

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// ScheduleRestart spawns a detached restart-pending helper that will bring Mimic
// back after the current process exits. viaService mirrors RunningUnderService()
// from the calling instance.
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
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// PerformPendingRestart starts Mimic again after the parent process has exited.
func PerformPendingRestart(cfgFile string, viaService bool) error {
	if viaService {
		if out, err := exec.Command("systemctl", "start", "mimic").CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl start mimic: %s: %w", out, err)
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"run"}
	if cfgFile != "" {
		args = append(args, "-c", cfgFile)
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}