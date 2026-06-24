//go:build windows

package platform

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

// hiddenCmd returns a command that will not flash a visible console window.
// Use for netsh/sc and other helper invocations from an interactive mimic run.
func hiddenCmd(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	return cmd
}

// startHiddenDetached starts a short-lived helper (restart-pending) with no console flash.
func startHiddenDetached(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS | windows.CREATE_NO_WINDOW,
	}
	return cmd.Start()
}

// startDetachedRun respawns mimic run after a control-plane restart. Detached from
// the caller's console but not CREATE_NO_WINDOW — failures remain debuggable and
// the process keeps the elevated token inherited from restart-pending.
func startDetachedRun(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
	return cmd.Start()
}