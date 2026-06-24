package platform

import "time"

const (
	// MimicServiceName is the OS service identifier (SCM / systemd unit base name).
	MimicServiceName = "Mimic"
	// RestartWaitTimeout is how long restart-pending waits for the parent to exit.
	RestartWaitTimeout = 30 * time.Second
)

// WaitForProcessExit polls until pid is gone or timeout elapses.
func WaitForProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !ProcessAlive(pid) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return !ProcessAlive(pid)
}