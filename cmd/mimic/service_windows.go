//go:build windows

package main

import "golang.org/x/sys/windows/svc"

// serviceName is the Windows service identifier (SCM name + display).
const serviceName = "Mimic"

// mimicService adapts a `mimic run` invocation to the Windows Service Control
// Manager. The SCM launches the binary with the args baked into the service's
// ImagePath (e.g. `run -c C:\ProgramData\Mimic\config.yaml`), so the handler just
// runs the normal cobra command and translates an SCM Stop/Shutdown into the
// graceful shutdown path via serviceStopCh (see run.go).
type mimicService struct{}

func (m *mimicService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	// Arm the cooperative stop channel before launching the command.
	serviceStopCh = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- rootCmd.Execute() }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(serviceStopCh)
				<-done // wait for graceful teardown
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case <-done:
			// The command exited on its own (startup error or completion).
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

// maybeRunAsService runs the SCM dispatcher when the process was launched by the
// Service Control Manager, and reports whether it handled execution. When run
// interactively it returns false so main() falls through to normal CLI dispatch.
func maybeRunAsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false
	}
	_ = svc.Run(serviceName, &mimicService{})
	return true
}
