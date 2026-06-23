//go:build !linux && !windows

package stack

// Available reports whether a stack-fingerprint backend exists on this platform.
// Linux uses eBPF (backend_linux.go); Windows uses WinDivert (backend_windows.go).
// Any other platform (e.g. macOS dev hosts) has none.
func Available() bool { return false }

// New has no stack backend on these platforms; callers get ErrUnsupported and
// degrade to service emulation only.
func New(ifaceName string) (Backend, error) {
	return nil, ErrUnsupported
}

// Teardown is a no-op where there is no backend to tear down.
func Teardown(ifaceName string, purgeQdisc bool) (TeardownResult, error) {
	return TeardownResult{}, nil
}
