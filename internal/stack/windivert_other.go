//go:build !windows

package stack

// WinDivertInstalled is a Windows-only concept (the WinDivert driver/DLL backing
// the stack-mutation backend). On non-Windows platforms it is always false so the
// cross-platform run.go (which gates Windows-only WinDivert hints on it) compiles
// and links — the Linux build uses the eBPF backend and never consults this.
func WinDivertInstalled() bool { return false }
