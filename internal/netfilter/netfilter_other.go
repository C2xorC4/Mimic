//go:build !linux

package netfilter

// Supported is false off Linux until the Windows host-disposition backend lands
// (Phase 1c). The orchestrator then skips closed-port/probe/firewall shaping and
// runs service emulation only.
func Supported() bool { return false }
