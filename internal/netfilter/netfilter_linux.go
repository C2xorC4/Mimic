//go:build linux

// Package netfilter is the platform seam for host-level packet disposition —
// the closed-port RST/drop, T2/T3 probe responses, and the firewalled-client
// default-drop persona. On Linux these are implemented with nftables (see
// internal/services); on Windows they will be implemented with WinDivert /
// Windows Firewall in Phase 1c. Until then non-Linux reports Supported() = false
// and the orchestrator skips the host-shaping layer (service emulation still runs).
package netfilter

// Supported reports whether host packet-disposition shaping is available on this
// platform (Linux nftables present at build time).
func Supported() bool { return true }
