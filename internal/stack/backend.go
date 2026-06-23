// Package stack is the platform-agnostic seam for TCP/IP stack-fingerprint
// mutation. On Linux it is backed by the eBPF/TC egress program
// (internal/ebpf); on Windows it is backed by a userland WinDivert handle. The
// orchestration layer (cmd/mimic) depends only on this interface, so neither
// backend's platform-specific dependencies (cilium/ebpf + netlink on Linux,
// WinDivert on Windows) leak into the shared command code.
package stack

import (
	"errors"

	"github.com/c2xorc4/mimic/internal/config"
)

// ErrUnsupported is returned by New on a platform that has no stack backend
// wired up yet (so callers can degrade gracefully instead of failing to build).
var ErrUnsupported = errors.New("stack fingerprint backend is not supported on this platform")

// Backend applies an OS TCP/IP stack fingerprint to outgoing packets on a given
// interface. The lifecycle mirrors the existing eBPF FingerprintManager:
// New → Load → SetProfile → Enable, then Close on shutdown.
type Backend interface {
	// Load brings up the backend (loads the program / opens the handle and
	// attaches it to the interface) in a disabled state.
	Load() error
	// SetProfile installs the stack parameters to emit.
	SetProfile(*config.OSProfile) error
	// Enable / Disable toggle active mutation without tearing down the attachment.
	Enable() error
	Disable() error
	// IsEnabled reports the current toggle state.
	IsEnabled() bool
	// InterfaceName returns the attached interface name.
	InterfaceName() string
	// Close detaches and releases all resources.
	Close() error
}

// TeardownResult reports what a stateless host-state teardown removed. It mirrors
// the Linux TC teardown outcome; non-Linux backends populate what applies.
type TeardownResult struct {
	FiltersRemoved int  // backend filters/rules removed
	QdiscRemoved   bool // Linux: clsact qdisc removed (purge + sole-user only)
	ForeignFilters int  // Linux: non-Mimic filters left on the shared qdisc
}
