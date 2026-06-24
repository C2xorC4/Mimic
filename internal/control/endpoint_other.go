//go:build !linux && !windows

package control

// DefaultEndpoint is unused on platforms without a control transport.
func DefaultEndpoint() string { return "" }