//go:build linux

package control

// DefaultEndpoint is the control-plane listen path when config leaves socket empty.
func DefaultEndpoint() string { return "/run/mimic.sock" }