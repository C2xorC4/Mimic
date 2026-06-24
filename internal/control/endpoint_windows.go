//go:build windows

package control

// DefaultEndpoint is the control-plane named pipe when config leaves socket empty.
func DefaultEndpoint() string { return `\\.\pipe\mimic` }