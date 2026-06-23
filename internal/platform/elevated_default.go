//go:build !linux && !windows

package platform

// IsElevated is a permissive fallback for unsupported dev platforms (e.g.
// macOS): the privileged backends aren't available there anyway, so this only
// gates the up-front check, not real packet mutation.
func IsElevated() bool { return true }

// PrivilegeName is the generic name for the elevated principal.
func PrivilegeName() string { return "elevated" }
