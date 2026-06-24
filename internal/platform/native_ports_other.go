//go:build !windows

package platform

import "fmt"

// NativePortHint returns generic bind guidance on non-Windows hosts.
func NativePortHint(port int) string {
	return fmt.Sprintf("port %d is already in use — stop the conflicting listener or remove the service from config", port)
}