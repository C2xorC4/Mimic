//go:build linux

package platform

import "os"

// IsElevated reports whether the current process has the privilege needed to
// load eBPF, attach TC filters, and bind low ports — i.e. it runs as root.
func IsElevated() bool { return os.Geteuid() == 0 }

// PrivilegeName is the OS-appropriate name for the elevated principal, used in
// user-facing "requires X privileges" errors.
func PrivilegeName() string { return "root" }
