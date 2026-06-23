//go:build windows

package platform

import "golang.org/x/sys/windows"

// IsElevated reports whether the current process token is a member of the
// built-in Administrators group — the Windows equivalent of root for the packet
// backend (WinDivert) and low-port binding.
func IsElevated() bool {
	var sid *windows.SID
	// S-1-5-32-544 — BUILTIN\Administrators.
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	// Token(0) is the current process token; IsMember honours elevation.
	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

// PrivilegeName is the OS-appropriate name for the elevated principal.
func PrivilegeName() string { return "administrator" }
