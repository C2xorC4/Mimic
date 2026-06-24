//go:build windows

package platform

import "fmt"

// NativePortHint returns guidance when mimic cannot bind a well-known Windows port.
func NativePortHint(port int) string {
	switch port {
	case 135:
		return "port 135 is usually held by the RPC Endpoint Mapper — remove msrpc from services or use a VM without the native service"
	case 139:
		return "port 139 is usually held by NetBIOS / LanmanWorkstation — remove netbios from services"
	case 445:
		return "port 445 is held by Windows SMB (LanmanServer). Stop it with `Stop-Service LanmanServer` (disables host file sharing) or remove smb/smb_honeypot from services"
	case 3389:
		return "port 3389 is usually held by Remote Desktop (TermService) — remove rdp from services or disable RDP"
	case 22:
		return "port 22 is usually held by Windows OpenSSH (sshd). Stop it with `Stop-Service sshd` and `Set-Service sshd -StartupType Disabled`, or remove ssh/ssh_honeypot from services"
	default:
		return fmt.Sprintf("port %d is already in use by another process", port)
	}
}