package control

// IsBootstrapAdmin reports whether the peer has unconditional admin access —
// Linux root (uid 0, unix peer creds) or a Windows member of BUILTIN\Administrators.
// Windows peers carry UserSID; uid 0 on those structs is not meaningful and must
// not trigger the Linux bootstrap path. UAC-filtered Administrator sessions often
// have IsAdmin=false while still carrying S-1-5-32-544 in GroupSIDs — those peers
// are treated as bootstrap admin for same-host management.
func (p Peer) IsBootstrapAdmin() bool {
	if p.IsAdmin {
		return true
	}
	for _, g := range p.GroupSIDs {
		if wellKnownGroupLabel(g) == "administrators" {
			return true
		}
	}
	return p.UserSID == "" && p.UID == 0
}