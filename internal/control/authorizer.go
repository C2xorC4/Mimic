package control

import (
	"strings"

	"github.com/c2xorc4/mimic/internal/config"
)

// RoleAuthorizer maps a connecting peer's OS credentials to a configured role
// and checks the requested operation against that role's allow-list. This is the
// separation-of-duties enforcement point: e.g. a "blue-team" gid may be allowed
// status+logs but not service control.
//
// Bootstrap rule: the platform admin principal is always granted (role "admin") —
// Linux root (uid 0) or a Windows member of BUILTIN\Administrators — so an
// operator can never lock themselves out via config. With no roles configured,
// only that bootstrap principal may use the control plane.
type RoleAuthorizer struct {
	roles []config.Role
}

// NewRoleAuthorizer builds an authorizer from the RBAC config.
func NewRoleAuthorizer(cfg config.RBACConfig) *RoleAuthorizer {
	return &RoleAuthorizer{roles: cfg.Roles}
}

// AccessDeniedMessage returns a client-facing hint when Authorize rejects a peer.
func AccessDeniedMessage(peer Peer) string {
	if peer.UserSID != "" {
		return "access denied — Windows control plane requires BUILTIN\\Administrators " +
			"(if mimic.exe was rebuilt, restart mimic run so the control server picks up auth fixes; " +
			"otherwise add rbac.roles for your user SID, or confirm whoami /user matches the elevated shell running ctl)"
	}
	return "access denied — Linux control plane requires root (uid 0) or an rbac.roles entry in config"
}

// Authorize returns the role the peer is granted for op, or ErrDenied.
func (a *RoleAuthorizer) Authorize(peer Peer, op string) (string, error) {
	if peer.IsBootstrapAdmin() {
		return "admin", nil
	}
	for _, r := range a.roles {
		if !roleMatchesPeer(r, peer) {
			continue
		}
		if opAllowed(r.Allow, op) {
			return r.Name, nil
		}
	}
	return "", ErrDenied
}

func roleMatchesPeer(r config.Role, peer Peer) bool {
	if peer.UserSID != "" {
		for _, s := range r.SIDs {
			if sidEqual(s, peer.UserSID) {
				return true
			}
		}
		for _, g := range r.Groups {
			if groupMatchesPeer(g, peer) {
				return true
			}
		}
		return false
	}
	for _, u := range r.UIDs {
		if u == peer.UID {
			return true
		}
	}
	for _, g := range r.GIDs {
		if g == peer.GID {
			return true
		}
	}
	return false
}

// groupMatchesPeer reports whether a role group entry matches any of the peer's
// token groups. Entries may be raw SIDs (S-1-5-...) or well-known names such as
// BUILTIN\Administrators.
func groupMatchesPeer(entry string, peer Peer) bool {
	entry = strings.TrimSpace(entry)
	if strings.HasPrefix(strings.ToUpper(entry), "S-") {
		for _, g := range peer.GroupSIDs {
			if sidEqual(entry, g) {
				return true
			}
		}
		return false
	}
	norm := normalizeWellKnownGroup(entry)
	for _, g := range peer.GroupSIDs {
		if wellKnownGroupLabel(g) == norm {
			return true
		}
	}
	return false
}

func sidEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// normalizeWellKnownGroup maps friendly RBAC group names to a canonical label
// compared against peer group SIDs via wellKnownGroupLabel.
func normalizeWellKnownGroup(name string) string {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(name), "/", `\`)) {
	case `BUILTIN\ADMINISTRATORS`, `ADMINISTRATORS`, `DOMAIN ALIAS\ADMINS`:
		return "administrators"
	case `NT AUTHORITY\SYSTEM`, `SYSTEM`:
		return "system"
	case `BUILTIN\USERS`, `USERS`:
		return "users"
	default:
		return strings.ToLower(name)
	}
}

// wellKnownGroupLabel returns a canonical label for well-known group SIDs.
func wellKnownGroupLabel(sid string) string {
	switch strings.ToUpper(sid) {
	case "S-1-5-32-544":
		return "administrators"
	case "S-1-5-18":
		return "system"
	case "S-1-5-32-545":
		return "users"
	default:
		return ""
	}
}

// opAllowed reports whether op matches any allow pattern: "*" (all), an exact
// name, or a "<prefix>.*" wildcard (e.g. "services.*" allows "services.restart").
func opAllowed(allow []string, op string) bool {
	for _, a := range allow {
		switch {
		case a == "*" || a == op:
			return true
		case strings.HasSuffix(a, ".*") && strings.HasPrefix(op, a[:len(a)-1]):
			return true
		}
	}
	return false
}