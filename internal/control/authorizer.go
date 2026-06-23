package control

import (
	"strings"

	"github.com/c2xorc4/mimic/internal/config"
)

// RoleAuthorizer maps a connecting peer's unix credentials (uid/gid) to a
// configured role and checks the requested operation against that role's
// allow-list. This is the separation-of-duties enforcement point: e.g. a
// "blue-team" gid may be allowed status+logs but not service control.
//
// Bootstrap rule: root (uid 0) is always granted (role "admin"), so an operator
// can never lock themselves out via config. With no roles configured, only root
// may use the control plane — preserving the prior root-only behaviour while
// leaving the seam open for least-privilege roles.
type RoleAuthorizer struct {
	roles []config.Role
}

// NewRoleAuthorizer builds an authorizer from the RBAC config.
func NewRoleAuthorizer(cfg config.RBACConfig) *RoleAuthorizer {
	return &RoleAuthorizer{roles: cfg.Roles}
}

// Authorize returns the role the peer is granted for op, or ErrDenied.
func (a *RoleAuthorizer) Authorize(peer Peer, op string) (string, error) {
	for _, r := range a.roles {
		if !roleMatchesPeer(r, peer) {
			continue
		}
		if opAllowed(r.Allow, op) {
			return r.Name, nil
		}
	}
	if peer.UID == 0 {
		return "admin", nil // root bootstrap (cannot be locked out)
	}
	return "", ErrDenied
}

func roleMatchesPeer(r config.Role, peer Peer) bool {
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

// opAllowed reports whether op matches any allow pattern: "*" (all), an exact
// name, or a "<prefix>.*" wildcard (e.g. "service.*" allows "service.stop").
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
