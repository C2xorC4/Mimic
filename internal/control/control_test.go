package control

import (
	"testing"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/events"
)

func TestRoleAuthorizer(t *testing.T) {
	a := NewRoleAuthorizer(config.RBACConfig{Roles: []config.Role{
		{Name: "ops", UIDs: []uint32{1000}, Allow: []string{"*"}},
		{Name: "auditor", GIDs: []uint32{50}, Allow: []string{"status", "logs"}},
		{Name: "svcadmin", UIDs: []uint32{1100}, Allow: []string{"services.*"}},
	}})

	cases := []struct {
		name     string
		peer     Peer
		op       string
		wantRole string
		wantErr  bool
	}{
		{"root bootstrap", Peer{UID: 0}, "services.stop", "admin", false},
		{"ops wildcard", Peer{UID: 1000}, "services.stop", "ops", false},
		{"auditor allowed", Peer{UID: 2000, GID: 50}, "status", "auditor", false},
		{"auditor denied op", Peer{UID: 2000, GID: 50}, "services.stop", "", true},
		{"svcadmin prefix", Peer{UID: 1100}, "services.reload", "svcadmin", false},
		{"svcadmin restart", Peer{UID: 1100}, "services.restart", "svcadmin", false},
		{"svcadmin not status", Peer{UID: 1100}, "status", "", true},
		{"unknown peer denied", Peer{UID: 4321, GID: 4321}, "status", "", true},
	}
	for _, c := range cases {
		role, err := a.Authorize(c.peer, c.op)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected denial, got role %q", c.name, role)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if role != c.wantRole {
			t.Errorf("%s: role = %q, want %q", c.name, role, c.wantRole)
		}
	}
}

func TestEmptyConfigRootOnly(t *testing.T) {
	a := NewRoleAuthorizer(config.RBACConfig{}) // no roles
	if _, err := a.Authorize(Peer{UID: 0}, "status"); err != nil {
		t.Errorf("root must be allowed with empty config: %v", err)
	}
	if _, err := a.Authorize(Peer{UID: 1000}, "status"); err == nil {
		t.Error("non-root must be denied with empty config (root-only default)")
	}
}

func TestWindowsBootstrapAdmin(t *testing.T) {
	a := NewRoleAuthorizer(config.RBACConfig{})
	if _, err := a.Authorize(Peer{IsAdmin: true, UserSID: "S-1-5-21-1"}, "status"); err != nil {
		t.Errorf("Windows admin must be allowed with empty config: %v", err)
	}
	// UAC-filtered Administrator: IsMember(Administrators) is often false, but the
	// group SID is still present on the token.
	if _, err := a.Authorize(Peer{
		UserSID:   "S-1-5-21-1",
		GroupSIDs: []string{"S-1-5-32-544"},
	}, "status"); err != nil {
		t.Errorf("Windows Administrators group must bootstrap with empty config: %v", err)
	}
	if _, err := a.Authorize(Peer{UserSID: "S-1-5-21-1000"}, "status"); err == nil {
		t.Error("non-admin Windows user must be denied with empty config")
	}
}

func TestWindowsRoleBySIDAndGroup(t *testing.T) {
	a := NewRoleAuthorizer(config.RBACConfig{Roles: []config.Role{
		{Name: "auditor", Groups: []string{"BUILTIN\\Users"}, Allow: []string{"status", "logs"}},
		{Name: "named", SIDs: []string{"S-1-5-21-99"}, Allow: []string{"ping"}},
	}})
	role, err := a.Authorize(Peer{
		UserSID:   "S-1-5-21-42",
		GroupSIDs: []string{"S-1-5-32-545"},
	}, "status")
	if err != nil || role != "auditor" {
		t.Fatalf("group role: role=%q err=%v", role, err)
	}
	role, err = a.Authorize(Peer{UserSID: "S-1-5-21-99"}, "ping")
	if err != nil || role != "named" {
		t.Fatalf("sid role: role=%q err=%v", role, err)
	}
	if _, err := a.Authorize(Peer{UserSID: "S-1-5-21-99"}, "services.stop"); err == nil {
		t.Error("sid role must not allow unlisted ops")
	}
}

func TestRing(t *testing.T) {
	r := NewRing(3)
	for i := 0; i < 5; i++ {
		r.Write(events.Event{Message: string(rune('a' + i))})
	}
	if r.Count() != 3 {
		t.Errorf("Count = %d, want 3 (capped)", r.Count())
	}
	last := r.Last(2)
	if len(last) != 2 || last[0].Message != "d" || last[1].Message != "e" {
		t.Errorf("Last(2) = %v, want [d e]", last)
	}
	if got := r.Last(10); len(got) != 3 {
		t.Errorf("Last(10) = %d events, want 3", len(got))
	}
}
