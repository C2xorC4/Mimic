package smb

import "testing"

func TestGuestAdminSharePolicyHelpers(t *testing.T) {
	if !isAdminShare("C$") || !isAdminShare("admin$") {
		t.Fatal("admin share detection failed")
	}
	if isAdminShare("IPC$") {
		t.Fatal("IPC$ is not an admin share")
	}
	if !isRegistryHiveFile("SAM") || !isRegistryHiveFile("system") {
		t.Fatal("hive file detection failed")
	}
}

func TestSessionGuestFlag(t *testing.T) {
	s := newSession()
	if s.isGuest() {
		t.Fatal("new session should not be guest")
	}
	s.setGuest(true)
	if !s.isGuest() {
		t.Fatal("expected guest after setGuest(true)")
	}
}