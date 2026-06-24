//go:build windows

package control

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestPeerFromTokenLinkedAdmin(t *testing.T) {
	// Exercise the real token path for the current process. When this test runs
	// under UAC elevation it checks the primary token; when run from a filtered
	// Administrator shell it relies on GetLinkedToken.
	proc, err := windows.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()

	peer, err := peerFromToken(token, int32(windows.GetCurrentProcessId()))
	if err != nil {
		t.Fatal(err)
	}
	if peer.UserSID == "" {
		t.Fatal("expected UserSID")
	}

	adminSID, err := administratorsSID()
	if err != nil {
		t.Fatal(err)
	}
	defer windows.FreeSid(adminSID)

	primary := tokenIsAdministrator(token, adminSID)
	linkedAdmin := false
	if linked, err := token.GetLinkedToken(); err == nil {
		defer linked.Close()
		linkedAdmin = tokenIsAdministrator(linked, adminSID)
	}

	expectAdmin := primary || linkedAdmin
	if expectAdmin && !peer.IsAdmin && !peer.IsBootstrapAdmin() {
		t.Fatalf("peer should be admin: IsAdmin=%v groups=%v primary=%v linked=%v",
			peer.IsAdmin, peer.GroupSIDs, primary, linkedAdmin)
	}
	if !expectAdmin && peer.IsBootstrapAdmin() {
		t.Fatalf("peer must not bootstrap as admin: %+v", peer)
	}
}