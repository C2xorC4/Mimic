package smb

import (
	"encoding/binary"
	"testing"
)

func buildSessionSetup2BodyAnonymous() []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25)
	return body
}

func readDataLength(resp []byte) uint32 {
	if len(resp) < 76 {
		return 0
	}
	return binary.LittleEndian.Uint32(resp[72:76])
}

func TestCanAccessAdminShare(t *testing.T) {
	s := newSession()
	if !s.canAccessAdminShare() {
		t.Fatal("fresh session should allow admin share (not guest)")
	}
	s.setGuest(true)
	if s.canAccessAdminShare() {
		t.Fatal("guest session should block admin share")
	}
	s.setSeededAuth(true)
	if !s.canAccessAdminShare() {
		t.Fatal("seeded auth should allow admin share even when guest flag was set")
	}
}

func TestGuestBlockedSeededCredMazeAccess(t *testing.T) {
	allow := true
	srv := New(Config{
		ComputerName:   "TESTBOX",
		DomainName:     "TESTDOM",
		AllowGuestEnum: &allow,
		Credentials:    []Credential{testAuthCredential()},
	})
	ln, err := newFreeListener()
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	srv.cfg.Port = uint16(extractPort(addr))
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)

	conn, err := dialAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	var msgID uint64
	next := func() uint64 { msgID += 5; return msgID }

	// Null session: C$ tree-connect denied.
	resp := sendRecv(t, conn, buildTestPacket(CmdNegotiate, 0, 0, next(), buildNegotiateBody()))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("negotiate: %#x", respStatus(resp))
	}
	resp = sendRecv(t, conn, buildTestPacket(CmdSessionSetup, 0, 0, next(), buildSessionSetup1Body()))
	if respStatus(resp) != StatusMoreProcessing {
		t.Fatalf("ss1: %#x", respStatus(resp))
	}
	sessionID := respSessionID(resp)
	resp = sendRecv(t, conn, buildTestPacket(CmdSessionSetup, sessionID, 0, next(), buildSessionSetup2BodyAnonymous()))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("ss2 anon: %#x", respStatus(resp))
	}
	resp = sendRecv(t, conn, buildTestPacket(CmdTreeConnect, sessionID, 0, next(), buildTreeConnectBody(`\\TESTBOX\C$`)))
	if respStatus(resp) != StatusAccessDenied {
		t.Fatalf("null C$ tree: want ACCESS_DENIED, got %#x", respStatus(resp))
	}

	// Seeded credential: C$ tree-connect + bait file read.
	conn2, err := dialAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn2.Close() })
	msgID = 0
	next2 := func() uint64 { msgID += 5; return msgID }
	cred := testAuthCredential()

	resp = sendRecv(t, conn2, buildTestPacket(CmdNegotiate, 0, 0, next2(), buildNegotiateBody()))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("negotiate2: %#x", respStatus(resp))
	}
	resp = sendRecv(t, conn2, buildTestPacket(CmdSessionSetup, 0, 0, next2(), buildSessionSetup1Body()))
	if respStatus(resp) != StatusMoreProcessing {
		t.Fatalf("ss1 cred: %#x", respStatus(resp))
	}
	sessionID = respSessionID(resp)
	challenge := extractChallengeFromSS1(resp)
	resp = sendRecv(t, conn2, buildTestPacket(CmdSessionSetup, sessionID, 0, next2(), buildSessionSetup2BodyCred(challenge, cred)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("ss2 cred: %#x", respStatus(resp))
	}
	resp = sendRecv(t, conn2, buildTestPacket(CmdTreeConnect, sessionID, 0, next2(), buildTreeConnectBody(`\\TESTBOX\C$`)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("seeded C$ tree: want SUCCESS, got %#x", respStatus(resp))
	}
	treeID := respTreeID(resp)

	resp = sendRecv(t, conn2, buildTestPacket(CmdCreate, sessionID, treeID, next2(),
		buildCreateBody(`Users\Administrator\Documents\passwords.txt`)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("open passwords.txt: %#x", respStatus(resp))
	}
	fileHandle := extractVolatileID(resp)
	resp = sendRecv(t, conn2, buildTestPacket(CmdRead, sessionID, treeID, next2(),
		buildReadBody(fileHandle, 0, 512)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("read passwords.txt: %#x", respStatus(resp))
	}
	dataLen := readDataLength(resp)
	if dataLen < 50 {
		t.Fatalf("passwords.txt read too short: %d bytes", dataLen)
	}
}