package smb

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/c2xorc4/mimic/internal/deception"
)

// TestConfigDrivenVFS drives a config-defined share end-to-end: a custom share
// "BACKUPS" with a seeded file whose inline content interpolates a pooled
// credential. It connects, authenticates (guest), tree-connects to the config
// share, opens the seeded file, and reads back the interpolated content.
func TestConfigDrivenVFS(t *testing.T) {
	store := deception.NewCredStore([]deception.Credential{
		{ID: "svc", Username: "svc_backup", Password: "V33m!", Domain: "CORP"},
	})
	fs := &deception.TreeConfig{
		Shares: []deception.ShareDef{
			{Name: "BACKUPS", Type: "disk", Remark: "Backup storage", Root: &deception.NodeDefGroup{
				Files: []deception.FileDef{
					{Name: "secret.txt", Content: "user={{cred:svc.username}} pass={{cred:svc.password}}"},
				},
			}},
			{Name: "IPC$", Type: "ipc"},
		},
		Maze: deception.DefaultMazeConfig(),
	}

	srv := New(Config{ComputerName: "TESTBOX", DomainName: "TESTDOM", Filesystem: fs, CredStore: store})

	// The advertised shares must reflect the config (so isKnownShare accepts BACKUPS).
	if !srv.isKnownShare("BACKUPS") {
		t.Fatal("BACKUPS not advertised/known after config build")
	}

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

	sessionID, treeID := doAuth(t, conn, `\\TESTBOX\BACKUPS`)

	var msgID uint64
	next := func() uint64 { msgID += 10; return msgID }

	resp := sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, next(), buildCreateBody(`secret.txt`)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("create config file: %#x", respStatus(resp))
	}
	fh := extractVolatileID(resp)

	resp = sendRecv(t, conn, buildTestPacket(CmdRead, sessionID, treeID, next(), buildReadBody(fh, 0, 256)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("read config file: %#x", respStatus(resp))
	}
	if dataLen := binary.LittleEndian.Uint32(resp[68+4 : 68+8]); dataLen == 0 {
		t.Fatal("seeded file returned 0 bytes")
	}
	if !bytes.Contains(resp, []byte("user=svc_backup pass=V33m!")) {
		t.Errorf("seeded+interpolated content not found in read response")
	}
}

// TestShareEnumMatchesConfig verifies the SRVSVC share advertisement derived from
// the filesystem config maps each share type correctly.
func TestShareEnumMatchesConfig(t *testing.T) {
	tc := deception.TreeConfig{Shares: []deception.ShareDef{
		{Name: "C$", Type: "disk_special", Remark: "Default share"},
		{Name: "DATA", Type: "disk", Remark: "Data"},
		{Name: "IPC$", Type: "ipc", Remark: "Remote IPC"},
	}}
	got := sharesFromTreeConfig(tc)
	if len(got) != 3 {
		t.Fatalf("want 3 shares, got %d", len(got))
	}
	want := map[string]uint32{
		"C$":   ShareTypeDisk | ShareTypeSpecial,
		"DATA": ShareTypeDisk,
		"IPC$": ShareTypeIPC | ShareTypeSpecial,
	}
	for _, s := range got {
		if want[s.Name] != s.Type {
			t.Errorf("share %s: type=%#x want %#x", s.Name, s.Type, want[s.Name])
		}
	}
}

// TestSeededCredAuth verifies that a credential from the pool authenticates via a
// genuine NTLMv2 proof, and that a wrong password is rejected. It exercises the
// verifyCredential/matchCredential path directly (the full SPNEGO handshake is
// covered by the state-machine tests).
func TestSeededCredAuth(t *testing.T) {
	const (
		user     = "svc_backup"
		password = "V33m@Backup!23"
		domain   = "CORP"
	)
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	blob := []byte{0x01, 0x01, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd} // arbitrary client/temp blob

	// Compute a valid NTLMv2 NTResponse = NTProofStr(16) || blob.
	ntHash := md4Sum(utf16LE(password))
	mac := hmac.New(md5.New, ntHash[:])
	mac.Write(utf16LE(strings.ToUpper(user) + domain))
	ntowfv2 := mac.Sum(nil)
	mac = hmac.New(md5.New, ntowfv2)
	mac.Write(challenge[:])
	mac.Write(blob)
	proof := mac.Sum(nil)
	ntResponse := append(append([]byte{}, proof...), blob...)

	cred := Credential{Username: user, Password: password, Domain: domain}
	if !verifyCredential(cred, user, domain, challenge, ntResponse) {
		t.Error("valid NTLMv2 proof rejected")
	}
	wrong := Credential{Username: user, Password: "not-the-password", Domain: domain}
	if verifyCredential(wrong, user, domain, challenge, ntResponse) {
		t.Error("wrong password accepted")
	}

	// matchCredential is case-insensitive on the username.
	creds := []Credential{cred}
	if matchCredential(creds, "SVC_BACKUP") == nil {
		t.Error("matchCredential should be case-insensitive")
	}
	if matchCredential(creds, "nobody") != nil {
		t.Error("matchCredential should not match unknown user")
	}
}
