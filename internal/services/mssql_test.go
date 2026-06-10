package services

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
)

// TestMSSQLPreloginAndLogin drives the TDS flow: client-first PRELOGIN -> server
// PRELOGIN response (carrying the SQL Server version), then LOGIN7 -> Login failed
// — and verifies the real lab hostname was scrubbed from the login response.
func TestMSSQLPreloginAndLogin(t *testing.T) {
	dir := t.TempDir()
	// Real captured responses (PRELOGIN response + scrubbed login error).
	prelogin, _ := base64.StdEncoding.DecodeString("BAEAJQAAAQAAABUABgEAGwABAgAcAAEDAB0AAP8QABCfAAAAAA==")
	login, _ := base64.StdEncoding.DecodeString("BAEBBgBAAQCq8gAUSAAAAQ5mAEwAbwBnAGkAbgAgAGYAYQBpAGwAZQBkAC4AIABUAGgAZQAgAGwAbwBnAGkAbgAgAGkAcwAgAGYAcgBvAG0AIABhAG4AIAB1AG4AdAByAHUAcwB0AGUAZAAgAGQAbwBtAGEAaQBuACAAYQBuAGQAIABjAGEAbgBuAG8AdAAgAGIAZQAgAHUAcwBlAGQAIAB3AGkAdABoACAASQBuAHQAZQBnAHIAYQB0AGUAZAAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgAuAA1XAEkATgAtAFMAUQBMAFAAUgBPAEQAMAAxAAABAP0CAAAAAAAAAA==")
	if err := os.WriteFile(filepath.Join(dir, "prelogin.bin"), prelogin, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "login.bin"), login, 0o644); err != nil {
		t.Fatal(err)
	}
	probes := []config.ProbeConfig{
		{Name: "prelogin", Signature: config.SignatureConfig{Pattern: `\x12`, MinLength: 8}, ResponseFile: "prelogin.bin"},
		{Name: "login7", Signature: config.SignatureConfig{Pattern: `\x10`, MinLength: 8}, ResponseFile: "login.bin"},
	}
	cfg := &config.ServiceConfig{Name: "mssql", Port: 0, Protocol: "tcp", Stateful: true, Probes: probes}
	l, conn := startSvc(t, cfg, dir, nil)
	defer l.Stop()
	defer conn.Close()
	rd := func() []byte {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		return buf[:n]
	}
	// PRELOGIN (TDS type 0x12), 8-byte header + a couple option bytes
	conn.Write([]byte{0x12, 0x01, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0xff})
	pre := rd()
	if len(pre) < 8 || pre[0] != 0x04 {
		t.Fatalf("prelogin response not a TDS response: % x", pre)
	}
	// version 16.0.4255 -> bytes 10 00 10 9f present in PRELOGIN VERSION option
	if !bytes.Contains(pre, []byte{0x10, 0x00, 0x10, 0x9f}) {
		t.Errorf("prelogin missing version 16.0.4255: % x", pre)
	}
	// LOGIN7 (TDS type 0x10)
	conn.Write([]byte{0x10, 0x01, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0, 0})
	lg := rd()
	if !bytes.Contains(lg, utf16le("Login failed")) {
		t.Errorf("login response missing 'Login failed': % x", lg)
	}
	if bytes.Contains(lg, utf16le("sectestubuntu")) {
		t.Errorf("login response leaks real hostname sectestubuntu")
	}
	if !bytes.Contains(lg, utf16le("WIN-SQLPROD01")) {
		t.Errorf("login response missing scrubbed hostname")
	}
}

func utf16le(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		b = append(b, byte(r), 0x00)
	}
	return b
}
