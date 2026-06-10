package services

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
)

// TestMySQLHandshake verifies the server-first MySQL handshake: greeting sent on
// connect, protocol/version/auth-plugin intact, per-connection salt randomization,
// and a Bad-handshake error for a post-greeting client packet.
func TestMySQLHandshake(t *testing.T) {
	dir := t.TempDir()
	// Minimal real-shaped greeting: header + proto + version\0 + thread_id(4) +
	// salt1(8) + filler + caps/charset/status + len + reserved(10) + salt2(13) + plugin.
	greeting := []byte{0x6b, 0, 0, 0, 0x0a}
	greeting = append(greeting, []byte("5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1")...)
	greeting = append(greeting, 0x00)                                                 // version null @44
	greeting = append(greeting, 0x25, 0, 0, 0)                                        // thread_id @45
	greeting = append(greeting, []byte("Oqj@@^8?")...)                                // salt1 @49
	greeting = append(greeting, 0x00, 0xfe, 0xf7, 0x2d, 0x02, 0x00, 0xff, 0x81, 0x15) // @57..65
	greeting = append(greeting, make([]byte, 10)...)                                  // reserved @66
	greeting = append(greeting, []byte("rabcd3\"+R<rNk")...)                          // salt2 @76 (13B incl null-ish)
	greeting[len(greeting)-1] = 0x00                                                  // salt2 terminator @88
	greeting = append(greeting, []byte("mysql_native_password")...)
	greeting = append(greeting, 0x00)
	badhs := append([]byte{0x16, 0, 0, 2}, []byte("\xff\x13\x04#08S01Bad handshake")...)

	if err := os.WriteFile(filepath.Join(dir, "greeting.bin"), greeting, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.bin"), badhs, 0o644); err != nil {
		t.Fatal(err)
	}
	probes := []config.ProbeConfig{
		{Name: "login", Signature: config.SignatureConfig{MinLength: 1}, ResponseFile: "bad.bin"},
		{Name: "greeting", Signature: config.SignatureConfig{MinLength: 0}, ResponseFile: "greeting.bin",
			RewriteRules: []config.RewriteRule{
				{Offset: 45, Length: 4, Type: "random"},
				{Offset: 49, Length: 8, Type: "random"},
				{Offset: 76, Length: 12, Type: "random"},
			}},
	}
	cfg := &config.ServiceConfig{Name: "mysql", Port: 0, Protocol: "tcp", SpeaksFirst: true, Stateful: true, Probes: probes}

	read := func() ([]byte, []byte) {
		l, conn := startSvc(t, cfg, dir, nil)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf) // server-first greeting
		g := append([]byte(nil), buf[:n]...)
		conn.Write([]byte{0x05, 0, 0, 1, 0, 0, 0, 0}) // bogus client packet
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		m, _ := conn.Read(buf)
		e := append([]byte(nil), buf[:m]...)
		conn.Close()
		l.Stop()
		return g, e
	}

	g1, e1 := read()
	g2, _ := read()

	if len(g1) < 90 || g1[4] != 0x0a {
		t.Fatalf("greeting malformed: % x", g1)
	}
	if !bytes.Contains(g1, []byte("MariaDB")) || !bytes.Contains(g1, []byte("mysql_native_password")) {
		t.Errorf("greeting missing version/plugin: %q", g1)
	}
	// salt1 @49 must differ between connections — including its tail bytes
	// (a time-derived "random" leaves the high bytes constant; crypto/rand doesn't).
	if bytes.Equal(g1[49:57], g2[49:57]) || bytes.Equal(g1[53:57], g2[53:57]) {
		t.Errorf("salt1 not fully randomized: %x vs %x", g1[49:57], g2[49:57])
	}
	// auth plugin name must survive the salt2 rewrite (not clobbered)
	if !bytes.Contains(g2, []byte("mysql_native_password")) {
		t.Errorf("salt2 rewrite clobbered auth plugin name: %q", g2)
	}
	if len(e1) < 5 || e1[4] != 0xff || !bytes.Contains(e1, []byte("Bad handshake")) {
		t.Errorf("expected Bad handshake error, got % x (%q)", e1, e1)
	}
}
