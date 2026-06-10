package services

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
)

// TestVNCHandshake drives the RFB handshake: server-first ProtocolVersion, then
// security types after the client version, a 16-byte challenge on VNC-auth select,
// and an auth-failure SecurityResult — verifying the empty-pattern banner probe
// (last) does not shadow the handshake steps.
func TestVNCHandshake(t *testing.T) {
	dir := t.TempDir()
	write := func(n string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("version.bin", []byte("RFB 003.008\n"))
	write("security_types.bin", []byte{0x01, 0x02})
	write("challenge.bin", make([]byte, 16))
	authfail := append([]byte{0, 0, 0, 1, 0, 0, 0, 0x16}, []byte("Authentication failure")...)
	write("authfail.bin", authfail)

	probes := []config.ProbeConfig{
		{Name: "client_version", Signature: config.SignatureConfig{Pattern: "RFB ", MinLength: 12}, ResponseFile: "security_types.bin"},
		{Name: "sectype", Signature: config.SignatureConfig{Pattern: `\x02`, MinLength: 1, MaxLength: 1}, ResponseFile: "challenge.bin",
			RewriteRules: []config.RewriteRule{{Offset: 0, Length: 16, Type: "random"}}},
		{Name: "authresp", Signature: config.SignatureConfig{MinLength: 16, MaxLength: 16}, ResponseFile: "authfail.bin"},
		{Name: "banner", Signature: config.SignatureConfig{MinLength: 0}, ResponseFile: "version.bin"},
	}
	cfg := &config.ServiceConfig{Name: "vnc", Port: 0, Protocol: "tcp", SpeaksFirst: true, Stateful: true, Probes: probes}
	l, err := NewListenerWithOptions(cfg, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	conn, err := net.Dial("tcp", l.tcpLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	read := func(n int) []byte {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, n)
		got, _ := conn.Read(buf)
		return buf[:got]
	}

	if v := read(12); string(v) != "RFB 003.008\n" {
		t.Fatalf("server ProtocolVersion = %q", v)
	}
	conn.Write([]byte("RFB 003.008\n"))
	if st := read(2); !bytes.Equal(st, []byte{0x01, 0x02}) {
		t.Fatalf("security types = % x; want 01 02", st)
	}
	conn.Write([]byte{0x02}) // select VNC Authentication
	if ch := read(16); len(ch) != 16 {
		t.Fatalf("challenge len = %d; want 16", len(ch))
	}
	conn.Write(make([]byte, 16)) // DES auth response
	res := read(64)
	if len(res) < 8 || !bytes.Equal(res[:4], []byte{0, 0, 0, 1}) || !bytes.Contains(res, []byte("Authentication failure")) {
		t.Fatalf("SecurityResult = % x (%q); want failure", res, res)
	}
}
