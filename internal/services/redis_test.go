package services

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
)

func startSvc(t *testing.T, cfg *config.ServiceConfig, dir string, opts map[string]string) (*Listener, net.Conn) {
	t.Helper()
	l, err := NewListenerWithOptions(cfg, dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", l.tcpLn.Addr().String())
	if err != nil {
		l.Stop()
		t.Fatal(err)
	}
	return l, conn
}

// TestRedisCommandLoop verifies client-first RESP command matching via `contains`
// (verb inside framing), per-OS INFO, and the catch-all for unknown commands.
func TestRedisCommandLoop(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"pong.bin":         "+PONG\r\n",
		"auth.bin":         "-ERR Client sent AUTH, but no password is set\r\n",
		"unknown.bin":      "-ERR unknown command\r\n",
		"info_linux.bin":   "$30\r\nredis_version:7.0.11\r\nos:Linux\r\n",
		"info_windows.bin": "$32\r\nredis_version:7.0.11\r\nos:Windows\r\n",
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	probes := []config.ProbeConfig{
		{Name: "ping", Signature: config.SignatureConfig{Contains: "PING"}, ResponseFile: "pong.bin"},
		{Name: "info_linux", Signature: config.SignatureConfig{Contains: "INFO"}, ResponseFile: "info_linux.bin", Requires: map[string]string{"os_family": "linux"}},
		{Name: "info_windows", Signature: config.SignatureConfig{Contains: "INFO"}, ResponseFile: "info_windows.bin", Requires: map[string]string{"os_family": "windows"}},
		{Name: "auth", Signature: config.SignatureConfig{Contains: "AUTH"}, ResponseFile: "auth.bin"},
		{Name: "unknown", Signature: config.SignatureConfig{MinLength: 1}, ResponseFile: "unknown.bin"},
	}

	for _, fam := range []string{"linux", "windows"} {
		cfg := &config.ServiceConfig{Name: "redis", Port: 0, Protocol: "tcp", Stateful: true, Probes: probes}
		l, conn := startSvc(t, cfg, dir, map[string]string{"os_family": fam})
		r := bufio.NewReader(conn)
		send := func(b string) string {
			conn.Write([]byte(b))
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 256)
			n, _ := r.Read(buf)
			return string(buf[:n])
		}
		// INFO inside RESP framing must match via `contains`.
		if got := send("*1\r\n$4\r\nINFO\r\n"); !strings.Contains(got, "os:"+strings.Title(fam)) {
			t.Errorf("%s INFO = %q; want os:%s", fam, got, strings.Title(fam))
		}
		if got := send("PING\r\n"); got != "+PONG\r\n" {
			t.Errorf("%s PING = %q", fam, got)
		}
		if got := send("AUTH secret\r\n"); !strings.HasPrefix(got, "-ERR") || !strings.Contains(got, "no password") {
			t.Errorf("%s AUTH = %q", fam, got)
		}
		if got := send("GET foo\r\n"); !strings.Contains(got, "unknown command") {
			t.Errorf("%s unknown = %q", fam, got)
		}
		conn.Close()
		l.Stop()
	}
}

// TestTelnetBannerPerOS verifies the server-first per-OS telnet banner.
func TestTelnetBannerPerOS(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"banner_linux.bin":   "\xff\xfb\x01\r\nUbuntu 22.04.3 LTS\r\nlogin: ",
		"banner_windows.bin": "\xff\xfb\x01\r\nWelcome to Microsoft Telnet Service\r\nlogin: ",
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	probes := []config.ProbeConfig{
		{Name: "linux", Signature: config.SignatureConfig{}, ResponseFile: "banner_linux.bin", Requires: map[string]string{"os_family": "linux"}},
		{Name: "windows", Signature: config.SignatureConfig{}, ResponseFile: "banner_windows.bin", Requires: map[string]string{"os_family": "windows"}},
	}
	cases := map[string]string{"linux": "Ubuntu", "windows": "Microsoft Telnet"}
	for fam, want := range cases {
		cfg := &config.ServiceConfig{Name: "telnet", Port: 0, Protocol: "tcp", SpeaksFirst: true, Probes: probes}
		l, conn := startSvc(t, cfg, dir, map[string]string{"os_family": fam})
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf) // server-first
		if got := string(buf[:n]); !strings.Contains(got, want) || !strings.Contains(got, "login: ") {
			t.Errorf("%s telnet banner = %q; want %q + login:", fam, got, want)
		}
		conn.Close()
		l.Stop()
	}
}
