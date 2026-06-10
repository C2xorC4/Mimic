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

func sig(pattern string, min int) config.SignatureConfig {
	return config.SignatureConfig{Pattern: pattern, MinLength: min}
}

// TestSMTPCommandLoopPerOS drives the SMTP service end to end: server-first banner
// (per OS), EHLO capabilities (per OS), and the verb command loop — verifying the
// empty-pattern banner probe (ordered last) does NOT shadow real commands.
func TestSMTPCommandLoopPerOS(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"banner_windows.bin": "220 MAIL01 Microsoft ESMTP MAIL Service ready\r\n",
		"banner_linux.bin":   "220 mail.corp.local ESMTP Postfix\r\n",
		"ehlo_windows.bin":   "250-MAIL01 Hello\r\n250-CHUNKING\r\n250 AUTH LOGIN\r\n",
		"ehlo_linux.bin":     "250-mail.corp.local\r\n250-ETRN\r\n250 DSN\r\n",
		"ok_250.bin":         "250 2.1.0 Ok\r\n",
		"data_354.bin":       "354 End data\r\n",
		"queued_250.bin":     "250 2.0.0 Ok: queued as 4F1A2C3D\r\n",
		"quit_221.bin":       "221 2.0.0 Bye\r\n",
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	probes := []config.ProbeConfig{
		{Name: "ehlo_win", Signature: sig("EHLO", 4), ResponseFile: "ehlo_windows.bin", Requires: map[string]string{"os_family": "windows"}},
		{Name: "ehlo_linux", Signature: sig("EHLO", 4), ResponseFile: "ehlo_linux.bin", Requires: map[string]string{"os_family": "linux"}},
		{Name: "mail", Signature: sig("MAIL", 4), ResponseFile: "ok_250.bin"},
		{Name: "rcpt", Signature: sig("RCPT", 4), ResponseFile: "ok_250.bin"},
		{Name: "data", Signature: sig("DATA", 4), ResponseFile: "data_354.bin"},
		{Name: "dataend", Signature: config.SignatureConfig{Pattern: `\x2e\x0d\x0a`, MinLength: 3, MaxLength: 3}, ResponseFile: "queued_250.bin"},
		{Name: "quit", Signature: sig("QUIT", 4), ResponseFile: "quit_221.bin"},
		{Name: "banner_win", Signature: sig("", 0), ResponseFile: "banner_windows.bin", Requires: map[string]string{"os_family": "windows"}},
		{Name: "banner_linux", Signature: sig("", 0), ResponseFile: "banner_linux.bin", Requires: map[string]string{"os_family": "linux"}},
	}

	cases := []struct {
		family        string
		wantBanner    string
		wantEhloToken string
	}{
		{"windows", "Microsoft ESMTP", "CHUNKING"},
		{"linux", "Postfix", "ETRN"},
	}

	for _, tc := range cases {
		cfg := &config.ServiceConfig{Name: "smtp", Port: 0, Protocol: "tcp", SpeaksFirst: true, Stateful: true, Probes: probes}
		l, err := NewListenerWithOptions(cfg, dir, map[string]string{"os_family": tc.family})
		if err != nil {
			t.Fatalf("%s: %v", tc.family, err)
		}
		if err := l.Start(); err != nil {
			t.Fatalf("%s start: %v", tc.family, err)
		}
		addr := l.tcpLn.Addr().String()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			l.Stop()
			t.Fatalf("%s dial: %v", tc.family, err)
		}
		r := bufio.NewReader(conn)
		readResp := func() string {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 512)
			n, _ := r.Read(buf)
			return string(buf[:n])
		}
		send := func(s string) { conn.Write([]byte(s + "\r\n")) }

		if got := readResp(); !strings.Contains(got, tc.wantBanner) {
			t.Errorf("%s banner = %q; want substring %q", tc.family, got, tc.wantBanner)
		}
		send("EHLO scanner.example")
		ehlo := readResp()
		if !strings.HasPrefix(ehlo, "250") || !strings.Contains(ehlo, tc.wantEhloToken) {
			t.Errorf("%s EHLO = %q; want 250.. with %q", tc.family, ehlo, tc.wantEhloToken)
		}
		send("MAIL FROM:<a@b.com>")
		if got := readResp(); !strings.HasPrefix(got, "250") {
			t.Errorf("%s MAIL = %q; want 250", tc.family, got)
		}
		send("DATA")
		if got := readResp(); !strings.HasPrefix(got, "354") {
			t.Errorf("%s DATA = %q; want 354", tc.family, got)
		}
		conn.Write([]byte(".\r\n"))
		if got := readResp(); !strings.HasPrefix(got, "250") {
			t.Errorf("%s end-of-data = %q; want 250 queued", tc.family, got)
		}
		send("QUIT")
		if got := readResp(); !strings.HasPrefix(got, "221") {
			t.Errorf("%s QUIT = %q; want 221", tc.family, got)
		}
		conn.Close()
		l.Stop()
	}
}
