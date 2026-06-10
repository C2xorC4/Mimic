package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
)

// TestHTTPPerOSAndLiveDate verifies per-OS Server selection (IIS vs nginx) and the
// http_date rewrite replacing the stale placeholder Date with the current time.
func TestHTTPPerOSAndLiveDate(t *testing.T) {
	dir := t.TempDir()
	const ph = "Xxx, 00 Xxx 0000 00:00:00 GMT" // 29-char placeholder
	iis := "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nDate: " + ph + "\r\nContent-Length: 0\r\n\r\n"
	ngx := "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nDate: " + ph + "\r\nContent-Length: 0\r\n\r\n"
	if err := os.WriteFile(filepath.Join(dir, "iis.bin"), []byte(iis), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ngx.bin"), []byte(ngx), 0o644); err != nil {
		t.Fatal(err)
	}
	probes := []config.ProbeConfig{
		{Name: "get_win", Signature: config.SignatureConfig{Pattern: "GET ", MinLength: 4}, ResponseFile: "iis.bin",
			Requires: map[string]string{"os_family": "windows"}, RewriteRules: []config.RewriteRule{{Type: "http_date"}}},
		{Name: "get_linux", Signature: config.SignatureConfig{Pattern: "GET ", MinLength: 4}, ResponseFile: "ngx.bin",
			Requires: map[string]string{"os_family": "linux"}, RewriteRules: []config.RewriteRule{{Type: "http_date"}}},
	}
	cur := time.Now().UTC().Format("02 Jan 2006")
	cases := map[string]string{"windows": "Microsoft-IIS/10.0", "linux": "nginx/1.18.0 (Ubuntu)"}
	for fam, wantServer := range cases {
		cfg := &config.ServiceConfig{Name: "http", Port: 0, Protocol: "tcp", Probes: probes}
		l, conn := startSvc(t, cfg, dir, map[string]string{"os_family": fam})
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		got := string(buf[:n])
		conn.Close()
		l.Stop()
		if !strings.Contains(got, wantServer) {
			t.Errorf("%s: Server header missing %q in %q", fam, wantServer, got)
		}
		if strings.Contains(got, ph) {
			t.Errorf("%s: Date placeholder not rewritten: %q", fam, got)
		}
		if !strings.Contains(got, cur) {
			t.Errorf("%s: Date not current (want %q) in %q", fam, cur, got)
		}
	}
}
