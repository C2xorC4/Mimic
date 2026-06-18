package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/deception"
)

func TestHTTPCredentialLeakAndContentLength(t *testing.T) {
	dir := t.TempDir()
	body := "Veeam Backup Service Account\r\n{{leak:backup_svc}}\r\n"
	tmpl := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n" + body
	if err := os.WriteFile(filepath.Join(dir, "leak.bin"), []byte(tmpl), 0o644); err != nil {
		t.Fatal(err)
	}

	store := deception.NewCredStore([]deception.Credential{{
		ID: "backup_svc", Username: "svc_backup", Password: "V33m@Backup!23", Domain: "CORP",
	}})
	r, err := NewResponder(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.SetCredStore(store)

	got, err := r.GetResponse("leak.bin", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if strings.Contains(s, "{{leak:") {
		t.Fatalf("leak placeholder not substituted: %q", s)
	}
	if !strings.Contains(s, "svc_backup:V33m@Backup!23") {
		t.Fatalf("expected leaked cred in body, got %q", s)
	}
	parts := strings.SplitN(s, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("missing body separator: %q", s)
	}
	wantLen := len(parts[1])
	if !strings.Contains(parts[0], "Content-Length: "+itoa(wantLen)) {
		t.Fatalf("Content-Length not fixed: header=%q body_len=%d", parts[0], wantLen)
	}

	cfg := &config.ServiceConfig{
		Name: "http", Port: 0, Protocol: "tcp",
		Probes: []config.ProbeConfig{{
			Name: "get_backup", Signature: config.SignatureConfig{Pattern: "GET /backup_credentials", MinLength: 22},
			ResponseFile: "leak.bin", RewriteRules: []config.RewriteRule{{Type: "http_date"}},
		}},
	}
	l, conn := startSvc(t, cfg, dir, map[string]string{"os_family": "windows"})
	l.SetCredStore(store)
	conn.Write([]byte("GET /backup_credentials.txt HTTP/1.1\r\nHost: x\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	conn.Close()
	l.Stop()
	if !strings.Contains(resp, "svc_backup:V33m@Backup!23") {
		t.Fatalf("listener path missing leak: %q", resp)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}