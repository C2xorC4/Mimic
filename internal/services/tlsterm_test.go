package services

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHTTPPath(t *testing.T) {
	req := []byte("GET /admin/login HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := parseHTTPPath(req); got != "/admin/login" {
		t.Fatalf("parseHTTPPath = %q", got)
	}
}

func TestTLSBackendHTTPResponseLinuxDebian(t *testing.T) {
	httpDir := filepath.Join("..", "..", "services", "http")
	r := &Responder{options: map[string]string{"os_family": "linux", "os_name": "Debian"}}
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	out := string(r.TLSBackendHTTPResponse(req, httpDir))
	if !strings.Contains(out, "Server: nginx/1.22.1\r\n") {
		t.Fatalf("Debian HTTPS backend Server header: %q", out[:min(200, len(out))])
	}
	if !strings.Contains(out, "Welcome to nginx") {
		t.Fatalf("expected nginx body, got: %q", out[:min(200, len(out))])
	}
}

func TestTLSBackendHTTPResponseLinuxRocky(t *testing.T) {
	httpDir := filepath.Join("..", "..", "services", "http")
	r := &Responder{options: map[string]string{"os_family": "linux", "os_name": "Rocky Linux"}}
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	out := string(r.TLSBackendHTTPResponse(req, httpDir))
	if !strings.Contains(out, "Server: Apache/2.4.57 (Rocky Linux)\r\n") {
		t.Fatalf("Rocky HTTPS backend Server header: %q", out[:min(200, len(out))])
	}
	if !strings.Contains(out, "It works!") {
		t.Fatalf("expected Apache body, got: %q", out[:min(200, len(out))])
	}
}

func TestTLSBackendHTTPResponseWindows(t *testing.T) {
	r := &Responder{options: map[string]string{"os_family": "windows", "os_name": "Windows 11"}}
	out := string(r.TLSBackendHTTPResponse([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), ""))
	if !strings.Contains(out, "Server: Microsoft-IIS/10.0\r\n") {
		t.Fatalf("Windows HTTPS backend: %q", out[:min(120, len(out))])
	}
}

func TestIISHTTPResponseRootVsOther(t *testing.T) {
	root := string(iisHTTPResponse([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")))
	if !strings.HasPrefix(root, "HTTP/1.1 200 OK") {
		t.Fatalf("root response status: %q", root[:20])
	}
	other := string(iisHTTPResponse([]byte("GET /secret HTTP/1.1\r\nHost: x\r\n\r\n")))
	if !strings.HasPrefix(other, "HTTP/1.1 404 Not Found") {
		t.Fatalf("other path status: %q", other[:30])
	}
	if len(root) == len(other) {
		t.Fatalf("root and 404 bodies should differ in length (%d vs %d)", len(root), len(other))
	}
}