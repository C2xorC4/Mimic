package services

import (
	"strings"
	"testing"
)

func TestParseHTTPPath(t *testing.T) {
	req := []byte("GET /admin/login HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := parseHTTPPath(req); got != "/admin/login" {
		t.Fatalf("parseHTTPPath = %q", got)
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