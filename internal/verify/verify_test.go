package verify

import (
	"testing"

	"github.com/c2xorc4/mimic/internal/config"
)

func TestCheckProfileConsistency(t *testing.T) {
	win11 := &config.OSProfile{Name: "Windows 11", Family: "windows", Version: "10.0.26200"}
	win11.Stack.WindowSize = 65535
	win11.Stack.TCPTimestamps = true
	if r := checkProfileConsistency(win11); r.Status != StatusOK {
		t.Fatalf("coherent Win11 → %s (%s)", r.Status, r.Detail)
	}

	// Win11-class build advertising the Win10 stack = the documented tell.
	bad := &config.OSProfile{Name: "Windows 11", Family: "windows", Version: "10.0.26200"}
	bad.Stack.WindowSize = 8192
	bad.Stack.TCPTimestamps = false
	if r := checkProfileConsistency(bad); r.Status != StatusTell {
		t.Fatalf("Win11 build + Win10 stack should be a TELL, got %s", r.Status)
	}

	// Server-class is not held to the Win11 65535/TS rule.
	srv := &config.OSProfile{Name: "Windows Server 2022", Family: "windows", Version: "10.0.20348"}
	srv.Stack.WindowSize = 8192
	if r := checkProfileConsistency(srv); r.Status != StatusOK {
		t.Fatalf("server profile → %s (%s)", r.Status, r.Detail)
	}

	// Unparseable version is a tell; non-Windows is skipped.
	if r := checkProfileConsistency(&config.OSProfile{Family: "windows", Version: "garbage"}); r.Status != StatusTell {
		t.Fatalf("bad version should be a TELL, got %s", r.Status)
	}
	if r := checkProfileConsistency(&config.OSProfile{Family: "linux", Version: "5.15"}); r.Status != StatusSkip {
		t.Fatalf("non-Windows should SKIP, got %s", r.Status)
	}
}

func TestParseVersion(t *testing.T) {
	if maj, min, b, ok := parseVersion("10.0.26200"); !ok || maj != 10 || min != 0 || b != 26200 {
		t.Fatalf("parseVersion = %d.%d.%d ok=%v", maj, min, b, ok)
	}
	if _, _, _, ok := parseVersion("10.0"); ok {
		t.Fatal("parseVersion should reject 2-component version")
	}
}

func TestHTTPHeader(t *testing.T) {
	resp := "HTTP/1.1 404 Not Found\r\nServer: Microsoft-HTTPAPI/2.0\r\nDate: x\r\n\r\n"
	if got := httpHeader(resp, "Server"); got != "Microsoft-HTTPAPI/2.0" {
		t.Fatalf("httpHeader = %q", got)
	}
}
