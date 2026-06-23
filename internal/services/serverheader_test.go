package services

import (
	"strings"
	"testing"
)

func TestServerStringFor(t *testing.T) {
	cases := map[string]string{
		"Ubuntu":      "nginx/1.18.0 (Ubuntu)",
		"Debian":      "nginx/1.22.1",
		"Rocky Linux": "Apache/2.4.57 (Rocky Linux)",
		"Fedora":      "Apache/2.4.62 (Fedora Linux)",
		"Arch Linux":  "nginx/1.27.4",
		"Kali":        "nginx/1.26.0 (Debian)",
		"":            "",
	}
	for name, want := range cases {
		if got := serverStringFor(name); got != want {
			t.Errorf("serverStringFor(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestWebServerForOS(t *testing.T) {
	cases := map[string]string{
		"Ubuntu":      "nginx",
		"Debian":      "nginx",
		"Kali":        "nginx",
		"Arch Linux":  "nginx",
		"Rocky Linux": "apache",
		"AlmaLinux":   "apache",
		"Fedora":      "apache",
		"RHEL":        "apache",
	}
	for name, want := range cases {
		if got := webServerForOS(name); got != want {
			t.Errorf("webServerForOS(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestApplyServerHeader(t *testing.T) {
	resp := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Length: 2\r\n\r\nhi")

	// Linux/Rocky → per-distro Apache string (RHEL family); body untouched.
	r := &Responder{options: map[string]string{"os_family": "linux", "os_name": "Rocky Linux"}}
	out := r.applyServerHeader(resp)
	if !strings.Contains(string(out), "Server: Apache/2.4.57 (Rocky Linux)\r\n") {
		t.Errorf("Rocky header not applied: %q", out)
	}
	if !strings.HasSuffix(string(out), "\r\n\r\nhi") {
		t.Errorf("body corrupted: %q", out)
	}

	// Ubuntu → its own string.
	ru := &Responder{options: map[string]string{"os_family": "linux", "os_name": "Ubuntu"}}
	if !strings.Contains(string(ru.applyServerHeader(resp)), "Server: nginx/1.18.0 (Ubuntu)\r\n") {
		t.Errorf("Ubuntu header wrong")
	}

	// Windows family → unchanged (no Linux rewrite).
	rw := &Responder{options: map[string]string{"os_family": "windows", "os_name": "Windows 11"}}
	if string(rw.applyServerHeader(resp)) != string(resp) {
		t.Errorf("windows response should be unchanged")
	}

	// Non-HTTP payload → unchanged.
	raw := []byte("\x00\xfeSMB not http")
	if string(r.applyServerHeader(raw)) != string(raw) {
		t.Errorf("non-HTTP response should be unchanged")
	}
}
