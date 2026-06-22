package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEditionExposesPort(t *testing.T) {
	cases := []struct {
		edition string
		port    uint16
		want    bool
	}{
		{"", 139, true},
		{"workstation", 139, false},
		{"workstation", 135, false},
		{"workstation", 445, false},
		{"server", 139, true},
		{"server", 135, true},
		{"dc", 139, true},
		{"server", 445, true},
		// Desktop-persona ports: workstation exposes, server/dc filter, non-Windows n/a.
		{"workstation", 5357, true},
		{"workstation", 7680, true},
		{"server", 5357, false},
		{"dc", 7680, false},
		{"", 5357, true},
		// 5040 (CDPSvc) is NOT a persona port (not a default Win11 listener) — it
		// hits the generic default, exposed everywhere, never specially gated.
		{"workstation", 5040, true},
		{"server", 5040, true},
		// WinRM (5985) is not edition-gated here — generic default applies.
		{"workstation", 5985, true},
		{"server", 5985, true},
	}
	for _, tc := range cases {
		if got := EditionExposesPort(tc.edition, tc.port); got != tc.want {
			t.Fatalf("EditionExposesPort(%q, %d) = %v, want %v", tc.edition, tc.port, got, tc.want)
		}
	}
}

func TestServiceListenPorts(t *testing.T) {
	// Build a minimal services dir with two template manifests.
	dir := t.TempDir()
	writeManifest := func(name string, port int) {
		sub := filepath.Join(dir, name)
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "name: " + name + "\nport: " + itoa(port) + "\nprotocol: tcp\n"
		if err := os.WriteFile(filepath.Join(sub, "manifest.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest("wsd", 5357)
	writeManifest("winrm", 5985)

	ws := &OSProfile{Name: "Windows 11", Family: "windows", Edition: "workstation"}
	srv := &OSProfile{Name: "Windows Server 2022", Family: "windows", Edition: "server"}

	// Workstation: smb_honeypot binds 445 only (no 139), plus template ports.
	got := ServiceListenPorts([]string{"smb_honeypot", "rdp", "wsd", "winrm"}, ws, dir)
	want := []uint16{445, 3389, 5357, 5985}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("workstation ServiceListenPorts = %v, want %v", got, want)
	}

	// Server: smb_honeypot also binds 139.
	got = ServiceListenPorts([]string{"smb_honeypot"}, srv, dir)
	want = []uint16{139, 445}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("server ServiceListenPorts = %v, want %v", got, want)
	}

	// Unknown/missing template manifest contributes no port (skipped, not zero).
	got = ServiceListenPorts([]string{"nonexistent", "rdp"}, ws, dir)
	want = []uint16{3389}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing-manifest ServiceListenPorts = %v, want %v", got, want)
	}
}

// itoa avoids importing strconv just for the test manifest builder.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}