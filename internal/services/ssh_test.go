package services

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
)

// TestSSHServerFirstPerOS verifies the new speaks-first path: the listener sends
// the OS-appropriate banner immediately on connect (before the client sends
// anything), selected via `requires` gating on the profile options.
func TestSSHServerFirstPerOS(t *testing.T) {
	dir := t.TempDir()
	const (
		ubuntu  = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
		linux   = "SSH-2.0-OpenSSH_9.6p1\r\n"
		windows = "SSH-2.0-OpenSSH_for_Windows_9.5\r\n"
	)
	for name, body := range map[string]string{
		"banner_ubuntu.bin": ubuntu, "banner_linux.bin": linux, "banner_windows.bin": windows,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	probes := []config.ProbeConfig{
		{Name: "ubuntu", ResponseFile: "banner_ubuntu.bin", Requires: map[string]string{"os_name": "Ubuntu"}},
		{Name: "linux", ResponseFile: "banner_linux.bin", Requires: map[string]string{"os_family": "linux"}},
		{Name: "windows", ResponseFile: "banner_windows.bin", Requires: map[string]string{"os_family": "windows"}},
		{Name: "default", ResponseFile: "banner_linux.bin"},
	}

	cases := []struct {
		name string
		opts map[string]string
		want string
	}{
		{"ubuntu", map[string]string{"os_name": "Ubuntu", "os_family": "linux"}, ubuntu},
		{"windows", map[string]string{"os_name": "Windows 11", "os_family": "windows"}, windows},
		{"alpine-fallback", map[string]string{"os_name": "Alpine Linux", "os_family": "linux"}, linux},
	}

	for _, tc := range cases {
		cfg := &config.ServiceConfig{Name: "ssh", Port: 0, Protocol: "tcp", SpeaksFirst: true, Probes: probes}
		l, err := NewListenerWithOptions(cfg, dir, tc.opts)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if err := l.Start(); err != nil {
			t.Fatalf("%s start: %v", tc.name, err)
		}
		addr := l.tcpLn.Addr().String()

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			l.Stop()
			t.Fatalf("%s dial: %v", tc.name, err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf) // read WITHOUT sending — server must speak first
		conn.Close()
		l.Stop()

		if got := string(buf[:n]); got != tc.want {
			t.Errorf("%s: banner = %q; want %q", tc.name, got, tc.want)
		}
	}
}
