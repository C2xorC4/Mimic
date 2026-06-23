package ssh

import (
	"strings"
	"testing"

	"github.com/c2xorc4/mimic/internal/deception"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	store := deception.NewCredStore([]deception.Credential{
		{ID: "backup_svc", Username: "svc_backup", Password: "Passw0rd123", Domain: "WORKGROUP"},
	})
	s, err := New(Config{OSName: "Ubuntu", Hostname: "web01", CredStore: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestDistroFor(t *testing.T) {
	cases := map[string]string{
		"Ubuntu":           "ubuntu",
		"Debian":           "debian",
		"Rocky Linux":      "rocky",
		"Fedora":           "fedora",
		"Arch Linux":       "arch",
		"Kali":             "kali",
		"SomethingUnknown": "ubuntu", // fallback
	}
	for name, wantID := range cases {
		if got := distroFor(name); got.osID != wantID {
			t.Errorf("distroFor(%q).osID = %q, want %q", name, got.osID, wantID)
		}
		if !strings.HasPrefix(distroFor(name).sshBanner, "SSH-2.0-OpenSSH_") {
			t.Errorf("distroFor(%q) banner not an OpenSSH SSH-2.0 string", name)
		}
	}
}

func TestCheckCred(t *testing.T) {
	s := testServer(t)
	if !s.checkCred("svc_backup", "Passw0rd123") {
		t.Error("seeded cred should authenticate")
	}
	if s.checkCred("svc_backup", "wrong") {
		t.Error("wrong password must be rejected")
	}
	if s.checkCred("nobody", "Passw0rd123") {
		t.Error("unknown user must be rejected")
	}
}

func TestShellCommands(t *testing.T) {
	s := testServer(t)
	sess := &shellSession{user: "svc_backup", cwd: "/home/svc_backup"}
	r := "10.9.9.9:5555"

	if got := s.runCommand(sess, "pwd", r); got != "/home/svc_backup\n" {
		t.Errorf("pwd = %q", got)
	}
	if got := s.runCommand(sess, "whoami", r); got != "svc_backup\n" {
		t.Errorf("whoami = %q", got)
	}
	if got := s.runCommand(sess, "uname -r", r); !strings.Contains(got, "5.15.0") {
		t.Errorf("uname -r = %q, want Ubuntu kernel", got)
	}
	if got := s.runCommand(sess, "uname -a", r); !strings.Contains(got, "Linux web01") {
		t.Errorf("uname -a = %q", got)
	}
	// cd then pwd
	if out := s.runCommand(sess, "cd /etc", r); out != "" {
		t.Errorf("cd /etc unexpected output %q", out)
	}
	if sess.cwd != "/etc" {
		t.Errorf("cwd = %q, want /etc", sess.cwd)
	}
	if got := s.runCommand(sess, "cat os-release", r); !strings.Contains(got, "Ubuntu") {
		t.Errorf("cat os-release = %q, want Ubuntu", got)
	}
	if got := s.runCommand(sess, "ls", r); !strings.Contains(got, "passwd") || !strings.Contains(got, "os-release") {
		t.Errorf("ls /etc = %q, want passwd + os-release", got)
	}
	// /etc/passwd carries the seeded user
	if got := s.runCommand(sess, "cat passwd", r); !strings.Contains(got, "svc_backup") {
		t.Errorf("cat passwd = %q, want svc_backup entry", got)
	}
	// unknown command
	if got := s.runCommand(sess, "frobnicate", r); !strings.Contains(got, "command not found") {
		t.Errorf("unknown cmd = %q", got)
	}
}

func TestCredLeakBreadcrumb(t *testing.T) {
	s := testServer(t)
	sess := &shellSession{user: "root", cwd: "/root"}
	out := s.runCommand(sess, "cat /root/.credentials", "10.9.9.9:5555")
	if !strings.Contains(out, "svc_backup") || !strings.Contains(out, "Passw0rd123") {
		t.Errorf("cred-leak file = %q, want the pooled credential", out)
	}
}

func TestExecDecode(t *testing.T) {
	// SSH exec payload: 4-byte big-endian length + command bytes.
	cmd := "id"
	payload := []byte{0, 0, 0, byte(len(cmd))}
	payload = append(payload, cmd...)
	if got := decodeString(payload); got != "id" {
		t.Errorf("decodeString = %q, want id", got)
	}
	if got := decodeString(nil); got != "" {
		t.Errorf("decodeString(nil) = %q, want empty", got)
	}
}
