package ssh

import (
	"os"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

func TestSFTPHandler(t *testing.T) {
	s := testServer(t)
	h := &sftpHandler{s: s, remote: "10.9.9.9:5555"}

	// List /etc → the seeded files.
	lister, err := h.Filelist(&sftp.Request{Method: "List", Filepath: "/etc"})
	if err != nil {
		t.Fatalf("Filelist /etc: %v", err)
	}
	buf := make([]os.FileInfo, 32)
	n, _ := lister.ListAt(buf, 0)
	names := map[string]bool{}
	for _, fi := range buf[:n] {
		names[fi.Name()] = true
	}
	if !names["passwd"] || !names["os-release"] {
		t.Errorf("List /etc names = %v, want passwd + os-release", names)
	}

	// Download the cred-leak breadcrumb.
	ra, err := h.Fileread(&sftp.Request{Method: "Get", Filepath: "/root/.credentials"})
	if err != nil {
		t.Fatalf("Fileread /root/.credentials: %v", err)
	}
	content := make([]byte, 256)
	cn, _ := ra.ReadAt(content, 0)
	if got := string(content[:cn]); !strings.Contains(got, "svc_backup") {
		t.Errorf("cred file = %q, want svc_backup", got)
	}

	// Stat a file.
	st, err := h.Filelist(&sftp.Request{Method: "Stat", Filepath: "/etc/passwd"})
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	one := make([]os.FileInfo, 1)
	if k, _ := st.ListAt(one, 0); k != 1 || one[0].Name() != "passwd" || one[0].IsDir() {
		t.Errorf("Stat /etc/passwd = %+v (k=%d)", one[0], k)
	}

	// Writes are denied (read-only honeypot).
	if _, err := h.Filewrite(&sftp.Request{Method: "Put", Filepath: "/tmp/x"}); err != os.ErrPermission {
		t.Errorf("Filewrite err = %v, want permission denied", err)
	}
	if err := h.Filecmd(&sftp.Request{Method: "Remove", Filepath: "/etc/passwd"}); err != os.ErrPermission {
		t.Errorf("Filecmd err = %v, want permission denied", err)
	}

	// Missing file → not exist.
	if _, err := h.Fileread(&sftp.Request{Method: "Get", Filepath: "/nope"}); err != os.ErrNotExist {
		t.Errorf("Fileread missing = %v, want not-exist", err)
	}
}
