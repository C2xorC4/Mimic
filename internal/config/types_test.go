package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// TestAppConfigRoundTrip verifies the Phase-1 schema additions (shared credential
// pool, leak wiring, and the SMB honeypot config-driven filesystem) unmarshal into
// the expected structs.
func TestAppConfigRoundTrip(t *testing.T) {
	const doc = `
profile: "Windows 11"
services: [smb_honeypot, http, ssh]
credentials:
  - id: backup_svc
    username: svc_backup
    password: V33m@Backup!23
    domain: CORP
  - id: sql_sa
    username: sa
    password: Adm1n@SQL2019!
credential_leaks:
  - cred: backup_svc
    via: http
    location: body
smb_honeypot:
  allow_guest_enum: true
  accept_credentials: [backup_svc, sql_sa]
  filesystem:
    shares:
      - name: C$
        type: disk_special
        remark: "Default share"
        root:
          dirs:
            - name: Users
              files:
                - name: creds.txt
                  content: "u={{cred:backup_svc.username}}"
      - name: BACKUPS
        type: disk
        generate:
          seed: "v1"
          dirs: { min: 4, max: 8 }
          files: { min: 2, max: 6 }
          depth: 2
      - name: IPC$
        type: ipc
    maze:
      enabled: true
      max_depth: 8
      min_dirs: 3
      max_dirs: 7
      min_files: 2
      max_files: 5
`
	var cfg AppConfig
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(cfg.Credentials) != 2 || cfg.Credentials[0].ID != "backup_svc" || cfg.Credentials[0].Domain != "CORP" {
		t.Fatalf("credentials pool: %+v", cfg.Credentials)
	}
	if len(cfg.CredentialLeaks) != 1 || cfg.CredentialLeaks[0].Via != "http" || cfg.CredentialLeaks[0].Cred != "backup_svc" {
		t.Fatalf("credential_leaks: %+v", cfg.CredentialLeaks)
	}
	if cfg.SMBHoneypot.AllowGuestEnum == nil || !*cfg.SMBHoneypot.AllowGuestEnum {
		t.Fatal("allow_guest_enum should be true")
	}
	if got := cfg.SMBHoneypot.AcceptCredentials; len(got) != 2 || got[0] != "backup_svc" {
		t.Fatalf("accept_credentials: %+v", got)
	}

	fs := cfg.SMBHoneypot.Filesystem
	if fs == nil {
		t.Fatal("filesystem should be non-nil")
	}
	if len(fs.Shares) != 3 {
		t.Fatalf("want 3 shares, got %d", len(fs.Shares))
	}
	// explicit + seeded
	cShare := fs.Shares[0]
	if cShare.Name != "C$" || cShare.Type != "disk_special" || cShare.Root == nil {
		t.Fatalf("C$ share: %+v", cShare)
	}
	if cShare.Root.Dirs[0].Files[0].Content != "u={{cred:backup_svc.username}}" {
		t.Fatalf("inline content: %q", cShare.Root.Dirs[0].Files[0].Content)
	}
	// generate mode
	bShare := fs.Shares[1]
	if bShare.Generate == nil || bShare.Generate.Seed != "v1" || bShare.Generate.Dirs.Max != 8 || bShare.Generate.Depth != 2 {
		t.Fatalf("BACKUPS generate: %+v", bShare.Generate)
	}
	// maze
	if !fs.Maze.Enabled || fs.Maze.MaxDepth != 8 || fs.Maze.MaxDirs != 7 {
		t.Fatalf("maze: %+v", fs.Maze)
	}
}

// TestAppConfigDefaultsNoFilesystem confirms an omitted filesystem block leaves
// the pointer nil (so the honeypot falls back to its default tree).
func TestAppConfigDefaultsNoFilesystem(t *testing.T) {
	var cfg AppConfig
	if err := yaml.Unmarshal([]byte("profile: \"Windows 11\"\nsmb_honeypot:\n  allow_guest_enum: false\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SMBHoneypot.Filesystem != nil {
		t.Error("filesystem should be nil when omitted")
	}
	if cfg.SMBHoneypot.AllowGuestEnum == nil || *cfg.SMBHoneypot.AllowGuestEnum {
		t.Error("allow_guest_enum should be explicitly false")
	}
}
