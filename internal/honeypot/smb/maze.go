package smb

import (
	"fmt"
	"hash/fnv"
	"strings"
	"time"
)

// MazeConfig controls the infinite virtual filesystem generator.
// A zero-value MazeConfig is treated as disabled; use defaultMazeConfig() for defaults.
type MazeConfig struct {
	Enabled  bool
	MaxDepth int // 0 = unlimited
	MinDirs  int // min subdirectories generated per level
	MaxDirs  int // max subdirectories generated per level
	MinFiles int // min files generated per level
	MaxFiles int // max files generated per level
}

func defaultMazeConfig() MazeConfig {
	return MazeConfig{Enabled: true, MaxDepth: 0, MinDirs: 3, MaxDirs: 7, MinFiles: 2, MaxFiles: 5}
}

// --- deterministic RNG ---

// lcg is a seeded 64-bit linear congruential generator.
type lcg struct{ state uint64 }

func newLCG(seed uint64) *lcg { return &lcg{state: seed} }

func (l *lcg) next() uint64 {
	l.state = l.state*6364136223846793005 + 1442695040888963407
	return l.state
}

func (l *lcg) intn(n int) int {
	if n <= 1 {
		return 0
	}
	return int(l.next() % uint64(n))
}

// pathSeed returns a deterministic 64-bit seed for a canonical path string.
func pathSeed(path string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(strings.ToLower(path)))
	return h.Sum64()
}

// pickUnique picks an unused name from corpus; falls back to name+number after 5 collisions.
func pickUnique(rng *lcg, corpus []string, used map[string]bool) string {
	for i := 0; i < 5; i++ {
		name := corpus[rng.intn(len(corpus))]
		if !used[name] {
			used[name] = true
			return name
		}
	}
	for i := 1; ; i++ {
		name := fmt.Sprintf("%s%d", corpus[rng.intn(len(corpus))], i)
		if !used[name] {
			used[name] = true
			return name
		}
	}
}

// buildMazeChildren generates a deterministic child list for parentPath at parentDepth.
func buildMazeChildren(parentPath string, parentDepth int, cfg *MazeConfig) []*VFSNode {
	rng := newLCG(pathSeed(parentPath))

	nDirs := cfg.MinDirs + rng.intn(cfg.MaxDirs-cfg.MinDirs+1)
	nFiles := cfg.MinFiles + rng.intn(cfg.MaxFiles-cfg.MinFiles+1)

	nextDepth := parentDepth + 1
	if cfg.MaxDepth > 0 && nextDepth > cfg.MaxDepth {
		nDirs = 0 // no subdirectories at max depth
	}

	used := make(map[string]bool)
	var children []*VFSNode

	for i := 0; i < nDirs; i++ {
		name := pickUnique(rng, mazeDirCorpus, used)
		childPath := parentPath + `\` + name
		children = append(children, newMazeDirNode(childPath, name, nextDepth))
	}
	for i := 0; i < nFiles; i++ {
		name := pickUnique(rng, mazeFileCorpus, used)
		childPath := parentPath + `\` + name
		children = append(children, newMazeFileNode(childPath, name))
	}
	return children
}

func newMazeDirNode(path, name string, depth int) *VFSNode {
	t := mazeNodeTime(path)
	return &VFSNode{
		name: name, attrs: FileAttrDirectory,
		created: t, modified: t,
		mazePath: path, mazeDepth: depth,
	}
}

func newMazeFileNode(path, name string) *VFSNode {
	t := mazeNodeTime(path)
	return &VFSNode{
		name: name, attrs: FileAttrArchive,
		content:  mazeFileContent(name),
		created:  t,
		modified: t,
		mazePath: path,
	}
}

// mazeNodeTime returns a deterministic creation timestamp for a path.
func mazeNodeTime(path string) time.Time {
	rng := newLCG(pathSeed(path))
	base := vfsBaseTime()
	return base.Add(-time.Duration(rng.next()%uint64(180*24)) * time.Hour)
}

// mazeFileContent returns bait content for files with sensitive-looking names,
// nil for ordinary files.
func mazeFileContent(name string) []byte {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "password") || lower == "credentials.txt" || lower == "accounts.txt":
		return baitPasswords
	case strings.Contains(lower, "credential") || strings.Contains(lower, "backup_cred"):
		return baitBackupCreds
	case lower == "id_rsa" || lower == "private.key" || lower == "server.key":
		return baitSSHKey
	default:
		return nil
	}
}

// --- naming corpora ---

var mazeDirCorpus = []string{
	"AppData", "Application Data", "Cache", "Config", "Configs",
	"Data", "Database", "Databases", "Logs", "Log",
	"Backup", "Backups", "Archive", "Archives",
	"Temp", "Temporary", "Working", "Work",
	"Microsoft", "Adobe", "Oracle", "SAP", "Citrix", "VMware",
	"Intel", "HP", "Dell", "Symantec", "Sophos",
	"Reports", "Export", "Import",
	"Scripts", "Tools", "Utilities", "Bin", "Lib",
	"2022", "2023", "2024",
	"v1", "v2", "v2.1", "old", "new", "current",
	"Users", "Groups", "Accounts", "Settings",
	"Production", "Development", "Staging", "Test",
	"Server", "Client", "Service", "Agent",
	"Shared", "Public", "Private", "Internal",
	"Resources", "Assets", "Content",
}

var mazeFileCorpus = []string{
	"error.log", "debug.log", "access.log", "application.log",
	"system.log", "event.log", "audit.log", "security.log",
	"install.log", "setup.log", "update.log",
	"config.xml", "settings.xml", "app.config", "web.config",
	"database.db", "users.db", "config.db",
	"backup.dat", "export.dat", "data.dat",
	"passwords.txt", "credentials.txt", "accounts.txt",
	"readme.txt", "notes.txt", "todo.txt",
	"service.ini", "settings.ini", "config.ini",
	"dump.sql", "backup.sql",
	"private.key", "server.key", "cert.pem",
	"id_rsa", "authorized_keys",
	"deploy.bat", "startup.bat",
}

// baitSSHKey is a plausible-looking (but fake) RSA private key.
var baitSSHKey = []byte(
	"-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEpAIBAAKCAQEA2a2rwplBQLzamygykEMmYz0+Kcj3bKBp29P2rFj7qQROep\n" +
		"q1pnMxzBNV5dEomD8V8bJZ9gQEoMqrLHNYKjb2MQZG1SLAe0+qkVxMRZ5CgTM\n" +
		"lrX9QVuWPMpCuuB9hNAXM5G5p3N7HJMT8s6I5bDRJqIyFLRBdAT0iOKgMJEhV\n" +
		"K9GXMV2LQJM9hKEf4q8lZnlRN+0pNDhkHdJzOFG8MZ9aLePYVmEBSgOFiMN5b\n" +
		"PX5MQQr8G4V9RjFqI7BmHwD+mVkSbPfFXvXyLX8q5VVfRQ5O2J6Lw8h3AqtWx\n" +
		"V+Z5kZlK3XDYF+z5PGT7Bq3X9W0j8I0RvRwIDAQABAoIBAC5RgZ+hBx7xHNaM\n" +
		"-----END RSA PRIVATE KEY-----\n",
)
