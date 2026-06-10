package deception

import (
	"fmt"
	"hash/fnv"
	"strings"
	"time"
)

// MazeConfig controls the infinite virtual filesystem generator.
// A zero-value MazeConfig is treated as disabled; use DefaultMazeConfig() for defaults.
//
// This is the protocol-neutral home of the maze generator (moved out of the SMB
// honeypot). It produces *Node trees; a protocol adapter (e.g. the SMB VFS)
// converts Node into its own wire representation.
type MazeConfig struct {
	Enabled  bool `yaml:"enabled"`
	MaxDepth int  `yaml:"max_depth"` // 0 = unlimited
	MinDirs  int  `yaml:"min_dirs"`  // min subdirectories generated per level
	MaxDirs  int  `yaml:"max_dirs"`  // max subdirectories generated per level
	MinFiles int  `yaml:"min_files"` // min files generated per level
	MaxFiles int  `yaml:"max_files"` // max files generated per level
}

// DefaultMazeConfig returns the standard unlimited-depth maze settings.
func DefaultMazeConfig() MazeConfig {
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

// MazeChildren generates a deterministic child list for parentPath at parentDepth.
// Generation is lazy and stateless: callers invoke it per directory request and
// must NOT memoize the full tree (memory stays O(open handles × children/dir)).
func MazeChildren(parentPath string, parentDepth int, cfg *MazeConfig) []*Node {
	rng := newLCG(pathSeed(parentPath))

	nDirs := cfg.MinDirs + rng.intn(cfg.MaxDirs-cfg.MinDirs+1)
	nFiles := cfg.MinFiles + rng.intn(cfg.MaxFiles-cfg.MinFiles+1)

	nextDepth := parentDepth + 1
	if cfg.MaxDepth > 0 && nextDepth > cfg.MaxDepth {
		nDirs = 0 // no subdirectories at max depth
	}

	used := make(map[string]bool)
	var children []*Node

	for i := 0; i < nDirs; i++ {
		name := pickUnique(rng, mazeDirCorpus, used)
		childPath := parentPath + `\` + name
		children = append(children, MazeDirNode(childPath, name, nextDepth))
	}
	for i := 0; i < nFiles; i++ {
		name := pickUnique(rng, mazeFileCorpus, used)
		childPath := parentPath + `\` + name
		children = append(children, MazeFileNode(childPath, name))
	}
	return children
}

// MazeDirNode builds a single maze directory node for the given canonical path.
func MazeDirNode(path, name string, depth int) *Node {
	t := mazeNodeTime(path)
	return &Node{
		Name: name, Dir: true,
		Created: t, Modified: t,
		MazePath: path, MazeDepth: depth,
	}
}

// MazeFileNode builds a single maze file node. Maze files carry the Archive
// attribute only (no Normal), matching the original SMB behavior.
func MazeFileNode(path, name string) *Node {
	t := mazeNodeTime(path)
	return &Node{
		Name: name, Archive: true,
		Content:  MazeFileContent(name),
		Created:  t,
		Modified: t,
		MazePath: path,
	}
}

// mazeNodeTime returns a deterministic creation timestamp for a path.
func mazeNodeTime(path string) time.Time {
	rng := newLCG(pathSeed(path))
	base := BaseTime()
	return base.Add(-time.Duration(rng.next()%uint64(180*24)) * time.Hour)
}

// MazeFileContent returns bait content for files with sensitive-looking names,
// nil for ordinary files.
func MazeFileContent(name string) []byte {
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
