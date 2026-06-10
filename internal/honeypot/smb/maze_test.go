package smb

import (
	"encoding/binary"
	"testing"

	"github.com/c2xorc4/mimic/internal/deception"
)

// mazeVFS builds a VFS with a static C$ skeleton plus a generative ("maze: true")
// share FILES — the plausible, advertised tarpit entry point an attacker reaches
// by navigating into a listed share rather than guessing nonexistent paths.
func mazeVFS(t *testing.T) *VFS {
	t.Helper()
	tc := deception.TreeConfig{
		Shares: []deception.ShareDef{
			{Name: "C$", Type: "disk_special", Root: &deception.NodeDefGroup{
				Dirs: []deception.DirDef{{Name: "Windows"}, {Name: "Users"}},
			}},
			{Name: "FILES", Type: "disk", Maze: true},
		},
		Maze: deception.MazeConfig{Enabled: true, MaxDepth: 0, MinDirs: 3, MaxDirs: 5, MinFiles: 2, MaxFiles: 4},
	}
	v, err := newVFSFromConfig(tc, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestMazeStaticMiss404 — a name not present in a real directory's listing returns
// nil (NOT_FOUND), exactly like a real share. No fabrication of guessed names.
func TestMazeStaticMiss404(t *testing.T) {
	v := mazeVFS(t)
	for _, p := range []string{`Windows\NoSuchThing`, `Users\Nobody`, `NoSuchTop`, `Windows\a\b\c`} {
		if n := v.resolve("C$", p); n != nil {
			t.Errorf("resolve(C$, %q) = %+v; want nil (NOT_FOUND)", p, n)
		}
	}
}

// TestMazeGenerativeDiscoverable — the generative share lists children, exactly those
// listed children resolve (membership), a non-listed name 404s, and descent is
// infinite (a listed subdir is itself generative and lists more).
func TestMazeGenerativeDiscoverable(t *testing.T) {
	v := mazeVFS(t)
	root := v.resolve("FILES", "")
	if root == nil || root.mazePath == "" {
		t.Fatal("FILES root should be a generative node")
	}
	kids := buildMazeChildren(root.mazePath, root.mazeDepth, v.maze)
	if len(kids) == 0 {
		t.Fatal("generative share produced no children")
	}
	var aDir *VFSNode
	for _, c := range kids {
		if v.resolve("FILES", c.name) == nil {
			t.Errorf("listed child %q did not resolve", c.name)
		}
		if c.isDir() && aDir == nil {
			aDir = c
		}
	}
	if v.resolve("FILES", "zzz_not_listed_zzz") != nil {
		t.Error("non-listed name resolved under generative share (should 404)")
	}
	if aDir == nil {
		t.Fatal("expected at least one generated subdir")
	}
	sub := v.resolve("FILES", aDir.name)
	if sub == nil || sub.mazePath == "" {
		t.Fatal("generated subdir should itself be generative")
	}
	if len(buildMazeChildren(sub.mazePath, sub.mazeDepth, v.maze)) == 0 {
		t.Error("generated subdir lists no children (tarpit bottomed out)")
	}
}

// TestMazeDeterminism — same generative path yields identical listings; siblings differ.
func TestMazeDeterminism(t *testing.T) {
	v := mazeVFS(t)
	a := buildMazeChildren(`FILES\Alpha`, 1, v.maze)
	b := buildMazeChildren(`FILES\Alpha`, 1, v.maze)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].name != b[i].name {
			t.Errorf("child[%d]: %q vs %q", i, a[i].name, b[i].name)
		}
	}
	c := buildMazeChildren(`FILES\Beta`, 1, v.maze)
	same := len(a) == len(c)
	if same {
		for i := range a {
			if a[i].name != c[i].name {
				same = false
				break
			}
		}
	}
	if same {
		t.Error("different paths produced identical children")
	}
}

// TestMazeDepthLimit — a finite MaxDepth terminates the tarpit (no subdirs past the cap).
func TestMazeDepthLimit(t *testing.T) {
	tc := deception.TreeConfig{
		Shares: []deception.ShareDef{{Name: "FILES", Type: "disk", Maze: true}},
		Maze:   deception.MazeConfig{Enabled: true, MaxDepth: 2, MinDirs: 2, MaxDirs: 2, MinFiles: 1, MaxFiles: 1},
	}
	v, err := newVFSFromConfig(tc, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range buildMazeChildren(`FILES\A\B`, 2, v.maze) {
		if c.isDir() {
			t.Errorf("MaxDepth=2: subdir generated past cap: %q", c.name)
		}
	}
}

// TestMazeBaitFiles — sensitive-looking generated names carry bait content.
func TestMazeBaitFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"passwords.txt", true}, {"credentials.txt", true}, {"id_rsa", true},
		{"error.log", false}, {"config.xml", false},
	} {
		if got := len(mazeFileContent(tc.name)) > 0; got != tc.want {
			t.Errorf("mazeFileContent(%q)=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestMazeStateMachine — full wire flow into the generative share: connect to FILES,
// descend into a *listed* generated subdirectory, and enumerate it (infinite descent).
func TestMazeStateMachine(t *testing.T) {
	mc := deception.MazeConfig{Enabled: true, MaxDepth: 0, MinDirs: 3, MaxDirs: 5, MinFiles: 2, MaxFiles: 4}
	srv := New(Config{ComputerName: "TESTBOX", DomainName: "TESTDOM", Filesystem: &deception.TreeConfig{
		Shares: []deception.ShareDef{
			{Name: "FILES", Type: "disk", Maze: true},
			{Name: "IPC$", Type: "ipc"},
		},
		Maze: mc,
	}})

	ln, err := newFreeListener()
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	srv.cfg.Port = uint16(extractPort(addr))
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)

	conn, err := dialAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	sessionID, treeID := doAuth(t, conn, `\\TESTBOX\FILES`)
	var msgID uint64
	next := func() uint64 { msgID += 10; return msgID }

	// Pick a generated subdirectory name deterministically (what LIST would show).
	var childDir string
	for _, c := range buildMazeChildren("FILES", 0, &mc) {
		if c.isDir() {
			childDir = c.name
			break
		}
	}
	if childDir == "" {
		t.Fatal("no generated subdir at FILES root")
	}

	// CREATE that listed child → resolves (membership), QUERY_DIRECTORY → entries.
	resp := sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, next(), buildCreateBody(childDir)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("create listed maze dir %q: want 0, got %#x", childDir, respStatus(resp))
	}
	dh := extractVolatileID(resp)
	resp = sendRecv(t, conn, buildTestPacket(CmdQueryDirectory, sessionID, treeID, next(), buildQueryDirBody(3, dh)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("query maze dir: want 0, got %#x", respStatus(resp))
	}
	if binary.LittleEndian.Uint32(resp[68+4:68+8]) == 0 {
		t.Fatal("generative subdir QUERY_DIRECTORY returned empty buffer")
	}

	// A guessed name NOT in the listing must 404 (no fabrication).
	resp = sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, next(), buildCreateBody(`zzz_not_listed_zzz`)))
	if respStatus(resp) != StatusObjectNotFound {
		t.Fatalf("guessed name: want %#x, got %#x", StatusObjectNotFound, respStatus(resp))
	}
}
