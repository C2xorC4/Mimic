package smb

import (
	"encoding/binary"
	"testing"
)

// TestMazeResolution verifies that paths outside the static tree resolve to
// maze-generated nodes rather than nil.
func TestMazeResolution(t *testing.T) {
	v := newDefaultVFS(defaultMazeConfig())

	cases := []struct {
		share string
		path  string
		isDir bool
	}{
		// Unknown dir under static parent
		{"C$", `Program Files\FakeVendor`, true},
		// Two levels deep into the maze
		{"C$", `Program Files\FakeVendor\Configs`, true},
		// File with extension → maze file node
		{"C$", `Program Files\FakeVendor\config.xml`, false},
		// ADMIN$ (Windows dir) maze miss
		{"ADMIN$", `FakeSubsystem`, true},
		// IPC$ miss
		{"IPC$", `notexist`, true},
	}

	for _, tc := range cases {
		node := v.resolve(tc.share, tc.path)
		if node == nil {
			t.Errorf("resolve(%q, %q) = nil; want maze node", tc.share, tc.path)
			continue
		}
		if node.mazePath == "" {
			t.Errorf("resolve(%q, %q): expected maze node (mazePath set), got static node",
				tc.share, tc.path)
		}
		if tc.isDir != node.isDir() {
			t.Errorf("resolve(%q, %q): isDir=%v; want %v", tc.share, tc.path, node.isDir(), tc.isDir)
		}
	}
}

// TestMazeDeterminism verifies that the same path always produces the same children.
func TestMazeDeterminism(t *testing.T) {
	v := newDefaultVFS(defaultMazeConfig())

	path := `Program Files\FakeApp`
	node := v.resolve("C$", path)
	if node == nil || node.mazePath == "" {
		t.Fatal("expected maze node")
	}

	// Generate children twice and compare names.
	list1 := buildMazeChildren(node.mazePath, node.mazeDepth, v.maze)
	list2 := buildMazeChildren(node.mazePath, node.mazeDepth, v.maze)

	if len(list1) != len(list2) {
		t.Fatalf("non-deterministic: got %d vs %d children", len(list1), len(list2))
	}
	for i := range list1 {
		if list1[i].name != list2[i].name {
			t.Errorf("child[%d] name mismatch: %q vs %q", i, list1[i].name, list2[i].name)
		}
	}
}

// TestMazeDifferentPaths verifies that sibling paths produce different listings.
func TestMazeDifferentPaths(t *testing.T) {
	v := newDefaultVFS(defaultMazeConfig())

	n1 := v.resolve("C$", `Program Files\VendorA`)
	n2 := v.resolve("C$", `Program Files\VendorB`)
	if n1 == nil || n2 == nil {
		t.Fatal("expected maze nodes")
	}

	list1 := buildMazeChildren(n1.mazePath, n1.mazeDepth, v.maze)
	list2 := buildMazeChildren(n2.mazePath, n2.mazeDepth, v.maze)

	// At least one child should differ (overwhelmingly likely for different seeds).
	allSame := len(list1) == len(list2)
	if allSame {
		for i := range list1 {
			if list1[i].name != list2[i].name {
				allSame = false
				break
			}
		}
	}
	if allSame {
		t.Error("different paths produced identical children — seed not working")
	}
}

// TestMazeDepthLimit verifies that MaxDepth is enforced.
func TestMazeDepthLimit(t *testing.T) {
	cfg := MazeConfig{Enabled: true, MaxDepth: 2, MinDirs: 2, MaxDirs: 2, MinFiles: 1, MaxFiles: 1}
	v := newDefaultVFS(cfg)

	// depth 1 — should work
	n1 := v.resolve("C$", `Program Files\A`)
	if n1 == nil || !n1.isDir() {
		t.Fatal("expected maze dir at depth 1")
	}
	if n1.mazeDepth != 1 {
		t.Errorf("depth 1 node has mazeDepth=%d", n1.mazeDepth)
	}

	// depth 2 — should work
	n2 := v.resolve("C$", `Program Files\A\B`)
	if n2 == nil || !n2.isDir() {
		t.Fatal("expected maze dir at depth 2")
	}
	if n2.mazeDepth != 2 {
		t.Errorf("depth 2 node has mazeDepth=%d", n2.mazeDepth)
	}

	// depth 3 — should be blocked
	n3 := v.resolve("C$", `Program Files\A\B\C`)
	if n3 != nil {
		t.Errorf("expected nil at depth 3 (MaxDepth=2), got node: %+v", n3)
	}

	// depth 2 listing should have NO subdirectories
	children := buildMazeChildren(n2.mazePath, n2.mazeDepth, v.maze)
	for _, c := range children {
		if c.isDir() {
			t.Errorf("MaxDepth=2 node at depth 2 generated a subdirectory: %q", c.name)
		}
	}
}

// TestMazeBaitFiles verifies that bait-named maze files carry content.
func TestMazeBaitFiles(t *testing.T) {
	cases := []struct {
		name string
		want bool // true = non-empty content expected
	}{
		{"passwords.txt", true},
		{"credentials.txt", true},
		{"accounts.txt", true},
		{"id_rsa", true},
		{"private.key", true},
		{"error.log", false},
		{"config.xml", false},
	}
	for _, tc := range cases {
		content := mazeFileContent(tc.name)
		got := len(content) > 0
		if got != tc.want {
			t.Errorf("mazeFileContent(%q): non-empty=%v; want %v", tc.name, got, tc.want)
		}
	}
}

// TestMazeChildrenCountRange verifies that generated child counts respect MinDirs/MaxDirs.
func TestMazeChildrenCountRange(t *testing.T) {
	cfg := &MazeConfig{Enabled: true, MaxDepth: 0, MinDirs: 2, MaxDirs: 4, MinFiles: 1, MaxFiles: 3}

	// Sample several different paths and check counts.
	paths := []string{
		`C$\FolderAlpha`, `C$\FolderBeta`, `C$\FolderGamma`,
		`C$\FolderDelta`, `C$\FolderEpsilon`,
	}
	for _, p := range paths {
		depth := 1
		children := buildMazeChildren(p, depth, cfg)
		var nDirs, nFiles int
		for _, c := range children {
			if c.isDir() {
				nDirs++
			} else {
				nFiles++
			}
		}
		if nDirs < cfg.MinDirs || nDirs > cfg.MaxDirs {
			t.Errorf("path %q: nDirs=%d outside [%d,%d]", p, nDirs, cfg.MinDirs, cfg.MaxDirs)
		}
		if nFiles < cfg.MinFiles || nFiles > cfg.MaxFiles {
			t.Errorf("path %q: nFiles=%d outside [%d,%d]", p, nFiles, cfg.MinFiles, cfg.MaxFiles)
		}
	}
}

// TestMazeStateMachine tests the full flow: negotiate → auth → tree → CREATE maze dir
// → QUERY_DIRECTORY (gets maze children) → CREATE maze subdirectory → more maze children.
func TestMazeStateMachine(t *testing.T) {
	srv := New(Config{ComputerName: "TESTBOX", DomainName: "TESTDOM"})

	ln, err := newFreeListener()
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	port := extractPort(addr)
	srv.cfg.Port = uint16(port)

	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)

	conn, err := dialAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	sessionID, treeID := doAuth(t, conn, `\\TESTBOX\C$`)

	var msgID uint64
	nextMsg := func() uint64 { msgID += 10; return msgID }

	// Open a path that doesn't exist in the static tree → maze dir.
	resp := sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, nextMsg(),
		buildCreateBody(`Program Files\UnknownVendor`)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("create maze dir: want 0, got %#x", respStatus(resp))
	}
	mazeHandle := extractVolatileID(resp)

	// QUERY_DIRECTORY on the maze dir → must return entries.
	resp = sendRecv(t, conn, buildTestPacket(CmdQueryDirectory, sessionID, treeID, nextMsg(),
		buildQueryDirBody(3, mazeHandle)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("query_dir maze: want 0, got %#x", respStatus(resp))
	}
	outputLen := binary.LittleEndian.Uint32(resp[68+4 : 68+8])
	if outputLen == 0 {
		t.Fatal("maze QUERY_DIRECTORY returned empty buffer")
	}

	// Drain the maze listing to StatusNoMoreFiles.
	for {
		resp = sendRecv(t, conn, buildTestPacket(CmdQueryDirectory, sessionID, treeID, nextMsg(),
			buildQueryDirBody(3, mazeHandle)))
		if respStatus(resp) == StatusNoMoreFiles {
			break
		}
		if respStatus(resp) != StatusSuccess {
			t.Fatalf("drain maze dir: unexpected %#x", respStatus(resp))
		}
	}

	// SL_RESTART_SCAN (flags=1) should re-enumerate from the start.
	restartBody := buildQueryDirBody(3, mazeHandle)
	restartBody[3] = 0x01 // SL_RESTART_SCAN
	resp = sendRecv(t, conn, buildTestPacket(CmdQueryDirectory, sessionID, treeID, nextMsg(), restartBody))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("restart scan: want 0, got %#x", respStatus(resp))
	}

	// Descend one level deeper — resolve a child of the maze dir.
	// We don't know the child name, so use a fresh unknown path two levels deep.
	resp = sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, nextMsg(),
		buildCreateBody(`Program Files\UnknownVendor\DeepConfig`)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("create maze subdir: want 0, got %#x", respStatus(resp))
	}
	deepHandle := extractVolatileID(resp)

	resp = sendRecv(t, conn, buildTestPacket(CmdQueryDirectory, sessionID, treeID, nextMsg(),
		buildQueryDirBody(37, deepHandle))) // FileIdBothDirectoryInformation
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("query_dir deep: want 0, got %#x", respStatus(resp))
	}
	if binary.LittleEndian.Uint32(resp[68+4:68+8]) == 0 {
		t.Fatal("deep maze QUERY_DIRECTORY returned empty buffer")
	}

	// A maze file path with extension → resolvable and readable.
	resp = sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, nextMsg(),
		buildCreateBody(`Program Files\UnknownVendor\passwords.txt`)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("create maze file: want 0, got %#x", respStatus(resp))
	}
	fileHandle := extractVolatileID(resp)

	resp = sendRecv(t, conn, buildTestPacket(CmdRead, sessionID, treeID, nextMsg(),
		buildReadBody(fileHandle, 0, 512)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("read maze bait file: want 0, got %#x", respStatus(resp))
	}
	dataLen := binary.LittleEndian.Uint32(resp[68+4 : 68+8])
	if dataLen == 0 {
		t.Fatal("bait file returned 0 bytes")
	}
}
