// Package deception provides a protocol-neutral content-deception core: a virtual
// content tree, an infinite-maze generator, seeded artifacts, and a shared
// credential store. It carries no protocol knowledge (no SMB/NTLM/NDR). Protocol
// honeypots (the SMB VFS today; FTP/HTTP-listing later) adapt these Nodes into
// their own wire representations, so config-driven shares, seeded files, the maze,
// and the credential-leak loop are reusable across services.
package deception

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Node is one node in a protocol-neutral virtual filesystem.
//
// Static nodes have MazePath == "". Maze nodes set MazePath to the canonical
// path used as the deterministic seed for child generation. Attribute booleans
// are intentionally generic; a protocol adapter maps them to its own attribute
// representation (e.g. the SMB FILE_ATTRIBUTE_* bitfield).
type Node struct {
	Name     string
	Dir      bool
	ReadOnly bool
	System   bool
	Archive  bool
	Hidden   bool
	Normal   bool // FILE_ATTRIBUTE_NORMAL analogue; set for empty static files

	Content  []byte // nil for directories
	Children []*Node

	Created  time.Time
	Modified time.Time

	MazePath  string // non-empty → maze-generated; path acts as RNG seed
	MazeDepth int    // depth within the maze (0 for static and top-level entries)
}

// IsDir reports whether the node is a directory.
func (n *Node) IsDir() bool { return n.Dir }

// Size returns the content length in bytes.
func (n *Node) Size() int64 { return int64(len(n.Content)) }

// AllocSize returns a plausible on-disk allocation size (4 KiB clusters).
func (n *Node) AllocSize() int64 {
	if n.Dir {
		return 0
	}
	sz := n.Size()
	if sz == 0 {
		return 4096
	}
	return ((sz + 4095) / 4096) * 4096
}

// FindChild returns the named child (case-insensitive), or nil.
func (n *Node) FindChild(name string) *Node {
	if n == nil {
		return nil
	}
	uname := strings.ToUpper(name)
	for _, c := range n.Children {
		if strings.ToUpper(c.Name) == uname {
			return c
		}
	}
	return nil
}

// Tree holds named roots (share/path roots) and the maze configuration.
type Tree struct {
	Roots map[string]*Node // uppercase logical name → root node
	Maze  *MazeConfig
}

// BaseTime returns a plausible installation timestamp shared by static and maze
// nodes. Exported so protocol adapters can reuse the same baseline (e.g. SMB
// volume-creation time).
func BaseTime() time.Time {
	return time.Date(2024, 9, 14, 8, 23, 11, 0, time.UTC)
}

// --- node constructors (mirror the previous smb dirNode/fileNode behavior) ---

// DirNode builds a directory node with the given children.
func DirNode(name string, children ...*Node) *Node {
	t := BaseTime()
	return &Node{Name: name, Dir: true, Children: children, Created: t, Modified: t}
}

// FileNode builds a file node. When content is nil the Normal attribute is set,
// matching the original smb fileNode() semantics for byte-identical attrs.
func FileNode(name string, content []byte, readonly, system, archive bool) *Node {
	t := BaseTime()
	n := &Node{
		Name: name, ReadOnly: readonly, System: system, Archive: archive,
		Content: content, Created: t, Modified: t,
	}
	if content == nil {
		n.Normal = true
	}
	return n
}

// DefaultTree builds the canonical Windows-like tree. It is a faithful port of
// the previous hardcoded SMB VFS so existing behavior (and tests) are preserved.
func DefaultTree(maze MazeConfig) *Tree {
	cRoot := DirNode("",
		DirNode("Windows",
			DirNode("System32",
				FileNode("ntoskrnl.exe", nil, false, true, false),
				FileNode("kernel32.dll", nil, false, true, false),
				FileNode("advapi32.dll", nil, false, true, false),
				DirNode("drivers"),
				DirNode("config",
					FileNode("SAM", nil, true, true, false),
					FileNode("SYSTEM", nil, true, true, false),
					FileNode("SECURITY", nil, true, true, false),
				),
			),
			DirNode("Temp"),
			DirNode("SysWOW64"),
			DirNode("Logs",
				DirNode("CBS"),
				FileNode("WindowsUpdate.log", nil, false, false, true),
			),
		),
		DirNode("Users",
			DirNode("Administrator",
				DirNode("Desktop"),
				DirNode("Documents",
					FileNode("passwords.txt", baitPasswords, false, false, true),
					FileNode("backup_credentials.txt", baitBackupCreds, false, false, true),
				),
				DirNode("Downloads"),
				DirNode("AppData",
					DirNode("Roaming"),
					DirNode("Local"),
				),
			),
			DirNode("Public",
				DirNode("Desktop"),
				DirNode("Documents"),
				DirNode("Downloads"),
			),
		),
		DirNode("Program Files",
			DirNode("Common Files"),
			DirNode("Internet Explorer"),
			DirNode("Windows Defender"),
			DirNode("Windows NT",
				DirNode("Accessories"),
			),
		),
		DirNode("Program Files (x86)"),
		DirNode("ProgramData",
			DirNode("Microsoft"),
		),
		FileNode("pagefile.sys", nil, true, true, false),
		FileNode("hiberfil.sys", nil, true, true, false),
	)

	winNode := cRoot.FindChild("Windows")

	m := maze
	return &Tree{
		Roots: map[string]*Node{
			"C$":     cRoot,
			"ADMIN$": winNode,
			"IPC$":   DirNode(""),
		},
		Maze: &m,
	}
}

// BuildTree constructs a Tree from declarative config, handling the explicit (a),
// seeded (b), and random-but-plausible (c) modes. The runtime infinite-maze mode
// (d) is the resolve-time fall-through governed by cfg.Maze. store interpolates
// {{cred:id.field}} placeholders in inline file content; baseDir resolves relative
// seed_file paths.
func BuildTree(cfg TreeConfig, store *CredStore, baseDir string) (*Tree, error) {
	roots := make(map[string]*Node, len(cfg.Shares))
	for _, sd := range cfg.Shares {
		if sd.Name == "" {
			return nil, fmt.Errorf("share with empty name")
		}
		root := DirNode("")
		if sd.Root != nil {
			kids, err := buildGroup(*sd.Root, store, baseDir)
			if err != nil {
				return nil, fmt.Errorf("share %s: %w", sd.Name, err)
			}
			root.Children = append(root.Children, kids...)
		}
		if sd.Generate != nil {
			root.Children = append(root.Children, generateChildren(strings.ToUpper(sd.Name), sd.Generate, 1)...)
		}
		roots[strings.ToUpper(sd.Name)] = root
	}
	m := cfg.Maze
	return &Tree{Roots: roots, Maze: &m}, nil
}

func buildGroup(g NodeDefGroup, store *CredStore, baseDir string) ([]*Node, error) {
	var out []*Node
	for _, d := range g.Dirs {
		n, err := buildDir(d, store, baseDir)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	for _, f := range g.Files {
		n, err := buildFile(f, store, baseDir)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func buildDir(d DirDef, store *CredStore, baseDir string) (*Node, error) {
	n := DirNode(d.Name)
	kids, err := buildGroup(NodeDefGroup{Dirs: d.Dirs, Files: d.Files}, store, baseDir)
	if err != nil {
		return nil, err
	}
	n.Children = kids
	return n, nil
}

func buildFile(f FileDef, store *CredStore, baseDir string) (*Node, error) {
	var content []byte
	switch {
	case f.SeedFile != "":
		p := f.SeedFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(baseDir, p)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("file %q seed_file: %w", f.Name, err)
		}
		if len(data) > maxSeedFileSize {
			return nil, fmt.Errorf("file %q seed_file exceeds %d bytes", f.Name, maxSeedFileSize)
		}
		content = data
	case f.Content != "":
		s := f.Content
		if store != nil {
			r, err := store.Render(s)
			if err != nil {
				return nil, fmt.Errorf("file %q: %w", f.Name, err)
			}
			s = r
		}
		content = []byte(s)
	}

	t := BaseTime()
	n := &Node{
		Name: f.Name, ReadOnly: f.ReadOnly, System: f.System, Hidden: f.Hidden, Archive: f.Archive,
		Content: content, Created: t, Modified: t,
	}
	// Mirror fileNode: empty files are Normal; otherwise default a flag-less file
	// to Archive (a typical user file).
	if len(content) == 0 {
		n.Normal = true
	} else if !n.Archive && !n.System && !n.ReadOnly {
		n.Archive = true
	}
	return n, nil
}

// generateChildren produces a deterministic, plausible directory layout for mode
// (c). With a fixed GenSpec.Seed the layout is stable across restarts (a re-scan
// sees the same host); an empty seed varies per process start salt is applied by
// the caller via the seed string. Depth bounds the materialized static levels;
// deeper paths fall through to the runtime maze.
func generateChildren(pathLabel string, gs *GenSpec, depth int) []*Node {
	rng := newLCG(pathSeed(gs.Seed + "|" + pathLabel))
	nDirs := pickCount(gs.Dirs, rng)
	nFiles := pickCount(gs.Files, rng)

	used := make(map[string]bool)
	var out []*Node
	for i := 0; i < nDirs; i++ {
		name := pickUnique(rng, mazeDirCorpus, used)
		childLabel := pathLabel + `\` + name
		d := MazeDirNode(childLabel, name, depth)
		d.MazePath = "" // materialized static node, not a live maze node
		d.MazeDepth = 0
		if depth < gs.Depth {
			d.Children = generateChildren(childLabel, gs, depth+1)
		}
		out = append(out, d)
	}
	for i := 0; i < nFiles; i++ {
		name := pickUnique(rng, mazeFileCorpus, used)
		fn := MazeFileNode(pathLabel+`\`+name, name)
		fn.MazePath = "" // materialized static node
		out = append(out, fn)
	}
	return out
}

// pickCount returns a clamped, deterministic count within [r.Min, r.Max].
func pickCount(r Range, rng *lcg) int {
	min, max := r.Min, r.Max
	if min < 0 {
		min = 0
	}
	if max < min {
		max = min
	}
	if max > maxGenChildren {
		max = maxGenChildren
	}
	if max == min {
		return min
	}
	return min + rng.intn(max-min+1)
}
