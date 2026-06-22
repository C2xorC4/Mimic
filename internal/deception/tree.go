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

// staticNodeTimes returns deterministic Created/Modified times for a canonical
// VFS path. Spreads mtimes across a plausible window so directory listings do
// not show one identical second-stamp (an emulation tell from OSE-2026-001).
func staticNodeTimes(path string) (created, modified time.Time) {
	rng := newLCG(pathSeed(strings.ToUpper(path)))
	base := BaseTime()
	created = base.Add(-time.Duration(1+rng.next()%uint64(180*24)) * time.Hour)
	modified = created.Add(time.Duration(1+rng.next()%uint64(72*24)) * time.Hour)
	if modified.After(base) {
		modified = base.Add(-time.Duration(rng.next()%uint64(24)) * time.Hour)
	}
	if !modified.After(created) {
		modified = created.Add(time.Hour)
	}
	return created, modified
}

// stampStaticTimes walks a static subtree and assigns path-seeded timestamps.
func stampStaticTimes(shareRoot string, n *Node) {
	var path string
	switch {
	case n.Name == "":
		path = shareRoot
	case shareRoot == "":
		path = n.Name
	default:
		path = shareRoot + `\` + n.Name
	}
	n.Created, n.Modified = staticNodeTimes(path)
	for _, ch := range n.Children {
		stampStaticTimes(path, ch)
	}
}

// Resolve walks rootName + filePath (either separator, case-insensitive) by
// membership: at each step the name must be among the current directory's
// effective children — its explicit children plus, for a generative (maze) node,
// its deterministically generated set. A name that is not present returns nil
// (NOT_FOUND); there is NO fabrication of arbitrary names. This makes a guessed
// path under a real directory fail exactly like a real filesystem, while a
// generative subtree (reached by navigating into an advertised maze share/dir)
// is infinitely deep because every generated subdirectory is itself generative.
// This is the protocol-neutral resolution logic; SMB VFS and FTP reuse it.
func (t *Tree) Resolve(rootName, filePath string) *Node {
	root := t.Roots[strings.ToUpper(rootName)]
	if root == nil {
		return nil
	}
	filePath = strings.TrimLeft(filePath, `\/`)
	if filePath == "" {
		return root
	}
	parts := strings.FieldsFunc(filePath, func(r rune) bool { return r == '\\' || r == '/' })

	cur := root
	for _, part := range parts {
		if part == "." || part == ".." {
			continue // '..' is resolved by callers at the command layer
		}
		child := t.findChild(cur, part)
		if child == nil {
			return nil // NOT_FOUND — no fabrication
		}
		cur = child
	}
	return cur
}

// findChild looks up name among cur's effective children: explicit children
// first, then (for a generative node) the deterministically generated set.
func (t *Tree) findChild(cur *Node, name string) *Node {
	if c := cur.FindChild(name); c != nil {
		return c
	}
	if cur.MazePath != "" {
		for _, gc := range MazeChildren(cur.MazePath, cur.MazeDepth, t.Maze) {
			if strings.EqualFold(gc.Name, name) {
				return gc
			}
		}
	}
	return nil
}

// Children returns the directory's effective children to enumerate: explicit
// children, plus the generated set for a generative (maze) node. The two are
// combined so specific bait planted inside a generative share is listed alongside
// the generated entries.
func (t *Tree) Children(n *Node) []*Node {
	if n == nil {
		return nil
	}
	if n.MazePath == "" {
		return n.Children
	}
	gen := MazeChildren(n.MazePath, n.MazeDepth, t.Maze)
	if len(n.Children) == 0 {
		return gen
	}
	return append(append([]*Node{}, n.Children...), gen...)
}

// --- node constructors (mirror the previous smb dirNode/fileNode behavior) ---

// DirNode builds a directory node with the given children.
func DirNode(name string, children ...*Node) *Node {
	created, modified := staticNodeTimes(name)
	return &Node{Name: name, Dir: true, Children: children, Created: created, Modified: modified}
}

// FileNode builds a file node. When content is nil the Normal attribute is set,
// matching the original smb fileNode() semantics for byte-identical attrs.
func FileNode(name string, content []byte, readonly, system, archive bool) *Node {
	created, modified := staticNodeTimes(name)
	n := &Node{
		Name: name, ReadOnly: readonly, System: system, Archive: archive,
		Content: content, Created: created, Modified: modified,
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
			FileNode("win.ini", []byte("; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n[Mail]\r\nMAPI=1\r\n"), false, false, true),
			DirNode("System32",
				FileNode("ntoskrnl.exe", nil, false, true, false),
				FileNode("kernel32.dll", nil, false, true, false),
				FileNode("advapi32.dll", nil, false, true, false),
				DirNode("drivers"),
				DirNode("config",
					FileNode("SAM", RegistryHiveStub("SAM"), true, true, false),
					FileNode("SYSTEM", RegistryHiveStub("SYSTEM"), true, true, false),
					FileNode("SECURITY", RegistryHiveStub("SECURITY"), true, true, false),
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
		DirNode("inetpub",
			DirNode("wwwroot",
				FileNode("iisstart.htm", []byte("<html><head><title>IIS Windows</title></head><body><img src=\"iisstart.png\" alt=\"IIS\"></body></html>"), false, false, true),
			),
		),
		FileNode("pagefile.sys", nil, true, true, false),
		FileNode("hiberfil.sys", nil, true, true, false),
	)

	winNode := cRoot.FindChild("Windows")
	stampStaticTimes("C$", cRoot)
	ipcRoot := DirNode("")
	stampStaticTimes("IPC$", ipcRoot)
	if winNode != nil {
		stampStaticTimes("ADMIN$", winNode)
	}

	m := maze
	return &Tree{
		Roots: map[string]*Node{
			"C$":     cRoot,
			"ADMIN$": winNode,
			"IPC$":   ipcRoot,
		},
		Maze: &m,
	}
}

// BuildTree constructs a Tree from declarative config: explicit (a), seeded (b),
// finite-materialized (c, GenSpec), and generative-tarpit (Maze flag) modes. A
// Maze-flagged share or directory becomes a generative root (MazePath set) whose
// contents are produced lazily by the resolve/Children membership logic. store
// interpolates {{cred:id.field}} placeholders in inline file content; baseDir
// resolves relative seed_file paths.
func BuildTree(cfg TreeConfig, store *CredStore, baseDir string) (*Tree, error) {
	roots := make(map[string]*Node, len(cfg.Shares))
	for _, sd := range cfg.Shares {
		if sd.Name == "" {
			return nil, fmt.Errorf("share with empty name")
		}
		shareKey := strings.ToUpper(sd.Name)
		root := DirNode("")
		if sd.Root != nil {
			kids, err := buildGroup(*sd.Root, store, baseDir, shareKey)
			if err != nil {
				return nil, fmt.Errorf("share %s: %w", sd.Name, err)
			}
			root.Children = append(root.Children, kids...)
		}
		if sd.Generate != nil {
			root.Children = append(root.Children, generateChildren(shareKey, sd.Generate, 1)...)
		}
		if sd.Maze {
			root.MazePath = shareKey // generative tarpit root (maze depth starts here)
			root.MazeDepth = 0
		}
		stampStaticTimes(shareKey, root)
		roots[shareKey] = root
	}
	m := cfg.Maze
	return &Tree{Roots: roots, Maze: &m}, nil
}

func buildGroup(g NodeDefGroup, store *CredStore, baseDir, pathPrefix string) ([]*Node, error) {
	var out []*Node
	for _, d := range g.Dirs {
		n, err := buildDir(d, store, baseDir, pathPrefix)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	for _, f := range g.Files {
		n, err := buildFile(f, store, baseDir, pathPrefix)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func buildDir(d DirDef, store *CredStore, baseDir, pathPrefix string) (*Node, error) {
	myPath := pathPrefix + `\` + d.Name
	created, modified := staticNodeTimes(myPath)
	n := &Node{Name: d.Name, Dir: true, Created: created, Modified: modified}
	kids, err := buildGroup(NodeDefGroup{Dirs: d.Dirs, Files: d.Files}, store, baseDir, myPath)
	if err != nil {
		return nil, err
	}
	n.Children = kids
	if d.Maze {
		n.MazePath = myPath // generative tarpit root at this directory
		n.MazeDepth = 0
	}
	return n, nil
}

func buildFile(f FileDef, store *CredStore, baseDir, pathPrefix string) (*Node, error) {
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

	filePath := pathPrefix + `\` + f.Name
	created, modified := staticNodeTimes(filePath)
	n := &Node{
		Name: f.Name, ReadOnly: f.ReadOnly, System: f.System, Hidden: f.Hidden, Archive: f.Archive,
		Content: content, Created: created, Modified: modified,
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
