package smb

import (
	"encoding/binary"
	"strings"
	"sync/atomic"
	"time"

	"github.com/c2xorc4/mimic/internal/deception"
)

// File attribute constants (MS-FSCC 2.6)
const (
	FileAttrReadOnly  = uint32(0x00000001)
	FileAttrHidden    = uint32(0x00000002)
	FileAttrSystem    = uint32(0x00000004)
	FileAttrDirectory = uint32(0x00000010)
	FileAttrArchive   = uint32(0x00000020)
	FileAttrNormal    = uint32(0x00000080)
)

// VFSNode is one node in the virtual filesystem.
// Static nodes: mazePath == "".  Maze nodes: mazePath is the canonical
// share-rooted path used as deterministic seed for child generation.
type VFSNode struct {
	name      string
	attrs     uint32
	content   []byte     // nil for directories
	children  []*VFSNode // explicit children (static nodes only)
	created   time.Time
	modified  time.Time
	mazePath  string // non-empty → maze-generated; path acts as RNG seed
	mazeDepth int    // depth within the maze (0 for static and top-level entries)
}

// VFS holds named share roots and the maze configuration.
type VFS struct {
	shares map[string]*VFSNode // uppercase share name → root
	maze   *MazeConfig
}

// --- construction from the neutral deception tree ---

// newDefaultVFS builds the default Windows-like VFS by converting the neutral
// default deception tree. mazeCfg governs resolve() fall-through for paths
// outside the static tree.
func newDefaultVFS(mazeCfg MazeConfig) *VFS {
	return vfsFromTree(deception.DefaultTree(mazeCfg))
}

// newVFSFromConfig builds a config-driven VFS. store interpolates {{cred:...}}
// placeholders in seeded file content; baseDir resolves relative seed_file paths.
func newVFSFromConfig(tc deception.TreeConfig, store *deception.CredStore, baseDir string) (*VFS, error) {
	tree, err := deception.BuildTree(tc, store, baseDir)
	if err != nil {
		return nil, err
	}
	return vfsFromTree(tree), nil
}

// vfsFromTree converts a neutral deception.Tree into the SMB VFS representation.
func vfsFromTree(tree *deception.Tree) *VFS {
	shares := make(map[string]*VFSNode, len(tree.Roots))
	for name, root := range tree.Roots {
		shares[name] = vfsNodeFrom(root)
	}
	return &VFS{shares: shares, maze: tree.Maze}
}

// vfsNodeFrom converts a neutral node (and its children, recursively) into a
// *VFSNode, mapping the generic attribute booleans onto the SMB FILE_ATTRIBUTE_*
// bitfield. This converter is the template a future stateful service would mirror
// to reuse the same deception core.
func vfsNodeFrom(n *deception.Node) *VFSNode {
	if n == nil {
		return nil
	}
	vn := &VFSNode{
		name:      n.Name,
		attrs:     smbAttrs(n),
		content:   n.Content,
		created:   n.Created,
		modified:  n.Modified,
		mazePath:  n.MazePath,
		mazeDepth: n.MazeDepth,
	}
	if len(n.Children) > 0 {
		vn.children = make([]*VFSNode, 0, len(n.Children))
		for _, c := range n.Children {
			vn.children = append(vn.children, vfsNodeFrom(c))
		}
	}
	return vn
}

// vfsNodesFrom converts a slice of neutral nodes (used for maze child lists).
func vfsNodesFrom(ns []*deception.Node) []*VFSNode {
	out := make([]*VFSNode, 0, len(ns))
	for _, n := range ns {
		out = append(out, vfsNodeFrom(n))
	}
	return out
}

// smbAttrs maps the neutral attribute booleans onto the SMB FILE_ATTRIBUTE_*
// bitfield, reproducing the original per-node attributes exactly.
func smbAttrs(n *deception.Node) uint32 {
	var a uint32
	if n.Dir {
		a |= FileAttrDirectory
	}
	if n.ReadOnly {
		a |= FileAttrReadOnly
	}
	if n.System {
		a |= FileAttrSystem
	}
	if n.Archive {
		a |= FileAttrArchive
	}
	if n.Hidden {
		a |= FileAttrHidden
	}
	if n.Normal {
		a |= FileAttrNormal
	}
	return a
}

// --- tree navigation ---

// resolve finds the node for shareName+filePath; returns nil if not found.
// filePath uses either \ or / separators and is case-insensitive.
// When the static tree has no match, the maze layer generates nodes deterministically
// provided v.maze.Enabled is true.
func (v *VFS) resolve(shareName, filePath string) *VFSNode {
	shareUpper := strings.ToUpper(shareName)
	root := v.shares[shareUpper]
	if root == nil {
		return nil
	}
	filePath = strings.TrimLeft(filePath, `\/`)
	if filePath == "" {
		return root
	}
	parts := strings.FieldsFunc(filePath, func(r rune) bool { return r == '\\' || r == '/' })

	cur := root
	pathBuf := shareUpper // canonical path accumulated as we descend

	for i, part := range parts {
		if part == "." {
			continue
		}
		pathBuf += `\` + part

		child := cur.findChild(part)
		if child != nil {
			cur = child
			continue
		}

		// Static miss — fall through to maze if enabled.
		if v.maze == nil || !v.maze.Enabled {
			return nil
		}
		nextDepth := cur.mazeDepth + 1
		if v.maze.MaxDepth > 0 && nextDepth > v.maze.MaxDepth {
			return nil
		}

		isLast := i == len(parts)-1
		if isLast && strings.Contains(part, ".") {
			cur = newMazeFileNode(pathBuf, part)
		} else {
			cur = newMazeDirNode(pathBuf, part, nextDepth)
		}
	}
	return cur
}

// listMazeChildren returns the deterministic child list for a maze directory node.
func (v *VFS) listMazeChildren(node *VFSNode) []*VFSNode {
	if v.maze == nil || !v.maze.Enabled || node.mazePath == "" {
		return nil
	}
	return buildMazeChildren(node.mazePath, node.mazeDepth, v.maze)
}

func (n *VFSNode) findChild(name string) *VFSNode {
	if n == nil {
		return nil
	}
	uname := strings.ToUpper(name)
	for _, c := range n.children {
		if strings.ToUpper(c.name) == uname {
			return c
		}
	}
	return nil
}

func (n *VFSNode) isDir() bool { return n.attrs&FileAttrDirectory != 0 }
func (n *VFSNode) size() int64 { return int64(len(n.content)) }
func (n *VFSNode) allocSize() int64 {
	if n.isDir() {
		return 0
	}
	sz := n.size()
	if sz == 0 {
		return 4096
	}
	return ((sz + 4095) / 4096) * 4096
}

// --- file handles ---

// FileHandle is an open SMB2 handle (file, directory, or named pipe).
// Exactly one of node or pipe is non-nil.
type FileHandle struct {
	node         *VFSNode
	shareName    string
	dirIdx       int        // enumeration cursor: 0=".", 1="..", 2+=children
	offset       int64      // read offset for files
	mazeChildren []*VFSNode // lazily populated for maze directory enumeration
	pipe         *PipeState // non-nil for IPC$ named pipe handles
}

// effectiveChildren returns the child list to enumerate.
// For maze dirs it is generated once and cached; for static dirs it is node.children.
func (h *FileHandle) effectiveChildren(v *VFS) []*VFSNode {
	if h.node.mazePath != "" {
		if h.mazeChildren == nil {
			h.mazeChildren = v.listMazeChildren(h.node)
		}
		return h.mazeChildren
	}
	return h.node.children
}

// nextChild returns the next (name, node) pair for directory enumeration.
// Returns ("", nil, false) when exhausted.
func (h *FileHandle) nextChild(v *VFS) (string, *VFSNode, bool) {
	children := h.effectiveChildren(v)
	switch h.dirIdx {
	case 0:
		h.dirIdx++
		return ".", h.node, true
	case 1:
		h.dirIdx++
		return "..", h.node, true
	default:
		idx := h.dirIdx - 2
		if idx >= len(children) {
			return "", nil, false
		}
		h.dirIdx++
		c := children[idx]
		return c.name, c, true
	}
}

func (h *FileHandle) hasMoreChildren(v *VFS) bool {
	children := h.effectiveChildren(v)
	return h.dirIdx < 2+len(children)
}

var globalHandleSeq uint64

func nextHandleID() uint64 { return atomic.AddUint64(&globalHandleSeq, 1) }

// --- directory entry serialization ---

// buildDirEntry serializes a single directory entry for QUERY_DIRECTORY.
// The fixed fields through FileNameLength (offset 64) are identical across the
// FileXxxDirectoryInformation classes; only the offset of the FileName field
// differs (the optional EaSize / ShortName / FileId blocks). We honor whichever
// class the client requested so the FileName lands where the client parses it.
//
//	class 1  FileDirectoryInformation        FileName @ 64
//	class 2  FileFullDirectoryInformation     FileName @ 68  (EaSize, no ShortName)
//	class 3  FileBothDirectoryInformation     FileName @ 94  (EaSize + ShortName)
//	class 37 FileIdBothDirectoryInformation   FileName @ 104 (+ Reserved2 + FileId)
//
// impacket's listPath (and thus netexec/smbclient/smbmap) requests class 2, so
// defaulting non-37 classes to the class-3 offset produced blank filenames there.
func buildDirEntry(name string, node *VFSNode, infoClass byte) []byte {
	nameBuf := utf16LE(name)

	var nameOff int
	switch infoClass {
	case 1: // FileDirectoryInformation
		nameOff = 64
	case 2: // FileFullDirectoryInformation
		nameOff = 68
	case 37: // FileIdBothDirectoryInformation
		nameOff = 104
	default: // FileBothDirectoryInformation (3)
		nameOff = 94
	}

	totalSize := nameOff + len(nameBuf)
	aligned := (totalSize + 7) &^ 7
	b := make([]byte, aligned)

	// NextEntryOffset filled in by caller; leave 0 (last entry) for now.
	// [0:4] NextEntryOffset = 0 (caller sets for non-last entries)
	// [4:8] FileIndex = 0
	copy(b[8:16], windowsFiletime(node.created))
	copy(b[16:24], windowsFiletime(node.modified))
	copy(b[24:32], windowsFiletime(node.modified))
	copy(b[32:40], windowsFiletime(node.modified))
	binary.LittleEndian.PutUint64(b[40:48], uint64(node.size()))
	binary.LittleEndian.PutUint64(b[48:56], uint64(node.allocSize()))
	binary.LittleEndian.PutUint32(b[56:60], node.attrs)
	binary.LittleEndian.PutUint32(b[60:64], uint32(len(nameBuf)))
	// [64:68] EaSize = 0
	// [68]    ShortNameLength = 0
	// [69]    Reserved1 = 0
	// [70:94] ShortName = zeros
	// class 37 only: [94:96] Reserved2=0, [96:104] FileId=0

	copy(b[nameOff:], nameBuf)
	return b
}
