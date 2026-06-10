package smb

import (
	"encoding/binary"
	"strings"
	"sync/atomic"
	"time"
)

// File attribute constants (MS-FSCC 2.6)
const (
	FileAttrReadOnly  = uint32(0x00000001)
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

// --- constructors ---

func dirNode(name string, children ...*VFSNode) *VFSNode {
	t := vfsBaseTime()
	return &VFSNode{name: name, attrs: FileAttrDirectory, children: children, created: t, modified: t}
}

func fileNode(name string, attrs uint32, content []byte) *VFSNode {
	t := vfsBaseTime()
	if content == nil {
		attrs |= FileAttrNormal
	}
	return &VFSNode{name: name, attrs: attrs, content: content, created: t, modified: t}
}

// vfsBaseTime returns a plausible Windows installation timestamp.
func vfsBaseTime() time.Time {
	return time.Date(2024, 9, 14, 8, 23, 11, 0, time.UTC)
}

// newDefaultVFS builds a realistic-looking Windows VFS tree.
// mazeCfg is stored and used by resolve() for paths that fall outside the static tree.
func newDefaultVFS(mazeCfg MazeConfig) *VFS {
	cRoot := dirNode("",
		dirNode("Windows",
			dirNode("System32",
				fileNode("ntoskrnl.exe", FileAttrSystem, nil),
				fileNode("kernel32.dll", FileAttrSystem, nil),
				fileNode("advapi32.dll", FileAttrSystem, nil),
				dirNode("drivers"),
				dirNode("config",
					fileNode("SAM", FileAttrSystem|FileAttrReadOnly, nil),
					fileNode("SYSTEM", FileAttrSystem|FileAttrReadOnly, nil),
					fileNode("SECURITY", FileAttrSystem|FileAttrReadOnly, nil),
				),
			),
			dirNode("Temp"),
			dirNode("SysWOW64"),
			dirNode("Logs",
				dirNode("CBS"),
				fileNode("WindowsUpdate.log", FileAttrArchive, nil),
			),
		),
		dirNode("Users",
			dirNode("Administrator",
				dirNode("Desktop"),
				dirNode("Documents",
					fileNode("passwords.txt", FileAttrArchive, baitPasswords),
					fileNode("backup_credentials.txt", FileAttrArchive, baitBackupCreds),
				),
				dirNode("Downloads"),
				dirNode("AppData",
					dirNode("Roaming"),
					dirNode("Local"),
				),
			),
			dirNode("Public",
				dirNode("Desktop"),
				dirNode("Documents"),
				dirNode("Downloads"),
			),
		),
		dirNode("Program Files",
			dirNode("Common Files"),
			dirNode("Internet Explorer"),
			dirNode("Windows Defender"),
			dirNode("Windows NT",
				dirNode("Accessories"),
			),
		),
		dirNode("Program Files (x86)"),
		dirNode("ProgramData",
			dirNode("Microsoft"),
		),
		fileNode("pagefile.sys", FileAttrSystem|FileAttrReadOnly, nil),
		fileNode("hiberfil.sys", FileAttrSystem|FileAttrReadOnly, nil),
	)

	winNode := cRoot.findChild("Windows")

	maze := &mazeCfg // store pointer; caller owns the value
	return &VFS{
		shares: map[string]*VFSNode{
			"C$":     cRoot,
			"ADMIN$": winNode,
			"IPC$":   dirNode(""),
		},
		maze: maze,
	}
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

func (n *VFSNode) isDir() bool  { return n.attrs&FileAttrDirectory != 0 }
func (n *VFSNode) size() int64  { return int64(len(n.content)) }
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
// Supports FileInformationClass 3 (FileBothDirectoryInformation) and
// 37 (FileIdBothDirectoryInformation); defaults to 3-style for others.
func buildDirEntry(name string, node *VFSNode, infoClass byte) []byte {
	nameBuf := utf16LE(name)

	// Fixed bytes before FileName:
	//   class 3  (FileBothDir):   94 bytes
	//   class 37 (FileIdBothDir): 104 bytes
	var nameOff int
	if infoClass == 37 {
		nameOff = 104
	} else {
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

// --- bait file content ---

var baitPasswords = []byte(`# Network Credentials - CONFIDENTIAL
# Last updated: 2024-09-14

[Database]
host=10.0.1.50
user=sa
password=Adm1n@SQL2019!

[Backup Service]
host=10.0.1.20
user=backup_svc
password=Backup$ecure99

[vCenter]
host=10.0.1.10
user=administrator@vsphere.local
password=VMware1!

[Firewall]
host=10.0.1.1
user=admin
password=F!rewall2024
`)

var baitBackupCreds = []byte(`Veeam Backup Service Account
Domain: CORP
Username: svc_backup
Password: V33m@Backup!23

SQL Backup Job
Server: SQL-PROD-01
User: sa
Pass: Adm1n@SQL2019!
`)
