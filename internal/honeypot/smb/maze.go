package smb

import (
	"time"

	"github.com/c2xorc4/mimic/internal/deception"
)

// This file adapts the protocol-neutral deception core (maze generator, content
// tree, bait corpus) to the SMB honeypot's VFSNode representation. The generation
// logic itself lives in internal/deception so future stateful services can reuse
// it; here we only convert deception.Node → *VFSNode.

// MazeConfig is the maze generator configuration. It is defined in the neutral
// deception package and aliased here for the SMB honeypot's config surface, so
// existing references (Config.Maze, MazeConfig{...} literals) keep working.
type MazeConfig = deception.MazeConfig

// defaultMazeConfig returns the standard unlimited-depth maze settings.
func defaultMazeConfig() MazeConfig { return deception.DefaultMazeConfig() }

// vfsBaseTime returns the shared installation baseline timestamp (used for the
// SMB volume-creation time in server.go).
func vfsBaseTime() time.Time { return deception.BaseTime() }

// buildMazeChildren generates a deterministic child list for parentPath as SMB
// VFS nodes.
func buildMazeChildren(parentPath string, parentDepth int, cfg *MazeConfig) []*VFSNode {
	return vfsNodesFrom(deception.MazeChildren(parentPath, parentDepth, cfg))
}

// newMazeDirNode / newMazeFileNode build a single maze node (used by resolve()).
func newMazeDirNode(path, name string, depth int) *VFSNode {
	return vfsNodeFrom(deception.MazeDirNode(path, name, depth))
}

func newMazeFileNode(path, name string) *VFSNode {
	return vfsNodeFrom(deception.MazeFileNode(path, name))
}

// mazeFileContent returns bait content for sensitive-looking file names.
func mazeFileContent(name string) []byte { return deception.MazeFileContent(name) }
