package deception

// TreeConfig is the declarative description of a protocol's virtual filesystem.
// It is YAML-tagged and protocol-neutral; the SMB honeypot embeds it today, and
// future stateful services (FTP, HTTP file listing) can reuse it unchanged.
type TreeConfig struct {
	Shares []ShareDef `yaml:"shares"`
	Maze   MazeConfig `yaml:"maze"`
}

// ShareDef defines one advertised root. Exactly one of Root (explicit/seeded) or
// Generate (random-but-plausible) is typically set; both may be combined.
type ShareDef struct {
	Name     string        `yaml:"name"`
	Type     string        `yaml:"type"`     // disk | disk_special | ipc
	Remark   string        `yaml:"remark"`   // share comment shown in enumeration
	Root     *NodeDefGroup `yaml:"root"`     // mode (a)/(b): explicit dirs/files
	Generate *GenSpec      `yaml:"generate"` // mode (c): random-but-plausible
}

// NodeDefGroup is a directory's declared contents.
type NodeDefGroup struct {
	Dirs  []DirDef  `yaml:"dirs"`
	Files []FileDef `yaml:"files"`
}

// DirDef is an explicit directory with nested contents.
type DirDef struct {
	Name  string    `yaml:"name"`
	Dirs  []DirDef  `yaml:"dirs"`
	Files []FileDef `yaml:"files"`
}

// FileDef is an explicit file. Content (inline, supports {{cred:id.field}}
// interpolation) and SeedFile (real content from disk) are mutually exclusive;
// SeedFile wins if both are set.
type FileDef struct {
	Name     string `yaml:"name"`
	Content  string `yaml:"content"`
	SeedFile string `yaml:"seed_file"`
	ReadOnly bool   `yaml:"readonly"`
	System   bool   `yaml:"system"`
	Hidden   bool   `yaml:"hidden"`
	Archive  bool   `yaml:"archive"`
}

// GenSpec controls random-but-plausible structure generation (mode c).
type GenSpec struct {
	Seed  string `yaml:"seed"`  // fixed string => reproducible across restarts; "" => stable-but-unsalted
	Dirs  Range  `yaml:"dirs"`  // directories generated per level
	Files Range  `yaml:"files"` // files generated per level
	Depth int    `yaml:"depth"` // materialized static levels (deeper => runtime maze)
}

// Range is an inclusive [Min, Max] count bound.
type Range struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}
