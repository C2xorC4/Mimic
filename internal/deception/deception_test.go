package deception

import (
	"os"
	"path/filepath"
	"testing"
)

// --- maze generator (ported from the smb package; regression net for the move) ---

func TestMazeDeterminism(t *testing.T) {
	cfg := DefaultMazeConfig()
	path := `C$\Program Files\FakeApp`
	a := MazeChildren(path, 1, &cfg)
	b := MazeChildren(path, 1, &cfg)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			t.Errorf("child[%d] mismatch: %q vs %q", i, a[i].Name, b[i].Name)
		}
	}
}

func TestMazeDifferentPaths(t *testing.T) {
	cfg := DefaultMazeConfig()
	a := MazeChildren(`C$\VendorA`, 1, &cfg)
	b := MazeChildren(`C$\VendorB`, 1, &cfg)
	same := len(a) == len(b)
	if same {
		for i := range a {
			if a[i].Name != b[i].Name {
				same = false
				break
			}
		}
	}
	if same {
		t.Error("different paths produced identical children — seed not working")
	}
}

func TestMazeDepthLimit(t *testing.T) {
	cfg := &MazeConfig{Enabled: true, MaxDepth: 2, MinDirs: 2, MaxDirs: 2, MinFiles: 1, MaxFiles: 1}
	// Children generated for a node at depth 2 (nextDepth 3 > MaxDepth) must have no dirs.
	children := MazeChildren(`C$\A\B`, 2, cfg)
	for _, c := range children {
		if c.IsDir() {
			t.Errorf("MaxDepth=2 at depth 2 generated a subdirectory: %q", c.Name)
		}
	}
	// At depth 1 (nextDepth 2 <= MaxDepth) dirs are allowed.
	if got := MazeChildren(`C$\A`, 1, cfg); len(got) == 0 {
		t.Error("expected children at depth 1")
	}
}

func TestMazeChildrenCountRange(t *testing.T) {
	cfg := &MazeConfig{Enabled: true, MaxDepth: 0, MinDirs: 2, MaxDirs: 4, MinFiles: 1, MaxFiles: 3}
	for _, p := range []string{`C$\Alpha`, `C$\Beta`, `C$\Gamma`, `C$\Delta`, `C$\Epsilon`} {
		var nDirs, nFiles int
		for _, c := range MazeChildren(p, 1, cfg) {
			if c.IsDir() {
				nDirs++
			} else {
				nFiles++
			}
		}
		if nDirs < cfg.MinDirs || nDirs > cfg.MaxDirs {
			t.Errorf("%s: nDirs=%d outside [%d,%d]", p, nDirs, cfg.MinDirs, cfg.MaxDirs)
		}
		if nFiles < cfg.MinFiles || nFiles > cfg.MaxFiles {
			t.Errorf("%s: nFiles=%d outside [%d,%d]", p, nFiles, cfg.MinFiles, cfg.MaxFiles)
		}
	}
}

func TestMazeFileContent(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"passwords.txt", true}, {"credentials.txt", true}, {"accounts.txt", true},
		{"id_rsa", true}, {"private.key", true},
		{"error.log", false}, {"config.xml", false},
	}
	for _, tc := range cases {
		if got := len(MazeFileContent(tc.name)) > 0; got != tc.want {
			t.Errorf("MazeFileContent(%q): non-empty=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestMazeFileNodeAttrs(t *testing.T) {
	// Maze files carry Archive only (no Normal) — the attr distinction the SMB
	// adapter must preserve byte-identically.
	n := MazeFileNode(`C$\x\error.log`, "error.log")
	if !n.Archive || n.Normal || n.Dir {
		t.Errorf("maze file flags: Archive=%v Normal=%v Dir=%v; want Archive only", n.Archive, n.Normal, n.Dir)
	}
}

// --- default tree (byte-identical attribute reproduction) ---

func TestDefaultTreeAttrs(t *testing.T) {
	tr := DefaultTree(DefaultMazeConfig())
	c := tr.Roots["C$"]
	if c == nil {
		t.Fatal("C$ root missing")
	}
	sys32 := c.FindChild("Windows").FindChild("System32")

	ntos := sys32.FindChild("ntoskrnl.exe")
	if !ntos.System || !ntos.Normal || ntos.Archive {
		t.Errorf("ntoskrnl.exe flags: System=%v Normal=%v Archive=%v; want System|Normal", ntos.System, ntos.Normal, ntos.Archive)
	}
	sam := sys32.FindChild("config").FindChild("SAM")
	if !sam.ReadOnly || !sam.System || !sam.Normal {
		t.Errorf("SAM flags: RO=%v System=%v Normal=%v; want RO|System|Normal", sam.ReadOnly, sam.System, sam.Normal)
	}
	pw := c.FindChild("Users").FindChild("Administrator").FindChild("Documents").FindChild("passwords.txt")
	if pw == nil || !pw.Archive || pw.Normal || len(pw.Content) == 0 {
		t.Errorf("passwords.txt: want Archive, !Normal, content; got %+v", pw)
	}
	// ADMIN$ root mirrors the Windows subtree.
	if tr.Roots["ADMIN$"].FindChild("System32") == nil {
		t.Error("ADMIN$ should expose System32")
	}
}

// --- BuildTree: explicit (a) + seeded (b) ---

func TestBuildTreeExplicitAndSeeded(t *testing.T) {
	dir := t.TempDir()
	seedPath := "seeds/secret.txt"
	if err := os.MkdirAll(filepath.Join(dir, "seeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, seedPath), []byte("TOPSECRET-DATA"), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewCredStore([]Credential{{ID: "svc", Username: "svc_backup", Password: "V33m!", Domain: "CORP"}})

	cfg := TreeConfig{
		Shares: []ShareDef{{
			Name: "BACKUPS",
			Type: "disk",
			Root: &NodeDefGroup{
				Dirs: []DirDef{{
					Name: "creds",
					Files: []FileDef{
						{Name: "from_seed.txt", SeedFile: seedPath},
						{Name: "inline.txt", Content: "user={{cred:svc.username}} pass={{cred:svc.password}}"},
					},
				}},
			},
		}},
		Maze: DefaultMazeConfig(),
	}

	tr, err := BuildTree(cfg, store, dir)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	creds := tr.Roots["BACKUPS"].FindChild("creds")
	if creds == nil {
		t.Fatal("creds dir missing")
	}
	fromSeed := creds.FindChild("from_seed.txt")
	if fromSeed == nil || string(fromSeed.Content) != "TOPSECRET-DATA" {
		t.Errorf("seed_file content wrong: %q", fromSeed.Content)
	}
	inline := creds.FindChild("inline.txt")
	if inline == nil || string(inline.Content) != "user=svc_backup pass=V33m!" {
		t.Errorf("inline interpolation wrong: %q", inline.Content)
	}
}

func TestBuildTreeUnknownCredErrors(t *testing.T) {
	cfg := TreeConfig{Shares: []ShareDef{{
		Name: "X",
		Root: &NodeDefGroup{Files: []FileDef{{Name: "f", Content: "{{cred:missing.password}}"}}},
	}}}
	if _, err := BuildTree(cfg, NewCredStore(nil), ""); err == nil {
		t.Error("expected error for unknown credential id")
	}
}

// --- BuildTree: generate (c) determinism ---

func TestBuildTreeGenerateDeterministic(t *testing.T) {
	mk := func() *Tree {
		cfg := TreeConfig{Shares: []ShareDef{{
			Name:     "DATA",
			Type:     "disk",
			Generate: &GenSpec{Seed: "fixed-v1", Dirs: Range{Min: 3, Max: 6}, Files: Range{Min: 2, Max: 4}, Depth: 2},
		}}}
		tr, err := BuildTree(cfg, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		return tr
	}
	a, b := mk(), mk()
	an, bn := a.Roots["DATA"].Children, b.Roots["DATA"].Children
	if len(an) == 0 {
		t.Fatal("generate produced no children")
	}
	if len(an) != len(bn) {
		t.Fatalf("non-deterministic generate: %d vs %d", len(an), len(bn))
	}
	for i := range an {
		if an[i].Name != bn[i].Name {
			t.Errorf("generate child[%d] mismatch: %q vs %q", i, an[i].Name, bn[i].Name)
		}
	}
	// Materialized generate nodes must NOT be live maze nodes.
	for _, c := range an {
		if c.MazePath != "" {
			t.Errorf("generated node %q unexpectedly marked as maze node", c.Name)
		}
	}
}

// --- CredStore ---

func TestCredStoreRenderAndLeak(t *testing.T) {
	s := NewCredStore([]Credential{{ID: "a", Username: "alice", Password: "pw1", Domain: "D"}})
	got, err := s.Render("u={{cred:a.username}} p={{cred:a.password}} d={{cred:a.domain}}")
	if err != nil {
		t.Fatal(err)
	}
	if got != "u=alice p=pw1 d=D" {
		t.Errorf("Render = %q", got)
	}
	if _, err := s.Render("{{cred:nope.username}}"); err == nil {
		t.Error("expected error for unknown id")
	}
	if ls, ok := s.LeakString("a"); !ok || ls != "alice:pw1" {
		t.Errorf("LeakString = %q,%v", ls, ok)
	}
	if _, ok := s.LeakString("nope"); ok {
		t.Error("LeakString should fail for unknown id")
	}
}
