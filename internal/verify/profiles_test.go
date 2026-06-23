package verify

import (
	"path/filepath"
	"testing"

	"github.com/c2xorc4/mimic/internal/config"
)

// TestAllProfilesSelfConsistent is the offline, no-scanner regression gate: every
// shipped profile must pass the version<->stack-era coherence check. This is the
// codified OSE-2026-001 tell (a Win11 build advertising the Win10 stack, or vice
// versa) caught at the source in `go test`/CI, before any deploy. A profile edit
// that reintroduces the contradiction fails here.
func TestAllProfilesSelfConsistent(t *testing.T) {
	pm := config.NewProfileManager(filepath.Join("..", "..", "profiles"))
	if err := pm.LoadAllProfiles(); err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	names := pm.ListProfileNames()
	if len(names) == 0 {
		t.Fatal("no profiles loaded")
	}
	for _, name := range names {
		p, err := pm.GetProfile(name)
		if err != nil {
			t.Errorf("get profile %q: %v", name, err)
			continue
		}
		r := checkProfileConsistency(p)
		if r.Status == StatusTell {
			t.Errorf("profile %q self-contradiction: %s (expected=%q observed=%q)",
				name, r.Detail, r.Expected, r.Observed)
		}
	}
}
