package control

import (
	"path/filepath"
	"testing"
)

func TestListProfiles(t *testing.T) {
	dir := filepath.Join("..", "..", "profiles")
	cat, err := ListProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Names) == 0 {
		t.Fatal("expected profiles")
	}
	if len(cat.Families) == 0 {
		t.Fatal("expected families map")
	}
	found := false
	for _, n := range cat.Names {
		if n == "Windows 11" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Windows 11 not in %v", cat.Names)
	}
}