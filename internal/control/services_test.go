package control

import (
	"path/filepath"
	"testing"
)

func TestListServices(t *testing.T) {
	dir := filepath.Join("..", "..", "services")
	cat, err := ListServices(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Names) == 0 {
		t.Fatal("expected services")
	}
	found := false
	for _, n := range cat.Names {
		if n == "smb" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("smb not in %v", cat.Names)
	}
}