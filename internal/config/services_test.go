package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRunServicesAll(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"http", "smb", "msrpc", "rdp"} {
		svcDir := filepath.Join(dir, name)
		if err := os.MkdirAll(svcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(svcDir, "manifest.yaml"), []byte("name: "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	profile := &OSProfile{Edition: "server"}
	got, err := ResolveRunServices([]string{"all"}, dir, profile)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"smb_honeypot", "ftp_honeypot", "rdp",
		"http", "msrpc",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v (%d), want %v (%d)", got, len(got), want, len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("index %d: got %q want %q (full %v)", i, got[i], w, got)
		}
	}
	if contains(got, "smb") {
		t.Fatalf("smb template should be superseded by smb_honeypot: %v", got)
	}
}

func TestResolveRunServicesWorkstationGatesRPC(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"msrpc", "netbios", "http"} {
		svcDir := filepath.Join(dir, name)
		if err := os.MkdirAll(svcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(svcDir, "manifest.yaml"), []byte("name: "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	profile := &OSProfile{Edition: "workstation"}
	got, err := ResolveRunServices([]string{"all"}, dir, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, gated := range []string{"msrpc", "netbios"} {
		if contains(got, gated) {
			t.Fatalf("workstation should gate %s, got %v", gated, got)
		}
	}
	if !contains(got, "smb_honeypot") || !contains(got, "http") {
		t.Fatalf("expected smb_honeypot and http, got %v", got)
	}
}

func TestResolveServeServicesAll(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"http", "smb"} {
		svcDir := filepath.Join(dir, name)
		if err := os.MkdirAll(svcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(svcDir, "manifest.yaml"), []byte("name: "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ResolveServeServices([]string{"all"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "http" || got[1] != "smb" {
		t.Fatalf("got %v", got)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}