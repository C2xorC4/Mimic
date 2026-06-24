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
	for _, gated := range []string{"msrpc", "netbios", "smb_honeypot"} {
		if contains(got, gated) {
			t.Fatalf("workstation should gate %s, got %v", gated, got)
		}
	}
	if !contains(got, "http") {
		t.Fatalf("expected http, got %v", got)
	}
}

func TestDesktopPersonaPortGating(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"wsd", "deliveryopt", "http", "msrpc"} {
		svcDir := filepath.Join(dir, name)
		if err := os.MkdirAll(svcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(svcDir, "manifest.yaml"), []byte("name: "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Workstation: desktop ports exposed, server RPC gated out.
	ws, err := ResolveRunServices([]string{"all"}, dir, &OSProfile{Family: "windows", Edition: "workstation"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"wsd", "deliveryopt", "http"} {
		if !contains(ws, want) {
			t.Fatalf("workstation should expose %s, got %v", want, ws)
		}
	}
	if contains(ws, "msrpc") {
		t.Fatalf("workstation should gate msrpc, got %v", ws)
	}

	// Server: desktop ports gated out, RPC exposed.
	srv, err := ResolveRunServices([]string{"all"}, dir, &OSProfile{Family: "windows", Edition: "server"})
	if err != nil {
		t.Fatal(err)
	}
	for _, gated := range []string{"wsd", "deliveryopt"} {
		if contains(srv, gated) {
			t.Fatalf("server should gate desktop port %s, got %v", gated, srv)
		}
	}
	if !contains(srv, "msrpc") {
		t.Fatalf("server should expose msrpc, got %v", srv)
	}
}

func TestPromoteLinuxSSH(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ssh", "http"} {
		svcDir := filepath.Join(dir, name)
		if err := os.MkdirAll(svcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(svcDir, "manifest.yaml"), []byte("name: "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	linux := &OSProfile{Family: "linux", Name: "Debian"}
	got, err := ResolveRunServices([]string{"ssh", "http"}, dir, linux)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(got, "ssh_honeypot") {
		t.Fatalf("linux profile should promote ssh to ssh_honeypot, got %v", got)
	}
	if contains(got, "ssh") {
		t.Fatalf("banner ssh template should be replaced, got %v", got)
	}

	win := &OSProfile{Family: "windows", Edition: "server"}
	got, err = ResolveRunServices([]string{"ssh", "http"}, dir, win)
	if err != nil {
		t.Fatal(err)
	}
	if contains(got, "ssh_honeypot") {
		t.Fatalf("windows profile should keep ssh template, got %v", got)
	}
	if !contains(got, "ssh") {
		t.Fatalf("expected ssh template on windows, got %v", got)
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