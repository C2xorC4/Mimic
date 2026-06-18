package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/c2xorc4/mimic/internal/config"
)

func TestExtractNcacnIPTCPPortsFromCapture(t *testing.T) {
	path := filepath.Join("..", "..", "services", "msrpc", "responses", "epm_lookup.bin")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ports := ExtractNcacnIPTCPPorts(data)
	if len(ports) < 10 {
		t.Fatalf("expected many dynamic ports, got %d: %v", len(ports), ports)
	}
	for _, p := range ports {
		if p < windowsDynamicPortMin {
			t.Fatalf("port %d below dynamic range", p)
		}
	}
	// Spot-check a port known from the Win11 25H2 capture (stable in template).
	if !containsPort(ports, 49664) && !containsPort(ports, 49665) {
		t.Logf("49664/49665 not in set (capture may differ); ports=%v", ports)
	}
}

func TestExtractNcacnIPTCPPortsAfterHostIPRewrite(t *testing.T) {
	dir := filepath.Join("..", "..", "services", "msrpc")
	r, err := NewResponderWithOptions(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := []config.RewriteRule{
		{Type: "dcerpc_callid"},
		{Type: "host_ip", Token: "10.0.254.67"},
	}
	probe := eptLookupProbeBytes()
	resp, err := r.GetResponse("responses/epm_lookup.bin", probe, rules)
	if err != nil {
		t.Fatal(err)
	}
	ports := ExtractNcacnIPTCPPorts(resp)
	if len(ports) < 10 {
		t.Fatalf("after rewrite: expected many ports, got %d", len(ports))
	}
}

func containsPort(ports []uint16, want uint16) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}