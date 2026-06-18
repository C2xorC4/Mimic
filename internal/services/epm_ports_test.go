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
	ports := ExtractNcacnIPTCPPorts(data, nil)
	if len(ports) < 4 {
		t.Fatalf("expected several dynamic ports, got %d: %v", len(ports), ports)
	}
	if len(ports) > 20 {
		t.Fatalf("tower parse should not over-extract; got %d: %v", len(ports), ports)
	}
	for _, p := range ports {
		if p < windowsDynamicPortMin {
			t.Fatalf("port %d below dynamic range", p)
		}
	}
	if !containsPort(ports, 49664) {
		t.Fatalf("expected 49664 in capture set, got %v", ports)
	}

	captureHost := []byte{10, 0, 254, 67}
	filtered := ExtractNcacnIPTCPPorts(data, captureHost)
	if len(filtered) != len(ports) {
		t.Fatalf("capture IP filter: unfiltered=%d filtered=%d ports=%v", len(ports), len(filtered), filtered)
	}
}

func TestExtractNcacnIPTCPPortsAfterHostIPRewrite(t *testing.T) {
	host := hostEgressIPv4()
	if host == nil {
		t.Skip("no egress IPv4 on this host")
	}

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
	ports := ExtractNcacnIPTCPPorts(resp, host)
	if len(ports) < 4 {
		t.Fatalf("after rewrite: expected several ports, got %d", len(ports))
	}
	if len(ports) > 20 {
		t.Fatalf("after rewrite: tower parse over-extracted %d ports", len(ports))
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