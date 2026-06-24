//go:build windows

package netfilter

import (
	"strings"
	"testing"
)

func TestLinuxTProbeFilterForPorts(t *testing.T) {
	filter, ok := linuxTProbeFilterForPorts(nil)
	if ok || filter != "" {
		t.Fatalf("empty ports: filter=%q ok=%v", filter, ok)
	}

	filter, ok = linuxTProbeFilterForPorts([]uint16{80, 9999})
	if !ok {
		t.Fatal("expected filter for ports")
	}
	for _, want := range []string{
		"inbound and tcp and !loopback",
		linuxTProbeFlagClause,
		"tcp.DstPort == 80",
		"tcp.DstPort == 9999",
	} {
		if !strings.Contains(filter, want) {
			t.Fatalf("filter missing %q:\n%s", want, filter)
		}
	}
	// Must not be a global ACK/SYN+ACK catcher — port clause is mandatory.
	if !strings.Contains(filter, " and (tcp.DstPort == ") {
		t.Fatalf("filter not port-scoped: %s", filter)
	}
}

func TestLinuxT7ProbeFilterForPorts(t *testing.T) {
	filter, ok := linuxT7ProbeFilterForPorts([]uint16{80})
	if !ok {
		t.Fatal("expected T7 filter")
	}
	for _, want := range []string{
		"tcp.Fin",
		"!tcp.Syn and !tcp.Rst",
		"tcp.DstPort == 80",
	} {
		if !strings.Contains(filter, want) {
			t.Fatalf("T7 filter missing %q:\n%s", want, filter)
		}
	}
	if strings.Contains(filter, "tcp.Urg") {
		t.Fatalf("T7 filter should not require URG: %s", filter)
	}
}