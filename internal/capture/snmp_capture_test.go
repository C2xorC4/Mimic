package capture

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSNMPCapture_ProxmoxCurated(t *testing.T) {
	pcapPath := filepath.Join("..", "..", "captures", "snmp_srv2022.pcapng")
	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("pcap not available: %v", err)
	}

	proc := NewPCAPProcessor([]net.IP{net.ParseIP("10.0.251.141")}, []uint16{161})
	if err := proc.ProcessFile(pcapPath); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	gen := NewTemplateGenerator(outDir, "snmp", "Windows Server 2022")
	for _, session := range proc.GetSessions() {
		gen.AddSession(session)
	}
	if len(gen.exchanges) == 0 {
		t.Fatal("no exchanges after SNMP filter")
	}
	output, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	count := probeCountFromManifest(t, output.ManifestPath)
	if count > 10 {
		t.Errorf("curated SNMP capture produced %d probes, want <= 10", count)
	}
	if count < 2 {
		t.Errorf("curated SNMP capture produced %d probes, want at least sysDescr/sysUpTime/sysName", count)
	}
	t.Logf("SNMP srv2022 curated probes: %d (was 236)", count)
}