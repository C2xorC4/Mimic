package capture

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeSNMPOIDs(t *testing.T) {
	pcapPath := filepath.Join("..", "..", "captures", "snmp_srv2022.pcapng")
	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("pcap not available: %v", err)
	}
	proc := NewPCAPProcessor([]net.IP{net.ParseIP("10.0.251.141")}, []uint16{161})
	if err := proc.ProcessFile(pcapPath); err != nil {
		t.Fatal(err)
	}
	oids := map[string]int{}
	total := 0
	for _, s := range proc.GetSessions() {
		for _, ex := range s.Exchanges {
			if len(ex.Probe) == 0 {
				continue
			}
			total++
			for _, oid := range extractSNMPRequestOIDs(ex.Probe) {
				oids[oid]++
			}
		}
	}
	t.Logf("exchanges=%d unique_oids=%d", total, len(oids))
	for oid, n := range oids {
		if isScannerSNMPOID(oid) {
			t.Logf("  keep %s (%d)", oid, n)
		}
	}
	kept := 0
	for oid := range oids {
		if isScannerSNMPOID(oid) {
			kept++
		}
	}
	t.Logf("system_mib_oids=%d of %d total", kept, len(oids))
	if kept > 10 {
		t.Errorf("system MIB filter should keep a handful, got %d", kept)
	}
}