package capture

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestServerIPFromSidecar_LLMRNTarget(t *testing.T) {
	dir := t.TempDir()
	pcap := filepath.Join(dir, "llmnr_20260612_145119.pcapng")
	sidecar := filepath.Join(dir, "llmnr_20260612_145119.nmap.txt")
	if err := os.WriteFile(sidecar, []byte("LLMNR query name=DESKTOP-G6JUGNO target=10.0.251.64\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ip, ok := ServerIPFromSidecar(pcap)
	if !ok || ip.String() != "10.0.251.64" {
		t.Fatalf("ServerIPFromSidecar() = (%v, %v), want 10.0.251.64 true", ip, ok)
	}
}

func TestLLMNRCapture_ProxmoxMulticast(t *testing.T) {
	pcapPath := filepath.Join("..", "..", "captures", "llmnr_win11_proxmox.pcapng")
	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("pcap not available: %v", err)
	}
	ip, ok := ServerIPFromSidecar(pcapPath)
	if !ok {
		ip = net.ParseIP("10.0.251.64")
	}

	proc := NewPCAPProcessor([]net.IP{ip}, []uint16{5355})
	if err := proc.ProcessFile(pcapPath); err != nil {
		t.Fatal(err)
	}
	sessions := proc.GetSessions()
	if len(sessions) == 0 {
		t.Fatal("expected LLMNR session")
	}
	exchanges := 0
	for _, s := range sessions {
		exchanges += len(s.Exchanges)
	}
	if exchanges == 0 {
		t.Fatalf("expected probe/response exchanges, stats=%+v sessions=%d", proc.GetStats(), len(sessions))
	}
	if exchanges > 5 {
		t.Errorf("got %d exchanges, want a small number (deduped probes)", exchanges)
	}
	t.Logf("LLMNR proxmox: %d sessions, %d exchanges", len(sessions), exchanges)
}

func TestLLMNRCapture_HMDXINAggregatesSessions(t *testing.T) {
	pcapPath := filepath.Join("..", "..", "captures", "hmdxin-services-20260218-084543", "llmnr.pcapng")
	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("pcap not available: %v", err)
	}
	proc := NewPCAPProcessor([]net.IP{net.ParseIP("10.0.250.7")}, []uint16{5355})
	if err := proc.ProcessFile(pcapPath); err != nil {
		t.Fatal(err)
	}
	if len(proc.GetSessions()) != 1 {
		t.Fatalf("expected aggregated LLMNR session, got %d", len(proc.GetSessions()))
	}
}