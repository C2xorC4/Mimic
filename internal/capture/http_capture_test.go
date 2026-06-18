package capture

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/c2xorc4/mimic/internal/config"
)

func probeCountFromManifest(t *testing.T, manifestPath string) int {
	t.Helper()
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var manifest config.ServiceConfig
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	return len(manifest.Probes)
}

func generateHTTPFromPcap(t *testing.T, pcapPath, serverIP string, ports []uint16) int {
	t.Helper()
	processor := NewPCAPProcessor([]net.IP{net.ParseIP(serverIP)}, ports)
	if err := processor.ProcessFile(pcapPath); err != nil {
		t.Fatalf("processing %s: %v", pcapPath, err)
	}
	sessions := processor.GetSessions()
	if len(sessions) == 0 {
		t.Fatalf("no sessions in %s (server %s)", pcapPath, serverIP)
	}

	outDir := t.TempDir()
	gen := NewTemplateGenerator(outDir, "http", "test")
	for _, session := range sessions {
		gen.AddSession(session)
	}
	if len(gen.exchanges) == 0 {
		t.Fatalf("no exchanges after HTTP filter in %s", pcapPath)
	}
	output, err := gen.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return probeCountFromManifest(t, output.ManifestPath)
}

func TestHTTPPcapCapture_CleanHMDXIN(t *testing.T) {
	pcapPath := filepath.Join("..", "..", "captures", "hmdxin-services-20260218-084543", "http.pcapng")
	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("pcap not available: %v", err)
	}
	count := generateHTTPFromPcap(t, pcapPath, "10.0.250.7", []uint16{80, 443})
	if count > 15 {
		t.Errorf("clean http capture produced %d probes, want <= 15", count)
	}
	t.Logf("clean hmdxin http probes: %d", count)
}

func TestTemplateGenerator_HTTPBulkEnumFiltered(t *testing.T) {
	// Simulates http-enum output: hundreds of unique GET paths that should collapse
	// to a handful of method buckets once non-root paths are dropped.
	tg := NewTemplateGenerator(t.TempDir(), "http", "test")
	exchanges := make([]Exchange, 0, 520)
	for i := 0; i < 500; i++ {
		exchanges = append(exchanges, Exchange{
			Probe:    []byte("GET /enum-path-" + string(rune('a'+i%26)) + " HTTP/1.0\r\n\r\n"),
			Response: []byte("HTTP/1.1 404 Not Found\r\n\r\n"),
		})
	}
	exchanges = append(exchanges,
		Exchange{Probe: []byte("GET / HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\n")},
		Exchange{Probe: []byte("OPTIONS / HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\n")},
		Exchange{Probe: []byte("HEAD / HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\n")},
		Exchange{Probe: []byte("GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0\r\n\r\n"), Response: []byte("HTTP/1.1 404\r\n\r\n")},
	)
	session := &Session{Key: FlowKey{ServerPort: 80}, Exchanges: exchanges}
	tg.AddSession(session)

	if len(tg.exchanges) != 3 {
		t.Fatalf("bulk enum: kept %d exchanges, want 3 (GET /, OPTIONS, HEAD)", len(tg.exchanges))
	}
	output, err := tg.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	count := probeCountFromManifest(t, output.ManifestPath)
	if count > 10 {
		t.Errorf("bulk enum produced %d manifest probes, want <= 10", count)
	}
	t.Logf("bulk enum filtered to %d probes", count)
}