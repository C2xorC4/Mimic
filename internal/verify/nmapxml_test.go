package verify

import (
	"os"
	"path/filepath"
	"testing"
)

// fixtureXML is a real `nmap 7.98 -O -sV -oX` scan of a validated Server 2025
// Mimic instance (argus, 2026-06-22). It anchors the parser+comparator so the
// fingerprint regression logic is covered offline, no lab required.
const fixtureXML = "testdata/nmap_srv2025_argus.xml"

func loadFixture(t *testing.T) *ScanResult {
	t.Helper()
	data, err := os.ReadFile(fixtureXML)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	scan, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return scan
}

func TestParseNmapXML_Fixture(t *testing.T) {
	scan := loadFixture(t)

	wantOpen := map[int]bool{135: true, 139: true, 443: true, 445: true, 3389: true, 5985: true}
	if len(scan.Open) != len(wantOpen) {
		t.Errorf("open ports = %v, want %v", scan.Open, wantOpen)
	}
	for _, p := range scan.Open {
		if !wantOpen[p] {
			t.Errorf("unexpected open port %d", p)
		}
	}
	if !intSet(scan.Closed)[5040] {
		t.Errorf("5040 should be closed; closed=%v filtered=%v", scan.Closed, scan.Filtered)
	}

	// OS attribution.
	if len(scan.OSFamilies) != 1 || scan.OSFamilies[0] != "windows" {
		t.Errorf("osfamilies = %v, want [windows]", scan.OSFamilies)
	}
	hasGen := map[string]bool{}
	for _, g := range scan.OSGens {
		hasGen[g] = true
	}
	if !hasGen["10"] || !hasGen["11"] {
		t.Errorf("osgens = %v, want both 10 and 11", scan.OSGens)
	}

	// Service detection.
	if svc, ok := scan.Services[443]; !ok || svc.Tunnel != "ssl" {
		t.Errorf("443 service = %+v, want ssl tunnel", svc)
	}
	if svc := scan.Services[5985]; svc.Product == "" {
		t.Errorf("5985 should have a product banner, got %+v", svc)
	}
}

func TestCompareScan_GoldenMatches(t *testing.T) {
	scan := loadFixture(t)
	g, err := LoadGolden(filepath.Join("..", "..", "test", "golden", "windows-server-2025.yaml"))
	if err != nil {
		t.Fatalf("load golden: %v", err)
	}
	results := CompareScan(g, scan)
	if len(results) == 0 {
		t.Fatal("CompareScan returned no checks")
	}
	for _, r := range results {
		if r.Status == StatusTell {
			t.Errorf("unexpected TELL: %s/%s expected=%q observed=%q (%s)",
				r.Layer, r.Check, r.Expected, r.Observed, r.Detail)
		}
	}
}

func TestCompareScan_DetectsDrift(t *testing.T) {
	scan := loadFixture(t)

	// A golden expecting a Linux box, a port that's actually closed to be open,
	// and a wrong banner — every one of these must be flagged as a TELL.
	bad := &Golden{Profile: "broken"}
	bad.OSMatch.Family = "linux"
	bad.OSMatch.Gens = []string{"5.x"}
	bad.OpenPorts = []int{5040}        // actually closed in the fixture
	bad.ClosedOrFiltered = []int{443}  // actually open
	bad.Services = map[int]string{443: "nginx"} // actually IIS

	tells := 0
	for _, r := range CompareScan(bad, scan) {
		if r.Status == StatusTell {
			tells++
		}
	}
	// Expect: osfamily, osgen, 5040-not-open, 443-should-not-be-open, 443-banner.
	if tells < 5 {
		t.Errorf("expected >=5 TELLs for a fully-wrong golden, got %d", tells)
	}
}
