package verify

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Golden is the recorded, expected fingerprint surface for one profile. It is
// the source of truth the live matrix runner diffs each scan against; a drift
// (OS attribution changed, a persona port flipped open/filtered, a service
// banner regressed) is a TELL and fails the run. Capture once from a validated
// instance, review, commit under test/golden/.
type Golden struct {
	Profile string `yaml:"profile"`

	// OSMatch is the nmap -O attribution that must hold. Family is matched
	// case-insensitively; the observed osgen set must intersect Gens (nmap
	// labels the modern Windows stack "10|11" regardless of the real build).
	OSMatch struct {
		Family string   `yaml:"family"` // e.g. "windows"
		Gens   []string `yaml:"gens"`   // acceptable osgen values, e.g. ["10","11"]
	} `yaml:"os_match"`

	// OpenPorts must be open; ClosedOrFiltered must NOT be open (closed or
	// filtered both acceptable — the edition persona decides which, asserted
	// separately by the disposition checks if needed).
	OpenPorts        []int `yaml:"open_ports"`
	ClosedOrFiltered []int `yaml:"closed_or_filtered"`

	// Services maps an open port to a substring that must appear (case-
	// insensitively) in that port's nmap service banner (name+product+version).
	Services map[int]string `yaml:"services"`
}

// LoadGolden reads one golden YAML file.
func LoadGolden(path string) (*Golden, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g Golden
	if err := yaml.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("parse golden %s: %w", path, err)
	}
	return &g, nil
}

// CompareScan diffs an observed scan against the golden and returns one Result
// per check. Any TELL means the fingerprint regressed for this profile.
func CompareScan(g *Golden, scan *ScanResult) []Result {
	var out []Result

	// OS attribution.
	out = append(out, checkOSFamily(g, scan))
	out = append(out, checkOSGen(g, scan))

	// Port disposition.
	openSet := intSet(scan.Open)
	for _, p := range g.OpenPorts {
		r := Result{Layer: "ports", Check: fmt.Sprintf("%d open", p), Expected: "open"}
		if openSet[p] {
			r.Status, r.Observed = StatusOK, "open"
		} else {
			r.Status, r.Observed = StatusTell, dispositionOf(scan, p)
			r.Detail = "persona port is not open"
		}
		out = append(out, r)
	}
	for _, p := range g.ClosedOrFiltered {
		r := Result{Layer: "ports", Check: fmt.Sprintf("%d not open", p), Expected: "closed|filtered"}
		if openSet[p] {
			r.Status, r.Observed, r.Detail = StatusTell, "open", "port should not be open for this persona"
		} else {
			r.Status, r.Observed = StatusOK, dispositionOf(scan, p)
		}
		out = append(out, r)
	}

	// Service banners.
	ports := make([]int, 0, len(g.Services))
	for p := range g.Services {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		want := strings.ToLower(g.Services[p])
		r := Result{Layer: "service", Check: fmt.Sprintf("%d banner ~ %q", p, want), Expected: want}
		svc, ok := scan.Services[p]
		if !ok {
			r.Status, r.Observed, r.Detail = StatusTell, "(no service / closed)", "expected an open service here"
		} else if strings.Contains(svc.Banner(), want) {
			r.Status, r.Observed = StatusOK, svc.Banner()
		} else {
			r.Status, r.Observed, r.Detail = StatusTell, svc.Banner(), "service banner does not contain the expected token"
		}
		out = append(out, r)
	}
	return out
}

func checkOSFamily(g *Golden, scan *ScanResult) Result {
	want := strings.ToLower(g.OSMatch.Family)
	r := Result{Layer: "os", Check: "nmap osfamily", Expected: want, Observed: strings.Join(scan.OSFamilies, "|")}
	if want == "" {
		r.Status, r.Detail = StatusSkip, "no os_match.family in golden"
		return r
	}
	for _, f := range scan.OSFamilies {
		if f == want {
			r.Status = StatusOK
			return r
		}
	}
	r.Status, r.Detail = StatusTell, "nmap OS family attribution drifted"
	return r
}

func checkOSGen(g *Golden, scan *ScanResult) Result {
	r := Result{Layer: "os", Check: "nmap osgen", Expected: strings.Join(g.OSMatch.Gens, "|"), Observed: strings.Join(scan.OSGens, "|")}
	if len(g.OSMatch.Gens) == 0 {
		r.Status, r.Detail = StatusSkip, "no os_match.gens in golden"
		return r
	}
	want := map[string]bool{}
	for _, gen := range g.OSMatch.Gens {
		want[gen] = true
	}
	for _, gen := range scan.OSGens {
		if want[gen] {
			r.Status = StatusOK
			return r
		}
	}
	r.Status, r.Detail = StatusTell, "nmap OS generation attribution drifted"
	return r
}

func intSet(xs []int) map[int]bool {
	m := make(map[int]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func dispositionOf(scan *ScanResult, port int) string {
	switch {
	case intSet(scan.Open)[port]:
		return "open"
	case intSet(scan.Closed)[port]:
		return "closed"
	case intSet(scan.Filtered)[port]:
		return "filtered"
	default:
		return "absent"
	}
}
