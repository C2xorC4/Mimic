// Command matrix is the live tier of the fingerprint regression harness. It
// scans a running Mimic target with nmap (-O -sV) and diffs the result against
// the committed per-profile goldens (test/golden/*.yaml), reusing the exact
// parser+comparator that internal/verify unit-tests offline. Any drift in OS
// attribution, persona port disposition, or service banner is a TELL and the
// command exits non-zero — the mechanical "no fingerprint regression" gate the
// working method requires.
//
// It scans whatever profile the target is CURRENTLY running; point it at one
// golden that matches that instance, or run it per profile in a deploy loop
// (see `make matrix` and the cross-version loop documented in MEMORY.md). The
// scan+diff engine is intentionally separate from deployment so it works against
// any reachable target (lab VM, a real host) without embedding lab specifics.
//
// Usage:
//
//	go run ./test/matrix -target 10.0.254.45 -golden windows-server-2025.yaml
//	go run ./test/matrix -target 10.0.254.45 -all      # every golden (target must match each)
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"flag"

	"github.com/c2xorc4/mimic/internal/verify"
)

func main() {
	var (
		target    = flag.String("target", "", "target host/IP to scan (required)")
		goldenDir = flag.String("golden-dir", filepath.Join("test", "golden"), "directory of golden YAML files")
		golden    = flag.String("golden", "", "single golden file (under -golden-dir) to check")
		all       = flag.Bool("all", false, "check every golden in -golden-dir (target must match each in turn)")
		nmapBin   = flag.String("nmap", "nmap", "nmap binary")
		extra     = flag.String("nmap-args", "--osscan-guess -Pn", "extra nmap args")
	)
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "error: -target is required")
		flag.Usage()
		os.Exit(2)
	}

	goldens, err := selectGoldens(*goldenDir, *golden, *all)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	totalTells := 0
	for _, gf := range goldens {
		g, err := verify.LoadGolden(gf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load %s: %v\n", gf, err)
			totalTells++
			continue
		}
		fmt.Printf("\n== %s (%s) ==\n", g.Profile, filepath.Base(gf))
		scan, err := runNmap(*nmapBin, *extra, *target, scanPorts(g))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  scan failed: %v\n", err)
			totalTells++
			continue
		}
		fmt.Printf("  nmap OS: %q  (families=%v gens=%v)\n", scan.OSMatchName, scan.OSFamilies, scan.OSGens)
		for _, r := range verify.CompareScan(g, scan) {
			fmt.Printf("  [%-4s] %-8s %-26s expected=%q observed=%q %s\n",
				r.Status, r.Layer, r.Check, r.Expected, r.Observed, r.Detail)
			if r.Status == verify.StatusTell {
				totalTells++
			}
		}
	}

	fmt.Println()
	if totalTells > 0 {
		fmt.Printf("FAIL — %d tell(s) / error(s) across %d profile(s)\n", totalTells, len(goldens))
		os.Exit(1)
	}
	fmt.Printf("PASS — %d profile(s) coherent, no fingerprint drift\n", len(goldens))
}

// selectGoldens resolves which golden files to check.
func selectGoldens(dir, single string, all bool) ([]string, error) {
	switch {
	case single != "":
		return []string{filepath.Join(dir, single)}, nil
	case all:
		matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no goldens in %s", dir)
		}
		sort.Strings(matches)
		return matches, nil
	default:
		return nil, fmt.Errorf("specify -golden <file> or -all")
	}
}

// scanPorts is the union of the golden's open, closed/filtered, and service
// ports — exactly the persona surface, so nmap probes what we assert on.
func scanPorts(g *verify.Golden) string {
	seen := map[int]bool{}
	var ports []int
	add := func(p int) {
		if p > 0 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	for _, p := range g.OpenPorts {
		add(p)
	}
	for _, p := range g.ClosedOrFiltered {
		add(p)
	}
	for p := range g.Services {
		add(p)
	}
	sort.Ints(ports)
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// runNmap executes an OS+version scan and parses the XML from stdout.
func runNmap(bin, extra, target, ports string) (*verify.ScanResult, error) {
	args := []string{"-O", "-sV"}
	args = append(args, strings.Fields(extra)...)
	if ports != "" {
		args = append(args, "-p", ports)
	}
	args = append(args, "-oX", "-", target)

	cmd := exec.Command(bin, args...)
	out, err := cmd.Output()
	if err != nil {
		// nmap may exit non-zero yet still emit usable XML; try to parse anyway.
		if len(out) == 0 {
			return nil, fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
		}
	}
	return verify.ParseNmapXML(out)
}
