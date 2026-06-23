package verify

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// This file parses `nmap -O -sV -oX` output into a normalized ScanResult and
// compares it against a per-profile golden. It is the parsing+diff core of the
// fingerprint regression harness: the live matrix runner (test/matrix) feeds it
// real scans, and nmapxml_test.go exercises it offline against a recorded
// fixture so the comparator itself is covered in `go test` / CI without a lab.

// nmap -oX schema (only the fields the harness asserts on).
type nmapRun struct {
	Hosts []struct {
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
					Tunnel  string `xml:"tunnel,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
		OS struct {
			OSMatch []struct {
				Name     string `xml:"name,attr"`
				Accuracy int    `xml:"accuracy,attr"`
				OSClass  []struct {
					OSFamily string `xml:"osfamily,attr"`
					OSGen    string `xml:"osgen,attr"`
					Vendor   string `xml:"vendor,attr"`
				} `xml:"osclass"`
			} `xml:"osmatch"`
		} `xml:"os"`
	} `xml:"host"`
}

// ServiceInfo is the version-detection result for one open port.
type ServiceInfo struct {
	Name    string // nmap service name (e.g. "http", "msrpc")
	Product string // e.g. "Microsoft IIS httpd"
	Version string // e.g. "10.0"
	Tunnel  string // e.g. "ssl"
}

// Banner is the lower-cased concatenation used for substring matching.
func (s ServiceInfo) Banner() string {
	return strings.ToLower(strings.TrimSpace(s.Name + " " + s.Product + " " + s.Version))
}

// ScanResult is the normalized, profile-agnostic view of one nmap scan.
type ScanResult struct {
	Open     []int               // ports in state "open"
	Closed   []int               // ports in state "closed" (RST)
	Filtered []int               // ports in state "filtered" (dropped)
	Services map[int]ServiceInfo // open-port service detection
	// OSFamilies / OSGens are the union across osclass entries of the top
	// osmatch — nmap's digestible OS attribution.
	OSMatchName string
	OSFamilies  []string
	OSGens      []string
}

// ParseNmapXML parses `nmap -oX` bytes into a ScanResult. It reads the first
// host (the harness scans one target at a time).
func ParseNmapXML(data []byte) (*ScanResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}
	if len(run.Hosts) == 0 {
		return nil, fmt.Errorf("nmap xml has no host (target down or unscanned?)")
	}
	h := run.Hosts[0]
	res := &ScanResult{Services: map[int]ServiceInfo{}}
	for _, p := range h.Ports.Port {
		if p.Protocol != "tcp" {
			continue
		}
		switch p.State.State {
		case "open":
			res.Open = append(res.Open, p.PortID)
			res.Services[p.PortID] = ServiceInfo{
				Name: p.Service.Name, Product: p.Service.Product,
				Version: p.Service.Version, Tunnel: p.Service.Tunnel,
			}
		case "closed":
			res.Closed = append(res.Closed, p.PortID)
		case "filtered":
			res.Filtered = append(res.Filtered, p.PortID)
		}
	}
	sort.Ints(res.Open)
	sort.Ints(res.Closed)
	sort.Ints(res.Filtered)

	// Use the highest-accuracy osmatch (nmap emits them sorted, but be explicit).
	bestAcc := -1
	famSeen, genSeen := map[string]bool{}, map[string]bool{}
	for _, m := range h.OS.OSMatch {
		if m.Accuracy <= bestAcc {
			continue
		}
		bestAcc = m.Accuracy
		res.OSMatchName = m.Name
		res.OSFamilies, res.OSGens = nil, nil
		famSeen, genSeen = map[string]bool{}, map[string]bool{}
		for _, c := range m.OSClass {
			if f := strings.ToLower(c.OSFamily); f != "" && !famSeen[f] {
				famSeen[f] = true
				res.OSFamilies = append(res.OSFamilies, f)
			}
			if c.OSGen != "" && !genSeen[c.OSGen] {
				genSeen[c.OSGen] = true
				res.OSGens = append(res.OSGens, c.OSGen)
			}
		}
	}
	return res, nil
}
