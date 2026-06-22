package config

import (
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// EditionExposesPort reports whether a Windows edition should listen on a
// well-known persona port. Two port classes distinguish a server from a
// workstation (OSE-2026-001: Mimic's server-shaped open set 135/139/443/445/3389
// was the tell vs. a real Win11 client's 3389/5040/5357/5985/7680 with
// 135/139/445 FILTERED):
//
//   - 135/139/445 (RPC, NetBIOS, SMB): exposed by Server/DC; a firewalled
//     workstation filters them.
//   - 5040/5357/7680 (CDPSvc, WSDAPI, Delivery Optimization): client-SKU
//     "desktop" ports a workstation exposes but a server does not.
//
// 5985 (WinRM) is intentionally NOT gated here — a real Win11 client in
// OSE-2026-001 had it on, so it answers faithfully whenever enabled (see
// services/winrm/manifest.yaml). Non-Windows profiles (edition "") expose all
// ports — the concept does not apply.
func EditionExposesPort(edition string, port uint16) bool {
	if edition == "" {
		return true
	}
	switch port {
	case 135, 139, 445:
		return edition == "server" || edition == "dc"
	case 5040, 5357, 7680:
		return edition == "workstation"
	default:
		return true
	}
}

// honeypotListenPorts maps the interactive honeypot service names to the TCP
// ports they bind. The SMB honeypot additionally binds 139 on Server/DC
// editions (added by ServiceListenPorts via EditionExposesPort). Template
// services are not listed here — their port is read from the manifest.
var honeypotListenPorts = map[string][]uint16{
	"smb_honeypot": {445},
	"rdp":          {3389},
	"ftp_honeypot": {21},
}

// ServiceListenPorts returns the sorted, de-duplicated set of TCP ports the
// given resolved service list will actually bind under the supplied profile.
// Honeypot ports are known statically; template-service ports are read from each
// service's manifest. Used to derive the firewall allow-list for the workstation
// default-drop persona, so the served decoy ports stay reachable while every
// other port (incl. 135/139/445) is filtered.
func ServiceListenPorts(services []string, profile *OSProfile, servicesDir string) []uint16 {
	ed := ""
	if profile != nil {
		ed = profile.ResolvedEdition()
	}
	seen := make(map[uint16]struct{})
	var out []uint16
	add := func(p uint16) {
		if p == 0 {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, name := range services {
		if ports, ok := honeypotListenPorts[name]; ok {
			for _, p := range ports {
				add(p)
			}
			if name == "smb_honeypot" && EditionExposesPort(ed, 139) {
				add(139)
			}
			continue
		}
		if p := manifestPort(servicesDir, name); p != 0 {
			add(p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// manifestPort reads just the `port:` field from a template service manifest.
// Returns 0 if the manifest is missing or unparseable (the caller skips it).
func manifestPort(servicesDir, name string) uint16 {
	data, err := os.ReadFile(filepath.Join(servicesDir, name, "manifest.yaml"))
	if err != nil {
		return 0
	}
	var m struct {
		Port uint16 `yaml:"port"`
	}
	if yaml.Unmarshal(data, &m) != nil {
		return 0
	}
	return m.Port
}
