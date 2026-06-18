package capture

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	sidecarTargetRE = regexp.MustCompile(`target=(\d+\.\d+\.\d+\.\d+)`)
	sidecarNmapRE   = regexp.MustCompile(`Nmap scan report for .*\((\d+\.\d+\.\d+\.\d+)\)`)
)

// ServerIPFromSidecar extracts the target server IP recorded alongside a capture.
// Proxmox LLMNR harness writes "target=<ip>" into the companion .nmap.txt; standard
// nmap output uses "Nmap scan report for host (ip)".
func ServerIPFromSidecar(pcapPath string) (net.IP, bool) {
	for _, path := range sidecarCandidates(pcapPath) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(data)
		if m := sidecarTargetRE.FindStringSubmatch(text); len(m) == 2 {
			if ip := net.ParseIP(m[1]); ip != nil {
				return ip, true
			}
		}
		if m := sidecarNmapRE.FindStringSubmatch(text); len(m) == 2 {
			if ip := net.ParseIP(m[1]); ip != nil {
				return ip, true
			}
		}
	}
	return nil, false
}

func sidecarCandidates(pcapPath string) []string {
	dir := filepath.Dir(pcapPath)
	base := strings.TrimSuffix(filepath.Base(pcapPath), filepath.Ext(pcapPath))
	// e.g. llmnr_20260612_145119.pcapng -> llmnr_20260612_145119.nmap.txt
	return []string{
		filepath.Join(dir, base+".nmap.txt"),
		filepath.Join(dir, base+".txt"),
	}
}