package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// StatefulServiceNames are interactive honeypots started by mimic run (not template replay).
var StatefulServiceNames = []string{"smb_honeypot", "ftp_honeypot", "rdp", "ssh_honeypot"}

// templateSupersededBy maps replay templates replaced when a stateful honeypot is enabled.
var templateSupersededBy = map[string]string{
	"smb": "smb_honeypot",
	"rdp": "rdp",
	"ssh": "ssh_honeypot", // banner-only ssh template → interactive ssh honeypot
}

// ListTemplateServices returns manifest-backed service names under servicesDir.
func ListTemplateServices(servicesDir string) ([]string, error) {
	entries, err := os.ReadDir(servicesDir)
	if err != nil {
		return nil, fmt.Errorf("reading services dir: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(servicesDir, entry.Name(), "manifest.yaml")
		if _, err := os.Stat(manifestPath); err == nil {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// ResolveRunServices expands "all", merges explicit entries, drops templates
// superseded by stateful honeypots, and applies os_edition port persona rules.
func ResolveRunServices(requested []string, servicesDir string, profile *OSProfile) ([]string, error) {
	expanded, err := expandRequested(requested, servicesDir, true)
	if err != nil {
		return nil, err
	}
	expanded = dropSupersededTemplates(expanded)
	return filterEditionGated(expanded, profile), nil
}

// ResolveServeServices expands "all" to every template service (no honeypots).
func ResolveServeServices(requested []string, servicesDir string) ([]string, error) {
	return expandRequested(requested, servicesDir, false)
}

func expandRequested(requested []string, servicesDir string, includeHoneypots bool) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	templates, err := ListTemplateServices(servicesDir)
	if err != nil {
		return nil, err
	}

	needsAll := false
	for _, s := range requested {
		if strings.EqualFold(s, "all") {
			needsAll = true
			break
		}
	}

	seen := make(map[string]bool)
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}

	if needsAll {
		if includeHoneypots {
			for _, h := range StatefulServiceNames {
				add(h)
			}
		}
		for _, t := range templates {
			if includeHoneypots && templateSuperseded(t, seen) {
				continue
			}
			add(t)
		}
	}

	for _, s := range requested {
		if strings.EqualFold(s, "all") {
			continue
		}
		add(s)
	}
	return out, nil
}

func dropSupersededTemplates(names []string) []string {
	enabled := make(map[string]bool, len(names))
	for _, n := range names {
		enabled[n] = true
	}
	var out []string
	for _, n := range names {
		if templateSuperseded(n, enabled) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// templateSuperseded reports whether a replay template is replaced by an enabled honeypot.
func templateSuperseded(name string, enabled map[string]bool) bool {
	if isStatefulHoneypot(name) {
		return false
	}
	if sup, ok := templateSupersededBy[name]; ok && enabled[sup] {
		return true
	}
	// services/rdp template shares the "rdp" name with the stateful honeypot.
	return name == "rdp" && enabled["rdp"]
}

func isStatefulHoneypot(name string) bool {
	for _, h := range StatefulServiceNames {
		if h == name {
			return true
		}
	}
	return false
}

func filterEditionGated(names []string, profile *OSProfile) []string {
	smbOn139 := false
	if profile != nil {
		for _, n := range names {
			if n == "smb_honeypot" && EditionExposesPort(profile.ResolvedEdition(), 139) {
				smbOn139 = true
				break
			}
		}
	}
	var out []string
	for _, n := range names {
		if ShouldStartService(n, profile, smbOn139) {
			out = append(out, n)
		}
	}
	return out
}

// ShouldStartService applies os_edition port persona rules. The SMB honeypot
// subsumes the netbios template on 139 when it binds that port.
func ShouldStartService(name string, profile *OSProfile, smbHoneypotOn139 bool) bool {
	if name == "netbios" && smbHoneypotOn139 {
		return false
	}
	if profile == nil {
		return true
	}
	ed := profile.ResolvedEdition()
	switch name {
	case "ssh_honeypot":
		// SSH honeypot is a Linux persona; don't start it under a Windows/macOS
		// profile (a real Windows box doesn't run sshd by default — it'd be a tell).
		return strings.EqualFold(profile.Family, "linux")
	case "msrpc":
		return EditionExposesPort(ed, 135)
	case "netbios":
		return EditionExposesPort(ed, 139)
	case "smb_honeypot", "smb":
		return EditionExposesPort(ed, 445)
	case "wsd":
		return EditionExposesPort(ed, 5357)
	case "deliveryopt":
		return EditionExposesPort(ed, 7680)
	default:
		return true
	}
}