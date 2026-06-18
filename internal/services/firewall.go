package services

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"github.com/c2xorc4/mimic/internal/logging"
)

// FirewallManager installs a default-drop policy for inbound TCP so the host
// presents like a firewalled Windows client: only allow-listed ports answer and
// every other port is silently DROPPED (nmap "filtered") rather than RST. This
// closes the OSE-2026-001 tell where the Mimic host RST'd all closed ports
// (Linux default) while a real firewalled Win11 client (Op-1) dropped them.
//
// Safety: established/related connections are accepted FIRST, so the live
// control SSH session is never severed when the policy is applied. New
// management logins survive only if their port is in the preserve list — hence
// PreservePorts MUST carry the SSH/management port under drop mode.
//
// Rules are added to the shared mimic_reject table AFTER the T2/T3 probe and
// per-port closed rules, so those terminal RST rules still match first and the
// default-drop catches only the remainder.
type FirewallManager struct {
	active bool
	mu     sync.Mutex
	log    *logging.Logger
}

// NewFirewallManager creates a default-drop firewall manager.
func NewFirewallManager() *FirewallManager {
	return &FirewallManager{log: logging.Component("firewall")}
}

// EnableDrop installs the default-drop ruleset. openPorts are answered normally
// (real service + decoy ports); preservePorts are always accepted (management).
func (f *FirewallManager) EnableDrop(openPorts, preservePorts []uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := nftEnsureTable(); err != nil {
		f.log.Warn("Default-drop firewall requires netfilter kernel support", map[string]interface{}{
			"error": err.Error(),
			"hint":  "Load nf_tables and nft_reject_inet kernel modules",
		})
		return err
	}

	// 1. Accept established/related FIRST so the live control session survives.
	if err := nftAddRule("ct", "state", "established,related", "accept"); err != nil {
		return fmt.Errorf("firewall established-accept: %w", err)
	}

	// 2. Accept the allow-listed + preserved TCP ports.
	allow := mergePorts(openPorts, preservePorts)
	if len(allow) > 0 {
		if err := nftAddRule("tcp", "dport", portSetExpr(allow), "accept"); err != nil {
			return fmt.Errorf("firewall allow-list: %w", err)
		}
	}
	if len(preservePorts) == 0 {
		f.log.Warn("Default-drop firewall has no preserve_ports set — new management/SSH logins will be dropped (the current session survives via established-accept). Add the SSH port to firewall.preserve_ports.", nil)
	}

	// 3. Drop all remaining inbound TCP (default-drop = nmap "filtered").
	if err := nftAddRule("meta", "l4proto", "tcp", "drop"); err != nil {
		return fmt.Errorf("firewall default-drop: %w", err)
	}

	f.active = true
	f.log.Info("Default-drop firewall active (firewalled-Windows persona)", map[string]interface{}{
		"open_ports":     openPorts,
		"preserve_ports": preservePorts,
	})
	return nil
}

// Stop removes the firewall rules (via shared-table deletion).
func (f *FirewallManager) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.active {
		nftDeleteTable()
		f.active = false
	}
}

// nftAddRule appends one rule to the mimic_reject input chain.
func nftAddRule(ruleArgs ...string) error {
	args := append([]string{"nft", "add", "rule", "inet", "mimic_reject", "input"}, ruleArgs...)
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", args, out)
	}
	return nil
}

// mergePorts returns the sorted, de-duplicated union of two port lists.
func mergePorts(a, b []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(a)+len(b))
	for _, p := range a {
		seen[p] = struct{}{}
	}
	for _, p := range b {
		seen[p] = struct{}{}
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// portSetExpr renders ports as an nftables anonymous set, e.g. "{ 80, 443, 2222 }".
func portSetExpr(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}
