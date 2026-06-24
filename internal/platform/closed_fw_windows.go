//go:build windows

package platform

import (
	"fmt"
	"strconv"
	"strings"
)

const closedFWRulePrefix = "Mimic Closed RST "
const udpProbeFWRulePrefix = "Mimic UDP Probe "
const udpProbeFWRuleAny = "Mimic UDP Probe Any"
const icmpOutFWRuleName = "Mimic ICMP Out"

// EnsureClosedPortFirewallRules allows inbound SYNs to closed-port targets so
// WinDivert can answer with RST (otherwise Windows Firewall drops them as
// filtered before the driver sees the packet). Idempotent per port.
func EnsureClosedPortFirewallRules(ports []uint16) error {
	var errs []string
	for _, p := range ports {
		name := closedFWRulePrefix + strconv.Itoa(int(p))
		out, err := hiddenCmd("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+name,
			"dir=in",
			"action=allow",
			"protocol=TCP",
			"localport="+strconv.Itoa(int(p)),
			"enable=yes",
			"profile=any",
		).CombinedOutput()
		if err != nil {
			s := string(out)
			if strings.Contains(s, "already exists") || strings.Contains(s, "Object already exists") {
				continue
			}
			errs = append(errs, fmt.Sprintf("port %d: %s", p, strings.TrimSpace(s)))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("closed-port firewall rules: %s", strings.Join(errs, "; "))
	}
	return nil
}

// RemoveClosedPortFirewallRules deletes Mimic closed-port allow rules.
func RemoveClosedPortFirewallRules(ports []uint16) {
	for _, p := range ports {
		name := closedFWRulePrefix + strconv.Itoa(int(p))
		hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run() //nolint:errcheck
	}
}

// EnsureUDPProbeFirewallAnyInbound allows all inbound UDP so nmap U1 probes to random
// closed high ports reach WinDivert (U1 does not use only -PU listed ports).
func EnsureUDPProbeFirewallAnyInbound() error {
	out, err := hiddenCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+udpProbeFWRuleAny,
		"dir=in",
		"action=allow",
		"protocol=UDP",
		"enable=yes",
		"profile=any",
	).CombinedOutput()
	if err != nil {
		s := string(out)
		if strings.Contains(s, "already exists") || strings.Contains(s, "Object already exists") {
			return nil
		}
		return fmt.Errorf("udp-probe any rule: %s", strings.TrimSpace(s))
	}
	return nil
}

// RemoveUDPProbeFirewallAnyInbound deletes the catch-all UDP probe allow rule.
func RemoveUDPProbeFirewallAnyInbound() {
	hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+udpProbeFWRuleAny).Run() //nolint:errcheck
}

// EnsureUDPProbeFirewallRules allows inbound UDP to nmap U1 probe ports so WinDivert
// can answer with ICMP port-unreachable (otherwise Windows Firewall drops them first).
func EnsureUDPProbeFirewallRules(ports []uint16) error {
	var errs []string
	for _, p := range ports {
		name := udpProbeFWRulePrefix + strconv.Itoa(int(p))
		out, err := hiddenCmd("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+name,
			"dir=in",
			"action=allow",
			"protocol=UDP",
			"localport="+strconv.Itoa(int(p)),
			"enable=yes",
			"profile=any",
		).CombinedOutput()
		if err != nil {
			s := string(out)
			if strings.Contains(s, "already exists") || strings.Contains(s, "Object already exists") {
				continue
			}
			errs = append(errs, fmt.Sprintf("port %d: %s", p, strings.TrimSpace(s)))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("udp-probe firewall rules: %s", strings.Join(errs, "; "))
	}
	return nil
}

// RemoveUDPProbeFirewallRules deletes Mimic UDP probe allow rules.
func RemoveUDPProbeFirewallRules(ports []uint16) {
	for _, p := range ports {
		name := udpProbeFWRulePrefix + strconv.Itoa(int(p))
		hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run() //nolint:errcheck
	}
}

// EnsureICMPOutboundFirewallRule allows outbound ICMP (echo-reply + dest-unreachable for U1).
func EnsureICMPOutboundFirewallRule() error {
	out, err := hiddenCmd("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+icmpOutFWRuleName,
		"dir=out",
		"action=allow",
		"protocol=icmpv4:any,any",
		"enable=yes",
		"profile=any",
	).CombinedOutput()
	if err != nil {
		s := string(out)
		if strings.Contains(s, "already exists") || strings.Contains(s, "Object already exists") {
			return nil
		}
		return fmt.Errorf("icmp outbound rule: %s", strings.TrimSpace(s))
	}
	return nil
}

// RemoveICMPOutboundFirewallRule deletes the Mimic ICMP outbound allow rule.
func RemoveICMPOutboundFirewallRule() {
	hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+icmpOutFWRuleName).Run() //nolint:errcheck
}