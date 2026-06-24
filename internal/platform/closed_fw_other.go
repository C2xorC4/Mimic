//go:build !windows

package platform

func EnsureClosedPortFirewallRules(ports []uint16) error { return nil }

func RemoveClosedPortFirewallRules(ports []uint16) {}

func EnsureUDPProbeFirewallRules(ports []uint16) error { return nil }

func RemoveUDPProbeFirewallRules(ports []uint16) {}

func EnsureICMPOutboundFirewallRule() error { return nil }

func RemoveICMPOutboundFirewallRule() {}