//go:build !windows

package netfilter

// NewPersonaFirewall has no non-Windows implementation: Linux installs the
// firewalled-client persona through the nftables path (internal/services
// FirewallManager), gated by Supported(); other platforms have none.
func NewPersonaFirewall() PersonaFirewall { return nil }
