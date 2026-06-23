package netfilter

// PersonaFirewall installs the closed-port disposition that makes a host present
// like a firewalled client: unserved ports read as FILTERED (silently dropped),
// not RST/closed. It is the Windows analogue of the Linux nft default-drop in
// internal/services (FirewallManager). NewPersonaFirewall returns a platform
// implementation, or nil where none applies (Linux uses the nft path directly;
// other platforms have none).
type PersonaFirewall interface {
	// EnableDrop silently drops NEW inbound connections to any TCP port not in
	// openPorts∪preservePorts, so those ports appear filtered. Established
	// connections and the host's own outbound client traffic are unaffected
	// (only bare SYN to blocked ports is dropped). preservePorts MUST include the
	// management port (e.g. WinRM 5985) or new management logins are lost.
	EnableDrop(openPorts, preservePorts []uint16) error
	// EnableICMPDrop drops inbound echo-requests (a firewalled client doesn't pong).
	EnableICMPDrop() error
	// Stop removes the persona (closes the drop handles; traffic flows normally).
	Stop()
}
