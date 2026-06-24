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

// ClosedPortResponder makes configured TCP ports answer probes with RST (closed),
// which nmap -O requires alongside at least one open port. Linux uses nftables;
// Windows uses WinDivert RST injection.
type ClosedPortResponder interface {
	// AddPorts installs RST responders for ports. ttl is the IP TTL on outbound
	// RST packets (profile stack TTL; 0 → 64).
	AddPorts(ports []uint16, ttl uint8, linuxPersona bool) error
	Stop()
}

// NewClosedPortResponder returns a platform closed-port responder, or nil where
// none applies (Linux uses the services.ClosedPortManager nft path directly).
func NewClosedPortResponder() ClosedPortResponder {
	return newClosedPortResponder()
}

// ProbeResponder answers inbound nmap T-series OS-fingerprint probes with RST.
// Linux uses nftables (services.ProbeResponseManager for Windows T2/T3 only);
// Windows uses WinDivert for Linux-persona T4/T6/T7 on scoped ports.
type ProbeResponder interface {
	// Start installs probe interceptors. ports scopes T4/T6 (closed + service);
	// t7Ports scopes T7 (closed only — nmap sends FIN probes to a closed TCP port).
	Start(ports []uint16, t7Ports []uint16, ttl uint8, window uint16, ackZero bool) error
	Stop()
}

// NewProbeResponder returns a platform T-probe responder, or nil where none applies.
func NewProbeResponder() ProbeResponder {
	return newProbeResponder()
}

// ICMPResponder answers inbound ICMP echo (IE) and UDP-closed (U1) OS-fingerprint
// probes with Linux-shaped replies on Windows-hosted Linux personas.
type ICMPResponder interface {
	// udpClosedPorts is the ALLOW-LIST of closed UDP ports the persona answers with
	// an ICMP port-unreachable (U1). Only inbound UDP to these specific ports is
	// captured; all other inbound UDP (DNS replies, QUIC, app traffic) flows
	// untouched. An empty list disables U1 capture entirely. (Previously this was an
	// EXCLUDE list applied to "all inbound UDP", which blackholed every UDP packet
	// not bound for a served port — killing host connectivity.)
	Start(ttl, quoteSize, quoteTTL uint8, quoteDF bool, udpClosedPorts []uint16) error
	Stop()
}

// NewICMPResponder returns a platform ICMP responder, or nil where none applies.
func NewICMPResponder() ICMPResponder {
	return newICMPResponder()
}
