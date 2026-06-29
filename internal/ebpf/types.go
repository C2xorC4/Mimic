package ebpf

// OSProfileBPF is the BPF map representation of an OS profile
// Must match the struct os_profile in fingerprint.c exactly
type OSProfileBPF struct {
	// IP layer
	TTL          uint8
	DFBit        uint8
	IPIDBehavior uint8
	// EcnEcho: 1 = OS echoes ECE in the SYN-ACK (Linux/macOS â†’ nmap CC=Y) and keeps
	// its native ECN-probe options; 0 = clear ECE + force Windows-ordered ECN options
	// (Windows â†’ CC=N). Repurposes the former _pad1 byte (no struct-layout change).
	EcnEcho uint8

	// TCP layer
	WindowSize    uint16
	WindowScale   uint8
	TCPTimestamps uint8
	MSS           uint16
	SACKPermitted uint8
	ECNSupport    uint8

	// TCP options order (max 10 options, 0 = end)
	TCPOptionsOrder [10]uint8
	TCPOptionsCount uint8
	// WinQuirks: 1 = Windows profile â†’ apply Windows-only stack quirks (shared
	// IP-ID/SS=S, A=O RST ack, ICMP CD=Z). 0 (Linux/macOS) leaves the host's native
	// behavior. Repurposes the former _pad2 byte (no struct-layout change).
	WinQuirks uint8

	// RST behavior
	AckInRST uint8
	// EcnCC: 1 = reflect ECE on the ECN-probe SYN-ACK â†’ nmap CC=Y (Linux/macOS, and
	// Windows Server editions via explicit_congestion: echo); 0 = clear ECE â†’ CC=N
	// (Windows workstation). Repurposes the former _pad3 byte (no struct-layout change).
	EcnCC       uint8
	WindowInRST uint16

	// ICMP
	ICMPQuoteSize  uint8
	ICMPDFInQuote  uint8
	ICMPTTLInQuote uint8
	ICMPRateLimit  uint8

	// UDP
	UDPClosedPortResponse uint8
	// TsSlow: 1 = use 10ms TSval clock (-> nmap TS=7, Windows 6.x era: Vista/7/8/
	// Server 2008/2012). 0 = use 1ms TSval clock (-> TS=A, Windows 10+ era).
	// Linux/macOS unaffected. Repurposes the first byte of the former _pad4[3].
	TsSlow uint8
	_pad4  [2]uint8
}

// IPIDState maintains state for IP ID generation
// Must match C struct with explicit padding for alignment
type IPIDState struct {
	Counter    uint16
	_pad       uint16 // Padding to align RandomSeed to 4-byte boundary
	RandomSeed uint32
}

// TCP Option kinds
const (
	TCPOptEOL       = 0
	TCPOptNOP       = 1
	TCPOptMSS       = 2
	TCPOptWindow    = 3
	TCPOptSACKPerm  = 4
	TCPOptSACK      = 5
	TCPOptTimestamp = 8
)

// IP ID behaviors
const (
	IPIDIncremental = 0
	IPIDRandom      = 1
	IPIDZero        = 2
)

// ACK in RST behaviors
const (
	AckRSTZero      = 0
	AckRSTEchoed    = 1
	AckRSTIncrement = 2
)

// TCPOptionFromString converts a string option name to its kind value
func TCPOptionFromString(s string) uint8 {
	switch s {
	case "mss":
		return TCPOptMSS
	case "nop":
		return TCPOptNOP
	case "window_scale", "wscale":
		return TCPOptWindow
	case "sack_permitted", "sack_perm", "sack":
		return TCPOptSACKPerm
	case "timestamp", "timestamps":
		return TCPOptTimestamp
	case "eol":
		return TCPOptEOL
	default:
		return TCPOptNOP
	}
}

// IPIDBehaviorFromString converts a string to IP ID behavior constant
func IPIDBehaviorFromString(s string) uint8 {
	switch s {
	case "incremental", "inc":
		return IPIDIncremental
	case "random", "rand":
		return IPIDRandom
	case "zero", "0":
		return IPIDZero
	default:
		return IPIDIncremental
	}
}

// AckInRSTFromString converts a string to ACK in RST behavior constant
func AckInRSTFromString(s string) uint8 {
	switch s {
	case "zero", "0":
		return AckRSTZero
	case "echoed", "echo":
		return AckRSTEchoed
	case "incremented", "inc", "increment":
		return AckRSTIncrement
	default:
		return AckRSTZero
	}
}

