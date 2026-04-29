package config

// OSProfile defines the TCP/IP stack characteristics for a specific OS
type OSProfile struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Family      string      `yaml:"family"` // windows, linux, macos
	Version     string      `yaml:"version"`
	Stack       StackConfig `yaml:"stack"`
}

// StackConfig contains all TCP/IP stack fingerprint parameters
type StackConfig struct {
	// IP Layer
	TTL          uint8  `yaml:"ttl"`
	DFBit        bool   `yaml:"df_bit"`
	IPIDBehavior string `yaml:"ip_id_behavior"` // incremental, random, zero

	// TCP Layer
	WindowSize      uint16   `yaml:"window_size"`
	WindowScale     uint8    `yaml:"window_scale"`
	MSS             uint16   `yaml:"mss"`
	TCPTimestamps   bool     `yaml:"tcp_timestamps"`
	SACKPermitted   bool     `yaml:"sack_permitted"`
	TCPOptionsOrder []string `yaml:"tcp_options_order"`

	// TCP Quirks (for nmap OPS/WIN/ECN tests)
	ECNSupport        bool   `yaml:"ecn_support"`
	URGPointer        uint16 `yaml:"urg_pointer"`         // Value in URG responses
	AckInRST          string `yaml:"ack_in_rst"`          // zero, echoed, incremented
	WindowInRST       uint16 `yaml:"window_in_rst"`       // Window value in RST packets
	FINAckBehavior    string `yaml:"fin_ack_behavior"`    // Response to FIN on open port
	BogusFlags        string `yaml:"bogus_flags"`         // Response to invalid flag combos
	ExplicitCongestion string `yaml:"explicit_congestion"` // ECN flag handling

	// ICMP
	ICMPQuoteSize    uint8 `yaml:"icmp_quote_size"`    // Bytes quoted in ICMP errors
	ICMPDFInQuote    bool  `yaml:"icmp_df_in_quote"`   // Preserve DF in quoted header
	ICMPTTLInQuote   uint8 `yaml:"icmp_ttl_in_quote"`  // TTL value in quoted header
	ICMPRateLimit    bool  `yaml:"icmp_rate_limit"`    // Rate limit ICMP errors
	ICMPChecksumBad  bool  `yaml:"icmp_checksum_bad"`  // Some old OS had bugs

	// UDP
	UDPClosedPortResponse bool `yaml:"udp_closed_port_response"` // Send ICMP port unreach
}

// ServiceConfig defines a fake service listener
type ServiceConfig struct {
	Name      string          `yaml:"name"`
	Port      uint16          `yaml:"port"`
	Protocol  string          `yaml:"protocol"` // tcp, udp
	Stateful  bool            `yaml:"stateful"`
	Probes    []ProbeConfig   `yaml:"probes"`
}

// ProbeConfig defines how to match and respond to a specific probe
type ProbeConfig struct {
	Name         string            `yaml:"name"`
	Signature    SignatureConfig   `yaml:"signature"`
	ResponseFile string            `yaml:"response_file"`
	RewriteRules []RewriteRule     `yaml:"rewrite_rules"`
}

// SignatureConfig defines how to identify an incoming probe
type SignatureConfig struct {
	Pattern    string `yaml:"pattern"`     // Regex pattern
	Offset     int    `yaml:"offset"`      // Byte offset to start matching
	MinLength  int    `yaml:"min_length"`  // Minimum packet length
	MaxLength  int    `yaml:"max_length"`  // Maximum packet length
	TCPFlags   string `yaml:"tcp_flags"`   // Required TCP flags
}

// RewriteRule defines how to modify a field in the response
type RewriteRule struct {
	Offset int    `yaml:"offset"`
	Length int    `yaml:"length"`
	Type   string `yaml:"type"` // timestamp, guid, seq, ip, port, random
}

// ServiceOptions contains per-service configuration options
type ServiceOptions struct {
	NetBIOSName string `yaml:"netbios_name"` // Computer name for NetBIOS responses
	Hostname    string `yaml:"hostname"`     // Hostname for various services
	Domain      string `yaml:"domain"`       // Domain/workgroup name
	ServerGUID  string `yaml:"server_guid"`  // Fixed GUID (random if empty)
	MACAddress  string `yaml:"mac_address"`  // MAC address for NBNS responses (format: aa:bb:cc:dd:ee:ff)

	// Response timing jitter (milliseconds)
	JitterMinMs int `yaml:"jitter_min_ms"` // Minimum response delay (0 = no jitter)
	JitterMaxMs int `yaml:"jitter_max_ms"` // Maximum response delay
}

// LogConfig contains logging configuration
type LogConfig struct {
	Level    string `yaml:"level"`     // debug, info, warn, error
	LogDir   string `yaml:"log_dir"`   // Directory for log files (default: /var/log/mimic)
	JSONMode bool   `yaml:"json_mode"` // Use JSON format for log entries
	ToStdout bool   `yaml:"to_stdout"` // Also log to stdout
}

// AppConfig is the main application configuration
type AppConfig struct {
	Profile        string         `yaml:"profile"`          // Active OS profile name
	Interface      string         `yaml:"interface"`        // Network interface to attach to
	Services       []string       `yaml:"services"`         // Enabled service emulators
	ClosedPorts    []uint16       `yaml:"closed_ports"`     // Ports that appear closed (RST on connect)
	ServiceOptions ServiceOptions `yaml:"service_options"`  // Per-service configuration
	Logging        LogConfig      `yaml:"logging"`          // Logging configuration
	ProfilesDir    string         `yaml:"profiles_dir"`     // Path to profiles directory
	ServicesDir    string         `yaml:"services_dir"`     // Path to services directory

	// Deprecated: Use Logging.LogDir instead
	ProbeLogFile string `yaml:"probe_log_file"` // Legacy: Path to log unmatched probes
	LogLevel     string `yaml:"log_level"`      // Legacy: Use Logging.Level instead
}
