package config

import (
	"github.com/c2xorc4/mimic/internal/deception"
	"github.com/c2xorc4/mimic/internal/defense"
	"github.com/c2xorc4/mimic/internal/events"
)

// OSProfile defines the TCP/IP stack characteristics for a specific OS
type OSProfile struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Family      string      `yaml:"family"` // windows, linux, macos
	Version     string      `yaml:"version"`
	Stack       StackConfig `yaml:"stack"`
	SMB         SMBConfig   `yaml:"smb"`
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
	ECNSupport         bool   `yaml:"ecn_support"`
	URGPointer         uint16 `yaml:"urg_pointer"`         // Value in URG responses
	AckInRST           string `yaml:"ack_in_rst"`          // zero, echoed, incremented
	WindowInRST        uint16 `yaml:"window_in_rst"`       // Window value in RST packets
	FINAckBehavior     string `yaml:"fin_ack_behavior"`    // Response to FIN on open port
	BogusFlags         string `yaml:"bogus_flags"`         // Response to invalid flag combos
	ExplicitCongestion string `yaml:"explicit_congestion"` // ECN flag handling

	// ICMP
	ICMPQuoteSize   uint8 `yaml:"icmp_quote_size"`   // Bytes quoted in ICMP errors
	ICMPDFInQuote   bool  `yaml:"icmp_df_in_quote"`  // Preserve DF in quoted header
	ICMPTTLInQuote  uint8 `yaml:"icmp_ttl_in_quote"` // TTL value in quoted header
	ICMPRateLimit   bool  `yaml:"icmp_rate_limit"`   // Rate limit ICMP errors
	ICMPChecksumBad bool  `yaml:"icmp_checksum_bad"` // Some old OS had bugs

	// UDP
	UDPClosedPortResponse bool `yaml:"udp_closed_port_response"` // Send ICMP port unreach
}

// ServiceConfig defines a fake service listener
type ServiceConfig struct {
	Name     string `yaml:"name"`
	Port     uint16 `yaml:"port"`
	Protocol string `yaml:"protocol"` // tcp, udp
	Stateful bool   `yaml:"stateful"`
	// SpeaksFirst marks a server-speaks-first protocol (SSH, SMTP, FTP banner):
	// the listener sends the connect-banner response (the probe matching an empty
	// buffer, after `requires` gating) immediately on connect, before reading.
	SpeaksFirst bool          `yaml:"speaks_first"`
	Probes      []ProbeConfig `yaml:"probes"`
}

// ProbeConfig defines how to match and respond to a specific probe
type ProbeConfig struct {
	Name         string          `yaml:"name"`
	Signature    SignatureConfig `yaml:"signature"`
	ResponseFile string          `yaml:"response_file"`
	RewriteRules []RewriteRule   `yaml:"rewrite_rules"`
	// Requires is an optional set of option key=value conditions that must be
	// satisfied for this probe to be active. If a key is absent from options the
	// condition is ignored (probe is included). Use to gate protocol-version-specific
	// probes on the active OS profile (e.g. smb1_enabled: "true").
	Requires map[string]string `yaml:"requires,omitempty"`
}

// SignatureConfig defines how to identify an incoming probe
type SignatureConfig struct {
	Pattern   string `yaml:"pattern"`    // Hex/wildcard pattern matched at Offset (prefix)
	Contains  string `yaml:"contains"`   // Match if data contains these bytes anywhere (\xNN ok); ignores Offset
	Offset    int    `yaml:"offset"`     // Byte offset to start matching
	MinLength int    `yaml:"min_length"` // Minimum packet length
	MaxLength int    `yaml:"max_length"` // Maximum packet length
	TCPFlags  string `yaml:"tcp_flags"`  // Required TCP flags
}

// RewriteRule defines how to modify a field in the response
type RewriteRule struct {
	Offset int    `yaml:"offset"`
	Length int    `yaml:"length"`
	Type   string `yaml:"type"`  // timestamp, guid, seq, ip, port, random, leak
	Token  string `yaml:"token"` // for type=leak: the credential id to emit at Offset
}

// SMBConfig defines protocol-level SMB behavior for an OS profile
type SMBConfig struct {
	Dialect         string `yaml:"dialect"`          // "1.0", "2.0", "2.1", "3.0", "3.0.2", "3.1.1"
	SMB1Enabled     bool   `yaml:"smb1_enabled"`     // false on Win10 1709+ / Server 2019+
	SigningRequired bool   `yaml:"signing_required"` // true on domain controllers
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

// SMBCredential is a seeded fake account that authenticates successfully against
// the SMB honeypot. Other emulated services can "leak" these so an attacker who
// "discovers" them can use them against SMB.
type SMBCredential struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Domain   string `yaml:"domain"` // optional
}

// SMBHoneypotConfig contains deployment-level settings for the stateful SMB
// honeypot (distinct from the OS-fingerprint properties carried by the profile).
type SMBHoneypotConfig struct {
	// AllowGuestEnum controls whether guest/null sessions may enumerate shares.
	// Pointer so an unset value can default to true (engagement) rather than false.
	AllowGuestEnum *bool `yaml:"allow_guest_enum"`

	// Credentials is the legacy inline list of accounts that authenticate against
	// the honeypot. Prefer the top-level shared pool referenced by AcceptCredentials;
	// this is retained for backward compatibility and merged with the pool.
	Credentials []SMBCredential `yaml:"credentials"`

	// AcceptCredentials lists ids from the top-level Credentials pool that should
	// authenticate against this honeypot. Empty means "all pool credentials".
	AcceptCredentials []string `yaml:"accept_credentials"`

	// Filesystem is the config-driven share/VFS definition. When nil, the built-in
	// default Windows-like tree is used.
	Filesystem *deception.TreeConfig `yaml:"filesystem"`
}

// FtpHoneypotConfig configures the stateful FTP honeypot. Its Filesystem reuses
// the protocol-neutral deception tree; when nil it falls back to the SMB
// honeypot's filesystem (so one definition can drive both services).
type FtpHoneypotConfig struct {
	AllowAnonymous    *bool                 `yaml:"allow_anonymous"`    // nil => default allow
	AcceptCredentials []string              `yaml:"accept_credentials"` // pool ids; empty => all
	RootShare         string                `yaml:"root_share"`         // tree root exposed as FTP root; default C$
	Filesystem        *deception.TreeConfig `yaml:"filesystem"`         // nil => reuse smb_honeypot.filesystem
}

// CredentialDef is one account in the shared, top-level credential pool. The same
// credential can authenticate against a honeypot and be "leaked" by another
// service (see CredentialLeaks), keeping the planted and accepted values in sync.
type CredentialDef struct {
	ID       string `yaml:"id"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Domain   string `yaml:"domain"`
}

// LeakDef wires a pool credential to a service that surfaces it. It validates the
// intended leak path and lets the orchestrator inject the credential store only
// into the services that need it; the actual emission point is a {{leak:<id>}}
// placeholder (text) or a type=leak rewrite rule (binary) in that service.
type LeakDef struct {
	Cred     string `yaml:"cred"`     // CredentialDef.ID to leak
	Via      string `yaml:"via"`      // service name that surfaces it
	Location string `yaml:"location"` // body | header | banner | file (informational)
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
	Profile        string            `yaml:"profile"`         // Active OS profile name
	Interface      string            `yaml:"interface"`       // Network interface to attach to
	Services       []string          `yaml:"services"`        // Enabled service emulators
	ClosedPorts    []uint16          `yaml:"closed_ports"`    // Ports that appear closed (RST on connect)
	ServiceOptions ServiceOptions    `yaml:"service_options"` // Per-service configuration
	SMBHoneypot    SMBHoneypotConfig `yaml:"smb_honeypot"`    // Stateful SMB honeypot settings
	FtpHoneypot    FtpHoneypotConfig `yaml:"ftp_honeypot"`    // Stateful FTP honeypot settings
	Logging        LogConfig         `yaml:"logging"`         // Logging configuration
	Events         events.Config     `yaml:"events"`          // SIEM-ingestible security-event pipeline
	Defense        defense.Config    `yaml:"defense"`         // abuse detection + active response (alert-only by default)
	ProfilesDir    string            `yaml:"profiles_dir"`    // Path to profiles directory
	ServicesDir    string            `yaml:"services_dir"`    // Path to services directory

	// Credentials is the shared, protocol-neutral pool of fake accounts. Honeypots
	// reference these by id (e.g. SMBHoneypot.AcceptCredentials) and services leak
	// them (CredentialLeaks), keeping planted and accepted values in sync.
	Credentials     []CredentialDef `yaml:"credentials"`
	CredentialLeaks []LeakDef       `yaml:"credential_leaks"`

	// Deprecated: Use Logging.LogDir instead
	ProbeLogFile string `yaml:"probe_log_file"` // Legacy: Path to log unmatched probes
	LogLevel     string `yaml:"log_level"`      // Legacy: Use Logging.Level instead
}
