package services

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/deception"
)

// Responder handles loading and rewriting response templates
type Responder struct {
	baseDir   string
	cache     map[string][]byte
	options   map[string]string
	mu        sync.RWMutex
	bootTime  time.Time            // fixed fake boot time for this run (used by timestamp_past)
	credStore *deception.CredStore // shared pool for credential-leak emission (nil = disabled)
}

// SetCredStore injects the shared credential store used to resolve {{leak:<id>}}
// placeholders (text responses) and type=leak rewrite rules (binary slots).
func (r *Responder) SetCredStore(s *deception.CredStore) { r.credStore = s }

// leakPlaceholder matches {{leak:<id>}} in a (text) response template.
var leakPlaceholder = regexp.MustCompile(`\{\{leak:([A-Za-z0-9_-]+)\}\}`)

// applyLeak substitutes {{leak:<id>}} placeholders with "username:password" from
// the credential store. It is length-changing, so callers must run it BEFORE any
// fixed-offset rewrite rules — only use it on text responses (HTTP body, banners),
// never on length-prefixed binary templates.
func (r *Responder) applyLeak(response []byte) []byte {
	if r.credStore == nil || !strings.Contains(string(response), "{{leak:") {
		return response
	}
	out := leakPlaceholder.ReplaceAllStringFunc(string(response), func(m string) string {
		sub := leakPlaceholder.FindStringSubmatch(m)
		if ls, ok := r.credStore.LeakString(sub[1]); ok {
			return ls
		}
		return m // unknown id: leave placeholder untouched
	})
	return []byte(out)
}

// NewResponder creates a new responder
func NewResponder(baseDir string) (*Responder, error) {
	return NewResponderWithOptions(baseDir, nil)
}

// NewResponderWithOptions creates a new responder with custom options
func NewResponderWithOptions(baseDir string, options map[string]string) (*Responder, error) {
	if options == nil {
		options = make(map[string]string)
	}
	return &Responder{
		baseDir:  baseDir,
		cache:    make(map[string][]byte),
		options:  options,
		bootTime: fakeBootTime(),
	}, nil
}

// fakeBootTime returns a plausible fake boot time: 2–26 hours before now.
// Fixed per Responder instance so all responses report the same start_date.
func fakeBootTime() time.Time {
	ns := time.Now().UnixNano()
	hours := 2 + (ns>>32)%24
	minutes := (ns >> 16) % 60
	return time.Now().Add(-time.Duration(hours)*time.Hour - time.Duration(minutes)*time.Minute)
}

// GetResponse loads a response template and applies rewrite rules
func (r *Responder) GetResponse(filename string, originalProbe []byte, rules []config.RewriteRule) ([]byte, error) {
	// Load template
	template, err := r.loadTemplate(filename)
	if err != nil {
		return nil, err
	}

	// Make a copy to modify
	response := make([]byte, len(template))
	copy(response, template)

	// Credential-leak substitution (text responses). Length-changing, so it runs
	// before any fixed-offset rewrite rules.
	response = r.applyLeak(response)

	// Apply rewrite rules
	for _, rule := range rules {
		if err := r.applyRule(response, originalProbe, &rule); err != nil {
			return nil, fmt.Errorf("applying rule at offset %d: %w", rule.Offset, err)
		}
	}

	return response, nil
}

func (r *Responder) loadTemplate(filename string) ([]byte, error) {
	r.mu.RLock()
	if data, ok := r.cache[filename]; ok {
		r.mu.RUnlock()
		return data, nil
	}
	r.mu.RUnlock()

	path := filepath.Join(r.baseDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading template %s: %w", path, err)
	}

	r.mu.Lock()
	r.cache[filename] = data
	r.mu.Unlock()

	return data, nil
}

func (r *Responder) applyRule(response, probe []byte, rule *config.RewriteRule) error {
	if rule.Offset < 0 || rule.Offset >= len(response) {
		return fmt.Errorf("offset %d out of bounds (len=%d)", rule.Offset, len(response))
	}

	end := rule.Offset + rule.Length
	if end > len(response) {
		return fmt.Errorf("offset+length exceeds response size")
	}

	switch rule.Type {
	case "timestamp":
		// Write current timestamp as Windows FILETIME (100ns intervals since 1601)
		if rule.Length < 8 {
			return fmt.Errorf("timestamp requires 8 bytes")
		}
		// Convert Unix time to Windows FILETIME
		now := time.Now()
		// Unix epoch to Windows epoch difference in 100ns intervals
		const epochDiff = 116444736000000000
		filetime := uint64(now.UnixNano()/100) + epochDiff
		binary.LittleEndian.PutUint64(response[rule.Offset:], filetime)

	case "timestamp_past":
		// Write fake boot time as Windows FILETIME — same value for all responses in this run
		if rule.Length < 8 {
			return fmt.Errorf("timestamp_past requires 8 bytes")
		}
		const epochDiff = 116444736000000000
		filetime := uint64(r.bootTime.UnixNano()/100) + epochDiff
		binary.LittleEndian.PutUint64(response[rule.Offset:], filetime)

	case "timestamp_unix":
		// Write current Unix timestamp
		if rule.Length >= 8 {
			binary.LittleEndian.PutUint64(response[rule.Offset:], uint64(time.Now().Unix()))
		} else if rule.Length >= 4 {
			binary.LittleEndian.PutUint32(response[rule.Offset:], uint32(time.Now().Unix()))
		}

	case "guid":
		// Generate a random GUID
		if rule.Length < 16 {
			return fmt.Errorf("GUID requires 16 bytes")
		}
		guid := generateGUID()
		copy(response[rule.Offset:], guid[:])

	case "random":
		// Fill with cryptographically-random bytes (salts, challenges, nonces).
		// Must be true random, not time-derived — a time-derived value leaves the
		// high bytes near-constant across connections (a replay/predictability tell).
		if _, err := cryptorand.Read(response[rule.Offset : rule.Offset+rule.Length]); err != nil {
			return fmt.Errorf("random rewrite: %w", err)
		}

	case "seq":
		// Copy sequence number from probe (TCP seq handling)
		// This requires knowing where in the probe the seq is
		// For now, this is a placeholder for protocol-specific handling

	case "ip":
		// IP address rewriting - placeholder for future implementation

	case "port":
		// Port rewriting - placeholder for future implementation

	case "echo":
		// Echo bytes from probe at same offset
		if rule.Offset+rule.Length <= len(probe) {
			copy(response[rule.Offset:end], probe[rule.Offset:rule.Offset+rule.Length])
		}

	case "netbios_name":
		// Write NetBIOS-encoded computer name from options
		name := r.options["netbios_name"]
		if name == "" {
			name = "WORKSTATION" // Default
		}
		encoded := encodeNetBIOSName(name, rule.Length)
		copy(response[rule.Offset:end], encoded)

	case "hostname":
		// Write hostname from options
		name := r.options["hostname"]
		if name == "" {
			name = r.options["netbios_name"]
		}
		if name == "" {
			name = "workstation"
		}
		// Pad or truncate to fit
		nameBytes := []byte(name)
		if len(nameBytes) > rule.Length {
			nameBytes = nameBytes[:rule.Length]
		}
		copy(response[rule.Offset:end], nameBytes)

	case "domain":
		// Write domain/workgroup name from options
		domain := r.options["domain"]
		if domain == "" {
			domain = "WORKGROUP"
		}
		domainBytes := []byte(domain)
		if len(domainBytes) > rule.Length {
			domainBytes = domainBytes[:rule.Length]
		}
		copy(response[rule.Offset:end], domainBytes)

	case "mac_address":
		// Write MAC address from options (format: aa:bb:cc:dd:ee:ff or aabbccddeeff)
		mac := r.options["mac_address"]
		if mac == "" {
			// Generate a random MAC with local admin bit set
			mac = generateRandomMAC()
		}
		macBytes := parseMAC(mac)
		if len(macBytes) == 6 && rule.Length >= 6 {
			copy(response[rule.Offset:], macBytes)
		}

	case "nbns_name":
		// Write NetBIOS name (16 bytes: 15 char name + suffix, space-padded)
		name := r.options["netbios_name"]
		if name == "" {
			name = "WORKSTATION"
		}
		nameBytes := formatNetBIOSName(name, 0x00) // 0x00 = workstation suffix
		if rule.Length >= 16 {
			copy(response[rule.Offset:], nameBytes[:16])
		}

	case "nbns_domain":
		// Write NetBIOS domain/workgroup name (16 bytes with 0x00 suffix)
		domain := r.options["domain"]
		if domain == "" {
			domain = "WORKGROUP"
		}
		domainBytes := formatNetBIOSName(domain, 0x00)
		if rule.Length >= 16 {
			copy(response[rule.Offset:], domainBytes[:16])
		}

	case "http_date":
		// Overwrite the value of the HTTP Date header with the current time
		// (RFC1123/GMT, fixed 29 bytes). Search-based, so Offset/Length are
		// ignored — works regardless of where Date sits in the response.
		now := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05") + " GMT" // 29 chars
		if idx := bytes.Index(response, []byte("Date: ")); idx >= 0 && idx+6+len(now) <= len(response) {
			copy(response[idx+6:idx+6+len(now)], now)
		}
		return nil

	case "dcerpc_callid":
		// Echo the probe's DCE/RPC call_id into EVERY fragment header of the
		// response, so a multi-fragment reply (e.g. a captured ept_lookup whose
		// response spans many 4280-byte PDUs) correlates to the client's request
		// regardless of which call_id the client chose. Walks the buffer as a
		// sequence of connection-oriented PDUs (ver 5; frag_len at +8 LE; call_id
		// at +12) — Offset/Length are ignored. No-op if the probe is too short.
		if len(probe) < 16 || probe[0] != 0x05 {
			return nil
		}
		callID := probe[12:16]
		for i := 0; i+16 <= len(response); {
			if response[i] != 0x05 { // not a CO RPC PDU boundary — stop walking
				break
			}
			fragLen := int(response[i+8]) | int(response[i+9])<<8
			if fragLen < 16 || i+fragLen > len(response) {
				break
			}
			copy(response[i+12:i+16], callID)
			i += fragLen
		}

	case "host_ip":
		// Replace every 4-byte occurrence of the captured server IP (rule.Token,
		// dotted-quad) with this host's egress IPv4, so replayed EPM towers
		// (ncacn_ip_tcp floors) advertise the running host's address instead of the
		// capture box's — otherwise the bindings point at a foreign/dead host, a
		// tell and a broken deception. Fixed-length (4→4), so offsets are preserved.
		capIP := parseIPv4(rule.Token)
		if capIP == nil {
			return fmt.Errorf("host_ip: bad token IP %q", rule.Token)
		}
		host := hostEgressIPv4()
		if host == nil {
			return nil // can't determine host IP — leave capture IP rather than corrupt
		}
		for i := 0; i+4 <= len(response); i++ {
			if bytes.Equal(response[i:i+4], capIP) {
				copy(response[i:i+4], host)
			}
		}

	case "leak":
		// Write "username:password" for the credential id (rule.Token) into a
		// fixed-width binary slot. Truncated to rule.Length; remaining slot bytes
		// are zeroed. For text responses prefer the {{leak:<id>}} placeholder.
		if r.credStore == nil {
			return nil
		}
		ls, ok := r.credStore.LeakString(rule.Token)
		if !ok {
			return fmt.Errorf("leak: unknown credential id %q", rule.Token)
		}
		b := []byte(ls)
		if len(b) > rule.Length {
			b = b[:rule.Length]
		}
		for i := rule.Offset; i < end; i++ {
			response[i] = 0
		}
		copy(response[rule.Offset:end], b)

	default:
		return fmt.Errorf("unknown rewrite type: %s", rule.Type)
	}

	return nil
}

// ClearCache clears the response template cache
func (r *Responder) ClearCache() {
	r.mu.Lock()
	r.cache = make(map[string][]byte)
	r.mu.Unlock()
}

// parseIPv4 parses a dotted-quad into 4 network-order bytes, or nil if invalid.
func parseIPv4(s string) []byte {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return []byte{v4[0], v4[1], v4[2], v4[3]}
	}
	return nil
}

// hostEgressIPv4 returns this host's primary outbound IPv4 (the source the kernel
// picks for the default route), cached for the process. Falls back to the first
// non-loopback/non-link-local IPv4 interface address. Returns nil if none found.
var (
	egressIPOnce sync.Once
	egressIPv4   []byte
)

func hostEgressIPv4() []byte {
	egressIPOnce.Do(func() {
		// UDP "dial" performs no handshake; it just makes the kernel select a
		// source address per its routing table. TEST-NET-1 dest keeps it inert.
		if c, err := net.Dial("udp", "192.0.2.1:9"); err == nil {
			if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
				if v4 := ua.IP.To4(); v4 != nil {
					egressIPv4 = []byte{v4[0], v4[1], v4[2], v4[3]}
				}
			}
			c.Close()
		}
		if egressIPv4 == nil {
			addrs, _ := net.InterfaceAddrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					v4 := ipn.IP.To4()
					if v4 != nil && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
						egressIPv4 = []byte{v4[0], v4[1], v4[2], v4[3]}
						break
					}
				}
			}
		}
	})
	return egressIPv4
}

// generateGUID generates a random GUID
func generateGUID() [16]byte {
	var guid [16]byte
	now := time.Now().UnixNano()
	for i := 0; i < 16; i++ {
		guid[i] = byte(now >> (i * 4))
		now = now*1103515245 + 12345
	}
	// Set version (4) and variant bits
	guid[6] = (guid[6] & 0x0f) | 0x40
	guid[8] = (guid[8] & 0x3f) | 0x80
	return guid
}

// encodeNetBIOSName encodes a name using NetBIOS first-level encoding
// NetBIOS names are 16 bytes: 15 chars + 1 suffix byte, encoded to 32 bytes
func encodeNetBIOSName(name string, maxLen int) []byte {
	// Uppercase and pad to 15 chars
	nameBytes := make([]byte, 16)
	for i := 0; i < 15; i++ {
		if i < len(name) {
			nameBytes[i] = byte(name[i])
			// Uppercase ASCII letters
			if nameBytes[i] >= 'a' && nameBytes[i] <= 'z' {
				nameBytes[i] -= 32
			}
		} else {
			nameBytes[i] = ' ' // Pad with spaces
		}
	}
	nameBytes[15] = 0x00 // Suffix: 0x00 = workstation

	// First-level encoding: each byte becomes two bytes (nibbles + 'A')
	encoded := make([]byte, 32)
	for i := 0; i < 16; i++ {
		encoded[i*2] = 'A' + (nameBytes[i] >> 4)
		encoded[i*2+1] = 'A' + (nameBytes[i] & 0x0F)
	}

	if maxLen > 0 && len(encoded) > maxLen {
		return encoded[:maxLen]
	}
	return encoded
}

// formatNetBIOSName creates a 16-byte NetBIOS name (15 chars + suffix, space-padded)
func formatNetBIOSName(name string, suffix byte) []byte {
	result := make([]byte, 16)
	// Fill with spaces
	for i := range result {
		result[i] = ' '
	}
	// Copy name (uppercase)
	for i := 0; i < 15 && i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		result[i] = c
	}
	result[15] = suffix
	return result
}

// parseMAC parses a MAC address string (aa:bb:cc:dd:ee:ff or aabbccddeeff)
func parseMAC(mac string) []byte {
	// Remove colons, dashes, dots
	clean := strings.ReplaceAll(mac, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ".", "")

	if len(clean) != 12 {
		return nil
	}

	result, err := hex.DecodeString(clean)
	if err != nil {
		return nil
	}
	return result
}

// generateRandomMAC generates a random locally-administered MAC address
func generateRandomMAC() string {
	now := time.Now().UnixNano()
	mac := make([]byte, 6)
	for i := 0; i < 6; i++ {
		mac[i] = byte(now >> (i * 8))
		now = now*1103515245 + 12345
	}
	// Set locally administered bit, clear multicast bit
	mac[0] = (mac[0] | 0x02) & 0xFE
	return hex.EncodeToString(mac)
}
