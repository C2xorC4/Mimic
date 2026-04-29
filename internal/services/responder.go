package services

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
)

// Responder handles loading and rewriting response templates
type Responder struct {
	baseDir string
	cache   map[string][]byte
	options map[string]string
	mu      sync.RWMutex
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
		baseDir: baseDir,
		cache:   make(map[string][]byte),
		options: options,
	}, nil
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
		// Fill with random bytes
		for i := 0; i < rule.Length; i++ {
			response[rule.Offset+i] = byte(time.Now().UnixNano() >> (i * 8))
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
