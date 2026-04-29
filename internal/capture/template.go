package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/c2xorc4/mimic/internal/config"
)

// TemplateGenerator generates service templates from captured sessions
type TemplateGenerator struct {
	outputDir   string
	serviceName string
	sourceOS    string
	exchanges   []ExchangeRecord
}

// ExchangeRecord holds a captured exchange with metadata
type ExchangeRecord struct {
	Session   *Session
	Exchange  *Exchange
	ProbeHash string
	Port      uint16
}

// DynamicField represents a field that changes between captures
type DynamicField struct {
	Offset int    `yaml:"offset"`
	Length int    `yaml:"length"`
	Type   string `yaml:"type"` // timestamp, guid, random, seq, etc.
	Note   string `yaml:"note,omitempty"`
}

// TemplateOutput represents the generated template files
type TemplateOutput struct {
	ManifestPath  string
	ResponseFiles []string
	CaptureFiles  []string
}

// NewTemplateGenerator creates a new template generator
func NewTemplateGenerator(outputDir, serviceName, sourceOS string) *TemplateGenerator {
	return &TemplateGenerator{
		outputDir:   outputDir,
		serviceName: serviceName,
		sourceOS:    sourceOS,
		exchanges:   make([]ExchangeRecord, 0),
	}
}

// AddSession adds all exchanges from a session
func (tg *TemplateGenerator) AddSession(session *Session) {
	for i := range session.Exchanges {
		ex := &session.Exchanges[i]
		if len(ex.Probe) == 0 {
			continue
		}

		// Hash the probe for deduplication
		hash := sha256.Sum256(ex.Probe)
		hashStr := hex.EncodeToString(hash[:8])

		tg.exchanges = append(tg.exchanges, ExchangeRecord{
			Session:   session,
			Exchange:  ex,
			ProbeHash: hashStr,
			Port:      session.Key.ServerPort,
		})
	}
}

// Generate creates the template files
func (tg *TemplateGenerator) Generate() (*TemplateOutput, error) {
	// Create output directories
	responsesDir := filepath.Join(tg.outputDir, "responses")
	capturesDir := filepath.Join(tg.outputDir, "captures")

	for _, dir := range []string{tg.outputDir, responsesDir, capturesDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	output := &TemplateOutput{}

	// Group exchanges by probe similarity
	groups := tg.groupExchanges()

	// Generate probe configs
	probes := make([]config.ProbeConfig, 0)

	for groupName, records := range groups {
		if len(records) == 0 {
			continue
		}

		// Use first exchange as template
		first := records[0]

		// Generate response file
		responseFile := fmt.Sprintf("%s.bin", groupName)
		responsePath := filepath.Join(responsesDir, responseFile)
		if err := os.WriteFile(responsePath, first.Exchange.Response, 0644); err != nil {
			return nil, fmt.Errorf("writing response: %w", err)
		}
		output.ResponseFiles = append(output.ResponseFiles, responsePath)

		// Generate capture metadata
		captureMeta := tg.generateCaptureMeta(groupName, records)
		captureFile := fmt.Sprintf("%s.yaml", groupName)
		capturePath := filepath.Join(capturesDir, captureFile)
		captureData, _ := yaml.Marshal(captureMeta)
		if err := os.WriteFile(capturePath, captureData, 0644); err != nil {
			return nil, fmt.Errorf("writing capture meta: %w", err)
		}
		output.CaptureFiles = append(output.CaptureFiles, capturePath)

		// Generate probe signature
		signature := tg.generateSignature(first.Exchange.Probe)

		// Detect dynamic fields in response
		dynamicFields := tg.detectDynamicFields(records)

		// Convert to rewrite rules
		rewriteRules := make([]config.RewriteRule, 0, len(dynamicFields))
		for _, df := range dynamicFields {
			rewriteRules = append(rewriteRules, config.RewriteRule{
				Offset: df.Offset,
				Length: df.Length,
				Type:   df.Type,
			})
		}

		probe := config.ProbeConfig{
			Name:         groupName,
			Signature:    signature,
			ResponseFile: filepath.Join("responses", responseFile),
			RewriteRules: rewriteRules,
		}
		probes = append(probes, probe)
	}

	// Generate manifest
	manifest := config.ServiceConfig{
		Name:     tg.serviceName,
		Port:     tg.inferPort(),
		Protocol: "tcp",
		Stateful: tg.inferStateful(),
		Probes:   probes,
	}

	manifestPath := filepath.Join(tg.outputDir, "manifest.yaml")
	manifestData, err := yaml.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshaling manifest: %w", err)
	}

	// Add header comment
	header := fmt.Sprintf("# %s Service Template\n# Generated from %s captures\n# Source OS: %s\n\n",
		tg.serviceName, tg.serviceName, tg.sourceOS)
	manifestData = append([]byte(header), manifestData...)

	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}
	output.ManifestPath = manifestPath

	return output, nil
}

// groupExchanges groups exchanges by probe similarity
func (tg *TemplateGenerator) groupExchanges() map[string][]ExchangeRecord {
	groups := make(map[string][]ExchangeRecord)

	for _, record := range tg.exchanges {
		// Generate a name based on probe characteristics
		name := tg.generateProbeName(record.Exchange.Probe, record.Port)
		groups[name] = append(groups[name], record)
	}

	return groups
}

// generateProbeName creates a descriptive name for a probe type
func (tg *TemplateGenerator) generateProbeName(probe []byte, port uint16) string {
	// Try to identify common protocol signatures
	name := fmt.Sprintf("%s_probe", tg.serviceName)

	switch port {
	case 445: // SMB
		if len(probe) >= 8 {
			if bytes.HasPrefix(probe[4:], []byte{0xfe, 'S', 'M', 'B'}) {
				name = "smb2"
				// Try to identify command
				if len(probe) >= 16 {
					cmd := uint16(probe[12]) | uint16(probe[13])<<8
					switch cmd {
					case 0:
						name = "smb2_negotiate"
					case 1:
						name = "smb2_session_setup"
					case 3:
						name = "smb2_tree_connect"
					default:
						name = fmt.Sprintf("smb2_cmd_%d", cmd)
					}
				}
			} else if bytes.HasPrefix(probe[4:], []byte{0xff, 'S', 'M', 'B'}) {
				name = "smb1_negotiate"
			}
		}

	case 3389: // RDP
		if len(probe) >= 4 {
			// TPKT header
			if probe[0] == 0x03 && probe[1] == 0x00 {
				name = "rdp_connection"
			}
		}

	case 80, 443, 8080: // HTTP
		if bytes.HasPrefix(probe, []byte("GET ")) {
			name = "http_get"
		} else if bytes.HasPrefix(probe, []byte("POST ")) {
			name = "http_post"
		} else if bytes.HasPrefix(probe, []byte("HEAD ")) {
			name = "http_head"
		}

	case 22: // SSH
		if bytes.HasPrefix(probe, []byte("SSH-")) {
			name = "ssh_banner"
		}

	case 21: // FTP
		name = "ftp"

	case 1433: // MSSQL
		name = "mssql"
	}

	// Add hash suffix for uniqueness
	hash := sha256.Sum256(probe)
	return fmt.Sprintf("%s_%s", name, hex.EncodeToString(hash[:4]))
}

// generateSignature creates a probe matching signature
func (tg *TemplateGenerator) generateSignature(probe []byte) config.SignatureConfig {
	sig := config.SignatureConfig{
		MinLength: len(probe),
		MaxLength: len(probe) + 100, // Allow some variance
		Offset:    0,
	}

	// Find stable prefix bytes to use as pattern
	// Look for ASCII strings or known magic bytes
	patternBytes := tg.findStablePattern(probe)
	if len(patternBytes) > 0 {
		sig.Pattern = patternBytes
	}

	return sig
}

// findStablePattern identifies stable bytes in a probe for matching
func (tg *TemplateGenerator) findStablePattern(probe []byte) string {
	if len(probe) < 4 {
		return ""
	}

	// For now, use first N bytes as hex pattern
	// This could be improved with more sophisticated analysis
	patternLen := 8
	if len(probe) < patternLen {
		patternLen = len(probe)
	}

	// Convert to regex-safe pattern
	var pattern strings.Builder
	pattern.WriteString("^")

	for i := 0; i < patternLen; i++ {
		b := probe[i]
		if b >= 0x20 && b <= 0x7e && !isRegexMeta(b) {
			pattern.WriteByte(b)
		} else {
			pattern.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}

	return pattern.String()
}

// isRegexMeta checks if a byte is a regex metacharacter
func isRegexMeta(b byte) bool {
	return bytes.ContainsAny([]byte{b}, `\.+*?^$[]{}()|`)
}

// detectDynamicFields compares multiple captures to find changing bytes
func (tg *TemplateGenerator) detectDynamicFields(records []ExchangeRecord) []DynamicField {
	if len(records) < 2 {
		// Can't detect dynamic fields with single capture
		// Fall back to heuristics
		return tg.heuristicDynamicFields(records[0].Exchange.Response)
	}

	// Compare responses byte-by-byte
	base := records[0].Exchange.Response
	fields := make([]DynamicField, 0)

	var diffStart int = -1

	for i := 0; i < len(base); i++ {
		isDiff := false
		for _, r := range records[1:] {
			if i >= len(r.Exchange.Response) {
				isDiff = true
				break
			}
			if r.Exchange.Response[i] != base[i] {
				isDiff = true
				break
			}
		}

		if isDiff && diffStart == -1 {
			// Start of different region
			diffStart = i
		} else if !isDiff && diffStart != -1 {
			// End of different region
			length := i - diffStart
			fieldType := tg.inferFieldType(base[diffStart:i], length)
			fields = append(fields, DynamicField{
				Offset: diffStart,
				Length: length,
				Type:   fieldType,
			})
			diffStart = -1
		}
	}

	// Handle trailing difference
	if diffStart != -1 {
		length := len(base) - diffStart
		fieldType := tg.inferFieldType(base[diffStart:], length)
		fields = append(fields, DynamicField{
			Offset: diffStart,
			Length: length,
			Type:   fieldType,
		})
	}

	return fields
}

// heuristicDynamicFields uses heuristics to guess dynamic fields
func (tg *TemplateGenerator) heuristicDynamicFields(response []byte) []DynamicField {
	fields := make([]DynamicField, 0)

	// Look for common patterns
	// 8-byte aligned fields that could be timestamps
	// 16-byte fields that could be GUIDs
	// etc.

	// This is a simplified heuristic - real implementation would be protocol-aware

	return fields
}

// inferFieldType guesses the type of a dynamic field based on its characteristics
func (tg *TemplateGenerator) inferFieldType(data []byte, length int) string {
	switch length {
	case 4:
		return "timestamp_unix"
	case 8:
		return "timestamp"
	case 16:
		return "guid"
	default:
		return "random"
	}
}

// generateCaptureMeta creates metadata about a captured exchange group
func (tg *TemplateGenerator) generateCaptureMeta(name string, records []ExchangeRecord) map[string]interface{} {
	meta := map[string]interface{}{
		"name":      name,
		"service":   tg.serviceName,
		"source_os": tg.sourceOS,
		"captures":  len(records),
	}

	if len(records) > 0 {
		first := records[0]
		meta["probe_hex"] = hex.EncodeToString(first.Exchange.Probe)
		meta["response_hex"] = hex.EncodeToString(first.Exchange.Response)
		meta["probe_length"] = len(first.Exchange.Probe)
		meta["response_length"] = len(first.Exchange.Response)
	}

	return meta
}

// inferPort returns the most common port in captures
func (tg *TemplateGenerator) inferPort() uint16 {
	ports := make(map[uint16]int)
	for _, ex := range tg.exchanges {
		ports[ex.Port]++
	}

	var maxPort uint16
	var maxCount int
	for port, count := range ports {
		if count > maxCount {
			maxPort = port
			maxCount = count
		}
	}

	return maxPort
}

// inferStateful guesses if the protocol is stateful
func (tg *TemplateGenerator) inferStateful() bool {
	// If we see multiple exchanges per session, it's likely stateful
	for _, ex := range tg.exchanges {
		if len(ex.Session.Exchanges) > 1 {
			return true
		}
	}
	return false
}

// ValidateManifest validates a generated manifest against captured data
func ValidateManifest(manifestPath string, sessions []*Session) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}

	var manifest config.ServiceConfig
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parsing manifest: %w", err)
	}

	// Try to match each captured probe against the manifest
	matched := 0
	unmatched := 0

	for _, session := range sessions {
		for _, ex := range session.Exchanges {
			found := false
			for _, probe := range manifest.Probes {
				if matchProbe(&probe.Signature, ex.Probe) {
					found = true
					matched++
					break
				}
			}
			if !found {
				unmatched++
			}
		}
	}

	if unmatched > 0 {
		return fmt.Errorf("manifest validation: %d matched, %d unmatched probes", matched, unmatched)
	}

	return nil
}

// matchProbe tests if a probe matches a signature
func matchProbe(sig *config.SignatureConfig, probe []byte) bool {
	if sig.MinLength > 0 && len(probe) < sig.MinLength {
		return false
	}
	if sig.MaxLength > 0 && len(probe) > sig.MaxLength {
		return false
	}

	if sig.Pattern != "" {
		re, err := regexp.Compile(sig.Pattern)
		if err != nil {
			return false
		}
		searchData := probe
		if sig.Offset > 0 && sig.Offset < len(probe) {
			searchData = probe[sig.Offset:]
		}
		if !re.Match(searchData) {
			return false
		}
	}

	return true
}
