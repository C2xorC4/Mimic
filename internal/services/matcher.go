package services

import (
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/c2xorc4/mimic/internal/config"
)

// ProbeMatcher matches incoming packets against known probe signatures
type ProbeMatcher struct {
	probes []compiledProbe
}

type compiledProbe struct {
	config      *config.ProbeConfig
	hexPrefix   []byte   // Hex-decoded prefix bytes for matching
	hasWildcard bool     // Whether pattern contains wildcards
	segments    [][]byte // For patterns with wildcards: segments between wildcards
}

// NewProbeMatcher creates a new probe matcher from probe configurations
func NewProbeMatcher(probes []config.ProbeConfig) (*ProbeMatcher, error) {
	compiled := make([]compiledProbe, 0, len(probes))

	for i := range probes {
		probe := &probes[i]
		cp := compiledProbe{config: probe}

		if probe.Signature.Pattern != "" {
			// Parse pattern - supports hex escapes and '.' as single-byte wildcard
			pattern := probe.Signature.Pattern

			// Remove regex anchors if present
			pattern = strings.TrimPrefix(pattern, "^")
			pattern = strings.TrimSuffix(pattern, "$")

			// Check for wildcards
			if strings.Contains(pattern, ".") {
				cp.hasWildcard = true
				cp.segments = parsePatternWithWildcards(pattern)
			} else {
				// Simple prefix match
				cp.hexPrefix = parseHexPattern(pattern)
			}
		}

		compiled = append(compiled, cp)
	}

	return &ProbeMatcher{probes: compiled}, nil
}

// parseHexPattern converts a pattern with \xNN escapes to bytes
func parseHexPattern(pattern string) []byte {
	var result []byte
	i := 0
	for i < len(pattern) {
		if i+3 < len(pattern) && pattern[i] == '\\' && pattern[i+1] == 'x' {
			// Parse \xNN
			hexStr := pattern[i+2 : i+4]
			if b, err := hex.DecodeString(hexStr); err == nil {
				result = append(result, b[0])
				i += 4
				continue
			}
		}
		result = append(result, pattern[i])
		i++
	}
	return result
}

// parsePatternWithWildcards splits pattern on '.' wildcards
func parsePatternWithWildcards(pattern string) [][]byte {
	var segments [][]byte
	var current strings.Builder

	i := 0
	for i < len(pattern) {
		if pattern[i] == '.' {
			// Wildcard - save current segment and start new one
			if current.Len() > 0 {
				segments = append(segments, parseHexPattern(current.String()))
				current.Reset()
			}
			// Add nil to represent wildcard position
			segments = append(segments, nil)
			i++
			continue
		}

		if i+3 < len(pattern) && pattern[i] == '\\' && pattern[i+1] == 'x' {
			current.WriteString(pattern[i : i+4])
			i += 4
			continue
		}

		current.WriteByte(pattern[i])
		i++
	}

	if current.Len() > 0 {
		segments = append(segments, parseHexPattern(current.String()))
	}

	return segments
}

// Match attempts to match incoming data against known probes
// Returns the matching probe config or nil if no match
func (pm *ProbeMatcher) Match(data []byte) *config.ProbeConfig {
	for _, probe := range pm.probes {
		if pm.matchProbe(&probe, data) {
			return probe.config
		}
	}
	return nil
}

func (pm *ProbeMatcher) matchProbe(probe *compiledProbe, data []byte) bool {
	sig := &probe.config.Signature

	// Check length constraints
	if sig.MinLength > 0 && len(data) < sig.MinLength {
		return false
	}
	if sig.MaxLength > 0 && len(data) > sig.MaxLength {
		return false
	}

	// Apply offset
	searchData := data
	if sig.Offset > 0 {
		if sig.Offset >= len(data) {
			return false
		}
		searchData = data[sig.Offset:]
	}

	// Match pattern
	if probe.hasWildcard {
		return matchWithWildcards(searchData, probe.segments)
	} else if len(probe.hexPrefix) > 0 {
		return bytes.HasPrefix(searchData, probe.hexPrefix)
	}

	// No pattern = match by length only
	return true
}

// matchWithWildcards matches data against segments with single-byte wildcards between them
func matchWithWildcards(data []byte, segments [][]byte) bool {
	pos := 0

	for _, seg := range segments {
		if seg == nil {
			// Wildcard - skip one byte
			pos++
			if pos > len(data) {
				return false
			}
			continue
		}

		// Match segment
		if pos+len(seg) > len(data) {
			return false
		}
		if !bytes.Equal(data[pos:pos+len(seg)], seg) {
			return false
		}
		pos += len(seg)
	}

	return true
}

// MatchByName finds a probe by name
func (pm *ProbeMatcher) MatchByName(name string) *config.ProbeConfig {
	for _, probe := range pm.probes {
		if probe.config.Name == name {
			return probe.config
		}
	}
	return nil
}
