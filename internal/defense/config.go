// Package defense turns the honeypot event stream into abuse detection and
// (optionally) active response. The Detector is an events.Sink that scores each
// source IP over a sliding window; when the score crosses a threshold it asks the
// Blocker to act. The Blocker defaults to alert-only (dry-run): it emits a block
// event and logs the intended action but does NOT touch the firewall unless
// Enforce is set, and it always honors a whitelist so legitimate/management
// sources are never blocked.
package defense

import (
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from friendly YAML strings ("1h",
// "60s", "5m").
type Duration time.Duration

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	pd, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	*d = Duration(pd)
	return nil
}

// D returns the underlying time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Config configures detection and active response.
type Config struct {
	Enabled   bool     `yaml:"enabled"`   // run the detector
	Enforce   bool     `yaml:"enforce"`   // false => alert-only (dry-run); true => add firewall blocks
	BlockTTL  Duration `yaml:"block_ttl"` // how long a block lasts (nft element timeout)
	Window    Duration `yaml:"window"`    // scoring sliding window
	Score     int      `yaml:"score"`     // score threshold that triggers a block
	Cooldown  Duration `yaml:"cooldown"`  // minimum interval between re-blocking the same source
	Whitelist []string `yaml:"whitelist"` // CIDRs (and bare IPs) that are never blocked
}

// withDefaults returns a copy with sensible defaults filled in.
func (c Config) withDefaults() Config {
	if c.BlockTTL == 0 {
		c.BlockTTL = Duration(time.Hour)
	}
	if c.Window == 0 {
		c.Window = Duration(60 * time.Second)
	}
	if c.Score == 0 {
		c.Score = 12
	}
	if c.Cooldown == 0 {
		c.Cooldown = Duration(5 * time.Minute)
	}
	return c
}
