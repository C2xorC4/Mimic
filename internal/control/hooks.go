package control

import "github.com/c2xorc4/mimic/internal/config"

// Hooks supplies optional control-plane callbacks wired by the running instance.
// Nil hooks disable the corresponding operations.
type Hooks struct {
	GetConfig     func() (ConfigSnapshot, error)
	SetConfig     func(patch ConfigPatch, dryRun bool) (ConfigSetResult, error)
	ListProfiles  func() (ProfileCatalog, error)
	ListServices  func() (ServiceCatalog, error)
	Restart       func() error
	Stop          func() error
	TailLogFile   func(name string, lines int) (LogTail, error)
}

// ConfigSnapshot is the UI-safe, editable subset of the on-disk config.
type ConfigSnapshot struct {
	Path           string                 `json:"path"`
	Profile        string                 `json:"profile"`
	Interface      string                 `json:"interface,omitempty"`
	Services       []string               `json:"services"`
	ClosedPorts    []uint16               `json:"closed_ports,omitempty"`
	ServiceOptions config.ServiceOptions  `json:"service_options"`
	Logging        config.LogConfig       `json:"logging"`
	Firewall       config.FirewallConfig  `json:"firewall"`
	Defense        DefenseSnapshot        `json:"defense"`
}

// DefenseSnapshot exposes only the defense fields a management UI should edit.
type DefenseSnapshot struct {
	Enabled   bool     `json:"enabled"`
	Enforce   bool     `json:"enforce"`
	Whitelist []string `json:"whitelist,omitempty"`
}

// ConfigPatch updates a subset of ConfigSnapshot fields. Omitted fields are left
// unchanged. A nil slice for services does not clear services; use an empty slice
// explicitly to clear (which validation rejects — at least profile or services
// must remain valid).
type ConfigPatch struct {
	Profile        *string                `json:"profile,omitempty"`
	Interface      *string                `json:"interface,omitempty"`
	Services       *[]string              `json:"services,omitempty"`
	ClosedPorts    *[]uint16              `json:"closed_ports,omitempty"`
	ServiceOptions *config.ServiceOptions `json:"service_options,omitempty"`
	Logging        *LoggingPatch          `json:"logging,omitempty"`
	Firewall       *config.FirewallConfig `json:"firewall,omitempty"`
	Defense        *DefensePatch          `json:"defense,omitempty"`
}

// LoggingPatch updates logging fields without clobbering unspecified booleans.
type LoggingPatch struct {
	Level    *string `json:"level,omitempty"`
	LogDir   *string `json:"log_dir,omitempty"`
	JSONMode *bool   `json:"json_mode,omitempty"`
	ToStdout *bool   `json:"to_stdout,omitempty"`
}

// DefensePatch updates editable defense fields.
type DefensePatch struct {
	Enabled   *bool     `json:"enabled,omitempty"`
	Enforce   *bool     `json:"enforce,omitempty"`
	Whitelist *[]string `json:"whitelist,omitempty"`
}

// ConfigSetResult is returned by config.set / config.validate.
type ConfigSetResult struct {
	Path            string `json:"path"`
	RestartRequired bool   `json:"restart_required"`
	Backup          string `json:"backup,omitempty"`
	Message         string `json:"message,omitempty"`
}

// LogTail is the tail of a whitelisted log file.
type LogTail struct {
	File   string   `json:"file"`
	Path   string   `json:"path"`
	Lines  []string `json:"lines"`
	Total  int      `json:"total"`
	Offset int      `json:"offset"` // byte offset of first returned line
}

// SnapshotFrom builds a UI-safe view from a loaded AppConfig.
func SnapshotFrom(cfg *config.AppConfig, path string) ConfigSnapshot {
	return ConfigSnapshot{
		Path:           path,
		Profile:        cfg.Profile,
		Interface:      cfg.Interface,
		Services:       append([]string(nil), cfg.Services...),
		ClosedPorts:    append([]uint16(nil), cfg.ClosedPorts...),
		ServiceOptions: cfg.ServiceOptions,
		Logging:        cfg.Logging,
		Firewall:       cfg.Firewall,
		Defense: DefenseSnapshot{
			Enabled:   cfg.Defense.Enabled,
			Enforce:   cfg.Defense.Enforce,
			Whitelist: append([]string(nil), cfg.Defense.Whitelist...),
		},
	}
}

// ApplyPatch merges patch into cfg (in place). Returns an error for empty patches
// or invalid field values.
func ApplyPatch(cfg *config.AppConfig, patch ConfigPatch) error {
	if patch.isEmpty() {
		return errEmptyPatch
	}
	if patch.Profile != nil {
		cfg.Profile = *patch.Profile
	}
	if patch.Interface != nil {
		cfg.Interface = *patch.Interface
	}
	if patch.Services != nil {
		cfg.Services = append([]string(nil), (*patch.Services)...)
	}
	if patch.ClosedPorts != nil {
		cfg.ClosedPorts = append([]uint16(nil), (*patch.ClosedPorts)...)
	}
	if patch.ServiceOptions != nil {
		cfg.ServiceOptions = *patch.ServiceOptions
	}
	if patch.Logging != nil {
		applyLoggingPatch(&cfg.Logging, *patch.Logging)
	}
	if patch.Firewall != nil {
		cfg.Firewall = *patch.Firewall
	}
	if patch.Defense != nil {
		if patch.Defense.Enabled != nil {
			cfg.Defense.Enabled = *patch.Defense.Enabled
		}
		if patch.Defense.Enforce != nil {
			cfg.Defense.Enforce = *patch.Defense.Enforce
		}
		if patch.Defense.Whitelist != nil {
			cfg.Defense.Whitelist = append([]string(nil), (*patch.Defense.Whitelist)...)
		}
	}
	return nil
}

func (p ConfigPatch) isEmpty() bool {
	return p.Profile == nil && p.Interface == nil && p.Services == nil &&
		p.ClosedPorts == nil && p.ServiceOptions == nil && p.Logging == nil &&
		p.Firewall == nil && p.Defense == nil
}

func applyLoggingPatch(dst *config.LogConfig, patch LoggingPatch) {
	if patch.Level != nil {
		dst.Level = *patch.Level
	}
	if patch.LogDir != nil {
		dst.LogDir = *patch.LogDir
	}
	if patch.JSONMode != nil {
		dst.JSONMode = *patch.JSONMode
	}
	if patch.ToStdout != nil {
		dst.ToStdout = *patch.ToStdout
	}
}