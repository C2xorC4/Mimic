package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/logging"
)

var (
	errEmptyPatch     = errors.New("empty config patch")
	errNoConfigPath   = errors.New("config path not set")
	errInvalidProfile = errors.New("profile not found")
	errNoProfileOrSvc = errors.New("profile or services must be specified")
)

// ErrNoConfigPath reports that the instance has no on-disk config path.
func ErrNoConfigPath() error { return errNoConfigPath }

// ValidateEditableConfig checks the post-patch config is safe to persist and run.
func ValidateEditableConfig(cfg *config.AppConfig, profilesDir, servicesDir string) error {
	if cfg.Profile == "" && len(cfg.Services) == 0 {
		return errNoProfileOrSvc
	}
	if cfg.Profile != "" {
		pm := config.NewProfileManager(profilesDir)
		if err := pm.LoadAllProfiles(); err != nil {
			return fmt.Errorf("loading profiles: %w", err)
		}
		if _, err := pm.GetProfile(cfg.Profile); err != nil {
			return fmt.Errorf("%w: %s", errInvalidProfile, cfg.Profile)
		}
	}
	if cfg.Logging.Level != "" {
		switch strings.ToLower(cfg.Logging.Level) {
		case "debug", "info", "warn", "error":
		default:
			return fmt.Errorf("invalid logging.level %q", cfg.Logging.Level)
		}
	}
	switch strings.ToLower(cfg.Firewall.ClosedPortBehavior) {
	case "", "reset", "drop", "filtered":
	default:
		return fmt.Errorf("invalid firewall.closed_port_behavior %q", cfg.Firewall.ClosedPortBehavior)
	}
	if len(cfg.Services) > 0 {
		var profile *config.OSProfile
		if cfg.Profile != "" {
			pm := config.NewProfileManager(profilesDir)
			_ = pm.LoadAllProfiles()
			profile, _ = pm.GetProfile(cfg.Profile)
		}
		if _, err := config.ResolveRunServices(cfg.Services, servicesDir, profile); err != nil {
			return fmt.Errorf("invalid services: %w", err)
		}
	}
	return nil
}

// PersistConfig writes cfg to path, keeping a .bak of any existing file.
func PersistConfig(path string, cfg *config.AppConfig) (backup string, err error) {
	if path == "" {
		return "", errNoConfigPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("mkdir config dir: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		backup = path + ".bak"
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return "", fmt.Errorf("reading config for backup: %w", rerr)
		}
		if werr := os.WriteFile(backup, data, 0o644); werr != nil {
			return "", fmt.Errorf("writing config backup: %w", werr)
		}
	}
	if err := config.SaveAppConfig(path, cfg); err != nil {
		return backup, err
	}
	return backup, nil
}

// ValidateLoggingLevel is exported for tests.
func ValidateLoggingLevel(level string) bool {
	switch strings.ToLower(level) {
	case "debug", "info", "warn", "error", "":
		return true
	default:
		return false
	}
}

// NormalizeLogName maps a short log name to a filename in logDir.
func NormalizeLogName(name string) (file string, err error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "events", "events.log":
		return "events.log", nil
	case "mimic", "mimic.log":
		return "mimic.log", nil
	case "probes", "probes.log":
		return "probes.log", nil
	default:
		return "", fmt.Errorf("unknown log file %q (allowed: events, mimic, probes)", name)
	}
}

// ResolveLogPath returns the absolute path for a whitelisted log name.
func ResolveLogPath(logDir, name string) (string, string, error) {
	file, err := NormalizeLogName(name)
	if err != nil {
		return "", "", err
	}
	if logDir == "" {
		logDir = logging.DefaultFallbackDir
	}
	return file, filepath.Join(logDir, file), nil
}