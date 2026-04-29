package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProfileManager handles loading and managing OS profiles
type ProfileManager struct {
	profilesDir string
	profiles    map[string]*OSProfile
	current     *OSProfile
}

// NewProfileManager creates a new profile manager
func NewProfileManager(profilesDir string) *ProfileManager {
	return &ProfileManager{
		profilesDir: profilesDir,
		profiles:    make(map[string]*OSProfile),
	}
}

// LoadAllProfiles loads all profiles from the profiles directory
func (pm *ProfileManager) LoadAllProfiles() error {
	families := []string{"windows", "linux", "macos"}

	for _, family := range families {
		familyDir := filepath.Join(pm.profilesDir, family)
		if _, err := os.Stat(familyDir); os.IsNotExist(err) {
			continue
		}

		entries, err := os.ReadDir(familyDir)
		if err != nil {
			return fmt.Errorf("reading %s profiles: %w", family, err)
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
				continue
			}

			profilePath := filepath.Join(familyDir, entry.Name())
			profile, err := pm.loadProfile(profilePath)
			if err != nil {
				return fmt.Errorf("loading profile %s: %w", profilePath, err)
			}

			// Use lowercase name as key
			key := strings.ToLower(profile.Name)
			pm.profiles[key] = profile
		}
	}

	return nil
}

// loadProfile loads a single profile from a YAML file
func (pm *ProfileManager) loadProfile(path string) (*OSProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var profile OSProfile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	return &profile, nil
}

// GetProfile returns a profile by name (case-insensitive)
func (pm *ProfileManager) GetProfile(name string) (*OSProfile, error) {
	profile, ok := pm.profiles[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", name)
	}
	return profile, nil
}

// SetCurrentProfile sets the active profile
func (pm *ProfileManager) SetCurrentProfile(name string) error {
	profile, err := pm.GetProfile(name)
	if err != nil {
		return err
	}
	pm.current = profile
	return nil
}

// CurrentProfile returns the currently active profile
func (pm *ProfileManager) CurrentProfile() *OSProfile {
	return pm.current
}

// ListProfiles returns all available profile names grouped by family
func (pm *ProfileManager) ListProfiles() map[string][]string {
	result := make(map[string][]string)

	for _, profile := range pm.profiles {
		result[profile.Family] = append(result[profile.Family], profile.Name)
	}

	return result
}

// ListProfileNames returns all profile names as a flat list
func (pm *ProfileManager) ListProfileNames() []string {
	names := make([]string, 0, len(pm.profiles))
	for _, profile := range pm.profiles {
		names = append(names, profile.Name)
	}
	return names
}

// LoadAppConfig loads the main application configuration
func LoadAppConfig(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return defaults
			return &AppConfig{
				ProfilesDir: "./profiles",
				ServicesDir: "./services",
				Logging: LogConfig{
					Level:    "info",
					LogDir:   "/var/log/mimic",
					JSONMode: true,
					ToStdout: true,
				},
			}, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var config AppConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Set defaults for empty fields
	if config.ProfilesDir == "" {
		config.ProfilesDir = "./profiles"
	}
	if config.ServicesDir == "" {
		config.ServicesDir = "./services"
	}

	// Set logging defaults
	// If logging section wasn't provided (Level empty), set all defaults
	loggingSectionMissing := config.Logging.Level == "" && config.Logging.LogDir == ""

	if config.Logging.Level == "" {
		// Check legacy field
		if config.LogLevel != "" {
			config.Logging.Level = config.LogLevel
		} else {
			config.Logging.Level = "info"
		}
	}
	if config.Logging.LogDir == "" {
		config.Logging.LogDir = "/var/log/mimic"
	}
	// Default to stdout and JSON mode when logging section wasn't explicitly configured
	// This ensures sensible defaults for users who haven't configured logging yet
	if loggingSectionMissing {
		config.Logging.JSONMode = true
		config.Logging.ToStdout = true
	}

	return &config, nil
}

// SaveAppConfig saves the application configuration
func SaveAppConfig(path string, config *AppConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}
