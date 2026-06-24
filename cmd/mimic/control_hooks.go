package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/control"
	"github.com/c2xorc4/mimic/internal/logging"
	"github.com/c2xorc4/mimic/internal/platform"
)

// buildControlHooks wires the running instance into the control plane API.
func buildControlHooks(cfgPath string, profilesDir, servicesDir string, restartCh, stopCh chan<- struct{}) *control.Hooks {
	return &control.Hooks{
		GetConfig: func() (control.ConfigSnapshot, error) {
			if cfgPath == "" {
				return control.ConfigSnapshot{}, control.ErrNoConfigPath()
			}
			cfg, err := config.LoadAppConfig(cfgPath)
			if err != nil {
				return control.ConfigSnapshot{}, err
			}
			return control.SnapshotFrom(cfg, cfgPath), nil
		},
		ListProfiles: func() (control.ProfileCatalog, error) {
			return control.ListProfiles(profilesDir)
		},
		ListServices: func() (control.ServiceCatalog, error) {
			return control.ListServices(servicesDir)
		},
		SetConfig: func(patch control.ConfigPatch, dryRun bool) (control.ConfigSetResult, error) {
			if cfgPath == "" {
				return control.ConfigSetResult{}, control.ErrNoConfigPath()
			}
			cfg, err := config.LoadAppConfig(cfgPath)
			if err != nil {
				return control.ConfigSetResult{}, err
			}
			if err := control.ApplyPatch(cfg, patch); err != nil {
				return control.ConfigSetResult{}, err
			}
			if err := control.ValidateEditableConfig(cfg, profilesDir, servicesDir); err != nil {
				return control.ConfigSetResult{}, err
			}
			result := control.ConfigSetResult{
				Path:            cfgPath,
				RestartRequired: true,
			}
			if dryRun {
				result.Message = "validation ok"
				return result, nil
			}
			backup, err := control.PersistConfig(cfgPath, cfg)
			if err != nil {
				return control.ConfigSetResult{}, err
			}
			result.Backup = backup
			result.Message = "saved; restart required to apply"
			return result, nil
		},
		Restart: func() error {
			if err := platform.ScheduleRestart(os.Getpid(), cfgPath, platform.RunningUnderService()); err != nil {
				return fmt.Errorf("scheduling restart: %w", err)
			}
			if restartCh != nil {
				// Let the control client read the OK response before teardown.
				go func() {
					time.Sleep(200 * time.Millisecond)
					close(restartCh)
				}()
			}
			return nil
		},
		Stop: func() error {
			if stopCh != nil {
				// Let the control client read the OK response before teardown.
				go func() {
					time.Sleep(200 * time.Millisecond)
					close(stopCh)
				}()
			}
			return nil
		},
		TailLogFile: func(name string, lines int) (control.LogTail, error) {
			file, path, err := control.ResolveLogPath(logging.GetActiveLogDir(), name)
			if err != nil {
				return control.LogTail{}, err
			}
			tail, err := control.TailFile(path, lines)
			if err != nil {
				return control.LogTail{}, err
			}
			tail.File = file
			return tail, nil
		},
	}
}

// defaultProfilesDir returns profiles_dir from config or the CLI default.
func defaultProfilesDir(cfgPath string) string {
	if cfgPath != "" {
		if cfg, err := config.LoadAppConfig(cfgPath); err == nil && cfg.ProfilesDir != "" {
			return cfg.ProfilesDir
		}
	}
	if profilesDir != "" {
		return profilesDir
	}
	return "./profiles"
}

// defaultServicesDir returns services_dir from config or the CLI default.
func defaultServicesDir(cfgPath string) string {
	if cfgPath != "" {
		if cfg, err := config.LoadAppConfig(cfgPath); err == nil && cfg.ServicesDir != "" {
			return cfg.ServicesDir
		}
	}
	if servicesDir != "" {
		return servicesDir
	}
	return "./services"
}

// absConfigPath resolves cfgFile to an absolute path when possible.
func absConfigPath() string {
	if cfgFile == "" {
		return ""
	}
	if abs, err := filepath.Abs(cfgFile); err == nil {
		return abs
	}
	return cfgFile
}