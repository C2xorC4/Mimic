//go:build windows

package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/c2xorc4/mimic/internal/platform"
)

// Windows install layout: the binary + profile/service data live under Program
// Files; the editable config + logs live under ProgramData (the Windows analogue
// of /etc + /var/log). The service runs the binary as `run -c <config>`.
func winPaths() (binDir, binTarget, dataDir, cfgFile, logDir string) {
	prog := os.Getenv("ProgramFiles")
	if prog == "" {
		prog = `C:\Program Files`
	}
	data := os.Getenv("ProgramData")
	if data == "" {
		data = `C:\ProgramData`
	}
	binDir = filepath.Join(prog, "Mimic")
	binTarget = filepath.Join(binDir, "mimic.exe")
	dataDir = filepath.Join(data, "Mimic")
	cfgFile = filepath.Join(dataDir, "config.yaml")
	logDir = filepath.Join(dataDir, "logs")
	return
}

// winStarterConfig is a Windows-pathed starter config (the embedded
// assets/config.starter.yaml uses Linux paths and an interface, neither of which
// apply here — Windows has no eBPF interface and uses ProgramData paths).
func winStarterConfig(binDir, logDir string) []byte {
	return []byte(fmt.Sprintf(`# Mimic Windows starter config — EDIT before starting the service.
# Service emulation runs today; TCP/IP stack spoofing (WinDivert) arrives in a
# later build. No 'interface' is needed on Windows.
profile: "Windows 11"
services:
  - winrm
  - wsd
  - deliveryopt
service_options:
  netbios_name: "WORKSTATION"
  domain: "WORKGROUP"
profiles_dir: %q
services_dir: %q
logging:
  level: info
  log_dir: %q
  json_mode: true
  to_stdout: false
`, filepath.Join(binDir, "profiles"), filepath.Join(binDir, "services"), logDir))
}

var uninstallPurge bool

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Mimic as a Windows service",
	Long: `Installs the mimic binary and profile/service data under Program Files, a
starter config under ProgramData (only if absent), and registers a Windows
service (manual start). Run from the source/dist tree so profiles/ and services/
are present. Does not start the service — edit the config first, then:
  sc start Mimic   (or use services.msc)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !platform.IsElevated() {
			return fmt.Errorf("this command requires %s privileges", platform.PrivilegeName())
		}
		binDir, binTarget, dataDir, cfgFile, logDir := winPaths()

		for _, d := range []string{binDir, dataDir, logDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", d, err)
			}
		}

		// 1. Binary -> Program Files\Mimic\mimic.exe.
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locating self: %w", err)
		}
		if !sameFile(self, binTarget) {
			if err := copyFile(self, binTarget, 0o755); err != nil {
				return fmt.Errorf("installing binary: %w", err)
			}
			fmt.Printf("installed binary -> %s\n", binTarget)
		} else {
			fmt.Printf("binary already at %s\n", binTarget)
		}

		// 2. Profile + service data -> Program Files\Mimic (copied from CWD).
		for _, d := range []string{"profiles", "services"} {
			if _, err := os.Stat(d); err != nil {
				fmt.Printf("warning: .\\%s not found — set %s_dir in config to an absolute path\n", d, d[:len(d)-1])
				continue
			}
			dst := filepath.Join(binDir, d)
			_ = os.RemoveAll(dst)
			if err := copyTree(d, dst); err != nil {
				fmt.Printf("warning: copying %s: %v\n", d, err)
			} else {
				fmt.Printf("installed %s -> %s\n", d, dst)
			}
		}

		// 3. Starter config (never overwrite an existing one).
		if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
			if err := os.WriteFile(cfgFile, winStarterConfig(binDir, logDir), 0o644); err != nil {
				return fmt.Errorf("writing starter config: %w", err)
			}
			fmt.Printf("wrote starter config -> %s (EDIT before starting)\n", cfgFile)
		} else {
			fmt.Printf("kept existing config %s\n", cfgFile)
		}

		// 4. Register the service (manual start; ImagePath = binary + run args).
		if err := registerService(binTarget, cfgFile); err != nil {
			return err
		}

		fmt.Printf("\nInstalled. Next:\n  1. edit %s (profile + services)\n"+
			"  2. sc start Mimic   (or services.msc)\n  3. logs: %s\n", cfgFile, logDir)
		return nil
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the Mimic Windows service",
	Long: `Stops and removes the Mimic service. With --purge it also removes the
installed binary, profile/service data, and config under Program Files/ProgramData.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !platform.IsElevated() {
			return fmt.Errorf("this command requires %s privileges", platform.PrivilegeName())
		}
		binDir, _, dataDir, _, _ := winPaths()

		if err := removeService(); err != nil {
			fmt.Printf("warning: removing service: %v\n", err)
		} else {
			fmt.Println("removed service Mimic")
		}

		if uninstallPurge {
			for _, p := range []string{binDir, dataDir} {
				if err := os.RemoveAll(p); err != nil {
					fmt.Printf("warning: removing %s: %v\n", p, err)
				} else {
					fmt.Printf("removed %s\n", p)
				}
			}
		} else {
			fmt.Printf("kept %s and %s (use --purge to remove)\n", binDir, dataDir)
		}
		fmt.Println("Uninstalled.")
		return nil
	},
}

func init() {
	uninstallCmd.Flags().BoolVar(&uninstallPurge, "purge", false,
		"also remove the installed binary, data, and config")
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
}

// registerService creates (or refreshes) the Mimic service pointing at binTarget
// with `run -c <cfgFile>` as its arguments.
func registerService(binTarget, cfgFile string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists — uninstall first", serviceName)
	}

	cfg := mgr.Config{
		DisplayName:  "Mimic OS Deception",
		Description:  "OS-fingerprint deception: service emulation (and stack spoofing on supported builds).",
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
	}
	s, err := m.CreateService(serviceName, binTarget, cfg, "run", "-c", cfgFile)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	fmt.Printf("registered service %q -> %s run -c %s\n", serviceName, binTarget, cfgFile)
	return nil
}

// removeService stops (best-effort) and deletes the Mimic service.
func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service not installed")
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop) // best-effort; ignore if already stopped
	return s.Delete()
}

// copyTree recursively copies a directory tree (src -> dst).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target, 0o644)
	})
}

// sameFile reports whether two paths resolve to the same file on disk.
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}
