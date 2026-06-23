//go:build linux

package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/platform"
)

//go:embed assets/mimic.service
var systemdUnit []byte

const (
	unitPath    = "/etc/systemd/system/mimic.service"
	binTarget   = "/usr/local/bin/mimic"
	cfgDirPath  = "/etc/mimic"
	cfgFilePath = "/etc/mimic/config.yaml"
	logDirPath  = "/var/log/mimic"
)

var uninstallPurge bool

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Mimic as a systemd service",
	Long: `Installs the mimic binary to /usr/local/bin, a starter config to
/etc/mimic/config.yaml (only if absent), and a systemd unit, then runs
daemon-reload. Does not start or enable the service — edit the config first,
then: systemctl enable --now mimic`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !platform.IsElevated() {
			return fmt.Errorf("this command requires %s privileges", platform.PrivilegeName())
		}

		// 1. Binary -> /usr/local/bin/mimic (skip if we're already it).
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locating self: %w", err)
		}
		if self, err = filepath.EvalSymlinks(self); err != nil {
			return fmt.Errorf("resolving self: %w", err)
		}
		if self != binTarget {
			if err := copyFile(self, binTarget, 0o755); err != nil {
				return fmt.Errorf("installing binary: %w", err)
			}
			fmt.Printf("installed binary -> %s\n", binTarget)
		} else {
			fmt.Printf("binary already at %s\n", binTarget)
		}

		// 2. Config dir + starter config (never overwrite an existing config).
		if err := os.MkdirAll(cfgDirPath, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", cfgDirPath, err)
		}
		if _, err := os.Stat(cfgFilePath); os.IsNotExist(err) {
			if err := os.WriteFile(cfgFilePath, starterConfig, 0o644); err != nil {
				return fmt.Errorf("writing starter config: %w", err)
			}
			fmt.Printf("wrote starter config -> %s (EDIT before starting)\n", cfgFilePath)
		} else {
			fmt.Printf("kept existing config %s\n", cfgFilePath)
		}
		if err := os.MkdirAll(logDirPath, 0o750); err != nil {
			fmt.Printf("warning: mkdir %s: %v\n", logDirPath, err)
		}

		// 3. Profile + service data -> /etc/mimic so the daemon (CWD=/) can find
		// them; the starter config points profiles_dir/services_dir here. Copied
		// from the current directory (run `install` from the source tree).
		for _, d := range []string{"profiles", "services"} {
			if _, err := os.Stat(d); err != nil {
				fmt.Printf("warning: ./%s not found — set %s_dir in config to an absolute path\n", d, d[:len(d)-1])
				continue
			}
			dst := filepath.Join(cfgDirPath, d)
			_ = os.RemoveAll(dst)
			if out, err := exec.Command("cp", "-r", d, dst).CombinedOutput(); err != nil {
				fmt.Printf("warning: copying %s: %s\n", d, out)
			} else {
				fmt.Printf("installed %s -> %s\n", d, dst)
			}
		}

		// 4. systemd unit + reload.
		if err := os.WriteFile(unitPath, systemdUnit, 0o644); err != nil {
			return fmt.Errorf("writing unit: %w", err)
		}
		fmt.Printf("wrote unit -> %s\n", unitPath)
		if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %s", out)
		}

		fmt.Printf("\nInstalled. Next:\n  1. edit %s (interface + profile)\n"+
			"  2. systemctl enable --now mimic\n  3. journalctl -u mimic -f\n", cfgFilePath)
		return nil
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the Mimic systemd service",
	Long: `Stops and disables the service and removes the unit. With --purge it
also tears down live state (incl. the clsact qdisc if Mimic was its sole user)
and removes /etc/mimic and the installed binary.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !platform.IsElevated() {
			return fmt.Errorf("this command requires %s privileges", platform.PrivilegeName())
		}

		_ = exec.Command("systemctl", "disable", "--now", "mimic").Run() //nolint:errcheck
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("warning: removing unit: %v\n", err)
		} else {
			fmt.Printf("removed %s\n", unitPath)
		}
		_ = exec.Command("systemctl", "daemon-reload").Run() //nolint:errcheck

		if uninstallPurge {
			rep := teardownStack(resolveIface(), true)
			fmt.Print(rep.String())
			for _, p := range []string{cfgFilePath, cfgDirPath, binTarget} {
				if err := os.RemoveAll(p); err != nil {
					fmt.Printf("warning: removing %s: %v\n", p, err)
				} else {
					fmt.Printf("removed %s\n", p)
				}
			}
		} else {
			fmt.Printf("kept %s and %s (use --purge to remove)\n", cfgDirPath, binTarget)
		}
		fmt.Println("Uninstalled.")
		return nil
	},
}

func init() {
	uninstallCmd.Flags().BoolVar(&uninstallPurge, "purge", false,
		"also tear down live state + remove config and binary")
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
}
