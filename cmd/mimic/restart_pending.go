package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/logging"
	"github.com/c2xorc4/mimic/internal/platform"
)

var (
	restartParentPID int
	restartViaSvc    bool
)

var restartPendingCmd = &cobra.Command{
	Use:    "restart-pending",
	Hidden: true,
	Short:  "Internal helper: restart Mimic after the parent process exits",
	RunE: func(cmd *cobra.Command, args []string) error {
		if restartParentPID <= 0 {
			return fmt.Errorf("--parent-pid is required")
		}
		if !platform.WaitForProcessExit(restartParentPID, platform.RestartWaitTimeout) {
			appendRestartPendingLog(cfgFile, fmt.Sprintf("warning: parent pid %d still alive after timeout; attempting restart anyway", restartParentPID))
		}
		if err := platform.PerformPendingRestart(cfgFile, restartViaSvc); err != nil {
			appendRestartPendingLog(cfgFile, fmt.Sprintf("restart failed (via_service=%v): %v", restartViaSvc, err))
			return fmt.Errorf("restart: %w", err)
		}
		appendRestartPendingLog(cfgFile, fmt.Sprintf("restart spawned (via_service=%v, config=%q) — new mimic run is detached; check mimic ctl ping or mimic.log", restartViaSvc, cfgFile))
		return nil
	},
}

func init() {
	restartPendingCmd.Flags().IntVar(&restartParentPID, "parent-pid", 0, "PID of the exiting mimic process")
	restartPendingCmd.Flags().BoolVar(&restartViaSvc, "via-service", false, "Restart via OS service manager instead of spawning mimic run")
	rootCmd.AddCommand(restartPendingCmd)
}

// appendRestartPendingLog records restart-helper diagnostics when the main logger
// is not initialized (detached helper process).
func appendRestartPendingLog(cfgFile, message string) {
	logDir := logging.DefaultFallbackDir
	if cfgFile != "" {
		if cfg, err := config.LoadAppConfig(cfgFile); err == nil && cfg.Logging.LogDir != "" {
			logDir = cfg.Logging.LogDir
		}
	}
	_ = os.MkdirAll(logDir, 0755)
	path := filepath.Join(logDir, "restart-pending.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", message)
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), message)
}