package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/control"
)

var (
	ctlSocket string
	ctlNum    int
	ctlLines  int
	ctlFile   string
	ctlPatch  string
	ctlDryRun bool
)

var ctlCmd = &cobra.Command{
	Use:   "ctl <op>",
	Short: "Talk to the running mimic control plane (RBAC-gated)",
	Long: `Connects to a running mimic instance's control endpoint and invokes an
operation. Access is gated by RBAC; with no roles configured only the platform
admin principal may connect (root on Linux, Administrators on Windows).

Operations:
  ping              liveness check
  status            profile, services, pid, uptime, event count
  logs              recent in-memory security events (use -n)
  logs.file         tail a log file on disk (use --file, --lines)
  profiles.list     OS profiles available to this instance
  services.list     service templates available to this instance
  config.get        read editable config subset from disk
  config.set        apply a JSON patch (use --patch); saves to disk
  config.validate   validate --patch without writing
  services.restart  graceful stop + platform restart (alias: service.restart)
  services.stop     graceful stop without restart (alias: service.stop)
  services.start    start mimic (not implemented)`,
	Args: cobra.ExactArgs(1),
	RunE: runCtl,
}

func init() {
	ctlCmd.Flags().StringVar(&ctlSocket, "socket", control.DefaultEndpoint(), "control endpoint (unix socket or Windows named pipe)")
	ctlCmd.Flags().IntVarP(&ctlNum, "num", "n", 20, "number of in-memory events (logs)")
	ctlCmd.Flags().IntVar(&ctlLines, "lines", 50, "number of file lines (logs.file)")
	ctlCmd.Flags().StringVar(&ctlFile, "file", "events", "log file name (logs.file): events|mimic|probes")
	ctlCmd.Flags().StringVar(&ctlPatch, "patch", "", "JSON config patch (config.set / config.validate)")
	ctlCmd.Flags().BoolVar(&ctlDryRun, "dry-run", false, "validate only (config.set)")
	rootCmd.AddCommand(ctlCmd)
}

func runCtl(cmd *cobra.Command, args []string) error {
	conn, err := control.Dial(ctlSocket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connecting to control endpoint %s: %w (is mimic running with control.enabled?)", ctlSocket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	req := control.Request{Op: args[0], N: ctlNum, Lines: ctlLines, File: ctlFile, DryRun: ctlDryRun}
	if ctlPatch != "" {
		var patch control.ConfigPatch
		if err := json.Unmarshal([]byte(ctlPatch), &patch); err != nil {
			return fmt.Errorf("parsing --patch JSON: %w", err)
		}
		req.Patch = &patch
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	var resp control.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	b, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(b))
	if !resp.OK {
		os.Exit(1)
	}
	return nil
}