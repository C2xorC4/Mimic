package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/control"
)

var (
	ctlSocket string
	ctlNum    int
)

var ctlCmd = &cobra.Command{
	Use:   "ctl <status|logs|ping>",
	Short: "Query the running mimic control plane (RBAC-gated)",
	Long: `Connects to a running mimic instance's control socket and invokes a
control operation. Access is gated by the instance's RBAC config (peer uid/gid →
role → allowed operations); with no roles configured only root may connect.

Operations:
  status   profile, edition, services, pid, uptime, event count
  logs     recent security events (use -n)
  ping     liveness check`,
	Args: cobra.ExactArgs(1),
	RunE: runCtl,
}

func init() {
	ctlCmd.Flags().StringVar(&ctlSocket, "socket", "/run/mimic.sock", "control socket path")
	ctlCmd.Flags().IntVarP(&ctlNum, "num", "n", 20, "number of events (logs)")
	rootCmd.AddCommand(ctlCmd)
}

func runCtl(cmd *cobra.Command, args []string) error {
	conn, err := net.DialTimeout("unix", ctlSocket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connecting to control socket %s: %w (is mimic running with control.enabled?)", ctlSocket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := json.NewEncoder(conn).Encode(control.Request{Op: args[0], N: ctlNum}); err != nil {
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
