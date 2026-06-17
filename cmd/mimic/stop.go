package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/ebpf"
)

// mimicNftTables are the nftables tables Mimic owns and may delete wholesale.
// mimic_reject: closed-port RST + T2/T3 probe responses (internal/services).
// mimic_block:  defense blocker drop set (internal/defense).
// Mimic only ever creates/deletes these named tables, never another tool's ruleset.
var mimicNftTables = []string{"mimic_reject", "mimic_block"}

var stopPurge bool

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Tear down all Mimic host state (idempotent; safe after a crash)",
	Long: `Removes Mimic's TC filters (by BPF name, both clsact hooks) and its
nftables tables. It is stateless and idempotent — safe to run even when no mimic
process is active, to clean up orphaned state after a crash or SIGKILL.

The clsact qdisc is left in place by default (a co-tenant may share it). With
--purge it is removed too, but only if Mimic was its sole user (no other filters
remain after ours are stripped).

Used as the systemd unit's ExecStopPost safety net, and for manual cleanup.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("this command requires root privileges")
		}
		rep := teardownStack(resolveIface(), stopPurge)
		fmt.Print(rep.String())
		return nil
	},
}

func init() {
	stopCmd.Flags().BoolVar(&stopPurge, "purge", false,
		"also remove the clsact qdisc if Mimic is its only user")
	rootCmd.AddCommand(stopCmd)
}

// resolveIface picks the interface from -i, else the config file's interface.
func resolveIface() string {
	if iface != "" {
		return iface
	}
	if appCfg, err := config.LoadAppConfig(cfgFile); err == nil {
		return appCfg.Interface
	}
	return ""
}

// teardownReport summarizes an idempotent teardown for logging/printing.
type teardownReport struct {
	Iface    string
	NftFreed []string
	TC       ebpf.TeardownResult
	TCErr    error
}

func (r teardownReport) String() string {
	s := fmt.Sprintf("nft: deleted tables %v\n", r.NftFreed)
	if r.Iface == "" {
		return s + "tc: no interface resolved (skipped)\n"
	}
	if r.TCErr != nil {
		return s + fmt.Sprintf("tc: %v\n", r.TCErr)
	}
	s += fmt.Sprintf("tc: removed %d Mimic filter(s) on %s", r.TC.FiltersRemoved, r.Iface)
	switch {
	case r.TC.QdiscRemoved:
		s += "; removed clsact qdisc (Mimic was sole user)"
	case r.TC.ForeignFilters > 0:
		s += fmt.Sprintf("; left clsact qdisc (%d foreign filter(s))", r.TC.ForeignFilters)
	}
	return s + "\n"
}

// teardownStack removes all host-visible Mimic state. Idempotent and stateless;
// shared by the `stop` command and clean-on-start in `run`.
func teardownStack(ifn string, purgeQdisc bool) teardownReport {
	rep := teardownReport{Iface: ifn}

	// nftables: delete our named tables. Check existence first so the report
	// reflects what was actually removed (not just attempted).
	for _, tbl := range mimicNftTables {
		if exec.Command("nft", "list", "table", "inet", tbl).Run() != nil {
			continue // absent
		}
		_ = exec.Command("nft", "delete", "table", "inet", tbl).Run() //nolint:errcheck
		rep.NftFreed = append(rep.NftFreed, tbl)
	}

	// TC filters (+ optional content-diff qdisc purge).
	if ifn != "" {
		rep.TC, rep.TCErr = ebpf.TeardownInterface(ifn, purgeQdisc)
	}
	return rep
}
