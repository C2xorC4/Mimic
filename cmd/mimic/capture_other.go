//go:build !linux || nopcap

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// On non-Linux platforms the capture command is omitted: live/pcap capture is a
// Linux operator workflow and links libpcap (gopacket/pcap → cgo/Npcap), which
// would otherwise force every deployed Windows honeypot binary to require Npcap
// just to run service emulation. A stub is registered so `mimic capture` returns
// a clear message instead of "unknown command". Windows capture (via Npcap) is a
// later item; the capture→template pipeline runs on the Linux build today.
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture probe/response pairs into service templates (Linux only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("capture is only available on the Linux build; run it on a Linux host")
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)
}
