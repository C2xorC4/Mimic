package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/capture"
)

var (
	captureIface   string
	capturePorts   []uint16
	captureServerIP string
	captureOutput  string
	captureService string
	captureOS      string
	capturePcap    string
)

var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture probe/response pairs for service emulation",
	Long: `Captures network traffic to extract probe/response pairs that can
be replayed for service emulation. Run this on a target system (e.g., Windows)
while scanning with nmap to automatically record service responses.

The captured data is used to generate service templates for the emulation layer.`,
}

var captureLiveCmd = &cobra.Command{
	Use:   "live",
	Short: "Capture live traffic from an interface",
	Long: `Captures live network traffic from the specified interface.
Run this on the target system while scanning with nmap or other tools.

Example:
  # On Windows target, capture SMB traffic while being scanned
  deceiver capture live -i eth0 --ports 445 --server-ip 192.168.1.100 --service smb --os "Windows 10"

Then from attacker machine:
  nmap -sV -p445 --script smb-* 192.168.1.100`,
	RunE: runCaptureLive,
}

var capturePcapCmd = &cobra.Command{
	Use:   "pcap [file]",
	Short: "Process a pcap file to extract probe/response pairs",
	Long: `Processes a previously captured pcap file to extract probe/response pairs.
Useful when you've captured traffic with Wireshark or tcpdump and want to
process it offline.

Example:
  # Capture with tcpdump on target
  tcpdump -i eth0 -w smb_capture.pcap port 445

  # Process the capture
  deceiver capture pcap smb_capture.pcap --server-ip 192.168.1.100 --service smb --os "Windows 10"`,
	Args: cobra.ExactArgs(1),
	RunE: runCapturePcap,
}

var captureGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate service templates from captured sessions",
	Long: `After capturing traffic (live or from pcap), use this command to
generate service template files that can be used for emulation.

This command:
1. Analyzes captured probe/response pairs
2. Identifies dynamic fields (timestamps, GUIDs, etc.)
3. Generates manifest.yaml with probe signatures
4. Saves response templates as binary files`,
	RunE: runCaptureGenerate,
}

func init() {
	// Live capture flags
	captureLiveCmd.Flags().StringVarP(&captureIface, "interface", "i", "", "Network interface to capture on (required)")
	captureLiveCmd.Flags().StringVar(&captureServerIP, "server-ip", "", "Server IP address to identify direction (required)")
	captureLiveCmd.Flags().StringVar(&captureService, "service", "", "Service name (e.g., smb, rdp, http) (required)")
	captureLiveCmd.Flags().StringVar(&captureOS, "os", "", "Source OS name (e.g., 'Windows 10') (required)")
	captureLiveCmd.Flags().StringVarP(&captureOutput, "output", "o", "./captures", "Output directory for captures")
	captureLiveCmd.MarkFlagRequired("interface")
	captureLiveCmd.MarkFlagRequired("server-ip")
	captureLiveCmd.MarkFlagRequired("service")
	captureLiveCmd.MarkFlagRequired("os")

	// Pcap processing flags
	capturePcapCmd.Flags().StringVar(&captureServerIP, "server-ip", "", "Server IP address to identify direction (required)")
	capturePcapCmd.Flags().StringVar(&captureService, "service", "", "Service name (required)")
	capturePcapCmd.Flags().StringVar(&captureOS, "os", "", "Source OS name (required)")
	capturePcapCmd.Flags().StringVarP(&captureOutput, "output", "o", "./captures", "Output directory")
	capturePcapCmd.MarkFlagRequired("server-ip")
	capturePcapCmd.MarkFlagRequired("service")
	capturePcapCmd.MarkFlagRequired("os")

	// Generate flags
	captureGenerateCmd.Flags().StringVar(&captureService, "service", "", "Service name (required)")
	captureGenerateCmd.Flags().StringVar(&captureOS, "os", "", "Source OS name (required)")
	captureGenerateCmd.Flags().StringVarP(&captureOutput, "output", "o", "", "Output directory for templates (default: services/<service>)")
	captureGenerateCmd.Flags().StringVar(&capturePcap, "pcap", "", "Pcap file to process")
	captureGenerateCmd.MarkFlagRequired("service")
	captureGenerateCmd.MarkFlagRequired("os")

	// Port flag for all capture commands (no shorthand to avoid conflict with -p profiles)
	captureCmd.PersistentFlags().StringSlice("ports", []string{}, "Ports to capture (e.g., 445,3389)")

	captureCmd.AddCommand(captureLiveCmd)
	captureCmd.AddCommand(capturePcapCmd)
	captureCmd.AddCommand(captureGenerateCmd)
	rootCmd.AddCommand(captureCmd)
}

func parsePorts(cmd *cobra.Command) ([]uint16, error) {
	portStrs, _ := cmd.Flags().GetStringSlice("ports")
	ports := make([]uint16, 0, len(portStrs))

	for _, ps := range portStrs {
		// Handle comma-separated values
		for _, p := range strings.Split(ps, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			port, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", p, err)
			}
			ports = append(ports, uint16(port))
		}
	}

	// Default ports based on service if not specified
	if len(ports) == 0 && captureService != "" {
		switch strings.ToLower(captureService) {
		case "smb":
			ports = []uint16{445, 139}
		case "rdp":
			ports = []uint16{3389}
		case "http":
			ports = []uint16{80, 8080}
		case "https":
			ports = []uint16{443, 8443}
		case "ssh":
			ports = []uint16{22}
		case "ftp":
			ports = []uint16{21}
		case "mssql":
			ports = []uint16{1433}
		case "mysql":
			ports = []uint16{3306}
		case "ldap":
			ports = []uint16{389, 636}
		}
	}

	return ports, nil
}

func runCaptureLive(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("live capture requires root privileges")
	}

	serverIP := net.ParseIP(captureServerIP)
	if serverIP == nil {
		return fmt.Errorf("invalid server IP: %s", captureServerIP)
	}

	ports, err := parsePorts(cmd)
	if err != nil {
		return err
	}

	if len(ports) == 0 {
		return fmt.Errorf("no ports specified and couldn't infer from service name")
	}

	fmt.Printf("Starting live capture on %s\n", captureIface)
	fmt.Printf("Server IP: %s\n", serverIP)
	fmt.Printf("Ports: %v\n", ports)
	fmt.Printf("Service: %s\n", captureService)
	fmt.Printf("Source OS: %s\n", captureOS)
	fmt.Printf("\nPress Ctrl+C to stop capture and generate templates.\n\n")

	lc, err := capture.NewLiveCapture(captureIface, []net.IP{serverIP}, ports)
	if err != nil {
		return fmt.Errorf("initializing capture: %w", err)
	}

	lc.Start()

	// Wait for signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Print stats periodically
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats := lc.GetStats()
			fmt.Printf("\rPackets: %d total, %d captured, %d TCP, %d UDP",
				stats.TotalPackets, stats.CapturedPackets, stats.TCPPackets, stats.UDPPackets)

		case <-sigChan:
			fmt.Println("\n\nStopping capture...")
			lc.Stop()

			sessions := lc.GetSessions()
			stats := lc.GetStats()

			fmt.Printf("Captured %d sessions\n", len(sessions))
			fmt.Printf("Stats: %d total packets, %d captured\n", stats.TotalPackets, stats.CapturedPackets)

			if len(sessions) == 0 {
				fmt.Println("No sessions captured. Check that:")
				fmt.Println("  - Traffic is reaching this interface")
				fmt.Println("  - Server IP is correct")
				fmt.Println("  - Ports are correct")
				return nil
			}

			// Generate templates
			return generateTemplates(sessions)
		}
	}
}

func runCapturePcap(cmd *cobra.Command, args []string) error {
	pcapFile := args[0]

	serverIP := net.ParseIP(captureServerIP)
	if serverIP == nil {
		return fmt.Errorf("invalid server IP: %s", captureServerIP)
	}

	ports, err := parsePorts(cmd)
	if err != nil {
		return err
	}

	fmt.Printf("Processing pcap: %s\n", pcapFile)
	fmt.Printf("Server IP: %s\n", serverIP)
	fmt.Printf("Ports: %v\n", ports)
	fmt.Printf("Service: %s\n", captureService)
	fmt.Printf("Source OS: %s\n", captureOS)
	fmt.Println()

	processor := capture.NewPCAPProcessor([]net.IP{serverIP}, ports)
	if err := processor.ProcessFile(pcapFile); err != nil {
		return fmt.Errorf("processing pcap: %w", err)
	}

	sessions := processor.GetSessions()
	stats := processor.GetStats()

	fmt.Printf("Processed %d packets\n", stats.TotalPackets)
	fmt.Printf("Found %d sessions with %d exchanges\n", stats.Sessions, stats.Exchanges)

	if len(sessions) == 0 {
		fmt.Println("No sessions found. Check that:")
		fmt.Println("  - Server IP matches traffic in pcap")
		fmt.Println("  - Ports are correct")
		return nil
	}

	return generateTemplates(sessions)
}

func runCaptureGenerate(cmd *cobra.Command, args []string) error {
	if capturePcap == "" {
		return fmt.Errorf("--pcap flag is required for generate command")
	}

	serverIP := net.ParseIP(captureServerIP)
	if serverIP == nil {
		// Try to auto-detect from pcap
		fmt.Println("Warning: No server IP specified, attempting auto-detection...")
		serverIP = net.IPv4(0, 0, 0, 0) // Will need smarter detection
	}

	ports, err := parsePorts(cmd)
	if err != nil {
		return err
	}

	processor := capture.NewPCAPProcessor([]net.IP{serverIP}, ports)
	if err := processor.ProcessFile(capturePcap); err != nil {
		return fmt.Errorf("processing pcap: %w", err)
	}

	sessions := processor.GetSessions()
	return generateTemplates(sessions)
}

func generateTemplates(sessions []*capture.Session) error {
	if captureOutput == "" {
		captureOutput = filepath.Join("services", captureService)
	}

	fmt.Printf("Generating templates in %s\n", captureOutput)

	generator := capture.NewTemplateGenerator(captureOutput, captureService, captureOS)

	exchangeCount := 0
	for _, session := range sessions {
		generator.AddSession(session)
		exchangeCount += len(session.Exchanges)
	}

	if exchangeCount == 0 {
		fmt.Println("No probe/response exchanges found in sessions")
		return nil
	}

	output, err := generator.Generate()
	if err != nil {
		return fmt.Errorf("generating templates: %w", err)
	}

	fmt.Printf("\nGenerated:\n")
	fmt.Printf("  Manifest: %s\n", output.ManifestPath)
	fmt.Printf("  Response files: %d\n", len(output.ResponseFiles))
	fmt.Printf("  Capture metadata: %d\n", len(output.CaptureFiles))

	fmt.Println("\nNext steps:")
	fmt.Printf("1. Review the generated manifest at %s\n", output.ManifestPath)
	fmt.Println("2. Run additional captures to improve dynamic field detection")
	fmt.Println("3. Use 'deceiver serve' to test emulation (coming soon)")

	return nil
}
