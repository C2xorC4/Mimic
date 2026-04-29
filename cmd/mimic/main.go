package main

import (
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/ebpf"
)

var (
	profilesDir string
	iface       string
	cfgFile     string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "mimic",
	Short: "OS fingerprint mimicry tool",
	Long: `Mimic modifies outgoing network packets to emulate the TCP/IP
stack fingerprint of a specified operating system, deceiving fingerprinting
tools like nmap.

Requires root privileges to load eBPF programs and attach to network interfaces.`,
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available OS profiles",
	Long:  "Lists all available OS fingerprint profiles organized by family (Windows, Linux, macOS).",
	RunE: func(cmd *cobra.Command, args []string) error {
		pm := config.NewProfileManager(profilesDir)
		if err := pm.LoadAllProfiles(); err != nil {
			return fmt.Errorf("loading profiles: %w", err)
		}

		profiles := pm.ListProfiles()
		if len(profiles) == 0 {
			fmt.Println("No profiles found in", profilesDir)
			return nil
		}

		// Sort families for consistent output
		families := make([]string, 0, len(profiles))
		for family := range profiles {
			families = append(families, family)
		}
		sort.Strings(families)

		for _, family := range families {
			names := profiles[family]
			sort.Strings(names)
			fmt.Printf("\n%s:\n", strings.Title(family))
			for _, name := range names {
				fmt.Printf("  - %s\n", name)
			}
		}
		fmt.Println()

		return nil
	},
}

var showCmd = &cobra.Command{
	Use:   "show [profile-name]",
	Short: "Show details of a specific profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pm := config.NewProfileManager(profilesDir)
		if err := pm.LoadAllProfiles(); err != nil {
			return fmt.Errorf("loading profiles: %w", err)
		}

		profile, err := pm.GetProfile(args[0])
		if err != nil {
			return err
		}

		fmt.Printf("Profile: %s\n", profile.Name)
		fmt.Printf("Description: %s\n", profile.Description)
		fmt.Printf("Family: %s\n", profile.Family)
		fmt.Printf("Version: %s\n\n", profile.Version)

		fmt.Println("Stack Configuration:")
		fmt.Printf("  TTL: %d\n", profile.Stack.TTL)
		fmt.Printf("  DF Bit: %v\n", profile.Stack.DFBit)
		fmt.Printf("  IP ID Behavior: %s\n", profile.Stack.IPIDBehavior)
		fmt.Printf("  Window Size: %d\n", profile.Stack.WindowSize)
		fmt.Printf("  Window Scale: %d\n", profile.Stack.WindowScale)
		fmt.Printf("  MSS: %d\n", profile.Stack.MSS)
		fmt.Printf("  TCP Timestamps: %v\n", profile.Stack.TCPTimestamps)
		fmt.Printf("  SACK Permitted: %v\n", profile.Stack.SACKPermitted)
		fmt.Printf("  TCP Options Order: %v\n", profile.Stack.TCPOptionsOrder)
		fmt.Printf("  ECN Support: %v\n", profile.Stack.ECNSupport)

		return nil
	},
}

var applyCmd = &cobra.Command{
	Use:   "apply [profile-name]",
	Short: "Apply an OS fingerprint profile to the system",
	Long: `Applies the specified OS fingerprint profile by loading an eBPF
program to the TC egress hook on the specified interface. The program will
modify outgoing packets to match the target OS's TCP/IP stack characteristics.

Requires root privileges.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("this command requires root privileges")
		}

		if iface == "" {
			return fmt.Errorf("interface not specified (use -i or --interface)")
		}

		// Load profile
		pm := config.NewProfileManager(profilesDir)
		if err := pm.LoadAllProfiles(); err != nil {
			return fmt.Errorf("loading profiles: %w", err)
		}

		profile, err := pm.GetProfile(args[0])
		if err != nil {
			return err
		}

		fmt.Printf("Applying profile: %s\n", profile.Name)
		fmt.Printf("Interface: %s\n", iface)

		// Create and load fingerprint manager
		fm, err := ebpf.NewFingerprintManager(iface)
		if err != nil {
			return fmt.Errorf("creating fingerprint manager: %w", err)
		}

		if err := fm.Load(); err != nil {
			return fmt.Errorf("loading eBPF program: %w", err)
		}

		// Set profile
		if err := fm.SetProfile(profile); err != nil {
			fm.Close()
			return fmt.Errorf("setting profile: %w", err)
		}

		// Enable
		if err := fm.Enable(); err != nil {
			fm.Close()
			return fmt.Errorf("enabling fingerprint modification: %w", err)
		}

		fmt.Printf("\nFingerprint modification active.\n")
		fmt.Printf("Spoofing as: %s\n", profile.Name)
		fmt.Printf("Press Ctrl+C to stop.\n\n")

		// Wait for signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\nShutting down...")
		if err := fm.Close(); err != nil {
			return fmt.Errorf("cleanup: %w", err)
		}

		fmt.Println("Done.")
		return nil
	},
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run mimic as a background daemon",
	Long: `Starts mimic as a daemon process that applies the configured
profile and runs in the background. Use with systemd or other init systems.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("this command requires root privileges")
		}

		// Load app config
		appCfg, err := config.LoadAppConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		if appCfg.Profile == "" {
			return fmt.Errorf("no profile configured in %s", cfgFile)
		}

		if appCfg.Interface == "" {
			if iface == "" {
				return fmt.Errorf("no interface configured")
			}
			appCfg.Interface = iface
		}

		// Use config values or CLI overrides
		if profilesDir == "./profiles" && appCfg.ProfilesDir != "" {
			profilesDir = appCfg.ProfilesDir
		}

		// Load profiles
		pm := config.NewProfileManager(profilesDir)
		if err := pm.LoadAllProfiles(); err != nil {
			return fmt.Errorf("loading profiles: %w", err)
		}

		profile, err := pm.GetProfile(appCfg.Profile)
		if err != nil {
			return err
		}

		fmt.Printf("Starting daemon with profile: %s on interface: %s\n",
			profile.Name, appCfg.Interface)

		// Create and load fingerprint manager
		fm, err := ebpf.NewFingerprintManager(appCfg.Interface)
		if err != nil {
			return fmt.Errorf("creating fingerprint manager: %w", err)
		}

		if err := fm.Load(); err != nil {
			return fmt.Errorf("loading eBPF program: %w", err)
		}

		if err := fm.SetProfile(profile); err != nil {
			fm.Close()
			return fmt.Errorf("setting profile: %w", err)
		}

		if err := fm.Enable(); err != nil {
			fm.Close()
			return fmt.Errorf("enabling: %w", err)
		}

		fmt.Printf("Daemon running. Spoofing as: %s\n", profile.Name)

		// Wait for signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("Daemon stopping...")
		fm.Close()
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&profilesDir, "profiles", "p", "./profiles",
		"Path to profiles directory")
	rootCmd.PersistentFlags().StringVarP(&iface, "interface", "i", "",
		"Network interface to attach to")
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/mimic/config.yaml",
		"Path to config file")

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(daemonCmd)
}
