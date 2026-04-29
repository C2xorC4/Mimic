package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/ebpf"
	"github.com/c2xorc4/mimic/internal/logging"
	"github.com/c2xorc4/mimic/internal/services"
)

var runCmd = &cobra.Command{
	Use:   "run [profile-name]",
	Short: "Run full deception (eBPF fingerprint + service emulation)",
	Long: `Starts both eBPF stack fingerprinting and service emulation concurrently.
Reads configuration from the config file to determine which OS profile to apply
and which services to emulate.

This is the recommended way to run mimic for full OS deception.

Example:
  # Run with profile and services
  sudo mimic run "Windows 11" -i eth0 --services smb,msrpc,netbios --closed-ports 8080,8443

  # Run with config file
  sudo mimic run -c /etc/mimic/config.yaml

Config file example:
  profile: "Windows 11"
  interface: eth0
  services:
    - smb
    - msrpc
    - netbios
  closed_ports:
    - 8080
    - 8443
  service_options:
    netbios_name: "WORKSTATION"
    domain: "WORKGROUP"
  logging:
    level: info
    log_dir: /var/log/mimic
    json_mode: true`,
	Args: cobra.MaximumNArgs(1),
	RunE: runMimic,
}

var (
	runProfile     string
	runServices    []string
	runClosedPorts []int
)

func init() {
	runCmd.Flags().StringVar(&runProfile, "profile", "", "OS profile to apply (overrides config)")
	runCmd.Flags().StringSliceVar(&runServices, "services", []string{}, "Services to emulate (overrides config)")
	runCmd.Flags().IntSliceVar(&runClosedPorts, "closed-ports", []int{}, "Ports that appear closed (RST on connect, for OS fingerprinting)")
	runCmd.Flags().StringVar(&servicesDir, "services-dir", "./services", "Path to services directory")

	rootCmd.AddCommand(runCmd)
}

func runMimic(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges")
	}

	// Load app config
	appCfg, err := config.LoadAppConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// CLI overrides - positional arg takes precedence
	if len(args) > 0 {
		appCfg.Profile = args[0]
	} else if runProfile != "" {
		appCfg.Profile = runProfile
	}
	if len(runServices) > 0 {
		appCfg.Services = runServices
	}
	if iface != "" {
		appCfg.Interface = iface
	}
	if profilesDir != "./profiles" {
		appCfg.ProfilesDir = profilesDir
	}
	if servicesDir != "./services" {
		appCfg.ServicesDir = servicesDir
	}
	if len(runClosedPorts) > 0 {
		appCfg.ClosedPorts = make([]uint16, len(runClosedPorts))
		for i, p := range runClosedPorts {
			appCfg.ClosedPorts[i] = uint16(p)
		}
	}

	// Handle legacy config fields
	if appCfg.Logging.Level == "" && appCfg.LogLevel != "" {
		appCfg.Logging.Level = appCfg.LogLevel
	}

	// Initialize logging - config loader provides defaults
	logCfg := logging.Config{
		Level:    appCfg.Logging.Level,
		LogDir:   appCfg.Logging.LogDir,
		JSONMode: appCfg.Logging.JSONMode,
		ToStdout: appCfg.Logging.ToStdout,
	}
	// Ensure we have a level (config loader should set this, but just in case)
	if logCfg.Level == "" {
		logCfg.Level = "info"
	}

	if err := logging.Init(logCfg); err != nil {
		return fmt.Errorf("initializing logging: %w", err)
	}
	defer logging.Shutdown()

	// Validate required fields
	if appCfg.Interface == "" {
		return fmt.Errorf("interface not specified (use -i or config file)")
	}
	if appCfg.Profile == "" && len(appCfg.Services) == 0 {
		return fmt.Errorf("no profile or services specified")
	}

	// Log startup info
	logging.Info("Mimic starting", map[string]interface{}{
		"interface": appCfg.Interface,
		"profile":   appCfg.Profile,
		"services":  appCfg.Services,
	})

	if appCfg.ServiceOptions.NetBIOSName != "" {
		logging.Info("Service options", map[string]interface{}{
			"netbios_name": appCfg.ServiceOptions.NetBIOSName,
			"domain":       appCfg.ServiceOptions.Domain,
		})
	}

	// Channel to collect errors from goroutines
	errChan := make(chan error, 2)

	// WaitGroup for cleanup coordination
	var wg sync.WaitGroup

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Context for shutdown coordination
	shutdown := make(chan struct{})

	var fm *ebpf.FingerprintManager
	var svcMgr *services.Manager
	var closedMgr *services.ClosedPortManager

	// Start closed port listeners (optional - may fail if netfilter unavailable)
	if len(appCfg.ClosedPorts) > 0 {
		closedMgr = services.NewClosedPortManager()
		if err := closedMgr.AddPorts(appCfg.ClosedPorts); err != nil {
			logging.Warn("Closed ports unavailable - OS fingerprinting may be incomplete", map[string]interface{}{
				"error": err.Error(),
				"hint":  "Ensure kernel has nf_tables or ip_tables modules loaded",
			})
			closedMgr = nil // Continue without closed ports
		} else {
			logging.Info("Closed ports active", map[string]interface{}{
				"ports": appCfg.ClosedPorts,
			})
		}
	}

	// Start eBPF fingerprinting in goroutine
	if appCfg.Profile != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()

			ebpfLog := logging.Component("ebpf")

			// Load profile
			pm := config.NewProfileManager(appCfg.ProfilesDir)
			if err := pm.LoadAllProfiles(); err != nil {
				errChan <- fmt.Errorf("loading profiles: %w", err)
				return
			}

			profile, err := pm.GetProfile(appCfg.Profile)
			if err != nil {
				errChan <- fmt.Errorf("getting profile: %w", err)
				return
			}

			// Create and load fingerprint manager
			fm, err = ebpf.NewFingerprintManager(appCfg.Interface)
			if err != nil {
				errChan <- fmt.Errorf("creating fingerprint manager: %w", err)
				return
			}

			if err := fm.Load(); err != nil {
				errChan <- fmt.Errorf("loading eBPF program: %w", err)
				return
			}

			if err := fm.SetProfile(profile); err != nil {
				fm.Close()
				errChan <- fmt.Errorf("setting profile: %w", err)
				return
			}

			if err := fm.Enable(); err != nil {
				fm.Close()
				errChan <- fmt.Errorf("enabling fingerprint: %w", err)
				return
			}

			ebpfLog.Info("Stack fingerprinting active", map[string]interface{}{
				"profile": profile.Name,
			})

			// Wait for shutdown
			<-shutdown
			ebpfLog.Info("Shutting down", nil)
			fm.Close()
		}()
	}

	// Start service emulation in goroutine
	if len(appCfg.Services) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			svcMgr = services.NewManager(appCfg.ServicesDir)

			// Set service options if available
			if appCfg.ServiceOptions.NetBIOSName != "" {
				svcMgr.SetOption("netbios_name", appCfg.ServiceOptions.NetBIOSName)
			}
			if appCfg.ServiceOptions.Domain != "" {
				svcMgr.SetOption("domain", appCfg.ServiceOptions.Domain)
			}
			if appCfg.ServiceOptions.Hostname != "" {
				svcMgr.SetOption("hostname", appCfg.ServiceOptions.Hostname)
			}
			if appCfg.ServiceOptions.MACAddress != "" {
				svcMgr.SetOption("mac_address", appCfg.ServiceOptions.MACAddress)
			}
			// Set jitter options
			if appCfg.ServiceOptions.JitterMinMs > 0 {
				svcMgr.SetOption("jitter_min_ms", fmt.Sprintf("%d", appCfg.ServiceOptions.JitterMinMs))
			}
			if appCfg.ServiceOptions.JitterMaxMs > 0 {
				svcMgr.SetOption("jitter_max_ms", fmt.Sprintf("%d", appCfg.ServiceOptions.JitterMaxMs))
			}

			// Load and start services
			for _, svcName := range appCfg.Services {
				if err := svcMgr.LoadService(svcName); err != nil {
					errChan <- fmt.Errorf("loading service %s: %w", svcName, err)
					return
				}

				if err := svcMgr.StartService(svcName); err != nil {
					errChan <- fmt.Errorf("starting service %s: %w", svcName, err)
					return
				}
			}

			// Wait for shutdown
			<-shutdown
			logging.Info("Shutting down services", nil)
			svcMgr.StopAll()
		}()
	}

	// Give goroutines time to start and report errors
	time.Sleep(500 * time.Millisecond)

	// Check for early errors
	select {
	case err := <-errChan:
		close(shutdown)
		wg.Wait()
		if closedMgr != nil {
			closedMgr.StopAll()
		}
		return err
	default:
	}

	logging.Info("Mimic active", map[string]interface{}{
		"log_dir": logging.GetActiveLogDir(),
	})
	fmt.Printf("\nMimic active. Logs: %s\nPress Ctrl+C to stop.\n\n", logging.GetActiveLogDir())

	// Stats ticker
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Main loop
	for {
		select {
		case err := <-errChan:
			close(shutdown)
			wg.Wait()
			if closedMgr != nil {
				closedMgr.StopAll()
			}
			return err

		case <-ticker.C:
			if svcMgr != nil {
				logRunStats(svcMgr, appCfg.Services)
			}

		case sig := <-sigChan:
			logging.Info("Signal received", map[string]interface{}{
				"signal": sig.String(),
			})
			fmt.Printf("\nReceived %v, shutting down...\n", sig)
			close(shutdown)
			wg.Wait()
			if closedMgr != nil {
				closedMgr.StopAll()
			}
			logging.Info("Mimic stopped", nil)
			return nil
		}
	}
}

func logRunStats(mgr *services.Manager, serviceNames []string) {
	for _, name := range serviceNames {
		stats, err := mgr.GetServiceStats(name)
		if err != nil {
			continue
		}
		logging.Info("Service stats", map[string]interface{}{
			"service":        name,
			"connections":    stats.Connections,
			"probes_matched": stats.ProbesMatched,
			"probes_missed":  stats.ProbesMissed,
			"bytes_received": stats.BytesReceived,
			"bytes_sent":     stats.BytesSent,
		})
	}
}
