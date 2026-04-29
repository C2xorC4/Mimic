package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/services"
)

var (
	serveServices []string
	servicesDir   string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start service emulation listeners",
	Long: `Starts fake service listeners that respond to probes using captured
response templates. This is used to make a Linux system appear to be running
Windows services like SMB.

The service emulators use templates captured from real systems to provide
authentic-looking responses to scanning tools like nmap.

Example:
  # Start SMB emulation on port 445
  sudo mimic serve --services smb

  # Start multiple services
  sudo mimic serve --services smb,rdp,http`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringSliceVar(&serveServices, "services", []string{}, "Services to emulate (e.g., smb,rdp)")
	serveCmd.Flags().StringVar(&servicesDir, "services-dir", "./services", "Path to services directory")
	serveCmd.MarkFlagRequired("services")

	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("service emulation requires root privileges (binding to low ports)")
	}

	if len(serveServices) == 0 {
		return fmt.Errorf("no services specified")
	}

	// Create service manager
	mgr := services.NewManager(servicesDir)

	// List available services
	available, err := mgr.ListServices()
	if err != nil {
		log.Printf("Warning: Could not list services: %v", err)
	} else {
		log.Printf("Available services: %v", available)
	}

	// Load and start requested services
	for _, svcName := range serveServices {
		log.Printf("Loading service: %s", svcName)

		if err := mgr.LoadService(svcName); err != nil {
			return fmt.Errorf("loading service %s: %w", svcName, err)
		}

		cfg, _ := mgr.GetServiceInfo(svcName)
		log.Printf("  Port: %d/%s", cfg.Port, cfg.Protocol)
		log.Printf("  Probes defined: %d", len(cfg.Probes))

		if err := mgr.StartService(svcName); err != nil {
			return fmt.Errorf("starting service %s: %w", svcName, err)
		}

		log.Printf("  Started successfully")
	}

	fmt.Println()
	log.Println("Service emulation active. Press Ctrl+C to stop.")
	fmt.Println()

	// Wait for signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Print stats periodically
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			printServiceStats(mgr, serveServices)

		case sig := <-sigChan:
			fmt.Printf("\nReceived %v, shutting down...\n", sig)
			mgr.StopAll()
			log.Println("All services stopped.")
			return nil
		}
	}
}

func printServiceStats(mgr *services.Manager, serviceNames []string) {
	log.Println("--- Service Stats ---")
	for _, name := range serviceNames {
		cfg, running := mgr.GetServiceInfo(name)
		if cfg == nil {
			continue
		}
		status := "stopped"
		if running {
			status = "running"
		}
		log.Printf("  %s (port %d): %s", name, cfg.Port, status)
	}
}
