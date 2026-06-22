package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/coherence"
	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/deception"
	"github.com/c2xorc4/mimic/internal/defense"
	"github.com/c2xorc4/mimic/internal/ebpf"
	"github.com/c2xorc4/mimic/internal/events"
	honeyftp "github.com/c2xorc4/mimic/internal/honeypot/ftp"
	honeyrdp "github.com/c2xorc4/mimic/internal/honeypot/rdp"
	honeysmb "github.com/c2xorc4/mimic/internal/honeypot/smb"
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
  sudo mimic run "Windows 11" -i eth0 --services all --closed-ports 8080,8443
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
	runCmd.Flags().StringSliceVar(&runServices, "services", []string{}, "Services to emulate, or 'all' for full catalog with edition gating (overrides config)")
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

	// Security-event pipeline (SIEM ingest + detection feed). On by default with an
	// NDJSON event log; honeypots emit via the global emitter.
	evCfg := appCfg.Events
	evCfg.Enabled = true
	if !evCfg.JSONFile && !evCfg.Syslog.Enabled {
		evCfg.JSONFile = true
	}
	evBus, err := events.Init(evCfg, logging.GetActiveLogDir(), func(sink string, e error) {
		logging.Error("event sink failed", map[string]interface{}{"sink": sink, "error": e.Error()})
	})
	if err != nil {
		return fmt.Errorf("initializing events: %w", err)
	}
	defer events.CloseGlobal()
	if evBus != nil {
		logging.Info("Event pipeline active", map[string]interface{}{"sinks": evBus.Sinks()})

		// Abuse detection + active response. The detector is a sink on the event
		// bus; the blocker defaults to alert-only (dry-run) and always honors the
		// whitelist. Enforcement is opt-in via defense.enforce.
		defCfg := appCfg.Defense
		defCfg.Enabled = true // detection on by default (alert-only)
		blocker := defense.NewBlocker(defCfg)
		evBus.AddSink(defense.NewDetector(defCfg, blocker))
		defer blocker.Close()
		logging.Info("Defense active", map[string]interface{}{
			"enforce":   defCfg.Enforce,
			"whitelist": len(defCfg.Whitelist),
		})
	}

	// Validate required fields
	if appCfg.Interface == "" {
		return fmt.Errorf("interface not specified (use -i or config file)")
	}
	if appCfg.Profile == "" && len(appCfg.Services) == 0 {
		return fmt.Errorf("no profile or services specified")
	}

	if appCfg.ServiceOptions.NetBIOSName != "" {
		logging.Info("Service options", map[string]interface{}{
			"netbios_name": appCfg.ServiceOptions.NetBIOSName,
			"domain":       appCfg.ServiceOptions.Domain,
		})
	}

	// Load OS profile once so both eBPF and service layers share the same instance
	var profile *config.OSProfile
	if appCfg.Profile != "" {
		pm := config.NewProfileManager(appCfg.ProfilesDir)
		if err := pm.LoadAllProfiles(); err != nil {
			return fmt.Errorf("loading profiles: %w", err)
		}
		p, err := pm.GetProfile(appCfg.Profile)
		if err != nil {
			return fmt.Errorf("getting profile %q: %w", appCfg.Profile, err)
		}
		profile = p
	}

	// Expand "all", drop templates superseded by honeypots, edition-gate 135/139.
	if len(appCfg.Services) > 0 {
		resolved, err := config.ResolveRunServices(appCfg.Services, appCfg.ServicesDir, profile)
		if err != nil {
			return fmt.Errorf("resolving services: %w", err)
		}
		appCfg.Services = resolved
	}

	// Log startup info (after resolution so "all" shows the concrete list).
	logging.Info("Mimic starting", map[string]interface{}{
		"interface": appCfg.Interface,
		"profile":   appCfg.Profile,
		"services":  appCfg.Services,
	})

	// Build the shared credential pool (used by the SMB honeypot to accept creds
	// and by leaking services to emit them) and validate the leak wiring. seed_file
	// paths in the SMB filesystem config resolve relative to the config file.
	credStore := buildCredStore(appCfg.Credentials)
	validateLeaks(appCfg)
	configDir := "."
	if cfgFile != "" {
		configDir = filepath.Dir(cfgFile)
	}

	// Clean any stale Mimic state from a prior unclean exit (orphaned TC filters
	// or nft tables) so this run starts from a known-clean stack. Idempotent;
	// leaves the clsact qdisc in place (purge=false) for co-tenant safety.
	if rep := teardownStack(appCfg.Interface, false); rep.TC.FiltersRemoved > 0 || len(rep.NftFreed) > 0 {
		logging.Info("Cleaned stale Mimic state before start", map[string]interface{}{
			"tc_filters_removed": rep.TC.FiltersRemoved,
			"nft_tables_removed": rep.NftFreed,
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
	var probeMgr *services.ProbeResponseManager
	var fwMgr *services.FirewallManager

	// Start closed port listeners (optional - may fail if netfilter unavailable)
	if len(appCfg.ClosedPorts) > 0 {
		closedMgr = services.NewClosedPortManager()
		if err := closedMgr.AddPorts(appCfg.ClosedPorts); err != nil {
			logging.Warn("Closed ports unavailable - OS fingerprinting may be incomplete", map[string]interface{}{
				"error": err.Error(),
				"hint":  "Ensure kernel has nf_tables or nft_reject_inet modules loaded",
			})
			closedMgr = nil // Continue without closed ports
		} else {
			logging.Info("Closed ports active", map[string]interface{}{
				"ports": appCfg.ClosedPorts,
			})
		}
	}

	// Start T2/T3 probe response rules (nmap OS fingerprint probes, all ports)
	probeMgr = services.NewProbeResponseManager()
	if err := probeMgr.Start(); err != nil {
		logging.Warn("T2/T3 probe response unavailable", map[string]interface{}{
			"error": err.Error(),
		})
		probeMgr = nil
	}

	// Closed-port disposition. Workstation editions DEFAULT to the firewalled-Windows
	// persona (default-drop): unserved ports — including 135/139/445 — read as
	// FILTERED, matching a real firewalled Win11 client (OSE-2026-001 Op-1 dropped
	// ~all ports; closed-not-filtered on the server ports was the server-vs-client
	// tell). The allow-list is DERIVED from the actually-served decoy ports so the
	// client persona's open surface (3389/5040/5357/5985/7680, etc.) stays reachable.
	// Operators opt out with closed_port_behavior: reset (keeps the nmap closed-port
	// probe for higher -O confidence, at the cost of the persona). Other editions
	// only drop when explicitly configured.
	//
	// Rules are added AFTER the T2/T3 + closed-port rules so those terminal RST rules
	// match first and the default-drop catches only the remaining (filtered) ports.
	// Established connections are always accepted, so applying this never severs the
	// live SSH session — but new logins need their port in firewall.preserve_ports.
	fwBehavior := strings.ToLower(appCfg.Firewall.ClosedPortBehavior)
	isWorkstation := profile != nil && profile.ResolvedEdition() == "workstation"
	autoDrop := isWorkstation && fwBehavior != "reset"
	if fwBehavior == "drop" || fwBehavior == "filtered" || autoDrop {
		openPorts := appCfg.Firewall.OpenPorts
		if autoDrop {
			// Derive the allow-list from the served decoy ports (+ any configured ones)
			// so the workstation persona doesn't filter its own open ports.
			openPorts = mergeUint16(openPorts, config.ServiceListenPorts(appCfg.Services, profile, appCfg.ServicesDir))
		}
		fwMgr = services.NewFirewallManager()
		if err := fwMgr.EnableDrop(openPorts, appCfg.Firewall.PreservePorts); err != nil {
			logging.Warn("Default-drop firewall unavailable — closed ports will RST (Linux default), a Windows-client persona tell", map[string]interface{}{
				"error": err.Error(),
			})
			fwMgr = nil
		} else if autoDrop {
			logging.Info("Workstation persona: firewalled-client default-drop active (135/139/445 + unserved ports → filtered)", map[string]interface{}{
				"open_ports":     openPorts,
				"preserve_ports": appCfg.Firewall.PreservePorts,
			})
		}
	}
	// Workstation persona: drop inbound ping (Op-1 control filtered ICMP entirely).
	if isWorkstation {
		if fwMgr == nil {
			fwMgr = services.NewFirewallManager()
		}
		if err := fwMgr.EnableICMPDrop(); err != nil {
			logging.Warn("ICMP drop unavailable — host will answer ping unlike a firewalled Win11 client", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Start eBPF fingerprinting in goroutine
	if profile != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			ebpfLog := logging.Component("ebpf")

			// Create and load fingerprint manager
			var err error
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
			// Shared credential store so services can emit leaked creds.
			svcMgr.SetCredStore(credStore)

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
			// Apply profile-derived service options (e.g. smb1_enabled)
			svcMgr.SetProfileOptions(profile)
			// Set jitter options
			if appCfg.ServiceOptions.JitterMinMs > 0 {
				svcMgr.SetOption("jitter_min_ms", fmt.Sprintf("%d", appCfg.ServiceOptions.JitterMinMs))
			}
			if appCfg.ServiceOptions.JitterMaxMs > 0 {
				svcMgr.SetOption("jitter_max_ms", fmt.Sprintf("%d", appCfg.ServiceOptions.JitterMaxMs))
			}

			// Load and start services
			var honeypotSMB *honeysmb.Server
			var honeypotFTP *honeyftp.Server
			var honeypotRDP *honeyrdp.Server
			smbHoneypotOn139 := false
			if profile != nil {
				for _, sn := range appCfg.Services {
					if sn == "smb_honeypot" && config.EditionExposesPort(profile.ResolvedEdition(), 139) {
						smbHoneypotOn139 = true
						break
					}
				}
			}
			for _, svcName := range appCfg.Services {
				if !config.ShouldStartService(svcName, profile, smbHoneypotOn139) {
					logging.Info("Skipping edition-gated service", map[string]interface{}{
						"service": svcName,
						"edition": editionLabel(profile),
					})
					continue
				}
				if svcName == "smb_honeypot" {
					cfg := honeysmb.Config{
						ComputerName: appCfg.ServiceOptions.NetBIOSName,
						DomainName:   appCfg.ServiceOptions.Domain,
					}
					if cfg.ComputerName == "" {
						cfg.ComputerName = "WORKSTATION"
					}
					if cfg.DomainName == "" {
						cfg.DomainName = "WORKGROUP"
					}
					// Drive SMB protocol behaviour from the OS profile (dialect,
					// signing, OS strings). nil profile → honeypot defaults (modern Win).
					// SMB1 follows the profile (false on Win10/11+); enable only on profiles
					// that historically ran SMBv1 (Win7/8, older servers).
					if profile != nil {
						cfg.MaxDialect = honeysmb.DialectFromString(profile.SMB.Dialect)
						cfg.SigningRequired = profile.SMB.SigningRequired
						cfg.SMB1Enabled = profile.SMB.SMB1Enabled
						cfg.OSName = profile.Name
						cfg.OSVersion = profile.Version
						cfg.NetBIOSPort = config.EditionExposesPort(profile.ResolvedEdition(), 139)
					}
					// Auth model: workstation profiles default guest/null off (realistic
					// hardened client); server/dc default on. Explicit config overrides.
					allowGuest := true
					if profile != nil && profile.ResolvedEdition() == "workstation" {
						allowGuest = false
					}
					if appCfg.SMBHoneypot.AllowGuestEnum != nil {
						allowGuest = *appCfg.SMBHoneypot.AllowGuestEnum
					}
					cfg.AllowGuestEnum = &allowGuest
					// Legacy inline credentials.
					for _, c := range appCfg.SMBHoneypot.Credentials {
						cfg.Credentials = append(cfg.Credentials, honeysmb.Credential{
							Username: c.Username, Password: c.Password, Domain: c.Domain,
						})
					}
					// Shared-pool credentials accepted by this honeypot.
					cfg.Credentials = append(cfg.Credentials, acceptedSMBCreds(appCfg)...)
					// Config-driven VFS + shared store for {{cred:...}} interpolation in
					// seeded files; ConfigDir resolves relative seed_file paths.
					cfg.Filesystem = appCfg.SMBHoneypot.Filesystem
					cfg.CredStore = credStore
					cfg.ConfigDir = configDir
					honeypotSMB = honeysmb.New(cfg)
					if err := honeypotSMB.Start(); err != nil {
						errChan <- fmt.Errorf("starting smb_honeypot: %w", err)
						return
					}
					continue
				}

				if svcName == "rdp" {
					rcfg := honeyrdp.Config{
						ComputerName: appCfg.ServiceOptions.NetBIOSName,
						DomainName:   appCfg.ServiceOptions.Domain,
						ServicesDir:  appCfg.ServicesDir,
					}
					if rcfg.ComputerName == "" {
						rcfg.ComputerName = "WORKSTATION"
					}
					if rcfg.DomainName == "" {
						rcfg.DomainName = "WORKGROUP"
					}
					if profile != nil {
						rcfg.OSVersion = profile.Version
					}
					rdpSrv, err := honeyrdp.New(rcfg)
					if err != nil {
						errChan <- fmt.Errorf("creating rdp honeypot: %w", err)
						return
					}
					honeypotRDP = rdpSrv
					if err := honeypotRDP.Start(); err != nil {
						errChan <- fmt.Errorf("starting rdp honeypot: %w", err)
						return
					}
					continue
				}

				if svcName == "ftp_honeypot" {
					allowAnon := appCfg.FtpHoneypot.AllowAnonymous == nil || *appCfg.FtpHoneypot.AllowAnonymous
					// Filesystem falls back to the SMB honeypot's tree so one
					// definition can drive both services.
					fsCfg := appCfg.FtpHoneypot.Filesystem
					if fsCfg == nil {
						fsCfg = appCfg.SMBHoneypot.Filesystem
					}
					fcfg := honeyftp.Config{
						CredStore:         credStore,
						AcceptCredentials: appCfg.FtpHoneypot.AcceptCredentials,
						RootShare:         appCfg.FtpHoneypot.RootShare,
						Filesystem:        fsCfg,
						ConfigDir:         configDir,
						AllowAnonymous:    allowAnon,
					}
					if profile != nil {
						fcfg.OSName = profile.Name
					}
					ftpSrv, err := honeyftp.New(fcfg)
					if err != nil {
						errChan <- fmt.Errorf("creating ftp_honeypot: %w", err)
						return
					}
					honeypotFTP = ftpSrv
					if err := honeypotFTP.Start(); err != nil {
						errChan <- fmt.Errorf("starting ftp_honeypot: %w", err)
						return
					}
					continue
				}

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
			if honeypotSMB != nil {
				honeypotSMB.Stop()
			}
			if honeypotFTP != nil {
				honeypotFTP.Stop()
			}
			if honeypotRDP != nil {
				honeypotRDP.Stop()
			}
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
		if probeMgr != nil {
			probeMgr.Stop()
		}
		if fwMgr != nil {
			fwMgr.Stop()
		}
		return err
	default:
	}

	logging.Info("Mimic active", map[string]interface{}{
		"log_dir": logging.GetActiveLogDir(),
	})
	fmt.Printf("\nMimic active. Logs: %s\nPress Ctrl+C to stop.\n\n", logging.GetActiveLogDir())

	// Background OS/service coherence self-audit: warn the operator if a non-Mimic
	// service on the host advertises a banner that contradicts the emulated OS
	// family (e.g. a real vsftpd/OpenSSH on a Windows profile) — the strongest
	// fingerprint-deception tell. Advisory only; runs once after listeners settle.
	if profile != nil {
		go func() {
			time.Sleep(2 * time.Second)
			coherence.Check(profile.Family, logging.Component("coherence"))
		}()
	}

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
			if probeMgr != nil {
				probeMgr.Stop()
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
			if probeMgr != nil {
				probeMgr.Stop()
			}
			logging.Info("Mimic stopped", nil)
			return nil
		}
	}
}

// buildCredStore converts the config credential pool into the neutral store
// shared by the SMB honeypot (accept side) and leaking services (emit side).
func buildCredStore(defs []config.CredentialDef) *deception.CredStore {
	creds := make([]deception.Credential, 0, len(defs))
	for _, d := range defs {
		creds = append(creds, deception.Credential{
			ID: d.ID, Username: d.Username, Password: d.Password, Domain: d.Domain,
		})
	}
	return deception.NewCredStore(creds)
}

// acceptedSMBCreds returns the pool credentials the SMB honeypot should accept:
// the ids listed in AcceptCredentials, or all pool credentials when none listed.
func acceptedSMBCreds(appCfg *config.AppConfig) []honeysmb.Credential {
	want := appCfg.SMBHoneypot.AcceptCredentials
	var out []honeysmb.Credential
	for _, d := range appCfg.Credentials {
		if len(want) > 0 && !containsStr(want, d.ID) {
			continue
		}
		out = append(out, honeysmb.Credential{Username: d.Username, Password: d.Password, Domain: d.Domain})
	}
	return out
}

// validateLeaks logs warnings for credential_leaks that reference an unknown
// credential id or a service that is not enabled. Leaks are advisory wiring; a
// misconfiguration warns rather than fails.
func validateLeaks(appCfg *config.AppConfig) {
	ids := make(map[string]bool, len(appCfg.Credentials))
	for _, c := range appCfg.Credentials {
		ids[c.ID] = true
	}
	for _, l := range appCfg.CredentialLeaks {
		if !ids[l.Cred] {
			logging.Warn("credential_leak references unknown credential id", map[string]interface{}{"cred": l.Cred, "via": l.Via})
		}
		if !containsStr(appCfg.Services, l.Via) {
			logging.Warn("credential_leak via a service that is not enabled", map[string]interface{}{"cred": l.Cred, "via": l.Via})
		}
	}
}

// mergeUint16 returns the de-duplicated union of two uint16 slices (order: a then
// new-from-b), dropping zeros. Used to fold the derived served-port set into any
// operator-configured firewall.open_ports for the workstation default-drop persona.
func mergeUint16(a, b []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(a)+len(b))
	var out []uint16
	for _, p := range a {
		if p == 0 {
			continue
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	for _, p := range b {
		if p == 0 {
			continue
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func editionLabel(profile *config.OSProfile) string {
	if profile == nil {
		return ""
	}
	return profile.ResolvedEdition()
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
