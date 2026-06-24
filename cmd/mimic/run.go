package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/coherence"
	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/control"
	"github.com/c2xorc4/mimic/internal/deception"
	"github.com/c2xorc4/mimic/internal/defense"
	"github.com/c2xorc4/mimic/internal/events"
	honeyftp "github.com/c2xorc4/mimic/internal/honeypot/ftp"
	honeyrdp "github.com/c2xorc4/mimic/internal/honeypot/rdp"
	honeysmb "github.com/c2xorc4/mimic/internal/honeypot/smb"
	honeyssh "github.com/c2xorc4/mimic/internal/honeypot/ssh"
	"github.com/c2xorc4/mimic/internal/logging"
	"github.com/c2xorc4/mimic/internal/netfilter"
	"github.com/c2xorc4/mimic/internal/platform"
	"github.com/c2xorc4/mimic/internal/services"
	"github.com/c2xorc4/mimic/internal/stack"
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

// serviceStopCh, when non-nil, lets a platform service manager (the Windows SCM
// handler) request a graceful shutdown of a running `mimic run`. It is nil for
// interactive/Linux runs; selecting on a nil channel never fires, so the main
// loop is unaffected. The windows service wrapper sets and closes it.
var serviceStopCh chan struct{}

func init() {
	runCmd.Flags().StringVar(&runProfile, "profile", "", "OS profile to apply (overrides config)")
	runCmd.Flags().StringSliceVar(&runServices, "services", []string{}, "Services to emulate, or 'all' for full catalog with edition gating (overrides config)")
	runCmd.Flags().IntSliceVar(&runClosedPorts, "closed-ports", []int{}, "Ports that appear closed (RST on connect, for OS fingerprinting)")
	runCmd.Flags().StringVar(&servicesDir, "services-dir", "./services", "Path to services directory")

	rootCmd.AddCommand(runCmd)
}

func runMimic(cmd *cobra.Command, args []string) error {
	if !platform.IsElevated() {
		return fmt.Errorf("this command requires %s privileges", platform.PrivilegeName())
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

	// Control-plane event ring: when the control plane is enabled, retain recent
	// events in memory so `mimic ctl logs` can serve them. Registered as a bus
	// sink up front so it captures everything from startup.
	var ctrlRing *control.Ring
	if appCfg.Control.Enabled {
		ctrlRing = control.NewRing(200)
		if evBus != nil {
			evBus.AddSink(ctrlRing)
		}
	}

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

	// Validate required fields. The interface is only needed for the stack
	// backend (eBPF/TC on Linux); on platforms without one, run is service-only
	// and binds to all interfaces, so no -i is required.
	if stack.Available() && appCfg.Interface == "" {
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

	// Control plane (RBAC-gated local management endpoint). statusFn reads the
	// resolved profile/services at call time; hooks expose config + lifecycle ops.
	restartReq := make(chan struct{})
	stopReq := make(chan struct{})
	if appCfg.Control.Enabled {
		if !control.Supported() {
			logging.Warn("Control plane enabled but not supported on this platform — skipping", nil)
		} else {
			socket := appCfg.Control.Socket
			if socket == "" {
				socket = control.DefaultEndpoint()
			}
			statusFn := func() control.Status {
				return control.Status{
					Profile: appCfg.Profile, Edition: editionLabel(profile),
					Services: appCfg.Services, Pid: os.Getpid(),
				}
			}
			hooks := buildControlHooks(absConfigPath(), defaultProfilesDir(absConfigPath()), defaultServicesDir(absConfigPath()), restartReq, stopReq)
			ctrlSrv := control.New(control.NewRoleAuthorizer(appCfg.RBAC), statusFn, ctrlRing, hooks)
			if err := ctrlSrv.Start(socket); err != nil {
				logging.Warn("Control plane failed to start", map[string]interface{}{"error": err.Error()})
			} else {
				defer ctrlSrv.Stop()
			}
		}
	}

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

	var fm stack.Backend
	var svcMgr *services.Manager
	var closedMgr *services.ClosedPortManager
	var probeMgr *services.ProbeResponseManager
	var fwMgr *services.FirewallManager

	// Host packet-disposition shaping — closed-port RST/drop, T2/T3 probe
	// responses, and the firewalled-client default-drop persona — is nftables-based
	// (Linux only for now; Windows lands in Phase 1c behind internal/netfilter).
	// Where unsupported, the whole block is skipped and service emulation runs alone.
	if netfilter.Supported() {
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

		// Start T2/T3 probe response rules (nmap OS fingerprint probes, all ports).
		// These emit the Windows RST+ACK T2/T3 behavior — a Windows tell — so they
		// run ONLY for Windows profiles. A Linux/macOS profile leaves the host's
		// native (Linux) T-series responses, so it fingerprints cleanly as Linux (#13).
		if profile != nil && strings.EqualFold(profile.Family, "windows") {
			probeMgr = services.NewProbeResponseManager()
			if err := probeMgr.Start(); err != nil {
				logging.Warn("T2/T3 probe response unavailable", map[string]interface{}{
					"error": err.Error(),
				})
				probeMgr = nil
			}
		}

		// Closed-port disposition. Workstation editions DEFAULT to the firewalled-Windows
		// persona (default-drop): unserved ports — including 135/139/445 — read as
		// FILTERED, matching a real firewalled Win11 client (OSE-2026-001 Op-1 dropped
		// ~all ports; closed-not-filtered on the server ports was the server-vs-client
		// tell). The allow-list is DERIVED from the actually-served decoy ports so the
		// client persona's open surface (3389/5357/5985/7680, etc.) stays reachable.
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
	} // end netfilter.Supported()

	// Windows (and any non-nft platform with a packet backend) firewalled-client
	// persona: the Linux nft default-drop above is skipped, so install the same
	// disposition via the platform PersonaFirewall (WinDivert SYN-drop). Workstation
	// editions default to dropping unserved ports to FILTERED; opt out with
	// closed_port_behavior: reset. Torn down via defer on every return path.
	var winFw netfilter.PersonaFirewall
	var winClosed netfilter.ClosedPortResponder
	var winProbes netfilter.ProbeResponder
	var winICMP netfilter.ICMPResponder
	defer func() {
		if winICMP != nil {
			winICMP.Stop()
		}
		if winProbes != nil {
			winProbes.Stop()
		}
		if winClosed != nil {
			winClosed.Stop()
		}
		if winFw != nil {
			winFw.Stop()
		}
	}()
	if !netfilter.Supported() {
		if fw := netfilter.NewPersonaFirewall(); fw != nil {
			fwBehavior := strings.ToLower(appCfg.Firewall.ClosedPortBehavior)
			isWks := profile != nil && profile.ResolvedEdition() == "workstation"
			autoDrop := isWks && fwBehavior != "reset"
			if fwBehavior == "drop" || fwBehavior == "filtered" || autoDrop {
				open := appCfg.Firewall.OpenPorts
				if autoDrop {
					open = mergeUint16(open, config.ServiceListenPorts(appCfg.Services, profile, appCfg.ServicesDir))
				}
				if err := fw.EnableDrop(open, appCfg.Firewall.PreservePorts); err != nil {
					fields := map[string]interface{}{"error": err.Error()}
					if runtime.GOOS == "windows" && !stack.WinDivertInstalled() {
						fields["hint"] = platform.WinDivertInstallHint
					}
					logging.Warn("Persona firewall unavailable — unserved ports will not read as filtered (WinDivert required on Windows)", fields)
				} else {
					winFw = fw
					logging.Info("Workstation persona: firewalled-client default-drop active (unserved ports → filtered)", map[string]interface{}{
						"open_ports": open, "preserve_ports": appCfg.Firewall.PreservePorts,
					})
				}
				if isWks && winFw != nil {
					if err := winFw.EnableICMPDrop(); err != nil {
						logging.Warn("Persona ICMP drop unavailable — host will answer ping unlike a firewalled client", map[string]interface{}{"error": err.Error()})
					}
				}
			}
		}
		// Closed-port RST for nmap -O (Linux uses nft above; Windows uses WinDivert).
		if len(appCfg.ClosedPorts) > 0 {
			if cp := netfilter.NewClosedPortResponder(); cp != nil {
				var closedTTL uint8 = 64
				if profile != nil && profile.Stack.TTL > 0 {
					closedTTL = profile.Stack.TTL
				}
				linuxClosed := profile != nil && strings.EqualFold(profile.Family, "linux")
				if err := cp.AddPorts(appCfg.ClosedPorts, closedTTL, linuxClosed); err != nil {
					fields := map[string]interface{}{"error": err.Error(), "ports": appCfg.ClosedPorts}
					if runtime.GOOS == "windows" && !stack.WinDivertInstalled() {
						fields["hint"] = platform.WinDivertInstallHint
					}
					logging.Warn("Closed ports unavailable — OS fingerprinting may be incomplete", fields)
				} else {
					winClosed = cp
					logging.Info("Closed ports active (WinDivert RST)", map[string]interface{}{
						"ports": appCfg.ClosedPorts,
					})
				}
			}
		}
		// T4/T6/T7 probe responses for Linux personas on Windows. T2/T3 must stay
		// R=N on modern Linux — do not intercept. Scoped to closed + service ports
		// so T4 (ACK) / T6 (SYN+ACK) filters do not swallow normal client traffic.
		if profile != nil && strings.EqualFold(profile.Family, "linux") {
			if pr := netfilter.NewProbeResponder(); pr != nil {
				probePorts := mergeUint16(appCfg.ClosedPorts,
					config.ServiceListenPorts(appCfg.Services, profile, appCfg.ServicesDir))
				var probeTTL uint8 = 64
				if profile.Stack.TTL > 0 {
					probeTTL = profile.Stack.TTL
				}
				ackZero := strings.EqualFold(profile.Stack.AckInRST, "zero")
				if err := pr.Start(probePorts, appCfg.ClosedPorts, probeTTL, profile.Stack.WindowInRST, ackZero); err != nil {
					fields := map[string]interface{}{"error": err.Error()}
					if runtime.GOOS == "windows" && !stack.WinDivertInstalled() {
						fields["hint"] = platform.WinDivertInstallHint
					}
					logging.Warn("T4/T6/T7 probe response unavailable", fields)
				} else {
					winProbes = pr
				}
			}
			if ic := netfilter.NewICMPResponder(); ic != nil {
				var icmpTTL uint8 = 64
				quoteSize := uint8(64)
				if profile.Stack.TTL > 0 {
					icmpTTL = profile.Stack.TTL
				}
				if profile.Stack.ICMPQuoteSize > 0 {
					quoteSize = profile.Stack.ICMPQuoteSize
				}
				quoteTTL := icmpTTL
				if profile.Stack.ICMPTTLInQuote > 0 {
					quoteTTL = profile.Stack.ICMPTTLInQuote
				}
				if err := ic.Start(icmpTTL, quoteSize, quoteTTL, profile.Stack.ICMPDFInQuote, appCfg.ClosedPorts); err != nil {
					logging.Warn("ICMP probe response unavailable", map[string]interface{}{"error": err.Error()})
				} else {
					winICMP = ic
				}
			}
		}
	}

	// Start eBPF fingerprinting in goroutine
	if profile != nil && stack.Available() {
		wg.Add(1)
		go func() {
			defer wg.Done()

			ebpfLog := logging.Component("ebpf")

			// Create and load fingerprint manager
			var err error
			fm, err = stack.New(appCfg.Interface)
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
	} else if profile != nil {
		if runtime.GOOS == "windows" && !stack.WinDivertInstalled() {
			logging.Warn("WinDivert not installed — TCP/IP stack spoofing disabled; copy WinDivert.dll + WinDivert64.sys next to mimic.exe", map[string]interface{}{
				"profile": profile.Name,
				"hint":    platform.WinDivertInstallHint,
			})
		}
		logging.Warn("Stack fingerprinting unavailable — running service emulation only (no TCP/IP stack spoofing)", map[string]interface{}{
			"platform": runtime.GOOS,
			"profile":  profile.Name,
		})
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
			var honeypotSSH *honeyssh.Server
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
						if skipBindConflict("smb_honeypot", 445, err) {
							continue
						}
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
						if skipBindConflict("rdp", 3389, err) {
							continue
						}
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
						if skipBindConflict("ftp_honeypot", 21, err) {
							continue
						}
						errChan <- fmt.Errorf("starting ftp_honeypot: %w", err)
						return
					}
					continue
				}

				if svcName == "ssh_honeypot" {
					scfg := honeyssh.Config{
						CredStore:         credStore,
						AcceptCredentials: appCfg.SMBHoneypot.AcceptCredentials,
						Hostname:          appCfg.ServiceOptions.Hostname,
					}
					if scfg.Hostname == "" {
						scfg.Hostname = appCfg.ServiceOptions.NetBIOSName
					}
					if profile != nil {
						scfg.OSName = profile.Name
					}
					sshSrv, err := honeyssh.New(scfg)
					if err != nil {
						errChan <- fmt.Errorf("creating ssh_honeypot: %w", err)
						return
					}
					honeypotSSH = sshSrv
					if err := honeypotSSH.Start(); err != nil {
						if skipBindConflict("ssh_honeypot", 22, err) {
							continue
						}
						errChan <- fmt.Errorf("starting ssh_honeypot: %w", err)
						return
					}
					continue
				}

				if err := svcMgr.LoadService(svcName); err != nil {
					errChan <- fmt.Errorf("loading service %s: %w", svcName, err)
					return
				}

				if err := svcMgr.StartService(svcName); err != nil {
					port := templateServicePort(svcMgr, svcName)
					if skipBindConflict(svcName, port, err) {
						continue
					}
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
			if honeypotSSH != nil {
				honeypotSSH.Stop()
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
			if fwMgr != nil {
				fwMgr.Stop()
			}
			logging.Info("Mimic stopped", nil)
			return nil

		case <-serviceStopCh:
			// Windows SCM (or any platform service manager) requested stop.
			logging.Info("Service stop requested", nil)
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
			logging.Info("Mimic stopped", nil)
			return nil

		case <-restartReq:
			logging.Info("Service restart requested", nil)
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
			logging.Info("Mimic stopped for restart", nil)
			// The restart helper respawns mimic run as a detached process — it keeps
			// running after this terminal returns to the prompt (by design for tray/UI).
			fmt.Printf("\nMimic is restarting in the background. This terminal will exit.\n")
			fmt.Printf("  Check:  mimic ctl ping\n")
			fmt.Printf("  Logs:   %s\n\n", filepath.Join(logging.GetActiveLogDir(), "mimic.log"))
			return nil

		case <-stopReq:
			logging.Info("Control stop requested", nil)
			fmt.Printf("\nMimic stop requested via control plane, shutting down...\n")
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

// skipBindConflict logs and returns true when a service could not bind because the
// port is already owned (common on Windows where LanmanServer holds :445).
func skipBindConflict(service string, port uint16, err error) bool {
	if !platform.IsAddrInUse(err) {
		return false
	}
	fields := map[string]interface{}{
		"service": service,
		"error":   err.Error(),
		"hint":    platform.NativePortHint(int(port)),
	}
	if port > 0 {
		fields["port"] = port
	}
	logging.Warn("Skipping service — port already in use", fields)
	return true
}

func templateServicePort(mgr *services.Manager, name string) uint16 {
	// GetServiceInfo's bool is "running", not "loaded" — read port even when bind failed.
	cfg, _ := mgr.GetServiceInfo(name)
	if cfg != nil {
		return cfg.Port
	}
	return 0
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
