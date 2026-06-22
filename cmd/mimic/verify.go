package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/verify"
)

var verifyTarget string

var verifyCmd = &cobra.Command{
	Use:   "verify [profile-name]",
	Short: "Cross-layer coherence self-audit of a running Mimic instance",
	Long: `Probes a running Mimic instance the way a skilled operator would and flags any
cross-layer self-contradiction — the codified form of the OSE-2026-001 finding
that deception was caught pre-shell by correlating independent layers.

Checks the profile's internal consistency (declared version vs. declared TCP/IP
stack era) and, against the live target, the TLS cert identity and HTTP.sys
banners, cross-correlated with the computer name the profile/config advertise.
Exits non-zero if any TELL is found, so it can gate CI.

Example:
  mimic verify -c /etc/mimic/config.yaml
  mimic verify "Windows 11" -c ./config.yaml --target 10.0.254.45`,
	Args: cobra.MaximumNArgs(1),
	// A coherence failure is a real result, not CLI misuse — don't dump usage.
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyTarget, "target", "127.0.0.1", "host to probe (default localhost)")
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	appCfg, err := config.LoadAppConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if len(args) > 0 {
		appCfg.Profile = args[0]
	}
	if profilesDir != "./profiles" {
		appCfg.ProfilesDir = profilesDir
	}
	if servicesDir != "./services" {
		appCfg.ServicesDir = servicesDir
	}

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

	results, coherent := verify.Run(appCfg, profile, verifyTarget, 5*time.Second)

	fmt.Printf("\nmimic verify — target %s, profile %q\n\n", verifyTarget, appCfg.Profile)
	for _, r := range results {
		fmt.Printf("  [%-4s] %-8s %-26s", r.Status, r.Layer, r.Check)
		if r.Expected != "" || r.Observed != "" {
			fmt.Printf(" expected=%q observed=%q", r.Expected, r.Observed)
		}
		if r.Detail != "" {
			fmt.Printf("  — %s", r.Detail)
		}
		fmt.Println()
	}

	if coherent {
		fmt.Println("\nCOHERENT — no cross-layer tells detected.")
		return nil
	}
	fmt.Println("\nTELLS DETECTED — the instance is self-inconsistent (see TELL rows above).")
	return fmt.Errorf("coherence check failed")
}
