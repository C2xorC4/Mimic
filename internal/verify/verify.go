// Package verify implements a network-only cross-layer coherence oracle for a
// running Mimic instance. It is the codified form of the OSE-2026-001 finding
// that a skilled operator flagged the deception pre-shell by cross-correlating
// independent layers (stack, service banners, identity, timing) for internal
// contradiction. mimic verify runs that same adversarial check against itself,
// serving both as a CI quality gate and as the threat model made executable.
//
// The profile is the source of truth. Each layer probe reports an expected vs.
// observed value and a status; any disagreement is a TELL. Known, deliberate
// divergences (the dual-path TLS Schannel-vs-Go boundary) are reported as
// accepted, not failures.
package verify

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
)

// Status is a per-check verdict.
type Status string

const (
	StatusOK   Status = "OK"
	StatusTell Status = "TELL"
	StatusSkip Status = "SKIP"
	StatusNote Status = "NOTE" // a known, accepted divergence
)

// Result is one layer/identity coherence check.
type Result struct {
	Layer    string
	Check    string
	Status   Status
	Expected string
	Observed string
	Detail   string
}

// Run probes target across layers and cross-correlates them against the profile
// and config. It returns the per-check results and whether the instance is
// coherent (no TELLs). target is host:"" — ports are derived from the services.
func Run(cfg *config.AppConfig, profile *config.OSProfile, target string, timeout time.Duration) ([]Result, bool) {
	var out []Result
	add := func(r Result) { out = append(out, r) }

	computerName := cfg.ServiceOptions.NetBIOSName
	if computerName == "" {
		computerName = "WORKSTATION"
	}

	// Layer 1 — profile self-consistency (no probe): the OSE tell where a profile's
	// declared version disagrees with its declared stack era (Win11 21H2 vs a 25H2
	// stack). Pure source-of-truth check; the strongest, cheapest coherence guard.
	add(checkProfileConsistency(profile))

	// Which services are actually live (so we only probe what should answer).
	services, err := config.ResolveRunServices(cfg.Services, cfg.ServicesDir, profile)
	if err != nil {
		services = cfg.Services
	}
	has := func(n string) bool {
		for _, s := range services {
			if s == n {
				return true
			}
		}
		return false
	}

	// Layer 2 — TLS identity: the cert CN is a cross-layer anchor that must match
	// the computer name SMB/NBNS/NTLM advertise. A mismatch is a classic tell.
	if has("https") {
		add(checkTLSCertCN(target, 443, computerName, timeout))
	}

	// Layer 3 — HTTP.sys banner coherence on the client-persona web ports.
	if has("winrm") {
		add(checkHTTPSysBanner(target, 5985, "winrm", timeout))
	}
	if has("wsd") {
		add(checkHTTPSysBanner(target, 5357, "wsd", timeout))
	}

	coherent := true
	for _, r := range out {
		if r.Status == StatusTell {
			coherent = false
		}
	}
	return out, coherent
}

// checkProfileConsistency flags a profile whose declared version contradicts its
// declared TCP/IP stack era. Conservative: only clear contradictions are TELLs.
func checkProfileConsistency(p *config.OSProfile) Result {
	r := Result{Layer: "profile", Check: "version<->stack era"}
	if p == nil || !strings.EqualFold(p.Family, "windows") {
		r.Status, r.Detail = StatusSkip, "non-Windows profile (n/a)"
		return r
	}
	maj, min, build, ok := parseVersion(p.Version)
	if !ok {
		r.Status, r.Observed = StatusTell, p.Version
		r.Detail = "profile.version is not a parseable major.minor.build"
		return r
	}
	r.Expected = fmt.Sprintf("%d.%d.%d", maj, min, build)
	r.Observed = fmt.Sprintf("win=%d ts=%v", p.Stack.WindowSize, p.Stack.TCPTimestamps)
	// Win11-class client (build >= 22000, not Server) shipped the 25H2-era stack
	// change: default receive window 65535 with TCP timestamps ON. Win10/Server
	// use 8192 with timestamps OFF. A Win11 build advertising the Win10 stack (or
	// vice-versa) is the documented self-contradiction.
	isServer := strings.Contains(strings.ToLower(p.Name), "server")
	if build >= 22000 && !isServer {
		if p.Stack.WindowSize != 65535 || !p.Stack.TCPTimestamps {
			r.Status = StatusTell
			r.Detail = "Win11-class build but stack is not 65535/TS-on (version/stack capture mismatch)"
			return r
		}
	}
	r.Status = StatusOK
	return r
}

// checkTLSCertCN dials a TLS port and verifies the leaf cert CN matches the
// expected computer name (the same identity SMB/NBNS advertise).
func checkTLSCertCN(host string, port int, computerName string, timeout time.Duration) Result {
	r := Result{Layer: "tls", Check: "cert CN == computer name", Expected: computerName}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec
	if err != nil {
		r.Status, r.Detail = StatusSkip, "TLS dial failed: "+err.Error()
		return r
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		// JARM/scanner path serves a static ServerHello with no completed cert
		// exchange — a known, accepted dual-path divergence, not a tell.
		r.Status, r.Detail = StatusNote, "no leaf cert (static Schannel JARM path — accepted dual-path divergence)"
		return r
	}
	cn := cs.PeerCertificates[0].Subject.CommonName
	r.Observed = cn
	if !strings.EqualFold(cn, computerName) {
		r.Status, r.Detail = StatusTell, "TLS cert CN disagrees with the SMB/NBNS computer name"
		return r
	}
	r.Status, r.Detail = StatusOK, fmt.Sprintf("TLS %s", tlsVersionName(cs.Version))
	return r
}

// checkHTTPSysBanner confirms an HTTP.sys-backed port answers with the
// Microsoft-HTTPAPI/2.0 Server header a real Windows kernel HTTP stack emits.
func checkHTTPSysBanner(host string, port int, layer string, timeout time.Duration) Result {
	r := Result{Layer: layer, Check: "Server: Microsoft-HTTPAPI/2.0", Expected: "Microsoft-HTTPAPI/2.0"}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		r.Status, r.Detail = StatusSkip, "dial failed: "+err.Error()
		return r
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		r.Status, r.Detail = StatusSkip, "write failed: "+err.Error()
		return r
	}
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	server := httpHeader(string(buf[:n]), "Server")
	r.Observed = server
	if !strings.Contains(server, "Microsoft-HTTPAPI") {
		r.Status, r.Detail = StatusTell, "HTTP.sys port does not advertise Microsoft-HTTPAPI/2.0"
		return r
	}
	r.Status = StatusOK
	return r
}

// parseVersion splits "major.minor.build" (e.g. "10.0.26200").
func parseVersion(v string) (maj, min, build int, ok bool) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) < 3 {
		return 0, 0, 0, false
	}
	var err error
	if maj, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, 0, false
	}
	if min, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, 0, false
	}
	if build, err = strconv.Atoi(parts[2]); err != nil {
		return 0, 0, 0, false
	}
	return maj, min, build, true
}

func httpHeader(resp, name string) string {
	for _, line := range strings.Split(resp, "\r\n") {
		if k, v, found := strings.Cut(line, ":"); found && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
