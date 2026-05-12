package services

import (
	"fmt"
	"os/exec"
	"sync"

	"github.com/c2xorc4/mimic/internal/logging"
)

// nftTableName is the nftables table used for all Mimic reject rules.
const nftTableName = "inet mimic_reject"

// nftEnsureTable creates the Mimic nftables table and input chain if not present.
// Idempotent — safe to call multiple times.
func nftEnsureTable() error {
	cmds := [][]string{
		{"nft", "add", "table", "inet", "mimic_reject"},
		{"nft", "add", "chain", "inet", "mimic_reject", "input",
			"{ type filter hook input priority -100 ; policy accept ; }"},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft setup (%v): %s", args, out)
		}
	}
	return nil
}

// nftDeleteTable removes the Mimic nftables table entirely.
func nftDeleteTable() {
	exec.Command("nft", "delete", "table", "inet", "mimic_reject").Run() //nolint:errcheck
}

// ClosedPortListener simulates a closed port using nftables REJECT rules.
type ClosedPortListener struct {
	port uint16
	log  *logging.Logger
}

// NewClosedPortListener creates a listener that simulates a closed port.
func NewClosedPortListener(port uint16) *ClosedPortListener {
	return &ClosedPortListener{
		port: port,
		log:  logging.Component("closed"),
	}
}

// Start adds an nftables rule to reject SYN with RST, making the port appear closed.
func (c *ClosedPortListener) Start() error {
	if err := nftEnsureTable(); err != nil {
		c.log.Warn("Closed port requires netfilter kernel support", map[string]interface{}{
			"port":  c.port,
			"error": err.Error(),
			"hint":  "Load nf_tables and nft_reject_inet kernel modules",
		})
		return fmt.Errorf("closed port %d: netfilter not available (%w)", c.port, err)
	}
	args := []string{
		"nft", "add", "rule", "inet", "mimic_reject", "input",
		"tcp", "dport", fmt.Sprintf("%d", c.port),
		"reject", "with", "tcp", "reset",
	}
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("closed port %d: nft add rule: %s", c.port, out)
	}
	c.log.Info("Closed port active", map[string]interface{}{"port": c.port})
	return nil
}

// Stop flushes the entire table (called from ClosedPortManager.StopAll).
// Individual rules are not tracked by handle — the whole table is cleared at once.
func (c *ClosedPortListener) Stop() {
	// No-op: StopAll() deletes the entire table.
}

// GetPort returns the port number.
func (c *ClosedPortListener) GetPort() uint16 {
	return c.port
}

// ClosedPortManager manages multiple closed port listeners.
type ClosedPortManager struct {
	listeners []*ClosedPortListener
	mu        sync.Mutex
}

// NewClosedPortManager creates a new closed port manager.
func NewClosedPortManager() *ClosedPortManager {
	return &ClosedPortManager{}
}

// AddPort adds a closed port listener.
func (m *ClosedPortManager) AddPort(port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener := NewClosedPortListener(port)
	if err := listener.Start(); err != nil {
		return err
	}
	m.listeners = append(m.listeners, listener)
	return nil
}

// AddPorts adds multiple closed port listeners.
func (m *ClosedPortManager) AddPorts(ports []uint16) error {
	for _, port := range ports {
		if err := m.AddPort(port); err != nil {
			m.StopAll()
			return fmt.Errorf("adding closed port %d: %w", port, err)
		}
	}
	return nil
}

// StopAll removes all nftables rules by deleting the Mimic table.
func (m *ClosedPortManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	nftDeleteTable()
	m.listeners = nil
}

// GetPorts returns all active closed ports.
func (m *ClosedPortManager) GetPorts() []uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()

	ports := make([]uint16, len(m.listeners))
	for i, l := range m.listeners {
		ports[i] = l.GetPort()
	}
	return ports
}

// ProbeResponseManager adds nftables rules that respond to unusual TCP probes
// (nmap T2/T3 OS fingerprint probes) with RST, matching Windows behavior.
type ProbeResponseManager struct {
	openPorts []uint16
	active    bool
	mu        sync.Mutex
	log       *logging.Logger
}

// NewProbeResponseManager creates a manager for T2/T3 probe responses.
func NewProbeResponseManager() *ProbeResponseManager {
	return &ProbeResponseManager{
		log: logging.Component("probes"),
	}
}

// Start adds nftables rules to respond to T2/T3 nmap OS fingerprint probes.
// T2: NULL-flagged TCP (all flags=0) → Windows responds with RST+ACK
// T3: SYN+FIN+PSH+URG flagged TCP → Windows responds with RST+ACK
func (p *ProbeResponseManager) Start(openPorts []uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := nftEnsureTable(); err != nil {
		p.log.Warn("Probe response rules unavailable", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	// Build port set string: e.g. "{ 135, 139, 445, 3389 }"
	portSet := "{"
	for i, port := range openPorts {
		if i > 0 {
			portSet += ","
		}
		portSet += fmt.Sprintf(" %d", port)
	}
	portSet += " }"

	// T2 probe: TCP with NO flags set (NULL probe) to open ports
	args2 := []string{
		"nft", "add", "rule", "inet", "mimic_reject", "input",
		"tcp", "dport", portSet,
		"tcp", "flags", "&", "(fin|syn|rst|psh|ack|urg)", "==", "0x00",
		"reject", "with", "tcp", "reset",
	}
	if out, err := exec.Command(args2[0], args2[1:]...).CombinedOutput(); err != nil {
		p.log.Warn("T2 probe rule failed", map[string]interface{}{"error": string(out)})
	} else {
		p.log.Info("T2 probe response active (NULL flags → RST)")
	}

	// T3 probe: SYN+FIN+PSH+URG to open ports (0x2b)
	args3 := []string{
		"nft", "add", "rule", "inet", "mimic_reject", "input",
		"tcp", "dport", portSet,
		"tcp", "flags", "&", "(fin|syn|psh|urg)", "==", "(fin|syn|psh|urg)",
		"reject", "with", "tcp", "reset",
	}
	if out, err := exec.Command(args3[0], args3[1:]...).CombinedOutput(); err != nil {
		p.log.Warn("T3 probe rule failed", map[string]interface{}{"error": string(out)})
	} else {
		p.log.Info("T3 probe response active (SYN+FIN+PSH+URG → RST)")
	}

	p.openPorts = openPorts
	p.active = true
	return nil
}

// Stop removes the probe response rules (via table deletion).
func (p *ProbeResponseManager) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active {
		nftDeleteTable()
		p.active = false
	}
}
