package services

import (
	"fmt"
	"os/exec"
	"sync"

	"github.com/c2xorc4/mimic/internal/logging"
)

// ClosedPortListener simulates a closed port using nftables REJECT rules.
// This sends TCP RST in response to SYN, making the port appear closed to scanners.
type ClosedPortListener struct {
	port uint16
	log  *logging.Logger
}

// NewClosedPortListener creates a listener that simulates a closed port
func NewClosedPortListener(port uint16) *ClosedPortListener {
	return &ClosedPortListener{
		port: port,
		log:  logging.Component("closed"),
	}
}

// Start adds iptables/nftables rule to reject connections with RST
func (c *ClosedPortListener) Start() error {
	// Try iptables-nft first (nftables backend)
	cmd := exec.Command("/usr/bin/iptables-nft", "-I", "INPUT", "-p", "tcp", "--dport",
		fmt.Sprintf("%d", c.port), "-j", "REJECT", "--reject-with", "tcp-reset")
	output, err := cmd.CombinedOutput()
	if err == nil {
		c.log.Info("Closed port active (iptables-nft REJECT)", map[string]interface{}{
			"port": c.port,
		})
		return nil
	}

	// Try legacy iptables
	cmd = exec.Command("/usr/bin/iptables", "-I", "INPUT", "-p", "tcp", "--dport",
		fmt.Sprintf("%d", c.port), "-j", "REJECT", "--reject-with", "tcp-reset")
	output, err = cmd.CombinedOutput()
	if err == nil {
		c.log.Info("Closed port active (iptables REJECT)", map[string]interface{}{
			"port": c.port,
		})
		return nil
	}

	// Both failed - kernel likely missing netfilter modules
	c.log.Warn("Closed port requires netfilter kernel support", map[string]interface{}{
		"port":   c.port,
		"error":  string(output),
		"hint":   "Load nf_tables or ip_tables kernel modules, or use a kernel with netfilter support",
	})
	return fmt.Errorf("closed port %d: netfilter not available (kernel module missing)", c.port)
}

// Stop removes the iptables-nft rule
func (c *ClosedPortListener) Stop() {
	cmd := exec.Command("/usr/bin/iptables-nft", "-D", "INPUT", "-p", "tcp", "--dport",
		fmt.Sprintf("%d", c.port), "-j", "REJECT", "--reject-with", "tcp-reset")
	if err := cmd.Run(); err != nil {
		c.log.Warn("Failed to remove iptables-nft rule", map[string]interface{}{
			"port":  c.port,
			"error": err.Error(),
		})
	} else {
		c.log.Info("Closed port stopped", map[string]interface{}{
			"port": c.port,
		})
	}
}

// GetPort returns the port number
func (c *ClosedPortListener) GetPort() uint16 {
	return c.port
}

// ClosedPortManager manages multiple closed port listeners
type ClosedPortManager struct {
	listeners []*ClosedPortListener
	mu        sync.Mutex
}

// NewClosedPortManager creates a new closed port manager
func NewClosedPortManager() *ClosedPortManager {
	return &ClosedPortManager{}
}

// AddPort adds a closed port listener
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

// AddPorts adds multiple closed port listeners
func (m *ClosedPortManager) AddPorts(ports []uint16) error {
	for _, port := range ports {
		if err := m.AddPort(port); err != nil {
			// Stop any already started listeners on error
			m.StopAll()
			return fmt.Errorf("adding closed port %d: %w", port, err)
		}
	}
	return nil
}

// StopAll stops all closed port listeners
func (m *ClosedPortManager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, listener := range m.listeners {
		listener.Stop()
	}
	m.listeners = nil
}

// GetPorts returns all active closed ports
func (m *ClosedPortManager) GetPorts() []uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()

	ports := make([]uint16, len(m.listeners))
	for i, l := range m.listeners {
		ports[i] = l.GetPort()
	}
	return ports
}
