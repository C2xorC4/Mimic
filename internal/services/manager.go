package services

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/logging"
)

// Manager manages multiple service emulators
type Manager struct {
	servicesDir string
	services    map[string]*ServiceEmulator
	options     map[string]string
	mu          sync.RWMutex
	log         *logging.Logger
}

// ServiceEmulator handles emulation for a single service
type ServiceEmulator struct {
	config       *config.ServiceConfig
	listener     *Listener
	responsesDir string
	running      bool
}

// NewManager creates a new service manager
func NewManager(servicesDir string) *Manager {
	return &Manager{
		servicesDir: servicesDir,
		services:    make(map[string]*ServiceEmulator),
		options:     make(map[string]string),
		log:         logging.Component("manager"),
	}
}

// SetOption sets a global option for all services
func (m *Manager) SetOption(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.options[key] = value
}

// GetOption retrieves a global option
func (m *Manager) GetOption(key string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.options[key]
}

// LoadService loads a service configuration from disk
func (m *Manager) LoadService(name string) error {
	serviceDir := filepath.Join(m.servicesDir, name)
	manifestPath := filepath.Join(serviceDir, "manifest.yaml")

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}

	var cfg config.ServiceConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing manifest: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.services[name] = &ServiceEmulator{
		config:       &cfg,
		responsesDir: serviceDir,
	}

	if m.log != nil {
		m.log.Debug("Service loaded", map[string]interface{}{
			"service": name,
			"port":    cfg.Port,
		})
	}

	return nil
}

// StartService starts emulation for a service
func (m *Manager) StartService(name string) error {
	m.mu.Lock()
	svc, exists := m.services[name]
	options := make(map[string]string)
	for k, v := range m.options {
		options[k] = v
	}
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("service not loaded: %s", name)
	}

	if svc.running {
		return fmt.Errorf("service already running: %s", name)
	}

	listener, err := NewListenerWithOptions(svc.config, svc.responsesDir, options)
	if err != nil {
		return fmt.Errorf("creating listener: %w", err)
	}

	if err := listener.Start(); err != nil {
		return fmt.Errorf("starting listener: %w", err)
	}

	svc.listener = listener
	svc.running = true

	if m.log != nil {
		m.log.Info("Service started", map[string]interface{}{
			"service":  name,
			"port":     svc.config.Port,
			"protocol": svc.config.Protocol,
		})
	}

	return nil
}

// StopService stops emulation for a service
func (m *Manager) StopService(name string) error {
	m.mu.Lock()
	svc, exists := m.services[name]
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("service not loaded: %s", name)
	}

	if !svc.running {
		return nil
	}

	if svc.listener != nil {
		svc.listener.Stop()
	}

	svc.running = false

	if m.log != nil {
		m.log.Info("Service stopped", map[string]interface{}{
			"service": name,
		})
	}

	return nil
}

// StopAll stops all running services
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, svc := range m.services {
		if svc.running && svc.listener != nil {
			svc.listener.Stop()
			svc.running = false
			if m.log != nil {
				m.log.Info("Service stopped", map[string]interface{}{
					"service": name,
				})
			}
		}
	}
}

// ListServices returns available services in the services directory
func (m *Manager) ListServices() ([]string, error) {
	entries, err := os.ReadDir(m.servicesDir)
	if err != nil {
		return nil, fmt.Errorf("reading services dir: %w", err)
	}

	var services []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(m.servicesDir, entry.Name(), "manifest.yaml")
		if _, err := os.Stat(manifestPath); err == nil {
			services = append(services, entry.Name())
		}
	}

	return services, nil
}

// GetServiceInfo returns information about a loaded service
func (m *Manager) GetServiceInfo(name string) (*config.ServiceConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	svc, exists := m.services[name]
	if !exists {
		return nil, false
	}
	return svc.config, svc.running
}

// GetServiceStats returns statistics for a running service
func (m *Manager) GetServiceStats(name string) (*ListenerStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	svc, exists := m.services[name]
	if !exists {
		return nil, fmt.Errorf("service not loaded: %s", name)
	}

	if !svc.running || svc.listener == nil {
		return nil, fmt.Errorf("service not running: %s", name)
	}

	stats := svc.listener.GetStats()
	return &stats, nil
}
