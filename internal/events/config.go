package events

import "path/filepath"

// Config controls the event subsystem and its sinks.
type Config struct {
	Enabled  bool         `yaml:"enabled"`   // master switch (default on; see Init caller)
	JSONFile bool         `yaml:"json_file"` // NDJSON to <logdir>/events.log
	Syslog   SyslogConfig `yaml:"syslog"`
}

// SyslogConfig configures the RFC 5424 syslog sink.
type SyslogConfig struct {
	Enabled bool   `yaml:"enabled"`
	Network string `yaml:"network"` // udp | tcp (default udp)
	Address string `yaml:"address"` // host:port (default 127.0.0.1:514)
}

// Init builds a Bus from cfg, installs it as the global emitter, and returns it.
// logDir is where the NDJSON events.log is written. onError is invoked on sink
// write failures (wire it to the logger). Returns a nil bus when events are
// disabled or no sink is configured.
func Init(cfg Config, logDir string, onError func(sink string, err error)) (*Bus, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	bus := NewBus(onError)
	if cfg.JSONFile && logDir != "" {
		fs, err := NewFileSink(filepath.Join(logDir, "events.log"))
		if err != nil {
			return nil, err
		}
		bus.AddSink(fs)
	}
	if cfg.Syslog.Enabled {
		network := cfg.Syslog.Network
		if network == "" {
			network = "udp"
		}
		address := cfg.Syslog.Address
		if address == "" {
			address = "127.0.0.1:514"
		}
		ss, err := NewSyslogSink(network, address)
		if err != nil {
			return nil, err
		}
		bus.AddSink(ss)
	}
	SetGlobal(bus)
	return bus, nil
}
