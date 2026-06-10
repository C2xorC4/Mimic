package events

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// --- NDJSON file sink ---

// FileSink writes one JSON object per line (NDJSON) — universal file ingest for
// Splunk/Filebeat/etc.
type FileSink struct {
	mu sync.Mutex
	f  *os.File
}

// NewFileSink opens (appends) the NDJSON event log at path.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("events file %s: %w", path, err)
	}
	return &FileSink{f: f}, nil
}

func (s *FileSink) Name() string { return "ndjson-file" }

func (s *FileSink) Write(ev Event) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.f.Write(append(data, '\n'))
	return err
}

func (s *FileSink) Close() error { return s.f.Close() }

// --- syslog (RFC 5424) sink ---

// dialer is swappable in tests.
type netConn interface {
	Write([]byte) (int, error)
	Close() error
}

// SyslogSink emits RFC 5424 frames over UDP or TCP to a syslog collector. It
// deliberately avoids the unix-only log/syslog package so this stays
// cross-platform and unit-testable; the MSG payload is the event JSON so a SIEM
// gets both syslog routing and structured parse.
type SyslogSink struct {
	mu       sync.Mutex
	network  string // "udp" | "tcp"
	address  string
	hostname string
	appName  string
	procid   string
	conn     netConn
	dial     func() (netConn, error)
}

const local0Facility = 16

// NewSyslogSink connects to address over network ("udp"/"tcp"). A failed initial
// dial is not fatal — it retries lazily on Write.
func NewSyslogSink(network, address string) (*SyslogSink, error) {
	if network != "udp" && network != "tcp" {
		return nil, fmt.Errorf("syslog: unsupported network %q (use udp or tcp)", network)
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}
	s := &SyslogSink{
		network:  network,
		address:  address,
		hostname: host,
		appName:  "mimic",
		procid:   fmt.Sprintf("%d", os.Getpid()),
	}
	s.dial = s.dialNet
	_ = s.connect() // best-effort; lazy retry on Write
	return s, nil
}

func (s *SyslogSink) Name() string { return "syslog" }

func (s *SyslogSink) dialNet() (netConn, error) {
	return net.Dial(s.network, s.address)
}

func (s *SyslogSink) connect() error {
	c, err := s.dial()
	if err != nil {
		return err
	}
	s.conn = c
	return nil
}

func (s *SyslogSink) Write(ev Event) error {
	frame := s.format(ev)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return err
		}
	}
	if _, err := s.conn.Write([]byte(frame)); err != nil {
		// One reconnect attempt (handles dropped TCP / restarted collector).
		_ = s.conn.Close()
		s.conn = nil
		if cerr := s.connect(); cerr != nil {
			return err
		}
		_, werr := s.conn.Write([]byte(frame))
		return werr
	}
	return nil
}

func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// format renders an RFC 5424 frame: <PRI>1 TIMESTAMP HOST APP PROCID MSGID - MSG
// with the MSG being the compact event JSON. A trailing newline frames the record
// for both UDP datagrams and newline-delimited TCP collectors.
func (s *SyslogSink) format(ev Event) string {
	pri := local0Facility*8 + syslogSeverity(ev.Severity)
	ts := ev.Time.UTC().Format(time.RFC3339)
	msg, _ := json.Marshal(ev)
	return fmt.Sprintf("<%d>1 %s %s %s %s %s - %s\n",
		pri, ts, s.hostname, s.appName, s.procid, string(ev.Type), msg)
}

// syslogSeverity maps our coarse Severity onto RFC 5424 severity codes.
func syslogSeverity(sev Severity) int {
	switch sev {
	case SevAlert:
		return 1 // alert
	case SevWarn:
		return 4 // warning
	case SevNotice:
		return 5 // notice
	default:
		return 6 // informational
	}
}

// --- memory sink (testing) ---

// MemorySink records events in memory for assertions in tests.
type MemorySink struct {
	mu     sync.Mutex
	Events []Event
}

func (m *MemorySink) Name() string { return "memory" }

func (m *MemorySink) Write(ev Event) error {
	m.mu.Lock()
	m.Events = append(m.Events, ev)
	m.mu.Unlock()
	return nil
}

func (m *MemorySink) Close() error { return nil }

// Snapshot returns a copy of recorded events.
func (m *MemorySink) Snapshot() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.Events))
	copy(out, m.Events)
	return out
}
