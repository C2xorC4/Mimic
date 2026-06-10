// Package events provides a protocol-neutral security-event taxonomy and a
// fan-out bus for the honeypots. Each interaction (connection, auth attempt,
// credential capture, enumeration, download, maze descent) is emitted as a typed
// Event and delivered to every enabled sink (NDJSON file, syslog, the abuse
// detector). It is the defensive-value layer: turning honeypot interactions into
// SIEM-ingestible records and detection signal.
package events

import (
	"net"
	"sync"
	"time"
)

// Type is the kind of security event.
type Type string

const (
	Connection   Type = "connection"
	AuthAttempt  Type = "auth_attempt"
	AuthSuccess  Type = "auth_success"
	CredCapture  Type = "cred_capture"
	Enumeration  Type = "enumeration"
	FileDownload Type = "file_download"
	MazeDescent  Type = "maze_descent"
	Probe        Type = "probe"
	Block        Type = "block"
)

// Severity is a coarse signal level mapped onto syslog severities by sinks.
type Severity string

const (
	SevInfo   Severity = "info"
	SevNotice Severity = "notice"
	SevWarn   Severity = "warning"
	SevAlert  Severity = "alert"
)

// Event is one security-relevant observation from a honeypot or the detector.
type Event struct {
	Time     time.Time              `json:"time"`
	Type     Type                   `json:"type"`
	Severity Severity               `json:"severity"`
	Service  string                 `json:"service,omitempty"`
	SrcIP    string                 `json:"src_ip,omitempty"`
	SrcPort  string                 `json:"src_port,omitempty"`
	DstPort  uint16                 `json:"dst_port,omitempty"`
	Message  string                 `json:"message,omitempty"`
	Fields   map[string]interface{} `json:"fields,omitempty"`
}

// SplitHostPort fills SrcIP/SrcPort from a "host:port" remote address. Safe on
// malformed input (leaves fields blank).
func (e *Event) SplitHostPort(remoteAddr string) {
	if host, port, err := net.SplitHostPort(remoteAddr); err == nil {
		e.SrcIP, e.SrcPort = host, port
	}
}

// Sink consumes events. Implementations must be safe for concurrent Write calls.
type Sink interface {
	Name() string
	Write(Event) error
	Close() error
}

// Bus fans an event out to all registered sinks.
type Bus struct {
	mu       sync.RWMutex
	sinks    []Sink
	onError  func(sink string, err error)
}

// NewBus creates an empty bus. onError (optional) is called when a sink Write
// fails so the caller can log it without making delivery fatal.
func NewBus(onError func(sink string, err error)) *Bus {
	return &Bus{onError: onError}
}

// AddSink registers a sink.
func (b *Bus) AddSink(s Sink) {
	if s == nil {
		return
	}
	b.mu.Lock()
	b.sinks = append(b.sinks, s)
	b.mu.Unlock()
}

// Sinks returns the registered sink names (for startup logging).
func (b *Bus) Sinks() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names := make([]string, 0, len(b.sinks))
	for _, s := range b.sinks {
		names = append(names, s.Name())
	}
	return names
}

// Emit delivers ev to every sink. Defaults Time/Severity if unset. Sink failures
// are reported via onError but never block or panic the caller.
func (b *Bus) Emit(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if ev.Severity == "" {
		ev.Severity = SevInfo
	}
	b.mu.RLock()
	sinks := b.sinks
	b.mu.RUnlock()
	for _, s := range sinks {
		if err := s.Write(ev); err != nil && b.onError != nil {
			b.onError(s.Name(), err)
		}
	}
}

// Close closes all sinks.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.sinks {
		_ = s.Close()
	}
	b.sinks = nil
}

// --- global emitter (mirrors the logging package's global pattern) ---

var (
	globalMu sync.RWMutex
	global   *Bus
)

// SetGlobal installs the process-wide bus used by Emit.
func SetGlobal(b *Bus) {
	globalMu.Lock()
	global = b
	globalMu.Unlock()
}

// Emit sends an event to the global bus (no-op if uninitialized), so honeypots
// can emit without threading a bus reference through every call site.
func Emit(ev Event) {
	globalMu.RLock()
	b := global
	globalMu.RUnlock()
	if b != nil {
		b.Emit(ev)
	}
}

// CloseGlobal closes and clears the global bus.
func CloseGlobal() {
	globalMu.Lock()
	b := global
	global = nil
	globalMu.Unlock()
	if b != nil {
		b.Close()
	}
}
