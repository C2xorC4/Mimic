package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/deception"
	"github.com/c2xorc4/mimic/internal/events"
	"github.com/c2xorc4/mimic/internal/logging"
)

// Listener represents a fake service listener
type Listener struct {
	config      *config.ServiceConfig
	baseDir     string
	tcpLn       net.Listener
	udpConn     *net.UDPConn
	matcher     *ProbeMatcher
	responder   *Responder
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	stats       ListenerStats
	verbose     bool
	options     map[string]string
	jitterMinMs int
	jitterMaxMs int
	log         *logging.Logger

	tlsCfg     *tls.Config // lazily generated for TLS services
	tlsOnce    sync.Once
	dynamicRPC *dynamicRPCPool
}

// ListenerStats tracks listener statistics
type ListenerStats struct {
	Connections   uint64
	ProbesMatched uint64
	ProbesMissed  uint64
	BytesReceived uint64
	BytesSent     uint64
}

// NewListener creates a new service listener from config
func NewListener(cfg *config.ServiceConfig, baseDir string) (*Listener, error) {
	return NewListenerWithOptions(cfg, baseDir, nil)
}

// NewListenerWithOptions creates a new service listener with custom options
func NewListenerWithOptions(cfg *config.ServiceConfig, baseDir string, options map[string]string) (*Listener, error) {
	matcher, err := NewProbeMatcher(cfg.Probes, options)
	if err != nil {
		return nil, fmt.Errorf("creating probe matcher: %w", err)
	}

	// Use baseDir directly - manifest paths are relative to service directory
	responder, err := NewResponderWithOptions(baseDir, options)
	if err != nil {
		return nil, fmt.Errorf("creating responder: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	if options == nil {
		options = make(map[string]string)
	}

	// Parse jitter settings from options
	jitterMin, _ := strconv.Atoi(options["jitter_min_ms"])
	jitterMax, _ := strconv.Atoi(options["jitter_max_ms"])

	return &Listener{
		config:      cfg,
		baseDir:     baseDir,
		matcher:     matcher,
		responder:   responder,
		ctx:         ctx,
		cancel:      cancel,
		verbose:     true,
		options:     options,
		jitterMinMs: jitterMin,
		jitterMaxMs: jitterMax,
		log:         logging.Component(cfg.Name),
	}, nil
}

// SetCredStore forwards the shared credential store to this listener's responder
// so it can emit leaked credentials in matched responses.
func (l *Listener) SetCredStore(s *deception.CredStore) {
	if l.responder != nil {
		l.responder.SetCredStore(s)
	}
}

// SetJitter sets response timing jitter (milliseconds)
func (l *Listener) SetJitter(minMs, maxMs int) {
	l.jitterMinMs = minMs
	l.jitterMaxMs = maxMs
}

// applyJitter sleeps for a random duration within the jitter range
func (l *Listener) applyJitter() {
	if l.jitterMaxMs <= 0 {
		return
	}
	min := l.jitterMinMs
	max := l.jitterMaxMs
	if min > max {
		min, max = max, min
	}
	if max <= 0 {
		return
	}
	delay := min
	if max > min {
		delay = min + rand.Intn(max-min)
	}
	if delay > 0 {
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
}

// Start starts the listener
func (l *Listener) Start() error {
	addr := fmt.Sprintf(":%d", l.config.Port)

	switch l.config.Protocol {
	case "tcp":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listening on TCP %s: %w", addr, err)
		}
		l.tcpLn = ln
		l.wg.Add(1)
		go l.serveTCP()
		l.logInfo("Listening", map[string]interface{}{
			"protocol": "tcp",
			"port":     l.config.Port,
		})

	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("resolving UDP address: %w", err)
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("listening on UDP %s: %w", addr, err)
		}
		l.udpConn = conn
		l.wg.Add(1)
		go l.serveUDP()
		l.logInfo("Listening", map[string]interface{}{
			"protocol": "udp",
			"port":     l.config.Port,
		})

	default:
		return fmt.Errorf("unsupported protocol: %s", l.config.Protocol)
	}

	if l.config.Name == "msrpc" && l.config.Stateful && l.config.Protocol == "tcp" {
		if err := l.startDynamicRPCPorts(); err != nil {
			l.Stop()
			return err
		}
	}

	return nil
}

func (l *Listener) startDynamicRPCPorts() error {
	rules := epmLookupRewriteRules(l.config.Probes)
	probe := eptLookupProbeBytes()
	resp, err := l.responder.GetResponse("responses/epm_lookup.bin", probe, rules)
	if err != nil {
		return fmt.Errorf("epm template for dynamic ports: %w", err)
	}
	ports := ExtractNcacnIPTCPPorts(resp, hostEgressIPv4())
	pool, err := startDynamicRPCPool(l.ctx, ports, l.baseDir, l.log)
	if err != nil {
		return err
	}
	l.dynamicRPC = pool
	return nil
}

// Stop stops the listener
func (l *Listener) Stop() error {
	l.cancel()

	if l.dynamicRPC != nil {
		l.dynamicRPC.stop()
		l.dynamicRPC = nil
	}
	if l.tcpLn != nil {
		l.tcpLn.Close()
	}
	if l.udpConn != nil {
		l.udpConn.Close()
	}

	l.wg.Wait()
	l.logInfo("Stopped", nil)
	return nil
}

func (l *Listener) serveTCP() {
	defer l.wg.Done()

	for {
		conn, err := l.tcpLn.Accept()
		if err != nil {
			select {
			case <-l.ctx.Done():
				return
			default:
				l.logWarn("Accept error", map[string]interface{}{
					"error": err.Error(),
				})
				continue
			}
		}

		atomic.AddUint64(&l.stats.Connections, 1)
		l.wg.Add(1)
		go l.handleTCPConn(conn)
	}
}

// emit fills service/source/dest fields and sends a security event to the bus.
func (l *Listener) emit(remoteAddr string, ev events.Event) {
	ev.Service = l.config.Name
	ev.DstPort = l.config.Port
	ev.SplitHostPort(remoteAddr)
	events.Emit(ev)
}

// idleReadTimeout bounds how long a connection waits for client data before the
// handler gives up and closes. Kept short: a honeypot has no reason to hold a
// socket open for a slow/idle peer, and long waits let a port scanner (nmap -sV
// fires ~16 probes per port) pin every connection open, which serializes the scan
// and times services out into "unrecognized".
const idleReadTimeout = 3 * time.Second

func (l *Listener) handleTCPConn(conn net.Conn) {
	defer l.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	l.logDebug("Connection accepted", map[string]interface{}{
		"source_addr": remoteAddr,
	})
	l.emit(remoteAddr, events.Event{Type: events.Connection, Message: l.config.Name + " connection"})

	// TLS services route by ClientHello: scanner/JARM probes get a static
	// ServerHello replay (preserving the crafted fingerprint), real clients get a
	// completed handshake + backend response (so the port doesn't FIN after the
	// ClientHello). Handled entirely in handleTLSConn.
	if l.config.TLS {
		l.handleTLSConn(conn, remoteAddr)
		return
	}

	// Server-speaks-first protocols (SSH/SMTP banners): send the connect-banner —
	// the probe that matches an empty buffer after `requires` gating — immediately,
	// before waiting for client data the client will never send first.
	if l.config.SpeaksFirst {
		if m := l.matcher.Match(nil); m != nil {
			if resp, err := l.responder.GetResponse(m.ResponseFile, nil, m.RewriteRules); err == nil && len(resp) > 0 {
				l.applyJitter()
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if w, werr := conn.Write(resp); werr == nil {
					atomic.AddUint64(&l.stats.BytesSent, uint64(w))
					atomic.AddUint64(&l.stats.ProbesMatched, 1)
					l.emit(remoteAddr, events.Event{Type: events.Probe, Message: l.config.Name + " banner sent",
						Fields: map[string]interface{}{"probe": m.Name}})
				}
			}
		}
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(idleReadTimeout))

	// Read initial probe data
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		if err != io.EOF {
			l.logDebug("Read error", map[string]interface{}{
				"source_addr": remoteAddr,
				"error":       err.Error(),
			})
		}
		return // for speaks-first, this is the normal path after a banner grab
	}

	probe := buf[:n]
	atomic.AddUint64(&l.stats.BytesReceived, uint64(n))

	l.logDebug("Data received", map[string]interface{}{
		"source_addr": remoteAddr,
		"bytes":       n,
	})

	// Match probe
	match := l.matcher.Match(probe)
	if match == nil {
		atomic.AddUint64(&l.stats.ProbesMissed, 1)
		l.logDebug("Probe unmatched", map[string]interface{}{
			"source_addr": remoteAddr,
			"probe_len":   n,
		})
		// Log to probe log
		logging.LogProbeUnmatched(l.config.Name, l.config.Port, l.config.Protocol, remoteAddr, probe)
		// Per-service default instead of a silent FIN: a port that answers *something*
		// to an unrecognized probe reads as a live service, not a decoy. Services that
		// should stay silent simply leave default_response empty.
		l.sendDefaultResponse(conn, remoteAddr, probe)
		return
	}

	atomic.AddUint64(&l.stats.ProbesMatched, 1)
	l.logDebug("Probe matched", map[string]interface{}{
		"source_addr": remoteAddr,
		"probe_name":  match.Name,
	})
	// Log to probe log
	logging.LogProbeMatched(l.config.Name, l.config.Port, l.config.Protocol, remoteAddr, match.Name, probe)
	l.emit(remoteAddr, events.Event{Type: events.Probe, Message: l.config.Name + " probe matched",
		Fields: map[string]interface{}{"probe": match.Name}})

	// Get response
	response, err := l.responder.GetResponse(match.ResponseFile, probe, match.RewriteRules)
	if err != nil {
		l.logError("Response error", map[string]interface{}{
			"probe_name": match.Name,
			"error":      err.Error(),
		})
		return
	}

	if len(response) == 0 {
		l.logDebug("Empty response", map[string]interface{}{
			"probe_name": match.Name,
		})
		return
	}

	// Apply response timing jitter
	l.applyJitter()

	// Send response
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	written, err := conn.Write(response)
	if err != nil {
		l.logError("Write error", map[string]interface{}{
			"source_addr": remoteAddr,
			"error":       err.Error(),
		})
		return
	}

	atomic.AddUint64(&l.stats.BytesSent, uint64(written))
	l.logDebug("Response sent", map[string]interface{}{
		"source_addr": remoteAddr,
		"bytes":       written,
	})

	// For stateful protocols, continue the conversation
	if l.config.Stateful {
		l.handleStatefulConversation(conn, remoteAddr)
	}
}

func (l *Listener) handleStatefulConversation(conn net.Conn, remoteAddr string) {
	// Handle additional exchanges for stateful protocols
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(idleReadTimeout))

		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				l.logDebug("Stateful read ended", map[string]interface{}{
					"source_addr": remoteAddr,
					"error":       err.Error(),
				})
			}
			return
		}

		probe := buf[:n]
		atomic.AddUint64(&l.stats.BytesReceived, uint64(n))

		match := l.matcher.Match(probe)
		if match == nil {
			atomic.AddUint64(&l.stats.ProbesMissed, 1)
			l.logDebug("Stateful probe unmatched", map[string]interface{}{
				"source_addr": remoteAddr,
			})
			logging.LogProbeUnmatched(l.config.Name, l.config.Port, l.config.Protocol, remoteAddr, probe)
			continue
		}

		atomic.AddUint64(&l.stats.ProbesMatched, 1)
		logging.LogProbeMatched(l.config.Name, l.config.Port, l.config.Protocol, remoteAddr, match.Name, probe)
		l.emit(remoteAddr, events.Event{Type: events.Probe, Message: l.config.Name + " command",
			Fields: map[string]interface{}{"probe": match.Name}})

		response, err := l.responder.GetResponse(match.ResponseFile, probe, match.RewriteRules)
		if err != nil || len(response) == 0 {
			continue
		}

		// Apply response timing jitter
		l.applyJitter()

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		written, err := conn.Write(response)
		if err != nil {
			return
		}
		atomic.AddUint64(&l.stats.BytesSent, uint64(written))

		l.logDebug("Stateful exchange", map[string]interface{}{
			"source_addr": remoteAddr,
			"probe_name":  match.Name,
			"bytes":       written,
		})
	}
}

// sendDefaultResponse writes the service's configured default reply to an
// unmatched probe (no-op when default_response is empty), so an uncovered probe
// no longer produces a tell-tale silent close.
func (l *Listener) sendDefaultResponse(conn net.Conn, remoteAddr string, probe []byte) {
	if l.config.DefaultResponse == "" {
		return
	}
	resp, err := l.responder.GetResponse(l.config.DefaultResponse, probe, nil)
	if err != nil || len(resp) == 0 {
		return
	}
	l.applyJitter()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if w, werr := conn.Write(resp); werr == nil {
		atomic.AddUint64(&l.stats.BytesSent, uint64(w))
		l.logDebug("Default response sent", map[string]interface{}{"source_addr": remoteAddr})
	}
}

// tlsConfig lazily builds (once) the server TLS config for this listener, using
// the configured computer name for the cert subject.
func (l *Listener) tlsConfig() *tls.Config {
	l.tlsOnce.Do(func() {
		// Cert CN = the host's computer-name identity, the same value SMB advertises
		// as ComputerName and NBNS as the NetBIOS name, so a scraped TLS cert subject
		// agrees with every other layer. netbios_name is the computer name proper;
		// hostname is a fallback; default matches the honeypot's own default.
		cn := l.options["netbios_name"]
		if cn == "" {
			cn = l.options["hostname"]
		}
		if cn == "" {
			cn = "WORKSTATION"
		}
		cfg, err := newTLSConfig(cn)
		if err != nil {
			l.logError("TLS config init failed", map[string]interface{}{"error": err.Error()})
			return
		}
		l.tlsCfg = cfg
	})
	return l.tlsCfg
}

// handleTLSConn routes a TLS connection: a ClientHello matching a manifest probe
// (JARM/scanner) gets static ServerHello replay to preserve the crafted
// fingerprint; any other ClientHello is terminated with crypto/tls and served by
// the configured backend, so the handshake completes instead of FIN-after-hello.
func (l *Listener) handleTLSConn(conn net.Conn, remoteAddr string) {
	conn.SetReadDeadline(time.Now().Add(idleReadTimeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	hello := buf[:n]
	atomic.AddUint64(&l.stats.BytesReceived, uint64(n))

	// Scanner/JARM probe → static replay (fingerprint-preserving), then done.
	if match := l.matcher.Match(hello); match != nil {
		atomic.AddUint64(&l.stats.ProbesMatched, 1)
		logging.LogProbeMatched(l.config.Name, l.config.Port, l.config.Protocol, remoteAddr, match.Name, hello)
		if resp, gerr := l.responder.GetResponse(match.ResponseFile, hello, match.RewriteRules); gerr == nil && len(resp) > 0 {
			l.applyJitter()
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if w, werr := conn.Write(resp); werr == nil {
				atomic.AddUint64(&l.stats.BytesSent, uint64(w))
			}
		}
		return
	}

	// Real client → complete a TLS handshake, then serve the backend.
	cfg := l.tlsConfig()
	if cfg == nil {
		return
	}
	tconn := tls.Server(&prefixConn{Conn: conn, prefix: hello}, cfg)
	tconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if herr := tconn.Handshake(); herr != nil {
		l.logDebug("TLS handshake failed", map[string]interface{}{"source_addr": remoteAddr, "error": herr.Error()})
		return
	}
	l.emit(remoteAddr, events.Event{Type: events.Connection, Message: l.config.Name + " TLS handshake completed"})
	l.serveTLSBackend(tconn, remoteAddr)
}

// serveTLSBackend answers application requests over a terminated TLS channel.
func (l *Listener) serveTLSBackend(tconn *tls.Conn, remoteAddr string) {
	switch l.config.TLSBackend {
	case "http":
		tconn.SetReadDeadline(time.Now().Add(idleReadTimeout))
		rbuf := make([]byte, 8192)
		n, _ := tconn.Read(rbuf)
		l.applyJitter()
		tconn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if w, err := tconn.Write(iisHTTPResponse(rbuf[:n])); err == nil {
			atomic.AddUint64(&l.stats.BytesSent, uint64(w))
			l.emit(remoteAddr, events.Event{Type: events.Probe, Message: l.config.Name + " HTTPS request served"})
		}
	default:
		// Handshake completed is already far better than FIN-after-ClientHello;
		// with no backend, let the peer speak briefly, then close.
		tconn.SetReadDeadline(time.Now().Add(idleReadTimeout))
		tconn.Read(make([]byte, 1024)) //nolint:errcheck
	}
}

func (l *Listener) serveUDP() {
	defer l.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}

		l.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			l.logWarn("UDP read error", map[string]interface{}{
				"error": err.Error(),
			})
			continue
		}

		atomic.AddUint64(&l.stats.Connections, 1)
		atomic.AddUint64(&l.stats.BytesReceived, uint64(n))

		probe := buf[:n]
		match := l.matcher.Match(probe)
		if match == nil {
			atomic.AddUint64(&l.stats.ProbesMissed, 1)
			logging.LogProbeUnmatched(l.config.Name, l.config.Port, l.config.Protocol, addr.String(), probe)
			continue
		}

		atomic.AddUint64(&l.stats.ProbesMatched, 1)
		logging.LogProbeMatched(l.config.Name, l.config.Port, l.config.Protocol, addr.String(), match.Name, probe)

		response, err := l.responder.GetResponse(match.ResponseFile, probe, match.RewriteRules)
		if err != nil || len(response) == 0 {
			continue
		}

		// Apply response timing jitter
		l.applyJitter()

		written, _ := l.udpConn.WriteToUDP(response, addr)
		atomic.AddUint64(&l.stats.BytesSent, uint64(written))
	}
}

// GetStats returns current listener statistics
func (l *Listener) GetStats() ListenerStats {
	return ListenerStats{
		Connections:   atomic.LoadUint64(&l.stats.Connections),
		ProbesMatched: atomic.LoadUint64(&l.stats.ProbesMatched),
		ProbesMissed:  atomic.LoadUint64(&l.stats.ProbesMissed),
		BytesReceived: atomic.LoadUint64(&l.stats.BytesReceived),
		BytesSent:     atomic.LoadUint64(&l.stats.BytesSent),
	}
}

// GetName returns the service name
func (l *Listener) GetName() string {
	return l.config.Name
}

// GetPort returns the service port
func (l *Listener) GetPort() uint16 {
	return l.config.Port
}

// SetVerbose enables or disables verbose logging
func (l *Listener) SetVerbose(v bool) {
	l.verbose = v
}

// Logging helpers
func (l *Listener) logDebug(msg string, fields map[string]interface{}) {
	if l.log != nil {
		l.log.Debug(msg, fields)
	}
}

func (l *Listener) logInfo(msg string, fields map[string]interface{}) {
	if l.log != nil {
		l.log.Info(msg, fields)
	}
}

func (l *Listener) logWarn(msg string, fields map[string]interface{}) {
	if l.log != nil {
		l.log.Warn(msg, fields)
	}
}

func (l *Listener) logError(msg string, fields map[string]interface{}) {
	if l.log != nil {
		l.log.Error(msg, fields)
	}
}
