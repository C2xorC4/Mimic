package services

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
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
	matcher, err := NewProbeMatcher(cfg.Probes)
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

	return nil
}

// Stop stops the listener
func (l *Listener) Stop() error {
	l.cancel()

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

func (l *Listener) handleTCPConn(conn net.Conn) {
	defer l.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	l.logDebug("Connection accepted", map[string]interface{}{
		"source_addr": remoteAddr,
	})

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

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
		return
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
		return
	}

	atomic.AddUint64(&l.stats.ProbesMatched, 1)
	l.logDebug("Probe matched", map[string]interface{}{
		"source_addr": remoteAddr,
		"probe_name":  match.Name,
	})
	// Log to probe log
	logging.LogProbeMatched(l.config.Name, l.config.Port, l.config.Protocol, remoteAddr, match.Name, probe)

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

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

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
