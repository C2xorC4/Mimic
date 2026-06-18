// Package rdp implements a stateful RDP honeypot: X.224 negotiation, dual-path
// TLS (JARM static replay vs real termination), and CredSSP NTLM challenge with
// profile-derived Product_Version.
package rdp

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/c2xorc4/mimic/internal/events"
	"github.com/c2xorc4/mimic/internal/logging"
)

const (
	defaultPort     = 3389
	idleTimeout     = 5 * time.Second
	handshakeTimout = 8 * time.Second
)

// Config holds honeypot server configuration.
type Config struct {
	Port         uint16
	ComputerName string
	DomainName   string
	OSVersion    string // e.g. "10.0.20348" — drives NTLM Product_Version
	ServicesDir  string // base path containing rdp/responses/*.bin templates
}

// Stats holds per-server counters.
type Stats struct {
	Connections  uint64
	Negotiations uint64
	TLSHandshakes uint64
	Challenges   uint64
	Credentials  uint64
}

// Server is the RDP CredSSP honeypot TCP listener.
type Server struct {
	cfg       Config
	negTLS    []byte
	staticTLS *staticTLS
	tlsCfg    *tls.Config
	log       *logging.Logger

	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	stats struct {
		connections   uint64
		negotiations  uint64
		tlsHandshakes uint64
		challenges    uint64
		credentials   uint64
	}
}

// New creates a new RDP honeypot Server.
func New(cfg Config) (*Server, error) {
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.ComputerName == "" {
		cfg.ComputerName = "WORKSTATION"
	}
	if cfg.DomainName == "" {
		cfg.DomainName = "WORKGROUP"
	}

	rdpDir := filepath.Join(cfg.ServicesDir, "rdp")
	negPath := filepath.Join(rdpDir, "responses", "rdp_neg_tls.bin")
	negTLS, err := os.ReadFile(negPath)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", negPath, err)
	}

	staticTLS, err := newStaticTLS(rdpDir)
	if err != nil {
		return nil, err
	}

	tlsCfg, err := newTLSConfig(cfg.ComputerName)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:       cfg,
		negTLS:    negTLS,
		staticTLS: staticTLS,
		tlsCfg:    tlsCfg,
		log:       logging.Component("rdp-honeypot"),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// Start binds TCP 3389 and accepts connections.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	s.listener = ln
	s.wg.Add(1)
	go s.serve()
	if s.log != nil {
		s.log.Info("Listening", map[string]interface{}{"port": s.cfg.Port})
	}
	return nil
}

// Stop shuts down the listener.
func (s *Server) Stop() {
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
}

// GetStats returns current counters.
func (s *Server) GetStats() Stats {
	return Stats{
		Connections:   atomic.LoadUint64(&s.stats.connections),
		Negotiations:  atomic.LoadUint64(&s.stats.negotiations),
		TLSHandshakes: atomic.LoadUint64(&s.stats.tlsHandshakes),
		Challenges:    atomic.LoadUint64(&s.stats.challenges),
		Credentials:   atomic.LoadUint64(&s.stats.credentials),
	}
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}
		atomic.AddUint64(&s.stats.connections, 1)
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	s.emit(remote, events.Event{Type: events.Connection, Message: "rdp connection"})

	conn.SetReadDeadline(time.Now().Add(idleTimeout))
	payload, err := readTPKT(conn)
	if err != nil {
		return
	}

	if !isX224ConnectionRequest(payload) {
		return
	}

	conn.SetWriteDeadline(time.Now().Add(idleTimeout))
	if _, err := conn.Write(s.negTLS); err != nil {
		return
	}
	atomic.AddUint64(&s.stats.negotiations, 1)
	s.emit(remote, events.Event{Type: events.Probe, Message: "rdp x224 nego",
		Fields: map[string]interface{}{"phase": "nego"}})

	conn.SetReadDeadline(time.Now().Add(idleTimeout))
	hello := make([]byte, 4096)
	n, err := conn.Read(hello)
	if err != nil || n == 0 {
		return
	}
	hello = hello[:n]

	if resp, ok := s.staticTLS.maybeReplay(hello); ok {
		conn.SetWriteDeadline(time.Now().Add(idleTimeout))
		_, _ = conn.Write(resp)
		s.emit(remote, events.Event{Type: events.Probe, Message: "rdp tls static replay",
			Fields: map[string]interface{}{"phase": "tls_jarm"}})
		return
	}

	tconn := tls.Server(&prefixConn{Conn: conn, prefix: hello}, s.tlsCfg)
	tconn.SetReadDeadline(time.Now().Add(handshakeTimout))
	if err := tconn.Handshake(); err != nil {
		if s.log != nil {
			s.log.Debug("TLS handshake failed", map[string]interface{}{
				"source_addr": remote, "error": err.Error(),
			})
		}
		return
	}
	atomic.AddUint64(&s.stats.tlsHandshakes, 1)
	s.emit(remote, events.Event{Type: events.Connection, Message: "rdp tls handshake completed"})

	s.serveCredSSP(tconn, remote)
}

func (s *Server) serveCredSSP(conn io.ReadWriter, remote string) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if d, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			d.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		payload, tpktWrapped, err := readCredSSPPDU(conn)
		if err != nil {
			return
		}

		if negotiate := extractNTLMNegotiate(payload); negotiate != nil {
			challenge := s.buildChallenge()
			resp := buildTSRequestChallenge(challenge)
			if err := writeCredSSPPDU(conn, resp, tpktWrapped); err != nil {
				return
			}
			atomic.AddUint64(&s.stats.challenges, 1)
			s.emit(remote, events.Event{Type: events.Probe, Message: "rdp credssp challenge",
				Fields: map[string]interface{}{
					"phase": "ntlm_challenge",
					"build": s.cfg.OSVersion,
				}})
			continue
		}

		if auth := extractNTLMAuth(payload); auth != nil {
			domain, user, _ := parseNTLMAuthFields(auth)
			atomic.AddUint64(&s.stats.credentials, 1)
			s.emit(remote, events.Event{
				Type:     events.CredCapture,
				Severity: events.SevAlert,
				Message:  "RDP CredSSP NTLM credential captured",
				Fields: map[string]interface{}{
					"domain":   domain,
					"username": user,
					"ntlm":     hex.EncodeToString(auth[:min(64, len(auth))]),
				},
			})
			if s.log != nil {
				s.log.Info("RDP credential attempt", map[string]interface{}{
					"source_addr": remote,
					"domain":      domain,
					"username":    user,
				})
			}
			return
		}
	}
}

func (s *Server) buildChallenge() []byte {
	major, minor, build := osVersionTriple(s.cfg.OSVersion)
	chal := randomChallenge()
	return buildNTLMChallenge(s.cfg.ComputerName, s.cfg.DomainName, chal, major, minor, build)
}

func (s *Server) emit(remoteAddr string, ev events.Event) {
	ev.Service = "rdp"
	ev.DstPort = s.cfg.Port
	ev.SplitHostPort(remoteAddr)
	events.Emit(ev)
}