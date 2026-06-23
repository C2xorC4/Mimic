// Package ssh implements an interactive SSH honeypot for Linux personas. Unlike
// the template SSH service (banner-only), it completes the SSH transport via
// golang.org/x/crypto/ssh, authenticates seeded credentials from the shared
// deception.CredStore (the cross-service cred-leak loop), and presents a Linux
// pseudo-shell over an in-memory filesystem grounded in the active distro's
// captured identity (banner/uname/os-release from the Phase-2.0 nmap captures).
package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/c2xorc4/mimic/internal/deception"
	"github.com/c2xorc4/mimic/internal/events"
	"github.com/c2xorc4/mimic/internal/logging"
)

// OpenSSH-like algorithm sets (the subset x/crypto/ssh supports), advertised in
// the KEXINIT so nmap ssh2-enum-algos reads an OpenSSH-shaped list rather than
// Go's defaults. Not byte-identical to OpenSSH (x/crypto lacks e.g. sntrup761),
// but materially closer than the library default.
var (
	kexAlgos    = []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256"}
	cipherAlgos = []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"}
	macAlgos    = []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512"}
)

// Config holds SSH honeypot configuration.
type Config struct {
	Port     uint16 // default 22
	OSName   string // profile name → distro identity (banner/uname/os-release)
	Hostname string // shell prompt host + /etc/hostname; default from distro

	CredStore         *deception.CredStore
	AcceptCredentials []string // pool ids to accept; empty => all
}

// Server is the SSH honeypot listener.
type Server struct {
	cfg     Config
	distro  distroInfo
	host    string
	creds   map[string]string // lowercase user -> password
	leak    map[string]string // bait file path -> content (cred-leak breadcrumbs)
	signers []xssh.Signer

	vfsOnce sync.Once
	fs      *vnode // lazily built Linux filesystem (see shell.go vfs())

	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	log    *logging.Logger
}

// New builds an SSH honeypot. Host keys are generated fresh (ed25519 + RSA, the
// modern OpenSSH default pair).
func New(cfg Config) (*Server, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	d := distroFor(cfg.OSName)
	host := cfg.Hostname
	if host == "" {
		host = d.osID + "-srv"
	}

	creds := map[string]string{}
	if cfg.CredStore != nil {
		want := cfg.AcceptCredentials
		for _, c := range cfg.CredStore.All() {
			if len(want) > 0 && !contains(want, c.ID) {
				continue
			}
			creds[strings.ToLower(c.Username)] = c.Password
		}
	}

	signers, err := genHostKeys()
	if err != nil {
		return nil, fmt.Errorf("ssh host keys: %w", err)
	}

	return &Server{
		cfg: cfg, distro: d, host: host, creds: creds,
		leak: buildLeak(cfg.CredStore, cfg.AcceptCredentials),
		signers: signers, log: logging.Component("ssh-honeypot"),
	}, nil
}

func genHostKeys() ([]xssh.Signer, error) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	edSigner, err := xssh.NewSignerFromKey(edPriv)
	if err != nil {
		return nil, err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rsaSigner, err := xssh.NewSignerFromKey(rsaKey)
	if err != nil {
		return nil, err
	}
	return []xssh.Signer{edSigner, rsaSigner}, nil
}

// buildLeak plants one cred-leak breadcrumb: a "credentials" note in /root that
// surfaces a pooled credential, so an attacker who reads it can reuse it against
// SMB (the cross-service cred-leak loop). Only the first accepted pool cred is used.
func buildLeak(store *deception.CredStore, want []string) map[string]string {
	if store == nil {
		return nil
	}
	for _, c := range store.All() {
		if len(want) > 0 && !contains(want, c.ID) {
			continue
		}
		note := fmt.Sprintf("# service account hand-off\n# do not commit\n%s:%s\n", c.Username, c.Password)
		return map[string]string{"/root/.credentials": note}
	}
	return nil
}

// Start begins listening.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.Port))
	if err != nil {
		return fmt.Errorf("ssh listen :%d: %w", s.cfg.Port, err)
	}
	s.ln = ln
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.serve()
	if s.log != nil {
		s.log.Info("SSH honeypot listening", map[string]interface{}{"port": s.cfg.Port, "banner": s.distro.sshBanner})
	}
	return nil
}

// Stop shuts the listener down.
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
	if s.log != nil {
		s.log.Info("SSH honeypot stopped", nil)
	}
}

func (s *Server) serverConfig() *xssh.ServerConfig {
	cfg := &xssh.ServerConfig{
		ServerVersion: s.distro.sshBanner,
		Config:        xssh.Config{KeyExchanges: kexAlgos, Ciphers: cipherAlgos, MACs: macAlgos},
		MaxAuthTries:  6,
		PasswordCallback: func(c xssh.ConnMetadata, pass []byte) (*xssh.Permissions, error) {
			ok := s.checkCred(c.User(), string(pass))
			s.emitAuth(c.RemoteAddr().String(), c.User(), string(pass), ok)
			if ok {
				return &xssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("permission denied")
		},
	}
	for _, sg := range s.signers {
		cfg.AddHostKey(sg)
	}
	return cfg
}

func (s *Server) checkCred(user, pass string) bool {
	want, ok := s.creds[strings.ToLower(user)]
	return ok && want == pass
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	s.emit(remote, events.Event{Type: events.Connection, Message: "SSH connection opened"})

	sshConn, chans, reqs, err := xssh.NewServerConn(conn, s.serverConfig())
	if err != nil {
		// Handshake/auth failure (the common scanner/brute case) — already logged
		// per-attempt by the password callback.
		return
	}
	defer sshConn.Close()
	go xssh.DiscardRequests(reqs)

	// Clear the handshake deadline; an authenticated shell is interactive.
	_ = conn.SetDeadline(time.Time{})

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(xssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, requests, sshConn.User(), remote)
	}
}

// handleSession services one session channel: a pty + interactive shell, or a
// single exec command.
func (s *Server) handleSession(ch xssh.Channel, requests <-chan *xssh.Request, user, remote string) {
	defer ch.Close()
	sess := &shellSession{user: user, cwd: s.homeFor(user)}
	for req := range requests {
		switch req.Type {
		case "pty-req", "env", "window-change":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			s.runShell(ch, sess, remote)
			return
		case "exec":
			cmd := decodeString(req.Payload)
			req.Reply(true, nil)
			out := s.runCommand(sess, cmd, remote)
			ch.Write([]byte(out))
			sendExit(ch, 0)
			return
		case "subsystem":
			if decodeString(req.Payload) == "sftp" {
				req.Reply(true, nil)
				s.serveSFTP(ch, remote)
				return
			}
			req.Reply(false, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

// homeFor returns the starting directory for a user.
func (s *Server) homeFor(user string) string {
	if strings.EqualFold(user, "root") {
		return "/root"
	}
	return "/home/" + user
}

// emit fills common fields and emits a security event.
func (s *Server) emit(remote string, ev events.Event) {
	ev.Service = "ssh"
	ev.DstPort = s.cfg.Port
	ev.SplitHostPort(remote)
	events.Emit(ev)
}

func (s *Server) emitAuth(remote, user, pass string, ok bool) {
	if s.log != nil {
		s.log.Info("SSH auth attempt", map[string]interface{}{"remote": remote, "user": user, "password": pass, "accepted": ok})
	}
	if ok {
		s.emit(remote, events.Event{Type: events.AuthSuccess, Severity: events.SevWarn, Message: "SSH login success",
			Fields: map[string]interface{}{"username": user, "password": pass}})
	} else {
		s.emit(remote, events.Event{Type: events.AuthAttempt, Severity: events.SevNotice, Message: "SSH login failed",
			Fields: map[string]interface{}{"username": user, "password": pass}})
	}
}

// decodeString reads an SSH string (4-byte length prefix + bytes) — the exec
// request payload is a single such string (the command line).
func decodeString(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(b[:4])
	if int(n) > len(b)-4 {
		n = uint32(len(b) - 4)
	}
	return string(b[4 : 4+n])
}

// sendExit sends an exit-status reply for an exec/shell channel.
func sendExit(ch xssh.Channel, code uint32) {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], code)
	ch.SendRequest("exit-status", false, p[:])
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
