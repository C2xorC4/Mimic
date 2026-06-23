// Package control is the local management/control plane for a running Mimic
// instance — the RBAC-gated surface the `mimic ctl` client talks to. It listens
// on a same-host transport (a unix socket on Linux; Windows named-pipe is a
// future addition), authenticates the connecting peer by OS credentials, runs
// every request through an Authorizer (role → allowed-operations), serves
// read-only status/log/ping operations, and audits each access onto the event
// bus. It is deliberately small and authz-gated from day one so the full RBAC
// role engine and a future system-tray UI bolt onto the same seam without a
// retrofit; with no roles configured only root may use it (current behaviour).
package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/c2xorc4/mimic/internal/events"
	"github.com/c2xorc4/mimic/internal/logging"
)

// ErrUnsupported is returned by the platform listener where the control plane is
// not yet implemented (non-Linux).
var ErrUnsupported = errors.New("control plane is only supported on Linux (unix socket) for now")

// ErrDenied is returned by an Authorizer that rejects a peer/op.
var ErrDenied = errors.New("access denied")

// Peer is the authenticated identity of a control-plane client (unix peer creds).
type Peer struct {
	UID uint32
	GID uint32
	PID int32
}

// Request is one control operation (line-delimited JSON).
type Request struct {
	Op string `json:"op"`
	N  int    `json:"n,omitempty"` // for "logs": number of recent events
}

// Response is the reply to a Request.
type Response struct {
	OK    bool        `json:"ok"`
	Role  string      `json:"role,omitempty"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

// Status is the snapshot returned by the "status" op.
type Status struct {
	Profile   string   `json:"profile"`
	Edition   string   `json:"edition,omitempty"`
	Services  []string `json:"services"`
	Pid       int      `json:"pid"`
	UptimeSec int64    `json:"uptime_sec"`
	Events    int      `json:"events"`
}

// Authorizer decides whether a peer may invoke an operation, returning the role
// it was granted under (for audit) or an error (ErrDenied).
type Authorizer interface {
	Authorize(peer Peer, op string) (role string, err error)
}

// Server is the control-plane listener.
type Server struct {
	authz    Authorizer
	statusFn func() Status
	ring     *Ring
	socket   string
	start    time.Time
	log      *logging.Logger

	ln      net.Listener
	wg      sync.WaitGroup
	closing atomic.Bool
}

// New builds a control server. statusFn supplies the live status snapshot; ring
// is the event ring buffer served by "logs" (also a bus Sink — register it).
func New(authz Authorizer, statusFn func() Status, ring *Ring) *Server {
	return &Server{authz: authz, statusFn: statusFn, ring: ring, start: time.Now(), log: logging.Component("control")}
}

// Start opens the platform transport at socket and serves in the background.
func (s *Server) Start(socket string) error {
	ln, err := listen(socket)
	if err != nil {
		return err
	}
	s.ln, s.socket = ln, socket
	s.wg.Add(1)
	go s.accept()
	if s.log != nil {
		s.log.Info("Control plane listening", map[string]interface{}{"socket": socket})
	}
	return nil
}

// Stop closes the listener and removes the socket.
func (s *Server) Stop() {
	s.closing.Store(true)
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
	cleanupSocket(s.socket)
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if s.closing.Load() {
				return
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	peer, perr := peerCred(conn)
	dec := json.NewDecoder(bufio.NewReader(conn))
	var req Request
	if err := dec.Decode(&req); err != nil {
		writeJSON(conn, Response{OK: false, Error: "bad request"})
		return
	}

	grantedRole, aerr := s.authz.Authorize(peer, req.Op)
	s.audit(peer, req.Op, grantedRole, aerr == nil && perr == nil)
	if perr != nil {
		writeJSON(conn, Response{OK: false, Error: "peer authentication failed"})
		return
	}
	if aerr != nil {
		writeJSON(conn, Response{OK: false, Error: ErrDenied.Error()})
		return
	}

	switch req.Op {
	case "ping":
		writeJSON(conn, Response{OK: true, Role: grantedRole, Data: "pong"})
	case "status":
		st := s.statusFn()
		st.UptimeSec = int64(time.Since(s.start).Seconds())
		st.Events = s.ring.Count()
		writeJSON(conn, Response{OK: true, Role: grantedRole, Data: st})
	case "logs":
		n := req.N
		if n <= 0 {
			n = 20
		}
		writeJSON(conn, Response{OK: true, Role: grantedRole, Data: s.ring.Last(n)})
	default:
		writeJSON(conn, Response{OK: false, Role: grantedRole, Error: "unknown op: " + req.Op})
	}
}

// audit emits a Control event for every access (granted or denied) — the audit
// trail RBAC needs. Severity escalates for denials.
func (s *Server) audit(peer Peer, op, role string, allowed bool) {
	sev := events.SevInfo
	msg := "control access granted"
	if !allowed {
		sev, msg = events.SevWarn, "control access denied"
	}
	events.Emit(events.Event{
		Type: events.Control, Severity: sev, Service: "control", Message: msg,
		Fields: map[string]interface{}{"op": op, "role": role, "peer_uid": peer.UID, "peer_gid": peer.GID, "peer_pid": peer.PID, "allowed": allowed},
	})
}

func writeJSON(conn net.Conn, resp Response) {
	b, _ := json.Marshal(resp)
	conn.Write(append(b, '\n'))
}

// Ring is a fixed-size event ring buffer that is also an events.Sink, so the
// control plane can serve the last-N events without a separate store.
type Ring struct {
	mu  sync.Mutex
	buf []events.Event
	max int
}

// NewRing creates a ring retaining the most recent max events.
func NewRing(max int) *Ring {
	if max <= 0 {
		max = 200
	}
	return &Ring{max: max}
}

func (r *Ring) Name() string { return "control-ring" }

func (r *Ring) Write(ev events.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, ev)
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
	return nil
}

func (r *Ring) Close() error { return nil }

// Last returns up to n most-recent events (newest last).
func (r *Ring) Last(n int) []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n > len(r.buf) {
		n = len(r.buf)
	}
	out := make([]events.Event, n)
	copy(out, r.buf[len(r.buf)-n:])
	return out
}

// Count returns the number of retained events.
func (r *Ring) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf)
}
