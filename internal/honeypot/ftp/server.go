// Package ftp implements a stateful FTP honeypot whose virtual filesystem and
// seeded credentials come from the protocol-neutral internal/deception core — the
// same core the SMB honeypot uses. It is the second interactive service proving
// that deception depth (config-driven tree, seeded files, infinite maze) and the
// shared credential pool are reusable across protocols.
package ftp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/c2xorc4/mimic/internal/deception"
	"github.com/c2xorc4/mimic/internal/events"
	"github.com/c2xorc4/mimic/internal/logging"
)

// Config holds FTP honeypot configuration.
type Config struct {
	Port   uint16 // default 21
	Banner string // 220 greeting; default Microsoft FTP-style
	OSName string // for SYST / informational strings

	// Content: a prebuilt Tree (shared with other services) takes precedence;
	// otherwise Filesystem is built via deception.BuildTree.
	Tree       *deception.Tree
	Filesystem *deception.TreeConfig
	RootShare  string // which tree root is the FTP root; default: C$, else first
	ConfigDir  string // base dir for relative seed_file paths

	// Auth: anonymous and/or pooled cleartext credentials.
	AllowAnonymous    bool
	CredStore         *deception.CredStore
	AcceptCredentials []string // pool ids to accept; empty => all

	PasvHost string // address advertised in PASV; default: control conn local IP
}

// Server is the FTP honeypot listener.
type Server struct {
	cfg     Config
	tree    *deception.Tree
	rootKey string
	creds   map[string]string // lowercase username -> cleartext password (pooled)

	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	log    *logging.Logger
}

// New builds an FTP honeypot. A bad filesystem config falls back to the default
// deception tree rather than failing the service.
func New(cfg Config) (*Server, error) {
	if cfg.Port == 0 {
		cfg.Port = 21
	}
	if cfg.Banner == "" {
		cfg.Banner = "Microsoft FTP Service"
	}
	if cfg.OSName == "" {
		cfg.OSName = "Windows_NT"
	}

	log := logging.Component("ftp-honeypot")

	tree := cfg.Tree
	if tree == nil {
		tc := deception.DefaultMazeConfig()
		if cfg.Filesystem != nil {
			t, err := deception.BuildTree(*cfg.Filesystem, cfg.CredStore, cfg.ConfigDir)
			if err != nil {
				if log != nil {
					log.Error("config-driven FTP tree failed; using default", map[string]interface{}{"error": err.Error()})
				}
				tree = deception.DefaultTree(tc)
			} else {
				tree = t
			}
		} else {
			tree = deception.DefaultTree(tc)
		}
	}

	rootKey := strings.ToUpper(cfg.RootShare)
	if _, ok := tree.Roots[rootKey]; !ok {
		rootKey = pickRoot(tree)
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

	return &Server{cfg: cfg, tree: tree, rootKey: rootKey, creds: creds, log: log}, nil
}

func pickRoot(t *deception.Tree) string {
	if _, ok := t.Roots["C$"]; ok {
		return "C$"
	}
	for k := range t.Roots {
		return k
	}
	return ""
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Start begins listening on the configured port.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	s.ln = ln
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.serve()
	if s.log != nil {
		s.log.Info("FTP honeypot listening", map[string]interface{}{"port": s.cfg.Port, "root": s.rootKey})
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
		s.log.Info("FTP honeypot stopped", nil)
	}
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
			s.handle(conn)
		}()
	}
}

// session is per-control-connection state.
type session struct {
	conn   net.Conn
	r      *bufio.Reader
	user   string
	authed bool
	cwd    string // slash-rooted path within the FTP root, e.g. "/" or "/Users"
	dataLn net.Listener
	remote string
}

func (s *Server) reply(c net.Conn, code int, msg string) {
	c.Write([]byte(fmt.Sprintf("%d %s\r\n", code, msg)))
}

// emit fills the common service/source/dest fields and sends a security event.
func (s *Server) emit(sess *session, ev events.Event) {
	ev.Service = "ftp"
	ev.DstPort = s.cfg.Port
	ev.SplitHostPort(sess.remote)
	events.Emit(ev)
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	sess := &session{conn: conn, r: bufio.NewReader(conn), cwd: "/", remote: conn.RemoteAddr().String()}

	// Close the control connection promptly on server shutdown so a client idling
	// in ReadString doesn't block Stop() until the read deadline.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-s.ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	defer func() {
		if sess.dataLn != nil {
			sess.dataLn.Close()
		}
	}()

	if s.log != nil {
		s.log.Debug("FTP connection", map[string]interface{}{"remote": sess.remote})
	}
	s.emit(sess, events.Event{Type: events.Connection, Message: "FTP connection opened"})
	s.reply(conn, 220, s.cfg.Banner)

	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		line, err := sess.r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		cmd, arg := splitCmd(line)
		if !s.dispatch(sess, cmd, arg) {
			return // QUIT or fatal
		}
	}
}

func splitCmd(line string) (string, string) {
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return strings.ToUpper(line[:i]), line[i+1:]
	}
	return strings.ToUpper(line), ""
}

// dispatch handles one command; returns false to close the connection.
func (s *Server) dispatch(sess *session, cmd, arg string) bool {
	c := sess.conn
	switch cmd {
	case "USER":
		sess.user = arg
		sess.authed = false
		s.reply(c, 331, fmt.Sprintf("Password required for %s.", arg))
	case "PASS":
		s.handlePass(sess, arg)
	case "QUIT":
		s.reply(c, 221, "Goodbye.")
		return false
	case "SYST":
		s.reply(c, 215, "Windows_NT")
	case "FEAT":
		c.Write([]byte("211-Features:\r\n PASV\r\n UTF8\r\n SIZE\r\n MDTM\r\n211 End\r\n"))
	case "OPTS":
		s.reply(c, 200, "OK")
	case "NOOP":
		s.reply(c, 200, "OK")
	case "TYPE":
		s.reply(c, 200, "Type set to "+arg+".")
	case "PWD", "XPWD":
		s.reply(c, 257, fmt.Sprintf("%q is current directory.", sess.cwd))
	default:
		if !sess.authed {
			s.reply(c, 530, "Not logged in.")
			return true
		}
		return s.dispatchAuthed(sess, cmd, arg)
	}
	return true
}

func (s *Server) handlePass(sess *session, pass string) {
	c := sess.conn
	u := strings.ToLower(sess.user)
	ok := false
	switch {
	case s.cfg.AllowAnonymous && (u == "anonymous" || u == "ftp"):
		ok = true
	default:
		if want, exists := s.creds[u]; exists && want == pass {
			ok = true
		}
	}
	if s.log != nil {
		s.log.Info("FTP auth attempt", map[string]interface{}{
			"remote": sess.remote, "user": sess.user, "password": pass, "accepted": ok,
		})
	}
	if ok {
		sess.authed = true
		s.emit(sess, events.Event{Type: events.AuthSuccess, Severity: events.SevWarn, Message: "FTP login success",
			Fields: map[string]interface{}{"username": sess.user, "password": pass}})
		s.reply(c, 230, "User logged in.")
	} else {
		s.emit(sess, events.Event{Type: events.AuthAttempt, Severity: events.SevNotice, Message: "FTP login failed",
			Fields: map[string]interface{}{"username": sess.user, "password": pass}})
		s.reply(c, 530, "Login incorrect.")
	}
}

func (s *Server) dispatchAuthed(sess *session, cmd, arg string) bool {
	c := sess.conn
	switch cmd {
	case "CWD", "XCWD":
		target := s.resolvePath(sess.cwd, arg)
		n := s.tree.Resolve(s.rootKey, toTreePath(target))
		if n != nil && n.IsDir() {
			sess.cwd = target
			s.reply(c, 250, "Directory changed to "+target+".")
		} else {
			s.reply(c, 550, arg+": The system cannot find the path specified.")
		}
	case "CDUP":
		sess.cwd = s.resolvePath(sess.cwd, "..")
		s.reply(c, 250, "Directory changed to "+sess.cwd+".")
	case "PASV":
		s.handlePasv(sess)
	case "LIST":
		s.handleList(sess, arg, true)
	case "NLST":
		s.handleList(sess, arg, false)
	case "RETR":
		s.handleRetr(sess, arg)
	case "SIZE":
		n := s.tree.Resolve(s.rootKey, toTreePath(s.resolvePath(sess.cwd, arg)))
		if n != nil && !n.IsDir() {
			s.reply(c, 213, fmt.Sprintf("%d", n.Size()))
		} else {
			s.reply(c, 550, arg+": not a regular file.")
		}
	case "MDTM":
		n := s.tree.Resolve(s.rootKey, toTreePath(s.resolvePath(sess.cwd, arg)))
		if n != nil {
			s.reply(c, 213, n.Modified.UTC().Format("20060102150405"))
		} else {
			s.reply(c, 550, "not found.")
		}
	default:
		s.reply(c, 502, cmd+" not implemented.")
	}
	return true
}

// handlePasv opens an ephemeral data listener and advertises it.
func (s *Server) handlePasv(sess *session) {
	if sess.dataLn != nil {
		sess.dataLn.Close()
		sess.dataLn = nil
	}
	host := s.cfg.PasvHost
	if host == "" {
		if la, ok := sess.conn.LocalAddr().(*net.TCPAddr); ok {
			host = la.IP.String()
		} else {
			host = "127.0.0.1"
		}
	}
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		s.reply(sess.conn, 425, "Can't open data connection.")
		return
	}
	sess.dataLn = ln
	port := ln.Addr().(*net.TCPAddr).Port
	ipParts := strings.Split(host, ".")
	if len(ipParts) != 4 {
		ipParts = []string{"127", "0", "0", "1"}
	}
	s.reply(sess.conn, 227, fmt.Sprintf("Entering Passive Mode (%s,%s,%s,%s,%d,%d).",
		ipParts[0], ipParts[1], ipParts[2], ipParts[3], port>>8, port&0xff))
}

// acceptData accepts the pending PASV data connection (with a timeout).
func (s *session) acceptData() (net.Conn, error) {
	if s.dataLn == nil {
		return nil, fmt.Errorf("no PASV")
	}
	s.dataLn.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
	dc, err := s.dataLn.Accept()
	s.dataLn.Close()
	s.dataLn = nil
	return dc, err
}

func (s *Server) handleList(sess *session, arg string, long bool) {
	c := sess.conn
	// LIST/NLST may carry flags (e.g. "-la") or a path; strip leading flags.
	target := sess.cwd
	if arg != "" && !strings.HasPrefix(arg, "-") {
		target = s.resolvePath(sess.cwd, arg)
	}
	node := s.tree.Resolve(s.rootKey, toTreePath(target))
	if node == nil || !node.IsDir() {
		s.reply(c, 550, "Not a directory.")
		return
	}
	if sess.dataLn == nil {
		s.reply(c, 425, "Use PASV first.")
		return
	}
	s.reply(c, 150, "Opening ASCII mode data connection.")
	dc, err := sess.acceptData()
	if err != nil {
		s.reply(c, 425, "Can't open data connection.")
		return
	}
	children := s.tree.Children(node)
	var sb strings.Builder
	for _, ch := range children {
		if long {
			sb.WriteString(formatListLine(ch))
		} else {
			sb.WriteString(ch.Name + "\r\n")
		}
	}
	dc.Write([]byte(sb.String()))
	dc.Close()
	if s.log != nil {
		s.log.Info("FTP list", map[string]interface{}{"remote": sess.remote, "path": target, "entries": len(children)})
	}
	etype := events.Enumeration
	if node.MazePath != "" {
		etype = events.MazeDescent
	}
	s.emit(sess, events.Event{Type: etype, Severity: events.SevNotice, Message: "FTP directory listing",
		Fields: map[string]interface{}{"path": target, "entries": len(children), "maze": node.MazePath != ""}})
	s.reply(c, 226, "Transfer complete.")
}

func (s *Server) handleRetr(sess *session, arg string) {
	c := sess.conn
	node := s.tree.Resolve(s.rootKey, toTreePath(s.resolvePath(sess.cwd, arg)))
	if node == nil || node.IsDir() {
		s.reply(c, 550, arg+": The system cannot find the file specified.")
		return
	}
	if sess.dataLn == nil {
		s.reply(c, 425, "Use PASV first.")
		return
	}
	s.reply(c, 150, fmt.Sprintf("Opening BINARY mode data connection for %s (%d bytes).", path.Base(arg), node.Size()))
	dc, err := sess.acceptData()
	if err != nil {
		s.reply(c, 425, "Can't open data connection.")
		return
	}
	dc.Write(node.Content)
	dc.Close()
	if s.log != nil {
		s.log.Info("FTP download", map[string]interface{}{"remote": sess.remote, "file": arg, "bytes": node.Size()})
	}
	s.emit(sess, events.Event{Type: events.FileDownload, Severity: events.SevNotice, Message: "FTP file download",
		Fields: map[string]interface{}{"file": arg, "bytes": node.Size()}})
	s.reply(c, 226, "Transfer complete.")
}

// resolvePath joins/normalizes an FTP arg against the current dir into a clean
// slash-rooted path (always absolute within the FTP root).
func (s *Server) resolvePath(cwd, arg string) string {
	arg = strings.ReplaceAll(arg, "\\", "/")
	var p string
	if strings.HasPrefix(arg, "/") {
		p = arg
	} else {
		p = cwd + "/" + arg
	}
	p = path.Clean(p)
	if p == "." || p == "" {
		p = "/"
	}
	return p
}

// toTreePath converts a slash-rooted FTP path into the relative path the tree
// Resolve expects (no leading slash; backslash separators are also accepted).
func toTreePath(p string) string {
	return strings.TrimPrefix(p, "/")
}

// formatListLine renders one entry in Windows IIS (MS-DOS) LIST style.
func formatListLine(n *deception.Node) string {
	t := n.Modified
	if t.IsZero() {
		t = deception.BaseTime()
	}
	hour := t.Hour()
	ampm := "AM"
	if hour >= 12 {
		ampm = "PM"
	}
	h12 := hour % 12
	if h12 == 0 {
		h12 = 12
	}
	date := fmt.Sprintf("%02d-%02d-%02d  %02d:%02d%s", int(t.Month()), t.Day(), t.Year()%100, h12, t.Minute(), ampm)
	if n.IsDir() {
		return fmt.Sprintf("%s       <DIR>          %s\r\n", date, n.Name)
	}
	return fmt.Sprintf("%s       %14d %s\r\n", date, n.Size(), n.Name)
}
