// Package smb implements a stateful SMB2 honeypot server.
//
// Phase 2 state machine: NEGOTIATE → SESSION_SETUP (NTLM challenge/auth) →
// TREE_CONNECT → all file operations return STATUS_ACCESS_DENIED.
// All authentication attempts are accepted; credentials are logged.
package smb

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/c2xorc4/mimic/internal/deception"
	"github.com/c2xorc4/mimic/internal/events"
	"github.com/c2xorc4/mimic/internal/logging"
)

// Config holds honeypot server configuration.
type Config struct {
	Port         uint16      // default 445
	NetBIOSPort  bool        // also listen on TCP 139 with NBSS session handshake
	ComputerName string      // NTLM target name / NetBIOS computer name
	DomainName   string      // NTLM domain / workgroup
	Maze         MazeConfig  // zero value → defaultMazeConfig() applied
	Shares       []ShareInfo // shares advertised via SRVSVC; nil → defaultShares()

	// Protocol behaviour, driven by the emulated OS profile.
	MaxDialect      uint16 // highest SMB2 dialect to negotiate; 0 → dialect311. dialectSMB1 → SMBv1 only.
	SMB1Enabled     bool   // whether the legacy SMBv1 stack answers (XP–8.1, Win10 w/ SMB1 feature)
	SigningRequired bool   // advertise SMB2_NEGOTIATE_SIGNING_REQUIRED (advertisement only)
	OSName          string // e.g. "Windows 11" — for NativeOS strings
	OSVersion       string // e.g. "10.0.22000" — for NativeOS strings

	// Authentication model.
	AllowGuestEnum *bool        // accept guest/null sessions and serve shares; nil → default allow
	Credentials    []Credential // seeded fake credentials that authenticate successfully

	// Config-driven content (Phase 1 deception depth).
	Filesystem *deception.TreeConfig // nil → built-in default Windows-like tree
	CredStore  *deception.CredStore  // shared pool; interpolates {{cred:...}} in seeded files
	ConfigDir  string                // base dir for resolving relative seed_file paths
}

// Stats holds per-server counters.
type Stats struct {
	Connections     uint64
	Authentications uint64
	TreeConnects    uint64
	Credentials     uint64
}

// Server is the SMB2 honeypot TCP listener.
type Server struct {
	cfg           Config
	serverGUID    [16]byte
	bootTime      time.Time
	nextSessionID uint64 // atomic

	allowGuest bool // resolved from cfg.AllowGuestEnum (nil → true)

	vfs *VFS
	log *logging.Logger

	listeners []net.Listener
	ctx       context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// counters (accessed atomically)
	stats struct {
		connections     uint64
		authentications uint64
		treeConnects    uint64
		credentials     uint64
	}
}

// pipeContext builds the per-request input for named-pipe RPC. authenticated is
// true when the SMB session bound with a real credential (not guest/null); it
// gates SAMR user enumeration (anonymous SAM enum is denied on modern Windows).
func (s *Server) pipeContext(authenticated bool) PipeContext {
	return PipeContext{
		Shares: s.cfg.Shares,
		Env: PipeRPCEnv{
			ComputerName:  s.cfg.ComputerName,
			DomainName:    s.cfg.DomainName,
			Users:         baitUsers(s.cfg.Credentials),
			Authenticated: authenticated,
		},
	}
}

// New creates a new honeypot Server with the given config.
func New(cfg Config) *Server {
	if cfg.Port == 0 {
		cfg.Port = 445
	}
	if cfg.ComputerName == "" {
		cfg.ComputerName = "WORKSTATION"
	}
	if cfg.DomainName == "" {
		cfg.DomainName = "WORKGROUP"
	}

	if cfg.MaxDialect == 0 {
		cfg.MaxDialect = dialect311 // default to a modern Windows 10/11 host
	}

	mazeCfg := cfg.Maze
	if mazeCfg.MinDirs == 0 {
		mazeCfg = defaultMazeConfig()
	}

	log := logging.Component("smb-honeypot")

	// Build the VFS: config-driven when a Filesystem is provided, otherwise the
	// built-in default Windows-like tree. A bad config falls back to the default
	// rather than failing the honeypot.
	var vfs *VFS
	if cfg.Filesystem != nil {
		if cfg.Filesystem.Maze.MinDirs == 0 {
			cfg.Filesystem.Maze = mazeCfg // inherit resolved maze defaults
		}
		v, err := newVFSFromConfig(*cfg.Filesystem, cfg.CredStore, cfg.ConfigDir)
		if err != nil {
			if log != nil {
				log.Error("config-driven VFS failed; using default tree", map[string]interface{}{"error": err.Error()})
			}
			vfs = newDefaultVFS(mazeCfg)
		} else {
			vfs = v
			// Advertise exactly the configured shares unless the caller set them.
			if len(cfg.Shares) == 0 {
				cfg.Shares = sharesFromTreeConfig(*cfg.Filesystem)
			}
		}
	} else {
		vfs = newDefaultVFS(mazeCfg)
	}

	if len(cfg.Shares) == 0 {
		cfg.Shares = defaultShares()
	}

	s := &Server{
		cfg:        cfg,
		allowGuest: cfg.AllowGuestEnum == nil || *cfg.AllowGuestEnum, // default: allow
		bootTime:   fakeBootTime(),
		vfs:        vfs,
		log:        log,
	}
	s.serverGUID = generateGUID()
	return s
}

// Start begins listening on the configured port(s).
func (s *Server) Start() error {
	type bindSpec struct {
		port uint16
		nbss bool
	}
	binds := []bindSpec{{port: s.cfg.Port, nbss: false}}
	if s.cfg.NetBIOSPort {
		binds = append(binds, bindSpec{port: 139, nbss: true})
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel

	var ports []uint16
	for _, b := range binds {
		addr := fmt.Sprintf(":%d", b.port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, existing := range s.listeners {
				existing.Close()
			}
			s.listeners = nil
			cancel()
			return fmt.Errorf("listening on %s: %w", addr, err)
		}
		s.listeners = append(s.listeners, ln)
		ports = append(ports, b.port)

		s.wg.Add(1)
		go s.serveListener(ln, b.nbss)
	}

	if s.log != nil {
		s.log.Info("Honeypot listening", map[string]interface{}{
			"ports":         ports,
			"computer_name": s.cfg.ComputerName,
			"domain":        s.cfg.DomainName,
			"netbios_port":  s.cfg.NetBIOSPort,
		})
	}
	return nil
}

// Stop shuts down the listener and waits for all connections to close.
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	for _, ln := range s.listeners {
		ln.Close()
	}
	s.wg.Wait()
	if s.log != nil {
		s.log.Info("Honeypot stopped", nil)
	}
}

// GetStats returns a snapshot of current server statistics.
func (s *Server) GetStats() Stats {
	return Stats{
		Connections:     atomic.LoadUint64(&s.stats.connections),
		Authentications: atomic.LoadUint64(&s.stats.authentications),
		TreeConnects:    atomic.LoadUint64(&s.stats.treeConnects),
		Credentials:     atomic.LoadUint64(&s.stats.credentials),
	}
}

// --- internal ---

func (s *Server) serveListener(ln net.Listener, nbssRequired bool) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if s.log != nil {
					s.log.Warn("Accept error", map[string]interface{}{"error": err.Error()})
				}
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConn(conn, nbssRequired)
	}
}

func (s *Server) handleConn(conn net.Conn, nbssRequired bool) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	atomic.AddUint64(&s.stats.connections, 1)

	if s.log != nil {
		s.log.Debug("Connection accepted", map[string]interface{}{"addr": remoteAddr})
	}

	sess := newSession()
	sess.remote = remoteAddr
	s.emit(sess, events.Event{Type: events.Connection, Message: "SMB connection opened"})

	if nbssRequired {
		if err := negotiateNetBIOSSession(conn, s.cfg.ComputerName); err != nil {
			if s.log != nil {
				s.log.Debug("NBSS handshake failed", map[string]interface{}{
					"addr": remoteAddr, "error": err.Error(),
				})
			}
			return
		}
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, err := readFrame(conn)
		if err != nil {
			return
		}

		// SMBv1 dispatch — covers negotiate/session-setup (for smb-os-discovery) and
		// the full post-auth path (tree-connect, NT-create, write, read) needed by
		// smb-enum-shares and other tools that stay on the SMBv1 protocol.
		if len(frame) >= 9 && frame[4] == 0xFF && frame[5] == 'S' && frame[6] == 'M' && frame[7] == 'B' {
			h1, ok1 := parseSMB1Header(frame)
			if !ok1 {
				continue
			}
			var resp []byte
			switch h1.command {
			case 0x72: // COM_NEGOTIATE
				resp = s.handleSMBv1Negotiate(sess, frame)
			case 0x73: // COM_SESSION_SETUP_ANDX
				resp = s.handleSMBv1SessionSetup(sess)
			case smb1CmdTreeConnect:
				resp = s.handleSMBv1TreeConnect(sess, frame, h1.uid)
			case smb1CmdNTCreateAndX:
				resp = s.handleSMBv1NTCreateAndX(sess, frame, h1)
			case smb1CmdWriteAndX:
				resp = s.handleSMBv1WriteAndX(sess, frame, h1)
			case smb1CmdReadAndX:
				resp = s.handleSMBv1ReadAndX(sess, frame, h1)
			case smb1CmdClose:
				resp = s.handleSMBv1Close(sess, frame, h1)
			case smb1CmdTreeDisconnect:
				resp = s.handleSMBv1TreeDisconnect(sess, frame, h1)
			case 0x74: // COM_LOGOFF_ANDX
				resp = buildSMB1Response(0x74, 0, h1.tid, h1.uid, []byte{0xFF, 0x00, 0x00, 0x00}, nil)
			case 0x06: // COM_DELETE — return OBJECT_NAME_NOT_FOUND (pipes can't be deleted as files)
				resp = buildSMB1Response(0x06, 0xC0000034, h1.tid, h1.uid, nil, nil)
			case 0x25: // COM_TRANSACTION — used by impacket for TransactNamedPipe (write+read combined)
				resp = s.handleSMBv1Transaction(sess, frame, h1)
			default:
				if s.log != nil {
					s.log.Debug("SMBv1 unhandled command", map[string]interface{}{
						"cmd": fmt.Sprintf("0x%02x", h1.command), "tid": h1.tid,
					})
				}
				resp = buildSMB1Response(h1.command, 0xC0000002, h1.tid, h1.uid, nil, nil) // STATUS_NOT_IMPLEMENTED
			}
			if resp != nil {
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				conn.Write(resp) //nolint:errcheck
			}
			continue
		}

		if len(frame) < pktHdrLen {
			continue // keep-alive or stub
		}

		hdr, ok := parseHeader(frame)
		if !ok {
			return // not SMB2, bail
		}

		body := frame[pktHdrLen:]

		// SMB 3.1.1 preauth integrity: fold the SESSION_SETUP *request* into the
		// hash before dispatch, so the signing-key derivation in doAccept sees a
		// preauth value that already includes this AUTH message. (NEGOTIATE is
		// folded post-dispatch, once the negotiated dialect is known.) No-op until
		// a 3.1.1 NEGOTIATE has seeded the hash.
		if hdr.Command == CmdSessionSetup {
			sess.preauthUpdate(frame[netBIOSLen:])
		}

		var response []byte

		switch hdr.Command {
		case CmdNegotiate:
			response = s.handleNegotiate(sess, hdr, body)

		case CmdSessionSetup:
			response = s.handleSessionSetup(sess, hdr, body, frame)

		case CmdTreeConnect:
			response = s.handleTreeConnect(sess, hdr, body, frame)

		case CmdTreeDisconnect:
			if hdr.TreeID != 0 {
				sess.freeTree(hdr.TreeID)
			}
			response = buildPacket(hdr, StatusSuccess, sess.id, hdr.TreeID, buildErrorBody())

		case CmdLogoff:
			response = buildPacket(hdr, StatusSuccess, sess.id, 0, buildErrorBody())

		case CmdCreate:
			response = s.handleCreate(sess, hdr, body, frame)

		case CmdClose:
			response = s.handleClose(sess, hdr, body)

		case CmdQueryDirectory:
			response = s.handleQueryDirectory(sess, hdr, body, frame)

		case CmdQueryInfo:
			response = s.handleQueryInfo(sess, hdr, body)

		case CmdRead:
			response = s.handleRead(sess, hdr, body)

		case CmdWrite:
			response = s.handleWrite(sess, hdr, body, frame)

		case CmdIOCtl:
			response = s.handleIOCtl(sess, hdr, body, frame)

		default:
			response = buildPacket(hdr, StatusAccessDenied, sess.id, hdr.TreeID, buildErrorBody())
		}

		// SMB 3.1.1 preauth integrity (post-dispatch): seed + fold the NEGOTIATE
		// exchange, and fold the SESSION_SETUP challenge response. The final
		// SESSION_SETUP success response is NOT folded — it is signed with the key
		// derived from the hash up to and including the AUTH request.
		if response != nil && sess.dialect == dialect311 {
			switch hdr.Command {
			case CmdNegotiate:
				sess.preauthInit()
				sess.preauthUpdate(frame[netBIOSLen:])
				sess.preauthUpdate(response[netBIOSLen:])
			case CmdSessionSetup:
				if binary.LittleEndian.Uint32(response[12:16]) == StatusMoreProcessing {
					sess.preauthUpdate(response[netBIOSLen:])
				}
			}
		}

		if response == nil {
			continue
		}

		// Sign responses once a verified-credential session has installed a
		// signing key (doAccept). Guest/null sessions leave signingActive false and
		// are served unsigned, which their IS_GUEST flag tells the client to expect.
		if sess.signingActive {
			signFrame(response, sess.signingKey, sess.dialect)
		}

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

// handleNegotiate and handleSMBv1Negotiate are in negotiate.go.

// handleSessionSetup dispatches to round-1 (NTLM negotiate → challenge) or
// round-2 (NTLM auth → accept) based on the NTLMSSP message type embedded in
// the security buffer.
func (s *Server) handleSessionSetup(sess *Session, req smb2Header, body []byte, frame []byte) []byte {
	secBuf := extractSecBuf(body, frame)
	ntlm := findNTLMBlob(secBuf)

	if ntlm == nil || len(ntlm) < 12 {
		// No NTLMSSP magic found.  If the security buffer is empty the client
		// is doing an anonymous/null bind (smbmap -u '' with some impacket paths,
		// older SMB clients).  Accept as guest so the session proceeds.
		if len(secBuf) == 0 {
			return s.doAnonymous(sess, req)
		}
		return buildPacket(req, StatusLogonFailure, sess.id, 0, buildSessionSetupBody(0, nil))
	}

	msgType := binary.LittleEndian.Uint32(ntlm[8:12])
	switch msgType {
	case 1: // NTLMSSP_NEGOTIATE
		return s.doChallenge(sess, req)
	case 3: // NTLMSSP_AUTH
		return s.doAccept(sess, req, ntlm)
	default:
		return buildPacket(req, StatusLogonFailure, sess.id, 0, buildSessionSetupBody(0, nil))
	}
}

// doChallenge handles SESSION_SETUP round 1: generate NTLM challenge, save it,
// return STATUS_MORE_PROCESSING_REQUIRED.
func (s *Server) doChallenge(sess *Session, req smb2Header) []byte {
	// Allocate SessionId now; echoed in all subsequent responses for this session
	sess.mu.Lock()
	if sess.id == 0 {
		sess.id = atomic.AddUint64(&s.nextSessionID, 1)
	}
	sessID := sess.id
	sess.mu.Unlock()

	challenge := genChallenge()
	sess.setChallenge(challenge)
	sess.setState(StateSetupPending)

	major, minor, build := s.osVersionTriple()
	ntlmChallenge := buildNTLMChallenge(s.cfg.ComputerName, s.cfg.DomainName, challenge, major, minor, build)
	spnego := buildSPNEGOChallengeToken(ntlmChallenge)

	return buildPacket(req, StatusMoreProcessing, sessID, 0, buildSessionSetupBody(0, spnego))
}

// doAccept handles SESSION_SETUP round 2 (NTLMSSP_AUTH). It always logs the
// captured NTLM material (a honeypot feature), then decides the session outcome:
//
//   - A username that matches a seeded credential AND whose NTLMv2 proof verifies →
//     a real authenticated session (no guest flag).
//   - A null/empty username, or a username with no/failed credential match → guest
//     session when AllowGuestEnum is set (plausibly-misconfigured host that serves the
//     maze); otherwise STATUS_LOGON_FAILURE, like a locked-down modern Windows box.
func (s *Server) doAccept(sess *Session, req smb2Header, ntlmBlob []byte) []byte {
	// Defensive: ensure session ID is assigned even if round 1 was skipped
	sess.mu.Lock()
	if sess.id == 0 {
		sess.id = atomic.AddUint64(&s.nextSessionID, 1)
	}
	sessID := sess.id
	sess.mu.Unlock()

	creds, err := parseNTLMAuth(ntlmBlob)
	if err != nil {
		if s.log != nil {
			s.log.Warn("NTLM parse error", map[string]interface{}{"error": err.Error()})
		}
	} else {
		s.logCreds(sessID, creds) // capture the hash regardless of the auth outcome
		atomic.AddUint64(&s.stats.credentials, 1)
		s.emit(sess, events.Event{Type: events.CredCapture, Severity: events.SevAlert, Message: "SMB NTLM credential captured",
			Fields: map[string]interface{}{
				"username": creds.Username, "domain": creds.Domain, "workstation": creds.Workstation,
			}})
	}

	// Seeded-credential check: a real username with a verifying NTLMv2 proof gets a
	// genuine (non-guest) session.
	if creds != nil && creds.Username != "" {
		if cred := matchCredential(s.cfg.Credentials, creds.Username); cred != nil {
			if verifyCredential(*cred, creds.Username, creds.Domain, sess.getChallenge(), creds.NTResponse) {
				atomic.AddUint64(&s.stats.authentications, 1)
				sess.setState(StateAuthenticated)
				if s.log != nil {
					s.log.Info("Seeded credential accepted", map[string]interface{}{
						"session_id": sessID, "username": creds.Username,
					})
				}
				s.emit(sess, events.Event{Type: events.AuthSuccess, Severity: events.SevWarn, Message: "SMB seeded credential authenticated",
					Fields: map[string]interface{}{"username": creds.Username, "domain": creds.Domain}})

				// Install SMB signing so this real (non-guest) session's responses
				// are accepted by signing-enforcing clients (SMB3). Without it the
				// session authenticates but every file read fails "Bad SMB2
				// signature" (OSE-2026-001 Op-5). If a signing key can't be derived
				// (e.g. 3.1.1 without a preauth chain), advertise IS_GUEST so the
				// client skips signing — but keep seededAuth set so maze/admin-share
				// access is not conflated with anonymous guest enumeration.
				sess.setSeededAuth(true)
				sess.setGuest(false)
				sessFlags := uint16(0)
				if !s.setupSigning(sess, *cred, creds) {
					sessFlags = 0x0001 // IS_GUEST (wire only — not guestSession ACL)
				}
				return buildPacket(req, StatusSuccess, sessID, 0,
					buildSessionSetupBody(sessFlags, buildSPNEGOAcceptToken()))
			}
		}
	}

	// No matching credential → guest if allowed, else deny.
	if !s.allowGuest {
		return buildPacket(req, StatusLogonFailure, sessID, 0, buildSessionSetupBody(0, nil))
	}
	atomic.AddUint64(&s.stats.authentications, 1)
	sess.setState(StateAuthenticated)
	sess.setGuest(true)
	// SessionFlags IS_GUEST (0x0001) so clients count the session as authenticated.
	// SPNEGO accept-completed token finalises the GSSAPI handshake (without it
	// impacket's SMBConnection sends an immediate LOGOFF).
	return buildPacket(req, StatusSuccess, sessID, 0, buildSessionSetupBody(0x0001, buildSPNEGOAcceptToken()))
}

// doAnonymous handles SESSION_SETUP for clients that send an empty security buffer
// (null/anonymous bind). Accepts as guest when AllowGuestEnum is set, else denies.
func (s *Server) doAnonymous(sess *Session, req smb2Header) []byte {
	sess.mu.Lock()
	if sess.id == 0 {
		sess.id = atomic.AddUint64(&s.nextSessionID, 1)
	}
	sessID := sess.id
	sess.mu.Unlock()

	if !s.allowGuest {
		return buildPacket(req, StatusLogonFailure, sessID, 0, buildSessionSetupBody(0, nil))
	}
	atomic.AddUint64(&s.stats.authentications, 1)
	sess.setState(StateAuthenticated)
	sess.setGuest(true)
	return buildPacket(req, StatusSuccess, sessID, 0, buildSessionSetupBody(0x0001, buildSPNEGOAcceptToken()))
}

// setupSigning derives and installs the SMB session signing key for a verified
// seeded credential, so the honeypot can sign responses on a real (non-guest)
// session. Because we know the seeded password we can reproduce the same
// ExportedSessionKey the client computes:
//
//	SessionBaseKey → (NTLM key exchange) → ExportedSessionKey → (SP800-108 KDF) → SigningKey
//
// Returns false when no key can be derived (e.g. a 3.1.1 session with no preauth
// chain, or an NT response too short to verify), signalling the caller to fall
// back to a guest-flagged session rather than emit responses the client rejects.
func (s *Server) setupSigning(sess *Session, cred Credential, auth *NTLMCredentials) bool {
	if auth == nil {
		return false
	}
	baseKey := ntlmSessionBaseKey(cred, auth.Username, auth.Domain, auth.NTResponse)
	if baseKey == nil {
		return false
	}
	esk := exportedSessionKey(baseKey, auth.Flags, auth.EncryptedSessionKey)
	sk := deriveSigningKey(esk, sess.dialect, sess.preauth)
	if len(sk) < 16 {
		return false
	}
	sess.signingKey = sk
	sess.signingActive = true
	if s.log != nil {
		s.log.Debug("SMB signing active", map[string]interface{}{
			"session_id": sess.id, "dialect": sess.dialect,
		})
	}
	return true
}

// handleTreeConnect parses the share path and returns STATUS_SUCCESS with a
// newly allocated tree ID.  All subsequent file operations on this tree will
// return STATUS_ACCESS_DENIED.
func (s *Server) handleTreeConnect(sess *Session, req smb2Header, body []byte, frame []byte) []byte {
	if sess.getState() < StateAuthenticated {
		return buildPacket(req, StatusAccessDenied, sess.id, 0, buildErrorBody())
	}

	sharePath := extractTreePath(body, frame)
	shareName := shareFromTree(sharePath)
	if !sess.canAccessAdminShare() && isAdminShare(shareName) {
		return buildPacket(req, StatusAccessDenied, sess.id, 0, buildErrorBody())
	}
	if !s.isKnownShare(shareName) {
		if s.log != nil {
			s.log.Warn("Tree connect rejected", map[string]interface{}{
				"session_id": sess.id,
				"raw_path":   sharePath,
				"share_name": shareName,
			})
		}
		return buildPacket(req, 0xC00000CC, sess.id, 0, buildErrorBody()) // STATUS_BAD_NETWORK_NAME
	}

	treeID := sess.allocTree(sharePath)
	atomic.AddUint64(&s.stats.treeConnects, 1)

	if s.log != nil {
		s.log.Info("Tree connect", map[string]interface{}{
			"session_id": sess.id,
			"tree_id":    treeID,
			"share":      sharePath,
		})
	}

	shareType := byte(0x01) // DISK
	if strings.EqualFold(shareName, "IPC$") {
		shareType = 0x02 // PIPE
	}

	tcBody := make([]byte, 16)
	binary.LittleEndian.PutUint16(tcBody[0:2], 16) // StructureSize
	tcBody[2] = shareType
	binary.LittleEndian.PutUint32(tcBody[4:8], 0x00000800) // ShareFlags
	// Capabilities = 0
	binary.LittleEndian.PutUint32(tcBody[12:16], 0x001f01ff) // MaximalAccess (full access advertised)

	return buildPacket(req, StatusSuccess, sess.id, treeID, tcBody)
}

// --- packet field extractors ---

// extractSecBuf reads the security buffer from a SESSION_SETUP request body.
// SESSION_SETUP body: StructureSize(2) Flags(1) SecurityMode(1) Capabilities(4)
//
//	Channel(4) SecurityBufferOffset(2) SecurityBufferLength(2)
//	PreviousSessionId(8) Buffer(...)
//
// SecurityBufferOffset is from the start of the SMB2 header (packet[4]).
func extractSecBuf(body []byte, frame []byte) []byte {
	if len(body) < 16 {
		return nil
	}
	offset := binary.LittleEndian.Uint16(body[12:14]) // from SMB2 header start
	length := binary.LittleEndian.Uint16(body[14:16])
	if length == 0 {
		return nil
	}
	start := int(4) + int(offset) // packet[4] = SMB2 header start
	end := start + int(length)
	if end > len(frame) {
		return nil
	}
	return frame[start:end]
}

// extractTreePath reads the UNC share path from a TREE_CONNECT request body.
// TREE_CONNECT body: StructureSize(2) Reserved(2) PathOffset(2) PathLength(2) Buffer(...)
// PathOffset is from the start of the SMB2 header (packet[4]).
func extractTreePath(body []byte, frame []byte) string {
	if len(body) < 8 {
		return ""
	}
	pathOff := binary.LittleEndian.Uint16(body[4:6])
	pathLen := binary.LittleEndian.Uint16(body[6:8])
	if pathLen == 0 {
		return ""
	}
	start := int(4) + int(pathOff)
	end := start + int(pathLen)
	if end > len(frame) {
		return ""
	}
	raw := frame[start:end]
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(u16))
}

// --- response body builders ---

// buildSessionSetupBody builds a SESSION_SETUP response body.
// sessionFlags: 0x0000=normal, 0x0001=IS_GUEST, 0x0002=IS_NULL (anonymous).
// secBuf may be nil for an empty security buffer (STATUS_SUCCESS round 2).
func buildSessionSetupBody(sessionFlags uint16, secBuf []byte) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9)            // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], sessionFlags) // SessionFlags
	// SecurityBufferOffset: from SMB2 header start = 64 (header) + 8 (fixed body) = 72
	binary.LittleEndian.PutUint16(body[4:6], 72)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(secBuf)))
	body = append(body, secBuf...)
	return body
}

// --- misc helpers ---

func genChallenge() [8]byte {
	var c [8]byte
	ns := time.Now().UnixNano()
	for i := range c {
		c[i] = byte(ns >> (uint(i) * 8))
		ns = ns*6364136223846793005 + 1442695040888963407
	}
	return c
}

func generateGUID() [16]byte {
	var g [16]byte
	ns := time.Now().UnixNano()
	for i := range g {
		g[i] = byte(ns >> uint(i*4))
		ns = ns*1103515245 + 12345
	}
	g[6] = (g[6] & 0x0f) | 0x40 // version 4
	g[8] = (g[8] & 0x3f) | 0x80 // variant RFC 4122
	return g
}

func fakeBootTime() time.Time {
	ns := time.Now().UnixNano()
	hours := int64(2 + (ns>>32)%24)
	minutes := int64((ns >> 16) % 60)
	return time.Now().Add(-time.Duration(hours)*time.Hour - time.Duration(minutes)*time.Minute)
}

// emit fills the common service/source/dest fields and sends a security event.
func (s *Server) emit(sess *Session, ev events.Event) {
	ev.Service = "smb"
	ev.DstPort = s.cfg.Port
	if sess != nil {
		ev.SplitHostPort(sess.remote)
	}
	events.Emit(ev)
}

func (s *Server) logCreds(sessionID uint64, c *NTLMCredentials) {
	if s.log == nil {
		return
	}
	s.log.Info("Credentials captured", map[string]interface{}{
		"session_id":  sessionID,
		"domain":      c.Domain,
		"username":    c.Username,
		"workstation": c.Workstation,
		"nt_response": hex.EncodeToString(c.NTResponse),
		"lm_response": hex.EncodeToString(c.LMResponse),
	})
}

// --- Phase 3: VFS handlers ---

// shareFromTree extracts the share name from a UNC path like \\HOST\C$.
func shareFromTree(uncPath string) string {
	s := strings.TrimLeft(uncPath, `\/`)
	idx := strings.IndexAny(s, `\/`)
	if idx < 0 {
		return strings.ToUpper(s)
	}
	return strings.ToUpper(s[idx+1:])
}

// isKnownShare returns true if name matches one of the configured shares (case-insensitive).
// IPC$ is always valid (required for MSRPC regardless of share config).
func (srv *Server) isKnownShare(name string) bool {
	if strings.EqualFold(name, "IPC$") {
		return true
	}
	for _, sh := range srv.cfg.Shares {
		if strings.EqualFold(sh.Name, name) {
			return true
		}
	}
	return false
}

// handleCreate opens a file or directory handle from the VFS.
// CREATE request body[44:46]=NameOffset (from SMB2 hdr), body[46:48]=NameLength.
func (s *Server) handleCreate(sess *Session, req smb2Header, body []byte, frame []byte) []byte {
	if sess.getState() < StateAuthenticated {
		return buildPacket(req, StatusAccessDenied, sess.id, req.TreeID, buildErrorBody())
	}
	if len(body) < 57 {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}

	nameOff := binary.LittleEndian.Uint16(body[44:46])
	nameLen := binary.LittleEndian.Uint16(body[46:48])

	var filePath string
	if nameLen > 0 {
		start := 4 + int(nameOff) // nameOff relative to SMB2 header start (frame[4])
		end := start + int(nameLen)
		if end <= len(frame) {
			raw := frame[start:end]
			u16 := make([]uint16, len(raw)/2)
			for i := range u16 {
				u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
			}
			filePath = string(utf16.Decode(u16))
		}
	}

	shareName := shareFromTree(sess.treePathFor(req.TreeID))

	// Named pipes live on IPC$; bypass the VFS and allocate a pipe handle directly.
	if strings.EqualFold(shareName, "IPC$") {
		pipeName := canonicalizePipeName(filePath)
		if pipeName == "" {
			pipeName = "srvsvc" // default to SRVSVC if path is empty
		}
		ps := newPipeState(pipeName)
		volatileID := sess.allocPipeHandle(ps)
		b := make([]byte, 88)
		binary.LittleEndian.PutUint16(b[0:2], 89)
		binary.LittleEndian.PutUint32(b[4:8], 1) // CreateAction=FILE_OPENED
		copy(b[8:16], windowsFiletime(s.bootTime))
		copy(b[16:24], windowsFiletime(s.bootTime))
		copy(b[24:32], windowsFiletime(s.bootTime))
		copy(b[32:40], windowsFiletime(s.bootTime))
		binary.LittleEndian.PutUint32(b[56:60], 0x00000080) // FILE_ATTRIBUTE_NORMAL
		binary.LittleEndian.PutUint64(b[72:80], volatileID)
		if s.log != nil {
			s.log.Debug("Pipe open", map[string]interface{}{
				"session_id": sess.id, "pipe": pipeName, "handle": volatileID,
			})
		}
		return buildPacket(req, StatusSuccess, sess.id, req.TreeID, b)
	}

	node := s.vfs.resolve(shareName, filePath)
	if node == nil {
		return buildPacket(req, StatusObjectNotFound, sess.id, req.TreeID, buildErrorBody())
	}

	volatileID := sess.allocHandle(node, shareName)

	if s.log != nil {
		s.log.Debug("Create", map[string]interface{}{
			"session_id": sess.id,
			"share":      shareName,
			"path":       filePath,
			"handle":     volatileID,
		})
	}

	// CREATE response: StructureSize=89, fixed body = 88 bytes
	b := make([]byte, 88)
	binary.LittleEndian.PutUint16(b[0:2], 89) // StructureSize
	// OplockLevel=0 (none), Flags=0
	binary.LittleEndian.PutUint32(b[4:8], 1) // CreateAction=FILE_OPENED
	copy(b[8:16], windowsFiletime(node.created))
	copy(b[16:24], windowsFiletime(node.modified))
	copy(b[24:32], windowsFiletime(node.modified))
	copy(b[32:40], windowsFiletime(node.modified))
	binary.LittleEndian.PutUint64(b[40:48], uint64(node.allocSize()))
	binary.LittleEndian.PutUint64(b[48:56], uint64(node.size()))
	binary.LittleEndian.PutUint32(b[56:60], node.attrs)
	// [60:64] Reserved2 = 0
	// FileId: Persistent[64:72]=0, Volatile[72:80]=volatileID
	binary.LittleEndian.PutUint64(b[72:80], volatileID)
	// CreateContextsOffset[80:84]=0, CreateContextsLength[84:88]=0

	return buildPacket(req, StatusSuccess, sess.id, req.TreeID, b)
}

// handleClose closes a file handle and releases it.
// CLOSE request body[8:16]=FileId.Persistent, body[16:24]=FileId.Volatile.
func (s *Server) handleClose(sess *Session, req smb2Header, body []byte) []byte {
	if len(body) < 24 {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}
	volatileID := binary.LittleEndian.Uint64(body[16:24])
	h := sess.getHandle(volatileID)
	if h == nil {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}
	node := h.node
	sess.freeHandle(volatileID)

	// CLOSE response: StructureSize=60, fixed = 60 bytes
	b := make([]byte, 60)
	binary.LittleEndian.PutUint16(b[0:2], 60)
	if node != nil {
		copy(b[8:16], windowsFiletime(node.created))
		copy(b[16:24], windowsFiletime(node.modified))
		copy(b[24:32], windowsFiletime(node.modified))
		copy(b[32:40], windowsFiletime(node.modified))
		binary.LittleEndian.PutUint64(b[40:48], uint64(node.allocSize()))
		binary.LittleEndian.PutUint64(b[48:56], uint64(node.size()))
		binary.LittleEndian.PutUint32(b[56:60], node.attrs)
	} else {
		// Pipe handle — node is nil; return current time as timestamps.
		now := windowsFiletime(time.Now())
		copy(b[8:16], now)
		copy(b[16:24], now)
		copy(b[24:32], now)
		copy(b[32:40], now)
	}

	return buildPacket(req, StatusSuccess, sess.id, req.TreeID, b)
}

// handleQueryDirectory enumerates a directory handle.
// Supports FileInformationClass 3 (FileBothDir) and 37 (FileIdBothDir).
func (s *Server) handleQueryDirectory(sess *Session, req smb2Header, body []byte, frame []byte) []byte {
	if len(body) < 32 {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}

	infoClass := body[2]
	flags := body[3]
	volatileID := binary.LittleEndian.Uint64(body[16:24])
	outputLen := binary.LittleEndian.Uint32(body[28:32])

	h := sess.getHandle(volatileID)
	if h == nil || h.node == nil {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}
	if !h.node.isDir() {
		return buildPacket(req, StatusNotADirectory, sess.id, req.TreeID, buildErrorBody())
	}

	if flags&0x01 != 0 { // SL_RESTART_SCAN
		sess.resetDir(volatileID)
	}

	if !h.hasMoreChildren(s.vfs) {
		return buildPacket(req, StatusNoMoreFiles, sess.id, req.TreeID, buildErrorBody())
	}

	var packed [][]byte
	totalLen := 0
	for h.hasMoreChildren(s.vfs) {
		name, node, _ := h.nextChild(s.vfs)
		entry := buildDirEntry(name, node, infoClass)
		if totalLen+len(entry) > int(outputLen) && len(packed) > 0 {
			h.dirIdx-- // put back
			break
		}
		packed = append(packed, entry)
		totalLen += len(entry)
	}

	// Wire up NextEntryOffset chain; last entry stays 0.
	for i := 0; i < len(packed)-1; i++ {
		binary.LittleEndian.PutUint32(packed[i][0:4], uint32(len(packed[i])))
	}

	buf := make([]byte, 0, totalLen)
	for _, e := range packed {
		buf = append(buf, e...)
	}

	// Response body: StructureSize=9, OutputBufferOffset=72 (SMB2hdr+8), Length=len(buf)
	resp := make([]byte, 8)
	binary.LittleEndian.PutUint16(resp[0:2], 9)
	binary.LittleEndian.PutUint16(resp[2:4], 72)
	binary.LittleEndian.PutUint32(resp[4:8], uint32(len(buf)))
	resp = append(resp, buf...)

	return buildPacket(req, StatusSuccess, sess.id, req.TreeID, resp)
}

// handleQueryInfo returns file or filesystem metadata.
// InfoType 1=file, 2=filesystem.
func (s *Server) handleQueryInfo(sess *Session, req smb2Header, body []byte) []byte {
	if len(body) < 40 {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}

	infoType := body[2]
	infoClass := body[3]
	volatileID := binary.LittleEndian.Uint64(body[32:40])

	h := sess.getHandle(volatileID)
	if h == nil {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}
	node := h.node

	var infoBuf []byte

	switch infoType {
	case 1: // SMB2_0_INFO_FILE
		switch infoClass {
		case 4: // FileBasicInformation: times(32) + attrs(4) + reserved(4) = 40
			b := make([]byte, 40)
			copy(b[0:8], windowsFiletime(node.created))
			copy(b[8:16], windowsFiletime(node.modified))
			copy(b[16:24], windowsFiletime(node.modified))
			copy(b[24:32], windowsFiletime(node.modified))
			binary.LittleEndian.PutUint32(b[32:36], node.attrs)
			infoBuf = b

		case 5: // FileStandardInformation: allocSize(8)+endOfFile(8)+links(4)+del(1)+dir(1)+pad(2) = 24
			b := make([]byte, 24)
			binary.LittleEndian.PutUint64(b[0:8], uint64(node.allocSize()))
			binary.LittleEndian.PutUint64(b[8:16], uint64(node.size()))
			binary.LittleEndian.PutUint32(b[16:20], 1) // NumberOfLinks
			if node.isDir() {
				b[21] = 1
			}
			infoBuf = b

		case 34: // FileNetworkOpenInformation: times(32)+sizes(16)+attrs(4)+reserved(4) = 56
			b := make([]byte, 56)
			copy(b[0:8], windowsFiletime(node.created))
			copy(b[8:16], windowsFiletime(node.modified))
			copy(b[16:24], windowsFiletime(node.modified))
			copy(b[24:32], windowsFiletime(node.modified))
			binary.LittleEndian.PutUint64(b[32:40], uint64(node.allocSize()))
			binary.LittleEndian.PutUint64(b[40:48], uint64(node.size()))
			binary.LittleEndian.PutUint32(b[48:52], node.attrs)
			infoBuf = b

		case 18: // FileAllInformation (MS-FSCC 2.4.2) — smbclient queries this before
			// a download ("getattrib"); without it `get` fails NT_STATUS_NOT_SUPPORTED
			// even though the data is readable, so bait files can be listed but not
			// retrieved. Aggregate of Basic+Standard+Internal+Ea+Access+Position+
			// Mode+Alignment+Name = 100 bytes fixed + name.
			name := utf16LE(node.name)
			b := make([]byte, 100+len(name))
			// FileBasicInformation [0:40]
			copy(b[0:8], windowsFiletime(node.created))
			copy(b[8:16], windowsFiletime(node.modified))
			copy(b[16:24], windowsFiletime(node.modified))
			copy(b[24:32], windowsFiletime(node.modified))
			binary.LittleEndian.PutUint32(b[32:36], node.attrs)
			// FileStandardInformation [40:64]
			binary.LittleEndian.PutUint64(b[40:48], uint64(node.allocSize()))
			binary.LittleEndian.PutUint64(b[48:56], uint64(node.size()))
			binary.LittleEndian.PutUint32(b[56:60], 1) // NumberOfLinks
			if node.isDir() {
				b[61] = 1 // Directory
			}
			// FileInternalInformation [64:72] IndexNumber=0; FileEaInformation [72:76] EaSize=0
			binary.LittleEndian.PutUint32(b[76:80], 0x001f01ff) // FileAccessInformation: AccessFlags
			// FilePositionInformation [80:88]=0; FileModeInformation [88:92]=0; Alignment [92:96]=0
			binary.LittleEndian.PutUint32(b[96:100], uint32(len(name))) // FileNameInformation length
			copy(b[100:], name)
			infoBuf = b

		default:
			if s.log != nil {
				s.log.Debug("QueryInfo unsupported file class", map[string]interface{}{"class": infoClass})
			}
			return buildPacket(req, StatusNotSupported, sess.id, req.TreeID, buildErrorBody())
		}

	case 2: // SMB2_0_INFO_FILESYSTEM
		switch infoClass {
		case 1: // FileFsVolumeInformation
			label := utf16LE("Windows")
			b := make([]byte, 18+len(label))
			copy(b[0:8], windowsFiletime(vfsBaseTime()))                // VolumeCreationTime
			binary.LittleEndian.PutUint32(b[8:12], 0x12345678)          // VolumeSerialNumber
			binary.LittleEndian.PutUint32(b[12:16], uint32(len(label))) // VolumeLabelLength
			// SupportsObjects[16]=0, Reserved[17]=0
			copy(b[18:], label)
			infoBuf = b

		case 3: // FileFsSizeInformation: 24 bytes
			b := make([]byte, 24)
			binary.LittleEndian.PutUint64(b[0:8], 25165824)  // TotalAllocationUnits (~100 GB)
			binary.LittleEndian.PutUint64(b[8:16], 12582912) // AvailableAllocationUnits (~50 GB)
			binary.LittleEndian.PutUint32(b[16:20], 8)       // SectorsPerAllocationUnit
			binary.LittleEndian.PutUint32(b[20:24], 512)     // BytesPerSector
			infoBuf = b

		case 5: // FileFsAttributeInformation
			fsName := utf16LE("NTFS")
			b := make([]byte, 12+len(fsName))
			binary.LittleEndian.PutUint32(b[0:4], 0x0002003F) // FileSystemAttributes (NTFS)
			binary.LittleEndian.PutUint32(b[4:8], 255)        // MaximumComponentNameLength
			binary.LittleEndian.PutUint32(b[8:12], uint32(len(fsName)))
			copy(b[12:], fsName)
			infoBuf = b

		case 7: // FileFsFullSizeInformation: 32 bytes
			b := make([]byte, 32)
			binary.LittleEndian.PutUint64(b[0:8], 25165824)
			binary.LittleEndian.PutUint64(b[8:16], 12582912)
			binary.LittleEndian.PutUint64(b[16:24], 12582912)
			binary.LittleEndian.PutUint32(b[24:28], 8)
			binary.LittleEndian.PutUint32(b[28:32], 512)
			infoBuf = b

		default:
			return buildPacket(req, StatusNotSupported, sess.id, req.TreeID, buildErrorBody())
		}

	default:
		return buildPacket(req, StatusNotSupported, sess.id, req.TreeID, buildErrorBody())
	}

	// Response: StructureSize=9, OutputBufferOffset=72
	resp := make([]byte, 8)
	binary.LittleEndian.PutUint16(resp[0:2], 9)
	binary.LittleEndian.PutUint16(resp[2:4], 72)
	binary.LittleEndian.PutUint32(resp[4:8], uint32(len(infoBuf)))
	resp = append(resp, infoBuf...)

	return buildPacket(req, StatusSuccess, sess.id, req.TreeID, resp)
}

// handleRead serves bait file content.
// READ request: body[4:8]=Length, body[8:16]=Offset, body[16:24]=FileId.Persistent, body[24:32]=Volatile.
func (s *Server) handleRead(sess *Session, req smb2Header, body []byte) []byte {
	if len(body) < 48 {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}

	readLen := binary.LittleEndian.Uint32(body[4:8])
	offset := binary.LittleEndian.Uint64(body[8:16])
	volatileID := binary.LittleEndian.Uint64(body[24:32])

	h := sess.getHandle(volatileID)
	if h == nil {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}

	// Named pipe read: return queued DCE/RPC response.
	if h.pipe != nil {
		data := h.pipe.Read()
		if len(data) == 0 {
			return buildPacket(req, StatusEndOfFile, sess.id, req.TreeID, buildErrorBody())
		}
		resp := make([]byte, 16)
		binary.LittleEndian.PutUint16(resp[0:2], 17)
		resp[2] = 80
		binary.LittleEndian.PutUint32(resp[4:8], uint32(len(data)))
		resp = append(resp, data...)
		return buildPacket(req, StatusSuccess, sess.id, req.TreeID, resp)
	}

	if h.node.isDir() {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}

	if isRegistryHiveFile(h.node.name) {
		return buildPacket(req, StatusAccessDenied, sess.id, req.TreeID, buildErrorBody())
	}

	content := h.node.content
	if offset >= uint64(len(content)) {
		return buildPacket(req, StatusEndOfFile, sess.id, req.TreeID, buildErrorBody())
	}

	end := offset + uint64(readLen)
	if end > uint64(len(content)) {
		end = uint64(len(content))
	}
	data := content[offset:end]

	if offset == 0 { // emit once per file, at the start of the read
		s.emit(sess, events.Event{Type: events.FileDownload, Severity: events.SevNotice, Message: "SMB file read",
			Fields: map[string]interface{}{"file": h.node.name, "share": h.shareName, "bytes": h.node.size()}})
	}

	if s.log != nil {
		s.log.Debug("Read", map[string]interface{}{
			"session_id": sess.id,
			"handle":     volatileID,
			"offset":     offset,
			"length":     len(data),
		})
	}

	// READ response: StructureSize=17, DataOffset=80 (64 hdr + 16 fixed body)
	resp := make([]byte, 16)
	binary.LittleEndian.PutUint16(resp[0:2], 17)                // StructureSize
	resp[2] = 80                                                // DataOffset (from SMB2 header start)
	binary.LittleEndian.PutUint32(resp[4:8], uint32(len(data))) // DataLength
	// DataRemaining[8:12]=0, Reserved2[12:16]=0
	resp = append(resp, data...)

	return buildPacket(req, StatusSuccess, sess.id, req.TreeID, resp)
}

// handleWrite accepts data for named-pipe handles (DCE/RPC) or silently discards
// file writes. Returns a WRITE_RESPONSE with the byte count acknowledged.
// WRITE request: [2:4]=DataOffset [4:8]=Length [8:16]=Offset
//
//	[16:24]=FileId.Persistent [24:32]=FileId.Volatile [44:48]=Flags
//	DataOffset is from SMB2 header start (frame[4]).
func (s *Server) handleWrite(sess *Session, req smb2Header, body []byte, frame []byte) []byte {
	if len(body) < 48 {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}
	writeLen := binary.LittleEndian.Uint32(body[4:8])
	volatileID := binary.LittleEndian.Uint64(body[24:32]) // FileId.Volatile (not Persistent)
	dataOff := binary.LittleEndian.Uint16(body[2:4])      // DataOffset relative to SMB2 header start (frame[4])

	h := sess.getHandle(volatileID)
	if h == nil {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}

	if h.pipe != nil {
		start := int(4) + int(dataOff)
		end := start + int(writeLen)
		if end <= len(frame) {
			h.pipe.Write(frame[start:end], s.pipeContext(!sess.isGuest()))
		}
	}

	// WRITE response: StructureSize=17, Count=writeLen
	resp := make([]byte, 16)
	binary.LittleEndian.PutUint16(resp[0:2], 17)
	binary.LittleEndian.PutUint32(resp[4:8], writeLen)
	return buildPacket(req, StatusSuccess, sess.id, req.TreeID, resp)
}

// handleIOCtl dispatches IOCTL requests. The only code we handle is
// FSCTL_PIPE_TRANSCEIVE (0x0011C017) which combines a pipe write + read.
// IOCTL request body: StructureSize(2) Reserved(2) CtlCode(4) FileId(16)
//
//	InputOffset(4) InputCount(4) MaxInputResponse(4)
//	OutputOffset(4) OutputCount(4) MaxOutputResponse(4)
//	Flags(4) Reserved2(4) [Buffer…]
func (s *Server) handleIOCtl(sess *Session, req smb2Header, body []byte, frame []byte) []byte {
	if len(body) < 56 {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}
	ctlCode := binary.LittleEndian.Uint32(body[4:8])
	volatileID := binary.LittleEndian.Uint64(body[24:32]) // FileId.Volatile

	const fsctlPipeTransceive = uint32(0x0011C017)
	if ctlCode != fsctlPipeTransceive {
		// Unsupported IOCTL — return not supported
		return buildPacket(req, StatusNotSupported, sess.id, req.TreeID, buildErrorBody())
	}

	h := sess.getHandle(volatileID)
	if h == nil || h.pipe == nil {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
	}

	inputOff := binary.LittleEndian.Uint32(body[32:36])
	inputCount := binary.LittleEndian.Uint32(body[36:40])
	var input []byte
	if inputCount > 0 {
		start := int(4) + int(inputOff)
		end := start + int(inputCount)
		if end <= len(frame) {
			input = frame[start:end]
		}
	}

	output := h.pipe.Transceive(input, s.pipeContext(!sess.isGuest()))

	// IOCTL response: StructureSize=49, fixed body 48 bytes
	// OutputOffset = 64 (SMB2 header) + 48 (fixed body) = 112
	resp := make([]byte, 48)
	binary.LittleEndian.PutUint16(resp[0:2], 49)
	binary.LittleEndian.PutUint32(resp[4:8], ctlCode)
	binary.LittleEndian.PutUint64(resp[16:24], volatileID) // FileId.Volatile
	if len(output) > 0 {
		binary.LittleEndian.PutUint32(resp[36:40], 112)                 // OutputOffset
		binary.LittleEndian.PutUint32(resp[40:44], uint32(len(output))) // OutputCount
	}
	resp = append(resp, output...)
	return buildPacket(req, StatusSuccess, sess.id, req.TreeID, resp)
}

// --- SMBv1 compatibility layer (for nmap smb.lua scripts) ---

// buildSMBv1Frame constructs a NetBIOS-framed SMBv1 response packet.
// params must be an even number of bytes (WordCount = len(params)/2).
func buildSMBv1Frame(command byte, status uint32, uid uint16, params []byte, data []byte) []byte {
	wordCount := byte(len(params) / 2)
	payloadLen := 32 + 1 + len(params) + 2 + len(data)
	buf := make([]byte, 4+payloadLen)

	// NetBIOS session header (4 bytes)
	buf[1] = byte(payloadLen >> 16)
	buf[2] = byte(payloadLen >> 8)
	buf[3] = byte(payloadLen)

	// SMBv1 header (32 bytes starting at buf[4])
	off := 4
	buf[off], buf[off+1], buf[off+2], buf[off+3] = 0xFF, 'S', 'M', 'B'
	buf[off+4] = command
	binary.LittleEndian.PutUint32(buf[off+5:off+9], status)
	buf[off+9] = 0x98                                         // flags: REPLY(0x80) | CANONICAL_PATHS(0x10) | CASE_INSENSITIVE(0x08)
	binary.LittleEndian.PutUint16(buf[off+10:off+12], 0x4001) // flags2: UNICODE | LONG_NAMES
	binary.LittleEndian.PutUint16(buf[off+28:off+30], uid)    // uid
	off += 32

	buf[off] = wordCount
	off++
	copy(buf[off:off+len(params)], params)
	off += len(params)
	binary.LittleEndian.PutUint16(buf[off:off+2], uint16(len(data)))
	copy(buf[off+2:], data)

	return buf
}

// buildSMBv1NegotiateResponse builds a legacy SMBv1 NEGOTIATE response (NT LM 0.12 selected).
// Called for pure SMBv1-only clients that don't advertise any SMBv2 dialect.
// Data section carries domain + server as UTF-16LE null-terminated strings (required by smb.lua).
func (s *Server) buildSMBv1NegotiateResponse(sess *Session) []byte {
	sess.setState(StateNegotiated)

	// Parameters: 17 words = 34 bytes
	params := make([]byte, 34)
	binary.LittleEndian.PutUint16(params[0:2], 0)            // DialectIndex = 0
	params[2] = 0x03                                         // SecurityMode: user-level + challenge
	binary.LittleEndian.PutUint16(params[3:5], 50)           // MaxMPX
	binary.LittleEndian.PutUint16(params[5:7], 1)            // MaxVC
	binary.LittleEndian.PutUint32(params[7:11], 16644)       // MaxBufferSize
	binary.LittleEndian.PutUint32(params[11:15], 65536)      // MaxRawBuffer
	binary.LittleEndian.PutUint32(params[15:19], 0)          // SessionKey
	binary.LittleEndian.PutUint32(params[19:23], 0x000000B5) // Capabilities — CAP_EXTENDED_SECURITY bit intentionally absent
	copy(params[23:31], windowsFiletime(time.Now()))         // SystemTime
	// TimeZone[31:33] = 0 (UTC), KeyLength[33] = 0

	// Data: domain (UTF-16LE + null) + server (UTF-16LE + null).
	// smb.lua reads these even when key_length=0; fails with [14] if absent.
	data := append(utf16LE(s.cfg.DomainName), 0x00, 0x00)
	data = append(data, append(utf16LE(s.cfg.ComputerName), 0x00, 0x00)...)

	return buildSMBv1Frame(0x72, 0, 0, params, data)
}

// buildSMBv1NegotiateRefusal builds an SMBv1 NEGOTIATE response that accepts none
// of the offered dialects (DialectIndex = 0xFFFF). This emulates a Windows host
// with SMB1 removed (Win10 default / Win11 / Server 2019): the SMB1 negotiate fails,
// and SMBv1-only tools (nmap smb-enum-shares) report "couldn't negotiate a SMBv1
// connection" — the correct, realistic outcome for those hosts.
func (s *Server) buildSMBv1NegotiateRefusal(sess *Session) []byte {
	// WordCount = 1: just the DialectIndex field, set to 0xFFFF (no dialect chosen).
	params := make([]byte, 2)
	binary.LittleEndian.PutUint16(params[0:2], 0xFFFF)
	return buildSMBv1Frame(0x72, 0, 0, params, nil)
}

// handleSMBv1SessionSetup responds to SMB_COM_SESSION_SETUP_ANDX with OS info strings.
// nmap's smb-os-discovery reads NativeOS, NativeLanMan, and PrimaryDomain from here.
func (s *Server) handleSMBv1SessionSetup(sess *Session) []byte {
	sess.mu.Lock()
	if sess.id == 0 {
		sess.id = atomic.AddUint64(&s.nextSessionID, 1)
	}
	uid := uint16(sess.id & 0xFFFF)
	sess.mu.Unlock()
	sess.setState(StateAuthenticated)
	atomic.AddUint64(&s.stats.authentications, 1)

	// Parameters: 3 words = 6 bytes
	// ANDX_CMD(1) ANDX_RSVD(1) ANDX_OFF(2) ACTION(2)
	params := make([]byte, 6)
	params[0] = 0xFF                                   // no further ANDX command
	binary.LittleEndian.PutUint16(params[4:6], 0x0001) // Action = guest

	// Data: NativeOS\0 NativeLanMan\0 PrimaryDomain\0
	osStr := s.nativeOSString()
	var data []byte
	for _, str := range []string{osStr, osStr, s.cfg.DomainName} {
		data = append(data, []byte(str)...)
		data = append(data, 0x00)
	}

	return buildSMBv1Frame(0x73, 0, uid, params, data)
}

// nativeOSString derives the legacy NativeOS string ("Windows <major>.<minor>")
// from the profile version, so smb-os-discovery reflects the emulated OS instead of
// a hardcoded value (e.g. XP 5.1.2600 → "Windows 5.1", Win 7 → "Windows 6.1",
// Win 11 10.0.22000 → "Windows 10.0").
func (s *Server) nativeOSString() string {
	if parts := strings.SplitN(s.cfg.OSVersion, ".", 3); len(parts) >= 2 {
		return "Windows " + parts[0] + "." + parts[1]
	}
	return "Windows 10.0"
}

// osVersionTriple parses the profile version ("10.0.22000") into the
// major/minor/build fields the NTLM CHALLENGE advertises. When OSVersion is
// unset or malformed (e.g. in unit tests), it falls back to Windows 10.0
// build 19041 — the historic hardcoded default — so a missing profile never
// produces a nonsensical 0.0.0 version block.
func (s *Server) osVersionTriple() (major, minor uint8, build uint16) {
	major, minor, build = 10, 0, 19041
	parts := strings.SplitN(s.cfg.OSVersion, ".", 3)
	if len(parts) >= 1 {
		if v, err := strconv.Atoi(parts[0]); err == nil {
			major = uint8(v)
		}
	}
	if len(parts) >= 2 {
		if v, err := strconv.Atoi(parts[1]); err == nil {
			minor = uint8(v)
		}
	}
	if len(parts) >= 3 {
		if v, err := strconv.Atoi(parts[2]); err == nil {
			build = uint16(v)
		}
	}
	return major, minor, build
}
