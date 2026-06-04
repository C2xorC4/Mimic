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
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/c2xorc4/mimic/internal/logging"
)

// Config holds honeypot server configuration.
type Config struct {
	Port         uint16     // default 445
	ComputerName string     // NTLM target name / NetBIOS computer name
	DomainName   string     // NTLM domain / workgroup
	Maze         MazeConfig // zero value → defaultMazeConfig() applied
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
	cfg          Config
	serverGUID   [16]byte
	bootTime     time.Time
	nextSessionID uint64 // atomic

	vfs *VFS
	log *logging.Logger

	ln     net.Listener
	ctx    context.Context
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

	mazeCfg := cfg.Maze
	if mazeCfg.MinDirs == 0 {
		mazeCfg = defaultMazeConfig()
	}

	s := &Server{
		cfg:      cfg,
		bootTime: fakeBootTime(),
		vfs:      newDefaultVFS(mazeCfg),
		log:      logging.Component("smb-honeypot"),
	}
	s.serverGUID = generateGUID()
	return s
}

// Start begins listening on the configured port.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	s.ln = ln

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel

	s.wg.Add(1)
	go s.serve()

	if s.log != nil {
		s.log.Info("Honeypot listening", map[string]interface{}{
			"port":          s.cfg.Port,
			"computer_name": s.cfg.ComputerName,
			"domain":        s.cfg.DomainName,
		})
	}
	return nil
}

// Stop shuts down the listener and waits for all connections to close.
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.ln != nil {
		s.ln.Close()
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

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
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
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	atomic.AddUint64(&s.stats.connections, 1)

	if s.log != nil {
		s.log.Debug("Connection accepted", map[string]interface{}{"addr": remoteAddr})
	}

	sess := newSession()

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

		if len(frame) < pktHdrLen {
			continue // keep-alive or stub
		}

		hdr, ok := parseHeader(frame)
		if !ok {
			return // not SMB2, bail
		}

		body := frame[pktHdrLen:]
		var response []byte

		switch hdr.Command {
		case CmdNegotiate:
			response = s.handleNegotiate(sess, hdr)

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

		default:
			response = buildPacket(hdr, StatusAccessDenied, sess.id, hdr.TreeID, buildErrorBody())
		}

		if response == nil {
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

// handleNegotiate builds an SMB 2.1 NEGOTIATE response.
// We advertise dialect 0x0210 for simplicity (no NegotiateContexts required).
func (s *Server) handleNegotiate(sess *Session, req smb2Header) []byte {
	sess.setState(StateNegotiated)
	spnego := buildSPNEGONegotiateToken()

	// Body: 64 bytes fixed + security buffer
	body := make([]byte, 64+len(spnego))

	binary.LittleEndian.PutUint16(body[0:2], 65)     // StructureSize (must be 65)
	binary.LittleEndian.PutUint16(body[2:4], 0x0210) // DialectRevision: SMB 2.1
	// [4:6]  NegotiateContextCount = 0 (reserved in 2.1)
	// [6:8]  Reserved
	copy(body[8:24], s.serverGUID[:])
	binary.LittleEndian.PutUint32(body[24:28], 0x00000079) // Capabilities
	binary.LittleEndian.PutUint32(body[28:32], 8388608)    // MaxTransactSize
	binary.LittleEndian.PutUint32(body[32:36], 8388608)    // MaxReadSize
	binary.LittleEndian.PutUint32(body[36:40], 8388608)    // MaxWriteSize
	copy(body[40:48], windowsFiletime(time.Now()))         // SystemTime
	copy(body[48:56], windowsFiletime(s.bootTime))         // ServerStartTime
	// SecurityBufferOffset: from SMB2 header start (64) + body fixed (64) = 128
	binary.LittleEndian.PutUint16(body[56:58], 128)
	binary.LittleEndian.PutUint16(body[58:60], uint16(len(spnego)))
	// [60:64] NegotiateContextOffset = 0
	copy(body[64:], spnego)

	return buildPacket(req, StatusSuccess, 0, 0, body)
}

// handleSessionSetup dispatches to round-1 (NTLM negotiate → challenge) or
// round-2 (NTLM auth → accept) based on the NTLMSSP message type embedded in
// the security buffer.
func (s *Server) handleSessionSetup(sess *Session, req smb2Header, body []byte, frame []byte) []byte {
	secBuf := extractSecBuf(body, frame)
	ntlm := findNTLMBlob(secBuf)

	if ntlm == nil || len(ntlm) < 12 {
		// No recognizable NTLMSSP — return logon failure
		return buildPacket(req, StatusLogonFailure, sess.id, 0, buildSessionSetupBody(nil))
	}

	msgType := binary.LittleEndian.Uint32(ntlm[8:12])
	switch msgType {
	case 1: // NTLMSSP_NEGOTIATE
		return s.doChallenge(sess, req)
	case 3: // NTLMSSP_AUTH
		return s.doAccept(sess, req, ntlm)
	default:
		return buildPacket(req, StatusLogonFailure, sess.id, 0, buildSessionSetupBody(nil))
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

	ntlmChallenge := buildNTLMChallenge(s.cfg.ComputerName, s.cfg.DomainName, challenge)
	spnego := buildSPNEGOChallengeToken(ntlmChallenge)

	return buildPacket(req, StatusMoreProcessing, sessID, 0, buildSessionSetupBody(spnego))
}

// doAccept handles SESSION_SETUP round 2: parse credentials, log them, and
// return STATUS_SUCCESS with an empty security buffer.
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
		s.logCreds(sessID, creds)
		atomic.AddUint64(&s.stats.credentials, 1)
	}

	atomic.AddUint64(&s.stats.authentications, 1)
	sess.setState(StateAuthenticated)

	return buildPacket(req, StatusSuccess, sessID, 0, buildSessionSetupBody(nil))
}

// handleTreeConnect parses the share path and returns STATUS_SUCCESS with a
// newly allocated tree ID.  All subsequent file operations on this tree will
// return STATUS_ACCESS_DENIED.
func (s *Server) handleTreeConnect(sess *Session, req smb2Header, body []byte, frame []byte) []byte {
	if sess.getState() < StateAuthenticated {
		return buildPacket(req, StatusAccessDenied, sess.id, 0, buildErrorBody())
	}

	sharePath := extractTreePath(body, frame)
	treeID := sess.allocTree(sharePath)
	atomic.AddUint64(&s.stats.treeConnects, 1)

	if s.log != nil {
		s.log.Info("Tree connect", map[string]interface{}{
			"session_id": sess.id,
			"tree_id":    treeID,
			"share":      sharePath,
		})
	}

	tcBody := make([]byte, 16)
	binary.LittleEndian.PutUint16(tcBody[0:2], 16)       // StructureSize
	tcBody[2] = 0x01                                       // ShareType = DISK
	binary.LittleEndian.PutUint32(tcBody[4:8], 0x00000800) // ShareFlags
	// Capabilities = 0
	binary.LittleEndian.PutUint32(tcBody[12:16], 0x001f01ff) // MaximalAccess (full access advertised)

	return buildPacket(req, StatusSuccess, sess.id, treeID, tcBody)
}

// --- packet field extractors ---

// extractSecBuf reads the security buffer from a SESSION_SETUP request body.
// SESSION_SETUP body: StructureSize(2) Flags(1) SecurityMode(1) Capabilities(4)
//                     Channel(4) SecurityBufferOffset(2) SecurityBufferLength(2)
//                     PreviousSessionId(8) Buffer(...)
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
// secBuf may be nil for an empty security buffer (STATUS_SUCCESS round 2).
func buildSessionSetupBody(secBuf []byte) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	// SessionFlags = 0
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

func (s *Server) logCreds(sessionID uint64, c *NTLMCredentials) {
	if s.log == nil {
		return
	}
	s.log.Info("Credentials captured", map[string]interface{}{
		"session_id":   sessionID,
		"domain":       c.Domain,
		"username":     c.Username,
		"workstation":  c.Workstation,
		"nt_response":  hex.EncodeToString(c.NTResponse),
		"lm_response":  hex.EncodeToString(c.LMResponse),
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
	// Flags=0, Reserved=0
	copy(b[8:16], windowsFiletime(node.created))
	copy(b[16:24], windowsFiletime(node.modified))
	copy(b[24:32], windowsFiletime(node.modified))
	copy(b[32:40], windowsFiletime(node.modified))
	binary.LittleEndian.PutUint64(b[40:48], uint64(node.allocSize()))
	binary.LittleEndian.PutUint64(b[48:56], uint64(node.size()))
	binary.LittleEndian.PutUint32(b[56:60], node.attrs)

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
	if h == nil {
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

		default:
			return buildPacket(req, StatusNotSupported, sess.id, req.TreeID, buildErrorBody())
		}

	case 2: // SMB2_0_INFO_FILESYSTEM
		switch infoClass {
		case 1: // FileFsVolumeInformation
			label := utf16LE("Windows")
			b := make([]byte, 18+len(label))
			copy(b[0:8], windowsFiletime(vfsBaseTime()))         // VolumeCreationTime
			binary.LittleEndian.PutUint32(b[8:12], 0x12345678)  // VolumeSerialNumber
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
			binary.LittleEndian.PutUint32(b[0:4], 0x0002003F)        // FileSystemAttributes (NTFS)
			binary.LittleEndian.PutUint32(b[4:8], 255)               // MaximumComponentNameLength
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
	if h.node.isDir() {
		return buildPacket(req, StatusInvalidParam, sess.id, req.TreeID, buildErrorBody())
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
	binary.LittleEndian.PutUint16(resp[0:2], 17) // StructureSize
	resp[2] = 80                                  // DataOffset (from SMB2 header start)
	binary.LittleEndian.PutUint32(resp[4:8], uint32(len(data))) // DataLength
	// DataRemaining[8:12]=0, Reserved2[12:16]=0
	resp = append(resp, data...)

	return buildPacket(req, StatusSuccess, sess.id, req.TreeID, resp)
}
