package smb

import (
	"encoding/binary"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

// SMBv1 command constants
const (
	smb1CmdClose          = byte(0x04)
	smb1CmdReadAndX       = byte(0x2E)
	smb1CmdWriteAndX      = byte(0x2F)
	smb1CmdTreeDisconnect = byte(0x71)
	smb1CmdTreeConnect    = byte(0x75)
	smb1CmdNTCreateAndX   = byte(0xA2)
)

// smb1Header holds the parsed fields of a 32-byte SMBv1 header.
// SMBv1 header starts at frame[4]; offsets below are relative to frame[0].
//
//	frame[28:30] = TID
//	frame[32:34] = UID
type smb1Header struct {
	command uint8
	status  uint32
	tid     uint16
	uid     uint16
	mid     uint16
}

// parseSMB1Header parses the fixed fields we care about.
// frame must start at the NetBIOS layer (frame[4] = 0xFF 'S' 'M' 'B').
func parseSMB1Header(frame []byte) (smb1Header, bool) {
	if len(frame) < 36 {
		return smb1Header{}, false
	}
	return smb1Header{
		command: frame[8],
		status:  binary.LittleEndian.Uint32(frame[9:13]),
		tid:     binary.LittleEndian.Uint16(frame[28:30]),
		uid:     binary.LittleEndian.Uint16(frame[32:34]),
		mid:     binary.LittleEndian.Uint16(frame[34:36]),
	}, true
}

// smb1Body holds the body of an SMBv1 frame split into parameters and data.
// frame[36] = WordCount; parameters start at frame[37].
func smb1Body(frame []byte) (params []byte, data []byte) {
	if len(frame) < 37 {
		return nil, nil
	}
	wc := int(frame[36])
	paramEnd := 37 + wc*2
	if paramEnd+2 > len(frame) {
		return frame[37:min1(paramEnd, len(frame))], nil
	}
	byteCount := int(binary.LittleEndian.Uint16(frame[paramEnd : paramEnd+2]))
	dataEnd := paramEnd + 2 + byteCount
	if dataEnd > len(frame) {
		dataEnd = len(frame)
	}
	return frame[37:paramEnd], frame[paramEnd+2 : dataEnd]
}

func min1(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// buildSMB1Response constructs a complete NetBIOS-framed SMBv1 response.
// tid and uid are echoed from the request header.
func buildSMB1Response(cmd byte, status uint32, tid, uid uint16, params []byte, data []byte) []byte {
	wc := byte(len(params) / 2)
	payloadLen := 32 + 1 + len(params) + 2 + len(data)
	buf := make([]byte, 4+payloadLen)

	// NetBIOS header
	buf[1] = byte(payloadLen >> 16)
	buf[2] = byte(payloadLen >> 8)
	buf[3] = byte(payloadLen)

	// SMBv1 header (32 bytes at buf[4])
	buf[4], buf[5], buf[6], buf[7] = 0xFF, 'S', 'M', 'B'
	buf[8] = cmd
	binary.LittleEndian.PutUint32(buf[9:13], status)
	buf[13] = 0x98  // Flags: REPLY | CANONICAL_PATHS | CASE_INSENSITIVE
	binary.LittleEndian.PutUint16(buf[14:16], 0x4001) // Flags2: UNICODE | LONG_NAMES
	binary.LittleEndian.PutUint16(buf[28:30], tid)
	binary.LittleEndian.PutUint16(buf[32:34], uid)

	// Body
	off := 36
	buf[off] = wc
	off++
	copy(buf[off:], params)
	off += len(params)
	binary.LittleEndian.PutUint16(buf[off:off+2], uint16(len(data)))
	copy(buf[off+2:], data)
	return buf
}

// --- Session: SMBv1 tree and pipe handle state ---

// allocSMB1Tree registers a new SMBv1 tree connection and returns the TID.
func (s *Session) allocSMB1Tree(uncPath string) uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smb1NextTID++
	tid := s.smb1NextTID
	s.smb1Trees[tid] = uncPath
	return tid
}

// smb1TreePath returns the UNC path for a TID, or "" if not found.
func (s *Session) smb1TreePath(tid uint16) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.smb1Trees[tid]
}

// freeSMB1Tree removes a SMBv1 tree.
func (s *Session) freeSMB1Tree(tid uint16) {
	s.mu.Lock()
	delete(s.smb1Trees, tid)
	s.mu.Unlock()
}

// allocSMB1Pipe registers a new SMBv1 pipe handle and returns the FID.
func (s *Session) allocSMB1Pipe(pipe *PipeState) uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smb1NextFID++
	fid := s.smb1NextFID
	s.smb1Handles[fid] = pipe
	return fid
}

// getSMB1Pipe returns the PipeState for a FID, or nil.
func (s *Session) getSMB1Pipe(fid uint16) *PipeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.smb1Handles[fid]
}

// freeSMB1Handle removes a SMBv1 FID.
func (s *Session) freeSMB1Handle(fid uint16) {
	s.mu.Lock()
	delete(s.smb1Handles, fid)
	s.mu.Unlock()
}

// --- SMBv1 handlers ---

// handleSMBv1TreeConnect handles COM_TREE_CONNECT_ANDX (0x75).
//
// Request params (4 words):
//
//	ANDX_CMD(1) ANDX_RSVD(1) ANDX_OFF(2) Flags(2) PasswordLength(2)
//
// Request data: Password[PasswordLength] + Path\0 + Service\0
func (s *Server) handleSMBv1TreeConnect(sess *Session, frame []byte, uid uint16) []byte {
	params, data := smb1Body(frame)
	if len(params) < 8 {
		return nil
	}
	passwordLen := int(binary.LittleEndian.Uint16(params[6:8]))
	if len(data) < passwordLen {
		return nil
	}
	rest := data[passwordLen:]

	// Parse path (null-terminated ANSI or UTF-16LE depending on FLAGS2 bit 15).
	flags2 := binary.LittleEndian.Uint16(frame[14:16])
	var uncPath string
	if flags2&0x8000 != 0 {
		uncPath = extractSMB1UnicodeString(rest)
	} else {
		uncPath = extractSMB1ASCIIString(rest)
	}
	uncPath = strings.ToUpper(uncPath)

	// Validate share name: reject unknown shares so tools like nmap can confirm we
	// correctly distinguish valid from invalid shares.
	shareName := shareFromTree(uncPath)
	if !s.isKnownShare(shareName) {
		return buildSMB1Response(smb1CmdTreeConnect, 0xC00000CC, 0, uid, []byte{0xFF, 0, 0, 0}, nil)
	}

	tid := sess.allocSMB1Tree(uncPath)

	if s.log != nil {
		s.log.Info("SMBv1 tree connect", map[string]interface{}{
			"session_id": sess.id, "tid": tid, "path": uncPath,
		})
	}
	atomic.AddUint64(&s.stats.treeConnects, 1)

	// Determine service string from share name.
	service := "A:"
	if strings.EqualFold(shareName, "IPC$") {
		service = "IPC"
	}

	// Response: params = 3 words: ANDX(1)+RSVD(1)+OFF(2) + OptionalSupport(2)
	rParams := make([]byte, 6)
	rParams[0] = 0xFF // no ANDX
	binary.LittleEndian.PutUint16(rParams[4:6], 1) // OptionalSupport

	// Data: Service\0 + NativeFilesystem\0
	var rData []byte
	rData = append(rData, []byte(service)...)
	rData = append(rData, 0)
	rData = append(rData, []byte("NTFS")...)
	rData = append(rData, 0)

	return buildSMB1Response(smb1CmdTreeConnect, 0, tid, uid, rParams, rData)
}

// handleSMBv1NTCreateAndX handles COM_NT_CREATE_ANDX (0xA2).
// Returns a FID for named-pipe handles on IPC$; ACCESS_DENIED for everything else.
//
// Request params (24 words = 48 bytes):
//
//	ANDX(1)+RSVD(1)+OFF(2) Reserved(1) NameLength(2) Flags(4) RootFID(4)
//	Access(4) AllocSize(8) Attrs(4) ShareAccess(4) Disposition(4)
//	CreateOptions(4) Impersonation(4) SecurityFlags(1)
func (s *Server) handleSMBv1NTCreateAndX(sess *Session, frame []byte, h smb1Header) []byte {
	params, data := smb1Body(frame)
	if len(params) < 6 {
		return buildSMB1Response(smb1CmdNTCreateAndX, 0xC0000022, h.tid, h.uid, []byte{0xFF, 0, 0, 0}, nil)
	}
	nameLen := int(binary.LittleEndian.Uint16(params[5:7]))

	// Parse file name from data section.
	var filePath string
	if len(data) >= nameLen && nameLen > 0 {
		raw := data[:nameLen]
		flags2 := binary.LittleEndian.Uint16(frame[14:16])
		if flags2&0x8000 != 0 && nameLen%2 == 0 {
			u16 := make([]uint16, nameLen/2)
			for i := range u16 {
				u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
			}
			filePath = string(utf16.Decode(u16))
		} else {
			filePath = strings.TrimRight(string(raw), "\x00")
		}
	}

	// Only respond to IPC$ pipe opens.
	treePath := sess.smb1TreePath(h.tid)
	if !strings.EqualFold(shareFromTree(treePath), "IPC$") {
		return buildSMB1Response(smb1CmdNTCreateAndX, 0xC0000022, h.tid, h.uid, []byte{0xFF, 0, 0, 0}, nil)
	}

	pipeName := canonicalizePipeName(filePath)
	if pipeName == "" {
		pipeName = "srvsvc"
	}
	ps := newPipeState(pipeName)
	fid := sess.allocSMB1Pipe(ps)

	if s.log != nil {
		s.log.Info("SMBv1 pipe open", map[string]interface{}{
			"session_id": sess.id, "pipe": pipeName, "fid": fid, "raw_path": filePath,
		})
	}

	// Response: 34 words = 68 bytes of params.
	// Format: ANDX(1)+RSVD(1)+OFF(2)+OplockLevel(1)+FID(2)+CreateAction(4)+
	//         8xTimestamps(32)+Attrs(4)+AllocSize(8)+EndOfFile(8)+
	//         FileType(2)+IPCState(2)+IsDir(1) = 68 bytes (34 words... but 34*2=68 and one byte is odd)
	// Note: WordCount=34 means 34 words, but the actual Microsoft spec has this at 34.
	// Empirically: 34 words * 2 = 68 bytes. We treat OplockLevel as a half-word.
	ft := windowsFiletime(time.Now())
	rp := make([]byte, 68)
	rp[0] = 0xFF // no ANDX
	// rp[4] = OplockLevel = 0
	binary.LittleEndian.PutUint16(rp[5:7], fid)
	binary.LittleEndian.PutUint32(rp[7:11], 1) // CreateAction = FILE_OPENED
	// Timestamps: created, access, write, change (each 8 bytes)
	copy(rp[11:19], ft)
	copy(rp[19:27], ft)
	copy(rp[27:35], ft)
	copy(rp[35:43], ft)
	binary.LittleEndian.PutUint32(rp[43:47], 0x80)   // FILE_ATTRIBUTE_NORMAL
	// AllocationSize[47:55] = 0
	// EndOfFile[55:63] = 0
	binary.LittleEndian.PutUint16(rp[63:65], 2)        // FileType = MESSAGE_MODE_PIPE
	binary.LittleEndian.PutUint16(rp[65:67], 0x05FF)   // IPCState
	// rp[67] = IsDirectory = 0

	return buildSMB1Response(smb1CmdNTCreateAndX, 0, h.tid, h.uid, rp, nil)
}

// handleSMBv1WriteAndX handles COM_WRITE_ANDX (0x2F).
// Feeds DCE/RPC data to the named pipe and queues the response for a subsequent READ.
//
// Request params (14 words = 28 bytes):
//
//	ANDX(1)+RSVD(1)+OFF(2) FID(2) Offset(4) Timeout(4) WriteMode(2)
//	Remaining(2) DataLengthHigh(2) DataLength(2) DataOffset(2) OffsetHigh(4)
func (s *Server) handleSMBv1WriteAndX(sess *Session, frame []byte, h smb1Header) []byte {
	params, _ := smb1Body(frame)
	if len(params) < 28 {
		return buildSMB1Response(smb1CmdWriteAndX, 0xC0000022, h.tid, h.uid, []byte{0xFF, 0, 0, 0}, nil)
	}
	fid := binary.LittleEndian.Uint16(params[4:6])
	dataLen := int(binary.LittleEndian.Uint16(params[20:22]))
	dataOff := int(binary.LittleEndian.Uint16(params[22:24])) // relative to frame[4] (SMBv1 header start)

	ps := sess.getSMB1Pipe(fid)
	if ps == nil {
		return buildSMB1Response(smb1CmdWriteAndX, 0xC0000034, h.tid, h.uid, []byte{0xFF, 0, 0, 0}, nil)
	}

	// dataOff is relative to the start of the SMBv1 header (frame[4]).
	start := 4 + dataOff
	end := start + dataLen
	if end > len(frame) {
		end = len(frame)
	}
	if start < len(frame) && start < end {
		ps.Write(frame[start:end], s.cfg.Shares)
	}

	// Response: 6 words = 12 bytes
	rp := make([]byte, 12)
	rp[0] = 0xFF // no ANDX
	binary.LittleEndian.PutUint16(rp[4:6], uint16(dataLen)) // Count
	return buildSMB1Response(smb1CmdWriteAndX, 0, h.tid, h.uid, rp, nil)
}

// handleSMBv1ReadAndX handles COM_READ_ANDX (0x2E).
// Returns any queued DCE/RPC response from the named pipe.
//
// Request params (12 words = 24 bytes):
//
//	ANDX(1)+RSVD(1)+OFF(2) FID(2) Offset(4) MaxCount(2) MinCount(2)
//	MaxCountHigh(4) Remaining(2) OffsetHigh(4)
func (s *Server) handleSMBv1ReadAndX(sess *Session, frame []byte, h smb1Header) []byte {
	params, _ := smb1Body(frame)
	if len(params) < 6 {
		return buildSMB1Response(smb1CmdReadAndX, 0xC0000022, h.tid, h.uid, []byte{0xFF, 0, 0, 0}, nil)
	}
	fid := binary.LittleEndian.Uint16(params[4:6])

	ps := sess.getSMB1Pipe(fid)
	if ps == nil {
		return buildSMB1Response(smb1CmdReadAndX, 0xC0000034, h.tid, h.uid, []byte{0xFF, 0, 0, 0}, nil)
	}

	data := ps.Read()
	if len(data) == 0 {
		// No data yet — return PIPE_LISTENING (end of file equivalent for pipes)
		return buildSMB1Response(smb1CmdReadAndX, 0xC0000011, h.tid, h.uid, []byte{0xFF, 0, 0, 0}, nil)
	}

	// Response params: 12 words = 24 bytes
	// DataOffset per MS-CIFS: offset from start of SMB header (buf[4]), not wire frame start.
	// 32 (SMBv1 hdr) + 1 (WordCount) + 24 (params) + 2 (ByteCount) + 1 (pad) = 60
	const dataOffset = 60
	rp := make([]byte, 24)
	rp[0] = 0xFF  // no ANDX
	binary.LittleEndian.PutUint16(rp[4:6], 0xFFFF)              // Remaining (undefined for pipes)
	binary.LittleEndian.PutUint16(rp[10:12], uint16(len(data))) // DataLength
	binary.LittleEndian.PutUint16(rp[12:14], dataOffset)        // DataOffset

	// Data section: 1-byte pad + pipe data
	rData := make([]byte, 1+len(data))
	copy(rData[1:], data)

	return buildSMB1Response(smb1CmdReadAndX, 0, h.tid, h.uid, rp, rData)
}

// handleSMBv1Close handles COM_CLOSE (0x04).
func (s *Server) handleSMBv1Close(sess *Session, frame []byte, h smb1Header) []byte {
	params, _ := smb1Body(frame)
	if len(params) >= 2 {
		fid := binary.LittleEndian.Uint16(params[0:2])
		sess.freeSMB1Handle(fid)
	}
	return buildSMB1Response(smb1CmdClose, 0, h.tid, h.uid, nil, nil)
}

// handleSMBv1Transaction handles COM_TRANSACTION (0x25).
//
// impacket uses this for TRANS_TRANSACT_NMPIPE (Setup[0]=0x0026, Setup[1]=FID):
// a combined write+read on a named pipe in a single round trip.
//
// Request layout (params relative to frame[37]):
//
//	[0:2]  TotalParameterCount  [2:4]  TotalDataCount  [4:6]  MaxParameterCount
//	[6:8]  MaxDataCount         [8:9]  MaxSetupCount   [10:12] Flags
//	[12:16] Timeout             [18:20] ParameterCount  [20:22] ParameterOffset
//	[22:24] DataCount           [24:26] DataOffset      [26:27] SetupCount
//	[28:...] Setup words
func (s *Server) handleSMBv1Transaction(sess *Session, frame []byte, h smb1Header) []byte {
	params, _ := smb1Body(frame)
	if len(params) < 28 {
		return buildSMB1Response(0x25, 0xC0000010, h.tid, h.uid, nil, nil) // INVALID_PARAMETER
	}
	setupCount := int(params[26])
	if len(params) < 28+setupCount*2 {
		return buildSMB1Response(0x25, 0xC0000010, h.tid, h.uid, nil, nil)
	}

	// Only handle TRANS_TRANSACT_NMPIPE (0x0026) — ignore others.
	if setupCount < 2 {
		return buildSMB1Response(0x25, 0xC0000002, h.tid, h.uid, nil, nil) // NOT_IMPLEMENTED
	}
	funcCode := binary.LittleEndian.Uint16(params[28:30])
	if funcCode != 0x0026 {
		return buildSMB1Response(0x25, 0xC0000002, h.tid, h.uid, nil, nil)
	}
	fid := binary.LittleEndian.Uint16(params[30:32])

	ps := sess.getSMB1Pipe(fid)
	if ps == nil {
		return buildSMB1Response(0x25, 0xC0000034, h.tid, h.uid, nil, nil) // OBJECT_NAME_NOT_FOUND
	}

	// Extract data: DataOffset is from SMBv1 header start (frame[4]).
	dataCount := int(binary.LittleEndian.Uint16(params[22:24]))
	dataOff := int(binary.LittleEndian.Uint16(params[24:26]))
	start := 4 + dataOff
	end := start + dataCount
	if end > len(frame) {
		end = len(frame)
	}
	var pipeData []byte
	if start < len(frame) && start < end {
		pipeData = frame[start:end]
	}

	respData := ps.Transceive(pipeData, s.cfg.Shares)

	// Build TRANSACTION response.
	// DataOffset = SMBv1 hdr(32) + WordCount(1) + params(20) + ByteCount(2) + pad(1) = 56
	const txDataOffset = uint16(56)
	rp := make([]byte, 20)
	binary.LittleEndian.PutUint16(rp[2:4], uint16(len(respData)))   // TotalDataCount
	binary.LittleEndian.PutUint16(rp[12:14], uint16(len(respData))) // DataCount
	binary.LittleEndian.PutUint16(rp[14:16], txDataOffset)           // DataOffset
	// SetupCount=0, Reserved=0 at rp[18:20]

	// 1 pad byte before data to reach 4-byte alignment from SMBv1 header.
	rData := make([]byte, 1+len(respData))
	copy(rData[1:], respData)

	return buildSMB1Response(0x25, 0, h.tid, h.uid, rp, rData)
}

// handleSMBv1TreeDisconnect handles COM_TREE_DISCONNECT (0x71).
func (s *Server) handleSMBv1TreeDisconnect(sess *Session, frame []byte, h smb1Header) []byte {
	sess.freeSMB1Tree(h.tid)
	return buildSMB1Response(smb1CmdTreeDisconnect, 0, h.tid, h.uid, nil, nil)
}

// --- String helpers ---

// extractSMB1ASCIIString reads a null-terminated ASCII string from the start of b.
func extractSMB1ASCIIString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// extractSMB1UnicodeString reads a null-terminated UTF-16LE string from b.
func extractSMB1UnicodeString(b []byte) string {
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			u16 := make([]uint16, i/2)
			for j := range u16 {
				u16[j] = binary.LittleEndian.Uint16(b[j*2:])
			}
			return string(utf16.Decode(u16))
		}
	}
	return ""
}
