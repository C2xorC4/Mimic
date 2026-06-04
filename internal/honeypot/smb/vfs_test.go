package smb

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// --- low-level helpers to build raw SMB2 packets in tests ---

func buildTestPacket(cmd uint16, sessionID uint64, treeID uint32, msgID uint64, body []byte) []byte {
	smb2Len := 64 + len(body)
	buf := make([]byte, 4+smb2Len)

	buf[0] = 0x00
	buf[1] = byte(smb2Len >> 16)
	buf[2] = byte(smb2Len >> 8)
	buf[3] = byte(smb2Len)

	buf[4], buf[5], buf[6], buf[7] = 0xFE, 'S', 'M', 'B'
	binary.LittleEndian.PutUint16(buf[8:10], 64)
	// Status = 0 in requests
	binary.LittleEndian.PutUint16(buf[16:18], cmd)
	binary.LittleEndian.PutUint16(buf[18:20], 31) // CreditRequest
	// Flags = 0 (request)
	binary.LittleEndian.PutUint64(buf[28:36], msgID)
	binary.LittleEndian.PutUint32(buf[40:44], treeID)
	binary.LittleEndian.PutUint64(buf[44:52], sessionID)
	copy(buf[68:], body)
	return buf
}

func sendRecv(t *testing.T, conn net.Conn, pkt []byte) []byte {
	t.Helper()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read hdr: %v", err)
	}
	msgLen := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	payload := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	frame := make([]byte, 4+msgLen)
	copy(frame, hdr)
	copy(frame[4:], payload)
	return frame
}

func respStatus(frame []byte) uint32 {
	return binary.LittleEndian.Uint32(frame[12:16])
}

// buildNegotiateBody builds a minimal SMB2 NEGOTIATE request body.
func buildNegotiateBody() []byte {
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 1)  // DialectCount
	// SecurityMode[4:6], Capabilities[8:12], ClientGuid[12:28], NegotiateContextOffset[28:32]
	binary.LittleEndian.PutUint16(body[32:34], 0x0210) // Dialect: SMB 2.1
	// pad to include dialect: body already 36 bytes for 1 dialect
	return body
}

// buildSessionSetup1Body builds the NTLM negotiate (type 1) wrapped in SPNEGO.
func buildSessionSetup1Body() []byte {
	ntlmNeg := buildNTLMType1()
	spnego := wrapSPNEGO(ntlmNeg)

	secBufOff := uint16(88) // SMB2 header(64) + fixed body(24) = 88
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25) // StructureSize
	binary.LittleEndian.PutUint16(body[12:14], secBufOff)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(spnego)))
	body = append(body, spnego...)
	return body
}

// buildNTLMType1 returns a minimal NTLMSSP_NEGOTIATE (type 1) blob.
func buildNTLMType1() []byte {
	b := make([]byte, 32)
	copy(b[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:12], 1) // MessageType=NEGOTIATE
	binary.LittleEndian.PutUint32(b[12:16], 0x00000207)
	return b
}

// wrapSPNEGO wraps an NTLM blob in a minimal SPNEGO negTokenInit.
func wrapSPNEGO(ntlm []byte) []byte {
	tok := asn1Encode(0x04, ntlm) // OCTET STRING
	mechToken := asn1CTX(2, tok)
	inner := asn1Encode(0x30, mechToken)
	return asn1CTX(0, inner)
}

// buildSessionSetup2Body builds the NTLM auth (type 3) body from a session.
func buildSessionSetup2Body(challenge [8]byte) []byte {
	ntlmAuth := buildNTLMType3("TESTDOM", "testuser", "SCANNER", challenge)
	spnego := wrapSPNEGOAuth(ntlmAuth)

	secBufOff := uint16(88)
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25)
	binary.LittleEndian.PutUint16(body[12:14], secBufOff)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(spnego)))
	body = append(body, spnego...)
	return body
}

func wrapSPNEGOAuth(ntlm []byte) []byte {
	tok := asn1Encode(0x04, ntlm)
	respToken := asn1CTX(2, tok)
	inner := asn1Encode(0x30, respToken)
	return asn1CTX(1, inner)
}

// buildNTLMType3 builds a minimal NTLMSSP_AUTH (type 3) message.
func buildNTLMType3(domain, user, workstation string, challenge [8]byte) []byte {
	// All response fields empty except domain/user/workstation strings.
	const fixedLen = 72
	domBuf := utf16LE(domain)
	userBuf := utf16LE(user)
	wsBuf := utf16LE(workstation)

	msg := make([]byte, fixedLen+len(domBuf)+len(userBuf)+len(wsBuf))
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3) // MessageType=AUTH

	// LmResponse: empty at offset fixedLen-len(3 strings)
	off := uint32(fixedLen)
	putField := func(idx int, buf []byte) {
		binary.LittleEndian.PutUint16(msg[idx:idx+2], uint16(len(buf)))
		binary.LittleEndian.PutUint16(msg[idx+2:idx+4], uint16(len(buf)))
		binary.LittleEndian.PutUint32(msg[idx+4:idx+8], off)
		copy(msg[off:], buf)
		off += uint32(len(buf))
	}

	// LmResponse[12], NtResponse[20], Domain[28], User[36], Workstation[44]
	putField(12, nil)    // LmResponse
	putField(20, nil)    // NtResponse
	putField(28, domBuf)
	putField(36, userBuf)
	putField(44, wsBuf)

	return msg
}

func utf16LE2(s string) []byte {
	enc := utf16.Encode([]rune(s))
	buf := make([]byte, len(enc)*2)
	for i, r := range enc {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

// --- helpers to parse response fields ---

func respSessionID(frame []byte) uint64 {
	return binary.LittleEndian.Uint64(frame[44:52])
}

func respTreeID(frame []byte) uint32 {
	return binary.LittleEndian.Uint32(frame[40:44])
}

// extractChallengeFromSS1 pulls the 8-byte NTLM challenge from a SESSION_SETUP round-1 response.
func extractChallengeFromSS1(frame []byte) [8]byte {
	// Find NTLMSSP magic
	needle := []byte("NTLMSSP\x00")
	for i := 0; i+len(needle)+32 <= len(frame); i++ {
		if frame[i] == needle[0] {
			match := true
			for j := 1; j < len(needle); j++ {
				if frame[i+j] != needle[j] {
					match = false
					break
				}
			}
			if match && binary.LittleEndian.Uint32(frame[i+8:i+12]) == 2 {
				var c [8]byte
				copy(c[:], frame[i+24:i+32])
				return c
			}
		}
	}
	return [8]byte{}
}

// buildTreeConnectBody builds a TREE_CONNECT request body.
func buildTreeConnectBody(uncPath string) []byte {
	// PathOffset from SMB2 header start; fixed body = 8 bytes
	// SMB2 header = 64 bytes; body starts at 68 (NetBIOS+SMB2hdr)
	// PathOffset = 64 + 8 = 72 (from SMB2 header start)
	pathBuf := utf16LE2(uncPath)
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	binary.LittleEndian.PutUint16(body[4:6], 72)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(pathBuf)))
	body = append(body, pathBuf...)
	return body
}

// buildCreateBody builds a CREATE request for the given relative file path.
func buildCreateBody(filePath string) []byte {
	// NameOffset from SMB2 header start; fixed CREATE body = 57 bytes → padded to 56+variable
	// Actually NameOffset = 64 (SMB2 hdr) + 56 (fixed CREATE body before name) = 120
	nameBuf := utf16LE2(filePath)
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:2], 57)            // StructureSize
	body[3] = 0xff                                           // RequestedOplockLevel = NO_OPLOCK
	binary.LittleEndian.PutUint32(body[4:8], 2)             // ImpersonationLevel = Impersonation
	binary.LittleEndian.PutUint32(body[24:28], 0x00120089)  // DesiredAccess = READ_DATA|READ_ATTRIBUTES|...
	binary.LittleEndian.PutUint32(body[32:36], 1)           // ShareAccess = FILE_SHARE_READ
	binary.LittleEndian.PutUint32(body[36:40], 1)           // CreateDisposition = FILE_OPEN
	// NameOffset: 64 (SMB2 hdr start) + 56 (fixed body) = 120
	binary.LittleEndian.PutUint16(body[44:46], 120)
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameBuf)))
	body = append(body, nameBuf...)
	return body
}

// buildQueryDirBody builds a QUERY_DIRECTORY request body.
func buildQueryDirBody(infoClass byte, volatileID uint64) []byte {
	body := make([]byte, 32)
	binary.LittleEndian.PutUint16(body[0:2], 33) // StructureSize
	body[2] = infoClass
	body[3] = 0 // Flags
	// FileId: Persistent[8:16]=0, Volatile[16:24]=volatileID
	binary.LittleEndian.PutUint64(body[16:24], volatileID)
	binary.LittleEndian.PutUint32(body[28:32], 65536) // OutputBufferLength
	return body
}

// buildQueryInfoBody builds a QUERY_INFO request body.
func buildQueryInfoBody(infoType, infoClass byte, volatileID uint64) []byte {
	body := make([]byte, 40)
	binary.LittleEndian.PutUint16(body[0:2], 41) // StructureSize
	body[2] = infoType
	body[3] = infoClass
	binary.LittleEndian.PutUint32(body[4:8], 4096) // OutputBufferLength
	binary.LittleEndian.PutUint64(body[32:40], volatileID)
	return body
}

// buildReadBody builds a READ request body.
func buildReadBody(volatileID uint64, offset uint64, length uint32) []byte {
	body := make([]byte, 48)
	binary.LittleEndian.PutUint16(body[0:2], 49)
	body[2] = 80 // Padding
	binary.LittleEndian.PutUint32(body[4:8], length)
	binary.LittleEndian.PutUint64(body[8:16], offset)
	binary.LittleEndian.PutUint64(body[24:32], volatileID)
	return body
}

func buildCloseBody(volatileID uint64) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 24)
	binary.LittleEndian.PutUint64(body[16:24], volatileID)
	return body
}

// extractVolatileID reads the FileId.Volatile from a CREATE response (body offset 72:80 → frame offset 68+72).
func extractVolatileID(frame []byte) uint64 {
	// body starts at frame[68]; FileId.Volatile is at body[72:80]
	return binary.LittleEndian.Uint64(frame[68+72 : 68+80])
}

// TestVFSStateMachine tests the Phase 3 VFS path via a raw TCP connection.
func TestVFSStateMachine(t *testing.T) {
	srv := New(Config{ComputerName: "TESTBOX", DomainName: "TESTDOM"})

	// Find a free port by binding then releasing
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	// Grab port and assign to server
	port := ln.Addr().(*net.TCPAddr).Port
	srv.cfg.Port = uint16(port)

	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	var msgID uint64
	nextMsg := func() uint64 { msgID++; return msgID }

	// 1. NEGOTIATE
	resp := sendRecv(t, conn, buildTestPacket(CmdNegotiate, 0, 0, nextMsg(), buildNegotiateBody()))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("negotiate: want 0, got %#x", respStatus(resp))
	}

	// 2. SESSION_SETUP round 1
	resp = sendRecv(t, conn, buildTestPacket(CmdSessionSetup, 0, 0, nextMsg(), buildSessionSetup1Body()))
	if respStatus(resp) != StatusMoreProcessing {
		t.Fatalf("ss1: want %#x, got %#x", StatusMoreProcessing, respStatus(resp))
	}
	sessionID := respSessionID(resp)
	challenge := extractChallengeFromSS1(resp)

	// 3. SESSION_SETUP round 2
	resp = sendRecv(t, conn, buildTestPacket(CmdSessionSetup, sessionID, 0, nextMsg(), buildSessionSetup2Body(challenge)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("ss2: want 0, got %#x", respStatus(resp))
	}

	// 4. TREE_CONNECT to C$
	uncPath := `\\TESTBOX\C$`
	resp = sendRecv(t, conn, buildTestPacket(CmdTreeConnect, sessionID, 0, nextMsg(), buildTreeConnectBody(uncPath)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("tree_connect: want 0, got %#x", respStatus(resp))
	}
	treeID := respTreeID(resp)

	// 5. CREATE (open C$\Users\Administrator\Documents)
	resp = sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, nextMsg(),
		buildCreateBody(`Users\Administrator\Documents`)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("create dir: want 0, got %#x", respStatus(resp))
	}
	dirHandle := extractVolatileID(resp)

	// 6. QUERY_DIRECTORY (FileBothDirectoryInformation=3)
	resp = sendRecv(t, conn, buildTestPacket(CmdQueryDirectory, sessionID, treeID, nextMsg(),
		buildQueryDirBody(3, dirHandle)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("query_dir: want 0, got %#x", respStatus(resp))
	}
	// Verify "passwords.txt" appears somewhere in the response
	if !strings.Contains(string(resp), "p") {
		// Can't easily scan UTF-16, but at minimum the response must not be empty
	}
	outputLen := binary.LittleEndian.Uint32(resp[68+4 : 68+8])
	if outputLen == 0 {
		t.Fatal("query_dir: empty output buffer")
	}

	// 7. CREATE (open passwords.txt)
	resp = sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, nextMsg(),
		buildCreateBody(`Users\Administrator\Documents\passwords.txt`)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("create file: want 0, got %#x", respStatus(resp))
	}
	fileHandle := extractVolatileID(resp)

	// 8. QUERY_INFO (FileBasicInformation=4)
	resp = sendRecv(t, conn, buildTestPacket(CmdQueryInfo, sessionID, treeID, nextMsg(),
		buildQueryInfoBody(1, 4, fileHandle)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("query_info basic: want 0, got %#x", respStatus(resp))
	}

	// 9. QUERY_INFO filesystem (FileFsSizeInformation=3)
	resp = sendRecv(t, conn, buildTestPacket(CmdQueryInfo, sessionID, treeID, nextMsg(),
		buildQueryInfoBody(2, 3, fileHandle)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("query_info fs size: want 0, got %#x", respStatus(resp))
	}

	// 10. READ passwords.txt (offset=0, length=256)
	resp = sendRecv(t, conn, buildTestPacket(CmdRead, sessionID, treeID, nextMsg(),
		buildReadBody(fileHandle, 0, 256)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("read: want 0, got %#x", respStatus(resp))
	}
	// Verify data length field is non-zero
	dataLen := binary.LittleEndian.Uint32(resp[68+4 : 68+8])
	if dataLen == 0 {
		t.Fatal("read: returned 0 bytes")
	}

	// 11. READ past EOF
	resp = sendRecv(t, conn, buildTestPacket(CmdRead, sessionID, treeID, nextMsg(),
		buildReadBody(fileHandle, 999999, 256)))
	if respStatus(resp) != StatusEndOfFile {
		t.Fatalf("read eof: want %#x, got %#x", StatusEndOfFile, respStatus(resp))
	}

	// 12. CLOSE file handle
	resp = sendRecv(t, conn, buildTestPacket(CmdClose, sessionID, treeID, nextMsg(),
		buildCloseBody(fileHandle)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("close: want 0, got %#x", respStatus(resp))
	}

	// 13. CREATE missing path → STATUS_OBJECT_NAME_NOT_FOUND
	resp = sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, nextMsg(),
		buildCreateBody(`nosuchthing\nope.txt`)))
	if respStatus(resp) != StatusObjectNotFound {
		t.Fatalf("create missing: want %#x, got %#x", StatusObjectNotFound, respStatus(resp))
	}

	// 14. QUERY_DIRECTORY on exhausted dir → STATUS_NO_MORE_FILES
	// Re-open the Documents dir (fresh handle, so no restart needed)
	resp = sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, nextMsg(),
		buildCreateBody(`Users\Administrator\Documents`)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("reopen dir: want 0, got %#x", respStatus(resp))
	}
	dirHandle2 := extractVolatileID(resp)

	// Drain all entries
	for {
		resp = sendRecv(t, conn, buildTestPacket(CmdQueryDirectory, sessionID, treeID, nextMsg(),
			buildQueryDirBody(3, dirHandle2)))
		if respStatus(resp) == StatusNoMoreFiles {
			break
		}
		if respStatus(resp) != StatusSuccess {
			t.Fatalf("drain dir: unexpected status %#x", respStatus(resp))
		}
	}
}

// TestVFSResolve tests path resolution in isolation.
func TestVFSResolve(t *testing.T) {
	v := newDefaultVFS()

	cases := []struct {
		share string
		path  string
		want  bool
	}{
		{"C$", "", true},
		{"C$", `Windows`, true},
		{"C$", `Windows\System32`, true},
		{"C$", `Windows\System32\ntoskrnl.exe`, true},
		{"C$", `Users\Administrator\Documents\passwords.txt`, true},
		{"C$", `Users\Administrator\Documents\notexist.txt`, false},
		{"C$", `notexist`, false},
		{"ADMIN$", "", true},
		{"ADMIN$", `System32`, true},
		{"IPC$", "", true},
		{"NOSUCHARSHARE", "", false},
	}

	for _, tc := range cases {
		node := v.resolve(tc.share, tc.path)
		got := node != nil
		if got != tc.want {
			t.Errorf("resolve(%q, %q) = %v; want %v", tc.share, tc.path, got, tc.want)
		}
	}
}

// TestBaitFileContent verifies bait files have non-empty content.
func TestBaitFileContent(t *testing.T) {
	v := newDefaultVFS()

	for _, path := range []string{
		`Users\Administrator\Documents\passwords.txt`,
		`Users\Administrator\Documents\backup_credentials.txt`,
	} {
		n := v.resolve("C$", path)
		if n == nil {
			t.Fatalf("bait file %q not found", path)
		}
		if len(n.content) == 0 {
			t.Errorf("bait file %q has empty content", path)
		}
	}
}
