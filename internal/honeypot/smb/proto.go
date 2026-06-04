package smb

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// SMB2 command codes
const (
	CmdNegotiate      = uint16(0x0000)
	CmdSessionSetup   = uint16(0x0001)
	CmdLogoff         = uint16(0x0002)
	CmdTreeConnect    = uint16(0x0003)
	CmdTreeDisconnect = uint16(0x0004)
	CmdCreate         = uint16(0x0005)
	CmdClose          = uint16(0x0006)
	CmdFlush          = uint16(0x0007)
	CmdRead           = uint16(0x0008)
	CmdWrite          = uint16(0x0009)
	CmdLock           = uint16(0x000A)
	CmdIOCtl          = uint16(0x000B)
	CmdQueryDirectory = uint16(0x000E)
	CmdQueryInfo      = uint16(0x0010)
	CmdSetInfo        = uint16(0x0011)
)

// NTSTATUS codes
const (
	StatusSuccess        = uint32(0x00000000)
	StatusMoreProcessing = uint32(0xC0000016)
	StatusAccessDenied   = uint32(0xC0000022)
	StatusLogonFailure   = uint32(0xC000006D)
	StatusNotSupported   = uint32(0xC00000BB)
	StatusInvalidParam   = uint32(0xC000000D)
)

// SMB2 header flag bits
const FlagResponse = uint32(0x00000001)

// Packet layout constants
const (
	netBIOSLen   = 4
	smb2HdrLen   = 64
	pktHdrLen    = netBIOSLen + smb2HdrLen // 68 bytes total
	maxFrameSize = 16 * 1024 * 1024        // 16 MiB sanity cap
)

// smb2Header holds the parsed fields of one SMB2 header.
type smb2Header struct {
	Status    uint32
	Command   uint16
	Credits   uint16
	Flags     uint32
	MessageID uint64
	ProcessID uint32
	TreeID    uint32
	SessionID uint64
}

// parseHeader parses a NetBIOS-framed SMB2 packet.
// data must be at least pktHdrLen bytes; returns ok=false for bad magic.
func parseHeader(data []byte) (smb2Header, bool) {
	if len(data) < pktHdrLen {
		return smb2Header{}, false
	}
	if data[4] != 0xFE || data[5] != 'S' || data[6] != 'M' || data[7] != 'B' {
		return smb2Header{}, false
	}
	return smb2Header{
		Status:    binary.LittleEndian.Uint32(data[12:16]),
		Command:   binary.LittleEndian.Uint16(data[16:18]),
		Credits:   binary.LittleEndian.Uint16(data[18:20]),
		Flags:     binary.LittleEndian.Uint32(data[20:24]),
		MessageID: binary.LittleEndian.Uint64(data[28:36]),
		ProcessID: binary.LittleEndian.Uint32(data[36:40]),
		TreeID:    binary.LittleEndian.Uint32(data[40:44]),
		SessionID: binary.LittleEndian.Uint64(data[44:52]),
	}, true
}

// buildPacket assembles a complete NetBIOS-framed SMB2 response.
// sessionID and treeID are written into the SMB2 header verbatim
// (pass the request values to echo them, or pass new values to override).
func buildPacket(req smb2Header, status uint32, sessionID uint64, treeID uint32, body []byte) []byte {
	smb2Len := smb2HdrLen + len(body)
	buf := make([]byte, netBIOSLen+smb2Len)

	// NetBIOS session message: type=0x00, 3-byte big-endian length
	buf[0] = 0x00
	buf[1] = byte(smb2Len >> 16)
	buf[2] = byte(smb2Len >> 8)
	buf[3] = byte(smb2Len)

	// SMB2 header (64 bytes at offset 4)
	buf[4], buf[5], buf[6], buf[7] = 0xFE, 'S', 'M', 'B'
	binary.LittleEndian.PutUint16(buf[8:10], 64)  // StructureSize
	// CreditCharge = 0                            // [10:12]
	binary.LittleEndian.PutUint32(buf[12:16], status)
	binary.LittleEndian.PutUint16(buf[16:18], req.Command)
	binary.LittleEndian.PutUint16(buf[18:20], 1) // CreditResponse
	binary.LittleEndian.PutUint32(buf[20:24], FlagResponse)
	// NextCommand = 0                             // [24:28]
	binary.LittleEndian.PutUint64(buf[28:36], req.MessageID)
	// ProcessID = 0                               // [36:40]
	binary.LittleEndian.PutUint32(buf[40:44], treeID)
	binary.LittleEndian.PutUint64(buf[44:52], sessionID)
	// Signature = zeros (no signing)              // [52:68]

	copy(buf[68:], body)
	return buf
}

// buildErrorBody returns a minimal 9-byte SMB2 error response body.
// Used for all STATUS_* responses that don't carry a meaningful payload.
func buildErrorBody() []byte {
	return []byte{
		0x09, 0x00, // StructureSize = 9
		0x00,                   // ErrorContextCount
		0x00,                   // Reserved
		0x00, 0x00, 0x00, 0x00, // ByteCount = 0
		0x00,                   // ErrorData (1 byte padding when ByteCount=0)
	}
}

// readFrame reads one complete NetBIOS-framed SMB2 message from conn.
// Returns the full frame bytes (NetBIOS header + SMB2 payload).
func readFrame(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	msgLen := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if msgLen == 0 {
		return hdr, nil // keep-alive
	}
	if msgLen > maxFrameSize {
		return nil, fmt.Errorf("frame length %d exceeds limit", msgLen)
	}
	payload := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	frame := make([]byte, 4+msgLen)
	copy(frame, hdr)
	copy(frame[4:], payload)
	return frame, nil
}

// windowsFiletime converts t to a Windows FILETIME (100 ns intervals since
// 1601-01-01, little-endian).
func windowsFiletime(t time.Time) []byte {
	const epochDiff = uint64(116444736000000000)
	ft := uint64(t.UnixNano()/100) + epochDiff
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, ft)
	return b
}
