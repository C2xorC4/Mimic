package smb

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	nbssSessionRequest  = 0x81
	nbssPositiveSession = 0x82
	nbssNegativeSession = 0x83
)

var (
	nbssPositiveResponse = []byte{nbssPositiveSession, 0x00, 0x00, 0x00}
	nbssNegativeResponse = []byte{nbssNegativeSession, 0x00, 0x00, 0x01, 0x8F}
)

// negotiateNetBIOSSession performs the NetBIOS Session Service handshake
// required on TCP 139 before SMB frames flow. Port 445 sends SMB directly.
func negotiateNetBIOSSession(conn net.Conn, computerName string) error {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}

	msgType := hdr[0]
	msgLen := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])

	if msgType != nbssSessionRequest {
		// HTTP probes and other non-NBSS traffic get a negative session.
		if msgLen > 0 {
			_, _ = io.CopyN(io.Discard, conn, int64(msgLen))
		}
		_, _ = conn.Write(nbssNegativeResponse)
		return fmt.Errorf("non-session-request 0x%02x", msgType)
	}

	payload := make([]byte, msgLen)
	if msgLen > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return err
		}
	}

	if !sessionRequestAccepted(payload, computerName) {
		_, _ = conn.Write(nbssNegativeResponse)
		return fmt.Errorf("session request rejected")
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(nbssPositiveResponse); err != nil {
		return err
	}
	return nil
}

// sessionRequestAccepted decides whether to answer 0x82 for a Session Request.
// Windows accepts *SMBSERVER and the host computer name (any NetBIOS suffix).
func sessionRequestAccepted(payload []byte, computerName string) bool {
	if len(payload) < 32 {
		return false
	}
	called := decodeFirstLevelNBName(payload[:32])
	if called == "" {
		return false
	}
	upper := strings.ToUpper(called)
	if strings.HasPrefix(upper, "*") {
		return true
	}
	if strings.Contains(upper, "SMBSERVER") {
		return true
	}
	host := strings.ToUpper(strings.TrimSpace(computerName))
	if host == "" {
		host = "WORKSTATION"
	}
	// Match COMPUTERNAME with optional trailing service byte (0x20 file server).
	base := strings.TrimRight(upper, "\x00")
	if idx := strings.IndexByte(base, 0x00); idx >= 0 {
		base = base[:idx]
	}
	base = strings.TrimSpace(base)
	return base == host || strings.HasPrefix(base, host)
}

// decodeFirstLevelNBName reverses RFC 1001 first-level NetBIOS name encoding.
func decodeFirstLevelNBName(encoded []byte) string {
	var out strings.Builder
	for i := 0; i+1 < len(encoded) && i < 32; i += 2 {
		hi := int(encoded[i] - 'A')
		lo := int(encoded[i+1] - 'A')
		if hi < 0 || hi > 15 || lo < 0 || lo > 15 {
			break
		}
		b := byte((hi << 4) | lo)
		if b == ' ' {
			break
		}
		out.WriteByte(b)
	}
	return strings.TrimRight(out.String(), " ")
}