package smb

import (
	"encoding/binary"
	"time"
)

// SMB dialect revision codes.
const (
	dialectSMB1 = uint16(0x0101) // SMB 1.0 (CIFS) — sentinel; not a real SMB2 wire value
	dialect202  = uint16(0x0202) // SMB 2.0.2   — Vista / Server 2008
	dialect210  = uint16(0x0210) // SMB 2.1     — Windows 7 / Server 2008 R2
	dialect300  = uint16(0x0300) // SMB 3.0     — Windows 8 / Server 2012
	dialect302  = uint16(0x0302) // SMB 3.0.2   — Windows 8.1 / Server 2012 R2
	dialect311  = uint16(0x0311) // SMB 3.1.1   — Windows 10 / 11 / Server 2016+
)

// Dialects we support, highest-preference first.
// selectDialect picks the first entry the client also offered that is ≤ the
// profile's configured maximum.
var supportedDialects = []uint16{dialect311, dialect302, dialect300, dialect210, dialect202}

// DialectFromString maps a profile's SMB dialect string to a wire value.
// Returns 0 for empty/unknown so the caller can apply a default. "1.0" maps to
// the dialectSMB1 sentinel, meaning "SMBv1 only — never negotiate SMB2".
func DialectFromString(s string) uint16 {
	switch s {
	case "1.0":
		return dialectSMB1
	case "2.0", "2.0.2":
		return dialect202
	case "2.1":
		return dialect210
	case "3.0":
		return dialect300
	case "3.0.2":
		return dialect302
	case "3.1.1":
		return dialect311
	}
	return 0
}

// SMB2_NEGOTIATE_CONTEXT types (MS-SMB2 §2.2.3.1).
const (
	ctxPreauthIntegrity = uint16(0x0001)
	ctxEncryption       = uint16(0x0002)
	ctxNetName          = uint16(0x000F)
)

// handleSMBv1Negotiate handles COM_NEGOTIATE (0x72) and is the single point where
// SMB protocol-version behaviour is decided per the emulated OS.  The choice is
// driven by the profile's max dialect (s.cfg.MaxDialect) and SMB1 enablement
// (s.cfg.SMB1Enabled), so the honeypot behaves like the real OS would:
//
//   - SMBv1-only profile (XP / Server 2003): always speak NT LM 0.12, never SMB2,
//     even if the client offers "SMB 2.???".  Real XP has no SMB2 stack.
//   - SMB2-capable profile + client offered SMB2 dialects: upgrade to SMB2/3,
//     capped at the profile's max dialect.  This is the modern Windows path.
//   - SMB2-capable profile, SMBv1-only client, SMB1 still enabled (Vista–8.1,
//     Win10 w/ SMB1 feature): answer the legacy SMBv1 NEGOTIATE.
//   - SMB2-capable profile, SMBv1-only client, SMB1 disabled (Win10 default /
//     Win11 / Server 2019): refuse with DialectIndex 0xFFFF — exactly what a real
//     SMB1-removed host does.  Tools that only speak SMBv1 (nmap smb-enum-shares)
//     correctly fail to negotiate; that failure is the realistic, expected result.
func (s *Server) handleSMBv1Negotiate(sess *Session, frame []byte) []byte {
	// XP / SMBv1-only: native CIFS, never SMB2.
	if s.cfg.MaxDialect == dialectSMB1 {
		return s.buildSMBv1NegotiateResponse(sess)
	}

	offered := smb1ParseSMB2Dialects(frame)
	if len(offered) > 0 {
		// Multi-protocol negotiate offering SMB2 dialects → upgrade to SMB2/3.
		return s.buildNegotiateResponse(sess, smb2Header{Command: CmdNegotiate}, offered)
	}

	// Pure SMBv1-only negotiate against an SMB2-capable profile.
	if s.cfg.SMB1Enabled {
		return s.buildSMBv1NegotiateResponse(sess) // legacy SMB1 still listening
	}
	// SMB1 disabled → refuse, like a real SMB1-removed Windows host.
	return s.buildSMBv1NegotiateRefusal(sess)
}

// handleNegotiate handles a direct SMBv2 NEGOTIATE command.  The profile's max
// dialect is applied as a ceiling inside buildNegotiateResponse.
func (s *Server) handleNegotiate(sess *Session, req smb2Header, body []byte) []byte {
	return s.buildNegotiateResponse(sess, req, smb2ParseDialects(body))
}

// buildNegotiateResponse selects the best mutual dialect and returns the
// complete SMBv2 NEGOTIATE response frame.
func (s *Server) buildNegotiateResponse(sess *Session, req smb2Header, offered []uint16) []byte {
	dialect := selectDialect(offered, s.cfg.MaxDialect)
	if dialect == 0 {
		// No mutually-supported dialect at or below the profile's ceiling
		// (e.g. an SMB2-only client hitting an XP profile). Realistic refusal.
		return buildPacket(req, StatusNotSupported, 0, 0, buildErrorBody())
	}
	sess.setState(StateNegotiated)
	sess.mu.Lock()
	sess.dialect = dialect
	sess.mu.Unlock()

	spnego := buildSPNEGONegotiateToken()

	// For 3.1.1 we need NegotiateContexts and must know their offset before
	// writing the fixed body, so compute everything up front.
	var ctxs []byte
	var ctxCount uint16
	var ctxOff uint32
	if dialect == dialect311 {
		ctxs = s.buildNegotiateContexts()
		ctxCount = 1 // PreauthIntegrity only — see buildNegotiateContexts
		// Offset from SMBv2 header start: header(64) + fixed-body(64) + spnego + padding.
		// Since 64 is divisible by 8, padding needed = (-len(spnego)) mod 8.
		raw := 128 + len(spnego)
		ctxOff = uint32((raw + 7) &^ 7)
	}

	// SecurityMode: SIGNING_ENABLED, plus SIGNING_REQUIRED when the profile demands
	// it (e.g. a domain controller). We advertise faithfully; note we do not actually
	// sign, so a signing_required profile is an advertisement-only fingerprint.
	secMode := uint16(0x0001) // SMB2_NEGOTIATE_SIGNING_ENABLED
	if s.cfg.SigningRequired {
		secMode |= 0x0002 // SMB2_NEGOTIATE_SIGNING_REQUIRED
	}

	// Fixed body: 64 bytes.
	b := make([]byte, 64)
	binary.LittleEndian.PutUint16(b[0:2], 65)       // StructureSize (always 65)
	binary.LittleEndian.PutUint16(b[2:4], secMode)  // SecurityMode
	binary.LittleEndian.PutUint16(b[4:6], dialect)  // DialectRevision
	binary.LittleEndian.PutUint16(b[6:8], ctxCount) // NegotiateContextCount (0 for <3.1.1)
	copy(b[8:24], s.serverGUID[:])
	// Capabilities: DFS|LEASING|LARGE_MTU|MULTI_CHANNEL|PERSISTENT_HANDLES (0x1F).
	// Two high bits are deliberately cleared:
	//   - 0x40 SMB2_GLOBAL_CAP_ENCRYPTION: we have NO session-key material and
	//     cannot decrypt SMB2_TRANSFORM_HEADER (\xfdSMB) frames. If we advertise
	//     encryption, impacket (netexec/smbmap, newer builds) encrypts every
	//     post-auth request; our parser rejects \xfdSMB and tears down the conn,
	//     causing smbmap's "Error while reading from remote".
	//   - 0x20 SMB2_GLOBAL_CAP_DIRECTORY_LEASING: triggers impacket's create()
	//     uninitialized-variable (parentDir) bug.
	binary.LittleEndian.PutUint32(b[24:28], 0x0000001F)
	binary.LittleEndian.PutUint32(b[28:32], 8388608)             // MaxTransactSize (8 MiB)
	binary.LittleEndian.PutUint32(b[32:36], 8388608)             // MaxReadSize
	binary.LittleEndian.PutUint32(b[36:40], 8388608)             // MaxWriteSize
	copy(b[40:48], windowsFiletime(time.Now()))                  // SystemTime
	copy(b[48:56], windowsFiletime(s.bootTime))                  // ServerStartTime
	binary.LittleEndian.PutUint16(b[56:58], 128)                 // SecurityBufferOffset
	binary.LittleEndian.PutUint16(b[58:60], uint16(len(spnego))) // SecurityBufferLength
	binary.LittleEndian.PutUint32(b[60:64], ctxOff)              // NegotiateContextOffset (0 for <3.1.1)

	body := append(b, spnego...)
	if dialect == dialect311 {
		// Pad body to 8-byte boundary so first context is 8-aligned from msg start.
		// (body[0] is at absolute offset 64 from SMBv2 hdr; 64%8==0 so body alignment==msg alignment)
		for len(body)%8 != 0 {
			body = append(body, 0)
		}
		body = append(body, ctxs...)
	}

	return buildPacket(req, StatusSuccess, 0, 0, body)
}

// buildNegotiateContexts returns the serialised NegotiateContext list for SMB 3.1.1.
//
// We emit ONLY the mandatory SMB2_PREAUTH_INTEGRITY_CAPABILITIES context. The
// SMB2_ENCRYPTION_CAPABILITIES context is deliberately omitted: advertising a cipher
// makes clients (impacket/netexec/smbmap) set SupportsEncryption=True and wrap every
// post-auth request in an SMB2_TRANSFORM_HEADER (\xfdSMB). The honeypot has no session
// key material and cannot decrypt those frames, so it would tear the connection down.
// Omitting the context keeps the whole session in cleartext while still presenting a
// spec-correct 3.1.1 negotiate (PreauthIntegrity is the only required context).
func (s *Server) buildNegotiateContexts() []byte {
	var all []byte

	// SMB2_PREAUTH_INTEGRITY_CAPABILITIES (mandatory for 3.1.1)
	var salt [32]byte
	ns := time.Now().UnixNano()
	for i := range salt {
		salt[i] = byte(ns)
		ns = ns*1103515245 + 12345
	}
	data := make([]byte, 2+2+2+32)                   // HashAlgCount(2) SaltLen(2) Alg(2) Salt(32)
	binary.LittleEndian.PutUint16(data[0:2], 1)      // HashAlgorithmCount = 1
	binary.LittleEndian.PutUint16(data[2:4], 32)     // SaltLength = 32
	binary.LittleEndian.PutUint16(data[4:6], 0x0001) // SHA-512
	copy(data[6:], salt[:])
	all = appendContext(all, ctxPreauthIntegrity, data)

	return all
}

// appendContext serialises one NegotiateContext entry:
//
//	ContextType(2) DataLength(2) Reserved(4) Data[DataLength]
func appendContext(b []byte, ctxType uint16, data []byte) []byte {
	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint16(hdr[0:2], ctxType)
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(data)))
	// Reserved[4:8] = 0
	b = append(b, hdr...)
	return append(b, data...)
}

// selectDialect returns the highest mutually-supported dialect that is ≤ max
// (the profile's configured ceiling), or 0 if there is no acceptable mutual dialect.
func selectDialect(offered []uint16, max uint16) uint16 {
	if max == 0 {
		max = dialect311 // unset → default to highest
	}
	set := make(map[uint16]bool, len(offered))
	for _, d := range offered {
		set[d] = true
	}
	for _, d := range supportedDialects { // highest-preference first
		if d <= max && set[d] {
			return d
		}
	}
	return 0
}

// smb1ParseSMB2Dialects scans the COM_NEGOTIATE data section for SMBv2 dialect strings.
// Returns the implied set of supported SMBv2 dialects:
//   - "SMB 2.???" → all dialects through 3.1.1 (modern Windows clients)
//   - "SMB 2.002" → only 0x0202
func smb1ParseSMB2Dialects(frame []byte) []uint16 {
	_, data := smb1Body(frame)
	has2Multi, has2Base := false, false
	for i := 0; i < len(data); {
		if data[i] != 0x02 {
			break
		}
		j := i + 1
		for j < len(data) && data[j] != 0 {
			j++
		}
		name := string(data[i+1 : j])
		switch name {
		case "SMB 2.???":
			has2Multi = true
		case "SMB 2.002":
			has2Base = true
		}
		i = j + 1
	}
	if has2Multi {
		return []uint16{dialect202, dialect210, dialect300, dialect302, dialect311}
	}
	if has2Base {
		return []uint16{dialect202}
	}
	return nil
}

// smb2ParseDialects parses the DialectRevision list from an SMBv2 NEGOTIATE request body.
func smb2ParseDialects(body []byte) []uint16 {
	if len(body) < 38 {
		return supportedDialects
	}
	count := int(binary.LittleEndian.Uint16(body[2:4]))
	if count == 0 || 36+count*2 > len(body) {
		return supportedDialects
	}
	dialects := make([]uint16, count)
	for i := range dialects {
		dialects[i] = binary.LittleEndian.Uint16(body[36+i*2 : 36+i*2+2])
	}
	return dialects
}
