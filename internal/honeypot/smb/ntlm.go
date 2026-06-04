package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// ntlmFlags are the NTLM negotiate flags returned in our challenge.
// Matches a typical Windows 10/11 server (version=0xE28A8215).
const ntlmFlags = uint32(0xE28A8215)

var (
	// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
	ntlmsspOID = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	// SPNEGO OID: 1.3.6.1.5.5.2
	spnegoOID = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
)

// NTLMCredentials holds the credential material extracted from NTLMSSP_AUTH.
type NTLMCredentials struct {
	Domain      string
	Username    string
	Workstation string
	NTResponse  []byte
	LMResponse  []byte
}

// buildSPNEGONegotiateToken returns a SPNEGO negTokenInit that advertises
// NTLMSSP as the only supported mechanism.  Used as the security buffer in
// the SMB2 NEGOTIATE response.
func buildSPNEGONegotiateToken() []byte {
	mechOID := asn1Encode(0x06, ntlmsspOID)
	mechSeq := asn1Encode(0x30, mechOID)
	mechTypes := asn1CTX(0, mechSeq)
	innerSeq := asn1Encode(0x30, mechTypes)
	negTokenInit := asn1CTX(0, innerSeq)
	oid := asn1Encode(0x06, spnegoOID)
	app := append(oid, negTokenInit...)
	return asn1APP(0, app)
}

// buildSPNEGOChallengeToken wraps ntlmChallenge in a SPNEGO negTokenResp
// with negState=acceptIncomplete (round 1 of NTLM exchange).
func buildSPNEGOChallengeToken(ntlmChallenge []byte) []byte {
	negState := asn1CTX(0, asn1Encode(0x0a, []byte{0x01})) // acceptIncomplete
	mechOID := asn1Encode(0x06, ntlmsspOID)
	supportedMech := asn1CTX(1, mechOID)
	responseToken := asn1CTX(2, asn1Encode(0x04, ntlmChallenge))
	inner := concat(negState, supportedMech, responseToken)
	return asn1CTX(1, asn1Encode(0x30, inner))
}

// buildNTLMChallenge constructs an NTLMSSP CHALLENGE (type 2) message with a
// random server challenge and target info AV pairs for the given names.
func buildNTLMChallenge(computerName, domainName string, challenge [8]byte) []byte {
	targetName := utf16LE(domainName)
	targetInfo := buildTargetInfo(computerName, domainName)

	// Fixed header = 48 bytes + version (8) = 56 bytes
	const fixedLen = 56
	targetNameOff := uint32(fixedLen)
	targetInfoOff := targetNameOff + uint32(len(targetName))

	msg := make([]byte, fixedLen+len(targetName)+len(targetInfo))

	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2) // MessageType = CHALLENGE

	// TargetNameFields
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], targetNameOff)

	binary.LittleEndian.PutUint32(msg[20:24], ntlmFlags)

	copy(msg[24:32], challenge[:]) // ServerChallenge
	// Reserved [32:40] = zeros

	// TargetInfoFields
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], targetInfoOff)

	// Version: Windows 10.0 build 19041, NTLMRevisionCurrent=15
	msg[48] = 10 // MajorVersion
	msg[49] = 0  // MinorVersion
	binary.LittleEndian.PutUint16(msg[50:52], 19041) // ProductBuild
	// [52:55] reserved
	msg[55] = 15 // NTLMRevisionCurrent

	copy(msg[fixedLen:], targetName)
	copy(msg[fixedLen+len(targetName):], targetInfo)
	return msg
}

// buildTargetInfo assembles the NTLM TargetInfo AV pair list.
func buildTargetInfo(computerName, domainName string) []byte {
	var buf []byte
	av := func(id uint16, val []byte) {
		buf = append(buf, byte(id), byte(id>>8))
		buf = append(buf, byte(len(val)), byte(len(val)>>8))
		buf = append(buf, val...)
	}
	av(0x0002, utf16LE(domainName))   // MsvAvNbDomainName
	av(0x0001, utf16LE(computerName)) // MsvAvNbComputerName
	av(0x0004, utf16LE(domainName))   // MsvAvDnsDomainName
	av(0x0003, utf16LE(computerName)) // MsvAvDnsComputerName
	av(0x0000, nil)                   // MsvAvEOL (length=0, no value)
	return buf
}

// parseNTLMAuth extracts credentials from the NTLMSSP_AUTH (type 3) message
// embedded in data.  SPNEGO wrapper is tolerated — scans for the NTLMSSP magic.
func parseNTLMAuth(data []byte) (*NTLMCredentials, error) {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return nil, fmt.Errorf("NTLMSSP magic not found")
	}
	msg := data[idx:]
	if len(msg) < 52 {
		return nil, fmt.Errorf("NTLMSSP_AUTH too short (%d bytes)", len(msg))
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 3 {
		return nil, fmt.Errorf("expected NTLMSSP type 3")
	}

	lm := ntlmField{msg, 12}
	nt := ntlmField{msg, 20}
	dom := ntlmField{msg, 28}
	usr := ntlmField{msg, 36}
	ws := ntlmField{msg, 44}

	return &NTLMCredentials{
		Domain:      dom.utf16String(),
		Username:    usr.utf16String(),
		Workstation: ws.utf16String(),
		NTResponse:  nt.bytes(),
		LMResponse:  lm.bytes(),
	}, nil
}

// findNTLMBlob locates the start of an NTLMSSP message within a SPNEGO blob.
func findNTLMBlob(data []byte) []byte {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return nil
	}
	return data[idx:]
}

// --- helpers ---

// ntlmField wraps the three-word (len, maxLen, offset) descriptor stored at
// position off inside a parent blob.
type ntlmField struct {
	blob []byte
	off  int
}

func (f ntlmField) bytes() []byte {
	if f.off+8 > len(f.blob) {
		return nil
	}
	length := binary.LittleEndian.Uint16(f.blob[f.off : f.off+2])
	offset := binary.LittleEndian.Uint32(f.blob[f.off+4 : f.off+8])
	if length == 0 {
		return nil
	}
	end := int(offset) + int(length)
	if end > len(f.blob) {
		return nil
	}
	out := make([]byte, length)
	copy(out, f.blob[offset:end])
	return out
}

func (f ntlmField) utf16String() string {
	raw := f.bytes()
	if len(raw) < 2 {
		return ""
	}
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(u16))
}

// utf16LE encodes s as little-endian UTF-16 with no BOM.
func utf16LE(s string) []byte {
	enc := utf16.Encode([]rune(s))
	buf := make([]byte, len(enc)*2)
	for i, r := range enc {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

// concat appends all slices into a new slice.
func concat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ASN.1 DER encoding helpers

func asn1Encode(tag byte, content []byte) []byte { return asn1Build(tag, content) }
func asn1CTX(n int, content []byte) []byte        { return asn1Build(byte(0xa0+n), content) }
func asn1APP(n int, content []byte) []byte         { return asn1Build(byte(0x60+n), content) }

func asn1Build(tag byte, content []byte) []byte {
	l := len(content)
	var lenEnc []byte
	switch {
	case l < 128:
		lenEnc = []byte{byte(l)}
	case l < 256:
		lenEnc = []byte{0x81, byte(l)}
	default:
		lenEnc = []byte{0x82, byte(l >> 8), byte(l & 0xff)}
	}
	out := make([]byte, 1+len(lenEnc)+l)
	out[0] = tag
	copy(out[1:], lenEnc)
	copy(out[1+len(lenEnc):], content)
	return out
}
