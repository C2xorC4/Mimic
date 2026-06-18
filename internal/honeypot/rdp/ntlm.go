package rdp

import (
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const ntlmFiletimeEpochDiff = 116444736000000000

const ntlmFlags = uint32(0xE28A8215)

// buildNTLMChallenge constructs an NTLMSSP CHALLENGE (type 2) with profile-derived
// Product_Version and live MsvAvTimestamp.
func buildNTLMChallenge(computerName, domainName string, challenge [8]byte, major, minor uint8, build uint16) []byte {
	targetName := utf16LE(domainName)
	targetInfo := buildTargetInfo(computerName, domainName)

	const fixedLen = 56
	targetNameOff := uint32(fixedLen)
	targetInfoOff := targetNameOff + uint32(len(targetName))

	msg := make([]byte, fixedLen+len(targetName)+len(targetInfo))

	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2)

	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], targetNameOff)

	binary.LittleEndian.PutUint32(msg[20:24], ntlmFlags)

	copy(msg[24:32], challenge[:])

	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], targetInfoOff)

	msg[48] = major
	msg[49] = minor
	binary.LittleEndian.PutUint16(msg[50:52], build)
	msg[55] = 15

	copy(msg[fixedLen:], targetName)
	copy(msg[fixedLen+len(targetName):], targetInfo)
	return msg
}

func buildTargetInfo(computerName, domainName string) []byte {
	var buf []byte
	av := func(id uint16, val []byte) {
		buf = append(buf, byte(id), byte(id>>8))
		buf = append(buf, byte(len(val)), byte(len(val)>>8))
		buf = append(buf, val...)
	}
	av(0x0002, utf16LE(domainName))
	av(0x0001, utf16LE(computerName))
	av(0x0004, utf16LE(domainName))
	av(0x0003, utf16LE(computerName))
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Now().UnixNano()/100)+ntlmFiletimeEpochDiff)
	av(0x0007, ts)
	av(0x0000, nil)
	return buf
}

func buildSPNEGOChallengeToken(ntlmChallenge []byte) []byte {
	negState := asn1CTX(0, asn1Encode(0x0a, []byte{0x01}))
	mechOID := asn1Encode(0x06, ntlmsspOID)
	supportedMech := asn1CTX(1, mechOID)
	responseToken := asn1CTX(2, asn1Encode(0x04, ntlmChallenge))
	inner := concat(negState, supportedMech, responseToken)
	return asn1CTX(1, asn1Encode(0x30, inner))
}

func randomChallenge() [8]byte {
	var c [8]byte
	_, _ = rand.Read(c[:])
	return c
}

func osVersionTriple(osVersion string) (major, minor uint8, build uint16) {
	major, minor, build = 10, 0, 19041
	parts := strings.SplitN(osVersion, ".", 3)
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

var (
	ntlmsspOID = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

func utf16LE(s string) []byte {
	enc := utf16.Encode([]rune(s))
	buf := make([]byte, len(enc)*2)
	for i, r := range enc {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

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

func asn1Encode(tag byte, content []byte) []byte { return asn1Build(tag, content) }
func asn1CTX(n int, content []byte) []byte       { return asn1Build(byte(0xa0+n), content) }

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