package smb

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"strings"
)

// Credential is a seeded fake account that authenticates successfully against the
// honeypot. The intent is for other emulated services to "leak" a username/password
// (e.g. in a planted config file, an HTTP response, or a maze artifact) that an
// attacker can then use against SMB — deepening engagement beyond anonymous browsing.
type Credential struct {
	Username string
	Password string
	Domain   string // optional; informational/matching only (see verifyCredential)
}

// matchCredential returns the seeded credential whose username matches user
// (case-insensitive), or nil. Domain is not part of the match key because clients
// frequently send an empty or workgroup domain regardless of the account's home
// domain; the password is what proves identity.
func matchCredential(creds []Credential, user string) *Credential {
	for i := range creds {
		if strings.EqualFold(creds[i].Username, user) {
			return &creds[i]
		}
	}
	return nil
}

// verifyCredential reports whether the client's NTLMv2 response proves knowledge of
// cred.Password. It recomputes the NTLMv2 proof from our 8-byte server challenge and
// the username/domain the client actually used in its AUTH message, and compares it
// to the proof the client sent.
//
//	NTOWFv2    = HMAC_MD5( MD4(UTF16LE(password)), UTF16LE(UPPER(user) + domain) )
//	NTProofStr = HMAC_MD5( NTOWFv2, serverChallenge || blob )
//	NTResponse = NTProofStr(16) || blob
//
// Only NTLMv2 (response longer than the 16-byte proof, i.e. a temp/client-challenge
// blob is present) is supported — that is what netexec, smbmap and impacket send by
// default. Bare NTLMv1 (exactly 24 bytes, no blob) is treated as non-matching.
func verifyCredential(cred Credential, user, domain string, serverChallenge [8]byte, ntResponse []byte) bool {
	if len(ntResponse) <= 16 {
		return false
	}
	ntHash := md4Sum(utf16LE(cred.Password))

	mac := hmac.New(md5.New, ntHash[:])
	mac.Write(utf16LE(strings.ToUpper(user) + domain))
	ntowfv2 := mac.Sum(nil)

	proof := ntResponse[:16]
	blob := ntResponse[16:]

	mac = hmac.New(md5.New, ntowfv2)
	mac.Write(serverChallenge[:])
	mac.Write(blob)
	expected := mac.Sum(nil)

	return hmac.Equal(proof, expected)
}

// ntlmSessionBaseKey derives the NTLMv2 SessionBaseKey from a verified seeded
// credential and the client's AUTH material. For NTLMv2 this also serves as the
// KeyExchangeKey (MS-NLMP §3.4.5.1):
//
//	SessionBaseKey = HMAC_MD5( NTOWFv2, NTProofStr )
//
// where NTProofStr is the first 16 bytes of the NT response. Returns nil if the
// response is too short to contain a proof. The caller turns this into the
// ExportedSessionKey (handling NTLM key exchange) and then the SMB signing key.
func ntlmSessionBaseKey(cred Credential, user, domain string, ntResponse []byte) []byte {
	if len(ntResponse) < 16 {
		return nil
	}
	ntHash := md4Sum(utf16LE(cred.Password))

	mac := hmac.New(md5.New, ntHash[:])
	mac.Write(utf16LE(strings.ToUpper(user) + domain))
	ntowfv2 := mac.Sum(nil)

	mac = hmac.New(md5.New, ntowfv2)
	mac.Write(ntResponse[:16]) // NTProofStr
	return mac.Sum(nil)        // 16-byte SessionBaseKey
}

// md4Sum computes the MD4 digest (RFC 1320) of data. Go's standard library has no
// MD4, and we deliberately avoid adding golang.org/x/crypto/md4 so the build stays
// hermetic and offline-friendly (the lab host has no internet). MD4 is used here only
// to derive the NTLM NT-hash for credential verification — not for any protective
// purpose — so the long-broken state of MD4 is irrelevant.
func md4Sum(data []byte) [16]byte {
	var a, b, c, d uint32 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

	// Pad: 0x80, zeros to 56 mod 64, then 64-bit little-endian bit length.
	msgLen := len(data)
	padded := make([]byte, msgLen, msgLen+72)
	copy(padded, data)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], uint64(msgLen)*8)
	padded = append(padded, lenBytes[:]...)

	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	rotl := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

	var X [16]uint32
	for off := 0; off < len(padded); off += 64 {
		for i := 0; i < 16; i++ {
			X[i] = binary.LittleEndian.Uint32(padded[off+i*4 : off+i*4+4])
		}
		aa, bb, cc, dd := a, b, c, d

		r1 := func(a *uint32, b, c, d uint32, k int, s uint) { *a = rotl(*a+f(b, c, d)+X[k], s) }
		r1(&a, b, c, d, 0, 3)
		r1(&d, a, b, c, 1, 7)
		r1(&c, d, a, b, 2, 11)
		r1(&b, c, d, a, 3, 19)
		r1(&a, b, c, d, 4, 3)
		r1(&d, a, b, c, 5, 7)
		r1(&c, d, a, b, 6, 11)
		r1(&b, c, d, a, 7, 19)
		r1(&a, b, c, d, 8, 3)
		r1(&d, a, b, c, 9, 7)
		r1(&c, d, a, b, 10, 11)
		r1(&b, c, d, a, 11, 19)
		r1(&a, b, c, d, 12, 3)
		r1(&d, a, b, c, 13, 7)
		r1(&c, d, a, b, 14, 11)
		r1(&b, c, d, a, 15, 19)

		r2 := func(a *uint32, b, c, d uint32, k int, s uint) { *a = rotl(*a+g(b, c, d)+X[k]+0x5a827999, s) }
		r2(&a, b, c, d, 0, 3)
		r2(&d, a, b, c, 4, 5)
		r2(&c, d, a, b, 8, 9)
		r2(&b, c, d, a, 12, 13)
		r2(&a, b, c, d, 1, 3)
		r2(&d, a, b, c, 5, 5)
		r2(&c, d, a, b, 9, 9)
		r2(&b, c, d, a, 13, 13)
		r2(&a, b, c, d, 2, 3)
		r2(&d, a, b, c, 6, 5)
		r2(&c, d, a, b, 10, 9)
		r2(&b, c, d, a, 14, 13)
		r2(&a, b, c, d, 3, 3)
		r2(&d, a, b, c, 7, 5)
		r2(&c, d, a, b, 11, 9)
		r2(&b, c, d, a, 15, 13)

		r3 := func(a *uint32, b, c, d uint32, k int, s uint) { *a = rotl(*a+h(b, c, d)+X[k]+0x6ed9eba1, s) }
		r3(&a, b, c, d, 0, 3)
		r3(&d, a, b, c, 8, 9)
		r3(&c, d, a, b, 4, 11)
		r3(&b, c, d, a, 12, 15)
		r3(&a, b, c, d, 2, 3)
		r3(&d, a, b, c, 10, 9)
		r3(&c, d, a, b, 6, 11)
		r3(&b, c, d, a, 14, 15)
		r3(&a, b, c, d, 1, 3)
		r3(&d, a, b, c, 9, 9)
		r3(&c, d, a, b, 5, 11)
		r3(&b, c, d, a, 13, 15)
		r3(&a, b, c, d, 3, 3)
		r3(&d, a, b, c, 11, 9)
		r3(&c, d, a, b, 7, 11)
		r3(&b, c, d, a, 15, 15)

		a += aa
		b += bb
		c += cc
		d += dd
	}

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint32(out[4:8], b)
	binary.LittleEndian.PutUint32(out[8:12], c)
	binary.LittleEndian.PutUint32(out[12:16], d)
	return out
}
