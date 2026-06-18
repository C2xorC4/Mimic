package smb

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
)

// SMB2/3 response signing.
//
// Why this exists: once a client authenticates with a *real* (non-guest)
// credential, modern SMB clients (smbclient -m SMB3, netexec, impacket) enable
// signing on the session and REJECT unsigned server responses with "Bad SMB2
// signature" — so a keyless honeypot that accepts a seeded credential could
// authenticate and enumerate shares but never serve file content (observed in
// the OSE-2026-001 exercise, Op-5 FINDING-011). Because the honeypot KNOWS the
// seeded password, it can derive the same session key the client derives and
// sign its responses, closing that gap coherently (the attacker stays logged in
// as the real user and reads bait content).
//
// Guest/null sessions still skip signing (the client zeroes the key on the
// IS_GUEST flag), so this path only engages for verified seeded credentials.

// NTLMSSP_NEGOTIATE_KEY_EXCH — when set, the client sends an encrypted random
// session key that becomes the ExportedSessionKey after RC4 decryption.
const ntlmNegotiateKeyExch = uint32(0x40000000)

// smb2FlagsSigned is set in the SMB2 header Flags field on a signed message.
const smb2FlagsSigned = uint32(0x00000008)

// exportedSessionKey returns the NTLM ExportedSessionKey. For NTLMv2 the
// KeyExchangeKey equals the SessionBaseKey; when the client negotiated key
// exchange it additionally RC4-decrypts the EncryptedRandomSessionKey under that
// key. Otherwise the KeyExchangeKey is used directly.
func exportedSessionKey(keyExchangeKey []byte, flags uint32, encryptedSessionKey []byte) []byte {
	if len(keyExchangeKey) < 16 {
		return nil
	}
	if flags&ntlmNegotiateKeyExch != 0 && len(encryptedSessionKey) == 16 {
		c, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return keyExchangeKey
		}
		out := make([]byte, 16)
		c.XORKeyStream(out, encryptedSessionKey)
		return out
	}
	return keyExchangeKey
}

// deriveSigningKey produces the 16-byte signing key for the negotiated dialect.
//
//   - 3.1.1: SP800-108 CTR-HMAC-SHA256 KDF with label "SMBSigningKey\0" and the
//     session preauth-integrity hash as context. Requires a valid preauth chain;
//     returns nil when preauth is unavailable so the caller falls back safely.
//   - 3.0 / 3.0.2: same KDF with the fixed "SMB2AESCMAC\0" / "SmbSign\0" pair.
//   - 2.x: the ExportedSessionKey is used directly (HMAC-SHA256 signing).
func deriveSigningKey(exportedKey []byte, dialect uint16, preauth []byte) []byte {
	if len(exportedKey) < 16 {
		return nil
	}
	switch {
	case dialect >= dialect311:
		if len(preauth) == 0 {
			return nil // no preauth hash → cannot derive the 3.1.1 signing key
		}
		return kdfCounterMode(exportedKey, []byte("SMBSigningKey\x00"), preauth)
	case dialect == dialect300 || dialect == dialect302:
		return kdfCounterMode(exportedKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
	default:
		// 2.0.2 / 2.1 sign with HMAC-SHA256 keyed directly on the session key.
		return exportedKey
	}
}

// kdfCounterMode implements the NIST SP800-108 counter-mode KDF with HMAC-SHA256
// as used by MS-SMB2 §3.1.4.2, returning a 128-bit (16-byte) key. The input is
// [i]₃₂ || Label || 0x00 || Context || [L]₃₂ with i=1 and L=128, big-endian. The
// caller passes Label *including* its NTLM-style trailing NUL; the 0x00
// separator is added here (matching the reference implementation).
func kdfCounterMode(ki, label, context []byte) []byte {
	h := hmac.New(sha256.New, ki)
	h.Write([]byte{0x00, 0x00, 0x00, 0x01}) // counter i = 1
	h.Write(label)
	h.Write([]byte{0x00}) // separator
	h.Write(context)
	h.Write([]byte{0x00, 0x00, 0x00, 0x80}) // L = 128 bits
	return h.Sum(nil)[:16]
}

// signFrame signs a complete NetBIOS-framed SMB2 response in place: it sets the
// SMB2_FLAGS_SIGNED flag, zeroes the 16-byte Signature field, computes the MAC
// over the SMB2 message (excluding the 4-byte transport header), and writes it
// back. 3.x uses AES-128-CMAC; 2.x uses HMAC-SHA256 (first 16 bytes).
func signFrame(frame []byte, signingKey []byte, dialect uint16) {
	if len(frame) < pktHdrLen || len(signingKey) < 16 {
		return
	}
	msg := frame[netBIOSLen:] // SMB2 message: Flags @16, Signature @48

	flags := binary.LittleEndian.Uint32(msg[16:20]) | smb2FlagsSigned
	binary.LittleEndian.PutUint32(msg[16:20], flags)
	for i := 48; i < 64; i++ {
		msg[i] = 0
	}

	var mac []byte
	if dialect >= dialect300 {
		mac = aesCMAC(signingKey[:16], msg)
	} else {
		m := hmac.New(sha256.New, signingKey)
		m.Write(msg)
		mac = m.Sum(nil)
	}
	copy(msg[48:64], mac[:16])
}

// aesCMAC computes the AES-128-CMAC (RFC 4493) of msg under a 16-byte key.
func aesCMAC(key, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return make([]byte, 16)
	}
	const bs = 16

	// Subkey generation (RFC 4493 §2.3).
	l := make([]byte, bs)
	block.Encrypt(l, l)
	k1 := cmacDouble(l)
	k2 := cmacDouble(k1)

	n := (len(msg) + bs - 1) / bs
	complete := false
	if n == 0 {
		n = 1
	} else if len(msg)%bs == 0 {
		complete = true
	}

	last := make([]byte, bs)
	if complete {
		xorInto(last, msg[(n-1)*bs:], k1)
	} else {
		rem := msg[(n-1)*bs:]
		padded := make([]byte, bs)
		copy(padded, rem)
		padded[len(rem)] = 0x80
		xorInto(last, padded, k2)
	}

	x := make([]byte, bs)
	y := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		xorInto(y, x, msg[i*bs:(i+1)*bs])
		block.Encrypt(x, y)
	}
	xorInto(y, x, last)
	block.Encrypt(x, y)
	return x
}

// cmacDouble performs the GF(2^128) "left shift and conditional xor 0x87"
// doubling used in CMAC subkey generation.
func cmacDouble(b []byte) []byte {
	out := make([]byte, len(b))
	var carry byte
	for i := len(b) - 1; i >= 0; i-- {
		out[i] = b[i]<<1 | carry
		carry = b[i] >> 7
	}
	if b[0]&0x80 != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

// xorInto writes a XOR b into dst (all same length).
func xorInto(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}
