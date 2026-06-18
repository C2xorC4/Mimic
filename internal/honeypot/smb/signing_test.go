package smb

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestAESCMACRFC4493 validates the AES-128-CMAC implementation against the
// official RFC 4493 §4 test vectors (key 2b7e1516…). Getting CMAC byte-correct is
// the load-bearing part of SMB3 signing, so it is verified independently of a
// live SMB client.
func TestAESCMACRFC4493(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	full := mustHex(t,
		"6bc1bee22e409f96e93d7e117393172a"+
			"ae2d8a571e03ac9c9eb76fac45af8e51"+
			"30c81c46a35ce411e5fbc1191a0a52ef"+
			"f69f2445df4f9b17ad2b417be66c3710")

	cases := []struct {
		name string
		msg  []byte
		want string
	}{
		{"len0", full[:0], "bb1d6929e95937287fa37d129b756746"},
		{"len16", full[:16], "070a16b46b4d4144f79bdd9dd04a287c"},
		{"len40", full[:40], "dfa66747de9ae63030ca32611497c827"},
		{"len64", full[:64], "51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hex.EncodeToString(aesCMAC(key, c.msg))
			if got != c.want {
				t.Fatalf("aesCMAC(%s) = %s, want %s", c.name, got, c.want)
			}
		})
	}
}

// TestSignFrameSetsFlagAndSignature checks that signFrame sets SMB2_FLAGS_SIGNED,
// fills the 16-byte signature field, and is deterministic for a given key/message.
func TestSignFrameSetsFlagAndSignature(t *testing.T) {
	// Minimal NetBIOS-framed SMB2 message: 4-byte transport + 64-byte header.
	frame := make([]byte, pktHdrLen)
	frame[4], frame[5], frame[6], frame[7] = 0xFE, 'S', 'M', 'B'
	binary.LittleEndian.PutUint32(frame[20:24], FlagResponse) // Flags @ SMB2 offset 16

	key := mustHex(t, "00112233445566778899aabbccddeeff")
	signFrame(frame, key, dialect311)

	flags := binary.LittleEndian.Uint32(frame[20:24])
	if flags&smb2FlagsSigned == 0 {
		t.Fatalf("SMB2_FLAGS_SIGNED not set, flags=0x%08x", flags)
	}
	sig := frame[52:68] // Signature @ SMB2 offset 48
	if allZero(sig) {
		t.Fatal("signature field left zero after signing")
	}

	// Re-signing an identical message yields an identical signature.
	frame2 := make([]byte, pktHdrLen)
	copy(frame2, frame[:52]) // copy header up to the (now-set) signature
	for i := 52; i < 68; i++ {
		frame2[i] = 0
	}
	// reset the signed flag so signFrame recomputes from the same precondition
	binary.LittleEndian.PutUint32(frame2[20:24], FlagResponse)
	signFrame(frame2, key, dialect311)
	if hex.EncodeToString(frame2[52:68]) != hex.EncodeToString(sig) {
		t.Fatal("signing not deterministic for identical input")
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
