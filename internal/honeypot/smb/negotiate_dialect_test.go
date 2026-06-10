package smb

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

// buildNTLMv2Response constructs the client-side NTResponse (NTProofStr || blob)
// for the given password/identity, mirroring what a real SMB client computes.
func buildNTLMv2Response(pass, user, domain string, challenge [8]byte, blob []byte) []byte {
	ntHash := md4Sum(utf16LE(pass))
	m := hmac.New(md5.New, ntHash[:])
	m.Write(utf16LE(strings.ToUpper(user) + domain))
	ntowfv2 := m.Sum(nil)

	m = hmac.New(md5.New, ntowfv2)
	m.Write(challenge[:])
	m.Write(blob)
	proof := m.Sum(nil)

	return append(proof, blob...)
}

func TestDialectFromString(t *testing.T) {
	cases := map[string]uint16{
		"1.0":   dialectSMB1,
		"2.0":   dialect202,
		"2.0.2": dialect202,
		"2.1":   dialect210,
		"3.0":   dialect300,
		"3.0.2": dialect302,
		"3.1.1": dialect311,
		"":      0,
		"bogus": 0,
	}
	for in, want := range cases {
		if got := DialectFromString(in); got != want {
			t.Errorf("DialectFromString(%q) = %#x, want %#x", in, got, want)
		}
	}
}

func TestSelectDialectCeiling(t *testing.T) {
	all := []uint16{dialect202, dialect210, dialect300, dialect302, dialect311}

	tests := []struct {
		name    string
		offered []uint16
		max     uint16
		want    uint16
	}{
		{"win11 picks 3.1.1", all, dialect311, dialect311},
		{"win7 caps at 2.1", all, dialect210, dialect210},
		{"win8.1 caps at 3.0.2", all, dialect302, dialect302},
		{"unset defaults to highest", all, 0, dialect311},
		{"smb2-only client vs xp ceiling → none", all, dialectSMB1, 0},
		{"client offers only 3.1.1 vs win7 ceiling → none", []uint16{dialect311}, dialect210, 0},
		{"client offers 2.0.2 only", []uint16{dialect202}, dialect311, dialect202},
	}
	for _, tc := range tests {
		if got := selectDialect(tc.offered, tc.max); got != tc.want {
			t.Errorf("%s: selectDialect = %#x, want %#x", tc.name, got, tc.want)
		}
	}
}

// TestMD4Vectors checks md4Sum against RFC 1320 Appendix A.5 test vectors.
func TestMD4Vectors(t *testing.T) {
	cases := map[string]string{
		"":               "31d6cfe0d16ae931b73c59d7e0c089c0",
		"a":              "bde52cb31de33e46245e05fbdbd6fb24",
		"abc":            "a448017aaf21d8525fc10ae87aa6729d",
		"message digest": "d9130a8164549fe818874806e1c7014b",
	}
	for in, want := range cases {
		got := md4Sum([]byte(in))
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("md4Sum(%q) = %s, want %s", in, hex.EncodeToString(got[:]), want)
		}
	}
}

// TestVerifyCredentialRoundTrip builds a real NTLMv2 response for a known password
// and confirms verifyCredential accepts the right password and rejects a wrong one.
func TestVerifyCredentialRoundTrip(t *testing.T) {
	user, domain, pass := "guest", "WORKGROUP", "Summer2026!"
	var challenge [8]byte
	for i := range challenge {
		challenge[i] = byte(i * 7)
	}
	// A plausible NTLMv2 client-challenge blob (contents are opaque to verification).
	blob := []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	// Construct the matching NTResponse = NTProofStr || blob using the same math.
	ntResponse := buildNTLMv2Response(pass, user, domain, challenge, blob)

	cred := Credential{Username: user, Password: pass, Domain: domain}
	if !verifyCredential(cred, user, domain, challenge, ntResponse) {
		t.Fatal("verifyCredential rejected the correct password")
	}

	wrong := Credential{Username: user, Password: "wrong", Domain: domain}
	if verifyCredential(wrong, user, domain, challenge, ntResponse) {
		t.Fatal("verifyCredential accepted a wrong password")
	}

	// LMv1-sized response (<=16 after proof) must be rejected as non-NTLMv2.
	if verifyCredential(cred, user, domain, challenge, ntResponse[:16]) {
		t.Fatal("verifyCredential accepted a response with no blob")
	}
}

func TestBuildSMBv1NegotiateRefusal(t *testing.T) {
	srv := New(Config{ComputerName: "TESTBOX", DomainName: "TESTDOM"}) // SMB1 disabled by default
	resp := srv.buildSMBv1NegotiateRefusal(newSession())
	// NBT(4) + SMB1 hdr(32) + WordCount(1) at offset 36.
	if len(resp) < 39 {
		t.Fatalf("refusal too short: %d", len(resp))
	}
	if resp[36] != 1 {
		t.Errorf("refusal WordCount = %d, want 1", resp[36])
	}
	dialectIndex := uint16(resp[37]) | uint16(resp[38])<<8
	if dialectIndex != 0xFFFF {
		t.Errorf("refusal DialectIndex = %#x, want 0xFFFF", dialectIndex)
	}
}
