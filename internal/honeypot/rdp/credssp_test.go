package rdp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildTSRequestChallengeContainsNTLMType2(t *testing.T) {
	var chal [8]byte
	copy(chal[:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	ntlm := buildNTLMChallenge("WIN11LAB", "WORKGROUP", chal, 10, 0, 26200)
	ts := buildTSRequestChallenge(ntlm)

	if !bytes.Contains(ts, []byte("NTLMSSP\x00")) {
		t.Fatal("TSRequest missing NTLMSSP magic")
	}
	idx := bytes.Index(ts, []byte("NTLMSSP\x00"))
	if binary.LittleEndian.Uint32(ts[idx+8:idx+12]) != 2 {
		t.Fatalf("expected NTLM type 2, got type %d", binary.LittleEndian.Uint32(ts[idx+8:idx+12]))
	}
	if ts[idx+48] != 10 || ts[idx+49] != 0 {
		t.Errorf("Product_Version major/minor = %d.%d, want 10.0", ts[idx+48], ts[idx+49])
	}
	build := binary.LittleEndian.Uint16(ts[idx+50 : idx+52])
	if build != 26200 {
		t.Errorf("Product_Build = %d, want 26200", build)
	}
}

func TestExtractNTLMNegotiate(t *testing.T) {
	nego := buildNTLMNegotiate()
	ts := buildTSRequestWithNego(nego)
	got := extractNTLMNegotiate(ts)
	if got == nil {
		t.Fatal("failed to extract negotiate blob")
	}
	if binary.LittleEndian.Uint32(got[8:12]) != 1 {
		t.Fatalf("expected type 1, got %d", binary.LittleEndian.Uint32(got[8:12]))
	}
}

// buildNTLMNegotiate returns a minimal NTLMSSP type 1 message for tests.
func buildNTLMNegotiate() []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	binary.LittleEndian.PutUint32(msg[20:24], ntlmFlags)
	return msg
}

func buildTSRequestWithNego(ntlm []byte) []byte {
	spnego := buildSPNEGONegotiateToken(ntlm)
	negoItem := asn1CTX(0, asn1Encode(0x04, spnego))
	negoData := asn1Encode(0x30, negoItem)
	negoTokens := asn1CTX(1, negoData)
	version := asn1CTX(0, asn1Encode(0x02, []byte{byte(credSSPVersion)}))
	body := concat(version, negoTokens)
	return asn1Encode(0x30, body)
}

func buildSPNEGONegotiateToken(ntlm []byte) []byte {
	mechOID := asn1Encode(0x06, ntlmsspOID)
	mechSeq := asn1Encode(0x30, mechOID)
	mechTypes := asn1CTX(0, mechSeq)
	innerSeq := asn1Encode(0x30, mechTypes)
	negTokenInit := asn1CTX(0, innerSeq)
	mechList := asn1CTX(2, asn1Encode(0x04, ntlm))
	inner := concat(negTokenInit, mechList)
	return asn1CTX(0, asn1Encode(0x30, inner))
}