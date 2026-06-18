package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

const credSSPVersion = 6

// buildTSRequestChallenge wraps an NTLM challenge in a CredSSP TSRequest (MS-CSSP)
// and returns the raw ASN.1 DER (caller adds TPKT framing).
func buildTSRequestChallenge(ntlmChallenge []byte) []byte {
	spnego := buildSPNEGOChallengeToken(ntlmChallenge)
	negoItem := asn1CTX(0, asn1Encode(0x04, spnego))
	negoData := asn1Encode(0x30, negoItem)
	negoTokens := asn1CTX(1, negoData)
	version := asn1CTX(0, asn1Encode(0x02, []byte{byte(credSSPVersion)}))
	body := concat(version, negoTokens)
	return asn1Encode(0x30, body)
}

// extractNTLMNegotiate returns the NTLMSSP negotiate (type 1) blob from a CredSSP
// TSRequest payload, or nil when none is present.
func extractNTLMNegotiate(tsRequest []byte) []byte {
	return findNTLMType(tsRequest, 1)
}

// extractNTLMAuth returns the NTLMSSP authenticate (type 3) blob from a CredSSP
// TSRequest payload.
func extractNTLMAuth(tsRequest []byte) []byte {
	return findNTLMType(tsRequest, 3)
}

// extractNegoToken walks a TSRequest DER blob and returns the first negoToken
// OCTET STRING payload (SPNEGO wrapper).
func extractNegoToken(data []byte) []byte {
	// Fast path: scan for NTLMSSP inside any OCTET STRING context.
	if idx := bytes.Index(data, []byte("NTLMSSP\x00")); idx >= 0 {
		// Walk back to find the enclosing OCTET STRING (tag 0x04) if possible.
		for i := idx - 1; i >= 0 && i >= idx-4; i-- {
			if data[i] == 0x04 {
				return data[i:]
			}
		}
		return data[idx:]
	}
	return nil
}

func findNTLMType(data []byte, want uint32) []byte {
	idx := bytes.Index(data, []byte("NTLMSSP\x00"))
	if idx < 0 || idx+12 > len(data) {
		return nil
	}
	if binary.LittleEndian.Uint32(data[idx+8:idx+12]) != want {
		return nil
	}
	return data[idx:]
}

// parseNTLMAuthFields extracts domain/username from an NTLMSSP type 3 message.
func parseNTLMAuthFields(ntlm []byte) (domain, username string, err error) {
	if len(ntlm) < 52 {
		return "", "", fmt.Errorf("NTLMSSP_AUTH too short")
	}
	if binary.LittleEndian.Uint32(ntlm[8:12]) != 3 {
		return "", "", fmt.Errorf("expected NTLMSSP type 3")
	}
	dom := ntlmField{ntlm, 28}
	usr := ntlmField{ntlm, 36}
	return dom.utf16String(), usr.utf16String(), nil
}

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