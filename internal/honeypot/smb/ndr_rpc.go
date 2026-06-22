package smb

import "encoding/binary"

// appendSamprHandle appends a 20-byte SAMPR/LSAPR context handle.
func appendSamprHandle(b []byte, tag byte) []byte {
	h := make([]byte, 20)
	h[0] = tag
	return append(b, h...)
}

// appendRPCUnicodeStringHeader encodes the fixed RPC_UNICODE_STRING header.
func appendRPCUnicodeStringHeader(b []byte, s string, referent uint32) []byte {
	byteLen := uint16(len(s) * 2)
	b = appendU16(b, byteLen)
	b = appendU16(b, byteLen+2)
	b = appendU32(b, referent)
	return b
}

// appendRPCUnicodeStringBody encodes the deferred wchar buffer for RPC_UNICODE_STRING.
func appendRPCUnicodeStringBody(b []byte, s string) []byte {
	return appendNDRWString(b, s+"\x00")
}

// workstationSIDBody is the deferred NDR blob for a plausible standalone-workstation
// machine SID (S-1-5-21-1234567890-1234567890-1234567890).
var workstationSIDBody = []byte{
	0x04, 0x00, 0x00, 0x00,
	0x01, 0x04, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x05,
	0x15, 0x00, 0x00, 0x00,
	0xd2, 0x02, 0x96, 0x49,
	0xd2, 0x02, 0x96, 0x49,
	0xd2, 0x02, 0x96, 0x49,
}

func appendRPCSIDBody(b []byte) []byte {
	return append(b, workstationSIDBody...)
}

// appendRPCUnicodeStringHeaderNoNull encodes an RPC_UNICODE_STRING header whose
// MaximumLength equals Length (no NUL terminator) — the convention LSA uses for
// translated names and referenced-domain names (cf. appendRPCUnicodeStringHeader,
// which reserves a terminator for the SAMR string convention).
func appendRPCUnicodeStringHeaderNoNull(b []byte, s string, referent uint32) []byte {
	byteLen := uint16(len(s) * 2)
	b = appendU16(b, byteLen)
	b = appendU16(b, byteLen)
	b = appendU32(b, referent)
	return b
}

// appendNDRWStringNoNull encodes a deferred conformant+varying wchar array with
// no NUL terminator (MaxCount = ActualCount = len), padded to a 4-byte boundary.
// Bait names are ASCII, so one uint16 per byte is exact.
func appendNDRWStringNoNull(b []byte, s string) []byte {
	n := uint32(len(s))
	b = appendU32(b, n) // MaxCount
	b = appendU32(b, 0) // Offset
	b = appendU32(b, n) // ActualCount
	for i := 0; i < len(s); i++ {
		b = appendU16(b, uint16(s[i]))
	}
	if (len(s)*2)%4 != 0 {
		b = append(b, 0, 0) // pad to 4-byte boundary
	}
	return b
}

func accountDomainName(env PipeRPCEnv) string {
	if env.ComputerName != "" {
		return env.ComputerName
	}
	return "WORKSTATION"
}

// parsePolicyInformationClass reads the InformationClass from a
// QueryInformationPolicy(2) request: PolicyHandle(20) + a 2-byte
// POLICY_INFORMATION_CLASS enum (NDRUSHORT). Real clients (impacket-lookupsid)
// send only 2 bytes, so this must not require a 4-byte field.
func parsePolicyInformationClass(stub []byte) uint32 {
	if len(stub) < 22 {
		return 0
	}
	return uint32(binary.LittleEndian.Uint16(stub[20:22]))
}