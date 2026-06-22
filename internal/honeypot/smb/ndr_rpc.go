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

func accountDomainName(env PipeRPCEnv) string {
	if env.ComputerName != "" {
		return env.ComputerName
	}
	return "WORKSTATION"
}

func parsePolicyInformationClass(stub []byte) uint32 {
	if len(stub) < 24 {
		return 0
	}
	return binary.LittleEndian.Uint32(stub[20:24])
}