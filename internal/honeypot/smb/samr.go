package smb

import "encoding/binary"

// SAMR opnums — minimal subset for user/domain enumeration probes.
const (
	samrOpConnect                 = uint16(0)
	samrOpCloseHandle             = uint16(1)
	samrOpLookupDomain            = uint16(5)
	samrOpEnumerateDomains        = uint16(6)
	samrOpOpenDomain              = uint16(7)
	samrOpEnumerateUsersInDomain  = uint16(13)
	samrOpConnect2                = uint16(57)
	samrOpConnect4                = uint16(62)
	samrOpConnect5                = uint16(64)
)

func (p *PipeState) handleSamrRequest(data []byte, callID uint32, env PipeRPCEnv) []byte {
	if len(data) < 24 {
		return nil
	}
	opnum := binary.LittleEndian.Uint16(data[22:24])

	switch opnum {
	case samrOpConnect, samrOpConnect2, samrOpConnect4:
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrConnectStub())
	case samrOpConnect5:
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrConnect5Stub())
	case samrOpEnumerateDomains:
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrEnumerateDomainsStub(accountDomainName(env)))
	case samrOpLookupDomain:
		// SamrLookupDomainInSamServer: a client (impacket-samrdump, nmap
		// smb-enum-*) resolves the domain name to its SID before OpenDomain.
		// Returning STATUS_NOT_SUPPORTED here breaks the enum chain and surfaces
		// as a client-side unpack error — itself a tell of a broken/fake server.
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrLookupDomainStub())
	case samrOpOpenDomain:
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrOpenDomainStub())
	case samrOpEnumerateUsersInDomain:
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrEnumerateUsersStub())
	case samrOpCloseHandle:
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrCloseStub())
	default:
		return buildDCERPCResponse(callID, p.ctxID, appendU32(nil, 0xC00000BB)) // STATUS_NOT_SUPPORTED
	}
}

func encodeSamrConnectStub() []byte {
	var b []byte
	b = appendSamprHandle(b, 0x01)
	b = appendU32(b, 0)
	return b
}

func encodeSamrConnect5Stub() []byte {
	var b []byte
	b = appendU32(b, 1) // OutVersion
	b = appendU32(b, 1) // revision info tag
	b = appendU32(b, 3) // Revision
	b = appendU32(b, 1) // SupportedFeatures
	b = appendSamprHandle(b, 0x01)
	b = appendU32(b, 0)
	return b
}

func encodeSamrEnumerateDomainsStub(name string) []byte {
	const (
		bufRef  = uint32(0x0002000c)
		arrRef  = uint32(0x00020004)
		nameRef = uint32(0x00020008)
	)
	var b []byte
	b = appendU32(b, 0) // EnumerationContext
	b = appendU32(b, bufRef)
	b = appendU32(b, 1) // EntriesRead
	b = appendU32(b, arrRef)
	b = appendU32(b, 1) // array max
	b = appendU32(b, 0) // RelativeId
	b = appendRPCUnicodeStringHeader(b, name, nameRef)
	b = appendRPCUnicodeStringBody(b, name)
	b = appendU32(b, 1) // CountReturned
	b = appendU32(b, 0)
	return b
}

// encodeSamrLookupDomainStub returns the SamrLookupDomainInSamServer reply: a
// referent pointer to the domain SID, the SID NDR body, and NTSTATUS=0. Reuses
// the standalone-workstation machine SID — the same value LSARPC domain queries
// report — so the SID is self-consistent across the SAMR and LSA interfaces.
func encodeSamrLookupDomainStub() []byte {
	const sidRef = uint32(0x00020004)
	var b []byte
	b = appendU32(b, sidRef)
	b = appendRPCSIDBody(b)
	b = appendU32(b, 0)
	return b
}

func encodeSamrOpenDomainStub() []byte {
	var b []byte
	b = appendSamprHandle(b, 0x01)
	b = appendU32(b, 0)
	return b
}

func encodeSamrEnumerateUsersStub() []byte {
	const bufRef = uint32(0x0002000c)
	var b []byte
	b = appendU32(b, 0) // EnumerationContext
	b = appendU32(b, bufRef)
	b = appendU32(b, 0) // EntriesRead
	b = appendU32(b, 0) // null array ptr
	b = appendU32(b, 0) // CountReturned
	b = appendU32(b, 0)
	return b
}

func encodeSamrCloseStub() []byte {
	var b []byte
	b = appendSamprHandle(b, 0x01)
	b = appendU32(b, 0)
	return b
}