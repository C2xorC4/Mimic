package smb

import "encoding/binary"

// LSARPC opnums — minimal subset for policy/domain probes.
const (
	lsarOpClose                   = uint16(0)
	lsarOpQueryInformationPolicy  = uint16(7)
	lsarOpOpenPolicy              = uint16(6)
	lsarOpOpenPolicy2             = uint16(44)

	policyPrimaryDomainInformation     = uint32(3)
	policyAccountDomainInformation     = uint32(5)
	policyDnsDomainInformation         = uint32(12)
)

func (p *PipeState) handleLsarpcRequest(data []byte, callID uint32, env PipeRPCEnv) []byte {
	if len(data) < 24 {
		return nil
	}
	opnum := binary.LittleEndian.Uint16(data[22:24])
	stub := data[24:]

	switch opnum {
	case lsarOpOpenPolicy, lsarOpOpenPolicy2:
		return buildDCERPCResponse(callID, p.ctxID, encodeLsarOpenPolicyStub())
	case lsarOpQueryInformationPolicy:
		infoClass := parsePolicyInformationClass(stub)
		return buildDCERPCResponse(callID, p.ctxID, encodeLsarQueryPolicyStub(infoClass, accountDomainName(env)))
	case lsarOpClose:
		return buildDCERPCResponse(callID, p.ctxID, encodeLsarCloseStub())
	default:
		return buildDCERPCResponse(callID, p.ctxID, appendU32(nil, 0xC00000BB))
	}
}

func encodeLsarOpenPolicyStub() []byte {
	var b []byte
	b = appendSamprHandle(b, 0x02)
	b = appendU32(b, 0)
	return b
}

func encodeLsarCloseStub() []byte {
	var b []byte
	b = appendSamprHandle(b, 0x02)
	b = appendU32(b, 0)
	return b
}

func encodeLsarQueryPolicyStub(infoClass uint32, name string) []byte {
	switch infoClass {
	case policyPrimaryDomainInformation:
		return encodeLsarPrimaryDomainStub(name)
	case policyAccountDomainInformation:
		return encodeLsarAccountDomainStub(name)
	case policyDnsDomainInformation:
		return encodeLsarDnsDomainStub(name)
	default:
		return appendU32(nil, 0xC00000BB)
	}
}

func encodeLsarPrimaryDomainStub(name string) []byte {
	const (
		infoRef = uint32(0x0002000c)
		nameRef = uint32(0x00020008)
		sidRef  = uint32(0x00020010)
	)
	var b []byte
	b = appendU32(b, infoRef)
	b = appendU32(b, policyPrimaryDomainInformation)
	b = appendRPCUnicodeStringHeader(b, name, nameRef)
	b = appendU32(b, sidRef)
	b = appendRPCUnicodeStringBody(b, name)
	b = appendRPCSIDBody(b)
	b = appendU32(b, 0)
	return b
}

func encodeLsarAccountDomainStub(name string) []byte {
	const (
		infoRef = uint32(0x0002000c)
		nameRef = uint32(0x00020008)
		sidRef  = uint32(0x00020010)
	)
	var b []byte
	b = appendU32(b, infoRef)
	b = appendU32(b, policyAccountDomainInformation)
	b = appendRPCUnicodeStringHeader(b, name, nameRef)
	b = appendU32(b, sidRef)
	b = appendRPCUnicodeStringBody(b, name)
	b = appendRPCSIDBody(b)
	b = appendU32(b, 0)
	return b
}

func encodeLsarDnsDomainStub(name string) []byte {
	const (
		infoRef   = uint32(0x0002000c)
		nameRef   = uint32(0x00020008)
		dnsRef    = uint32(0x00020010)
		forestRef = uint32(0x00020014)
		sidRef    = uint32(0x00020018)
	)
	var b []byte
	b = appendU32(b, infoRef)
	b = appendU32(b, policyDnsDomainInformation)
	b = appendRPCUnicodeStringHeader(b, name, nameRef)
	b = appendRPCUnicodeStringHeader(b, name, dnsRef)
	b = appendRPCUnicodeStringHeader(b, name, forestRef)
	b = append(b, make([]byte, 16)...) // DomainGuid (zero)
	b = appendU32(b, sidRef)
	b = appendRPCUnicodeStringBody(b, name)
	b = appendRPCUnicodeStringBody(b, name)
	b = appendRPCUnicodeStringBody(b, name)
	b = appendRPCSIDBody(b)
	b = appendU32(b, 0)
	return b
}