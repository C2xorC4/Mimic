package smb

import (
	"bytes"
	"encoding/binary"
)

// LSARPC opnums — subset for policy/domain probes + SID→name lookup.
const (
	lsarOpClose                   = uint16(0)
	lsarOpQueryInformationPolicy  = uint16(7)
	lsarOpOpenPolicy              = uint16(6)
	lsarOpLookupSids              = uint16(15)
	lsarOpOpenPolicy2             = uint16(44)
	lsarOpQueryInformationPolicy2 = uint16(46)

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
	case lsarOpQueryInformationPolicy, lsarOpQueryInformationPolicy2:
		// QueryInformationPolicy2 (opnum 46) has the same request/response shape as
		// opnum 7; impacket-lookupsid uses 2 to fetch the account-domain SID before
		// RID-cycling, so both route to the same encoder.
		infoClass := parsePolicyInformationClass(stub)
		return buildDCERPCResponse(callID, p.ctxID, encodeLsarQueryPolicyStub(infoClass, accountDomainName(env)))
	case lsarOpLookupSids:
		// LsarLookupSids: resolve each input SID to a name. lookupsid.py builds SIDs
		// from our account-domain SID + RID and brute-forces; we map the bait RIDs
		// (consistent with SAMR EnumUsers) and mark the rest SidTypeUnknown.
		rids := parseLookupSidRIDs(stub)
		return buildDCERPCResponse(callID, p.ctxID, encodeLsarLookupSids(rids, env))
	case lsarOpClose:
		return buildDCERPCResponse(callID, p.ctxID, encodeLsarCloseStub())
	default:
		return buildDCERPCResponse(callID, p.ctxID, appendU32(nil, 0xC00000BB))
	}
}

// userSIDPrefix returns the constant leading bytes of a domain user's RPC_SID as
// it appears in a LookupSids request: Revision 1, SubAuthorityCount 5, the S-1-5
// IdentifierAuthority and our account domain's 4 sub-authorities — everything up
// to (but not including) the trailing RID. (workstationSIDBody layout: MaxCount
// [0:4], Rev+Count [4:6], IdAuth [6:12], 4 domain sub-authorities [12:28].)
func userSIDPrefix() []byte {
	p := []byte{0x01, 0x05} // Revision 1, SubAuthorityCount 5 (domain's 4 + RID)
	return append(p, workstationSIDBody[6:28]...)
}

// parseLookupSidRIDs scans a LookupSids request for user SIDs built from our
// account-domain SID and returns their RIDs in request order. Scanning for the
// fixed domain prefix (our unique sub-authorities) avoids a full NDR walk of the
// conformant SID array and cannot false-match on unrelated data.
func parseLookupSidRIDs(stub []byte) []uint32 {
	prefix := userSIDPrefix()
	var rids []uint32
	for i := 0; i+len(prefix)+4 <= len(stub); {
		if bytes.Equal(stub[i:i+len(prefix)], prefix) {
			rids = append(rids, binary.LittleEndian.Uint32(stub[i+len(prefix):i+len(prefix)+4]))
			i += len(prefix) + 4
			continue
		}
		i++
	}
	return rids
}

// lookupBaitName resolves a RID to a bait username (exact RID match).
func lookupBaitName(users []BaitUser, rid uint32) (string, bool) {
	for _, u := range users {
		if u.RID == rid {
			return u.Name, true
		}
	}
	return "", false
}

// encodeLsarLookupSids builds the LsarLookupSids reply: one ReferencedDomains
// entry (our account domain + SID) and a TranslatedNames array — SidTypeUser +
// name + DomainIndex 0 for a bait RID (consistent with SAMR EnumUsers),
// SidTypeUnknown for the rest. NTSTATUS is SUCCESS / STATUS_SOME_NOT_MAPPED /
// STATUS_NONE_MAPPED per mapped count. Names map to input SIDs by position.
func encodeLsarLookupSids(rids []uint32, env PipeRPCEnv) []byte {
	domain := accountDomainName(env)
	type res struct {
		use  uint16
		name string
		idx  uint32
	}
	results := make([]res, len(rids))
	mapped := 0
	for i, rid := range rids {
		if name, ok := lookupBaitName(env.Users, rid); ok {
			results[i] = res{use: 1, name: name, idx: 0} // SidTypeUser, ReferencedDomains[0]
			mapped++
		} else {
			results[i] = res{use: 8, name: "", idx: 0xFFFFFFFF} // SidTypeUnknown, DomainIndex -1
		}
	}

	ref := uint32(0x00020000)
	next := func() uint32 { r := ref; ref += 4; return r }

	var b []byte
	// ReferencedDomains (PLSAPR_REFERENCED_DOMAIN_LIST)
	b = appendU32(b, next()) // referent
	b = appendU32(b, 1)      // Entries
	b = appendU32(b, next()) // Domains array referent
	b = appendU32(b, 0)      // MaxEntries
	b = appendU32(b, 1)      // Domains array MaxCount
	b = appendRPCUnicodeStringHeaderNoNull(b, domain, next())
	b = appendU32(b, next())              // Domains[0].Sid referent
	b = appendNDRWStringNoNull(b, domain) // deferred domain name
	b = append(b, workstationSIDBody...)  // deferred domain Sid (incl. MaxCount)

	// TranslatedNames (LSAPR_TRANSLATED_NAMES)
	b = appendU32(b, uint32(len(rids))) // Entries
	b = appendU32(b, next())            // Names array referent
	b = appendU32(b, uint32(len(rids))) // Names array MaxCount
	for _, r := range results {
		b = appendU16(b, r.use)                                   // Use
		b = appendU16(b, 0)                                       // pad to 4
		b = appendRPCUnicodeStringHeaderNoNull(b, r.name, next()) // Name header
		b = appendU32(b, r.idx)                                   // DomainIndex
	}
	for _, r := range results {
		b = appendNDRWStringNoNull(b, r.name) // deferred name buffers (empty → count 0)
	}

	b = appendU32(b, uint32(mapped)) // MappedCount
	switch {
	case mapped == 0:
		b = appendU32(b, 0xC0000073) // STATUS_NONE_MAPPED
	case mapped < len(rids):
		b = appendU32(b, 0x00000107) // STATUS_SOME_NOT_MAPPED
	default:
		b = appendU32(b, 0) // STATUS_SUCCESS
	}
	return b
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