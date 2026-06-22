package smb

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// baitUsers builds the SAMR user list a real Windows box exposes: the standard
// built-in local accounts (canonical RIDs) followed by the honeypot's seeded
// credentials at RID 1000+. The seeded accounts (e.g. svc_backup) are the
// payoff — an attacker who enumerates them can reuse a leaked password against
// SMB (the cred-leak loop). RIDs are stable so LSA SID↔name lookups agree.
func baitUsers(creds []Credential) []BaitUser {
	users := []BaitUser{
		{RID: 500, Name: "Administrator"},
		{RID: 501, Name: "Guest"},
		{RID: 503, Name: "DefaultAccount"},
		{RID: 504, Name: "WDAGUtilityAccount"},
	}
	seen := make(map[string]bool, len(users))
	for _, u := range users {
		seen[strings.ToLower(u.Name)] = true
	}
	rid := uint32(1000)
	for _, c := range creds {
		if c.Username == "" || seen[strings.ToLower(c.Username)] {
			continue
		}
		users = append(users, BaitUser{RID: rid, Name: c.Username})
		seen[strings.ToLower(c.Username)] = true
		rid++
	}
	return users
}

// SAMR opnums — minimal subset for user/domain enumeration probes.
const (
	samrOpConnect                 = uint16(0)
	samrOpCloseHandle             = uint16(1)
	samrOpLookupDomain            = uint16(5)
	samrOpEnumerateDomains        = uint16(6)
	samrOpOpenDomain              = uint16(7)
	samrOpQueryInformationDomain  = uint16(8)
	samrOpEnumerateUsersInDomain  = uint16(13)
	samrOpOpenUser                = uint16(34)
	samrOpQueryInformationUser2   = uint16(47)
	samrOpConnect2                = uint16(57)
	samrOpConnect4                = uint16(62)
	samrOpConnect5                = uint16(64)
)

func (p *PipeState) handleSamrRequest(data []byte, callID uint32, env PipeRPCEnv) []byte {
	if len(data) < 24 {
		return nil
	}
	opnum := binary.LittleEndian.Uint16(data[22:24])
	stub := data[24:]

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
	case samrOpQueryInformationDomain:
		// SamrQueryInformationDomain stub: DomainHandle(20) + DomainInformationClass(2).
		// nmap smb-enum-domains reads the password/lockout/modified policy via this.
		var class uint16
		if len(stub) >= 22 {
			class = binary.LittleEndian.Uint16(stub[20:22])
		}
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrQueryDomainInfo(class))
	case samrOpEnumerateUsersInDomain:
		// Modern Windows denies anonymous SAM enumeration (RestrictAnonymousSAM=1):
		// a null/guest session gets ACCESS_DENIED, an authenticated session gets the
		// user list. This is both faithful and the deception sweet spot — the
		// attacker must reuse a leaked credential to enumerate (and find more).
		if !env.Authenticated {
			return buildDCERPCResponse(callID, p.ctxID, encodeSamrEnumUsersDenied())
		}
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrEnumerateUsersStub(env.Users))
	case samrOpOpenUser:
		// SamrOpenUser stub: DomainHandle(20) + DesiredAccess(4) + UserId/RID(4).
		// Anonymous sessions can't open a user (SAM enum is gated above) — deny.
		if !env.Authenticated {
			return buildDCERPCResponse(callID, p.ctxID, appendU32(appendSamprHandle(nil, 0), 0xC0000022))
		}
		var rid uint32
		if len(stub) >= 28 {
			rid = binary.LittleEndian.Uint32(stub[24:28])
		}
		// Echo the RID into the returned handle so QueryInformationUser2 (which only
		// receives a handle) can recover which user to describe — stateless.
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrOpenUserStub(rid))
	case samrOpQueryInformationUser2:
		var rid uint32
		if len(stub) >= 8 {
			rid = binary.LittleEndian.Uint32(stub[4:8]) // RID echoed in the handle
		}
		return buildDCERPCResponse(callID, p.ctxID, encodeSamrQueryUserAllStub(rid))
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

// encodeSamrEnumerateUsersStub encodes the SamrEnumerateUsersInDomain reply: a
// SAMPR_ENUMERATION_BUFFER of SAMPR_RID_ENUMERATION{RelativeId, Name}. NDR emits
// all fixed element parts (RID + RPC_UNICODE_STRING header) first, then every
// deferred name buffer, then CountReturned + STATUS_SUCCESS.
func encodeSamrEnumerateUsersStub(users []BaitUser) []byte {
	const (
		bufRef = uint32(0x0002000c)
		arrRef = uint32(0x00020010)
	)
	n := uint32(len(users))
	var b []byte
	b = appendU32(b, n) // EnumerationContext (resume index; ignored on STATUS_SUCCESS)
	if n == 0 {
		b = appendU32(b, bufRef)
		b = appendU32(b, 0) // EntriesRead
		b = appendU32(b, 0) // null array ptr
		b = appendU32(b, 0) // CountReturned
		b = appendU32(b, 0) // STATUS_SUCCESS
		return b
	}
	b = appendU32(b, bufRef) // SAMPR_ENUMERATION_BUFFER referent
	b = appendU32(b, n)      // EntriesRead
	b = appendU32(b, arrRef) // conformant array referent
	b = appendU32(b, n)      // MaxCount
	ref := uint32(0x00020014)
	for _, u := range users {
		b = appendU32(b, u.RID)
		b = appendRPCUnicodeStringHeader(b, u.Name, ref)
		ref += 4
	}
	for _, u := range users {
		b = appendRPCUnicodeStringBody(b, u.Name)
	}
	b = appendU32(b, n) // CountReturned
	b = appendU32(b, 0) // STATUS_SUCCESS
	return b
}

// encodeSamrEnumUsersDenied is the anonymous-enumeration ACCESS_DENIED reply
// (null buffer + STATUS_ACCESS_DENIED) a hardened modern Windows returns to a
// null/guest SAMR EnumUsers.
func encodeSamrEnumUsersDenied() []byte {
	var b []byte
	b = appendU32(b, 0)          // EnumerationContext
	b = appendU32(b, 0)          // null Buffer ptr
	b = appendU32(b, 0)          // CountReturned
	b = appendU32(b, 0xC0000022) // STATUS_ACCESS_DENIED
	return b
}

// encodeSamrOpenUserStub returns the SamrOpenUser reply: a 20-byte UserHandle
// (tag 0x03) with the requested RID echoed at bytes [4:8] so the stateless
// QueryInformationUser2 can recover which account to describe, plus STATUS_SUCCESS.
func encodeSamrOpenUserStub(rid uint32) []byte {
	h := make([]byte, 20)
	h[0] = 0x03
	binary.LittleEndian.PutUint32(h[4:8], rid)
	return appendU32(h, 0)
}

// samrUserAllTemplateHex is a byte-exact SamrQueryInformationUser2 (level 21,
// UserAllInformation) response stub generated by impacket v0.11.0 — so impacket-
// based clients (samrdump) parse it verbatim. Detail strings are empty,
// PrimaryGroupId=513, UserAccountControl=0x210 (NORMAL_ACCOUNT |
// DONT_EXPIRE_PASSWORD). samrdump prints the account NAME from the EnumUsers
// reply, not this struct; only the RID (UserId) must match, so it is patched per
// user at samrUserIDOffset. Regenerate via impacket getData() if the structure
// ever needs richer detail (see MEMORY Item 2).
const (
	samrUserAllTemplateHex = "342c00001500bdbd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c8e5000000000000e9fa000000000000c498000000000000d32b000000000000655000000000000039f70000000000008974000000000000f01d0000000000004e55000000000000007b0000000000000bf600000000000030d900000000000022fe000000000000d3560000ddccbbaa01020000100200000000000000000000dfe700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	samrUserIDOffset       = 168
)

// encodeSamrQueryUserAllStub returns the level-21 user-detail reply with the RID
// patched in, so the per-user query in a SAMR enumeration walk succeeds.
func encodeSamrQueryUserAllStub(rid uint32) []byte {
	b, err := hex.DecodeString(samrUserAllTemplateHex)
	if err != nil || len(b) < samrUserIDOffset+4 {
		return appendU32(nil, 0xC0000022) // defensive: should never happen (const)
	}
	binary.LittleEndian.PutUint32(b[samrUserIDOffset:samrUserIDOffset+4], rid)
	return b
}

// SamrQueryInformationDomain response templates — byte-exact stubs generated by
// impacket v0.11.0 getData() (so impacket/nmap parse them verbatim), one per
// DomainInformationClass nmap smb-enum-domains queries. Values are plausible
// modern-Windows-client defaults: password complexity ON / min length 7 (class
// 1), account-lockout threshold 10 (class 12). Times (max/min age, lockout
// window) are zero = "not set/never", a valid and common standalone default.
const (
	samrDomainPasswordInfoHex = "755600000100bdbd07000000010000000000000000000000000000000000000000000000" // class 1
	samrDomainLockoutInfoHex  = "4ace00000c00bdbd000000000000000000000000000000000a00bfbf00000000"         // class 12
	samrDomainModifiedInfoHex = "01fc00000800bdbd0000000000000000000000000000000000000000"                 // class 8
)

// encodeSamrQueryDomainInfo returns the domain-policy reply for the requested
// DomainInformationClass. Unsupported classes get STATUS_INVALID_INFO_CLASS
// (null buffer) — what a real SAM returns for a class it doesn't surface.
func encodeSamrQueryDomainInfo(class uint16) []byte {
	var h string
	switch class {
	case 1: // DomainPasswordInformation
		h = samrDomainPasswordInfoHex
	case 8: // DomainModifiedInformation
		h = samrDomainModifiedInfoHex
	case 12: // DomainLockoutInformation
		h = samrDomainLockoutInfoHex
	default:
		return appendU32(appendU32(nil, 0), 0xC0000003) // null Buffer + STATUS_INVALID_INFO_CLASS
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return appendU32(appendU32(nil, 0), 0xC0000003)
	}
	return b
}

func encodeSamrCloseStub() []byte {
	var b []byte
	b = appendSamprHandle(b, 0x01)
	b = appendU32(b, 0)
	return b
}