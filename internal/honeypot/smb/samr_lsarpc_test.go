package smb

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestPipeStateSamrConnectAndEnumerateDomains(t *testing.T) {
	ps := newPipeState("samr")
	ps.bound = true
	ps.ctxID = 0
	ctx := testPipeContext()

	bind := buildDCERPCBind(1, samrOpConnect)
	ps.Write(bind, ctx)
	if ack := ps.Read(); len(ack) == 0 || ack[2] != dcerpcBindAck {
		t.Fatal("expected bind ack")
	}

	connectResp := ps.Transceive(buildDCERPCRequest(2, samrOpConnect, nil), ctx)
	assertRPCSuccess(t, connectResp)
	if len(connectResp[24:]) < 24 {
		t.Fatalf("connect stub too short: %d", len(connectResp[24:]))
	}

	enumResp := ps.Transceive(buildDCERPCRequest(3, samrOpEnumerateDomains, nil), ctx)
	assertRPCSuccess(t, enumResp)
	stub := enumResp[24:]
	if !bytes.Contains(stub, utf16LEBytes("TESTBOX")) {
		t.Fatalf("expected computer name in enum stub, got %x", stub)
	}
	if binary.LittleEndian.Uint32(stub[len(stub)-4:]) != 0 {
		t.Fatalf("NTSTATUS = %x, want 0", binary.LittleEndian.Uint32(stub[len(stub)-4:]))
	}

	// SamrLookupDomainInSamServer (opnum 5): a real client (impacket-samrdump,
	// nmap smb-enum-*) resolves the domain SID here before OpenDomain. Must return
	// a parseable SID + NTSTATUS=0, not STATUS_NOT_SUPPORTED (which breaks the
	// enum chain with a client-side unpack error — a fake-server tell).
	lookupResp := ps.Transceive(buildDCERPCRequest(4, samrOpLookupDomain, nil), ctx)
	assertRPCSuccess(t, lookupResp)
	lookupStub := lookupResp[24:]
	if binary.LittleEndian.Uint32(lookupStub[len(lookupStub)-4:]) != 0 {
		t.Fatalf("LookupDomain NTSTATUS = %x, want 0", binary.LittleEndian.Uint32(lookupStub[len(lookupStub)-4:]))
	}
	if !bytes.Contains(lookupStub, workstationSIDBody) {
		t.Fatalf("LookupDomain should return the domain SID body, got %x", lookupStub)
	}

	openResp := ps.Transceive(buildDCERPCRequest(5, samrOpOpenDomain, nil), ctx)
	assertRPCSuccess(t, openResp)

	// Authenticated session: EnumUsers returns the bait list (built-ins + svc_backup).
	usersResp := ps.Transceive(buildDCERPCRequest(6, samrOpEnumerateUsersInDomain, nil), ctx)
	assertRPCSuccess(t, usersResp)
	usersStub := usersResp[24:]
	// Layout: EnumerationContext[0:4], Buffer referent[4:8], EntriesRead[8:12].
	if got := binary.LittleEndian.Uint32(usersStub[8:12]); got == 0 {
		t.Fatalf("authenticated EnumUsers EntriesRead = 0, want >0 (bait users)")
	}
	if binary.LittleEndian.Uint32(usersStub[len(usersStub)-4:]) != 0 {
		t.Fatalf("EnumUsers NTSTATUS = %x, want 0", binary.LittleEndian.Uint32(usersStub[len(usersStub)-4:]))
	}
	for _, want := range []string{"Administrator", "svc_backup"} {
		if !bytes.Contains(usersStub, utf16LEBytes(want)) {
			t.Fatalf("EnumUsers should list %q, got %x", want, usersStub)
		}
	}

	// Per-user walk: OpenUser(RID=500) → QueryInformationUser2(level 21). The
	// UserHandle echoes the RID at [4:8]; QueryInfoUser2 must return a parseable
	// level-21 stub with that RID so samrdump prints the account.
	openUserStub := make([]byte, 28) // DomainHandle(20)+DesiredAccess(4)+RID(4)
	binary.LittleEndian.PutUint32(openUserStub[24:28], 500)
	ouResp := ps.Transceive(buildDCERPCRequest(7, samrOpOpenUser, openUserStub), ctx)
	assertRPCSuccess(t, ouResp)
	handle := ouResp[24:]
	if binary.LittleEndian.Uint32(handle[4:8]) != 500 {
		t.Fatalf("OpenUser handle should echo RID 500, got %x", handle[:20])
	}
	// QueryInformationUser2 input: UserHandle(20) + InfoClass(2). Echo the handle.
	qReq := append(append([]byte{}, handle[:20]...), 0x15, 0x00)
	qResp := ps.Transceive(buildDCERPCRequest(8, samrOpQueryInformationUser2, qReq), ctx)
	assertRPCSuccess(t, qResp)
	qStub := qResp[24:]
	if binary.LittleEndian.Uint32(qStub[len(qStub)-4:]) != 0 {
		t.Fatalf("QueryInfoUser2 ErrorCode = %x, want 0", binary.LittleEndian.Uint32(qStub[len(qStub)-4:]))
	}
	if binary.LittleEndian.Uint32(qStub[samrUserIDOffset:samrUserIDOffset+4]) != 500 {
		t.Fatalf("QueryInfoUser2 UserId not patched to 500")
	}
}

// TestPipeStateSamrQueryInformationDomain verifies the domain-policy replies
// (password class 1, lockout class 12, modified class 8) parse with NTSTATUS=0
// and carry the expected policy scalars.
func TestPipeStateSamrQueryInformationDomain(t *testing.T) {
	ps := newPipeState("samr")
	ps.bound = true
	ps.ctxID = 0
	ctx := testPipeContext()

	query := func(class uint16) []byte {
		stub := make([]byte, 22) // DomainHandle(20) + class(2)
		binary.LittleEndian.PutUint16(stub[20:22], class)
		resp := ps.Transceive(buildDCERPCRequest(2, samrOpQueryInformationDomain, stub), ctx)
		assertRPCSuccess(t, resp)
		return resp[24:]
	}

	for _, class := range []uint16{1, 12, 8} {
		s := query(class)
		if binary.LittleEndian.Uint32(s[len(s)-4:]) != 0 {
			t.Fatalf("class %d ErrorCode = %x, want 0", class, binary.LittleEndian.Uint32(s[len(s)-4:]))
		}
	}
	// Class 1 (password): MinPasswordLength=7 at offset 8 (referent[0:4]+tag[4:6]+pad[6:8]).
	if pw := query(1); binary.LittleEndian.Uint16(pw[8:10]) != 7 {
		t.Fatalf("password MinPasswordLength = %d, want 7", binary.LittleEndian.Uint16(pw[8:10]))
	}
	// Unsupported class → STATUS_INVALID_INFO_CLASS.
	if s := query(2); binary.LittleEndian.Uint32(s[len(s)-4:]) != 0xC0000003 {
		t.Fatalf("class 2 status = %x, want INVALID_INFO_CLASS", binary.LittleEndian.Uint32(s[len(s)-4:]))
	}
}

// TestPipeStateSamrEnumUsersAnonDenied verifies that an unauthenticated
// (guest/null) session is denied SAM user enumeration (RestrictAnonymousSAM),
// matching a hardened modern Windows rather than leaking the user list.
func TestPipeStateSamrEnumUsersAnonDenied(t *testing.T) {
	ps := newPipeState("samr")
	ps.bound = true
	ps.ctxID = 0
	anon := testPipeContextAnon()

	resp := ps.Transceive(buildDCERPCRequest(2, samrOpEnumerateUsersInDomain, nil), anon)
	assertRPCSuccess(t, resp)
	stub := resp[24:]
	if status := binary.LittleEndian.Uint32(stub[len(stub)-4:]); status != 0xC0000022 {
		t.Fatalf("anon EnumUsers NTSTATUS = %#x, want STATUS_ACCESS_DENIED (0xC0000022)", status)
	}
}

func TestPipeStateLsarpcPolicyQuery(t *testing.T) {
	ps := newPipeState("lsarpc")
	ps.bound = true
	ps.ctxID = 0
	ctx := testPipeContext()

	ps.Write(buildDCERPCBind(1, lsarOpOpenPolicy), ctx)
	if ack := ps.Read(); len(ack) == 0 {
		t.Fatal("expected bind ack")
	}

	openResp := ps.Transceive(buildDCERPCRequest(2, lsarOpOpenPolicy, nil), ctx)
	assertRPCSuccess(t, openResp)

	for _, tc := range []struct {
		callID   uint32
		infoClass uint32
	}{
		{3, policyPrimaryDomainInformation},
		{4, policyAccountDomainInformation},
		{5, policyDnsDomainInformation},
	} {
		reqStub := make([]byte, 20) // policy handle placeholder
		reqStub = appendU32(reqStub, tc.infoClass)
		resp := ps.Transceive(buildDCERPCRequest(tc.callID, lsarOpQueryInformationPolicy, reqStub), ctx)
		assertRPCSuccess(t, resp)
		stub := resp[24:]
		if !bytes.Contains(stub, utf16LEBytes("TESTBOX")) {
			t.Fatalf("info class %d: expected TESTBOX in stub, got %x", tc.infoClass, stub)
		}
	}
}

func assertRPCSuccess(t *testing.T, resp []byte) {
	t.Helper()
	if len(resp) < 28 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	if resp[2] != dcerpcResponse {
		t.Fatalf("ptype = %d, want response", resp[2])
	}
}

func utf16LEBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, c := range u {
		out[i*2] = byte(c)
		out[i*2+1] = byte(c >> 8)
	}
	return out
}