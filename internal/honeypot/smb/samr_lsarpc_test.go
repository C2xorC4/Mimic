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

	usersResp := ps.Transceive(buildDCERPCRequest(6, samrOpEnumerateUsersInDomain, nil), ctx)
	assertRPCSuccess(t, usersResp)
	usersStub := usersResp[24:]
	if binary.LittleEndian.Uint32(usersStub[0:4]) != 0 {
		t.Fatalf("EntriesRead = %d, want 0", binary.LittleEndian.Uint32(usersStub[0:4]))
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