package smb

import (
	"encoding/binary"
	"testing"
)

func TestEncodeNetSessEnumLevel10Empty(t *testing.T) {
	stub := encodeNetSessEnumLevel10Empty()
	if len(stub) < 32 {
		t.Fatalf("stub too short: %d bytes", len(stub))
	}
	if got := binary.LittleEndian.Uint32(stub[0:4]); got != 10 {
		t.Fatalf("level = %d, want 10", got)
	}
	if got := binary.LittleEndian.Uint32(stub[4:8]); got != 10 {
		t.Fatalf("discriminant = %d, want 10", got)
	}
	if got := binary.LittleEndian.Uint32(stub[8:12]); got == 0 {
		t.Fatal("expected non-null NetSessCtr10 referent")
	}
	if got := binary.LittleEndian.Uint32(stub[12:16]); got != 0 {
		t.Fatalf("EntriesRead = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(stub[28:32]); got != 0 {
		t.Fatalf("return code = %d, want ERROR_SUCCESS", got)
	}
}

func TestBuildNetPathCompareResp(t *testing.T) {
	const callID = 0x41414141
	const ctxID = 0
	resp := buildNetPathCompareResp(callID, ctxID)
	if len(resp) < 28 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	if resp[2] != dcerpcResponse {
		t.Fatalf("ptype = %d, want response", resp[2])
	}
	stub := resp[24:]
	if len(stub) < 4 {
		t.Fatal("missing stub")
	}
	if got := binary.LittleEndian.Uint32(stub[0:4]); got != werrInvalidName {
		t.Fatalf("return = %d, want ERROR_INVALID_NAME (%d)", got, werrInvalidName)
	}
}

func TestPipeStateNetSessEnumAndPathCompare(t *testing.T) {
	ps := newPipeState("srvsvc")
	ps.bound = true
	ps.ctxID = 0

	bind := buildDCERPCBind(1, opNetrNetSessEnum)
	ps.Write(bind, defaultShares())
	if ack := ps.Read(); len(ack) == 0 {
		t.Fatal("expected bind ack")
	}

	sessResp := ps.Transceive(buildDCERPCRequest(2, opNetrNetSessEnum, nil), defaultShares())
	if len(sessResp) < 28 {
		t.Fatalf("NetSessEnum response too short: %d bytes", len(sessResp))
	}
	sessStub := sessResp[24:]
	if binary.LittleEndian.Uint32(sessStub[len(sessStub)-4:]) != 0 {
		t.Fatalf("NetSessEnum return = %x, want 0", binary.LittleEndian.Uint32(sessStub[len(sessStub)-4:]))
	}

	pathResp := ps.Transceive(buildDCERPCRequest(3, opNetrPathCompare, nil), defaultShares())
	pathStub := pathResp[24:]
	if binary.LittleEndian.Uint32(pathStub[0:4]) != werrInvalidName {
		t.Fatalf("PathCompare return = %d, want %d", binary.LittleEndian.Uint32(pathStub[0:4]), werrInvalidName)
	}
}

func TestEncodeRAPNetServerEnum2NotBrowser(t *testing.T) {
	out := encodeRAPNetServerEnum2NotBrowser()
	if len(out) != 8 {
		t.Fatalf("len = %d, want 8", len(out))
	}
	if got := binary.LittleEndian.Uint16(out[0:2]); got != rapStatusNotBrowser {
		t.Fatalf("status = %d, want %d", got, rapStatusNotBrowser)
	}
}

func TestHandleRAPNetServerEnum2(t *testing.T) {
	// Minimal NetServerEnum2 RAP request (opnum only — handler keys off opnum).
	req := []byte{0x68, 0x00}
	out := handleRAPRequest(req)
	if binary.LittleEndian.Uint16(out[0:2]) != rapStatusNotBrowser {
		t.Fatalf("status = %d, want %d", binary.LittleEndian.Uint16(out[0:2]), rapStatusNotBrowser)
	}
}

func buildDCERPCBind(callID uint32, opnum uint16) []byte {
	_ = opnum
	pdu := make([]byte, 72)
	pdu[0], pdu[1], pdu[2], pdu[3] = 5, 0, dcerpcBind, 0x03
	binary.LittleEndian.PutUint32(pdu[12:16], callID)
	// p_context_elem at offset 24: ctx_id=0 at byte 28
	copy(pdu[32:48], srvsvcUUID[:])
	return pdu
}

func buildDCERPCRequest(callID uint32, opnum uint16, stub []byte) []byte {
	pdu := make([]byte, 24+len(stub))
	pdu[0], pdu[1], pdu[2], pdu[3] = 5, 0, dcerpcRequest, 0x03
	binary.LittleEndian.PutUint32(pdu[12:16], callID)
	binary.LittleEndian.PutUint32(pdu[16:20], uint32(len(stub)))
	binary.LittleEndian.PutUint16(pdu[22:24], opnum)
	copy(pdu[24:], stub)
	return pdu
}