package smb

import (
	"encoding/binary"
	"strings"
)

// DCE/RPC packet type constants (connection-oriented, MS-RPCE 2.2.2.3).
const (
	dcerpcRequest  = byte(0)
	dcerpcResponse = byte(2)
	dcerpcBind     = byte(11)
	dcerpcBindAck  = byte(12)
)

// SRVSVC interface: {4b324fc8-1670-01d3-1278-5a47bf6ee188} v3.0
// Bytes in wire order (mixed-endian GUID: first three fields are LE, last two are BE).
var srvsvcUUID = [16]byte{
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
}

// NDR transfer syntax: {8a885d04-1ceb-11c9-9fe8-08002b104860} v2.0
var ndrTransferSyntaxUUID = [16]byte{
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
}

// SRVSVC opnums handled by this implementation.
// MS-SRVS opnum 15 = NetrShareEnum; some tools historically send opnum 7 (older spec).
// MS-SRVS opnum 16 = NetrShareGetInfo (not 8 — that is a legacy/wrong value).
const (
	opNetrShareEnum     = uint16(15)
	opNetrShareEnumAlt  = uint16(7)
	opNetrShareGetInfo  = uint16(16)
	opNetrServerGetInfo = uint16(13)
	opNetrNetSessEnum   = uint16(12) // 0x0C — nmap smb-enum-sessions
	opNetrPathCompare   = uint16(32) // 0x20 — nmap smb-vuln-ms08-067
)

// werrInvalidName is Win32 ERROR_INVALID_NAME (123) — patched MS08-067 response.
const werrInvalidName = uint32(123)

// PipeState tracks the DCE/RPC state for a single named-pipe handle.
type PipeState struct {
	name     string // canonical pipe name, e.g. "srvsvc"
	bound    bool
	ctxID    uint16
	pending  []byte // response queued for next SMB2_READ
	reasmHdr []byte // first fragment's 24-byte header of an in-progress request
	reasm    []byte // accumulated stub bytes of a fragmented request (FIRST seen, LAST pending)
}

// DCE/RPC PFC (fragment) flags in the PDU header at byte offset 3.
const (
	pfcFirstFrag = 0x01
	pfcLastFrag  = 0x02
)

func newPipeState(name string) *PipeState {
	return &PipeState{name: name}
}

// Write processes an incoming DCE/RPC PDU and queues a response for the next Read.
func (p *PipeState) Write(data []byte, ctx PipeContext) {
	if len(data) < 16 {
		return
	}
	ptype := data[2]
	callID := binary.LittleEndian.Uint32(data[12:16])

	switch ptype {
	case dcerpcBind:
		p.pending = p.buildBindAck(data, callID)
	case dcerpcRequest:
		if !p.bound {
			return
		}
		flags := data[3]
		// Fast path: a single, complete request PDU (FIRST+LAST, no reassembly active).
		if flags&pfcFirstFrag != 0 && flags&pfcLastFrag != 0 && p.reasm == nil {
			p.pending = p.handleRequest(data, callID, ctx)
			return
		}
		// Fragmented request: buffer stub bytes (data[24:]) until PFC_LAST_FRAG. A large
		// request (e.g. lookupsid's RID-cycling LookupSids, ~18KB) is split into
		// max-xmit-frag-sized PDUs; processing only one fragment mis-aligns the reply.
		if len(data) < 24 {
			return
		}
		if flags&pfcFirstFrag != 0 {
			p.reasmHdr = append([]byte(nil), data[:24]...) // keep first frag's opnum/header
			p.reasm = append([]byte(nil), data[24:]...)
		} else if p.reasm != nil {
			p.reasm = append(p.reasm, data[24:]...)
		}
		if flags&pfcLastFrag != 0 && p.reasm != nil {
			full := append(append([]byte(nil), p.reasmHdr...), p.reasm...)
			p.pending = p.handleRequest(full, callID, ctx)
			p.reasm, p.reasmHdr = nil, nil
		} else {
			p.pending = nil // no reply until the final fragment arrives
		}
	}
}

// Read returns and clears any queued response.
func (p *PipeState) Read() []byte {
	resp := p.pending
	p.pending = nil
	return resp
}

// Transceive is the combined write+read for FSCTL_PIPE_TRANSCEIVE.
func (p *PipeState) Transceive(data []byte, ctx PipeContext) []byte {
	p.Write(data, ctx)
	return p.Read()
}

// buildBindAck builds a DCE/RPC Bind_Ack PDU accepting the first context item.
//
// Bind_Ack layout (from header offset 0):
//   [0:16]  header: vers(1) vers_minor(1) PTYPE(1) flags(1) drep(4) frag_len(2) auth_len(2) call_id(4)
//   [16:18] max_xmit_frag
//   [18:20] max_recv_frag
//   [20:24] assoc_group_id
//   [24:26] sec_addr.length (includes null)
//   [26:26+len] sec_addr.port_spec (null-terminated)
//   [pad]   to next 4-byte boundary from start of PDU
//   [+0:2]  n_results
//   [+2:4]  reserved
//   [+4:6]  result (0=acceptance)
//   [+6:8]  reason (0)
//   [+8:24] transfer_syntax UUID
//   [+24:28] transfer_syntax version
func (p *PipeState) buildBindAck(data []byte, callID uint32) []byte {
	if len(data) >= 30 {
		p.ctxID = binary.LittleEndian.Uint16(data[28:30])
	}
	p.bound = true

	pipePath := `\PIPE\` + p.name + "\x00"
	secLen := uint16(len(pipePath))

	// Padding after sec_addr to align p_result_list to 4 bytes from packet start.
	// sec_addr ends at byte 26 + secLen.
	afterSec := uint16(26) + secLen
	pad := (4 - afterSec%4) % 4

	// Total: 16 header + 8 (max_xmit+max_recv+assoc) + 2+secLen+pad + 4 (n_results+rsvd) + 24 (p_result)
	fragLen := uint16(54) + secLen + pad

	b := make([]byte, 0, fragLen)
	b = append(b, 5, 0, dcerpcBindAck, 0x03)      // ver 5.0, BindAck, FirstFrag|LastFrag
	b = append(b, 0x10, 0x00, 0x00, 0x00)           // packed_drep: LE ASCII IEEE
	b = appendU16(b, fragLen)
	b = appendU16(b, 0)        // auth_length
	b = appendU32(b, callID)
	b = appendU16(b, 4280)     // max_xmit_frag
	b = appendU16(b, 4280)     // max_recv_frag
	b = appendU32(b, 0x53F0)   // assoc_group_id (arbitrary non-zero)
	b = appendU16(b, secLen)
	b = append(b, []byte(pipePath)...)
	for i := uint16(0); i < pad; i++ {
		b = append(b, 0)
	}
	// p_result_list: 1 result
	b = appendU16(b, 1) // n_results
	b = appendU16(b, 0) // reserved
	b = appendU16(b, 0) // result: acceptance
	b = appendU16(b, 0) // reason: 0
	b = append(b, ndrTransferSyntaxUUID[:]...)
	b = appendU32(b, 2) // NDR transfer syntax version 2.0
	return b
}

func (p *PipeState) handleRequest(data []byte, callID uint32, ctx PipeContext) []byte {
	if len(data) < 24 {
		return nil
	}
	switch p.name {
	case "samr":
		return p.handleSamrRequest(data, callID, ctx.Env)
	case "lsarpc":
		return p.handleLsarpcRequest(data, callID, ctx.Env)
	}

	opnum := binary.LittleEndian.Uint16(data[22:24])
	shares := ctx.Shares

	switch opnum {
	case opNetrShareEnum, opNetrShareEnumAlt:
		reqLevel := uint32(0)
		if len(data) > 24 {
			reqLevel = parseNetShareEnumLevel(data[24:])
		}
		return buildNetShareEnumAllResp(shares, reqLevel, callID, p.ctxID)
	case opNetrShareGetInfo:
		var stub []byte
		if len(data) > 24 {
			shareName, _ := parseNetShareGetInfoStub(data[24:])
			sh := lookupShareInfo(shareName, shares)
			return buildNetrShareGetInfoResp(sh, callID, p.ctxID)
		}
		// Malformed request: return NERR_NetNameNotFound
		stub = appendU32(nil, 0)
		stub = appendU32(stub, 0)
		stub = appendU32(stub, 2310)
		return buildDCERPCResponse(callID, p.ctxID, stub)
	case opNetrServerGetInfo:
		// Return access denied
		stub := appendU32(nil, 0) // null pointer
		stub = appendU32(stub, 0) // discriminant
		stub = appendU32(stub, 5) // ERROR_ACCESS_DENIED
		return buildDCERPCResponse(callID, p.ctxID, stub)
	case opNetrNetSessEnum:
		return buildNetSessEnumResp(callID, p.ctxID)
	case opNetrPathCompare:
		return buildNetPathCompareResp(callID, p.ctxID)
	default:
		// Unknown opnum: return ERROR_INVALID_FUNCTION (1)
		return buildDCERPCResponse(callID, p.ctxID, appendU32(nil, 1))
	}
}

// canonicalizePipeName extracts the base pipe name from paths like
// \srvsvc, \PIPE\srvsvc, srvsvc (case-insensitive).
func canonicalizePipeName(path string) string {
	s := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	s = strings.TrimLeft(s, `\`)
	if strings.HasPrefix(s, `pipe\`) {
		s = s[5:]
	}
	s = strings.TrimLeft(s, `\`)
	return s
}
