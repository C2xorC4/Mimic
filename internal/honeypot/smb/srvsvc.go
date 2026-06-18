package smb

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"

	"github.com/c2xorc4/mimic/internal/deception"
)

// Share type flags (MS-SRVS 2.2.2.4)
const (
	ShareTypeDisk    = uint32(0x00000000)
	ShareTypeIPC     = uint32(0x00000003)
	ShareTypeSpecial = uint32(0x80000000) // hidden/administrative
)

// ShareInfo describes an SMB share to advertise.
type ShareInfo struct {
	Name   string
	Type   uint32
	Remark string
}

// sharesFromTreeConfig derives the SRVSVC share advertisement list from the
// config-driven filesystem, mapping each share's declared type onto the SMB share
// type flags. This keeps NetShareEnum, isKnownShare, and lookupShareInfo consistent
// with the VFS roots by construction.
func sharesFromTreeConfig(tc deception.TreeConfig) []ShareInfo {
	out := make([]ShareInfo, 0, len(tc.Shares))
	for _, sd := range tc.Shares {
		var typ uint32
		remark := sd.Remark
		switch strings.ToLower(sd.Type) {
		case "ipc":
			typ = ShareTypeIPC | ShareTypeSpecial
			if remark == "" {
				remark = "Remote IPC" // match a real Windows IPC$ remark
			}
		case "disk_special":
			typ = ShareTypeDisk | ShareTypeSpecial
		default: // "disk" or unset
			typ = ShareTypeDisk
		}
		out = append(out, ShareInfo{Name: sd.Name, Type: typ, Remark: remark})
	}
	return out
}

// defaultShares returns the standard Windows administrative shares.
func defaultShares() []ShareInfo {
	return []ShareInfo{
		{Name: "IPC$", Type: ShareTypeIPC | ShareTypeSpecial, Remark: "Remote IPC"},
		{Name: "ADMIN$", Type: ShareTypeDisk | ShareTypeSpecial, Remark: "Remote Admin"},
		{Name: "C$", Type: ShareTypeDisk | ShareTypeSpecial, Remark: "Default share"},
	}
}

// buildNetShareEnumAllResp encodes a NetrShareEnum response at the requested level.
//
// nmap requests level=0 (name-only); impacket/netexec requests level=1 (name+type+remark).
// We mirror the requested level so each caller gets a parseable response.
func buildNetShareEnumAllResp(shares []ShareInfo, reqLevel uint32, callID uint32, ctxID uint16) []byte {
	var stub []byte
	if reqLevel == 1 {
		stub = encodeNetShareEnumLevel1(shares)
	} else {
		stub = encodeNetShareEnumLevel0(shares)
	}
	return buildDCERPCResponse(callID, ctxID, stub)
}

// parseNetShareEnumLevel extracts the requested level from a NetrShareEnum request stub.
// The stub layout matches impacket/nmap: ptr_server(4) [+ inline server string] Level(4) ...
func parseNetShareEnumLevel(stub []byte) uint32 {
	if len(stub) < 4 {
		return 0
	}
	ptrServer := binary.LittleEndian.Uint32(stub[0:4])
	pos := 4
	if ptrServer != 0 {
		pos = skipNDRWString(stub, pos)
		if pos < 0 {
			return 0
		}
	}
	if pos+4 <= len(stub) {
		return binary.LittleEndian.Uint32(stub[pos : pos+4])
	}
	return 0
}

// encodeNetShareEnumLevel1 builds the NDR stub for a NetrShareEnum Level-1 response.
//
// impacket uses standard NDR deferred referents (all fixed struct fields first,
// strings deferred after all elements). Wire layout:
//
//	Level(4)=1 + discriminant(4)=1 + ptr_container(4)
//	[container:] EntriesRead(4) + ptr_array(4)
//	[array:] max_count(4) + N×{ptr_name(4) type(4) ptr_remark(4)}
//	[deferred strings: name0 remark0 name1 remark1 ...]
//	TotalEntries(4) + ptr_resume(4)=0 + return_code(4)=0
func encodeNetShareEnumLevel1(shares []ShareInfo) []byte {
	var b []byte
	ref := uint32(0x00020000)
	nextRef := func() uint32 { r := ref; ref += 4; return r }

	b = appendU32(b, 1)         // Level = 1
	b = appendU32(b, 1)         // union discriminant = 1
	b = appendU32(b, nextRef()) // ptr to SHARE_INFO_1_CONTAINER

	// SHARE_INFO_1_CONTAINER: EntriesRead + ptr to array
	b = appendU32(b, uint32(len(shares)))
	b = appendU32(b, nextRef())

	// Conformant array: max_count + N × SHARE_INFO_1 fixed fields
	b = appendU32(b, uint32(len(shares)))
	nameRefs := make([]uint32, len(shares))
	remarkRefs := make([]uint32, len(shares))
	for i, sh := range shares {
		nameRefs[i] = nextRef()
		b = appendU32(b, nameRefs[i]) // ptr_name (non-null)
		b = appendU32(b, sh.Type)     // type (inline DWORD)
		if sh.Remark != "" {
			remarkRefs[i] = nextRef()
		}
		b = appendU32(b, remarkRefs[i]) // ptr_remark
	}

	// Deferred strings for all elements in order
	for i, sh := range shares {
		if nameRefs[i] != 0 {
			b = appendNDRWString(b, sh.Name)
		}
		if remarkRefs[i] != 0 {
			b = appendNDRWString(b, sh.Remark)
		}
	}

	b = appendU32(b, uint32(len(shares))) // TotalEntries
	b = appendU32(b, 0)                   // ResumeHandle ptr (null)
	b = appendU32(b, 0)                   // return code: ERROR_SUCCESS
	return b
}

// encodeNetShareEnumLevel0 builds the NDR stub for a NetrShareEnum Level-0 response.
//
// Level-0 (SHARE_INFO_0): name-only — compatible with nmap's msrpctypes.lua parser.
//
// Wire layout (all values little-endian):
//
//	Level(4)=0 + discriminant(4)=0 + ptr_container(4)
//	[container:] count(4) + ptr_array(4)
//	[array:] max_count(4) + N×{ptr_name(4)}
//	[deferred name strings]
//	TotalEntries(4) + ptr_resume(4)=0 + return_code(4)=0
func encodeNetShareEnumLevel0(shares []ShareInfo) []byte {
	var b []byte
	ref := uint32(0x00020000)
	nextRef := func() uint32 { r := ref; ref += 4; return r }

	b = appendU32(b, 0)         // Level = 0
	b = appendU32(b, 0)         // union discriminant = 0
	b = appendU32(b, nextRef()) // ptr to SHARE_INFO_0_CONTAINER

	// SHARE_INFO_0_CONTAINER: count + pointer to array
	b = appendU32(b, uint32(len(shares)))
	b = appendU32(b, nextRef())

	// Conformant array: max_count + one ptr_name per entry
	b = appendU32(b, uint32(len(shares)))
	nameRefs := make([]uint32, len(shares))
	for i := range shares {
		nameRefs[i] = nextRef()
		b = appendU32(b, nameRefs[i])
	}

	// Deferred name strings
	for _, sh := range shares {
		b = appendNDRWString(b, sh.Name)
	}

	b = appendU32(b, uint32(len(shares))) // TotalEntries
	b = appendU32(b, 0)                   // ResumeHandle ptr (null)
	b = appendU32(b, 0)                   // return code: ERROR_SUCCESS
	return b
}

// appendNDRWString appends a null-terminated NDR conformant-varying wide string.
// Format: MaxCount(4) + Offset(4)=0 + ActualCount(4) + chars + 4-byte padding.
func appendNDRWString(b []byte, s string) []byte {
	chars := utf16.Encode([]rune(s + "\x00")) // null terminator included in count
	count := uint32(len(chars))
	b = appendU32(b, count) // MaxCount
	b = appendU32(b, 0)     // Offset
	b = appendU32(b, count) // ActualCount
	for _, c := range chars {
		b = append(b, byte(c), byte(c>>8))
	}
	// pad data to 4-byte boundary
	dataBytes := int(count) * 2
	for pad := (4 - dataBytes%4) % 4; pad > 0; pad-- {
		b = append(b, 0)
	}
	return b
}

// buildDCERPCResponse wraps stub data in a DCE/RPC Response PDU (connection-oriented).
func buildDCERPCResponse(callID uint32, ctxID uint16, stub []byte) []byte {
	// header(16) + alloc_hint(4) + p_cont_id(2) + cancel_count+reserved(2) + stub
	fragLen := uint16(24 + len(stub))
	b := make([]byte, 0, fragLen)
	// Header: version 5.0, type=Response, flags=FirstFrag|LastFrag, little-endian
	b = append(b, 5, 0, dcerpcResponse, 0x03)
	b = append(b, 0x10, 0x00, 0x00, 0x00) // packed_drep: little-endian, ASCII, IEEE float
	b = appendU16(b, fragLen)
	b = appendU16(b, 0) // auth_length
	b = appendU32(b, callID)
	// Response body
	b = appendU32(b, uint32(len(stub))) // alloc_hint
	b = appendU16(b, ctxID)             // p_cont_id
	b = appendU16(b, 0)                 // cancel_count (1 byte) + reserved (1 byte) packed as uint16
	b = append(b, stub...)
	return b
}

// buildNetrShareGetInfoResp encodes a NetrShareGetInfo Level-1 response stub.
//
// nmap's msrpctypes.lua uses "inline" NDR — after each unique pointer the
// string data follows immediately rather than being deferred to the end.
// We match that convention so nmap can parse the name/type/remark fields.
func buildNetrShareGetInfoResp(sh ShareInfo, callID uint32, ctxID uint16) []byte {
	stub := encodeNetShareGetInfoLevel1(sh)
	return buildDCERPCResponse(callID, ctxID, stub)
}

// encodeNetShareGetInfoLevel1 builds the NDR stub for a NetrShareGetInfo level-1 response.
//
// nmap's unmarshall_srvsvc_NetShareInfo1 uses the standard NDR HEAD/BODY split:
//
//	HEAD: ptr_name(4) + sharetype(4) + ptr_comment(4)
//	BODY: deferred name string, then deferred comment string
//
// So strings are NOT inline after each pointer — they follow all HEAD fields.
//
// Wire layout:
//
//	Level(4)=1
//	outer_ptr(4)=1 (non-null, referent for SHARE_INFO_1)
//	ptr_name(4)=1  sharetype(4)  ptr_comment(4)=1|0
//	name_wstring   [comment_wstring if comment non-empty]
//	return_value(4)=0
func encodeNetShareGetInfoLevel1(sh ShareInfo) []byte {
	var b []byte
	b = appendU32(b, 1) // Level = 1
	b = appendU32(b, 1) // outer ptr to SHARE_INFO_1 (non-null)

	// HEAD: fixed struct fields
	b = appendU32(b, 1)       // ptr_name (non-null)
	b = appendU32(b, sh.Type) // sharetype (inline value, not a ptr)
	remarkRef := uint32(0)
	if sh.Remark != "" {
		remarkRef = 1
	}
	b = appendU32(b, remarkRef) // ptr_comment

	// BODY: deferred string data in order of appearance
	b = appendNDRWString(b, sh.Name)
	if sh.Remark != "" {
		b = appendNDRWString(b, sh.Remark)
	}

	b = appendU32(b, 0) // return_value = ERROR_SUCCESS
	return b
}

// parseNetShareGetInfoStub extracts the share name from a NetrShareGetInfo request stub.
//
// nmap encodes the request as:
//
//	marshall_unicode_ptr(server) → ptr(4) + MaxCount(4)+Offset(4)+ActualCount(4)+chars+pad
//	marshall_unicode(share)      → MaxCount(4)+Offset(4)+ActualCount(4)+chars+pad  (no ptr prefix)
//	marshall_int32(level)        → Level(4)
func parseNetShareGetInfoStub(stub []byte) (shareName string, level uint32) {
	if len(stub) < 4 {
		return "", 0
	}
	ptrServer := binary.LittleEndian.Uint32(stub[0:4])
	pos := 4
	// If server ptr non-null, skip the inline server name string that follows the pointer.
	if ptrServer != 0 {
		pos = skipNDRWString(stub, pos)
		if pos < 0 {
			return "", 0
		}
	}
	// NetName: no pointer prefix, just MaxCount+Offset+ActualCount+chars+pad
	name, newPos := readNDRWString(stub, pos)
	if newPos < 0 {
		return "", 0
	}
	pos = newPos
	if pos+4 <= len(stub) {
		level = binary.LittleEndian.Uint32(stub[pos : pos+4])
	}
	return name, level
}

// skipNDRWString advances pos past one NDR conformant-varying wide string.
func skipNDRWString(b []byte, pos int) int {
	if pos+12 > len(b) {
		return -1
	}
	actualCount := int(binary.LittleEndian.Uint32(b[pos+8 : pos+12]))
	pos += 12 + actualCount*2
	if (actualCount*2)%4 != 0 {
		pos += 4 - (actualCount*2)%4
	}
	return pos
}

// readNDRWString reads one NDR conformant-varying wide string and returns the string plus new pos.
func readNDRWString(b []byte, pos int) (string, int) {
	if pos+12 > len(b) {
		return "", -1
	}
	actualCount := int(binary.LittleEndian.Uint32(b[pos+8 : pos+12]))
	pos += 12
	if pos+actualCount*2 > len(b) {
		return "", -1
	}
	chars := make([]uint16, actualCount)
	for i := range chars {
		chars[i] = binary.LittleEndian.Uint16(b[pos+i*2 : pos+i*2+2])
	}
	pos += actualCount * 2
	if (actualCount*2)%4 != 0 {
		pos += 4 - (actualCount*2)%4
	}
	return strings.TrimRight(string(utf16.Decode(chars)), "\x00"), pos
}

// lookupShareInfo finds a ShareInfo by name; returns a sensible default if not found.
func lookupShareInfo(name string, shares []ShareInfo) ShareInfo {
	for _, sh := range shares {
		if strings.EqualFold(sh.Name, name) {
			return sh
		}
	}
	if strings.EqualFold(name, "IPC$") {
		return ShareInfo{Name: "IPC$", Type: ShareTypeIPC | ShareTypeSpecial, Remark: "Remote IPC"}
	}
	return ShareInfo{Name: name, Type: ShareTypeDisk, Remark: ""}
}

// buildNetSessEnumResp returns an empty NetrNetSessEnum level-10 result.
// nmap smb-enum-sessions calls opnum 0x0C anonymously on patched Windows hosts.
func buildNetSessEnumResp(callID uint32, ctxID uint16) []byte {
	return buildDCERPCResponse(callID, ctxID, encodeNetSessEnumLevel10Empty())
}

// encodeNetSessEnumLevel10Empty builds the NDR out-stub for NetrNetSessEnum with
// no active sessions (level 10, empty conformant array).
func encodeNetSessEnumLevel10Empty() []byte {
	var b []byte
	ref := uint32(0x00020000)
	// nmap unmarshall_srvsvc_NetSessCtr reads level once, then a single referent
	// for NetSessCtr10 — no separate union discriminant (unlike NetShareEnum).
	b = appendU32(b, 10)  // [in,out] level
	b = appendU32(b, ref) // ptr to NetSessCtr10
	b = appendU32(b, 0)   // EntriesRead / count
	b = appendU32(b, 0)   // null conformant array ptr
	b = appendU32(b, 0)   // TotalEntries
	b = appendU32(b, 0)   // ResumeHandle ptr (null)
	b = appendU32(b, 0)   // ERROR_SUCCESS
	return b
}

// buildNetPathCompareResp rejects the MS08-067 probe path with ERROR_INVALID_NAME
// so nmap reports PATCHED/NOT_VULN instead of VULNERABLE/LIKELY_VULN.
func buildNetPathCompareResp(callID uint32, ctxID uint16) []byte {
	stub := appendU32(nil, werrInvalidName)
	return buildDCERPCResponse(callID, ctxID, stub)
}

// --- NDR utility functions (used by pipe.go and srvsvc.go) ---

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
