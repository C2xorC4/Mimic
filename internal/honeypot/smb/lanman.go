package smb

import (
	"encoding/binary"
	"strings"
)

// RAP (Remote Administration Protocol) opnums served over \PIPE\LANMAN.
const (
	rapOpNetServerEnum2 = uint16(0x0068) // nmap smb-mbenum
)

// rapStatusNotBrowser is Win32 ERROR_REQ_NOT_ACCEP (71) — realistic for Server 2022
// hosts that are not master/backup browsers. nmap smb-mbenum treats this as success.
const rapStatusNotBrowser = uint16(71)

// handleRAPRequest dispatches a LANMAN RAP request and returns the RAP output
// parameter block (not including SMB framing).
func handleRAPRequest(rap []byte) []byte {
	if len(rap) < 2 {
		return encodeRAPError(1) // invalid function
	}
	opnum := binary.LittleEndian.Uint16(rap[0:2])
	switch opnum {
	case rapOpNetServerEnum2:
		return encodeRAPNetServerEnum2NotBrowser()
	default:
		return encodeRAPError(1)
	}
}

// encodeRAPNetServerEnum2NotBrowser returns the 8-byte RAP parameter block for
// NetServerEnum2 when the host is not a browse master.
//
// Layout (all uint16 LE): status, convert, entry_count, available_entries.
func encodeRAPNetServerEnum2NotBrowser() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b[0:2], rapStatusNotBrowser)
	// convert, entry_count, available_entries remain 0
	return b
}

func encodeRAPError(status uint16) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b[0:2], status)
	return b
}

// skipLANMANPipePrefix skips the leading null-terminated pipe path and any
// padding to the next 4-byte boundary (nmap packs "<zI4" before RAP data).
func skipLANMANPipePrefix(data []byte) []byte {
	i := 0
	for i < len(data) && data[i] != 0 {
		i++
	}
	if i < len(data) {
		i++ // skip NUL
	}
	for i < len(data) && i%4 != 0 {
		i++
	}
	if i >= len(data) {
		return nil
	}
	return data[i:]
}

// isLANMANPipe reports whether path refers to the LANMAN named pipe.
func isLANMANPipe(path string) bool {
	s := strings.ToUpper(strings.ReplaceAll(path, "/", `\`))
	s = strings.TrimLeft(s, `\`)
	if strings.HasPrefix(s, `PIPE\`) {
		s = s[5:]
	}
	return s == "LANMAN"
}

// buildSMBv1TransactionLANMANResp builds a COM_TRANSACTION response for a
// LANMAN RAP call (setup word count = 0).
func buildSMBv1TransactionLANMANResp(tid, uid uint16, rapOut []byte) []byte {
	// DataOffset = SMBv1 hdr(32) + WordCount(1) + params(20) + ByteCount(2) = 55
	const txDataOffset = uint16(55)
	rp := make([]byte, 20)
	n := uint16(len(rapOut))
	binary.LittleEndian.PutUint16(rp[0:2], n)   // TotalParameterCount
	binary.LittleEndian.PutUint16(rp[2:4], 0)   // TotalDataCount
	binary.LittleEndian.PutUint16(rp[12:14], n) // ParameterCount
	binary.LittleEndian.PutUint16(rp[14:16], txDataOffset)
	// SetupCount=0, Reserved=0 at rp[18:20]

	return buildSMB1Response(0x25, 0, tid, uid, rp, rapOut)
}