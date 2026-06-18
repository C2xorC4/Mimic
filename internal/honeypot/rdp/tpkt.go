package rdp

import (
	"encoding/binary"
	"fmt"
	"io"
)

const tpktVersion = 3

// readTPKT reads one TPKT-framed PDU (RFC 1006). Returns the payload after the
// 4-byte TPKT header.
func readTPKT(r io.Reader) ([]byte, error) {
	payload, _, err := readCredSSPPDU(r)
	return payload, err
}

// readCredSSPPDU reads one CredSSP PDU over TLS. Real clients (mstsc) wrap
// TSRequest in TPKT; nmap rdp-ntlm-info sends raw ASN.1 DER with no TPKT.
func readCredSSPPDU(r io.Reader) (payload []byte, tpktWrapped bool, err error) {
	first := make([]byte, 1)
	if _, err := io.ReadFull(r, first); err != nil {
		return nil, false, err
	}
	if first[0] == tpktVersion {
		rest := make([]byte, 3)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, false, err
		}
		length := int(binary.BigEndian.Uint16(rest[1:3]))
		if length < 4 {
			return nil, false, fmt.Errorf("invalid TPKT length %d", length)
		}
		payload = make([]byte, length-4)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, false, err
		}
		return payload, true, nil
	}
	return readASN1PDU(r, first[0])
}

func readASN1PDU(r io.Reader, firstByte byte) ([]byte, bool, error) {
	lenHdr, contentLen, err := readASN1Length(r)
	if err != nil {
		return nil, false, err
	}
	body := make([]byte, contentLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, false, err
	}
	out := make([]byte, 0, 1+len(lenHdr)+contentLen)
	out = append(out, firstByte)
	out = append(out, lenHdr...)
	out = append(out, body...)
	return out, false, nil
}

func readASN1Length(r io.Reader) (header []byte, contentLen int, err error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, 0, err
	}
	if b[0] < 0x80 {
		return b[:], int(b[0]), nil
	}
	switch b[0] {
	case 0x81:
		var x [1]byte
		if _, err := io.ReadFull(r, x[:]); err != nil {
			return nil, 0, err
		}
		return append(b[:], x[0]), int(x[0]), nil
	case 0x82:
		var x [2]byte
		if _, err := io.ReadFull(r, x[:]); err != nil {
			return nil, 0, err
		}
		return append(append(b[:], x[0]), x[1]), int(x[0])<<8 | int(x[1]), nil
	default:
		return nil, 0, fmt.Errorf("unsupported ASN.1 length 0x%02x", b[0])
	}
}

// writeCredSSPPDU writes a CredSSP response using the same framing as the request.
func writeCredSSPPDU(w io.Writer, payload []byte, tpktWrapped bool) error {
	if tpktWrapped {
		return writeTPKT(w, payload)
	}
	_, err := w.Write(payload)
	return err
}

// writeTPKT wraps payload in a TPKT header and writes it to w.
func writeTPKT(w io.Writer, payload []byte) error {
	length := len(payload) + 4
	if length > 0xffff {
		return fmt.Errorf("TPKT payload too large (%d)", len(payload))
	}
	hdr := []byte{tpktVersion, 0, byte(length >> 8), byte(length)}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}