package capture

import (
	"fmt"
	"strconv"
	"strings"
)

// classifySNMPProbe buckets an SNMP request by its primary OID.
// Returns ("", false) for deep ifTable walk steps beyond the scanner-relevant
// surface (mirrors the http-enum de-noise pattern).
func classifySNMPProbe(probe []byte) (name string, ok bool) {
	oids := extractSNMPRequestOIDs(probe)
	if len(oids) == 0 {
		return "", false
	}
	primary := oids[0]
	if !isScannerSNMPOID(primary) {
		return "", false
	}
	return snmpProbeName(primary), true
}

func snmpProbeName(oid string) string {
	safe := strings.NewReplacer(".", "_", "-", "_").Replace(oid)
	return "snmp_" + safe
}

// isScannerSNMPOID keeps the system MIB surface that nmap -sV / snmp-sysdescr
// exercise. Live proxmox capture: 236 exchanges collapse to 3 system OIDs
// (sysDescr, sysUpTime, sysName); the other 233 are snmp-interfaces ifTable
// GET-NEXT steps — valid for OID-keyed replay but enumeration noise for deception
// (same class as http-enum). Deep ifTable walk is deferred; use default_response
// or a future stateful handler if snmp-interfaces fidelity is required.
func isScannerSNMPOID(oid string) bool {
	return strings.HasPrefix(oid, "1.3.6.1.2.1.1.")
}

// extractSNMPRequestOIDs parses SNMPv1/v2c BER requests and returns OIDs from
// variable bindings. Best-effort — returns nil on malformed packets.
func extractSNMPRequestOIDs(pkt []byte) []string {
	// Message ::= SEQUENCE { version, community, PDU }
	msg, ok := berDecode(pkt)
	if !ok || msg.tag != 0x30 {
		return nil
	}
	if len(msg.children) < 3 {
		return nil
	}
	pdu := msg.children[2]
	// GET(0xa0) GETNEXT(0xa1) GETBULK(0xa5)
	switch pdu.tag {
	case 0xa0, 0xa1, 0xa5:
	default:
		return nil
	}
	if len(pdu.children) < 4 {
		return nil
	}
	varbinds := pdu.children[3]
	if varbinds.tag != 0x30 {
		return nil
	}
	oids := make([]string, 0, len(varbinds.children))
	for _, vb := range varbinds.children {
		if vb.tag != 0x30 || len(vb.children) == 0 {
			continue
		}
		oidNode := vb.children[0]
		if oidNode.tag != 0x06 {
			continue
		}
		if oid := decodeOID(oidNode.value); oid != "" {
			oids = append(oids, oid)
		}
	}
	return oids
}

type berNode struct {
	tag      byte
	value    []byte
	children []berNode
}

func berDecode(data []byte) (berNode, bool) {
	n, ok := berDecodeAt(data, 0)
	return n, ok
}

func berDecodeAt(data []byte, off int) (berNode, bool) {
	if off >= len(data) {
		return berNode{}, false
	}
	tag := data[off]
	off++
	if off >= len(data) {
		return berNode{}, false
	}
	length, loff, ok := berLength(data, off)
	if !ok {
		return berNode{}, false
	}
	off = loff
	if off+length > len(data) {
		return berNode{}, false
	}
	content := data[off : off+length]
	node := berNode{tag: tag}

	switch tag {
	case 0x30, 0xa0, 0xa1, 0xa5: // constructed
		cur := 0
		for cur < len(content) {
			child, ok := berDecodeAt(content, cur)
			if !ok {
				return berNode{}, false
			}
			node.children = append(node.children, child)
			clen, err := berEncodedLen(content[cur:])
			if err != nil || clen == 0 {
				return berNode{}, false
			}
			cur += clen
		}
	default:
		node.value = append([]byte(nil), content...)
	}
	return node, true
}

func berLength(data []byte, off int) (int, int, bool) {
	if off >= len(data) {
		return 0, off, false
	}
	b := data[off]
	off++
	if b&0x80 == 0 {
		return int(b), off, true
	}
	nbytes := int(b & 0x7f)
	if nbytes == 0 || off+nbytes > len(data) {
		return 0, off, false
	}
	length := 0
	for i := 0; i < nbytes; i++ {
		length = (length << 8) | int(data[off+i])
	}
	return length, off + nbytes, true
}

func berEncodedLen(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("empty")
	}
	off := 1
	length, loff, ok := berLength(data, off)
	if !ok {
		return 0, fmt.Errorf("bad length")
	}
	return (loff - 0) + length, nil
}

func decodeOID(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	parts := make([]string, 0, len(data)+1)
	first := int(data[0])
	parts = append(parts, strconv.Itoa(first/40), strconv.Itoa(first%40))
	for i := 1; i < len(data); {
		val := 0
		for {
			if i >= len(data) {
				return ""
			}
			b := data[i]
			i++
			val = (val << 7) | int(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
		parts = append(parts, strconv.Itoa(val))
	}
	return strings.Join(parts, ".")
}

func isSNMPServicePort(port uint16) bool {
	return port == 161 || port == 162
}