package services

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// windowsDynamicPortMin is the lower bound of the Windows RPC ephemeral port range.
const windowsDynamicPortMin = 49152

// ncacn_ip_tcp tower floor headers from MS-RPCE tower encoding (lhs_len, proto, rhs_len).
var (
	epmFloorTCP = []byte{0x01, 0x00, 0x07, 0x02, 0x00}
	epmFloorIP  = []byte{0x01, 0x00, 0x09, 0x04, 0x00}
)

// ExtractNcacnIPTCPPorts scans an EPM ept_lookup response for ncacn_ip_tcp tower
// bindings. Each binding is a TCP floor (port, big-endian) paired with a nearby IP
// floor (4-byte IPv4). When hostIP is non-nil, only bindings advertising that
// address are returned (post host_ip rewrite).
func ExtractNcacnIPTCPPorts(data []byte, hostIP []byte) []uint16 {
	seen := make(map[uint16]struct{})
	for i := 0; i+len(epmFloorTCP)+2 <= len(data); i++ {
		if !bytes.Equal(data[i:i+len(epmFloorTCP)], epmFloorTCP) {
			continue
		}
		portOff := i + len(epmFloorTCP)
		port := binary.BigEndian.Uint16(data[portOff:])
		if port < windowsDynamicPortMin {
			continue
		}
		ip := findEPMIPFloor(data, portOff+2)
		if ip == nil {
			continue
		}
		if hostIP != nil && !bytes.Equal(ip, hostIP) {
			continue
		}
		seen[port] = struct{}{}
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// findEPMIPFloor locates the first IP floor within a ncacn_ip_tcp tower tail.
func findEPMIPFloor(data []byte, from int) []byte {
	limit := from + 30
	if limit > len(data) {
		limit = len(data)
	}
	for j := from; j+len(epmFloorIP)+4 <= limit; j++ {
		if !bytes.Equal(data[j:j+len(epmFloorIP)], epmFloorIP) {
			continue
		}
		return data[j+len(epmFloorIP) : j+len(epmFloorIP)+4]
	}
	return nil
}