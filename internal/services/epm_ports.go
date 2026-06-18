package services

import (
	"encoding/binary"
	"sort"
)

// windowsDynamicPortMin is the lower bound of the Windows RPC ephemeral port range.
const windowsDynamicPortMin = 49152

// ExtractNcacnIPTCPPorts scans an EPM ept_lookup response for ncacn_ip_tcp tower
// host floors. Windows encodes each as a 4-byte IPv4 immediately followed by a
// uint16 little-endian TCP port.
func ExtractNcacnIPTCPPorts(data []byte) []uint16 {
	seen := make(map[uint16]struct{})
	for i := 0; i+6 <= len(data); i++ {
		if !looksLikeTowerIPv4(data[i : i+4]) {
			continue
		}
		port := binary.LittleEndian.Uint16(data[i+4:])
		if port < windowsDynamicPortMin {
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

func looksLikeTowerIPv4(ip []byte) bool {
	if len(ip) != 4 {
		return false
	}
	// 0.0.0.0 and multicast are not used in ncacn_ip_tcp host floors.
	if ip[0] == 0 || ip[0] >= 224 {
		return false
	}
	// Loopback towers are not advertised in the captured Win11 EPM database.
	if ip[0] == 127 {
		return false
	}
	return true
}