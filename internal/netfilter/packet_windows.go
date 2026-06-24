//go:build windows

package netfilter

import "encoding/binary"

// probeRSTOpts controls synthetic RST fields for nmap T-series probe responses.
type probeRSTOpts struct {
	ttl     uint8
	window  uint16
	ackZero bool // true → ack=0 (Linux A=Z); false → ack=clientSeq+1
	rstOnly bool // true → RST without ACK (Linux T4/T6 F=R); false → RST|ACK
}

// craftTCPRST turns an inbound IPv4 TCP probe into an outbound RST+ACK in place.
// Used for closed-port SYN probes (ack echoes client seq+1).
func craftTCPRST(pkt []byte, ttl uint8) (int, bool) {
	return craftProbeRST(pkt, probeRSTOpts{ttl: ttl, window: 0, ackZero: false, rstOnly: false})
}

// craftProbeRST swaps endpoints and emits a trimmed RST (20-byte TCP header).
func craftProbeRST(pkt []byte, opts probeRSTOpts) (int, bool) {
	ttl := opts.ttl
	if ttl == 0 {
		ttl = 64
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	tcpOff := ihl
	if len(pkt) < tcpOff+20 {
		return 0, false
	}

	var tmp [4]byte
	copy(tmp[:], pkt[12:16])
	copy(pkt[12:16], pkt[16:20])
	copy(pkt[16:20], tmp[:])

	copy(tmp[:2], pkt[tcpOff:tcpOff+2])
	copy(pkt[tcpOff:tcpOff+2], pkt[tcpOff+2:tcpOff+4])
	copy(pkt[tcpOff+2:tcpOff+4], tmp[:2])

	clientSeq := binary.BigEndian.Uint32(pkt[tcpOff+4 : tcpOff+8])
	binary.BigEndian.PutUint32(pkt[tcpOff+4:tcpOff+8], 0)
	if opts.ackZero {
		binary.BigEndian.PutUint32(pkt[tcpOff+8:tcpOff+12], 0)
	} else {
		binary.BigEndian.PutUint32(pkt[tcpOff+8:tcpOff+12], clientSeq+1)
	}
	pkt[tcpOff+12] = 0x50 // data offset = 5 (20 bytes)
	if opts.rstOnly {
		pkt[tcpOff+13] = 0x04 // RST
	} else {
		pkt[tcpOff+13] = 0x14 // RST|ACK
	}
	binary.BigEndian.PutUint16(pkt[tcpOff+14:tcpOff+16], opts.window)

	totalLen := ihl + 20
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = ttl
	pkt[10], pkt[11] = 0, 0
	pkt[tcpOff+16], pkt[tcpOff+17] = 0, 0
	return totalLen, true
}

// linuxProbeRSTOpts maps inbound nmap T-probe flags to Linux 5.x RST shapes.
func linuxProbeRSTOpts(flags uint8, ttl uint8, window uint16, ackZero bool) (probeRSTOpts, bool) {
	const (
		fin = 0x01
		syn = 0x02
		rst = 0x04
		psh = 0x08
		ack = 0x10
		urg = 0x20
	)
	switch {
	case flags == ack:
		// T4: ACK only → RST, ack=0 (F=R A=Z)
		return probeRSTOpts{ttl: ttl, window: window, ackZero: true, rstOnly: true}, true
	case flags == syn|ack:
		// T6: SYN+ACK → RST, ack=0
		return probeRSTOpts{ttl: ttl, window: window, ackZero: true, rstOnly: true}, true
	case flags&fin == fin && flags&(syn|rst) == 0:
		// T7: FIN (+ACK/PSH/URG; stack may strip flags before WinDivert) → RST+ACK
		return probeRSTOpts{ttl: ttl, window: window, ackZero: false, rstOnly: false}, true
	default:
		return probeRSTOpts{}, false
	}
}