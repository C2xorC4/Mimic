//go:build windows

package netfilter

import (
	"encoding/binary"
	"testing"
)

func TestCraftTCPRST(t *testing.T) {
	// Minimal IPv4 SYN: 20-byte IP + 20-byte TCP, client 10.0.0.1:1234 → server 10.0.0.2:9999
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = 6 // TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:22], 1234)
	binary.BigEndian.PutUint16(pkt[22:24], 9999)
	binary.BigEndian.PutUint32(pkt[24:28], 1000)
	pkt[32] = 0x02 // SYN

	n, ok := craftTCPRST(pkt, 64)
	if !ok || n != 40 {
		t.Fatalf("craftTCPRST failed ok=%v n=%d", ok, n)
	}
	pkt = pkt[:n]
	if pkt[12] != 10 || pkt[13] != 0 || pkt[14] != 0 || pkt[15] != 2 {
		t.Fatalf("dst/src swap wrong: %v", pkt[12:20])
	}
	if binary.BigEndian.Uint16(pkt[20:22]) != 9999 {
		t.Fatalf("sport want 9999 got %d", binary.BigEndian.Uint16(pkt[20:22]))
	}
	if pkt[32] != 0x50 {
		t.Fatalf("data offset want 5 got 0x%x", pkt[32]>>4)
	}
	if pkt[33]&0x14 != 0x14 {
		t.Fatalf("flags want RST|ACK got 0x%x", pkt[33])
	}
	if binary.BigEndian.Uint32(pkt[28:32]) != 1001 {
		t.Fatalf("ack want 1001 got %d", binary.BigEndian.Uint32(pkt[28:32]))
	}
}

func TestCraftProbeRSTLinuxT2(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:22], 1234)
	binary.BigEndian.PutUint16(pkt[22:24], 80)
	binary.BigEndian.PutUint32(pkt[24:28], 2000)
	// NULL flags (T2)

	n, ok := craftProbeRST(pkt, probeRSTOpts{ttl: 64, window: 0, ackZero: true})
	if !ok || n != 40 {
		t.Fatalf("craftProbeRST failed ok=%v n=%d", ok, n)
	}
	pkt = pkt[:n]
	if pkt[8] != 64 {
		t.Fatalf("ttl want 64 got %d", pkt[8])
	}
	if binary.BigEndian.Uint16(pkt[30:32]) != 0 {
		t.Fatalf("window want 0 got %d", binary.BigEndian.Uint16(pkt[30:32]))
	}
	if binary.BigEndian.Uint32(pkt[28:32]) != 0 {
		t.Fatalf("ack want 0 got %d", binary.BigEndian.Uint32(pkt[28:32]))
	}
	if pkt[33]&0x14 != 0x14 {
		t.Fatalf("flags want RST|ACK got 0x%x", pkt[33])
	}
}