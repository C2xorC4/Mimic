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

func TestCraftProbeRSTLinuxT4(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[20:22], 1234)
	binary.BigEndian.PutUint16(pkt[22:24], 80)
	binary.BigEndian.PutUint32(pkt[24:28], 2000)
	pkt[33] = 0x10 // ACK (T4)

	opts, ok := linuxProbeRSTOpts(pkt[33], 64, 0, true)
	if !ok {
		t.Fatal("linuxProbeRSTOpts T4")
	}
	n, ok := craftProbeRST(pkt, opts)
	if !ok || n != 40 {
		t.Fatalf("craftProbeRST failed ok=%v n=%d", ok, n)
	}
	pkt = pkt[:n]
	if pkt[33] != 0x04 {
		t.Fatalf("flags want RST only got 0x%x", pkt[33])
	}
	if binary.BigEndian.Uint32(pkt[28:32]) != 0 {
		t.Fatalf("ack want 0 got %d", binary.BigEndian.Uint32(pkt[28:32]))
	}
}