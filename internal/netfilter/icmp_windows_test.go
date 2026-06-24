//go:build windows

package netfilter

import (
	"encoding/binary"
	"testing"
)

// nmap's U1 probe is a 328-byte IP datagram (20 IP + 8 UDP + 300-byte 0x43
// payload). A real Linux port-unreachable quotes it VERBATIM and in FULL, so the
// response IP total length is 20+8+328 = 356 = 0x164 — nmap's Linux `IPL=164`
// signature — and the quoted header is byte-identical to the probe (giving nmap
// RIPL/RID/RIPCK/RUCK/RUD all = G).
func TestCraftPortUnreachableQuotesVerbatim(t *testing.T) {
	orig := make([]byte, 328)
	orig[0] = 0x45
	binary.BigEndian.PutUint16(orig[2:4], 328)
	orig[8] = 50
	orig[9] = 17 // UDP
	binary.BigEndian.PutUint16(orig[10:12], 0xABCD) // quoted IP checksum we must preserve
	orig[20] = 0
	orig[21] = 53
	orig[22] = 0
	orig[23] = 1
	for i := 28; i < 328; i++ {
		orig[i] = 0x43
	}

	pkt, ok := craftPortUnreachable(orig, 64, 64, 64, true)
	if !ok {
		t.Fatal("craftPortUnreachable failed")
	}
	if got := binary.BigEndian.Uint16(pkt[2:4]); got != 356 {
		t.Fatalf("response IP total length = %d (0x%x), want 356 (0x164)", got, got)
	}
	if pkt[9] != 1 {
		t.Fatalf("expected ICMP protocol, got %d", pkt[9])
	}
	if pkt[20] != 3 || pkt[21] != 3 {
		t.Fatalf("expected type3/code3, got %d/%d", pkt[20], pkt[21])
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x4000 != 0 {
		t.Fatal("outer DF must be clear (Linux U1 DFI=N)")
	}
	quoted := pkt[28:]
	if binary.BigEndian.Uint16(quoted[2:4]) != 328 {
		t.Fatalf("quoted IP length = %d, want 328 (verbatim, not capped)", binary.BigEndian.Uint16(quoted[2:4]))
	}
	if binary.BigEndian.Uint16(quoted[10:12]) != 0xABCD {
		t.Fatal("quoted IP checksum must be preserved verbatim (RIPCK=G)")
	}
	for i := 28; i < 328; i++ {
		if quoted[i] != 0x43 {
			t.Fatalf("quoted payload byte %d = 0x%x, want 0x43 (verbatim)", i, quoted[i])
		}
	}
}

func TestIsNmapU1Payload(t *testing.T) {
	mk := func(payloadLen int, fill byte) []byte {
		p := make([]byte, 28+payloadLen)
		p[0] = 0x45
		p[9] = 17 // UDP
		for i := 28; i < len(p); i++ {
			p[i] = fill
		}
		return p
	}
	if !isNmapU1Payload(mk(300, 0x43)) {
		t.Fatal("300-byte 0x43 payload should be the U1 probe")
	}
	if isNmapU1Payload(mk(300, 0x00)) {
		t.Fatal("300-byte non-0x43 payload is not the U1 probe")
	}
	if isNmapU1Payload(mk(299, 0x43)) {
		t.Fatal("299-byte payload is not the U1 probe")
	}
}
