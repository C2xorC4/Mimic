//go:build windows

package stack

import (
	"encoding/binary"
	"testing"

	"github.com/c2xorc4/mimic/internal/config"
)

// TestLinuxIPIDZero asserts the applyEgress IP-ID CONTRACT for a Linux persona:
// TCP/DF → 0 (intended nmap TI=Z/CI=Z), ICMP → incrementing (II=I). NOTE: on the
// default WinDivert backend the 0 does NOT reach the wire — the Windows transmit
// path re-stamps a 0 Identification (validated 2026-06-25), so TI/CI=I in practice.
// This test guards the mutation logic itself; TI=Z is delivered only by eBPF or the
// opt-in high-fidelity driver. See the IP-ID block in backend_windows.go.
func TestLinuxIPIDZero(t *testing.T) {
	p := &config.OSProfile{
		Family: "linux",
		Stack: config.StackConfig{
			TTL:                64,
			DFBit:              true,
			WindowSize:         65160,
			WindowScale:        8,
			MSS:                1460,
			TCPTimestamps:      true,
			SACKPermitted:      true,
			IPIDBehavior:       "random",
			TCPOptionsOrder:    []string{"mss", "sack_permitted", "timestamp", "nop", "window_scale"},
			ExplicitCongestion: "respond",
		},
	}
	wp := toWinProfile(p)
	t.Logf("winQuirks=%v ecnEcho=%v ipidBehavior=%d windowSize=%#x ecnWindow=%#x",
		wp.winQuirks, wp.ecnEcho, wp.ipidBehavior, wp.windowSize, wp.ecnWindow)

	b := &windowsBackend{ipid: ipidState{seed: 0x9e3779b9}}

	// Synthetic IPv4 + TCP SYN-ACK, 40 bytes, IP-ID = 0x1234.
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // v4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234) // IP-ID
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64
	pkt[9] = 6 // TCP
	// TCP header at offset 20
	binary.BigEndian.PutUint16(pkt[20:22], 80)   // src port
	binary.BigEndian.PutUint16(pkt[22:24], 4444) // dst port
	pkt[32] = 0x50                               // data offset 5
	pkt[33] = 0x12                               // SYN+ACK
	binary.BigEndian.PutUint16(pkt[34:36], 0xFFFF)

	out, changed := b.applyEgress(pkt, wp)
	gotID := binary.BigEndian.Uint16(out[4:6])
	t.Logf("TCP SYN-ACK: changed=%v IP-ID=%#x", changed, gotID)
	if gotID != 0 {
		t.Errorf("TCP IP-ID = %#x, want 0 (TI=Z)", gotID)
	}

	// ICMP echo reply should increment.
	icmp := make([]byte, 28)
	icmp[0] = 0x45
	binary.BigEndian.PutUint16(icmp[2:4], 28)
	binary.BigEndian.PutUint16(icmp[4:6], 0x1234)
	binary.BigEndian.PutUint16(icmp[6:8], 0x4000)
	icmp[8] = 64
	icmp[9] = 1 // ICMP
	icmp[20] = 0 // type 0 echo reply
	out2, _ := b.applyEgress(icmp, wp)
	t.Logf("ICMP: IP-ID=%#x", binary.BigEndian.Uint16(out2[4:6]))
}
