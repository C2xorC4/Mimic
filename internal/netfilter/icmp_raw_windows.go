//go:build windows

package netfilter

import (
	"net"
	"sync"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	rawICMPConn   *icmp.PacketConn
	rawICMPConnMu sync.Mutex
)

// sendPortUnreachableRaw emits ICMP type 3 code 3 via a raw socket, bypassing
// WinDivert egress reinjection (U1 replies were recv'd/sent in-process but never
// appeared on the wire when stack egress also held an outbound-ICMP handle).
func sendPortUnreachableRaw(dst net.IP, quoted []byte) error {
	if len(dst) != 4 {
		return nil
	}
	rawICMPConnMu.Lock()
	defer rawICMPConnMu.Unlock()
	if rawICMPConn == nil {
		c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return err
		}
		rawICMPConn = c
	}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeDestinationUnreachable,
		Code: 3,
		Body: &icmp.DstUnreach{Data: quoted},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = rawICMPConn.WriteTo(b, &net.IPAddr{IP: dst})
	return err
}

func closeRawICMP() {
	rawICMPConnMu.Lock()
	defer rawICMPConnMu.Unlock()
	if rawICMPConn != nil {
		_ = rawICMPConn.Close()
		rawICMPConn = nil
	}
}