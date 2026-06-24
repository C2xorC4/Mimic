//go:build windows

package netfilter

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/c2xorc4/mimic/internal/logging"
	"github.com/c2xorc4/mimic/internal/platform"
)

// winICMPResponder answers inbound ICMP echo (IE) and UDP-to-closed (U1) probes
// with Linux-shaped replies on Windows-hosted Linux personas.
type winICMPResponder struct {
	mu           sync.Mutex
	ttl          uint8
	quoteSize    uint8
	quoteTTL     uint8
	quoteDF      bool
	udpClosed    []uint16
	handles      []*wdHandle
	echoSend     *wdHandle // shared with echo loop — outbound reinject routes via stack egress
	wfpPermit    *wfpICMPPermit
	wg           sync.WaitGroup
	closing      bool
	log          *logging.Logger
}

func newICMPResponder() *winICMPResponder {
	return &winICMPResponder{log: logging.Component("icmp")}
}

// Start installs IE echo-reply and U1 port-unreachable handlers.
func (r *winICMPResponder) Start(ttl, quoteSize, quoteTTL uint8, quoteDF bool, udpClosedPorts []uint16) error {
	if ttl == 0 {
		ttl = 64
	}
	if quoteSize == 0 {
		quoteSize = 64
	}
	if quoteTTL == 0 {
		quoteTTL = ttl
	}
	if err := platform.EnsureUDPProbeFirewallAnyInbound(); err != nil {
		return err
	}
	if err := platform.EnsureICMPOutboundFirewallRule(); err != nil {
		return err
	}
	// A netsh outbound-allow rule does NOT override WFP's stateful drop of our
	// unsolicited injected ICMP error; a hard-permit WFP filter does. Best-effort:
	// without it U1 stays R=N (the host firewall eats the type-3) but everything
	// else works, so don't fail Start.
	if permit, perr := installWFPICMPErrorPermit(); perr == nil {
		r.wfpPermit = permit
	} else {
		r.log.Warn("WFP ICMP-error permit unavailable — U1 port-unreachable may not egress past the firewall",
			map[string]interface{}{"error": perr.Error()})
	}
	r.mu.Lock()
	r.ttl = ttl
	r.quoteSize = quoteSize
	r.quoteTTL = quoteTTL
	r.quoteDF = quoteDF
	r.udpClosed = append([]uint16(nil), udpClosedPorts...)
	r.mu.Unlock()

	echoH, err := wdOpenPriority("inbound and icmp and icmp.Type == 8 and !loopback", 1100)
	if err != nil {
		return fmt.Errorf("ICMP echo reply: %w", err)
	}
	r.mu.Lock()
	r.echoSend = echoH
	r.handles = append(r.handles, echoH)
	r.mu.Unlock()
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.echoLoop(echoH) }()
	if err := r.openLoop("inbound and icmp and icmp.Type == 13 and !loopback", r.timestampLoop, 1100); err != nil {
		return fmt.Errorf("ICMP timestamp reply: %w", err)
	}
	// U1 port-unreachable is ALLOW-LIST scoped to the declared closed UDP ports.
	// Capturing all inbound UDP and dropping it (the old EXCLUDE behaviour)
	// blackholed DNS/QUIC/app traffic and severed host connectivity. With no
	// closed ports there is nothing to answer, so the UDP handle is not opened.
	if filter, ok := udpUnreachableFilter(udpClosedPorts); ok {
		if err := r.openLoop(filter, r.udpUnreachableLoop, 2000); err != nil {
			return fmt.Errorf("ICMP port unreachable: %w", err)
		}
	}
	// nmap's U1 OS-detection probe is a 300-byte payload of 0x43 ('C') sent to a
	// port nmap believes closed — a RANDOM high port when no -sU narrowed it down.
	// A WinDivert filter on udp.PayloadLength==300 catches it on ANY port while
	// touching essentially no normal traffic; the handler verifies the 0x43
	// signature and reinjects anything else, so connectivity is unaffected. This is
	// what makes U1 answer under a plain `nmap -O` (not just -sU to a known port).
	if err := r.openLoop("inbound and udp and !loopback and udp.PayloadLength == 300", r.u1SignatureLoop, 2050); err != nil {
		r.log.Warn("U1 signature responder unavailable — U1 only answers on declared closed ports",
			map[string]interface{}{"error": err.Error()})
	}
	r.log.Info("ICMP probe response active (WinDivert)", map[string]interface{}{
		"udp_closed_ports": udpClosedPorts,
		"u1_mode":          "echo-handle+stack-egress",
	})
	return nil
}

func (r *winICMPResponder) openLoop(filter string, fn func(*wdHandle), priority int16) error {
	h, err := wdOpenPriority(filter, priority)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.handles = append(r.handles, h)
	r.mu.Unlock()
	r.wg.Add(1)
	go func() { defer r.wg.Done(); fn(h) }()
	return nil
}

// udpUnreachableFilter builds an ALLOW-LIST WinDivert filter that captures only
// inbound UDP destined to one of the declared closed ports. It returns ok=false
// when there are no closed ports, signalling the caller to skip the U1 handle (so
// no inbound UDP is intercepted at all). This is the connectivity-preserving
// inverse of the old exclude-list that swallowed every other UDP packet.
func udpUnreachableFilter(closedPorts []uint16) (string, bool) {
	var clauses []string
	for _, p := range closedPorts {
		if p != 0 {
			clauses = append(clauses, fmt.Sprintf("udp.DstPort == %d", p))
		}
	}
	if len(clauses) == 0 {
		return "", false
	}
	return "inbound and udp and !loopback and (" + strings.Join(clauses, " or ") + ")", true
}

func (r *winICMPResponder) echoLoop(h *wdHandle) {
	buf := make([]byte, 65535)
	var addr wdAddress
	for {
		n, err := h.recv(buf, &addr)
		if err != nil {
			r.mu.Lock()
			closing := r.closing
			r.mu.Unlock()
			if closing {
				return
			}
			continue
		}
		if n < 28 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl+8 || pkt[ihl] != 8 {
			_ = h.send(pkt, &addr)
			continue
		}
		r.mu.Lock()
		ttl := r.ttl
		r.mu.Unlock()
		if !craftEchoReply(pkt, ihl, ttl) {
			_ = h.send(pkt, &addr)
			continue
		}
		addr.setOutbound(true)
		h.calcChecksums(pkt, &addr)
		_ = h.send(pkt, &addr)
	}
}

func (r *winICMPResponder) timestampLoop(h *wdHandle) {
	buf := make([]byte, 65535)
	var addr wdAddress
	for {
		n, err := h.recv(buf, &addr)
		if err != nil {
			r.mu.Lock()
			closing := r.closing
			r.mu.Unlock()
			if closing {
				return
			}
			continue
		}
		if n < 28 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl+8 || pkt[ihl] != 13 {
			_ = h.send(pkt, &addr)
			continue
		}
		r.mu.Lock()
		ttl := r.ttl
		r.mu.Unlock()
		pkt[ihl] = 14 // timestamp reply
		pkt[8] = ttl
		fo := binary.BigEndian.Uint16(pkt[6:8])
		fo &^= 0x4000
		binary.BigEndian.PutUint16(pkt[6:8], fo)
		var tmp [4]byte
		copy(tmp[:], pkt[12:16])
		copy(pkt[12:16], pkt[16:20])
		copy(pkt[16:20], tmp[:])
		pkt[10], pkt[11] = 0, 0
		pkt[ihl+2], pkt[ihl+3] = 0, 0
		addr.setOutbound(true)
		h.calcChecksums(pkt, &addr)
		_ = h.send(pkt, &addr)
	}
}

func (r *winICMPResponder) udpUnreachableLoop(h *wdHandle) {
	buf := make([]byte, 65535)
	var addr wdAddress
	var udpRecv uint64
	for {
		n, err := h.recv(buf, &addr)
		if err != nil {
			r.mu.Lock()
			closing := r.closing
			r.mu.Unlock()
			if closing {
				return
			}
			continue
		}
		if n < 28 {
			continue
		}
		nRecv := atomic.AddUint64(&udpRecv, 1)
		if nRecv <= 10 {
			dstPort := binary.BigEndian.Uint16(buf[22:24])
			r.log.Info("U1 UDP recv", map[string]interface{}{"len": n, "dst_port": dstPort})
		}
		orig := make([]byte, n)
		copy(orig, buf[:n])
		r.mu.Lock()
		ttl, quote, quoteTTL, quoteDF, echoH := r.ttl, r.quoteSize, r.quoteTTL, r.quoteDF, r.echoSend
		r.mu.Unlock()
		pkt, ok := craftPortUnreachable(orig, ttl, quote, quoteTTL, quoteDF)
		if !ok || echoH == nil {
			continue
		}
		pkt[10], pkt[11] = 0, 0
		icmpOff := 20
		pkt[icmpOff+2], pkt[icmpOff+3] = 0, 0
		// NOTE: WinDivertSend succeeds but the type-3 is dropped by WFP's outbound
		// ICMP-error layer (unsolicited error, no tracked flow) UNLESS the Windows
		// Firewall is off — proven 2026-06-24. Neither freshOutboundAddr nor full
		// inbound-addr reuse changes this; the fix is a WFP filter / firewall policy,
		// not the address. See MEMORY.md U1 root-cause.
		sendAddr := freshOutboundAddr(&addr)
		echoH.calcChecksums(pkt, &sendAddr)
		if err := echoH.send(pkt, &sendAddr); err != nil {
			r.log.Warn("U1 send failed", map[string]interface{}{"error": err.Error(), "len": len(pkt)})
			continue
		}
		if nRecv <= 5 {
			r.log.Info("U1 ICMP sent", map[string]interface{}{"len": len(pkt)})
		}
	}
}

// u1SignatureLoop answers nmap's U1 OS-detection probe (300-byte 0x43 payload) on
// any port with a Linux-shaped ICMP port-unreachable, and reinjects any other
// 300-byte UDP it happens to capture so legitimate traffic is never dropped.
func (r *winICMPResponder) u1SignatureLoop(h *wdHandle) {
	buf := make([]byte, 65535)
	var addr wdAddress
	var nResp uint64
	for {
		n, err := h.recv(buf, &addr)
		if err != nil {
			r.mu.Lock()
			closing := r.closing
			r.mu.Unlock()
			if closing {
				return
			}
			continue
		}
		if n < 28 || !isNmapU1Payload(buf[:n]) {
			_ = h.send(buf[:n], &addr) // not the U1 probe — reinject untouched
			continue
		}
		orig := make([]byte, n)
		copy(orig, buf[:n])
		r.mu.Lock()
		ttl, quote, quoteTTL, quoteDF, echoH := r.ttl, r.quoteSize, r.quoteTTL, r.quoteDF, r.echoSend
		r.mu.Unlock()
		pkt, ok := craftPortUnreachable(orig, ttl, quote, quoteTTL, quoteDF)
		if !ok || echoH == nil {
			_ = h.send(orig, &addr)
			continue
		}
		pkt[10], pkt[11] = 0, 0
		pkt[20+2], pkt[20+3] = 0, 0
		sendAddr := freshOutboundAddr(&addr)
		echoH.calcChecksums(pkt, &sendAddr)
		if err := echoH.send(pkt, &sendAddr); err != nil {
			r.log.Warn("U1 signature send failed", map[string]interface{}{"error": err.Error()})
			continue
		}
		if n2 := atomic.AddUint64(&nResp, 1); n2 <= 5 {
			dstPort := binary.BigEndian.Uint16(orig[22:24])
			r.log.Info("U1 signature answered", map[string]interface{}{"dst_port": dstPort, "len": len(pkt)})
		}
	}
}

// isNmapU1Payload reports whether an IPv4/UDP packet is nmap's U1 probe: a 300-byte
// UDP payload of 0x43 ('C'). Matching the content (not just the length) avoids
// answering — and thus swallowing — a legitimate 300-byte datagram.
func isNmapU1Payload(pkt []byte) bool {
	if len(pkt) < 28 || pkt[9] != 17 { // IPv4 UDP
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+8 {
		return false
	}
	payload := pkt[ihl+8:]
	if len(payload) != 300 {
		return false
	}
	for _, b := range payload {
		if b != 0x43 {
			return false
		}
	}
	return true
}

// craftEchoReply turns an inbound echo request into an echo reply in place.
func craftEchoReply(pkt []byte, ihl int, ttl uint8) bool {
	if len(pkt) < ihl+8 {
		return false
	}
	var tmp [4]byte
	copy(tmp[:], pkt[12:16])
	copy(pkt[12:16], pkt[16:20])
	copy(pkt[16:20], tmp[:])
	pkt[ihl] = 0 // echo reply
	pkt[8] = ttl
	fo := binary.BigEndian.Uint16(pkt[6:8])
	fo &^= 0x4000 // Linux IE DFI=N
	binary.BigEndian.PutUint16(pkt[6:8], fo)
	pkt[10], pkt[11] = 0, 0
	pkt[ihl+2], pkt[ihl+3] = 0, 0
	return true
}

// craftPortUnreachable builds an outbound ICMP type 3 code 3 (port unreachable)
// from the offending UDP datagram. Linux quotes the ENTIRE original datagram
// VERBATIM (up to the RFC-1812 ~576-byte ICMP limit) — for nmap's 300-byte U1
// probe the full 328-byte IP datagram fits, so the response IP length is
// 20+8+328 = 356 = 0x164, which is exactly nmap's Linux `IPL=164` signature.
// Quoting verbatim (no rewrite of the quoted header) also keeps nmap's RIPL/RID/
// RIPCK/RUCK/RUD all = G; rewriting the quote was what produced RIPL=A4 + RIPCK=I.
// The quoteSize/quoteTTL/quoteDF params are retained for API parity but unused.
func craftPortUnreachable(orig []byte, ttl, quoteSize, quoteTTL uint8, quoteDF bool) ([]byte, bool) {
	if len(orig) < 28 {
		return nil, false
	}
	ihl := int(orig[0]&0x0f) * 4
	if len(orig) < ihl+8 {
		return nil, false
	}
	quote := len(orig)
	if quote > 548 { // 576 - 20 (IP) - 8 (ICMP) max ICMP payload
		quote = 548
	}
	total := 20 + 8 + quote
	out := make([]byte, total)
	out[0] = 0x45
	out[2] = byte(total >> 8)
	out[3] = byte(total)
	out[8] = ttl
	out[9] = 1 // ICMP
	// Outer frag_off stays 0 → DF=N (Linux U1 outer DFI=N).
	copy(out[16:20], orig[12:16]) // dst = original source (the scanner)
	copy(out[12:16], orig[16:20]) // src = original dest (us)
	out[20] = 3                   // type 3
	out[21] = 3                   // code 3 (port unreachable)
	copy(out[28:], orig[:quote])  // quote VERBATIM (preserves the quoted IP checksum)
	_ = quoteSize
	_ = quoteTTL
	_ = quoteDF
	return out, true
}

func (r *winICMPResponder) Stop() {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	r.closing = true
	handles := r.handles
	r.handles = nil
	r.mu.Unlock()
	for _, h := range handles {
		_ = h.close()
	}
	r.wg.Wait()
	if r.wfpPermit != nil {
		r.wfpPermit.Close()
		r.wfpPermit = nil
	}
	closeRawICMP()
	platform.RemoveUDPProbeFirewallAnyInbound()
	platform.RemoveICMPOutboundFirewallRule()
}

