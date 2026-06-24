//go:build windows

package netfilter

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/c2xorc4/mimic/internal/logging"
)

// linuxTProbeFlagClause matches nmap T4/T6 on scoped ports. T7 uses a separate
// broader handle — WinDivert's tcp.Urg filter misses nmap's T7 on some builds.
const linuxTProbeFlagClause = "(" +
	"(tcp.Ack and !tcp.Syn and !tcp.Fin and !tcp.Rst and !tcp.Psh and !tcp.Urg) or " +
	"(tcp.Syn and tcp.Ack and !tcp.Fin and !tcp.Rst and !tcp.Psh and !tcp.Urg)" +
	")"

// linuxT7ProbeFilterForPorts matches FIN+ACK probes (T7). Windows Tcpip often
// strips URG/PSH before WinDivert, so match FIN+ACK only on scoped ports.
func linuxT7ProbeFilterForPorts(ports []uint16) (string, bool) {
	if len(ports) == 0 {
		return "", false
	}
	var b strings.Builder
	b.WriteString("inbound and tcp and !loopback and tcp.Fin and !tcp.Syn and !tcp.Rst and (")
	for i, p := range ports {
		if i > 0 {
			b.WriteString(" or ")
		}
		fmt.Fprintf(&b, "tcp.DstPort == %d", p)
	}
	b.WriteString(")")
	return b.String(), true
}

func linuxTProbeFilterForPorts(ports []uint16) (string, bool) {
	if len(ports) == 0 {
		return "", false
	}
	var b strings.Builder
	b.WriteString("inbound and tcp and !loopback and ")
	b.WriteString(linuxTProbeFlagClause)
	b.WriteString(" and (")
	for i, p := range ports {
		if i > 0 {
			b.WriteString(" or ")
		}
		fmt.Fprintf(&b, "tcp.DstPort == %d", p)
	}
	b.WriteString(")")
	return b.String(), true
}

// winProbeResponder intercepts inbound T4/T6/T7 probes and answers with
// profile-shaped RST packets so a Linux persona on Windows fingerprints like
// native Linux (Debian 5.10: T4/T6 F=R, T7 F=AR).
type winProbeResponder struct {
	mu      sync.Mutex
	ttl     uint8
	window  uint16
	ackZero bool
	handles []*wdHandle
	wg      sync.WaitGroup
	closing bool
	log     *logging.Logger
}

func newProbeResponder() ProbeResponder {
	return &winProbeResponder{log: logging.Component("probes")}
}

func (p *winProbeResponder) Start(ports []uint16, t7Ports []uint16, ttl uint8, window uint16, ackZero bool) error {
	if len(t7Ports) == 0 {
		t7Ports = ports
	}
	if ttl == 0 {
		ttl = 64
	}
	p.mu.Lock()
	p.ttl = ttl
	p.window = window
	p.ackZero = ackZero
	p.mu.Unlock()

	if filter, ok := linuxTProbeFilterForPorts(ports); ok {
		h, err := wdOpenPriority(filter, 1000)
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.handles = append(p.handles, h)
		p.mu.Unlock()
		p.wg.Add(1)
		go p.respondLoop(h)
	}

	if t7Filter, ok := linuxT7ProbeFilterForPorts(t7Ports); ok {
		h7, err := wdOpenPriority(t7Filter, 2100)
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.handles = append(p.handles, h7)
		p.mu.Unlock()
		p.wg.Add(1)
		go p.respondLoop(h7)
	}

	if len(p.handles) == 0 {
		return fmt.Errorf("no ports configured for T4/T6/T7 probe response")
	}

	p.log.Info("T4/T6/T7 probe response active (WinDivert RST)", map[string]interface{}{
		"ports": ports, "t7_ports": t7Ports,
	})
	return nil
}

func (p *winProbeResponder) respondLoop(h *wdHandle) {
	defer p.wg.Done()
	buf := make([]byte, 65535)
	var addr wdAddress
	for {
		n, err := h.recv(buf, &addr)
		if err != nil {
			p.mu.Lock()
			closing := p.closing
			p.mu.Unlock()
			if closing {
				return
			}
			continue
		}
		if n < 40 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl+14 {
			_ = h.send(pkt, &addr)
			continue
		}
		tcpOff := ihl
		flags := pkt[tcpOff+13]
		urgPtr := binary.BigEndian.Uint16(pkt[tcpOff+18 : tcpOff+20])
		p.mu.Lock()
		ttl, window, ackZero := p.ttl, p.window, p.ackZero
		p.mu.Unlock()
		opts, ok := linuxProbeRSTOpts(flags, ttl, window, ackZero)
		if !ok && flags&(0x01|0x10) == 0x11 && flags&(0x02|0x04) == 0 && (flags&(0x20|0x08) != 0 || urgPtr > 0) {
			opts = probeRSTOpts{ttl: ttl, window: window, ackZero: false, rstOnly: false}
			ok = true
		}
		if !ok {
			_ = h.send(pkt, &addr)
			continue
		}
		n, ok = craftProbeRST(pkt, opts)
		if !ok {
			_ = h.send(pkt, &addr)
			continue
		}
		pkt = pkt[:n]
		addr.setOutbound(true)
		h.calcChecksums(pkt, &addr)
		_ = h.send(pkt, &addr)
	}
}

func (p *winProbeResponder) Stop() {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.closing = true
	handles := p.handles
	p.handles = nil
	p.mu.Unlock()
	for _, h := range handles {
		_ = h.close()
	}
	p.wg.Wait()
}