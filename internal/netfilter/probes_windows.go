//go:build windows

package netfilter

import (
	"sync"

	"github.com/c2xorc4/mimic/internal/logging"
)

// t2t3Filter matches nmap T2 (NULL flags) and T3 (SYN+FIN+PSH+URG) probes on
// all TCP ports. These flag combinations never appear in legitimate traffic.
const t2t3Filter = "inbound and tcp and !loopback and (" +
	"(tcp.Fin == 0 and tcp.Syn == 0 and tcp.Rst == 0 and tcp.Psh == 0 and tcp.Ack == 0 and tcp.Urg == 0) or " +
	"(tcp.Syn and tcp.Fin and tcp.Psh and tcp.Urg and !tcp.Ack and !tcp.Rst)" +
	")"

// winProbeResponder intercepts inbound T2/T3 probes and answers with profile-shaped
// RST packets so a Linux persona on Windows fingerprints like native Linux nft.
type winProbeResponder struct {
	mu       sync.Mutex
	ttl      uint8
	window   uint16
	ackZero  bool
	handles  []*wdHandle
	wg       sync.WaitGroup
	closing  bool
	log      *logging.Logger
}

func newProbeResponder() ProbeResponder {
	return &winProbeResponder{log: logging.Component("probes")}
}

func (p *winProbeResponder) Start(ttl uint8, window uint16, ackZero bool) error {
	if ttl == 0 {
		ttl = 64
	}
	p.mu.Lock()
	p.ttl = ttl
	p.window = window
	p.ackZero = ackZero
	p.mu.Unlock()

	// High priority so we see probes before the Windows TCP stack answers.
	h, err := wdOpenPriority(t2t3Filter, 1000)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.handles = append(p.handles, h)
	p.mu.Unlock()

	p.wg.Add(1)
	go p.respondLoop(h)
	p.log.Info("T2/T3 probe response active (WinDivert RST, all ports)", nil)
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
		p.mu.Lock()
		opts := probeRSTOpts{ttl: p.ttl, window: p.window, ackZero: p.ackZero}
		p.mu.Unlock()
		n, ok := craftProbeRST(pkt, opts)
		if !ok {
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