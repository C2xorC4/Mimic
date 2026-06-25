//go:build windows

package netfilter

import (
	"fmt"
	"strings"
	"sync"

	"github.com/c2xorc4/mimic/internal/platform"
)

// winClosedPorts answers inbound SYNs to configured ports with TCP RST+ACK so
// nmap reports them as closed (not filtered). Mirrors the Linux nft reject path.
type winClosedPorts struct {
	mu      sync.Mutex
	ports   []uint16
	ttl     uint8
	handles []*wdHandle
	wg      sync.WaitGroup
	closing bool
}

func newClosedPortResponder() ClosedPortResponder {
	return &winClosedPorts{}
}

func (c *winClosedPorts) AddPorts(ports []uint16, ttl uint8, linuxPersona bool) error {
	if len(ports) == 0 {
		return nil
	}
	if ttl == 0 {
		ttl = 64
	}
	if err := platform.EnsureClosedPortFirewallRules(ports); err != nil {
		return err
	}
	c.mu.Lock()
	c.ports = append([]uint16(nil), ports...)
	c.ttl = ttl
	c.mu.Unlock()

	// Windows persona: do NOT divert/craft — the firewall rule above lets the SYN
	// reach the Windows stack, which RSTs the closed port natively, and that RST
	// egresses through the stack-mutation handle that stamps the shared incremental
	// IP-ID (nmap CI=I, SS=S). Crafting the RST here instead would flip the inbound
	// probe in place and echo ITS IP-ID → nmap reads CI=RD (random) and SS=O. We only
	// hand-craft a (Linux-shaped) RST for a Linux persona on a Windows host.
	if !linuxPersona {
		return nil
	}

	filter := closedPortFilter(ports)
	h, err := wdOpen(filter)
	if err != nil {
		return fmt.Errorf("closed ports (WinDivert): %w", err)
	}
	c.mu.Lock()
	c.handles = append(c.handles, h)
	c.mu.Unlock()

	c.wg.Add(1)
	go c.rstLoop(h)
	return nil
}

func closedPortFilter(ports []uint16) string {
	var b strings.Builder
	b.WriteString("inbound and tcp and tcp.Syn and !tcp.Ack and !loopback and (")
	for i, p := range ports {
		if i > 0 {
			b.WriteString(" or ")
		}
		fmt.Fprintf(&b, "tcp.DstPort == %d", p)
	}
	b.WriteString(")")
	return b.String()
}

func (c *winClosedPorts) rstLoop(h *wdHandle) {
	defer c.wg.Done()
	buf := make([]byte, 65535)
	var addr wdAddress
	for {
		n, err := h.recv(buf, &addr)
		if err != nil {
			c.mu.Lock()
			closing := c.closing
			c.mu.Unlock()
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
		c.mu.Lock()
		ttl := c.ttl
		c.mu.Unlock()
		n, ok := craftTCPRST(pkt, ttl)
		if !ok {
			continue
		}
		pkt = pkt[:n]
		addr.setOutbound(true)
		h.calcChecksums(pkt, &addr)
		_ = h.send(pkt, &addr)
	}
}

func (c *winClosedPorts) Stop() {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return
	}
	c.closing = true
	handles := c.handles
	c.handles = nil
	ports := c.ports
	c.mu.Unlock()
	for _, h := range handles {
		_ = h.close()
	}
	c.wg.Wait()
	platform.RemoveClosedPortFirewallRules(ports)
}