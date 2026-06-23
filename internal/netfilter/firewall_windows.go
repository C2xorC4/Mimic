//go:build windows

package netfilter

import (
	"fmt"
	"sort"
	"sync"
)

// winFirewall implements PersonaFirewall with WinDivert drop handles. Each
// Enable* opens a handle whose filter matches exactly the packets to suppress;
// a drain goroutine recv's them and never reinjects, so they are dropped (the
// port reads "filtered"). Closing the handles reverts instantly — no host
// firewall config is touched.
type winFirewall struct {
	mu      sync.Mutex
	handles []*wdHandle
	wg      sync.WaitGroup
	closing bool
}

// NewPersonaFirewall returns the WinDivert-backed persona firewall.
func NewPersonaFirewall() PersonaFirewall { return &winFirewall{} }

// EnableDrop drops NEW inbound TCP connections (bare SYN) to ports outside the
// allow-list. SYN-only (not SYN-ACK) so the host's own outbound client traffic —
// whose inbound responses are SYN-ACK — is never affected, mirroring the Linux
// "accept established,related" rule. Loopback is exempt (a real firewall never
// blocks 127.0.0.1, and a remote scanner can't reach lo anyway).
func (f *winFirewall) EnableDrop(openPorts, preservePorts []uint16) error {
	allow := mergePorts(openPorts, preservePorts)
	filter := "inbound and tcp and tcp.Syn and !tcp.Ack and !loopback"
	for _, p := range allow {
		filter += fmt.Sprintf(" and tcp.DstPort != %d", p)
	}
	if err := f.openDrain(filter); err != nil {
		return fmt.Errorf("persona firewall (TCP drop): %w", err)
	}
	return nil
}

// EnableICMPDrop drops inbound ICMP echo-requests (type 8).
func (f *winFirewall) EnableICMPDrop() error {
	if err := f.openDrain("inbound and icmp and icmp.Type == 8 and !loopback"); err != nil {
		return fmt.Errorf("persona firewall (ICMP drop): %w", err)
	}
	return nil
}

// openDrain opens a WinDivert handle for filter and starts a goroutine that
// recv's (and drops) every matching packet until Stop closes the handle.
func (f *winFirewall) openDrain(filter string) error {
	h, err := wdOpen(filter)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.handles = append(f.handles, h)
	f.mu.Unlock()

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		buf := make([]byte, 65535)
		var addr wdAddress
		for {
			if _, err := h.recv(buf, &addr); err != nil {
				f.mu.Lock()
				closing := f.closing
				f.mu.Unlock()
				if closing {
					return
				}
				continue
			}
			// Drop: do not reinject.
		}
	}()
	return nil
}

func (f *winFirewall) Stop() {
	f.mu.Lock()
	f.closing = true
	hs := f.handles
	f.handles = nil
	f.mu.Unlock()
	for _, h := range hs {
		_ = h.close() // unblocks the drain goroutine's recv
	}
	f.wg.Wait()
}

// mergePorts returns the sorted, de-duplicated union of two port lists (drops 0).
func mergePorts(a, b []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(a)+len(b))
	for _, p := range append(append([]uint16{}, a...), b...) {
		if p != 0 {
			seen[p] = struct{}{}
		}
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
