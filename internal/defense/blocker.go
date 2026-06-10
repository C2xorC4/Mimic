package defense

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/c2xorc4/mimic/internal/events"
	"github.com/c2xorc4/mimic/internal/logging"
)

// Blocker enacts (or, in dry-run, only reports) a block decision. It always
// honors the whitelist and only touches the firewall when enforce is set; either
// way it emits a block event so the action is visible to the SIEM.
type Blocker struct {
	enforce   bool
	ttl       time.Duration
	whitelist []*net.IPNet
	log       *logging.Logger

	mu      sync.Mutex
	ensured bool
}

// NewBlocker builds a blocker from cfg. A nil-safe logger component is used.
func NewBlocker(cfg Config) *Blocker {
	cfg = cfg.withDefaults()
	b := &Blocker{
		enforce: cfg.Enforce,
		ttl:     cfg.BlockTTL.D(),
		log:     logging.Component("defense"),
	}
	for _, c := range cfg.Whitelist {
		if n := parseCIDR(c); n != nil {
			b.whitelist = append(b.whitelist, n)
		}
	}
	if cfg.Enforce && len(b.whitelist) == 0 && b.log != nil {
		b.log.Warn("active response ENFORCE is on with an empty whitelist — add your management/SSH subnet to defense.whitelist to avoid self-lockout", nil)
	}
	return b
}

// parseCIDR accepts a CIDR ("10.0.0.0/8") or a bare IP ("127.0.0.1").
func parseCIDR(s string) *net.IPNet {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if !strings.Contains(s, "/") {
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			s = fmt.Sprintf("%s/%d", s, bits)
		}
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil
	}
	return n
}

func (b *Blocker) whitelisted(ip net.IP) bool {
	for _, n := range b.whitelist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Block is invoked by the detector. Whitelisted sources are skipped. A block
// event is always emitted (alert-only when enforce is off); the firewall is
// modified only when enforce is set.
func (b *Blocker) Block(ipStr, reason string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}
	if b.whitelisted(ip) {
		if b.log != nil {
			b.log.Debug("abuse source whitelisted; not blocking", map[string]interface{}{"src_ip": ipStr})
		}
		return
	}

	enforced := false
	fields := map[string]interface{}{"reason": reason, "ttl": b.ttl.String(), "dry_run": !b.enforce}
	if b.enforce {
		if err := b.nftBlock(ip); err != nil {
			fields["error"] = err.Error()
		} else {
			enforced = true
		}
	}
	fields["enforced"] = enforced

	msg := "abuse detected (alert-only; would block source)"
	if enforced {
		msg = "source blocked"
	}
	events.Emit(events.Event{Type: events.Block, Severity: events.SevAlert, SrcIP: ipStr, Message: msg, Fields: fields})
	if b.log != nil {
		b.log.Warn(msg, fields)
	}
}

func (b *Blocker) nftBlock(ip net.IP) error {
	if ip.To4() == nil {
		return fmt.Errorf("ipv6 blocking not supported")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ensured {
		if err := b.ensure(); err != nil {
			return err
		}
		b.ensured = true
	}
	ttl := fmt.Sprintf("%ds", int(b.ttl.Seconds()))
	args := []string{"nft", "add", "element", "inet", "mimic_block", "blocked",
		fmt.Sprintf("{ %s timeout %s }", ip.String(), ttl)}
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("nft add element: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ensure creates the nft drop set + rule once. The set uses a native per-element
// timeout so blocks auto-expire with no reaper.
func (b *Blocker) ensure() error {
	cmds := [][]string{
		{"nft", "add", "table", "inet", "mimic_block"},
		{"nft", "add", "set", "inet", "mimic_block", "blocked", "{ type ipv4_addr ; flags timeout ; }"},
		{"nft", "add", "chain", "inet", "mimic_block", "input", "{ type filter hook input priority -150 ; policy accept ; }"},
		{"nft", "add", "rule", "inet", "mimic_block", "input", "ip", "saddr", "@blocked", "drop"},
	}
	for _, a := range cmds {
		if out, err := exec.Command(a[0], a[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("nft setup (%v): %s", a, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Close removes the block table (only created when enforcing).
func (b *Blocker) Close() {
	if b.enforce {
		exec.Command("nft", "delete", "table", "inet", "mimic_block").Run() //nolint:errcheck
	}
}
