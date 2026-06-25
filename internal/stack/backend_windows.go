//go:build windows

package stack

import (
	"encoding/binary"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/logging"
)

// The Windows stack backend reproduces the eBPF egress mutations (internal/ebpf/
// fingerprint.c) over a userland WinDivert handle. WinDivert delivers each
// outbound IPv4 packet at the NETWORK layer (starting at the IP header — no
// Ethernet), we edit the bytes, and WinDivertHelperCalcChecksums fixes the
// IP/TCP/ICMP checksums, so there is no incremental-checksum math to port.
//
// Coverage matches fingerprint.c's egress path except A=O RST ack rewriting,
// which needs inbound SEQ tracking (a second handle/seq-cache) and is deferred —
// it refines nmap T4/T6 only; primary OS attribution (TTL/window/options/DF/
// IP-ID + TS rate) is fully covered here.

// Outbound TCP + ICMP (incl. kernel-generated U1 port-unreachable), PLUS inbound
// bare SYNs. The inbound SYNs are captured on the SAME handle (one goroutine) so a
// SYN is recorded BEFORE the loop comes back around to the SYN-ACK it triggers —
// race-free, unlike a separate sniff goroutine. Inbound SYNs are reinjected
// unchanged; we only read their options (timestamp/ECN) to shape the SYN-ACK.
const winFilter = "(outbound and ip and (tcp or icmp)) or " +
	"(inbound and ip and tcp and tcp.Syn and !tcp.Ack and !loopback)"

var procGetTickCount64 = windows.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")

// uptimeMs returns milliseconds since boot — the Windows-authentic TSval clock
// (mirrors fingerprint.c's bpf_ktime_get_ns()/1e6).
func uptimeMs() uint32 {
	r, _, _ := procGetTickCount64.Call()
	return uint32(r)
}

// uptimeMs64 is the full 64-bit tick count for cache-expiry bookkeeping.
func uptimeMs64() uint64 {
	r, _, _ := procGetTickCount64.Call()
	return uint64(r)
}

// IP-ID behaviors (mirror internal/ebpf constants).
const (
	ipidIncremental = 0
	ipidRandom      = 1
	ipidZero        = 2
)

// winProfile is the immutable per-profile snapshot the mutation loop reads.
type winProfile struct {
	ttl           uint8
	dfBit         bool
	ipidBehavior  uint8
	windowSize    uint16
	windowScale   uint8
	mss           uint16
	tcpTimestamps bool
	sackPermitted bool
	optionsCount  uint8
	windowInRST   uint16
	opt1          uint8 // second option kind (drives the Linux SACK-first template)
	ecnEcho       bool  // Linux/macOS ECN OPTIONS behaviour (no-TS NNS template + native ECN opts)
	ecnCC         bool  // echo ECE on the ECN-probe SYN-ACK → nmap CC=Y (Linux/macOS + Windows Server via explicit_congestion: echo); Windows workstation = N
	ecnWindow     uint16 // window advertised on the ECN-probe SYN-ACK (nmap ECN W=); 0 = use windowSize. Linux ECN rwnd differs from the OS-probe WIN (FE88→FAF0).
	winQuirks     bool  // Windows profile → apply Windows-only quirks (ICMP CD=Z, A=O RST); off for Linux (#13)
	icmpQuoteTTL  uint8 // TTL stamped into U1 quoted IP header
	icmpQuoteDF   bool  // DF bit in U1 quoted IP header
}

func toWinProfile(p *config.OSProfile) *winProfile {
	s := p.Stack
	wp := &winProfile{
		ttl:           s.TTL,
		dfBit:         s.DFBit,
		windowSize:    s.WindowSize,
		windowScale:   s.WindowScale,
		mss:           s.MSS,
		tcpTimestamps: s.TCPTimestamps,
		sackPermitted: s.SACKPermitted,
		optionsCount:  uint8(len(s.TCPOptionsOrder)),
		windowInRST:   s.WindowInRST,
		icmpQuoteTTL:  s.ICMPTTLInQuote,
		icmpQuoteDF:   s.ICMPDFInQuote,
	}
	if wp.icmpQuoteTTL == 0 {
		wp.icmpQuoteTTL = wp.ttl
	}
	switch strings.ToLower(s.IPIDBehavior) {
	case "random", "rand":
		wp.ipidBehavior = ipidRandom
	case "zero", "0":
		wp.ipidBehavior = ipidZero
	default:
		wp.ipidBehavior = ipidIncremental
	}
	if len(s.TCPOptionsOrder) > 1 {
		wp.opt1 = tcpOptKind(s.TCPOptionsOrder[1])
	}
	switch strings.ToLower(p.Family) {
	case "linux", "macos":
		wp.ecnEcho = true
	}
	// CC=Y (echo ECE) for Linux/macOS always, and for any profile that opts in via
	// `explicit_congestion: echo` (modern Windows Server reflects ECE → nmap CC=Y;
	// Windows workstation = respond/CC=N). Kept separate from ecnEcho so a Windows
	// Server profile gets CC=Y WITHOUT the Linux ECN-options template.
	wp.ecnCC = wp.ecnEcho || strings.EqualFold(s.ExplicitCongestion, "echo")
	wp.winQuirks = strings.EqualFold(p.Family, "windows")
	// A real Linux kernel advertises a smaller rwnd on the ECN probe's SYN-ACK than on
	// the OS-detection probes (nmap WIN vs ECN W). Map the OS-probe window to its ECN
	// companion so the ECN test's W= field matches nmap-os-db. 0 = leave = windowSize.
	if wp.ecnEcho {
		switch wp.windowSize {
		case 0xFE88: // Linux 4.15-5.19 / 5.4-5.10: WIN=FE88, ECN W=FAF0
			wp.ecnWindow = 0xFAF0
		case 0x7120: // Linux 3.2-4.14: WIN=7120, ECN W=7210
			wp.ecnWindow = 0x7210
		}
	}
	return wp
}

// ipidState is the shared IP-ID counter (single-goroutine; no lock needed).
type ipidState struct {
	counter uint16
	seed    uint32
}

// synFlow records what an inbound SYN carried, so the outbound SYN-ACK shaper can
// reproduce a real Linux response: emit a timestamp ONLY if the client's SYN had
// one (nmap's OPS probes do, its ECN probe does not → that's what makes the ECN
// SYN-ACK options M5B4NNSNW7 instead of carrying a TS), and echo the client's
// TSval as TSecr (OPS ST11) rather than a synthetic value. Keyed by client IP:port.
type synFlow struct {
	hadTS bool
	tsval uint32
	exp   uint64 // GetTickCount64 ms after which the entry is stale
}

type windowsBackend struct {
	iface   string
	handle  *wdHandle
	profile atomic.Pointer[winProfile]
	enabled atomic.Bool
	ipid    ipidState
	closing atomic.Bool
	done    chan struct{}
	wg      sync.WaitGroup

	synMu    sync.Mutex
	synCache map[uint64]synFlow
}

// New returns the WinDivert-backed stack backend. iface is accepted for API
// parity but unused — WinDivert intercepts host-wide.
func New(ifaceName string) (Backend, error) {
	return &windowsBackend{
		iface:    ifaceName,
		done:     make(chan struct{}),
		ipid:     ipidState{seed: 0x9e3779b9},
		synCache: make(map[uint64]synFlow),
	}, nil
}

// Available reports whether the WinDivert stack backend can run on this host.
func Available() bool { return winDivertLoadable() }

// Teardown is a no-op: WinDivert leaves no persistent host state — closing the
// handle unloads the filter and the driver auto-unloads when idle.
func Teardown(ifaceName string, purgeQdisc bool) (TeardownResult, error) {
	return TeardownResult{}, nil
}

func (b *windowsBackend) Load() error {
	h, err := wdOpen(winFilter)
	if err != nil {
		return err
	}
	b.handle = h
	b.wg.Add(1)
	go b.loop()
	return nil
}

// recordInboundSyn caches an inbound bare SYN's timestamp presence + TSval, keyed
// by the client IP:port, for later SYN-ACK shaping. Called from the main loop
// (same goroutine that shapes the SYN-ACK) so the record exists before the
// SYN-ACK is processed. The packet is reinjected unchanged by the caller.
func (b *windowsBackend) recordInboundSyn(pkt []byte) {
	if len(pkt) < 24 || pkt[0]>>4 != 4 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+20 {
		return
	}
	tcp := pkt[ihl:]
	tcpHL := int(tcp[12]>>4) * 4
	if tcpHL < 20 || len(tcp) < tcpHL {
		return
	}
	key := flowKey(pkt[12:16], tcp[0:2]) // client src IP:port
	hadTS, tsval := scanSynTimestamp(tcp[20:tcpHL])
	if os.Getenv("MIMIC_WD_DEBUG") != "" {
		logging.Component("stackwin").Info("SYN in", map[string]interface{}{
			"sport": binary.BigEndian.Uint16(tcp[0:2]), "dport": binary.BigEndian.Uint16(tcp[2:4]),
			"hadTS": hadTS, "flags": tcp[13],
		})
	}
	b.synMu.Lock()
	if len(b.synCache) > 4096 {
		b.synCache = make(map[uint64]synFlow) // cheap bound; nmap flows are short-lived
	}
	b.synCache[key] = synFlow{hadTS: hadTS, tsval: tsval, exp: uptimeMs64() + 4000}
	b.synMu.Unlock()
}

// flowKey packs a 4-byte IP and 2-byte port (both network order) into a map key.
func flowKey(ip, port []byte) uint64 {
	return uint64(binary.BigEndian.Uint32(ip))<<16 | uint64(binary.BigEndian.Uint16(port))
}

// scanSynTimestamp walks TCP options for a timestamp (kind 8), returning whether
// one is present and its TSval (the client clock we echo back as TSecr).
func scanSynTimestamp(opts []byte) (bool, uint32) {
	for i := 0; i+1 <= len(opts); {
		switch opts[i] {
		case optEOL:
			return false, 0
		case optNOP:
			i++
			continue
		}
		if i+2 > len(opts) {
			return false, 0
		}
		olen := int(opts[i+1])
		if olen < 2 || i+olen > len(opts) {
			return false, 0
		}
		if opts[i] == optTimestamp && olen == olenTimestamp {
			return true, binary.BigEndian.Uint32(opts[i+2 : i+6])
		}
		i += olen
	}
	return false, 0
}

// lookupSynFlow consumes the cached inbound-SYN record matching an outbound
// SYN-ACK (keyed by its dst IP:port = the client). Returns ok=false if absent or
// stale, in which case the shaper uses its synthetic-TS default.
func (b *windowsBackend) lookupSynFlow(pkt []byte, ihl int) (synFlow, bool) {
	if len(pkt) < ihl+4 {
		return synFlow{}, false
	}
	// The client is the SYN-ACK's DESTINATION: dst IP = pkt[16:20], dst port =
	// tcp[2:4] = pkt[ihl+2:ihl+4]. (tcp[0:2]/pkt[ihl:ihl+2] is the SOURCE/server
	// port — using it here made every lookup search under the service port and miss.)
	key := flowKey(pkt[16:20], pkt[ihl+2:ihl+4])
	b.synMu.Lock()
	f, ok := b.synCache[key]
	b.synMu.Unlock()
	// Not deleted on read: nmap reuses ONE source port across OS-detection probes,
	// so the entry must survive to shape each probe's SYN-ACK. Each new SYN on the
	// flow overwrites it (latest wins); stale entries fall out via the TTL.
	if !ok || f.exp < uptimeMs64() {
		return synFlow{}, false
	}
	return f, true
}

func (b *windowsBackend) SetProfile(p *config.OSProfile) error {
	b.profile.Store(toWinProfile(p))
	return nil
}

func (b *windowsBackend) Enable() error         { b.enabled.Store(true); return nil }
func (b *windowsBackend) Disable() error        { b.enabled.Store(false); return nil }
func (b *windowsBackend) IsEnabled() bool       { return b.enabled.Load() }
func (b *windowsBackend) InterfaceName() string { return b.iface }

func (b *windowsBackend) Close() error {
	if b.handle == nil {
		return nil
	}
	b.closing.Store(true)
	err := b.handle.close() // unblocks the recv in loop()
	b.wg.Wait()
	return err
}

// loop is the recv → mutate → reinject pump. It ALWAYS re-sends every captured
// packet (modified or not) — failing to do so would drop the host's traffic.
func (b *windowsBackend) loop() {
	defer b.wg.Done()
	buf := make([]byte, 65535)
	var addr wdAddress
	debug := os.Getenv("MIMIC_WD_DEBUG") != ""
	var recvN, outN, modN, sendErr, firstErrLogged, u1Egress uint64
	if debug {
		dlog := logging.Component("stackwin")
		go func() {
			t := time.NewTicker(3 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-b.done:
					return
				case <-t.C:
					dlog.Info("windivert counters", map[string]interface{}{
						"recv": atomic.LoadUint64(&recvN), "outbound": atomic.LoadUint64(&outN),
						"modified": atomic.LoadUint64(&modN), "send_err": atomic.LoadUint64(&sendErr),
					})
				}
			}
		}()
	}
	for {
		n, err := b.handle.recv(buf, &addr)
		if err != nil {
			if b.closing.Load() {
				return
			}
			if debug && firstErrLogged == 0 {
				firstErrLogged = 1
				logging.Component("stackwin").Warn("recv error", map[string]interface{}{"error": err.Error()})
			}
			continue // transient; keep pumping
		}
		atomic.AddUint64(&recvN, 1)
		pkt := buf[:n]
		if debug && recvN <= 3 {
			logging.Component("stackwin").Info("packet", map[string]interface{}{
				"n": n, "outbound": addr.Outbound(), "bitfield": addr.Bitfield, "proto": pkt[9], "ttl": pkt[8],
			})
		}
		if !addr.Outbound() {
			// Inbound bare SYN (per filter): record its TS/ECN profile for SYN-ACK
			// shaping, then reinject unchanged. This runs in the SAME goroutine that
			// later shapes the SYN-ACK, so the record is guaranteed to be in place
			// before that SYN-ACK is processed (the prior sniff-goroutine approach
			// raced and lost, leaving the ECN probe's SYN-ACK with the wrong template).
			if b.enabled.Load() {
				b.recordInboundSyn(pkt)
			}
			if err := b.handle.send(pkt, &addr); err != nil {
				atomic.AddUint64(&sendErr, 1)
			}
			continue
		}
		if addr.Outbound() && len(pkt) >= 28 && pkt[9] == 1 {
			ihl := int(pkt[0]&0x0f) * 4
			if len(pkt) >= ihl+2 && pkt[ihl] == 3 && pkt[ihl+1] == 3 {
				u1n := atomic.AddUint64(&u1Egress, 1)
				if u1n <= 8 {
					logging.Component("stackwin").Info("U1 diverted", map[string]interface{}{
						"len": n, "enabled": b.enabled.Load(),
					})
				}
			}
		}
		if addr.Outbound() && b.enabled.Load() {
			atomic.AddUint64(&outN, 1)
			if prof := b.profile.Load(); prof != nil {
				var changed bool
				pkt, changed = b.applyEgress(pkt, prof)
				if changed {
					atomic.AddUint64(&modN, 1)
					b.handle.calcChecksums(pkt, &addr)
				}
			}
		}
		if err := b.handle.send(pkt, &addr); err != nil {
			atomic.AddUint64(&sendErr, 1)
		}
	}
}

// applyEgress edits an outbound IPv4 packet (IP header at offset 0) to match the
// profile, returning the (possibly grown) packet and whether anything changed.
func (b *windowsBackend) applyEgress(pkt []byte, p *winProfile) ([]byte, bool) {
	if len(pkt) < 20 {
		return pkt, false
	}
	if pkt[0]>>4 != 4 { // IPv4 only
		return pkt, false
	}
	modified := false
	proto := pkt[9]

	// === TTL ===
	if p.ttl > 0 && pkt[8] != p.ttl {
		pkt[8] = p.ttl
		modified = true
	}

	// === DF bit (frag_off, network order; DF = 0x4000) ===
	fo := binary.BigEndian.Uint16(pkt[6:8])
	curDF := fo&0x4000 != 0
	if curDF != p.dfBit {
		if p.dfBit {
			fo |= 0x4000
		} else {
			fo &^= 0x4000
		}
		binary.BigEndian.PutUint16(pkt[6:8], fo)
		modified = true
	}

	// === IP-ID ===
	// Windows (winQuirks): one shared counter across TCP+ICMP per ip_id_behavior →
	// nmap SS=S, TI=I. Linux is PER-PROTOCOL: TCP/DF segments carry IP-ID 0 (nmap
	// TI=Z, CI=Z) while ICMP echo replies increment (II=I).
	//
	// ★ WinDivert ceiling (validated 2026-06-25): writing IP-ID 0 here is CORRECT but
	// does NOT survive to the wire. The Windows IP transmit path treats a 0
	// Identification as "unassigned" and re-stamps it from the host's global counter
	// BELOW WinDivert's network-layer injection point — so TI/CI come out =I, not =Z.
	// Confirmed negative against Impostor + IPChecksum/TCPChecksum send flags (and they
	// decremented TTL as a side effect). Non-zero IDs DO survive (Windows personas get
	// CI=I), so the ICMP increment lands. TI=Z/CI=Z therefore require eBPF (native) or
	// the opt-in high-fidelity driver backend; they are unreachable on default WinDivert.
	// We still write 0 (harmless, correct intent, and the right value once a verbatim
	// emit path exists).
	var newID uint16
	if p.winQuirks {
		switch p.ipidBehavior {
		case ipidZero:
			newID = 0
		case ipidRandom:
			s := b.ipid.seed
			s ^= s << 13
			s ^= s >> 17
			s ^= s << 5
			b.ipid.seed = s
			newID = uint16(s)
		default:
			b.ipid.counter++
			newID = b.ipid.counter
		}
	} else if proto == 1 { // ICMP → incrementing IP-ID (nmap II=I)
		b.ipid.counter++
		newID = b.ipid.counter
	} else { // TCP/other → 0 (nmap TI=Z, CI=Z; modern Linux DF behavior)
		newID = 0
	}
	if binary.BigEndian.Uint16(pkt[4:6]) != newID {
		binary.BigEndian.PutUint16(pkt[4:6], newID)
		modified = true
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 {
		return pkt, modified
	}

	switch proto {
	case 6: // TCP
		var tcpChanged bool
		pkt, tcpChanged = b.applyTCP(pkt, ihl, p)
		if tcpChanged {
			modified = true
		}
	case 1: // ICMP
		if len(pkt) >= ihl+2 && pkt[ihl] == 3 && pkt[ihl+1] == 3 {
			if applyPortUnreachable(pkt, ihl, p) {
				modified = true
			}
		} else if applyICMP(pkt, ihl, p.winQuirks) {
			modified = true
		}
	}
	return pkt, modified
}

// growTCPHeader extends the TCP header by grow bytes and updates IP total length.
func growTCPHeader(pkt []byte, ihl, oldTCPHL, newTCPHL int) []byte {
	grow := newTCPHL - oldTCPHL
	if grow <= 0 || len(pkt) < ihl+oldTCPHL {
		return pkt
	}
	out := make([]byte, len(pkt)+grow)
	copy(out, pkt[:ihl+oldTCPHL])
	copy(out[ihl+newTCPHL:], pkt[ihl+oldTCPHL:])
	out[ihl+12] = (out[ihl+12] & 0x0f) | byte(newTCPHL/4)<<4
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// shrinkTCPHeader removes (oldTCPHL-newTCPHL) bytes of TCP options — the bytes at
// [ihl+newTCPHL : ihl+oldTCPHL], i.e. trailing options — and fixes the TCP data
// offset + IP total length. Inverse of growTCPHeader. Used to normalize a no-TS
// Windows SYN-ACK to its real 12-byte (O1–O5) / 8-byte (O6) option length when a
// TS-reflecting host produced longer options, so the OPS option LENGTH matches the
// nmap-os-db reference on ANY host (not just a TS-off host).
func shrinkTCPHeader(pkt []byte, ihl, oldTCPHL, newTCPHL int) []byte {
	shrink := oldTCPHL - newTCPHL
	if shrink <= 0 || newTCPHL < 20 || len(pkt) < ihl+oldTCPHL {
		return pkt
	}
	out := make([]byte, len(pkt)-shrink)
	copy(out, pkt[:ihl+newTCPHL])             // IP + base TCP + kept options
	copy(out[ihl+newTCPHL:], pkt[ihl+oldTCPHL:]) // payload after the old header
	out[ihl+12] = (out[ihl+12] & 0x0f) | byte(newTCPHL/4)<<4
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// applyTCP ports the TCP egress mutations (window, options templates, TS
// coherence, RST window, ECN) at IP-relative offsets.
func (b *windowsBackend) applyTCP(pkt []byte, ihl int, p *winProfile) ([]byte, bool) {
	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return pkt, false
	}
	tcpHL := int(tcp[12]>>4) * 4
	if tcpHL < 20 || len(tcp) < tcpHL {
		return pkt, false
	}
	flags := tcp[13]
	isSYN := flags&0x02 != 0
	isSYNACK := flags&0x12 == 0x12
	isSynPhase := isSYN || isSYNACK // OPS/ECN/O6 nmap probes measure SYN-ACK shapes
	optLen := tcpHL - 20
	modified := false

	// Inbound-SYN context for this flow: whether the client's SYN carried a
	// timestamp (and its TSval). Drives whether this SYN-ACK gets the TS template
	// (OPS, ST11 with a real TSecr echo) or the no-TS template (ECN probe →
	// M5B4NNSNW7). Absent ⇒ fall back to the synthetic-TS default below.
	var flow synFlow
	var haveFlow bool
	if isSYNACK {
		flow, haveFlow = b.lookupSynFlow(pkt, ihl)
		if os.Getenv("MIMIC_WD_DEBUG") != "" {
			logging.Component("stackwin").Info("SYN-ACK shape", map[string]interface{}{
				"cport": binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]), "haveFlow": haveFlow,
				"hadTS": flow.hadTS, "optlen": optLen,
			})
		}
	}

	// === Expand 12-byte Windows SYN-ACK → 20-byte Linux template (OPS ST11) ===
	// Only grow to the TS template when the client's SYN actually had a timestamp
	// (or we have no record). A SYN without TS (nmap's ECN probe) stays 12-byte and
	// is shaped by the no-TS ECN block below.
	if optLen == 12 && isSYNACK && p.tcpTimestamps && p.opt1 == optSACKPerm && p.windowScale > 0 && (!haveFlow || flow.hadTS) {
		pkt = growTCPHeader(pkt, ihl, tcpHL, 40)
		tcp = pkt[ihl:]
		tcpHL = 40
		optLen = 20
		modified = true
	}

	// === TCP window ===
	if p.windowSize > 0 && binary.BigEndian.Uint16(tcp[14:16]) != p.windowSize {
		binary.BigEndian.PutUint16(tcp[14:16], p.windowSize)
		modified = true
	}

	// === 20-byte SYN/SYN-ACK options template ===
	if optLen == 20 && p.optionsCount > 0 && isSynPhase && len(tcp) >= 40 {
		old := tcp[20:40]
		mss := p.mss
		if old[0] == optMSS && old[1] == 4 {
			mss = binary.BigEndian.Uint16(old[2:4])
		}
		hadSACK := old[4] == optSACKPerm || old[6] == optSACKPerm || old[8] == optSACKPerm ||
			old[10] == optSACKPerm || old[12] == optSACKPerm || old[16] == optSACKPerm
		useSACK := p.sackPermitted && hadSACK

		var no [20]byte
		for i := range no {
			no[i] = optNOP
		}
		wantOptLen := 20 // shrink to this after writing (no-TS Windows = 12; else 20)
		switch {
		case p.windowScale == 0 && !p.tcpTimestamps:
			// Windows XP: MSS, NOP, NOP, SACK
			putMSS(no[:], 0, mss)
			no[4], no[5] = optNOP, optNOP
			if useSACK {
				no[6], no[7] = optSACKPerm, 2
			}
		case p.windowScale > 0 && !p.tcpTimestamps:
			// Windows 7/10/11 (no TS): MSS, NOP, WS, NOP, NOP, SACK = 12 real bytes.
			// A TS-reflecting host produces a 20-byte SYN-ACK (it echoed nmap's TS); we
			// overwrite + shrink to 12 so the OPS option length matches a real no-TS
			// Windows box on ANY host (nmap-os-db O1=M5B4NW8NNS, not the padded 20B).
			putMSS(no[:], 0, mss)
			no[4] = optNOP
			no[5], no[6], no[7] = optWScale, 3, p.windowScale
			if useSACK {
				no[8], no[9] = optNOP, optNOP
				no[10], no[11] = optSACKPerm, 2
				wantOptLen = 12 // M5B4NW8NNS
			} else {
				// P3 probe carries no SACK → real no-TS Windows answers MSS,NOP,WS only
				// (nmap O3=M5B4NW8), no NOP/SACK tail. Shrink to 8 so O3 matches.
				wantOptLen = 8
			}
		case p.tcpTimestamps && p.opt1 == optSACKPerm:
			// Linux: MSS, SACK, TS, NOP, WS — REAL timestamp. Checked BEFORE the
			// Windows ws>0&&ts case (Linux profiles put SACK at option index 1,
			// Windows put NOP), so a Linux profile emits the Linux OPS order with
			// TS=A instead of a Windows-ordered template — the #10 fix. (Previously
			// this skipped the TS as NOPs and sat after the Windows case → dead.)
			var linTSecr uint32
			switch {
			case old[8] == optTimestamp && old[9] == olenTimestamp:
				linTSecr = binary.BigEndian.Uint32(old[14:18])
			case old[6] == optTimestamp && old[7] == olenTimestamp:
				linTSecr = binary.BigEndian.Uint32(old[12:16])
			case old[4] == optTimestamp && old[5] == olenTimestamp:
				linTSecr = binary.BigEndian.Uint32(old[10:14])
			}
			putMSS(no[:], 0, mss)
			if useSACK {
				no[4], no[5] = optSACKPerm, 2
			}
			no[6], no[7] = optTimestamp, olenTimestamp
			binary.BigEndian.PutUint32(no[8:12], uptimeMs())
			// TSecr echoes the client's SYN TSval (real RFC-7323 behaviour) when the
			// inbound-SYN tap captured it. The Windows host has TCP timestamps disabled
			// so its own SYN-ACK carries nothing to echo (linTSecr==0); without the tap
			// nmap would read ST10 (TSecr zero). Prefer the real client TSval; else fall
			// back to a synthetic nonzero so the pair still reads ST11.
			if haveFlow && flow.hadTS && flow.tsval != 0 {
				linTSecr = flow.tsval
			}
			if linTSecr == 0 {
				linTSecr = uptimeMs()
			}
			binary.BigEndian.PutUint32(no[12:16], linTSecr)
			no[16] = optNOP
			if p.windowScale > 0 {
				no[17], no[18], no[19] = optWScale, 3, p.windowScale
			}
		case p.windowScale > 0 && p.tcpTimestamps:
			// Win10/11 (TS on): MSS, NOP, WS, SACK, TS  — TSecr preserved, TSval = uptime
			var origTSecr uint32
			switch {
			case old[8] == optTimestamp && old[9] == olenTimestamp:
				origTSecr = binary.BigEndian.Uint32(old[14:18])
			case old[6] == optTimestamp && old[7] == olenTimestamp:
				origTSecr = binary.BigEndian.Uint32(old[12:16])
			case old[4] == optTimestamp && old[5] == olenTimestamp:
				origTSecr = binary.BigEndian.Uint32(old[10:14])
			}
			putMSS(no[:], 0, mss)
			no[4] = optNOP
			no[5], no[6], no[7] = optWScale, 3, p.windowScale
			if useSACK {
				no[8], no[9] = optSACKPerm, 2
			}
			no[10], no[11] = optTimestamp, olenTimestamp
			binary.BigEndian.PutUint32(no[12:16], uptimeMs())
			// TSecr must echo the client's SYN TSval for nmap OPS to read ST11. The
			// Windows host has TCP timestamps disabled, so its own SYN-ACK carries
			// nothing to echo (origTSecr==0) → nmap reads ST10. Prefer the real client
			// TSval from the inbound-SYN cache; else synthesize a nonzero value. (Same
			// fix as the Linux branch — this is what closes OPS ST10→ST11 for every
			// Windows profile, e.g. Win11/Server matching the nmap-os-db M5B4NW8ST11.)
			if haveFlow && flow.hadTS && flow.tsval != 0 {
				origTSecr = flow.tsval
			}
			if origTSecr == 0 {
				origTSecr = uptimeMs()
			}
			binary.BigEndian.PutUint32(no[16:20], origTSecr)
		default:
			// macOS/default: MSS, NOP, WS, SACK, NOPs
			putMSS(no[:], 0, mss)
			no[4] = optNOP
			if p.windowScale > 0 {
				no[5], no[6], no[7] = optWScale, 3, p.windowScale
			}
			if useSACK {
				no[8], no[9] = optSACKPerm, 2
			}
		}
		copy(tcp[20:40], no[:])
		if wantOptLen < 20 {
			pkt = shrinkTCPHeader(pkt, ihl, 40, 20+wantOptLen)
			tcp = pkt[ihl:]
			tcpHL = 20 + wantOptLen
			optLen = wantOptLen
		}
		modified = true
	}

	// === Linux ECN SYN-ACK: 12-byte opts without timestamps (O=M5B4NNSNW7) ===
	// Fires when the client's SYN had NO timestamp (nmap's ECN probe) — that, not the
	// ECE bit, is what makes a real Linux ECN SYN-ACK omit the TS option. The growth
	// block above is suppressed for this flow, so optLen is still 12 here.
	if isSYNACK && p.ecnEcho && haveFlow && !flow.hadTS && p.windowScale > 0 && p.optionsCount > 0 && optLen >= 12 && len(tcp) >= 20+optLen {
		// nmap ECN W=: Linux advertises a distinct rwnd on the ECN-probe SYN-ACK
		// (FAF0, not the FE88 of the OS probes). The general window-set above stamped
		// windowSize; override it here for the ECN probe only.
		if p.ecnWindow != 0 && binary.BigEndian.Uint16(tcp[14:16]) != p.ecnWindow {
			binary.BigEndian.PutUint16(tcp[14:16], p.ecnWindow)
			modified = true
		}
		old := tcp[20 : 20+optLen]
		mss := p.mss
		if old[0] == optMSS && old[1] == 4 {
			mss = binary.BigEndian.Uint16(old[2:4])
		}
		hadSACK := false
		for i := 0; i+1 < len(old); i++ {
			if old[i] == optSACKPerm {
				hadSACK = true
				break
			}
		}
		var no [12]byte
		for i := range no {
			no[i] = optNOP
		}
		putMSS(no[:], 0, mss)
		no[4], no[5] = optNOP, optNOP
		if p.sackPermitted && hadSACK {
			no[6], no[7] = optSACKPerm, 2
		}
		no[8] = optNOP
		no[9], no[10], no[11] = optWScale, 3, p.windowScale
		copy(tcp[20:32], no[:])
		for i := 32; i < 20+optLen; i++ {
			tcp[i] = optNOP
		}
		modified = true
	}

	// === 12-byte ECN-probe options template (outbound SYN) ===
	if optLen == 12 && p.windowScale > 0 && p.optionsCount > 0 && isSynPhase && !isSYNACK && len(tcp) >= 32 {
		old := tcp[20:32]
		mss := p.mss
		if old[0] == optMSS && old[1] == 4 {
			mss = binary.BigEndian.Uint16(old[2:4])
		}
		hadSACK := old[2] == optSACKPerm || old[4] == optSACKPerm || old[6] == optSACKPerm ||
			old[8] == optSACKPerm || old[10] == optSACKPerm
		var no [12]byte
		for i := range no {
			no[i] = optNOP
		}
		putMSS(no[:], 0, mss)
		if p.ecnEcho {
			// Linux ECN: MSS, NOP, NOP, SACK, NOP, WS → O=M5B4NNSNW7 (not NSNW7N)
			no[4], no[5] = optNOP, optNOP
			if p.sackPermitted && hadSACK {
				no[6], no[7] = optSACKPerm, 2
			}
			no[8] = optNOP
			if p.windowScale > 0 {
				no[9], no[10], no[11] = optWScale, 3, p.windowScale
			}
		} else {
			// Windows: MSS, NOP, WS, NOP, NOP, SACK → O=M5B4NW8NNS
			no[4] = optNOP
			no[5], no[6], no[7] = optWScale, 3, p.windowScale
			no[8], no[9] = optNOP, optNOP
			if p.sackPermitted && hadSACK {
				no[10], no[11] = optSACKPerm, 2
			}
		}
		copy(tcp[20:32], no[:])
		modified = true
	}

	// === 16-byte options (O6: no WS): override W6 window + TSval ===
	if optLen == 16 && p.tcpTimestamps && isSynPhase && len(tcp) >= 36 {
		if p.windowSize == 0xFFFF {
			if binary.BigEndian.Uint16(tcp[14:16]) != 0xFFDC {
				binary.BigEndian.PutUint16(tcp[14:16], 0xFFDC)
				modified = true
			}
		}
		// options offset 6 = tcp[26]; TS option there → TSval at tcp[28:32]
		if tcp[26] == optTimestamp && tcp[27] == olenTimestamp {
			binary.BigEndian.PutUint32(tcp[28:32], uptimeMs())
			modified = true
		}
	}

	// === 16-byte O6 for a NO-TS Windows profile: normalize to M5B4NNS (8 bytes) ===
	// A real no-TS Windows box answers the P6 (no-WS) probe with MSS,NOP,NOP,SACK
	// (nmap-os-db O6=M5B4NNS). A TS-reflecting host echoes nmap's TS → a 16-byte
	// M5B4ST11 O6; rewrite + shrink so O6 matches on ANY host.
	if optLen == 16 && isSynPhase && p.winQuirks && !p.tcpTimestamps && len(tcp) >= 36 {
		// O6 window (no window scale option in the probe): a 65535-window no-TS Windows
		// Server (2019) advertises FF70 on this probe, not the scaled FFFF (nmap W6=FF70).
		if p.windowSize == 0xFFFF && binary.BigEndian.Uint16(tcp[14:16]) != 0xFF70 {
			binary.BigEndian.PutUint16(tcp[14:16], 0xFF70)
			modified = true
		}
		mss := p.mss
		if tcp[20] == optMSS && tcp[21] == 4 {
			mss = binary.BigEndian.Uint16(tcp[22:24])
		}
		var no8 [8]byte
		putMSS(no8[:], 0, mss)
		no8[4], no8[5] = optNOP, optNOP
		if p.sackPermitted {
			no8[6], no8[7] = optSACKPerm, 2
		} else {
			no8[6], no8[7] = optNOP, optNOP
		}
		copy(tcp[20:28], no8[:])
		pkt = shrinkTCPHeader(pkt, ihl, 36, 28)
		tcp = pkt[ihl:]
		tcpHL = 28
		optLen = 8
		modified = true
	}

	// === TS coherence for established data / pure-ACK (NOP,NOP,TS = 12 bytes) ===
	if optLen == 12 && !isSYN && p.tcpTimestamps && p.windowScale > 0 && len(tcp) >= 32 {
		if tcp[20] == optNOP && tcp[21] == optNOP && tcp[22] == optTimestamp && tcp[23] == olenTimestamp {
			binary.BigEndian.PutUint32(tcp[24:28], uptimeMs()) // TSval; TSecr (28:32) preserved
			modified = true
		}
	}

	// === RST: enforce window 0 (window_in_rst) ===
	if flags&0x04 != 0 && p.windowInRST == 0 {
		if binary.BigEndian.Uint16(tcp[14:16]) != 0 {
			binary.BigEndian.PutUint16(tcp[14:16], 0)
			modified = true
		}
	}

	// === OPS ST11: non-zero TSval on SYN-ACK timestamp options ===
	if isSYNACK && p.tcpTimestamps && p.opt1 == optSACKPerm && optLen > 0 {
		if patchSynAckTSval(tcp, optLen) {
			modified = true
		}
	}

	// === ECN CC: clear ECE → CC=N (Windows workstation); set ECE → CC=Y (Linux/macOS
	// + Windows Server via explicit_congestion: echo). Driven by ecnCC, NOT ecnEcho. ===
	if flags&0x12 == 0x12 && flags&0x40 != 0 && !p.ecnCC {
		tcp[13] = flags &^ 0x40
		modified = true
	}
	if p.ecnCC && flags&0x12 == 0x12 && flags&0x40 == 0 {
		tcp[13] = flags | 0x40
		modified = true
	}

	return pkt, modified
}

// applyPortUnreachable shapes outbound ICMP type-3/code-3 (U1) on egress: TTL and
// outer DF only. The QUOTE is left verbatim — nmap's U1 expects the offending
// datagram quoted unmodified (RIPL/RID/RIPCK/RUCK/RUD all = G); rewriting the
// quoted header (length cap, TTL, DF) corrupted its checksum (RIPCK=I) and its
// length (RIPL/IPL wrong). The netfilter responder already builds the full verbatim
// quote; here we only correct the OUTER IP fields the general egress path set wrong.
func applyPortUnreachable(pkt []byte, ihl int, p *winProfile) bool {
	if len(pkt) < ihl+8 {
		return false
	}
	modified := false
	if p.ttl > 0 && pkt[8] != p.ttl {
		pkt[8] = p.ttl
		modified = true
	}
	fo := binary.BigEndian.Uint16(pkt[6:8])
	if fo&0x4000 != 0 { // Linux U1 outer DFI=N
		binary.BigEndian.PutUint16(pkt[6:8], fo&^0x4000)
		modified = true
	}
	return modified
}

// applyICMP clears DF (Windows IE DFI=N / U1 DF=N) and forces echo-reply code 0
// (Windows CD=Z). Port of the ICMP block in fingerprint.c at IP offset 0.
func applyICMP(pkt []byte, ihl int, winQuirks bool) bool {
	modified := false
	fo := binary.BigEndian.Uint16(pkt[6:8])
	if fo&0x4000 != 0 { // DF-clear: both Windows (DFI=N) and Linux ICMP, so ungated
		binary.BigEndian.PutUint16(pkt[6:8], fo&^0x4000)
		modified = true
	}
	// Force echo-reply code 0 (Windows CD=Z) only for Windows profiles; Linux
	// echoes the request code (CD=S), so a Linux profile leaves it (#13).
	if winQuirks && len(pkt) >= ihl+2 {
		if pkt[ihl] == 0 && pkt[ihl+1] != 0 {
			pkt[ihl+1] = 0
			modified = true
		}
	}
	return modified
}

// TCP option kinds/lengths (mirror fingerprint.c).
const (
	optEOL        = 0
	optNOP        = 1
	optMSS        = 2
	optWScale     = 3
	optSACKPerm   = 4
	optSACK       = 5
	optTimestamp  = 8
	olenTimestamp = 10
)

// patchSynAckTSval forces a non-zero TSval on SYN-ACK (ST10 → ST11 for nmap OPS).
func patchSynAckTSval(tcp []byte, optLen int) bool {
	if len(tcp) < 20+optLen {
		return false
	}
	modified := false
	for off := 20; off+olenTimestamp <= 20+optLen; {
		kind := tcp[off]
		if kind == optNOP {
			off++
			continue
		}
		if kind == optEOL {
			break
		}
		olen := int(tcp[off+1])
		if olen < 2 {
			off++
			continue
		}
		if kind == optTimestamp && olen == olenTimestamp && off+olenTimestamp <= 20+optLen {
			binary.BigEndian.PutUint32(tcp[off+2:off+6], uptimeMs())
			modified = true
		}
		off += olen
	}
	return modified
}

// putMSS writes an MSS option (kind, len=4, value) at off within b.
func putMSS(b []byte, off int, mss uint16) {
	b[off] = optMSS
	b[off+1] = 4
	binary.BigEndian.PutUint16(b[off+2:off+4], mss)
}

// tcpOptKind maps a profile option-order string to its TCP option kind.
func tcpOptKind(s string) uint8 {
	switch strings.ToLower(s) {
	case "mss":
		return optMSS
	case "nop":
		return optNOP
	case "window_scale", "wscale":
		return optWScale
	case "sack_permitted", "sack_perm", "sack":
		return optSACKPerm
	case "timestamp", "timestamps":
		return optTimestamp
	case "eol":
		return optEOL
	default:
		return optNOP
	}
}
