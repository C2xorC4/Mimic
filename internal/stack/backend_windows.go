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

const winFilter = "outbound and ip and (tcp or icmp)"

var procGetTickCount64 = windows.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")

// uptimeMs returns milliseconds since boot — the Windows-authentic TSval clock
// (mirrors fingerprint.c's bpf_ktime_get_ns()/1e6).
func uptimeMs() uint32 {
	r, _, _ := procGetTickCount64.Call()
	return uint32(r)
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
	ecnEcho       bool  // Linux/macOS echo ECE (CC=Y) + keep native ECN opts; Windows clears ECE (#12)
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
	return wp
}

// ipidState is the shared IP-ID counter (single-goroutine; no lock needed).
type ipidState struct {
	counter uint16
	seed    uint32
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
}

// New returns the WinDivert-backed stack backend. iface is accepted for API
// parity but unused — WinDivert intercepts host-wide.
func New(ifaceName string) (Backend, error) {
	return &windowsBackend{iface: ifaceName, done: make(chan struct{}), ipid: ipidState{seed: 0x9e3779b9}}, nil
}

// Available reports that a stack backend exists on Windows.
func Available() bool { return true }

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
	var recvN, outN, modN, sendErr, firstErrLogged uint64
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
		if addr.Outbound() && b.enabled.Load() {
			atomic.AddUint64(&outN, 1)
			if prof := b.profile.Load(); prof != nil {
				if b.applyEgress(pkt, prof) {
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

// applyEgress edits an outbound IPv4 packet (IP header at offset 0) in place to
// match the profile, returning whether anything changed. Port of the egress half
// of fingerprint.c with offsets shifted by the 14-byte Ethernet header it lacks.
func (b *windowsBackend) applyEgress(pkt []byte, p *winProfile) bool {
	if len(pkt) < 20 {
		return false
	}
	if pkt[0]>>4 != 4 { // IPv4 only
		return false
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

	// === IP-ID (shared counter so TCP+ICMP share a sequence; nmap SS=S) ===
	var newID uint16
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
	if binary.BigEndian.Uint16(pkt[4:6]) != newID {
		binary.BigEndian.PutUint16(pkt[4:6], newID)
		modified = true
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 {
		return modified
	}

	switch proto {
	case 6: // TCP
		if b.applyTCP(pkt, ihl, p) {
			modified = true
		}
	case 1: // ICMP
		if applyICMP(pkt, ihl) {
			modified = true
		}
	}
	return modified
}

// applyTCP ports the TCP egress mutations (window, options templates, TS
// coherence, RST window, ECN) at IP-relative offsets.
func (b *windowsBackend) applyTCP(pkt []byte, ihl int, p *winProfile) bool {
	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return false
	}
	tcpHL := int(tcp[12]>>4) * 4
	if tcpHL < 20 || len(tcp) < tcpHL {
		return false
	}
	flags := tcp[13]
	isSYN := flags&0x02 != 0
	optLen := tcpHL - 20
	modified := false

	// === TCP window ===
	if p.windowSize > 0 && binary.BigEndian.Uint16(tcp[14:16]) != p.windowSize {
		binary.BigEndian.PutUint16(tcp[14:16], p.windowSize)
		modified = true
	}

	// === 20-byte SYN/SYN-ACK options template ===
	if optLen == 20 && p.optionsCount > 0 && isSYN && len(tcp) >= 40 {
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
		switch {
		case p.windowScale == 0 && !p.tcpTimestamps:
			// Windows XP: MSS, NOP, NOP, SACK
			putMSS(no[:], 0, mss)
			no[4], no[5] = optNOP, optNOP
			if useSACK {
				no[6], no[7] = optSACKPerm, 2
			}
		case p.windowScale > 0 && !p.tcpTimestamps:
			// Windows 7/10/11: MSS, NOP, WS, NOP, NOP, SACK
			putMSS(no[:], 0, mss)
			no[4] = optNOP
			no[5], no[6], no[7] = optWScale, 3, p.windowScale
			no[8], no[9] = optNOP, optNOP
			if useSACK {
				no[10], no[11] = optSACKPerm, 2
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
		modified = true
	}

	// === 12-byte ECN-probe options template (Windows order; skipped for Linux/macOS — #12) ===
	if optLen == 12 && p.windowScale > 0 && p.optionsCount > 0 && isSYN && !p.ecnEcho && len(tcp) >= 32 {
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
		no[4] = optNOP
		no[5], no[6], no[7] = optWScale, 3, p.windowScale
		no[8], no[9] = optNOP, optNOP
		if p.sackPermitted && hadSACK {
			no[10], no[11] = optSACKPerm, 2
		}
		copy(tcp[20:32], no[:])
		modified = true
	}

	// === 16-byte options (O6: no WS): override W6 window + TSval ===
	if optLen == 16 && p.tcpTimestamps && isSYN && len(tcp) >= 36 {
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

	// === ECN: clear ECE in SYN-ACK (Windows CC=N). Linux/macOS echo ECE (CC=Y) — skip (#12). ===
	if flags&0x12 == 0x12 && flags&0x40 != 0 && !p.ecnEcho {
		tcp[13] = flags &^ 0x40
		modified = true
	}

	return modified
}

// applyICMP clears DF (Windows IE DFI=N / U1 DF=N) and forces echo-reply code 0
// (Windows CD=Z). Port of the ICMP block in fingerprint.c at IP offset 0.
func applyICMP(pkt []byte, ihl int) bool {
	modified := false
	fo := binary.BigEndian.Uint16(pkt[6:8])
	if fo&0x4000 != 0 {
		binary.BigEndian.PutUint16(pkt[6:8], fo&^0x4000)
		modified = true
	}
	if len(pkt) >= ihl+2 {
		// ICMP type at pkt[ihl], code at pkt[ihl+1]. Echo reply type 0.
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
