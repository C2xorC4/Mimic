//go:build windows

package stack

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Minimal direct bindings to WinDivert 2.x (WinDivert.dll + WinDivert64.sys).
// No third-party module: the surface we need is tiny and we want the layout
// fully inspectable. The .dll and matching .sys driver must sit next to mimic.exe
// (or on PATH/System32); WinDivertOpen loads the signed driver on first use and
// requires Administrator.
//
// We operate at the NETWORK layer: each captured packet starts at the IPv4
// header (no Ethernet), and WinDivertHelperCalcChecksums recomputes IP/TCP/ICMP
// checksums after we edit bytes — so the mutation code never touches checksum math.

var (
	winDivertDLL  = windows.NewLazyDLL("WinDivert.dll")
	procWDOpen    = winDivertDLL.NewProc("WinDivertOpen")
	procWDRecv    = winDivertDLL.NewProc("WinDivertRecv")
	procWDSend    = winDivertDLL.NewProc("WinDivertSend")
	procWDClose   = winDivertDLL.NewProc("WinDivertClose")
	procWDCalcCsm = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
)

// WinDivert layer + flag constants (windivert.h).
const (
	wdLayerNetwork = 0
	wdFlagDefault  = 0
)

// wdAddress mirrors WINDIVERT_ADDRESS (v2.x), 80 bytes:
//
//	INT64  Timestamp;        // 8
//	UINT32 <bitfield>;       // 4  (Layer:8,Event:8,Sniffed:1,Outbound:1,...)
//	UINT32 Reserved2;        // 4
//	union { ... } [64];      // 64 (WINDIVERT_DATA_NETWORK et al.)
//
// We only read the Outbound bit; the rest is carried verbatim from Recv to Send.
type wdAddress struct {
	Timestamp int64
	Bitfield  uint32
	Reserved2 uint32
	Union     [64]byte
}

// Outbound reports the WINDIVERT_ADDRESS.Outbound bit. Within the bitfield uint32:
// Layer:8 (0-7), Event:8 (8-15), Sniffed:1 (16), Outbound:1 (17), ...
func (a *wdAddress) Outbound() bool { return (a.Bitfield>>17)&1 == 1 }

// wdHandle wraps the WinDivert HANDLE.
type wdHandle struct{ h windows.Handle }

// wdOpen opens a WinDivert handle for the given filter at the network layer.
func wdOpen(filter string) (*wdHandle, error) {
	fb, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	r1, _, e := procWDOpen.Call(
		uintptr(unsafe.Pointer(fb)),
		uintptr(wdLayerNetwork),
		uintptr(0), // priority
		uintptr(wdFlagDefault),
	)
	h := windows.Handle(r1)
	if h == windows.InvalidHandle {
		return nil, fmt.Errorf("WinDivertOpen(%q): %w (is WinDivert.dll/.sys present and are we elevated?)", filter, e)
	}
	return &wdHandle{h: h}, nil
}

// recv blocks for the next matching packet, filling buf and addr. Returns the
// number of bytes read.
func (w *wdHandle) recv(buf []byte, addr *wdAddress) (int, error) {
	var recvLen uint32
	r1, _, e := procWDRecv.Call(
		uintptr(w.h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("WinDivertRecv: %w", e)
	}
	return int(recvLen), nil
}

// send reinjects a (possibly modified) packet using the addr from recv.
func (w *wdHandle) send(buf []byte, addr *wdAddress) error {
	var sendLen uint32
	r1, _, e := procWDSend.Call(
		uintptr(w.h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return fmt.Errorf("WinDivertSend: %w", e)
	}
	return nil
}

// calcChecksums recomputes IP/TCP/UDP/ICMP checksums in place after edits.
func (w *wdHandle) calcChecksums(buf []byte, addr *wdAddress) {
	procWDCalcCsm.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(addr)),
		uintptr(0),
	)
}

func (w *wdHandle) close() error {
	r1, _, e := procWDClose.Call(uintptr(w.h))
	if r1 == 0 {
		return e
	}
	return nil
}
