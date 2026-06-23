//go:build windows

package netfilter

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Minimal drop-only WinDivert bindings for the Windows firewall persona. This is
// a deliberately small subset (Open / Recv / Close) — to DROP a packet we recv it
// (draining it from the stack) and simply never reinject it. The fuller binding
// (Send + CalcChecksums) lives in internal/stack for the egress mutation backend;
// keeping a tiny independent copy here isolates the firewall from the validated
// stack code rather than coupling the two packages.

var (
	wdDLL       = windows.NewLazyDLL("WinDivert.dll")
	procWDOpen  = wdDLL.NewProc("WinDivertOpen")
	procWDRecv  = wdDLL.NewProc("WinDivertRecv")
	procWDClose = wdDLL.NewProc("WinDivertClose")
)

const wdLayerNetwork = 0

// wdAddress mirrors WINDIVERT_ADDRESS (v2.x), 80 bytes. We never read its fields
// here (drop path), but recv writes the full struct, so the size must be exact.
type wdAddress struct {
	Timestamp int64
	Bitfield  uint32
	Reserved2 uint32
	Union     [64]byte
}

type wdHandle struct{ h windows.Handle }

func wdOpen(filter string) (*wdHandle, error) {
	fb, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	r1, _, e := procWDOpen.Call(
		uintptr(unsafe.Pointer(fb)),
		uintptr(wdLayerNetwork),
		uintptr(0), // priority
		uintptr(0), // flags
	)
	h := windows.Handle(r1)
	if h == windows.InvalidHandle {
		return nil, fmt.Errorf("WinDivertOpen(%q): %w", filter, e)
	}
	return &wdHandle{h: h}, nil
}

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

func (w *wdHandle) close() error {
	r1, _, e := procWDClose.Call(uintptr(w.h))
	if r1 == 0 {
		return e
	}
	return nil
}
