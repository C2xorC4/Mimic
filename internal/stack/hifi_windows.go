//go:build windows

package stack

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// hifiCorrector is the userland client for the opt-in "mimic-hifi" kernel driver
// (an NDIS lightweight filter). The driver is the ONLY way to put a literal IP-ID 0
// on the wire for a Linux persona (nmap TI/CI=Z): WinDivert injects at the WFP
// network layer and the Windows IP transmit path re-stamps a 0 Identification from
// the host global counter BELOW that point (validated 2026-06-25). The driver runs
// UNDER WinDivert at the miniport edge and, while ARMED, forces outbound IPv4 TCP
// IP-ID 0 (TI/CI=Z) and ICMP IP-ID incrementing (II=I), then fixes the IP checksum.
//
// Control is a tiny DeviceIoControl channel. The driver defaults to PASS-THROUGH and
// only mutates while armed; closing this handle (or process death) auto-disarms it —
// fail-safe, so a mimic crash never leaves host traffic mangled.
//
// This client compiles and ships before the driver exists: openHifi fails cleanly
// when the device is absent, so the backend logs the posture warning and falls back
// to plain WinDivert. The device path + IOCTLs below are the contract the Phase 2
// driver must match.
type hifiCorrector struct {
	dev windows.Handle
}

// hifiDevicePath is the driver's user-mode symbolic link.
const hifiDevicePath = `\\.\MimicHiFi`

// IOCTL contract (CTL_CODE(FILE_DEVICE_NETWORK=0x12, fn, METHOD_BUFFERED=0, FILE_WRITE_ACCESS=0x2)).
//
//	ARM    fn=0x800  → input: 1 byte mode (1 = Linux persona: TCP IP-ID 0, ICMP increment)
//	DISARM fn=0x801  → no payload
const (
	ioctlHifiArm    = 0x12<<16 | 0x2<<14 | 0x800<<2 // 0x0012A000
	ioctlHifiDisarm = 0x12<<16 | 0x2<<14 | 0x801<<2 // 0x0012A004

	hifiModeLinux = 1
)

// openHifi opens the driver control device. Returns an error (device-not-found) when
// the driver is not installed/loaded — the caller treats that as "fall back to WinDivert".
func openHifi() (*hifiCorrector, error) {
	p, err := windows.UTF16PtrFromString(hifiDevicePath)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", hifiDevicePath, err)
	}
	return &hifiCorrector{dev: h}, nil
}

// Arm tells the driver to start correcting IP-IDs. linuxPersona selects the per-protocol
// mode (TCP→0, ICMP→increment); it is the only mode today.
func (c *hifiCorrector) Arm(linuxPersona bool) error {
	if c == nil || c.dev == windows.InvalidHandle {
		return fmt.Errorf("hifi: not open")
	}
	mode := byte(0)
	if linuxPersona {
		mode = hifiModeLinux
	}
	var ret uint32
	in := []byte{mode}
	return windows.DeviceIoControl(c.dev, ioctlHifiArm,
		&in[0], uint32(len(in)), nil, 0, &ret, nil)
}

// Disarm returns the driver to pass-through.
func (c *hifiCorrector) Disarm() error {
	if c == nil || c.dev == windows.InvalidHandle {
		return nil
	}
	var ret uint32
	return windows.DeviceIoControl(c.dev, ioctlHifiDisarm,
		nil, 0, nil, 0, &ret, nil)
}

// Close releases the control handle; the driver auto-disarms on close (fail-safe).
func (c *hifiCorrector) Close() error {
	if c == nil || c.dev == windows.InvalidHandle {
		return nil
	}
	err := windows.CloseHandle(c.dev)
	c.dev = windows.InvalidHandle
	return err
}
