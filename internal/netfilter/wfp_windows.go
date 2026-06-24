//go:build windows

package netfilter

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Filtering Platform (WFP) permit for outbound ICMP error messages.
//
// PROBLEM: mimic synthesizes ICMP type-3 (port-unreachable) for the nmap U1 probe
// and injects it via WinDivert. WinDivertSend succeeds, but the packet never hits
// the wire while the Windows Firewall is on — WFP drops it at
// FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 because it is an UNSOLICITED ICMP error with no
// tracked flow (WinDivert swallowed the inbound UDP before the stack saw it). A
// plain `netsh advfirewall ... allow` outbound rule does NOT override this stateful
// drop (proven 2026-06-24: only fully disabling the firewall let the type-3 out).
//
// FIX: install a HARD-PERMIT filter (FWP_ACTION_PERMIT + CLEAR_ACTION_RIGHT) at the
// outbound ICMP-error layer, inside our OWN max-weight sublayer so it is evaluated
// before the firewall's sublayer and its permit cannot be overridden. The objects
// are added in a DYNAMIC WFP session, so the BFE auto-removes them when the engine
// handle closes — or when the mimic process dies (crash-safe; no host state leaks).

// fwpuclnt.dll bindings.
var (
	fwpuclnt              = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0   = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0  = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0  = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0    = fwpuclnt.NewProc("FwpmFilterAdd0")
)

const (
	rpcCAuthnWinNT                  = 10
	fwpmSessionFlagDynamic          = 0x00000001
	fwpActionPermit                 = 0x1002
	fwpmFilterFlagClearActionRight  = 0x00000008
	fwpEmpty                        = 0
)

// GUID layout MUST match C (Data1 is a ULONG → 4-byte alignment for the whole GUID).
type wfpGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4 {41390100-564c-4b32-bc1d-718048354d7c}.
var layerOutboundICMPErrorV4 = wfpGUID{0x41390100, 0x564c, 0x4b32, [8]byte{0xbc, 0x1d, 0x71, 0x80, 0x48, 0x35, 0x4d, 0x7c}}

// Mimic's private sublayer key (arbitrary fixed GUID).
var mimicSublayerKey = wfpGUID{0x7a8b9c0d, 0x1e2f, 0x3a4b, [8]byte{0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3}}

type wfpDisplayData struct {
	name *uint16
	desc *uint16
}

type wfpByteBlob struct {
	size uint32
	data *byte
}

// FWP_VALUE0: type (enum, 4) + pad + 8-byte union slot.
type fwpValue0 struct {
	typ uint32
	_   uint32
	val uint64
}

// FWPM_ACTION0: type (4) + GUID (4-aligned).
type fwpmAction0 struct {
	typ        uint32
	filterType wfpGUID
}

// FWPM_SESSION0 (72 bytes on x64). We only set flags (dynamic).
type fwpmSession0 struct {
	sessionKey           wfpGUID
	displayData          wfpDisplayData
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processId            uint32
	_                    uint32
	sid                  uintptr
	username             *uint16
	kernelMode           int32
	_                    int32
}

// FWPM_SUBLAYER0 (72 bytes on x64).
type fwpmSublayer0 struct {
	subLayerKey  wfpGUID
	displayData  wfpDisplayData
	flags        uint16
	providerKey  uintptr
	providerData wfpByteBlob
	weight       uint16
}

// FWPM_FILTER0 (200 bytes on x64). The union (rawContext/providerContextKey) is a
// GUID-sized 16-byte slot — two uint64s here, both zero (no provider context).
type fwpmFilter0 struct {
	filterKey           wfpGUID
	displayData         wfpDisplayData
	flags               uint32
	providerKey         uintptr
	providerData        wfpByteBlob
	layerKey            wfpGUID
	subLayerKey         wfpGUID
	weight              fwpValue0
	numFilterConditions uint32
	_                   uint32
	filterCondition     uintptr
	action              fwpmAction0
	rawContext          uint64
	_                   uint64
	reserved            uintptr
	filterId            uint64
	effectiveWeight     fwpValue0
}

// wfpICMPPermit holds the dynamic WFP engine handle keeping the permit alive.
type wfpICMPPermit struct {
	engine windows.Handle
}

// installWFPICMPErrorPermit opens a dynamic WFP session and adds a hard-permit for
// all outbound ICMPv4 error messages, overriding the firewall's stateful drop so
// mimic's injected U1 type-3 reaches the wire. Returns a handle whose Close()
// removes the permit (auto-removed too if the process dies).
func installWFPICMPErrorPermit() (*wfpICMPPermit, error) {
	if err := fwpuclnt.Load(); err != nil {
		return nil, fmt.Errorf("load fwpuclnt.dll: %w", err)
	}
	session := fwpmSession0{flags: fwpmSessionFlagDynamic}
	var engine windows.Handle
	r, _, _ := procFwpmEngineOpen0.Call(
		0, // serverName = NULL (local)
		uintptr(rpcCAuthnWinNT),
		0, // authIdentity = NULL
		uintptr(unsafe.Pointer(&session)),
		uintptr(unsafe.Pointer(&engine)),
	)
	if r != 0 {
		return nil, fmt.Errorf("FwpmEngineOpen0: error 0x%x", r)
	}

	subName, _ := windows.UTF16PtrFromString("Mimic ICMP-error permit")
	sub := fwpmSublayer0{
		subLayerKey: mimicSublayerKey,
		displayData: wfpDisplayData{name: subName},
		weight:      0xFFFF, // max → evaluated before the firewall's sublayer
	}
	r, _, _ = procFwpmSubLayerAdd0.Call(
		uintptr(engine),
		uintptr(unsafe.Pointer(&sub)),
		0, // security descriptor = NULL
	)
	if r != 0 {
		procFwpmEngineClose0.Call(uintptr(engine))
		return nil, fmt.Errorf("FwpmSubLayerAdd0: error 0x%x", r)
	}

	fltName, _ := windows.UTF16PtrFromString("Mimic outbound ICMP-error permit")
	filter := fwpmFilter0{
		displayData: wfpDisplayData{name: fltName},
		flags:       fwpmFilterFlagClearActionRight, // hard permit
		layerKey:    layerOutboundICMPErrorV4,
		subLayerKey: mimicSublayerKey,
	}
	filter.weight.typ = fwpEmpty // sole filter in our sublayer → auto weight is fine
	filter.action.typ = fwpActionPermit
	var filterID uint64
	r, _, _ = procFwpmFilterAdd0.Call(
		uintptr(engine),
		uintptr(unsafe.Pointer(&filter)),
		0, // security descriptor = NULL
		uintptr(unsafe.Pointer(&filterID)),
	)
	if r != 0 {
		procFwpmEngineClose0.Call(uintptr(engine))
		return nil, fmt.Errorf("FwpmFilterAdd0: error 0x%x", r)
	}
	return &wfpICMPPermit{engine: engine}, nil
}

func (w *wfpICMPPermit) Close() {
	if w == nil || w.engine == 0 {
		return
	}
	procFwpmEngineClose0.Call(uintptr(w.engine)) // dynamic session → removes sublayer+filter
	w.engine = 0
}
