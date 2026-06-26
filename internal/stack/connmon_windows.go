//go:build windows

package stack

import (
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/c2xorc4/mimic/internal/logging"
	"golang.org/x/sys/windows"
)

// hifiWatchdog is the connectivity safeguard for the high-fidelity IP-ID driver.
//
// While the driver is armed it actively probes outbound reachability (ICMP echo to the
// interface gateway, or a configured canary). A sustained loss — the signature of a
// driver/offload interaction silently dropping the host's outbound packets — triggers an
// auto-disarm (windowsBackend.watchdogTrip) so the network recovers, trading the
// high-fidelity persona back down to WinDivert.
//
// Design choices that keep this from becoming an attacker-controlled fingerprinting
// oracle (an adversary inducing degradation to force the true OS to show):
//   - It is OPT-OUT per host (high_fidelity_watchdog: false holds the deception).
//   - It requires SUSTAINED failure (watchdogFails consecutive probes over
//     watchdogFails*watchdogInterval), not a single blip.
//   - After it trips it does NOT re-arm for the life of the process (no flapping that an
//     attacker could oscillate); recovery is an explicit restart.
//   - The probe rides the SAME mutated egress path, so it measures exactly what a real
//     peer experiences — not a side channel.
type hifiWatchdog struct {
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

const (
	watchdogInterval = 5 * time.Second // probe cadence while armed
	watchdogFails    = 3               // consecutive failures before auto-disarm (~15s sustained)
	watchdogPingMS   = 1500            // per-probe ICMP timeout (ms)
)

// startHifiWatchdog resolves the probe target and launches the monitor goroutine. Returns
// nil (watchdog inactive) when no target can be determined — fail-safe: with nothing to
// probe we never disarm a working deception on a guess.
func startHifiWatchdog(b *windowsBackend, canary string) *hifiWatchdog {
	log := logging.Component("stackwin")
	target := canary
	if target == "" {
		target = defaultGateway(b.iface)
	}
	if target == "" {
		log.Warn("high_fidelity watchdog enabled but no probe target (no canary configured and no gateway found) — connectivity safeguard INACTIVE; set high_fidelity_canary", nil)
		return nil
	}
	wd := &hifiWatchdog{stopCh: make(chan struct{})}
	wd.wg.Add(1)
	go wd.run(b, target)
	log.Info("high_fidelity connectivity watchdog active", map[string]interface{}{
		"probe": target, "interval": watchdogInterval.String(), "fails_to_disarm": watchdogFails,
	})
	return wd
}

func (wd *hifiWatchdog) stop() {
	wd.stopOnce.Do(func() { close(wd.stopCh) })
	wd.wg.Wait()
}

func (wd *hifiWatchdog) run(b *windowsBackend, target string) {
	defer wd.wg.Done()
	log := logging.Component("stackwin")
	t := time.NewTicker(watchdogInterval)
	defer t.Stop()
	fails := 0
	for {
		select {
		case <-wd.stopCh:
			return
		case <-t.C:
			if icmpReachable(target, watchdogPingMS) {
				if fails > 0 {
					log.Info("high_fidelity watchdog: connectivity recovered", map[string]interface{}{"probe": target})
				}
				fails = 0
				continue
			}
			fails++
			if fails >= watchdogFails {
				b.watchdogTrip() // disarms + marks tripped; we return next
				return
			}
			log.Warn("high_fidelity watchdog: outbound probe failed", map[string]interface{}{
				"probe": target, "consecutive": fails, "disarm_at": watchdogFails,
			})
		}
	}
}

// defaultGateway returns the IPv4 default gateway of the named interface (its friendly
// name, e.g. "Ethernet"); if no name matches, the first up adapter that has a gateway.
// "" if none found.
func defaultGateway(ifaceName string) string {
	const initial = 15000
	size := uint32(initial)
	buf := make([]byte, size)
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, aa, &size)
	if err == windows.ERROR_BUFFER_OVERFLOW {
		buf = make([]byte, size)
		aa = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err = windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, aa, &size)
	}
	if err != nil {
		return ""
	}
	var fallback string
	for ; aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp {
			continue
		}
		var gw string
		for g := aa.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil && ip.To4() != nil {
				gw = ip.String()
				break
			}
		}
		if gw == "" {
			continue
		}
		if ifaceName != "" && eqFold(windows.UTF16PtrToString(aa.FriendlyName), ifaceName) {
			return gw // exact interface match wins
		}
		if fallback == "" {
			fallback = gw
		}
	}
	return fallback
}

func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

var (
	iphlpapi            = windows.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

// icmpReachable pings an IPv4 target via the native IcmpSendEcho (iphlpapi). The echo
// request traverses the host stack → WinDivert → the armed driver, so it measures the
// real mutated egress path. Returns true if at least one reply came back within timeout.
func icmpReachable(ipv4 string, timeoutMS uint32) bool {
	ip := net.ParseIP(ipv4)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) { // INVALID_HANDLE_VALUE
		return false
	}
	defer procIcmpCloseHandle.Call(h)

	dest := uintptr(ip4[0]) | uintptr(ip4[1])<<8 | uintptr(ip4[2])<<16 | uintptr(ip4[3])<<24
	req := [8]byte{'m', 'i', 'm', 'i', 'c', 'h', 'i', 'f'}
	// ICMP_ECHO_REPLY (~28B) + payload + slack for a possible ICMP error; 128B is ample.
	reply := make([]byte, 128)
	n, _, _ := procIcmpSendEcho.Call(
		h,
		dest,
		uintptr(unsafe.Pointer(&req[0])), uintptr(len(req)),
		0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)),
		uintptr(timeoutMS),
	)
	return n != 0 // reply count; 0 = timeout/unreachable
}
