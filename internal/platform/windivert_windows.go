//go:build windows

package platform

import "fmt"

// WinDivertInstallHint tells operators how to supply WinDivert for stack spoofing
// and the Windows persona firewall.
const WinDivertInstallHint = "WinDivert 2.x required on Windows: copy WinDivert.dll and WinDivert64.sys (x64, same folder as mimic.exe). " +
	"Download: https://github.com/basil00/Divert/releases — without these files mimic runs service emulation + control only."

// HighFidelityInstallHint tells operators what the opt-in high-fidelity tier needs.
// The driver reaches below the Windows IP transmit re-stamp so a Linux persona emits
// IP-ID 0 (nmap TI/CI=Z) — unreachable on default WinDivert. It is a kernel driver and
// (in a lab) requires test-signing, a deliberate intrusiveness trade kept off by default.
const HighFidelityInstallHint = "high_fidelity requires the mimic-hifi NDIS driver installed + loaded " +
	"(lab: self-signed + 'bcdedit /set testsigning on' + reboot; weakens Secure Boot). " +
	"Without it, mimic falls back to WinDivert (Linux personas read TI/CI=I, ~95% not exact)."

// FormatWinDivertLoadError wraps a WinDivert.dll load/open failure with WinDivertInstallHint.
func FormatWinDivertLoadError(context string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w — %s", context, err, WinDivertInstallHint)
}