//go:build windows

package platform

import "fmt"

// WinDivertInstallHint tells operators how to supply WinDivert for stack spoofing
// and the Windows persona firewall.
const WinDivertInstallHint = "WinDivert 2.x required on Windows: copy WinDivert.dll and WinDivert64.sys (x64, same folder as mimic.exe). " +
	"Download: https://github.com/basil00/Divert/releases — without these files mimic runs service emulation + control only."

// FormatWinDivertLoadError wraps a WinDivert.dll load/open failure with WinDivertInstallHint.
func FormatWinDivertLoadError(context string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w — %s", context, err, WinDivertInstallHint)
}