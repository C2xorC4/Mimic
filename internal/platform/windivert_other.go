//go:build !windows

package platform

import "fmt"

// WinDivertInstallHint is empty on non-Windows platforms.
const WinDivertInstallHint = ""

// FormatWinDivertLoadError is a no-op wrapper on non-Windows platforms.
func FormatWinDivertLoadError(context string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}