//go:build windows

package control

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/windows"
)

// Dial connects to the control plane on a Windows named pipe.
func Dial(endpoint string, timeout time.Duration) (net.Conn, error) {
	path, err := windows.UTF16PtrFromString(normalizePipeName(endpoint))
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		h, err := windows.CreateFile(
			path,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			0,
			0,
		)
		if err == nil {
			return &pipeConn{handle: h}, nil
		}
		// Pipe may not exist yet (server still starting) or all instances are busy.
		if (err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PIPE_BUSY) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return nil, fmt.Errorf("connecting to control pipe %s: %w", endpoint, err)
	}
}