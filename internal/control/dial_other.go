//go:build !linux && !windows

package control

import (
	"net"
	"time"
)

// Dial is unavailable on platforms without a control transport.
func Dial(endpoint string, timeout time.Duration) (net.Conn, error) {
	return nil, ErrUnsupported
}