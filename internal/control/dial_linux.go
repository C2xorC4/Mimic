//go:build linux

package control

import (
	"net"
	"time"
)

// Dial connects to the control plane on a unix socket.
func Dial(endpoint string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", endpoint, timeout)
}