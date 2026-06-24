//go:build !linux && !windows

package control

import "net"

// The control plane is implemented on Linux (unix socket) and Windows (named
// pipe). Other platforms return ErrUnsupported until a transport is added.
func listen(socket string) (net.Listener, error) { return nil, ErrUnsupported }

func peerCred(conn net.Conn) (Peer, error) { return Peer{}, nil }

func cleanupSocket(socket string) {}

// Supported reports whether the control plane has a transport on this platform.
func Supported() bool { return false }