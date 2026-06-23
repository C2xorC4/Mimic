//go:build !linux

package control

import "net"

// The control plane uses a unix socket with SO_PEERCRED for peer authentication;
// the Windows named-pipe transport (with its own peer-identity mechanism) is a
// future addition. Until then Start returns ErrUnsupported and the orchestrator
// runs without a control plane.
func listen(socket string) (net.Listener, error) { return nil, ErrUnsupported }

func peerCred(conn net.Conn) (Peer, error) { return Peer{}, nil }

func cleanupSocket(socket string) {}

// Supported reports whether the control plane has a transport on this platform.
func Supported() bool { return false }
