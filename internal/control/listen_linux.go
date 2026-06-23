//go:build linux

package control

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// listen opens the control unix socket. Mode 0660 means owner + group can
// connect; combined with the socket's group ownership this is itself an
// access-control lever (the RBAC role gids should align with that group). Any
// stale socket from a prior run is removed first.
func listen(socket string) (net.Listener, error) {
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("control socket %s: %w", socket, err)
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod control socket: %w", err)
	}
	return ln, nil
}

// peerCred reads the connecting process's unix credentials (SO_PEERCRED) — the
// kernel-attested uid/gid the Authorizer maps to a role.
func peerCred(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, fmt.Errorf("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if cerr != nil {
		return Peer{}, cerr
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

func cleanupSocket(socket string) {
	if socket != "" {
		_ = os.Remove(socket)
	}
}

// Supported reports whether the control plane has a transport on this platform.
func Supported() bool { return true }
