//go:build windows

package control

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// pipeConn is a byte-mode named pipe wrapped as net.Conn for the JSON control protocol.
type pipeConn struct {
	handle windows.Handle
}

func (c *pipeConn) Read(b []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(c.handle, b, &n, nil)
	if err != nil {
		return int(n), err
	}
	return int(n), nil
}

func (c *pipeConn) Write(b []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(c.handle, b, &n, nil)
	if err != nil {
		return int(n), err
	}
	return int(n), nil
}

func (c *pipeConn) Close() error {
	return windows.CloseHandle(c.handle)
}

func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr{} }

func (c *pipeConn) SetDeadline(t time.Time) error       { return errPipeDeadline }
func (c *pipeConn) SetReadDeadline(t time.Time) error   { return errPipeDeadline }
func (c *pipeConn) SetWriteDeadline(t time.Time) error  { return errPipeDeadline }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

var errPipeDeadline = errors.New("pipe deadlines not supported")

// pipeListener accepts local named-pipe connections for the control plane.
type pipeListener struct {
	name    string
	sa      *windows.SecurityAttributes
	closing atomic.Bool
}

func (l *pipeListener) Accept() (net.Conn, error) {
	for {
		if l.closing.Load() {
			return nil, net.ErrClosed
		}
		h, err := windows.CreateNamedPipe(
			windows.StringToUTF16Ptr(l.name),
			windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
			windows.PIPE_UNLIMITED_INSTANCES,
			4096, 4096, 0, l.sa,
		)
		if err != nil {
			if l.closing.Load() {
				return nil, net.ErrClosed
			}
			return nil, err
		}
		err = windows.ConnectNamedPipe(h, nil)
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(h)
			if l.closing.Load() {
				return nil, net.ErrClosed
			}
			continue
		}
		return &pipeConn{handle: h}, nil
	}
}

func (l *pipeListener) Close() error {
	if l.closing.Swap(true) {
		return nil
	}
	// Unblock Accept() waiting in ConnectNamedPipe by opening a throwaway client.
	name := l.name
	go func() {
		c, err := Dial(name, 500*time.Millisecond)
		if err == nil {
			c.Close()
		}
	}()
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

func listen(socket string) (net.Listener, error) {
	name := normalizePipeName(socket)
	sa, err := pipeSecurityAttributes()
	if err != nil {
		return nil, fmt.Errorf("control pipe security: %w", err)
	}
	return &pipeListener{name: name, sa: sa}, nil
}

// normalizePipeName accepts a bare name ("mimic") or a full \\.\pipe\mimic path.
func normalizePipeName(socket string) string {
	s := strings.TrimSpace(socket)
	if s == "" {
		s = DefaultEndpoint()
	}
	if strings.HasPrefix(s, `\\.\pipe\`) {
		return s
	}
	s = strings.TrimPrefix(s, `\\.\pipe`)
	s = strings.Trim(s, `\`)
	return `\\.\pipe\` + s
}

// pipeSecurityAttributes grants authenticated local users read/write (RBAC gates
// operations) while giving SYSTEM and Administrators full control.
func pipeSecurityAttributes() (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString(
		"D:(A;;GRGW;;;AU)(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

func peerCred(conn net.Conn) (Peer, error) {
	pc, ok := conn.(*pipeConn)
	if !ok {
		return Peer{}, fmt.Errorf("not a pipe connection")
	}
	return peerFromPipe(pc.handle)
}

func peerFromPipe(pipe windows.Handle) (Peer, error) {
	var pid uint32
	_ = windows.GetNamedPipeClientProcessId(pipe, &pid)

	// Prefer impersonation — canonical named-pipe client identity and matches what
	// the client actually presented on the wire (incl. UAC elevation state).
	if peer, err := peerFromImpersonatedClient(pipe, int32(pid)); err == nil {
		return peer, nil
	}

	if pid == 0 {
		return Peer{}, fmt.Errorf("named pipe client pid unavailable")
	}
	return peerFromClientPID(pid)
}

func peerFromImpersonatedClient(pipe windows.Handle, pid int32) (Peer, error) {
	if err := impersonateNamedPipeClient(pipe); err != nil {
		return Peer{}, err
	}
	defer windows.RevertToSelf()

	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &token); err != nil {
		return Peer{}, err
	}
	defer token.Close()
	return peerFromToken(token, pid)
}

func peerFromClientPID(pid uint32) (Peer, error) {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Peer{}, err
	}
	defer windows.CloseHandle(proc)

	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return Peer{}, err
	}
	defer token.Close()
	return peerFromToken(token, int32(pid))
}

func impersonateNamedPipeClient(pipe windows.Handle) error {
	r1, _, e := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r1 == 0 {
		if e != nil && e != windows.ERROR_SUCCESS {
			return e
		}
		return windows.Errno(windows.ERROR_ACCESS_DENIED)
	}
	return nil
}

func peerFromToken(token windows.Token, pid int32) (Peer, error) {
	tu, err := token.GetTokenUser()
	if err != nil {
		return Peer{}, err
	}
	peer := Peer{PID: pid, UserSID: tu.User.Sid.String()}

	collectTokenGroups(&peer, token)

	adminSID, err := administratorsSID()
	if err != nil {
		return peer, nil
	}
	defer windows.FreeSid(adminSID)

	if tokenIsAdministrator(token, adminSID) {
		peer.IsAdmin = true
		return peer, nil
	}

	// UAC-filtered Administrator shells expose admin rights on the linked token,
	// not the filtered primary token (IsMember and GroupSIDs both miss it).
	if linked, err := token.GetLinkedToken(); err == nil {
		defer linked.Close()
		collectTokenGroups(&peer, linked)
		if tokenIsAdministrator(linked, adminSID) {
			peer.IsAdmin = true
		}
	}

	return peer, nil
}

func collectTokenGroups(peer *Peer, token windows.Token) {
	tg, err := token.GetTokenGroups()
	if err != nil {
		return
	}
	for _, g := range tg.AllGroups() {
		sid := g.Sid.String()
		if !sidInList(peer.GroupSIDs, sid) {
			peer.GroupSIDs = append(peer.GroupSIDs, sid)
		}
	}
}

// tokenIsAdministrator reports admin membership including UAC deny-only group
// entries (S-1-5-32-544 present but CheckTokenMembership returns false).
func tokenIsAdministrator(token windows.Token, adminSID *windows.SID) bool {
	if member, err := token.IsMember(adminSID); err == nil && member {
		return true
	}
	tg, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, g := range tg.AllGroups() {
		if g.Sid.Equals(adminSID) {
			return true
		}
	}
	return false
}

func sidInList(list []string, sid string) bool {
	for _, s := range list {
		if strings.EqualFold(s, sid) {
			return true
		}
	}
	return false
}

func administratorsSID() (*windows.SID, error) {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return nil, err
	}
	return sid, nil
}

func cleanupSocket(socket string) {}

// Supported reports whether the control plane has a transport on this platform.
func Supported() bool { return true }