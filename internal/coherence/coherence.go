// Package coherence performs a startup self-audit for OS/service contradictions —
// the strongest network-deception tell. Mimic can spoof the TCP/IP stack and run
// decoy listeners, but it cannot hide a *real* service running on the host that it
// does not front. In the OSE-2026-001 exercise the single signal that gave the
// deception away was a Linux daemon (vsftpd) answering on a host that fingerprinted
// as Windows 11 (Op-5 FINDING-006).
//
// Check enumerates host-listening TCP ports that are NOT owned by the Mimic process
// and grabs their banners; if a banner contradicts the emulated OS family it warns
// the operator with the specific port, banner, and remediation. It never modifies
// anything — coherence is the operator's to resolve (front the service, relocate
// it, or pick a matching profile).
package coherence

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/c2xorc4/mimic/internal/logging"
)

// nixTells are case-insensitive banner substrings that strongly indicate a
// Unix/Linux host. OpenSSH alone is intentionally excluded (it ships on Windows
// too); the distro suffix it appends ("Ubuntu"/"Debian") is the actual tell.
var nixTells = []string{
	"vsftpd", "proftpd", "pure-ftpd", "ubuntu", "debian", "raspbian",
	"(unix)", "postfix", "exim", "dovecot", "mariadb", " linux",
}

// Check audits foreign (non-Mimic) listeners against the emulated OS family and
// warns on contradictions. family is the active profile family ("windows",
// "linux", "macos"); an empty family (no profile) skips the audit. log may be nil.
// Intended to run in a background goroutine — it performs short, bounded banner
// grabs and never blocks startup.
func Check(family string, log *logging.Logger) {
	family = strings.ToLower(strings.TrimSpace(family))
	if family == "" {
		return
	}

	selfInodes := ownSocketInodes()
	ports := foreignListeningPorts(selfInodes)
	if len(ports) == 0 {
		return
	}

	for _, p := range ports {
		banner := grabBanner(p)
		if banner == "" {
			continue
		}
		if family == "windows" {
			if tell := matchTell(banner); tell != "" {
				warn(log, p, banner, tell)
			}
		}
	}
}

// matchTell returns the first Unix/Linux tell found in banner, or "".
func matchTell(banner string) string {
	low := strings.ToLower(banner)
	for _, t := range nixTells {
		if strings.Contains(low, t) {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

func warn(log *logging.Logger, port uint16, banner, tell string) {
	msg := fmt.Sprintf("OS/service coherence: a non-Mimic service on TCP/%d advertises %q (Unix/Linux tell %q) while the emulated profile is Windows. This contradiction is the strongest deception tell — front the service through Mimic, relocate it, or switch to a matching profile.", port, banner, tell)
	if log != nil {
		log.Warn(msg, map[string]interface{}{"port": port, "banner": banner, "tell": tell})
		return
	}
	fmt.Fprintln(os.Stderr, "[coherence] "+msg)
}

// grabBanner connects to 127.0.0.1:port and returns up to a line of banner text.
// It first waits briefly for a server-speaks-first banner (SSH/FTP/SMTP); if none
// arrives it sends a minimal HTTP HEAD and reads the response (to catch a Server:
// header). Returns "" on any error or empty read.
func grabBanner(port uint16) string {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 512)
	if n, _ := conn.Read(buf); n > 0 {
		return sanitize(buf[:n])
	}

	// No speaks-first banner — try an HTTP HEAD and read the Server header.
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n")); err != nil {
		return ""
	}
	conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	r := bufio.NewReader(conn)
	for i := 0; i < 30; i++ { // scan a bounded number of header lines
		line, err := r.ReadString('\n')
		if s := strings.TrimSpace(line); strings.HasPrefix(strings.ToLower(s), "server:") {
			return sanitize([]byte(s))
		}
		if err != nil {
			break
		}
	}
	return ""
}

// sanitize trims a banner to its first line and strips control characters so the
// log entry is clean and bounded.
func sanitize(b []byte) string {
	s := string(b)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ownSocketInodes returns the set of socket inodes owned by this process, read
// from /proc/self/fd. Listening sockets with these inodes are Mimic's own (decoy
// listeners, honeypots) and are excluded from the audit.
func ownSocketInodes() map[uint64]struct{} {
	out := make(map[uint64]struct{})
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return out
	}
	for _, e := range entries {
		target, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			if ino, err := strconv.ParseUint(target[8:len(target)-1], 10, 64); err == nil {
				out[ino] = struct{}{}
			}
		}
	}
	return out
}

// foreignListeningPorts returns externally-bound TCP listening ports that are NOT
// owned by this process (selfInodes). Loopback-only binds are ignored — they are
// not reachable by a remote scanner and so are not a fingerprint tell.
func foreignListeningPorts(selfInodes map[uint64]struct{}) []uint16 {
	seen := make(map[uint16]struct{})
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		parseProcNetTCP(path, selfInodes, seen)
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out
}

// parseProcNetTCP parses one /proc/net/tcp[6] table, adding externally-bound
// LISTEN ports not owned by selfInodes to dst.
func parseProcNetTCP(path string, selfInodes map[uint64]struct{}, dst map[uint16]struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		// fields: sl local_address rem_address st ... inode(10th, index 9)
		local, st := fields[1], fields[3]
		if st != "0A" { // 0A = TCP_LISTEN
			continue
		}
		ipHex, portHex, ok := splitAddr(local)
		if !ok || isLoopbackHex(ipHex) {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		ino, err := strconv.ParseUint(fields[9], 10, 64)
		if err == nil {
			if _, mine := selfInodes[ino]; mine {
				continue // Mimic's own listener
			}
		}
		dst[uint16(port)] = struct{}{}
	}
}

// splitAddr splits a /proc/net/tcp "HEXIP:HEXPORT" address column.
func splitAddr(s string) (ipHex, portHex string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// isLoopbackHex reports whether the hex IP column is a loopback bind (127.0.0.1
// for IPv4 = "0100007F", ::1 for IPv6 = 31 zeros then "1"). A loopback-only
// listener is not remotely visible, so it is not a deception tell.
func isLoopbackHex(ipHex string) bool {
	switch len(ipHex) {
	case 8: // IPv4, little-endian hex
		return strings.EqualFold(ipHex, "0100007F")
	case 32: // IPv6
		return strings.EqualFold(ipHex, "00000000000000000000000001000000")
	}
	return false
}
