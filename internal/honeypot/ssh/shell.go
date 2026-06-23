package ssh

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	xterm "golang.org/x/term"

	"github.com/c2xorc4/mimic/internal/events"
)

// shellSession is per-session shell state.
type shellSession struct {
	user string
	cwd  string // absolute, cleaned
}

// runShell drives the interactive pseudo-shell over the channel using a real
// terminal (echo + line editing). It returns when the client disconnects or runs
// `exit`. The VFS is the Server's; the session carries cwd/user.
func (s *Server) runShell(ch io.ReadWriter, sess *shellSession, remote string) {
	t := xterm.NewTerminal(ch, s.prompt(sess))
	// A plausible Ubuntu/Debian-style login MOTD.
	t.Write([]byte(fmt.Sprintf("Welcome to %s (GNU/Linux %s x86_64)\r\n\r\n", s.distro.prettyName, s.distro.kernel)))
	s.emit(remote, events.Event{Type: events.Connection, Severity: events.SevWarn, Message: "SSH shell opened",
		Fields: map[string]interface{}{"username": sess.user}})
	for {
		line, err := t.ReadLine()
		if err != nil { // EOF / Ctrl-D / disconnect
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "logout" {
			t.Write([]byte("logout\r\n"))
			return
		}
		out := s.runCommand(sess, line, remote)
		if out != "" {
			t.Write([]byte(normalizeNL(out)))
		}
		t.SetPrompt(s.prompt(sess))
	}
}

// prompt renders the shell prompt (# for root, $ otherwise; ~ for home).
func (s *Server) prompt(sess *shellSession) string {
	sym := "$"
	if strings.EqualFold(sess.user, "root") {
		sym = "#"
	}
	disp := sess.cwd
	home := s.homeFor(sess.user)
	if disp == home {
		disp = "~"
	} else if strings.HasPrefix(disp, home+"/") {
		disp = "~" + disp[len(home):]
	}
	return fmt.Sprintf("%s@%s:%s%s ", sess.user, s.host, disp, sym)
}

// runCommand parses and executes one command line, returning its stdout. It also
// emits recon (Enumeration) and file-read (FileDownload) events.
func (s *Server) runCommand(sess *shellSession, line, remote string) string {
	args := strings.Fields(line)
	if len(args) == 0 {
		return ""
	}
	cmd, rest := args[0], args[1:]
	// Allow a leading `sudo` — the honeypot lets it through (a real captured box
	// would; logging the attempt is the value).
	if cmd == "sudo" && len(rest) > 0 {
		s.emit(remote, events.Event{Type: events.Enumeration, Severity: events.SevWarn, Message: "SSH sudo invoked",
			Fields: map[string]interface{}{"command": line}})
		cmd, rest = rest[0], rest[1:]
	}

	switch cmd {
	case "pwd":
		return sess.cwd + "\n"
	case "whoami":
		return sess.user + "\n"
	case "id":
		return idString(sess.user) + "\n"
	case "hostname":
		return s.host + "\n"
	case "uname":
		return s.uname(rest) + "\n"
	case "echo":
		return strings.Join(rest, " ") + "\n"
	case "cd":
		return s.cmdCd(sess, rest)
	case "ls", "dir":
		s.emit(remote, events.Event{Type: events.Enumeration, Severity: events.SevNotice, Message: "SSH directory listing",
			Fields: map[string]interface{}{"cwd": sess.cwd, "args": strings.Join(rest, " ")}})
		return s.cmdLs(sess, rest)
	case "cat", "less", "more", "head", "tail":
		return s.cmdCat(sess, rest, remote)
	case "help":
		return "Supported: pwd ls cd cat whoami id uname hostname echo exit\n"
	case "clear":
		return "\033[H\033[2J"
	default:
		return cmd + ": command not found\n"
	}
}

func (s *Server) uname(args []string) string {
	long := false
	for _, a := range args {
		if a == "-a" {
			long = true
		} else if a == "-r" {
			return s.distro.kernel
		} else if a == "-s" {
			return "Linux"
		} else if a == "-n" {
			return s.host
		}
	}
	if long {
		return fmt.Sprintf("Linux %s %s #1 SMP PREEMPT_DYNAMIC x86_64 x86_64 x86_64 GNU/Linux", s.host, s.distro.kernel)
	}
	return "Linux"
}

func (s *Server) cmdCd(sess *shellSession, args []string) string {
	target := s.homeFor(sess.user)
	if len(args) > 0 {
		target = resolveAbs(sess.cwd, args[0])
	}
	n := s.vfs().resolve(target)
	if n == nil {
		return "cd: " + strings.Join(args, " ") + ": No such file or directory\n"
	}
	if !n.dir {
		return "cd: " + strings.Join(args, " ") + ": Not a directory\n"
	}
	sess.cwd = target
	return ""
}

func (s *Server) cmdLs(sess *shellSession, args []string) string {
	long, all := false, false
	var pathArg string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "l") {
				long = true
			}
			if strings.Contains(a, "a") {
				all = true
			}
			continue
		}
		pathArg = a
	}
	target := sess.cwd
	if pathArg != "" {
		target = resolveAbs(sess.cwd, pathArg)
	}
	n := s.vfs().resolve(target)
	if n == nil {
		return "ls: cannot access '" + pathArg + "': No such file or directory\n"
	}
	if !n.dir {
		// ls of a file just prints its name.
		if long {
			return lsLong(n) + "\n"
		}
		return n.name + "\n"
	}
	names := n.childNames()
	var out strings.Builder
	for _, nm := range names {
		if !all && strings.HasPrefix(nm, ".") {
			continue
		}
		ch := n.children[nm]
		if long {
			out.WriteString(lsLong(ch) + "\n")
		} else {
			out.WriteString(nm + "\n")
		}
	}
	return out.String()
}

func (s *Server) cmdCat(sess *shellSession, args []string, remote string) string {
	if len(args) == 0 {
		return ""
	}
	var out strings.Builder
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		target := resolveAbs(sess.cwd, a)
		n := s.vfs().resolve(target)
		if n == nil {
			out.WriteString("cat: " + a + ": No such file or directory\n")
			continue
		}
		if n.dir {
			out.WriteString("cat: " + a + ": Is a directory\n")
			continue
		}
		s.emit(remote, events.Event{Type: events.FileDownload, Severity: events.SevWarn, Message: "SSH file read",
			Fields: map[string]interface{}{"path": target}})
		out.Write(n.content)
	}
	return out.String()
}

// lsLong renders one `ls -l` line.
func lsLong(n *vnode) string {
	owner := n.owner
	if owner == "" {
		owner = "root root"
	}
	return fmt.Sprintf("%s 1 %s %6d %s %s", n.mode, owner, n.size(), n.mtime.Format("Jan _2 15:04"), n.name)
}

func idString(user string) string {
	if strings.EqualFold(user, "root") {
		return "uid=0(root) gid=0(root) groups=0(root)"
	}
	return fmt.Sprintf("uid=1000(%s) gid=1000(%s) groups=1000(%s),27(sudo)", user, user, user)
}

// resolveAbs joins arg against cwd into a cleaned absolute path.
func resolveAbs(cwd, arg string) string {
	if strings.HasPrefix(arg, "/") {
		return path.Clean(arg)
	}
	if arg == "~" {
		arg = ""
	}
	return path.Clean(cwd + "/" + arg)
}

// normalizeNL converts bare \n to \r\n for terminal output.
func normalizeNL(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// vfs lazily builds (once) and returns the server's filesystem. Built lazily so
// the user list (for /home + /etc/passwd) reflects the seeded creds.
func (s *Server) vfs() *vnode {
	s.vfsOnce.Do(func() {
		users := []string{"root"}
		for u := range s.creds {
			users = append(users, u)
		}
		sort.Strings(users)
		s.fs = buildVFS(s.distro, s.host, users, s.leak)
	})
	return s.fs
}
