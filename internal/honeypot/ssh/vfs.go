package ssh

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// vnode is a node in the honeypot's in-memory Linux filesystem. It is a Linux-
// shaped view (unlike the Windows-oriented internal/deception tree the SMB/FTP
// honeypots use) so the SSH pseudo-shell presents coherent /etc, /home, /var
// paths. Built once per Server from the active distro identity + seeded creds.
type vnode struct {
	name     string
	dir      bool
	content  []byte
	mode     string // ls -l mode column, e.g. "drwxr-xr-x" / "-rw-r--r--"
	owner    string // user:group, e.g. "root root"
	mtime    time.Time
	children map[string]*vnode
}

func dirNode(name string) *vnode {
	return &vnode{name: name, dir: true, mode: "drwxr-xr-x", owner: "root root",
		mtime: vfsTime(), children: map[string]*vnode{}}
}

func fileNode(name, mode, owner, content string) *vnode {
	return &vnode{name: name, mode: mode, owner: owner, content: []byte(content), mtime: vfsTime()}
}

func vfsTime() time.Time { return time.Date(2026, 3, 12, 9, 21, 0, 0, time.UTC) }

func (n *vnode) size() int64 {
	if n.dir {
		return 4096
	}
	return int64(len(n.content))
}

// distroInfo carries the per-distro identity strings, grounded in the Phase-2.0
// nmap captures (captures/proxmox/<distro>/). The SSH banner is what nmap -sV and
// ssh2-enum-algos read; uname/os-release back the pseudo-shell.
type distroInfo struct {
	sshBanner  string // full "SSH-2.0-OpenSSH_..." server version
	prettyName string // /etc/os-release PRETTY_NAME
	osID       string // /etc/os-release ID
	kernel     string // uname -r
}

// distroFor maps a profile name/family to its identity. Keys match substrings of
// the profile Name (case-insensitive); falls back to a generic modern Linux.
func distroFor(osName string) distroInfo {
	n := strings.ToLower(osName)
	switch {
	case strings.Contains(n, "ubuntu"):
		return distroInfo{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15",
			"Ubuntu 22.04.5 LTS", "ubuntu", "5.15.0-119-generic"}
	case strings.Contains(n, "debian"):
		return distroInfo{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
			"Debian GNU/Linux 12 (bookworm)", "debian", "6.1.0-26-amd64"}
	case strings.Contains(n, "rocky"), strings.Contains(n, "rhel"), strings.Contains(n, "alma"), strings.Contains(n, "centos"):
		return distroInfo{"SSH-2.0-OpenSSH_8.7",
			"Rocky Linux 9.4 (Blue Onyx)", "rocky", "5.14.0-427.el9.x86_64"}
	case strings.Contains(n, "fedora"):
		return distroInfo{"SSH-2.0-OpenSSH_9.6p1",
			"Fedora Linux 40 (Server Edition)", "fedora", "6.8.5-301.fc40.x86_64"}
	case strings.Contains(n, "arch"):
		return distroInfo{"SSH-2.0-OpenSSH_9.8",
			"Arch Linux", "arch", "6.10.6-arch1-1"}
	case strings.Contains(n, "kali"):
		return distroInfo{"SSH-2.0-OpenSSH_9.8p1 Debian-2",
			"Kali GNU/Linux Rolling", "kali", "6.10.11-amd64"}
	default:
		return distroInfo{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15",
			"Ubuntu 22.04.5 LTS", "ubuntu", "5.15.0-119-generic"}
	}
}

// buildVFS assembles the Linux filesystem skeleton for the given identity. users
// are the login accounts (each gets a /home dir); baitFiles maps an absolute path
// to its content (the cred-leak breadcrumbs). Returns the root ("/") node.
func buildVFS(d distroInfo, hostname string, users []string, baitFiles map[string]string) *vnode {
	root := dirNode("/")

	osRelease := fmt.Sprintf("PRETTY_NAME=%q\nNAME=%q\nID=%s\nVERSION_ID=%q\nHOME_URL=\"https://%s.org/\"\n",
		d.prettyName, strings.SplitN(d.prettyName, " ", 2)[0], d.osID, "", d.osID)

	etc := dirNode("etc")
	etc.children["os-release"] = fileNode("os-release", "-rw-r--r--", "root root", osRelease)
	etc.children["hostname"] = fileNode("hostname", "-rw-r--r--", "root root", hostname+"\n")
	etc.children["passwd"] = fileNode("passwd", "-rw-r--r--", "root root", buildPasswd(users))
	etc.children["issue"] = fileNode("issue", "-rw-r--r--", "root root", d.prettyName+" \\n \\l\n")
	root.children["etc"] = etc

	home := dirNode("home")
	for _, u := range users {
		if u == "root" {
			continue
		}
		uh := dirNode(u)
		uh.mode, uh.owner = "drwxr-xr-x", u+" "+u
		uh.children[".bashrc"] = fileNode(".bashrc", "-rw-r--r--", u+" "+u, "# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\$ '\n")
		uh.children[".bash_history"] = fileNode(".bash_history", "-rw-------", u+" "+u, "ls -la\nsudo systemctl status\ncat /etc/os-release\n")
		home.children[u] = uh
	}
	root.children["home"] = home

	rootHome := dirNode("root")
	rootHome.mode = "drwx------"
	root.children["root"] = rootHome

	varDir := dirNode("var")
	logDir := dirNode("log")
	logDir.children["auth.log"] = fileNode("auth.log", "-rw-r-----", "syslog adm",
		"Accepted publickey for root from 10.0.0.5 port 51000 ssh2\n")
	logDir.children["syslog"] = fileNode("syslog", "-rw-r-----", "syslog adm", "system boot\n")
	varDir.children["log"] = logDir
	root.children["var"] = varDir

	root.children["tmp"] = dirNode("tmp")
	root.children["tmp"].mode = "drwxrwxrwt"

	// Cred-leak breadcrumbs: write each bait file at its path, creating parents.
	for p, content := range baitFiles {
		placeFile(root, p, content)
	}
	return root
}

func buildPasswd(users []string) string {
	var b strings.Builder
	b.WriteString("root:x:0:0:root:/root:/bin/bash\n")
	b.WriteString("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
	b.WriteString("www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
	uid := 1000
	for _, u := range users {
		if u == "root" {
			continue
		}
		b.WriteString(fmt.Sprintf("%s:x:%d:%d:%s:/home/%s:/bin/bash\n", u, uid, uid, u, u))
		uid++
	}
	return b.String()
}

// placeFile inserts a file at an absolute path, creating intermediate dirs.
func placeFile(root *vnode, abs, content string) {
	parts := splitPath(abs)
	if len(parts) == 0 {
		return
	}
	cur := root
	for _, seg := range parts[:len(parts)-1] {
		nx, ok := cur.children[seg]
		if !ok || !nx.dir {
			nx = dirNode(seg)
			cur.children[seg] = nx
		}
		cur = nx
	}
	name := parts[len(parts)-1]
	cur.children[name] = fileNode(name, "-rw-r--r--", "root root", content)
}

// splitPath splits an absolute path into clean segments ("" for root).
func splitPath(p string) []string {
	var out []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	return out
}

// resolve walks from root to the node at abs (already cleaned). nil if absent.
func (root *vnode) resolve(abs string) *vnode {
	cur := root
	for _, seg := range splitPath(abs) {
		if !cur.dir {
			return nil
		}
		nx, ok := cur.children[seg]
		if !ok {
			return nil
		}
		cur = nx
	}
	return cur
}

// childNames returns sorted child names of a dir node.
func (n *vnode) childNames() []string {
	names := make([]string, 0, len(n.children))
	for k := range n.children {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
