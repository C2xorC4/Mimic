package ftp

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/c2xorc4/mimic/internal/deception"
)

func testTree() *deception.Tree {
	store := deception.NewCredStore([]deception.Credential{
		{ID: "svc", Username: "svc_backup", Password: "V33m!", Domain: "CORP"},
	})
	cfg := deception.TreeConfig{
		Shares: []deception.ShareDef{
			{Name: "C$", Type: "disk_special", Root: &deception.NodeDefGroup{
				Dirs: []deception.DirDef{{Name: "Users", Dirs: []deception.DirDef{{Name: "Administrator", Dirs: []deception.DirDef{{
					Name: "Documents",
					Files: []deception.FileDef{{Name: "backup_credentials.txt",
						Content: "user={{cred:svc.username}} pass={{cred:svc.password}}"}},
				}}}}}},
			}},
			{Name: "BACKUPS", Type: "disk", Generate: &deception.GenSpec{Seed: "v1", Dirs: deception.Range{Min: 3, Max: 5}, Files: deception.Range{Min: 2, Max: 3}, Depth: 1}},
		},
		Maze: deception.MazeConfig{Enabled: true, MaxDepth: 6, MinDirs: 3, MaxDirs: 5, MinFiles: 2, MaxFiles: 3},
	}
	t, err := deception.BuildTree(cfg, store, "")
	if err != nil {
		panic(err)
	}
	return t
}

func startTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	store := deception.NewCredStore([]deception.Credential{{ID: "svc", Username: "svc_backup", Password: "V33m!"}})
	srv, err := New(Config{Tree: testTree(), AllowAnonymous: true, CredStore: store, RootShare: "C$"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv.cfg.Port = uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return srv, addr
}

// --- minimal FTP client for tests ---

type ftpClient struct {
	conn net.Conn
	r    *bufio.Reader
	t    *testing.T
}

func dial(t *testing.T, addr string) *ftpClient {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c := &ftpClient{conn: conn, r: bufio.NewReader(conn), t: t}
	c.expect(220)
	return c
}

func (c *ftpClient) line() string {
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	s, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read reply: %v", err)
	}
	return strings.TrimRight(s, "\r\n")
}

func (c *ftpClient) expect(code int) string {
	c.t.Helper()
	l := c.line()
	if !strings.HasPrefix(l, strconv.Itoa(code)) {
		c.t.Fatalf("want %d, got %q", code, l)
	}
	return l
}

func (c *ftpClient) cmd(s string, code int) string {
	c.t.Helper()
	c.conn.Write([]byte(s + "\r\n"))
	return c.expect(code)
}

// pasvData sends PASV, dials the data port, returns the data conn.
func (c *ftpClient) pasvData() net.Conn {
	c.t.Helper()
	resp := c.cmd("PASV", 227)
	open := strings.IndexByte(resp, '(')
	close := strings.IndexByte(resp, ')')
	nums := strings.Split(resp[open+1:close], ",")
	if len(nums) != 6 {
		c.t.Fatalf("bad PASV: %q", resp)
	}
	host := strings.Join(nums[:4], ".")
	p1, _ := strconv.Atoi(nums[4])
	p2, _ := strconv.Atoi(nums[5])
	dc, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(p1*256+p2)))
	if err != nil {
		c.t.Fatalf("data dial: %v", err)
	}
	return dc
}

// transfer issues a data command (LIST/NLST/RETR), returns the data payload.
func (c *ftpClient) transfer(command string) string {
	c.t.Helper()
	dc := c.pasvData()
	c.conn.Write([]byte(command + "\r\n"))
	c.expect(150)
	dc.SetReadDeadline(time.Now().Add(3 * time.Second))
	data, _ := io.ReadAll(dc)
	dc.Close()
	c.expect(226)
	return string(data)
}

func TestFTPLoginListRetrieveMaze(t *testing.T) {
	_, addr := startTestServer(t)

	// Anonymous login.
	c := dial(t, addr)
	c.cmd("USER anonymous", 331)
	c.cmd("PASS x@x.com", 230)
	c.cmd("SYST", 215)
	if pwd := c.cmd("PWD", 257); !strings.Contains(pwd, "/") {
		t.Errorf("PWD: %q", pwd)
	}

	// LIST root (C$): should show Users and BACKUPS-less (root is C$, not the share list) — Windows/Users/etc.
	root := c.transfer("LIST")
	if !strings.Contains(root, "Users") {
		t.Errorf("root LIST missing Users:\n%s", root)
	}

	// Navigate to the seeded file's dir and download it.
	c.cmd("CWD /Users/Administrator/Documents", 250)
	doc := c.transfer("LIST")
	if !strings.Contains(doc, "backup_credentials.txt") {
		t.Errorf("Documents LIST missing seeded file:\n%s", doc)
	}
	content := c.transfer("RETR backup_credentials.txt")
	if content != "user=svc_backup pass=V33m!" {
		t.Errorf("RETR content = %q", content)
	}

	// Maze: a non-existent deep dir resolves and lists deterministically.
	c.cmd("CWD /NoSuchVendor/Deep", 250)
	m1 := c.transfer("LIST")
	if strings.Count(m1, "\n") < 2 {
		t.Errorf("maze LIST too small:\n%s", m1)
	}
	c.cmd("QUIT", 221)

	// Seeded-credential login on a fresh connection.
	c2 := dial(t, addr)
	c2.cmd("USER svc_backup", 331)
	c2.cmd("PASS V33m!", 230)
	c2.cmd("QUIT", 221)

	// Wrong password rejected.
	c3 := dial(t, addr)
	c3.cmd("USER svc_backup", 331)
	c3.cmd("PASS wrong", 530)
	c3.cmd("QUIT", 221)
}

func TestFTPRejectsUnauthed(t *testing.T) {
	_, addr := startTestServer(t)
	c := dial(t, addr)
	// LIST before login must be refused.
	c.conn.Write([]byte("LIST\r\n"))
	c.expect(530)
}
