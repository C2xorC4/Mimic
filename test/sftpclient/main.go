// Command sftpclient validates the SSH honeypot's SFTP subsystem: it authenticates
// with a password, opens SFTP, lists a directory, and downloads a file.
//
//	go run ./test/sftpclient <host:port> <user> <pass> <listdir> <getfile>
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) < 6 {
		fmt.Fprintln(os.Stderr, "usage: sftpclient <host:port> <user> <pass> <listdir> <getfile>")
		os.Exit(2)
	}
	addr, user, pass, dir, file := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	cc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 8 * time.Second,
	})
	if err != nil {
		fmt.Println("DIAL/AUTH ERROR:", err)
		os.Exit(1)
	}
	defer cc.Close()
	sc, err := sftp.NewClient(cc)
	if err != nil {
		fmt.Println("SFTP ERROR:", err)
		os.Exit(1)
	}
	defer sc.Close()
	fmt.Printf("SFTP OK: %s@%s\n\nls %s:\n", user, addr, dir)
	infos, err := sc.ReadDir(dir)
	if err != nil {
		fmt.Println("readdir error:", err)
	}
	for _, fi := range infos {
		fmt.Printf("  %s %8d %s\n", fi.Mode(), fi.Size(), fi.Name())
	}
	fmt.Printf("\nget %s:\n", file)
	f, err := sc.Open(file)
	if err != nil {
		fmt.Println("open error:", err)
		return
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	fmt.Print(string(b))
}
