// Command sshclient is a tiny password-auth SSH client for validating the SSH
// honeypot (internal/honeypot/ssh). It dials a target, authenticates, and runs
// each argument as a remote command via the exec channel, printing the output.
//
//	go run ./test/sshclient <host:port> <user> <pass> "uname -a" "cat /root/.credentials"
package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: sshclient <host:port> <user> <pass> [cmd...]")
		os.Exit(2)
	}
	addr, user, pass := os.Args[1], os.Args[2], os.Args[3]
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		fmt.Println("DIAL/AUTH ERROR:", err)
		os.Exit(1)
	}
	defer c.Close()
	fmt.Printf("AUTH OK: %s@%s (server %q)\n", user, addr, string(c.ServerVersion()))
	for _, cmd := range os.Args[4:] {
		sess, err := c.NewSession()
		if err != nil {
			fmt.Println("session error:", err)
			continue
		}
		out, _ := sess.CombinedOutput(cmd)
		fmt.Printf("\n$ %s\n%s", cmd, out)
		sess.Close()
	}
}
