package smb

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestDecodeFirstLevelNBName(t *testing.T) {
	encoded := buildEncodedNBName("*SMBSERVER")
	got := decodeFirstLevelNBName(encoded)
	if got != "*SMBSERVER" {
		t.Fatalf("decode = %q, want *SMBSERVER", got)
	}
}

func TestSessionRequestAccepted(t *testing.T) {
	smbServer := buildEncodedNBName("*SMBSERVER")
	win11 := buildEncodedNBName("WIN11LAB")

	if !sessionRequestAccepted(smbServer, "WIN11LAB") {
		t.Fatal("*SMBSERVER should be accepted")
	}
	if !sessionRequestAccepted(win11, "WIN11LAB") {
		t.Fatal("computer name should be accepted")
	}
	if sessionRequestAccepted(win11, "OTHERBOX") {
		t.Fatal("wrong computer name should be rejected")
	}
}

func buildEncodedNBName(name string) []byte {
	var padded [16]byte
	copy(padded[:], name)
	for i := len(name); i < 16; i++ {
		padded[i] = ' '
	}
	out := make([]byte, 32)
	for i := 0; i < 16; i++ {
		b := padded[i]
		out[i*2] = 'A' + (b >> 4)
		out[i*2+1] = 'A' + (b & 0x0f)
	}
	return out
}

func TestNegotiateNetBIOSSessionPositive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- negotiateNetBIOSSession(conn, "WIN11LAB")
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Session request: type 0x81, length 32 (called name only for minimal test)
	req := make([]byte, 4+32)
	req[0] = 0x81
	req[3] = 32
	copy(req[4:], buildEncodedNBName("WIN11LAB"))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != nbssPositiveSession {
		t.Fatalf("got response type 0x%02x, want 0x82", resp[0])
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}