package smb

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestSMBHoneypotOverNetBIOSPort(t *testing.T) {
	srv := New(Config{
		ComputerName: "WIN11LAB",
		DomainName:   "WORKGROUP",
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.ctx = ctx
	srv.cancel = cancel
	srv.listeners = []net.Listener{ln}

	srv.wg.Add(1)
	go srv.serveListener(ln, true)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := make([]byte, 4+32)
	req[0] = 0x81
	req[3] = 32
	copy(req[4:], buildEncodedNBName("WIN11LAB"))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	pos := make([]byte, 4)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, pos); err != nil {
		t.Fatal(err)
	}
	if pos[0] != nbssPositiveSession {
		t.Fatalf("NBSS response 0x%02x, want 0x82", pos[0])
	}

	resp := sendRecv(t, conn, buildTestPacket(CmdNegotiate, 0, 0, 1, buildNegotiateBody()))
	if len(resp) < 68 {
		t.Fatalf("short negotiate response: %d bytes", len(resp))
	}
	if resp[4] != 0xFE {
		t.Fatal("expected SMB2 negotiate response over NBSS")
	}
}