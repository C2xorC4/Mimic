//go:build windows

package control

import (
	"bufio"
	"encoding/json"
	"testing"
	"time"

)

// allowAllAuthorizer gates only the transport test — RBAC is covered separately.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Authorize(Peer, string) (string, error) { return "test", nil }

func TestPipeListenDialPing(t *testing.T) {
	if !Supported() {
		t.Fatal("expected Supported() on Windows")
	}
	name := `\\.\pipe\mimic-test-` + time.Now().Format("150405.000000")
	ring := NewRing(10)
	statusFn := func() Status {
		return Status{Profile: "test", Services: []string{"smb"}, Pid: 1}
	}
	srv := New(allowAllAuthorizer{}, statusFn, ring, nil)
	if err := srv.Start(name); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	conn, err := Dial(name, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(Request{Op: "ping"}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || resp.Data != "pong" {
		t.Fatalf("ping response: %+v", resp)
	}
}

func TestPipeServicesStop(t *testing.T) {
	if !Supported() {
		t.Fatal("expected Supported() on Windows")
	}
	name := `\\.\pipe\mimic-test-stop-` + time.Now().Format("150405.000000")
	stopCh := make(chan struct{}, 1)
	hooks := &Hooks{
		Stop: func() error {
			close(stopCh)
			return nil
		},
	}
	srv := New(allowAllAuthorizer{}, func() Status { return Status{} }, NewRing(10), hooks)
	if err := srv.Start(name); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	conn, err := Dial(name, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(Request{Op: "services.stop"}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK {
		t.Fatalf("services.stop response: %+v", resp)
	}
	select {
	case <-stopCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop hook did not fire")
	}
}