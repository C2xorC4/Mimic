package rdp

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCredSSPNTLMChallengeIntegration(t *testing.T) {
	servicesDir := findServicesDir(t)
	srv, err := New(Config{
		ComputerName: "SRV2022",
		DomainName:   "WORKGROUP",
		OSVersion:    "10.0.20348",
		ServicesDir:  servicesDir,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.listener = ln
	srv.wg.Add(1)
	go srv.serve()
	defer srv.Stop()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// X.224 Connection Request with RDP_NEG_REQ (nmap rdp-enum-encryption, 42 bytes).
	negoReq := []byte{
		0x03, 0x00, 0x00, 0x2a, 0x25, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74,
		0x73, 0x68, 0x61, 0x73, 0x68, 0x0d, 0x0a, 0x01, 0x00, 0x08, 0x00,
		0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(negoReq); err != nil {
		t.Fatalf("write nego: %v", err)
	}

	negResp := make([]byte, 64)
	n, err := conn.Read(negResp)
	if err != nil {
		t.Fatalf("read nego resp: %v", err)
	}
	if n < 4 || negResp[0] != 0x03 {
		t.Fatalf("expected TPKT nego response, got %x", negResp[:n])
	}

	tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	defer tconn.Close()

	nego := buildNTLMNegotiate()
	tsReq := buildTSRequestWithNego(nego)
	if err := writeTPKT(tconn, tsReq); err != nil {
		t.Fatalf("write tsrequest: %v", err)
	}

	challengePDU, err := readTPKT(tconn)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	idx := -1
	for i := 0; i+12 <= len(challengePDU); i++ {
		if string(challengePDU[i:i+8]) == "NTLMSSP\x00" {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("no NTLM challenge in response (%d bytes)", len(challengePDU))
	}
	if binary.LittleEndian.Uint32(challengePDU[idx+8:idx+12]) != 2 {
		t.Fatalf("expected NTLM type 2")
	}
	build := binary.LittleEndian.Uint16(challengePDU[idx+50 : idx+52])
	if build != 20348 {
		t.Errorf("Product_Build = %d, want 20348", build)
	}
}

func findServicesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "services")
		if _, err := os.Stat(filepath.Join(candidate, "rdp", "responses", "rdp_neg_tls.bin")); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("services/rdp templates not found from test cwd")
	return ""
}