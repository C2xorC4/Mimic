package services

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/c2xorc4/mimic/internal/config"
	"gopkg.in/yaml.v3"
)

// coRPCHeader builds a 24-byte connection-oriented DCE/RPC header with the given
// ptype, call_id, and opnum, then pads to wantLen with a zero stub.
func coRPCHeader(ptype byte, callID uint32, opnum uint16, wantLen int) []byte {
	b := make([]byte, wantLen)
	b[0] = 0x05 // rpc_vers
	b[1] = 0x00 // rpc_vers_minor
	b[2] = ptype
	b[3] = 0x03                                   // pfc_flags first+last
	b[4] = 0x10                                   // drep little-endian
	binary.LittleEndian.PutUint16(b[8:], uint16(wantLen))
	binary.LittleEndian.PutUint32(b[12:], callID) // call_id @12
	binary.LittleEndian.PutUint16(b[22:], opnum)  // opnum @22
	return b
}

// TestMSRPCEPMReplay validates the EPM endpoint-mapper service: a BIND is accepted,
// an ept_lookup (opnum 2) gets the captured multi-fragment endpoint response, the
// client's call_id is echoed into every fragment, and the capture IP is rewritten.
func TestMSRPCEPMReplay(t *testing.T) {
	dir := filepath.Join("..", "..", "services", "msrpc")
	data, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.ServiceConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("manifest parse: %v", err)
	}
	if !cfg.Stateful {
		t.Fatal("msrpc must be stateful to carry bind -> ept_lookup")
	}
	m, err := NewProbeMatcher(cfg.Probes, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewResponderWithOptions(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// BIND → bind_ack (ptype 0x0c), call_id echoed.
	bind := coRPCHeader(0x0b, 0xAABBCCDD, 0, 72)
	bm := m.Match(bind)
	if bm == nil || bm.Name != "dcerpc_bind_ack" {
		t.Fatalf("bind matched %v, want dcerpc_bind_ack", bm)
	}
	ack, err := r.GetResponse(bm.ResponseFile, bind, bm.RewriteRules)
	if err != nil {
		t.Fatal(err)
	}
	if ack[2] != 0x0c {
		t.Fatalf("bind_ack ptype = 0x%02x, want 0x0c", ack[2])
	}
	if got := binary.LittleEndian.Uint32(ack[12:]); got != 0xAABBCCDD {
		t.Fatalf("bind_ack call_id = 0x%08x, want 0xAABBCCDD", got)
	}

	// ept_lookup (opnum 2) → captured endpoint response.
	const cid = 0x11223344
	lookup := coRPCHeader(0x00, cid, 2, 64)
	lm := m.Match(lookup)
	if lm == nil || lm.Name != "dcerpc_ept_lookup" {
		t.Fatalf("ept_lookup matched %v, want dcerpc_ept_lookup", lm)
	}
	resp, err := r.GetResponse(lm.ResponseFile, lookup, lm.RewriteRules)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 45716 {
		t.Fatalf("epm response = %d bytes, want 45716", len(resp))
	}
	// Walk fragments; every one must carry the client's call_id and ver 5.
	frags := 0
	for i := 0; i+16 <= len(resp); {
		if resp[i] != 0x05 {
			t.Fatalf("fragment %d at off %d not a CO RPC PDU (0x%02x)", frags, i, resp[i])
		}
		fragLen := int(binary.LittleEndian.Uint16(resp[i+8:]))
		if got := binary.LittleEndian.Uint32(resp[i+12:]); got != cid {
			t.Fatalf("fragment %d call_id = 0x%08x, want 0x%08x", frags, got, cid)
		}
		frags++
		i += fragLen
	}
	if frags != 11 {
		t.Fatalf("walked %d fragments, want 11", frags)
	}
	// host_ip: when an egress IPv4 is available the capture IP must be gone.
	if hostEgressIPv4() != nil {
		if bytes.Contains(resp, []byte{0x0a, 0x00, 0xfe, 0x43}) {
			t.Fatal("capture IP 10.0.254.67 still present after host_ip rewrite")
		}
	}
}
