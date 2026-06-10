package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBusFanout(t *testing.T) {
	a, b := &MemorySink{}, &MemorySink{}
	bus := NewBus(nil)
	bus.AddSink(a)
	bus.AddSink(b)
	bus.Emit(Event{Type: AuthAttempt, Service: "ftp", SrcIP: "10.0.0.9"})
	for _, s := range []*MemorySink{a, b} {
		ev := s.Snapshot()
		if len(ev) != 1 || ev[0].Type != AuthAttempt {
			t.Fatalf("sink %s: %+v", s.Name(), ev)
		}
		if ev[0].Time.IsZero() || ev[0].Severity == "" {
			t.Errorf("Emit should default Time/Severity: %+v", ev[0])
		}
	}
}

func TestFileSinkNDJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	fs, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	in := []Event{
		{Time: time.Now(), Type: CredCapture, Severity: SevAlert, Service: "smb", SrcIP: "1.2.3.4",
			Fields: map[string]interface{}{"username": "svc_backup"}},
		{Time: time.Now(), Type: FileDownload, Severity: SevNotice, Service: "ftp", SrcIP: "1.2.3.4",
			Fields: map[string]interface{}{"file": "backup_credentials.txt", "bytes": 75}},
	}
	for _, e := range in {
		if err := fs.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	fs.Close()

	f, _ := os.Open(path)
	defer f.Close()
	var n int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line %d not valid JSON: %v", n, err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("want 2 NDJSON lines, got %d", n)
	}
}

// fakeConn captures syslog frames written to it.
type fakeConn struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *fakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}
func (c *fakeConn) Close() error { return nil }
func (c *fakeConn) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func TestSyslogFrameRFC5424(t *testing.T) {
	fc := &fakeConn{}
	s := &SyslogSink{network: "udp", address: "x", hostname: "honeypot1", appName: "mimic", procid: "42"}
	s.dial = func() (netConn, error) { return fc, nil }

	ev := Event{
		Time:     time.Date(2026, 6, 10, 18, 0, 0, 0, time.UTC),
		Type:     CredCapture,
		Severity: SevAlert,
		Service:  "smb",
		SrcIP:    "10.0.253.61",
		Fields:   map[string]interface{}{"username": "svc_backup"},
	}
	if err := s.Write(ev); err != nil {
		t.Fatal(err)
	}
	frame := fc.String()
	// PRI = local0(16)*8 + alert(1) = 129; version 1; MSGID = type.
	if !strings.HasPrefix(frame, "<129>1 2026-06-10T18:00:00Z honeypot1 mimic 42 cred_capture - ") {
		t.Fatalf("bad RFC5424 header: %q", frame)
	}
	if !strings.HasSuffix(frame, "\n") {
		t.Error("frame must be newline-terminated")
	}
	// MSG must be the event JSON.
	msg := frame[strings.Index(frame, "- ")+2:]
	var back Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(msg)), &back); err != nil {
		t.Fatalf("MSG not JSON: %v (%q)", err, msg)
	}
	if back.Type != CredCapture || back.SrcIP != "10.0.253.61" {
		t.Errorf("round-trip mismatch: %+v", back)
	}
}

func TestSyslogSeverityMap(t *testing.T) {
	cases := map[Severity]int{SevAlert: 1, SevWarn: 4, SevNotice: 5, SevInfo: 6, Severity("x"): 6}
	for sev, want := range cases {
		if got := syslogSeverity(sev); got != want {
			t.Errorf("syslogSeverity(%q)=%d want %d", sev, got, want)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	var e Event
	e.SplitHostPort("10.0.0.5:54321")
	if e.SrcIP != "10.0.0.5" || e.SrcPort != "54321" {
		t.Errorf("got %q %q", e.SrcIP, e.SrcPort)
	}
	e2 := Event{}
	e2.SplitHostPort("garbage")
	if e2.SrcIP != "" {
		t.Error("malformed addr should leave SrcIP empty")
	}
}
