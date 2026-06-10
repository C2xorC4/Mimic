package defense

import (
	"testing"
	"time"

	"github.com/c2xorc4/mimic/internal/events"
)

type fakeBlocker struct {
	calls int
	last  string
}

func (f *fakeBlocker) Block(ip, reason string) { f.calls++; f.last = ip }

func TestDetectorTriggersAtThreshold(t *testing.T) {
	fb := &fakeBlocker{}
	d := NewDetector(Config{Score: 6, Window: Duration(time.Minute), Cooldown: Duration(time.Minute)}, fb)
	base := time.Now()
	// AuthAttempt weight=3: after 2 events score=6 => trigger once.
	for i := 0; i < 3; i++ {
		d.Write(events.Event{Time: base.Add(time.Duration(i) * time.Second), Type: events.AuthAttempt, SrcIP: "1.2.3.4"})
	}
	if fb.calls != 1 {
		t.Fatalf("want exactly 1 block (cooldown suppresses repeats), got %d", fb.calls)
	}
	if fb.last != "1.2.3.4" {
		t.Errorf("blocked wrong ip: %q", fb.last)
	}
}

func TestDetectorWindowPrunes(t *testing.T) {
	fb := &fakeBlocker{}
	d := NewDetector(Config{Score: 6, Window: Duration(10 * time.Second), Cooldown: Duration(time.Minute)}, fb)
	base := time.Now()
	d.Write(events.Event{Time: base, Type: events.AuthAttempt, SrcIP: "9.9.9.9"})                       // score 3
	d.Write(events.Event{Time: base.Add(30 * time.Second), Type: events.AuthAttempt, SrcIP: "9.9.9.9"}) // prior pruned; score 3
	if fb.calls != 0 {
		t.Errorf("events outside the window should not accumulate to a block, got %d", fb.calls)
	}
}

func TestDetectorIgnoresBlockEvents(t *testing.T) {
	fb := &fakeBlocker{}
	d := NewDetector(Config{Score: 1, Window: Duration(time.Minute), Cooldown: Duration(time.Minute)}, fb)
	d.Write(events.Event{Time: time.Now(), Type: events.Block, SrcIP: "1.2.3.4"})
	if fb.calls != 0 {
		t.Error("block events must not feed the detector (would recurse)")
	}
}

func TestBlockerDryRunEmitsAndWhitelists(t *testing.T) {
	mem := &events.MemorySink{}
	bus := events.NewBus(nil)
	bus.AddSink(mem)
	events.SetGlobal(bus)
	defer events.CloseGlobal()

	b := NewBlocker(Config{Enforce: false, Whitelist: []string{"10.0.0.0/8", "127.0.0.1"}})
	b.Block("1.2.3.4", "test")  // not whitelisted, dry-run -> emit, no firewall
	b.Block("10.0.0.5", "test") // whitelisted -> nothing
	b.Block("127.0.0.1", "test")

	evs := mem.Snapshot()
	if len(evs) != 1 {
		t.Fatalf("want 1 block event (others whitelisted), got %d: %+v", len(evs), evs)
	}
	if evs[0].Type != events.Block || evs[0].SrcIP != "1.2.3.4" {
		t.Errorf("unexpected event: %+v", evs[0])
	}
	if evs[0].Fields["enforced"] != false || evs[0].Fields["dry_run"] != true {
		t.Errorf("dry-run block should be enforced=false dry_run=true: %+v", evs[0].Fields)
	}
}

func TestParseCIDR(t *testing.T) {
	if parseCIDR("10.0.0.0/8") == nil {
		t.Error("CIDR should parse")
	}
	if parseCIDR("127.0.0.1") == nil {
		t.Error("bare IP should parse")
	}
	if parseCIDR("nonsense") != nil {
		t.Error("garbage should not parse")
	}
}
