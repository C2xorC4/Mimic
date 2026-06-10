package defense

import (
	"fmt"
	"sync"
	"time"

	"github.com/c2xorc4/mimic/internal/events"
)

// blocker is the action the detector takes when a source crosses the threshold.
// Abstracted for testing.
type blocker interface {
	Block(ip, reason string)
}

// weight scores each event type by how indicative of abuse it is. Touching the
// honeypot at all is mildly suspicious; failed auth and credential capture more
// so; spidering the maze (a real user never does) is weighted up.
func weight(t events.Type) int {
	switch t {
	case events.AuthAttempt:
		return 3 // a failed login against a decoy
	case events.CredCapture, events.MazeDescent, events.FileDownload:
		return 2
	case events.Enumeration, events.Connection, events.AuthSuccess:
		return 1
	default:
		return 0
	}
}

type hit struct {
	t time.Time
	w int
}

type srcState struct {
	hits      []hit
	lastBlock time.Time
}

// Detector is an events.Sink that scores each source IP over a sliding window and
// asks the blocker to act when the score crosses the threshold.
type Detector struct {
	window    time.Duration
	cooldown  time.Duration
	threshold int
	blk       blocker

	mu  sync.Mutex
	src map[string]*srcState
}

// NewDetector builds a detector from cfg, dispatching blocks to blk.
func NewDetector(cfg Config, blk blocker) *Detector {
	cfg = cfg.withDefaults()
	return &Detector{
		window:    cfg.Window.D(),
		cooldown:  cfg.Cooldown.D(),
		threshold: cfg.Score,
		blk:       blk,
		src:       make(map[string]*srcState),
	}
}

func (d *Detector) Name() string { return "detector" }
func (d *Detector) Close() error { return nil }

// Write scores one event. Block events and event types with zero weight are
// ignored (the Block-ignore also prevents feedback when the blocker emits).
func (d *Detector) Write(e events.Event) error {
	if e.Type == events.Block || e.SrcIP == "" {
		return nil
	}
	w := weight(e.Type)
	if w == 0 {
		return nil
	}
	now := e.Time
	if now.IsZero() {
		now = time.Now()
	}

	d.mu.Lock()
	st := d.src[e.SrcIP]
	if st == nil {
		st = &srcState{}
		d.src[e.SrcIP] = st
	}
	cutoff := now.Add(-d.window)
	kept := st.hits[:0]
	score := 0
	for _, h := range st.hits {
		if h.t.After(cutoff) {
			kept = append(kept, h)
			score += h.w
		}
	}
	kept = append(kept, hit{now, w})
	score += w
	st.hits = kept

	trigger := score >= d.threshold && now.Sub(st.lastBlock) > d.cooldown
	var reason string
	if trigger {
		st.lastBlock = now
		reason = fmt.Sprintf("abuse score %d (threshold %d) in %s", score, d.threshold, d.window)
	}
	d.mu.Unlock()

	if trigger && d.blk != nil {
		d.blk.Block(e.SrcIP, reason)
	}
	return nil
}
