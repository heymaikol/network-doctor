package ui

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// tuiSlowClock is a fake clock that a probe may advance from its own goroutine.
// The probes of one pass run concurrently, so every read and advance is atomic.
type tuiSlowClock struct {
	start  time.Time
	offset atomic.Int64 // nanoseconds past start
}

func (c *tuiSlowClock) Now() time.Time { return c.start.Add(time.Duration(c.offset.Load())) }

func (c *tuiSlowClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// Every pass of a TUI Watch run takes 61 seconds on the session clock, with a
// 20 second probe timeout. The interface probe advances the clock, so each pass
// has been running 61 seconds when it publishes. Each published pass is recorded
// in the history, so four slow passes leave four entries. A refused pass would
// leave none, and settleWatch fails the test if the restarts never settle.
func TestWatchTUISlowPassesPublish(t *testing.T) {
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	target := mustTarget(t, "example.com:443")
	link := &tuiLink{}
	clock := &tuiSlowClock{start: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	m := NewWithSelection(target, nil, false, true, "", "test",
		diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{},
		func(m *model) { m.now = clock.Now }, WithProbeTimeout(20*time.Second)).(model)
	m.graph = func(*diagnostic.Target) []diagnostic.Probe {
		probes := tuiFakeProbes(target, link)
		for i := range probes {
			if probes[i].ID != diagnostic.ProbeIface {
				continue
			}
			run := probes[i].Run
			probes[i].Run = func(ctx context.Context, deps map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
				clock.advance(61 * time.Second)
				return run(ctx, deps)
			}
		}
		return probes
	}

	m.buildPass()
	m = settleWatch(t, m, m.Init())
	for pass := 2; pass <= 4; pass++ {
		m = startWatchPass(t, m)
	}
	if got := len(m.runHistory[diagnostic.ProbeTargetTCP]); got != 4 {
		t.Fatalf("after four slow passes the history has %d entries, want 4", got)
	}
}
