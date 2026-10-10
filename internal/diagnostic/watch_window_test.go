package diagnostic

import (
	"context"
	"math"
	"testing"
	"time"
)

// The window arithmetic is pinned to the graph's depth. Five rungs is where the
// graph stands (budget_test.go pins the same shape), so the expected windows are
// written out in full rather than recomputed.
func TestWatchPassWindowFollowsTheTimeout(t *testing.T) {
	base := ProbePlan(watchTarget(), DefaultPublicDNS, true)
	if got := chainDepth(base); got != 5 {
		t.Fatalf("chainDepth = %d, want 5: the expectations below assume five rungs", got)
	}
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"zero means the default timeout", 0, watchMaxAge},
		{"negative means the default timeout", -time.Second, watchMaxAge},
		{"the default timeout keeps watchMaxAge", DefaultProbeTimeout, watchMaxAge},
		{"five seconds fits inside watchMaxAge", 5 * time.Second, watchMaxAge},
		{"twenty seconds widens the window", 20 * time.Second, 200 * time.Second},
		{"the largest product that fits", math.MaxInt64 / 10, 10 * (math.MaxInt64 / 10)},
		{"a product that overflows saturates", math.MaxInt64/10 + 1, math.MaxInt64},
		{"the largest timeout saturates", math.MaxInt64, math.MaxInt64},
	} {
		if got := passWindow(base, tc.timeout); got != tc.want {
			t.Errorf("%s: passWindow(%v) = %v, want %v", tc.name, tc.timeout, got, tc.want)
		}
	}
	if got := passWindow(nil, time.Hour); got != watchMaxAge {
		t.Errorf("empty graph: passWindow = %v, want watchMaxAge", got)
	}
}

// passCurrent is decided on both clocks. Each row names what a rule missing one
// check would accept wrongly. The clock-drift allowance is 1% of the time the pass
// ran plus a second, so a 61 second pass allows 1.61 seconds of drift.
func TestWatchPassCurrentNeedsBothClocksAndNoSuspend(t *testing.T) {
	const window = 200 * time.Second
	const allowance = 61*time.Second + 1610*time.Millisecond
	for _, tc := range []struct {
		name       string
		mono, wall time.Duration
		window     time.Duration
		want       bool
	}{
		{"slow pass, clocks agree", 61 * time.Second, 61 * time.Second, window, true},
		{"slow pass, drift at the allowance", 61 * time.Second, allowance, window, true},
		{"slow pass, drift one nanosecond past the allowance", 61 * time.Second, allowance + time.Nanosecond, window, false},
		{"suspend the monotonic clock stops for, past the window", time.Second, 2 * time.Hour, window, false},
		{"suspend the monotonic clock stops for, inside the window", 30 * time.Second, 90 * time.Second, window, false},
		// A 2 second pass that a 30 second pause interrupts: long timeouts widen
		// the window, but the drift check follows the pass, so it still refuses.
		{"short pass, pause, long window", 2 * time.Second, 32 * time.Second, 3000 * time.Second, false},
		{"short pass, pause, saturated window", 2 * time.Second, 32 * time.Second, math.MaxInt64, false},
		// A monotonic clock that runs through a suspend shows no drift, so only the
		// window stands between such a suspend and a publish. This is the limit.
		{"suspend the monotonic clock also counts, inside the window", 90 * time.Second, 90 * time.Second, window, true},
		{"monotonic age at the window", window, window, window, false},
		{"monotonic age past the window", 201 * time.Second, 201 * time.Second, window, false},
		{"wall stepped back by more than the allowance", 61 * time.Second, 57 * time.Second, window, false},
		{"wall stepped back past the sample", 2 * time.Second, -time.Second, window, false},
		{"wall stepped forward a little", 61 * time.Second, 66 * time.Second, window, false},
	} {
		if got := passCurrent(tc.mono, tc.wall, tc.window); got != tc.want {
			t.Errorf("%s: passCurrent(mono %v, wall %v, window %v) = %t, want %t", tc.name, tc.mono, tc.wall, tc.window, got, tc.want)
		}
	}
}

// A complete pass that takes longer than watchMaxAge but less than its window
// publishes on the first attempt, pass after pass, at any length the window
// allows. Each pass begins 5 seconds after the last one publishes.
func TestWatchSlowPassesUpToTheWindowPublishFirst(t *testing.T) {
	const timeout = 20 * time.Second
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	for _, took := range []time.Duration{61 * time.Second, 150 * time.Second, 199 * time.Second, 61 * time.Second} {
		pass := s.Begin(n.graph(), timeout)
		results := RunAll(context.Background(), pass.Probes(), timeout)
		clock.Advance(took)
		if !pass.Publish(results) {
			t.Fatalf("pass that took %v refused on its first attempt", took)
		}
		clock.Advance(5 * time.Second)
	}
}

// A timeout so large that its product saturates still gives a pass a window it
// can use. A wrapped, negative window would refuse every pass.
func TestWatchAbsurdTimeoutDoesNotRefuseASlowPass(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	pass := s.Begin(n.graph(), math.MaxInt64)
	results := RunAll(context.Background(), pass.Probes(), time.Second)
	clock.Advance(61 * time.Second)
	if !pass.Publish(results) {
		t.Fatal("a 61s pass refused under a saturated window")
	}
}

// A reused observation keeps watchMaxAge even when the window is wider. The pass
// is 56 seconds old when it publishes, inside its 200 second window, but the row
// it reused was sampled 61 seconds ago. That row must refuse the pass, and the
// pass after it must run fresh.
func TestWatchWideWindowDoesNotWidenReuse(t *testing.T) {
	const timeout = 20 * time.Second
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	first := s.Begin(n.graph(), timeout)
	if !first.Publish(RunAll(context.Background(), first.Probes(), timeout)) {
		t.Fatal("first pass was not published")
	}

	clock.Advance(5 * time.Second)
	inFlight := s.Begin(n.graph(), timeout)
	results := RunAll(context.Background(), inFlight.Probes(), timeout)
	if !reusedAny(results) {
		t.Fatal("no reusable row was reused, so the window is not exercised")
	}
	clock.Advance(56 * time.Second)
	if inFlight.Publish(results) {
		t.Fatal("published a reused row 61s old: the wider window reached reuse")
	}

	next := s.Begin(n.graph(), timeout)
	results = RunAll(context.Background(), next.Probes(), timeout)
	if !next.Publish(results) {
		t.Fatal("the pass after the refusal was not published")
	}
	if !next.Fresh() {
		t.Error("the pass after the refusal reused a row, want every row run fresh")
	}
}

// A fully fresh pass that began before a gap longer than its window is still
// refused. With a 20 second timeout the window is 200 seconds, so a gap of 201
// seconds is already past it, and so is a two hour suspend.
func TestWatchWideWindowStillRefusesALongGap(t *testing.T) {
	const timeout = 20 * time.Second
	for _, gap := range []time.Duration{201 * time.Second, 2 * time.Hour} {
		clock := newWatchClock()
		n := newWatchNet()
		s := NewWatchSession(clock.Now)
		inFlight := s.Begin(n.graph(), timeout)
		results := RunAll(context.Background(), inFlight.Probes(), timeout)
		clock.Advance(gap)
		if inFlight.Publish(results) {
			t.Errorf("published a fresh pass after a %v gap, want it discarded", gap)
		}
	}
}
