package diagnostic

import (
	"context"
	"math"
	"testing"
	"time"
)

// The Windows scenario: a ten hour window, and wall and monotonic time both
// advance 90 seconds, 30 awake and then a 60 second suspend. The original logic
// accepts the pass, because the two clocks agree. The unbiased count does not
// count the suspend, so it refuses the pass.
func TestWatchUnbiasedCountRefusesSuspendThatMonotonicCounts(t *testing.T) {
	const timeout = time.Hour // five rungs times two times an hour is a ten hour window
	for _, tc := range []struct {
		name     string
		unbiased bool
		want     bool
	}{
		{"original logic, clocks agree", false, true},
		{"unbiased count shows the suspend", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newWatchClock()
			n := newWatchNet()
			s := NewWatchSession(clock.Now)
			if tc.unbiased {
				s.unbiased = clock.Unbiased
			}
			pass := s.Begin(n.graph(), timeout)
			if pass.window != 10*time.Hour {
				t.Fatalf("window = %v, want 10h", pass.window)
			}
			results := RunAll(context.Background(), pass.Probes(), timeout)
			clock.Advance(30 * time.Second)
			clock.Suspend(60 * time.Second)
			if got := pass.Publish(results); got != tc.want {
				t.Errorf("Publish = %t, want %t", got, tc.want)
			}
		})
	}
}

// A slow pass with no suspend publishes, at a short timeout and at the widest
// window a five rung graph reaches. The count moves with the awake time.
func TestWatchUnbiasedCountPublishesSlowPassWithoutSuspend(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		awake   time.Duration
	}{
		{"61s pass at a 20s timeout", 20 * time.Second, 61 * time.Second},
		{"199s pass at a 20s timeout", 20 * time.Second, 199 * time.Second},
		{"two hour pass in a ten hour window", time.Hour, 2 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newWatchClock()
			n := newWatchNet()
			s := NewWatchSession(clock.Now)
			s.unbiased = clock.Unbiased
			pass := s.Begin(n.graph(), tc.timeout)
			results := RunAll(context.Background(), pass.Probes(), tc.timeout)
			clock.Advance(tc.awake)
			if !pass.Publish(results) {
				t.Fatalf("a %v pass without suspend was refused", tc.awake)
			}
		})
	}
}

// A count that reads a little behind the monotonic clock, as a tick-granular
// read does, is normal skew and publishes.
func TestWatchUnbiasedCountAcceptsNormalReadSkew(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	// lag is how far the count reads behind the awake time at the read.
	var lag time.Duration
	s.unbiased = func() (uint64, bool) {
		return unbiasedTicks(clock.awake - lag), true
	}
	pass := s.Begin(n.graph(), 20*time.Second)
	results := RunAll(context.Background(), pass.Probes(), 20*time.Second)
	clock.Advance(61 * time.Second)
	lag = 15 * time.Millisecond
	if !pass.Publish(results) {
		t.Fatal("a 15ms read skew refused a 61s pass")
	}
}

// The unbiased check on its own, with the exact boundaries of the drift allowance.
// At a 61 second awake pass the allowance is 1.0305 seconds.
func TestUnbiasedCurrentBoundaries(t *testing.T) {
	const allowance61 = time.Second + 30500*time.Microsecond
	const window = 10 * time.Hour
	for _, tc := range []struct {
		name          string
		mono, working time.Duration
		window        time.Duration
		want          bool
	}{
		{"clocks agree", 61 * time.Second, 61 * time.Second, window, true},
		{"drift at the allowance", 61 * time.Second, 61*time.Second - allowance61, window, true},
		{"drift one nanosecond past the allowance", 61 * time.Second, 61*time.Second - allowance61 - time.Nanosecond, window, false},
		{"count ahead of the monotonic clock, past the allowance", 30 * time.Second, 90 * time.Second, window, false},
		{"suspend of 60s in a 30s awake pass", 90 * time.Second, 30 * time.Second, window, false},
		{"zero pass", 0, 0, window, true},
		{"working age at the window", window, window, window, false},
		{"monotonic age at the window", window, time.Hour, window, false},
		{"count moved backward", 90 * time.Second, -1, window, false},
		{"saturated window, clocks agree", 100 * time.Hour, 100 * time.Hour, math.MaxInt64, true},
		{"saturated window, 60s suspend", 100 * time.Hour, 100*time.Hour - 60*time.Second, math.MaxInt64, false},
	} {
		if got := unbiasedCurrent(tc.mono, tc.working, tc.window); got != tc.want {
			t.Errorf("%s: unbiasedCurrent(mono %v, working %v, window %v) = %t, want %t",
				tc.name, tc.mono, tc.working, tc.window, got, tc.want)
		}
	}
}

// The count is 100 ns units. A difference that moved backward is refused, and a
// difference too large for a Duration saturates instead of wrapping.
func TestTicksElapsedArithmetic(t *testing.T) {
	const maxTicks = math.MaxInt64 / 100
	for _, tc := range []struct {
		name       string
		start, end uint64
		want       time.Duration
	}{
		{"no time", 5, 5, 0},
		{"one tick", 5, 6, 100 * time.Nanosecond},
		{"one second", 0, 10_000_000, time.Second},
		{"moved backward", 6, 5, -1},
		{"largest difference that fits", 0, maxTicks, time.Duration(maxTicks) * 100},
		{"one tick past the largest that fits", 0, maxTicks + 1, math.MaxInt64},
		{"whole counter range saturates", 0, math.MaxUint64, math.MaxInt64},
		{"both at the top of the range", math.MaxUint64, math.MaxUint64, 0},
	} {
		if got := ticksElapsed(tc.start, tc.end); got != tc.want {
			t.Errorf("%s: ticksElapsed(%d, %d) = %v, want %v", tc.name, tc.start, tc.end, got, tc.want)
		}
	}
}

// A count that moves backward between Begin and publication refuses the pass.
func TestWatchUnbiasedCountMovingBackwardRefusesPass(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	count := uint64(1_000_000)
	s.unbiased = func() (uint64, bool) { return count, true }
	pass := s.Begin(n.graph(), 20*time.Second)
	results := RunAll(context.Background(), pass.Probes(), 20*time.Second)
	count = 500_000
	clock.Advance(5 * time.Second)
	if pass.Publish(results) {
		t.Fatal("a count that moved backward published the pass")
	}
}

// Where the counter is absent at the start of a pass, the pass keeps watchMaxAge
// rather than claim the widened window it cannot check.
func TestWatchUnavailableCountAtBeginKeepsSixtySeconds(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	s.unbiased = func() (uint64, bool) { return 0, false }
	pass := s.Begin(n.graph(), time.Hour)
	if pass.window != watchMaxAge {
		t.Fatalf("window = %v, want watchMaxAge when the count is unavailable", pass.window)
	}
	if pass.hasUnbiased {
		t.Fatal("pass claims an unbiased start it did not read")
	}
	results := RunAll(context.Background(), pass.Probes(), time.Hour)
	clock.Advance(30 * time.Second)
	clock.Suspend(31 * time.Second)
	if pass.Publish(results) {
		t.Fatal("a 61s pass published under the 60s bound")
	}
}

// settleSession publishes one fresh pass, so the session holds rows that a later pass may
// reuse. Without one, a refusal shows nothing: the next pass runs fresh anyway.
func settleSession(t *testing.T, s *WatchSession, base []Probe, timeout time.Duration) {
	t.Helper()
	pass := s.Begin(base, timeout)
	if !pass.Publish(RunAll(context.Background(), pass.Probes(), timeout)) {
		t.Fatal("the settling pass was not published")
	}
}

// A count that cannot be read at publication refuses the pass, because the pass
// cannot show it did not suspend. The refusal forces the next pass fresh, and that
// pass publishes.
func TestWatchUnavailableCountAtPublishRefusesThenFreshPassPublishes(t *testing.T) {
	const timeout = 20 * time.Second
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	available := true
	s.unbiased = func() (uint64, bool) { return unbiasedTicks(clock.awake), available }
	settleSession(t, s, n.graph(), timeout)
	clock.Advance(5 * time.Second)
	reusing := s.Begin(n.graph(), timeout)
	results := RunAll(context.Background(), reusing.Probes(), timeout)
	if reusing.Fresh() {
		t.Fatal("the pass reused no row, so the refusal below shows nothing")
	}
	available = false
	if reusing.Publish(results) {
		t.Fatal("a pass published with the count unreadable at publication")
	}
	available = true
	next := s.Begin(n.graph(), timeout)
	results = RunAll(context.Background(), next.Probes(), timeout)
	if !next.Publish(results) {
		t.Fatal("the fresh pass after the refusal was not published")
	}
	if !next.Fresh() {
		t.Error("the pass after the refusal reused a row, want every row run fresh")
	}
}

// A five second suspend that the counter shows and the clocks do not is refused.
// The rows the pass would reuse are only 10 seconds old, inside watchMaxAge, so
// the counter alone refuses the pass. The refusal forces the next pass fresh.
func TestWatchSuspendedPassThenFreshAcquisitionPublishes(t *testing.T) {
	const timeout = 20 * time.Second
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	s.unbiased = clock.Unbiased
	settleSession(t, s, n.graph(), timeout)
	clock.Advance(5 * time.Second)
	reusing := s.Begin(n.graph(), timeout)
	results := RunAll(context.Background(), reusing.Probes(), timeout)
	if reusing.Fresh() {
		t.Fatal("the pass reused no row, so the refusal below shows nothing")
	}
	clock.Suspend(5 * time.Second)
	if reusing.Publish(results) {
		t.Fatal("a pass that spanned a five second suspend published")
	}
	next := s.Begin(n.graph(), timeout)
	results = RunAll(context.Background(), next.Probes(), timeout)
	clock.Advance(5 * time.Second)
	if !next.Publish(results) {
		t.Fatal("the pass that began after the suspend was not published")
	}
	if !next.Fresh() {
		t.Error("the pass after the suspend reused a row, want every row run fresh")
	}
}

// A cached observation sampled before a suspend expires at watchMaxAge on both
// clocks, so a suspend cannot extend reuse. The pass is refused, and the pass
// after it runs the row fresh.
func TestWatchCachedObservationExpiresAcrossSuspend(t *testing.T) {
	const timeout = 20 * time.Second
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	s.unbiased = clock.Unbiased
	first := s.Begin(n.graph(), timeout)
	if !first.Publish(RunAll(context.Background(), first.Probes(), timeout)) {
		t.Fatal("first pass was not published")
	}
	clock.Advance(5 * time.Second)
	inFlight := s.Begin(n.graph(), timeout)
	results := RunAll(context.Background(), inFlight.Probes(), timeout)
	if !reusedAny(results) {
		t.Fatal("no reusable row was reused, so the expiry is not exercised")
	}
	clock.Suspend(56 * time.Second)
	if inFlight.Publish(results) {
		t.Fatal("published a row reused across a suspend that aged it past watchMaxAge")
	}
	next := s.Begin(n.graph(), timeout)
	results = RunAll(context.Background(), next.Probes(), timeout)
	if !next.Publish(results) {
		t.Fatal("the pass after the expired row was not published")
	}
	if !next.Fresh() {
		t.Error("the pass after the expired row reused a row")
	}
}

// A slow pass that is cancelled is never published. The next pass reads the
// counter from its own start. A start carried over from the cancelled pass would
// show a 61 second drift on the next pass and refuse it.
func TestWatchUnbiasedCountCancelledSlowPassDoesNotCarryIntoNextPass(t *testing.T) {
	const timeout = time.Hour
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	s.unbiased = clock.Unbiased
	ctx, cancel := context.WithCancel(context.Background())
	cancelled := s.Begin(n.graph(), timeout)
	cancel()
	clock.Advance(61 * time.Second)
	RunAll(ctx, cancelled.Probes(), timeout)
	next := s.Begin(n.graph(), timeout)
	results := RunAll(context.Background(), next.Probes(), timeout)
	clock.Advance(61 * time.Second)
	if !next.Publish(results) {
		t.Fatal("the pass after a cancelled slow pass was refused")
	}
}
