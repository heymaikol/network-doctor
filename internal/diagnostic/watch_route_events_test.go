package diagnostic

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// A route event on the QUIC footprint refuses the QUIC observation, so the next
// pass measures it. The same change without an event waits out watchMaxAge (see
// TestWatchQUICPathChangeSeenOnlyAtMaxAge).
func TestWatchRouteEventSeesQUICChangeOnTheNextPass(t *testing.T) {
	const cadence = 5 * time.Second
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	fault := false

	faultPass(t, s, n, &fault)
	fault = true
	changedAt := clock.now
	s.Invalidate()

	clock.Advance(cadence)
	results, runs, attempts := faultPass(t, s, n, &fault)
	latency := clock.now.Sub(changedAt)

	if q := results[ProbeQUIC]; q.Status != StatusFail || q.Cause != "timeout" {
		t.Fatalf("next pass: QUIC %v cause %q, want fail timeout", q.Status, q.Cause)
	}
	if runs[ProbeQUIC] != 1 || attempts != 1 {
		t.Errorf("next pass: QUIC runs=%d attempts=%d, want 1 run, 1 attempt", runs[ProbeQUIC], attempts)
	}
	if latency != cadence {
		t.Errorf("detection latency %v, want one cadence %v", latency, cadence)
	}
}

// Every reusable row runs after the interface row it depends on. An event raised
// after the pass began, but before the rows decide, must refuse all of them. A
// generation read once at Begin would reuse them.
func TestWatchInvalidateMidPassRefusesEveryReusableRow(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	clock.Advance(5 * time.Second)
	n.resetRuns()
	pass := s.Begin(eventGraph(n, ProbeIface, func() { s.Invalidate() }), time.Second)
	results := RunAll(context.Background(), pass.Probes(), time.Second)
	if !pass.Publish(results) {
		t.Fatal("pass was not published")
	}
	runs := n.snapshotRuns()
	for _, id := range watchIDs() {
		if watchReusable[id] && runs[id] != 1 {
			t.Errorf("reusable row %s ran %d times after a mid-pass event, want 1", id, runs[id])
		}
	}
}

// A row samples, then the change lands. The observation must carry the
// generation the pass began with, so the next pass refuses it. Stamping the
// generation when the row records would take the post-change one and keep it.
func TestWatchObservationKeepsTheGenerationItWasSampledUnder(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	// Force makes QUIC sample on this pass, so the event lands after a sample.
	s.Force()
	clock.Advance(5 * time.Second)
	n.resetRuns()
	pass := s.Begin(eventGraph(n, ProbeQUIC, func() { s.Invalidate() }), time.Second)
	if !pass.Publish(RunAll(context.Background(), pass.Probes(), time.Second)) {
		t.Fatal("pass was not published")
	}

	clock.Advance(5 * time.Second)
	_, runs, _ := watchPass(t, s, n)
	if runs[ProbeQUIC] != 1 {
		t.Errorf("QUIC sampled before the event ran %d times on the next pass, want 1", runs[ProbeQUIC])
	}
}

// A reused observation is refused by an event that lands after the reuse decision
// but before Publish. Publish must keep the old generation, so the next pass
// measures the row again.
func TestWatchPublishKeepsReusedObservationsOnTheirGeneration(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	clock.Advance(5 * time.Second)
	n.resetRuns()
	pass := s.Begin(n.graph(), time.Second)
	results := runInOrder(t, pass.Probes())
	if _, reused := results[ProbeQUIC].ReusedFrom(); !reused {
		t.Fatal("QUIC was not reused before the event")
	}
	s.Invalidate()
	if !pass.Publish(results) {
		t.Fatal("pass was not published")
	}

	clock.Advance(5 * time.Second)
	_, runs, _ := watchPass(t, s, n)
	if runs[ProbeQUIC] != 1 {
		t.Errorf("QUIC reused across an event ran %d times on the next pass, want 1", runs[ProbeQUIC])
	}
}

// A burst of events costs one fresh measurement of each reusable row, not one
// per event.
func TestWatchInvalidateBurstCostsOneFreshPass(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	for range 10000 {
		s.Invalidate()
	}
	clock.Advance(5 * time.Second)
	results, runs, attempts := watchPass(t, s, n)
	if attempts != 1 {
		t.Errorf("burst pass took %d attempts, want 1", attempts)
	}
	for _, id := range watchIDs() {
		if watchReusable[id] && runs[id] != 1 {
			t.Errorf("reusable row %s ran %d times after a burst, want 1", id, runs[id])
		}
	}
	for id, r := range results {
		if _, reused := r.ReusedFrom(); reused {
			t.Errorf("row %s reused after an invalidation", id)
		}
	}
}

// scriptedRouteEvents answers next from a script, then blocks until closed.
type scriptedRouteEvents struct {
	steps     []error
	released  chan struct{}
	closeOnce sync.Once
}

func newScriptedRouteEvents(steps ...error) *scriptedRouteEvents {
	return &scriptedRouteEvents{steps: steps, released: make(chan struct{})}
}

func (r *scriptedRouteEvents) next() error {
	if len(r.steps) > 0 {
		step := r.steps[0]
		r.steps = r.steps[1:]
		return step
	}
	<-r.released
	return errors.New("closed")
}

func (r *scriptedRouteEvents) close() error {
	r.closeOnce.Do(func() { close(r.released) })
	return nil
}

// The reader invalidates on every notification and on every overflow, keeps
// reading through an overflow, and stops at the first error that is not one.
func TestWatchRouteReaderInvalidatesOnEachChangeAndStopsAtAnEnd(t *testing.T) {
	s := NewWatchSession(nil)
	src := newScriptedRouteEvents(nil, errRouteEventsOverflow, nil, errors.New("link gone"))
	s.followRoutes(src)
	done := s.feed.done

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not stop after the subscription ended")
	}
	if got := s.generation.Load(); got != 4 {
		t.Errorf("generation after four reports = %d, want 4", got)
	}
	s.Close()
}

// Close stops a reader blocked in next, and does not count the stop as a change.
func TestWatchRouteEventsCloseStopsTheReaderSilently(t *testing.T) {
	s := NewWatchSession(nil)
	src := newScriptedRouteEvents()
	s.followRoutes(src)
	done := s.feed.done
	if !s.FollowsRouteEvents() {
		t.Fatal("FollowsRouteEvents = false while the reader is blocked in its source")
	}

	s.Close()
	if s.FollowsRouteEvents() {
		t.Error("FollowsRouteEvents = true after Close")
	}
	select {
	case <-done:
	default:
		t.Fatal("Close returned before the reader exited")
	}
	if got := s.generation.Load(); got != 0 {
		t.Errorf("generation after Close = %d, want 0", got)
	}
	s.Close()
	if s.feed != nil {
		t.Error("feed still set after Close")
	}
}

// A source that fails ends the subscription, and nothing restarts it. The owner
// asks FollowsRouteEvents whether route changes still reach the session, so it
// must say no once the reader has stopped on its own.
func TestWatchRouteEventsEndedBySourceIsNotFollowed(t *testing.T) {
	s := NewWatchSession(nil)
	s.followRoutes(newScriptedRouteEvents(errors.New("netlink socket failed")))
	select {
	case <-s.feed.done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not stop after its source failed")
	}
	if s.FollowsRouteEvents() {
		t.Error("FollowsRouteEvents = true after the reader stopped on its own")
	}
	if got := s.generation.Load(); got != 1 {
		t.Errorf("generation after the failure = %d, want 1", got)
	}
	closed := make(chan struct{})
	go func() {
		s.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung after the reader had stopped")
	}
	if got := s.generation.Load(); got != 1 {
		t.Errorf("generation after Close = %d, want 1: a stop is not a change", got)
	}
}

// eventGraph is the production graph with one row's Run calling event after it
// has produced its result. The row's result is unchanged.
func eventGraph(n *watchNet, id ProbeID, event func()) []Probe {
	probes := n.graph()
	for i := range probes {
		if probes[i].ID != id {
			continue
		}
		run := probes[i].Run
		probes[i].Run = func(ctx context.Context, in map[ProbeID]ProbeResult) ProbeResult {
			r := run(ctx, in)
			event()
			return r
		}
	}
	return probes
}

// runInOrder runs the probes one at a time, in graph order, so a test can act
// between two rows. It is only valid for a graph whose order puts each row after
// its dependencies, which the production graph is.
func runInOrder(t *testing.T, probes []Probe) map[ProbeID]ProbeResult {
	t.Helper()
	results := map[ProbeID]ProbeResult{}
	for _, p := range probes {
		results[p.ID] = p.Run(context.Background(), results)
	}
	return results
}
