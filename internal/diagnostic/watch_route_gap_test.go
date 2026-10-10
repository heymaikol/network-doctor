package diagnostic

import (
	"context"
	"testing"
	"time"
)

// quicFaultGraph is the production graph for watchTarget with the QUIC row
// turned faulty. The fault changes only that row's result. It is the shape of
// a route change that QUIC reads and no always-fresh row reads: production QUIC
// connects to the connectivity host and records no route (quic.go:138), and its
// only dependency is the interface row, whose fingerprint does not cover that
// host's route.
func quicFaultGraph(n *watchNet, fault *bool) []Probe {
	probes := n.graph()
	for i := range probes {
		if probes[i].ID != ProbeQUIC {
			continue
		}
		run := probes[i].Run
		probes[i].Run = func(ctx context.Context, in map[ProbeID]ProbeResult) ProbeResult {
			r := run(ctx, in)
			if *fault {
				return ProbeResult{Status: StatusFail, Cause: "timeout", Dur: r.Dur}
			}
			return r
		}
	}
	return probes
}

// faultPass runs one published pass over the QUIC fault graph, the way watchPass
// does: an unpublished pass is followed at once by a fresh one.
func faultPass(t *testing.T, s *WatchSession, n *watchNet, fault *bool) (map[ProbeID]ProbeResult, map[ProbeID]int, int) {
	t.Helper()
	for attempt := 1; attempt <= 2; attempt++ {
		n.resetRuns()
		pass := s.Begin(quicFaultGraph(n, fault), time.Second)
		results := RunAll(context.Background(), pass.Probes(), time.Second)
		if pass.Publish(results) {
			return results, n.snapshotRuns(), attempt
		}
	}
	t.Fatal("a fresh pass was not published")
	return nil, nil, 0
}

// Without a route event, a change that only a reused row reads is seen at max
// age. This pins the time-bounded fallback that every route-event test is
// measured against: the QUIC row keeps reporting its old PASS for every pass
// inside watchMaxAge, and fails on the first pass that is not reused.
func TestWatchQUICPathChangeSeenOnlyAtMaxAge(t *testing.T) {
	const cadence = 5 * time.Second
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	fault := false

	faultPass(t, s, n, &fault)
	path := s.path
	changedAt := clock.now
	fault = true

	masked := 0
	var detected map[ProbeID]ProbeResult
	var detectedRuns map[ProbeID]int
	var detectedAttempts int
	for detected == nil {
		clock.Advance(cadence)
		results, runs, attempts := faultPass(t, s, n, &fault)
		if s.path != path {
			t.Fatalf("pass at +%v changed the path key", clock.now.Sub(changedAt))
		}
		quic := results[ProbeQUIC]
		if quic.Status == StatusPass {
			masked++
			if masked > int(watchMaxAge/cadence) {
				t.Fatalf("QUIC still PASS %d passes after the change, past max age", masked)
			}
			if _, reused := quic.ReusedFrom(); !reused {
				t.Errorf("masked pass %d did not reuse QUIC", masked)
			}
			if runs[ProbeQUIC] != 0 {
				t.Errorf("masked pass %d ran QUIC %d times, want 0", masked, runs[ProbeQUIC])
			}
			continue
		}
		detected, detectedRuns, detectedAttempts = results, runs, attempts
	}

	latency := clock.now.Sub(changedAt)
	t.Logf("detection: masked=%d latency=%v (watchMaxAge=%v)", masked, latency, watchMaxAge)

	if q := detected[ProbeQUIC]; q.Status != StatusFail || q.Cause != "timeout" {
		t.Fatalf("detecting pass: QUIC %v cause %q, want fail timeout", q.Status, q.Cause)
	}
	if detectedRuns[ProbeQUIC] != 1 || detectedAttempts != 1 {
		t.Errorf("detecting pass: QUIC runs=%d attempts=%d, want 1 run, 1 attempt", detectedRuns[ProbeQUIC], detectedAttempts)
	}
	if latency != watchMaxAge {
		t.Errorf("detection latency %v, want exactly watchMaxAge %v: QUIC is reused until max age", latency, watchMaxAge)
	}
}
