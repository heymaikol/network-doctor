//go:build integration

package diagnostic

// One Watch hour over real loopback sockets. The run starts with an initial pass
// at t=0 and then runs 720 scheduled passes, one every five seconds, so the last
// one falls at t=3600s. Both the benchmark and the lockstep test drive it through
// hourRun, so what the benchmark counts is what the test checks.
//
// Two schedules. The stable hour changes nothing on the network. The events hour
// adds a target outage with recovery, a route change that the session is never
// told about, and a route event reported with Invalidate. The route change is
// found only by the rows that read the route, which is the path a missed OS
// notification takes.

import (
	"maps"
	"sort"
	"sync"
	"testing"
	"time"
)

// hourScheduled is the number of scheduled passes after the initial one.
const hourScheduled = 720

// hourSchedule names the network changes an hour contains.
type hourSchedule string

const (
	scheduleStable hourSchedule = "stable"
	scheduleEvents hourSchedule = "events"
)

// hourArm names what runs each pass. incremental is the production session.
// forced is the same session with Force before every pass, so no row is reused:
// the negative control for reuse. fresh runs no session at all, the oracle that
// the other two are measured against.
type hourArm string

const (
	armIncremental hourArm = "incremental"
	armForced      hourArm = "forced"
	armFresh       hourArm = "fresh"
)

// Pass indexes of the events schedule. None of them is a multiple of realCadence,
// so each one lands on an incremental pass unless the event itself forces a whole
// measurement.
const (
	hourOutageStart = 150 // the target stops before this pass; passes up to hourOutageEnd-1 fail
	hourOutageEnd   = 153 // the target restarts before this pass
	hourRouteChange = 250 // route answers move to netdoc1; the session gets no event
	hourInvalidate  = 370 // the session is told of a route change through Invalidate
)

// hourTotals is what a whole run put on the wire, and how its passes ran. Traffic
// includes every attempt of every pass, the attempts a publish discarded included.
type hourTotals struct {
	published, full, incremental, discarded int
	traffic                                 traffic
	runs                                    map[ProbeID]int64
	routeCalls, dnsCalls                    int64
}

// hourRun is one run: the network it runs against, its clock, its session, and
// the totals of the passes recorded so far.
type hourRun struct {
	sched  hourSchedule
	n      *realNet
	clock  *watchClock
	s      *WatchSession
	totals hourTotals
}

func newHourRun(t testing.TB, sched hourSchedule) *hourRun {
	t.Helper()
	n := newRealNet(t)
	n.runs = newRunCounts()
	clock := newWatchClock()
	return &hourRun{sched: sched, n: n, clock: clock, s: NewWatchSession(clock.Now)}
}

// advance moves to pass i. The clock steps five seconds past the pass before, and
// the network changes scheduled for i happen before the pass runs. Pass 0 is the
// initial pass, at t=0.
func (h *hourRun) advance(i int) {
	if i > 0 {
		h.clock.Advance(5 * time.Second)
	}
	if h.sched != scheduleEvents {
		return
	}
	switch i {
	case hourOutageStart:
		h.n.stop()
	case hourOutageEnd:
		h.n.restart()
	case hourRouteChange:
		h.n.setIface("netdoc1")
	case hourInvalidate:
		h.s.Invalidate()
	}
}

// pass runs the current pass under arm and records it. The Interpret call is the
// one the headless loop makes on every published pass, so each arm pays for it.
func (h *hourRun) pass(arm hourArm) passRun {
	var p passRun
	switch arm {
	case armFresh:
		p = h.n.freshStep()
	case armForced:
		h.s.Force()
		p = h.n.watchStep(h.s)
	default:
		p = h.n.watchStep(h.s)
	}
	h.n.diagnosisOf(p)
	h.record(p)
	return p
}

// record adds one published pass to the totals. A pass that ran fresh measured the
// whole graph, so it is a full pass; every other published pass is incremental.
func (h *hourRun) record(p passRun) {
	h.totals.published++
	if p.fresh {
		h.totals.full++
	} else {
		h.totals.incremental++
	}
	h.totals.discarded += p.attempts - 1
	h.totals.traffic = h.totals.traffic.add(p.traffic)
}

// result returns the totals, with the probe runs and the fixture hook calls.
func (h *hourRun) result() hourTotals {
	t := h.totals
	t.runs = h.n.runs.snapshot()
	t.routeCalls = h.n.routeCalls.Load()
	t.dnsCalls = h.n.dnsCalls.Load()
	return t
}

// runCounts counts how many times each probe ran. Probes run concurrently within
// a pass, so the count is guarded.
type runCounts struct {
	mu sync.Mutex
	n  map[ProbeID]int64
}

func newRunCounts() *runCounts {
	return &runCounts{n: map[ProbeID]int64{}}
}

func (c *runCounts) inc(id ProbeID) {
	c.mu.Lock()
	c.n[id]++
	c.mu.Unlock()
}

func (c *runCounts) snapshot() map[ProbeID]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.n)
}

// orderedRunIDs lists the probe IDs in a run's counts, so a report prints them in
// the same order every time.
func orderedRunIDs(counts map[ProbeID]int64) []ProbeID {
	ids := make([]ProbeID, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// TestRealWatchOneHourMatchesFreshPasses runs each schedule's hour with the session
// and the oracle in lockstep over one network. Every pass must agree with the
// oracle. The stable hour must make exactly the full passes its schedule implies,
// and the events hour must handle each event the way the single-event tests
// require.
func TestRealWatchOneHourMatchesFreshPasses(t *testing.T) {
	for _, sched := range []hourSchedule{scheduleStable, scheduleEvents} {
		t.Run(string(sched), func(t *testing.T) {
			h := newHourRun(t, sched)
			var oracle traffic
			for i := 0; i <= hourScheduled; i++ {
				h.advance(i)
				inc := h.n.watchStep(h.s)
				// The oracle shares the network but not the run counts, so a probe it
				// runs is not counted as one the session ran.
				sessionRuns := h.n.runs
				h.n.runs = newRunCounts()
				want := h.n.freshStep()
				h.n.runs = sessionRuns
				if masked, differs := h.n.checkEquivalent(i, h.clock.Now(), inc, want); len(masked) != 0 || differs {
					t.Errorf("pass %d: masked %v, diagnosis differs %v; a %s hour must never mask a pass", i, masked, differs, sched)
				}
				h.record(inc)
				oracle = oracle.add(want.traffic)
				if sched == scheduleEvents {
					checkHourEvent(t, i, inc, want)
				}
			}
			tot := h.result()
			t.Logf("published=%d full=%d incremental=%d discarded=%d", tot.published, tot.full, tot.incremental, tot.discarded)
			t.Logf("session traffic %+v", tot.traffic)
			t.Logf("oracle traffic  %+v", oracle)
			if sched == scheduleStable {
				checkStableHour(t, tot)
			} else if tot.discarded != 1 {
				t.Errorf("events hour discarded %d attempts, want 1: the outage onset is the only pass a publish refuses", tot.discarded)
			}
		})
	}
}

// checkHourEvent asserts what each event does to the pass that sees it, using the
// same expectations as the single-event tests.
func checkHourEvent(t *testing.T, i int, inc, want passRun) {
	t.Helper()
	if i >= hourOutageStart && i < hourOutageEnd {
		if !inc.fresh {
			t.Errorf("pass %d: a failing pass was not fresh; an incident needs whole measurement", i)
		}
		if want.res[ProbeTargetTCP].Status != StatusFail {
			t.Errorf("pass %d: target is down but oracle target_tcp is %s", i, want.res[ProbeTargetTCP].Status)
		}
	}
	switch i {
	case hourOutageStart:
		if inc.attempts != 2 {
			t.Errorf("outage onset published on attempt %d, want 2: the reused HTTP row should have been discarded once", inc.attempts)
		}
	case hourOutageEnd:
		if inc.attempts != 1 {
			t.Errorf("recovery published on attempt %d, want 1", inc.attempts)
		}
	case hourRouteChange:
		if !inc.fresh || inc.attempts != 1 {
			t.Errorf("route change pass fresh %v attempts %d, want a whole measurement on attempt 1", inc.fresh, inc.attempts)
		}
	case hourRouteChange + 1:
		if inc.attempts != 1 || inc.traffic.clientHellos != 0 {
			t.Errorf("pass after the route change: attempts %d ClientHellos %d, want reuse to resume with no handshake", inc.attempts, inc.traffic.clientHellos)
		}
	case hourInvalidate:
		if !inc.fresh || inc.attempts != 1 {
			t.Errorf("Invalidate pass fresh %v attempts %d, want a whole measurement on attempt 1", inc.fresh, inc.attempts)
		}
	}
}

// checkStableHour asserts the counts a stable hour must produce. They follow from
// the schedule: a whole measurement at t=0 and every 60 seconds after it, so 61 in
// all and 660 incremental passes. Every pass dials the target twice, the path MTU
// row's dial included, and a whole pass adds the handshake, the request, and the
// plain endpoint's accept, dial and request.
func checkStableHour(t *testing.T, tot hourTotals) {
	t.Helper()
	passes, full := int64(hourScheduled+1), int64(hourScheduled/realCadence+1)
	if int64(tot.published) != passes || int64(tot.full) != full || int64(tot.incremental) != passes-full || tot.discarded != 0 {
		t.Errorf("stable hour published %d (full %d, incremental %d, discarded %d), want %d (full %d, incremental %d, discarded 0)",
			tot.published, tot.full, tot.incremental, tot.discarded, passes, full, passes-full)
	}
	got := tot.traffic
	if got.accepts != 2*passes || got.dials != 2*passes || got.clientHellos != full || got.handshakes != full || got.requests != full {
		t.Errorf("stable hour target traffic = %+v, want %d accepts and dials, %d ClientHellos, handshakes and requests", got, 2*passes, full)
	}
	if got.plainAccepts != full || got.plainDials != full || got.plainRequests != full {
		t.Errorf("stable hour plain traffic = accepts %d dials %d requests %d, want %d of each", got.plainAccepts, got.plainDials, got.plainRequests, full)
	}
	if got.udp != 0 {
		t.Errorf("stable hour made %d UDP connects, want 0: UDP only runs when TCP never connects", got.udp)
	}
	if got.bytesIn == 0 || got.plainBytesIn == 0 {
		t.Errorf("stable hour read %d target and %d plain bytes, want both non-zero: path MTU sends its payload on every pass, and every whole pass sends a request", got.bytesIn, got.plainBytesIn)
	}
	for _, id := range []ProbeID{ProbeTargetTCP, ProbePMTU} {
		if tot.runs[id] != passes {
			t.Errorf("stable hour ran %s %d times, want %d: it runs on every pass", id, tot.runs[id], passes)
		}
	}
	for _, id := range []ProbeID{ProbeTLS, ProbeHTTPS, ProbeHTTP} {
		if tot.runs[id] != full {
			t.Errorf("stable hour ran %s %d times, want %d: it runs only on whole passes", id, tot.runs[id], full)
		}
	}
}
