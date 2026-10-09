package ui

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	ndoc "github.com/heymaikol/network-doctor/internal/snapshot"
)

// fakeWatchClock is the clock a TUI Watch test runs on. The session and the
// incident timeline both read it, so a reused row's age is decided by the test.
type fakeWatchClock struct{ now time.Time }

func newFakeWatchClock() *fakeWatchClock {
	return &fakeWatchClock{now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeWatchClock) Now() time.Time { return c.now }

func (c *fakeWatchClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// watchModelOn is watchModel on a clock the test controls.
func watchModelOn(t *testing.T, clock *fakeWatchClock) model {
	t.Helper()
	return NewWithSelection(mustTarget(t, "example.com:443"), nil, false, true, "", "test",
		diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{},
		func(m *model) { m.now = clock.Now }).(model)
}

// tuiWatchSetup starts a TUI Watch run on the fake network and waits for its
// first pass, which measures every row.
func tuiWatchSetup(t *testing.T, clock *fakeWatchClock, link *tuiLink) model {
	t.Helper()
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	target := mustTarget(t, "example.com:443")
	m := watchModelOn(t, clock)
	m.graph = func(*diagnostic.Target) []diagnostic.Probe { return tuiFakeProbes(target, link) }
	m.buildPass()
	m = settleWatch(t, m, m.Init())
	if !m.allDone() {
		t.Fatal("first pass did not finish")
	}
	return m
}

// A stable stretch that reuses rows opens no incident and leaves no evidence,
// and the incident that opens after it keeps the last pass that measured every
// row as its Before. Its onset compares against that pass, and nothing in the
// comparison is a row that did not run this pass.
func TestWatchTUIIncidentBeforeIsTheLastMeasuredPass(t *testing.T) {
	clock := newFakeWatchClock()
	link := &tuiLink{}
	m := tuiWatchSetup(t, clock, link)
	measured := clock.now

	for i := 0; i < 4; i++ {
		clock.advance(5 * time.Second)
		m = startWatchPass(t, m)
	}
	if got := len(m.runHistory[diagnostic.ProbeTargetTCP]); got != 5 {
		t.Fatalf("after four stable passes, target history has %d entries, want 5", got)
	}
	if n := len(m.incidents.Incidents()); n != 0 {
		t.Fatalf("a stable stretch opened %d incidents", n)
	}

	clock.advance(5 * time.Second)
	link.down.Store(true)
	m = startWatchPass(t, m)
	open, ok := m.incidents.Active()
	if !ok {
		t.Fatal("the outage opened no incident")
	}
	if open.Before == nil {
		t.Fatal("incident has no Before state")
	}
	if !open.Before.At.Equal(measured) {
		t.Fatalf("Before observed at %v, want the last pass that measured every row, at %v", open.Before.At, measured)
	}
	if open.Passes != 1 || len(open.Steps) != 0 {
		t.Errorf("open incident has %d failing passes and %d steps, want 1 and none", open.Passes, len(open.Steps))
	}
	// A row behind the failed connect is skipped, so it stops running for a real
	// reason. Any other row that stopped running would be reuse reading as a change.
	onsetStatus := map[string]string{}
	for _, c := range open.Onset.Snap.Checks {
		onsetStatus[c.ID] = c.Status
	}
	for _, c := range open.OnsetChanges {
		if strings.HasSuffix(c.Path, ".ran") && onsetStatus[c.Check] != ndoc.StatusSkip {
			t.Errorf("onset recorded %q as a change though %s is %s: reuse must not read as a row that stopped running", c.Path, c.Check, onsetStatus[c.Check])
		}
	}
	s := exportedIncident(t, m)
	if s.Incident == nil || s.Incident.Before == nil || !s.Incident.Before.OK {
		t.Error("exported incident has no healthy Before state")
	}
}

// A silent fault in a reused row is seen once the row's observation is older
// than the maximum age, so it is never masked for longer than that.
func TestWatchTUISilentFaultSurfacesAtMaxAge(t *testing.T) {
	const maxAge = 60 * time.Second
	clock := newFakeWatchClock()
	link := &tuiLink{}
	m := tuiWatchSetup(t, clock, link)
	started := clock.now

	link.tlsDown.Store(true)
	for i := 0; i < 30 && len(m.incidents.Incidents()) == 0; i++ {
		clock.advance(5 * time.Second)
		m = startWatchPass(t, m)
	}
	open, ok := m.incidents.Active()
	if !ok {
		t.Fatal("a silent TLS fault never opened an incident")
	}
	if lag := open.Started.Sub(started); lag > maxAge {
		t.Errorf("silent TLS fault surfaced %v after it began, want at most %v", lag, maxAge)
	}
	if got := open.Latest().Snap; got.OK {
		t.Error("the incident's failing state reads ok")
	}
}

// A pass that reused a row is shown with the time that row was measured, so the
// report cannot present an earlier measurement as this pass's.
func TestWatchTUIReportLabelsReusedRows(t *testing.T) {
	clock := newFakeWatchClock()
	link := &tuiLink{}
	m := tuiWatchSetup(t, clock, link)
	measured := clock.now.UTC().Format(time.RFC3339)

	clock.advance(5 * time.Second)
	m = startWatchPass(t, m)
	if !anyReused(m) {
		t.Fatal("stable pass reused no row, so there is nothing to label")
	}
	rep := m.report()
	if !strings.Contains(rep, "reused: measured "+measured+" on an earlier pass") {
		t.Errorf("report does not label the reused rows with the pass that measured them, want %q", measured)
	}
}

// After a pass that is not OK, every row runs on every pass until the network
// is OK again, so the failure and its recovery are measured in full.
func TestWatchTUIFailingStretchMeasuresEveryRow(t *testing.T) {
	clock := newFakeWatchClock()
	link := &tuiLink{}
	m := tuiWatchSetup(t, clock, link)
	clock.advance(5 * time.Second)
	m = startWatchPass(t, m)

	link.down.Store(true)
	for pass := 0; pass < 2; pass++ {
		clock.advance(5 * time.Second)
		m = startWatchPass(t, m)
		if anyReused(m) {
			t.Errorf("failing pass %d reused a row", pass+1)
		}
	}

	link.down.Store(false)
	clock.advance(5 * time.Second)
	before := link.runs.Load()
	m = startWatchPass(t, m)
	if anyReused(m) {
		t.Error("recovery pass reused a row")
	}
	ran := 0
	for _, r := range m.results {
		if r.Status != diagnostic.StatusSkip {
			ran++
		}
	}
	if got := link.runs.Load() - before; got != int64(ran) {
		t.Errorf("recovery pass ran %d rows, want all %d that were scheduled", got, ran)
	}
	if got := m.runHistory[diagnostic.ProbeTargetTCP]; got[len(got)-1] != diagnostic.StatusPass {
		t.Errorf("recovered target history ends in %v, want pass", got[len(got)-1])
	}
}

// A target switch starts a new session, so its first pass runs every row even
// though the previous target had reusable rows.
func TestWatchTUITargetSwitchRunsEveryRowFirst(t *testing.T) {
	clock := newFakeWatchClock()
	link := &tuiLink{}
	m := tuiWatchSetup(t, clock, link)
	clock.advance(5 * time.Second)
	m = startWatchPass(t, m)
	if !anyReused(m) {
		t.Fatal("stable pass reused no row before the switch")
	}

	before := link.runs.Load()
	u, cmd := m.restartWithTarget(mustTarget(t, "other.test:443"), true)
	m = settleWatch(t, asModel(t, u), cmd)
	if got := link.runs.Load() - before; got != int64(len(m.probes)) {
		t.Errorf("first pass after a target switch ran %d of %d rows, want all", got, len(m.probes))
	}
	if anyReused(m) {
		t.Error("first pass after a target switch reused a row from the previous target")
	}
}

// tuiCancelableProbes is tuiFakeProbes, except that a row whose context is
// already cancelled reports a failure instead of running. A restart cancels the
// rows still in flight, so their late answers are what a cancelled pass sends.
func tuiCancelableProbes(target *diagnostic.Target, link *tuiLink, cancelled *atomic.Int32) []diagnostic.Probe {
	probes := tuiFakeProbes(target, link)
	for i := range probes {
		run := probes[i].Run
		probes[i].Run = func(ctx context.Context, prev map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
			if ctx.Err() != nil {
				cancelled.Add(1)
				return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Cause: "canceled", Detail: "canceled before it ran", Dur: time.Millisecond}
			}
			return run(ctx, prev)
		}
	}
	return probes
}

// settlePartly runs the commands of an Update the way settleWatch does, but
// stops once stopAfter probes have reported. It returns the commands it did not
// run, which a cancel then leaves in flight.
func settlePartly(t *testing.T, m model, stopAfter int, cmds ...tea.Cmd) (model, []tea.Cmd) {
	t.Helper()
	queue := append([]tea.Cmd(nil), cmds...)
	reported := 0
	for len(queue) > 0 && reported < stopAfter {
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		switch msg := runCmd(c).(type) {
		case tea.BatchMsg:
			queue = append(queue, msg...)
		case scheduleMsg, probeDoneMsg:
			if _, ok := msg.(probeDoneMsg); ok {
				reported++
			}
			u, next := m.Update(msg)
			m = asModel(t, u)
			queue = append(queue, next)
		}
	}
	return m, queue
}

// A cancel that lands mid-pass is a restart. The cancelled rows answer late
// with the old generation, so the TUI must drop them: nothing from the cancelled
// pass is published, recorded in the status history, or opened as an incident,
// and the pass that replaces it is fresh. It is checked for a reused pass, which
// is the case that gained a publish rule, and for a forced retest pass.
func TestWatchCancelledPassLeavesNoEvidenceThroughTheTUI(t *testing.T) {
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	cases := []struct {
		name  string
		start func(m model) (tea.Model, tea.Cmd)
	}{
		{"reused pass", func(m model) (tea.Model, tea.Cmd) { return m.Update(watchMsg{gen: m.generation}) }},
		{"forced retest pass", func(m model) (tea.Model, tea.Cmd) { return m.retest() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeWatchClock()
			link := &tuiLink{}
			var cancelled atomic.Int32
			target := mustTarget(t, "example.com:443")
			m := watchModelOn(t, clock)
			m.graph = func(*diagnostic.Target) []diagnostic.Probe { return tuiCancelableProbes(target, link, &cancelled) }
			m.buildPass()
			m = settleWatch(t, m, m.Init())
			clock.advance(5 * time.Second)
			m = startWatchPass(t, m)

			historyBefore := len(m.runHistory[diagnostic.ProbeTargetTCP])
			incidentsBefore := len(m.incidents.Incidents())

			clock.advance(5 * time.Second)
			u, cmd := tc.start(m)
			m, rest := settlePartly(t, asModel(t, u), 3, cmd)
			if m.allDone() {
				t.Fatal("the pass finished before the cancel, so nothing was in flight")
			}
			cancelledBefore := cancelled.Load()

			clock.advance(5 * time.Second)
			link.down.Store(true)
			u, cmd = m.retest()
			m = settleWatch(t, asModel(t, u), append(rest, cmd)...)
			if !m.allDone() {
				t.Fatal("the replacement pass did not finish")
			}
			if n := cancelled.Load() - cancelledBefore; n == 0 {
				t.Fatal("no in-flight row saw its cancel, so the late answers were never produced")
			}

			if got := len(m.runHistory[diagnostic.ProbeTargetTCP]); got != historyBefore+1 {
				t.Errorf("status history has %d entries, want %d: the cancelled pass must not be recorded", got, historyBefore+1)
			}
			if got := m.runHistory[diagnostic.ProbeTargetTCP]; got[len(got)-1] != diagnostic.StatusFail {
				t.Errorf("latest recorded target status = %v, want fail from the replacement pass that saw the outage", got[len(got)-1])
			}
			if got := len(m.incidents.Incidents()); got != incidentsBefore+1 {
				t.Errorf("incidents = %d, want %d: the outage opens one incident, and the cancelled answers open none", got, incidentsBefore+1)
			}
			if cause := m.results[diagnostic.ProbeTargetTCP].Cause; cause == "canceled" {
				t.Error("the shown target result is a cancelled answer")
			}
			if anyReused(m) {
				t.Error("the replacement pass reused a row, so it was not a fresh pass")
			}
		})
	}
}
