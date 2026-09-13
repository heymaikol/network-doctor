// Retest inside a watch session. Pressing R asks the same diagnostic question
// again, so it restarts the run without ending the session that has been
// answering that question; naming a different target is a different question
// and does end it.

package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// failingWatch is a watch session mid-outage: passes failing passes five
// seconds apart, so there is one open incident whose duration is not a moment
// old and a sparkline with something in it.
func failingWatch(t *testing.T, passes int) (model, time.Time) {
	t.Helper()
	start := time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC)
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch, m.width, m.height = true, 100, 40
	for i := range passes {
		recordWatchPass(&m, start.Add(time.Duration(i)*5*time.Second), true, "wlan0")
	}
	return m, start
}

// openIncident reads the single incident the session is expected to be holding
// open, and reports when it began and how many failing passes it has counted.
func openIncident(t *testing.T, m model, when string) (time.Time, int) {
	t.Helper()
	items := m.incidents.Incidents()
	if len(items) != 1 {
		t.Fatalf("%s: %d incidents, want exactly one", when, len(items))
	}
	if !items[0].Active() {
		t.Fatalf("%s: the incident reads as recovered while the target is still failing", when)
	}
	return items[0].Started, items[0].Passes
}

// TestRetestKeepsTheWatchSession is the bug: a reader acts on the remediation
// netdoc printed, presses the key that remediation names, and the watch history
// they were reading is gone. The incident is the sharp end of it, since one
// reopened by the retest reports a duration that is not how long the failure
// has been going on.
func TestRetestKeepsTheWatchSession(t *testing.T) {
	m, start := failingWatch(t, 8)
	// The target connect is the probe recordWatchPass fails, so its history is
	// the one whose glyphs and failure count say how long the outage has run.
	probe := diagnostic.ProbeTargetTCP
	before := len(m.runHistory[probe])
	if before != 8 {
		t.Fatalf("the session recorded %d passes, want 8", before)
	}
	began, passes := openIncident(t, m, "before the retest")
	if !began.Equal(start) {
		t.Fatalf("the incident began at %s, want %s", began, start)
	}

	after := asModel(t, must(m.Update(keyMsg("R"))))
	if got := len(after.runHistory[probe]); got != before {
		t.Errorf("the retest left %d recorded passes, want the session's %d", got, before)
	}
	gotBegan, gotPasses := openIncident(t, after, "after the retest")
	if !gotBegan.Equal(began) {
		t.Errorf("the retest moved the incident's start to %s, want %s", gotBegan, began)
	}
	if gotPasses != passes {
		t.Errorf("the retest reset the failing pass count to %d, want %d", gotPasses, passes)
	}

	// The pass the retest runs continues the session rather than opening a
	// second incident beside the one still on screen.
	recordWatchPass(&after, start.Add(40*time.Second), true, "wlan0")
	nextBegan, nextPasses := openIncident(t, after, "after the retest's own pass")
	if !nextBegan.Equal(began) {
		t.Errorf("the retest's pass restarted the incident at %s, want %s", nextBegan, began)
	}
	if nextPasses != passes+1 {
		t.Errorf("the retest's pass counted %d failing passes, want %d", nextPasses, passes+1)
	}
	if got := len(after.runHistory[probe]); got != before+1 {
		t.Errorf("the retest's pass left %d recorded passes, want %d", got, before+1)
	}
	if spark := ansi.Strip(after.statusSparkline(probe, 0)); len([]rune(spark)) != before+1 {
		t.Errorf("the sparkline drew %q, want %d glyphs", spark, before+1)
	}
	if line := ansi.Strip(after.historyLine(probe)); !strings.Contains(line, "failed 9 of 9 runs") {
		t.Errorf("the history line reads %q, want the whole session's runs", line)
	}
}

// TestRepeatedRetestsKeepTheWatchSession: the loss was one press deep, so
// leaning on R while waiting for a fix has to leave the same session behind
// every time rather than eroding it press by press.
func TestRepeatedRetestsKeepTheWatchSession(t *testing.T) {
	m, start := failingWatch(t, 4)
	probe := m.probes[0].ID
	began, passes := openIncident(t, m, "before the retests")
	for i := range 5 {
		m = asModel(t, must(m.Update(keyMsg("R"))))
		if got := len(m.runHistory[probe]); got != 4 {
			t.Fatalf("retest %d left %d recorded passes, want 4", i, got)
		}
		gotBegan, gotPasses := openIncident(t, m, "after a retest")
		if !gotBegan.Equal(began) || gotPasses != passes {
			t.Fatalf("retest %d reports %d failing passes since %s, want %d since %s",
				i, gotPasses, gotBegan, passes, began)
		}
	}
	recordWatchPass(&m, start.Add(time.Minute), true, "wlan0")
	if _, got := openIncident(t, m, "after the retests"); got != passes+1 {
		t.Errorf("the pass after five retests counted %d failing passes, want %d", got, passes+1)
	}
}

// TestADeferredRetestKeepsTheWatchSession: a retest with a tool still running
// is held until that tool's terminal event lands, so the intent has to travel
// on the held action rather than being re-derived from the target when it runs.
func TestADeferredRetestKeepsTheWatchSession(t *testing.T) {
	m, _ := failingWatch(t, 3)
	probe := m.probes[0].ID
	began, passes := openIncident(t, m, "before the retest")
	m.cur = jobState{name: "port scan", status: JobRunning, active: &job{cancel: func() {}}}

	held := asModel(t, must(m.Update(keyMsg("R"))))
	if held.pending == nil || held.pending.kind != pendRestart {
		t.Fatal("a retest with a job running must be deferred, not dropped")
	}
	held.cur.active, held.cur.status = nil, JobCanceled
	ran := asModel(t, must(held.runPending(held.pending)))
	if got := len(ran.runHistory[probe]); got != 3 {
		t.Errorf("the deferred retest left %d recorded passes, want 3", got)
	}
	gotBegan, gotPasses := openIncident(t, ran, "after the deferred retest")
	if !gotBegan.Equal(began) || gotPasses != passes {
		t.Errorf("the deferred retest reports %d failing passes since %s, want %d since %s",
			gotPasses, gotBegan, passes, began)
	}
}

// TestRetestDoesNotHoldARecoveredIncidentOpen: keeping the session must not
// keep the failure. The incident still closes on the pass that recovers, and a
// later outage is still a second incident rather than a resumption of the first.
func TestRetestDoesNotHoldARecoveredIncidentOpen(t *testing.T) {
	m, start := failingWatch(t, 3)
	after := asModel(t, must(m.Update(keyMsg("R"))))
	recordWatchPass(&after, start.Add(30*time.Second), false, "wlan0")
	items := after.incidents.Incidents()
	if len(items) != 1 || items[0].Active() {
		t.Fatalf("incidents = %+v, want the one incident closed by the recovery", items)
	}
	if items[0].Passes != 3 {
		t.Errorf("the recovered incident holds %d failing passes, want 3", items[0].Passes)
	}
	recordWatchPass(&after, start.Add(35*time.Second), true, "wlan0")
	if items = after.incidents.Incidents(); len(items) != 2 || !items[1].Active() {
		t.Fatalf("incidents = %+v, want a second, open incident", items)
	}
	if want := start.Add(35 * time.Second); !items[1].Started.Equal(want) {
		t.Errorf("the second incident began at %s, want %s", items[1].Started, want)
	}
}

// TestANewTargetStillEndsTheWatchSession: the history describes the question it
// was collected against, so a different question starts over. This is what
// applyTarget has always done and the reason its reset cannot simply go.
func TestANewTargetStillEndsTheWatchSession(t *testing.T) {
	m, _ := failingWatch(t, 5)
	probe := m.probes[0].ID
	m.incidentViewing, m.incidentSelected = true, 0
	if len(m.runHistory[probe]) == 0 {
		t.Fatal("the session recorded nothing to lose")
	}
	after := asModel(t, must(m.restartWithTarget(mustTarget(t, "other.test:443"), true)))
	if got := len(after.runHistory[probe]); got != 0 {
		t.Errorf("a new target kept %d recorded passes from the old one", got)
	}
	if items := after.incidents.Incidents(); len(items) != 0 {
		t.Errorf("a new target kept %d incidents from the old one", len(items))
	}
	if after.incidentViewing {
		t.Error("a new target left the incident viewer open on the old target's incident")
	}
}

// TestTheRestartPromptStartsOverOnTheSameTarget pins what retyping the current
// target at the restart prompt does. The prompt is the user naming a run, and R
// is the key that repeats the one on screen, so the prompt stays a new session
// even when the line it commits is unchanged. Recorded so that revisiting it is
// a decision rather than a side effect of something else.
func TestTheRestartPromptStartsOverOnTheSameTarget(t *testing.T) {
	m, _ := failingWatch(t, 5)
	probe := m.probes[0].ID
	// The real path: r opens the prompt already filled with the current target.
	prompt := asModel(t, must(m.Update(keyMsg("r"))))
	if !prompt.entering || prompt.input.Value() != m.target.Raw {
		t.Fatalf("the restart prompt opened on %q, want %q", prompt.input.Value(), m.target.Raw)
	}
	after := asModel(t, must(prompt.Update(keyPress("enter"))))
	if got := len(after.runHistory[probe]); got != 0 {
		t.Errorf("the restart prompt kept %d recorded passes; change this test deliberately", got)
	}
	if items := after.incidents.Incidents(); len(items) != 0 {
		t.Errorf("the restart prompt kept %d incidents; change this test deliberately", len(items))
	}
}

// TestRetestOutsideWatchModeRecordsNothing: the session state belongs to watch
// mode, and a one-shot run has none of it on either side of a retest.
func TestRetestOutsideWatchModeRecordsNothing(t *testing.T) {
	m := pinnedRun(t, mustTarget(t, "example.com:443"))
	after := asModel(t, must(m.retest()))
	if len(after.runHistory) != 0 || len(after.incidents.Incidents()) != 0 {
		t.Errorf("a one-shot retest invented watch state: %d histories, %d incidents",
			len(after.runHistory), len(after.incidents.Incidents()))
	}
	if after.target == nil || after.target.Raw != "example.com:443" {
		t.Errorf("the retest changed the target to %v", after.target)
	}
	if len(after.results) != 0 {
		t.Errorf("the retest kept %d stale results", len(after.results))
	}
	if !strings.Contains(after.notice, "retesting example.com:443") {
		t.Errorf("the retest notice reads %q", after.notice)
	}
}

// TestARetestRebuildsTheSameProbesUnderAKeptSession: the preserved history is
// keyed by probe ID, so it would silently mismatch if a retest ever rebuilt a
// different plan than the one those passes were recorded against.
func TestARetestRebuildsTheSameProbesUnderAKeptSession(t *testing.T) {
	m, _ := failingWatch(t, 2)
	before := probeIDs(m)
	after := asModel(t, must(m.Update(keyMsg("R"))))
	if got := probeIDs(after); len(got) != len(before) {
		t.Fatalf("the retest rebuilt %d probes, want %d", len(got), len(before))
	}
	for i, id := range probeIDs(after) {
		if id != before[i] {
			t.Fatalf("the retest rebuilt a different plan: %v, want %v", probeIDs(after), before)
		}
	}
	for _, id := range before {
		if got := len(after.runHistory[id]); got != 2 {
			t.Errorf("probe %s kept %d recorded passes, want 2", id, got)
		}
	}
	if after.publicDNS != m.publicDNS || after.probeTimeout != m.probeTimeout {
		t.Errorf("the retest changed the resolver or timeout: %q %v", after.publicDNS, after.probeTimeout)
	}
	if after.sources != m.sources || after.snapshotCheck != nil || after.snapshotSkip != nil {
		t.Error("the retest changed the run configuration the kept history was recorded under")
	}
}

// TestRetestLeavesTheCursorOnTheRowTheReaderWasOn: the cursor is an index into
// the probe list, and a retest rebuilds the identical list, so the row stays
// the row. It matters more once the session is preserved than it did before: a
// pass with a session behind it takes focusTarget's changed-row branch, which
// moves nothing when the pass reports what the one before it did, so a cursor
// sent back to the top here would stay at the top with nothing to recover it.
func TestRetestLeavesTheCursorOnTheRowTheReaderWasOn(t *testing.T) {
	m, _ := failingWatch(t, 3)
	row := probeIndex(t, m, diagnostic.ProbeTargetTCP)
	m.selected = row

	after := asModel(t, must(m.Update(keyMsg("R"))))
	if after.selected != row {
		t.Errorf("the retest moved the cursor to row %d (%s), want row %d (%s)",
			after.selected, after.probes[after.selected].ID, row, diagnostic.ProbeTargetTCP)
	}
	// The pass the retest runs repeats the failure, so nothing changed rows and
	// nothing should move the cursor off the one the reader was reading.
	settled := watchRun(t, after, map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeTargetTCP: diagnostic.StatusFail,
	})
	if settled.selected != row {
		t.Errorf("the retest's pass moved the cursor to row %d (%s), want row %d (%s)",
			settled.selected, settled.probes[settled.selected].ID, row, diagnostic.ProbeTargetTCP)
	}
}

// TestANewTargetStillSendsTheCursorBack: the other side of the same index. A
// different target is a different probe list, so the row the cursor held is not
// a row of it and the cursor starts at the top.
func TestANewTargetStillSendsTheCursorBack(t *testing.T) {
	m, _ := failingWatch(t, 3)
	m.selected = probeIndex(t, m, diagnostic.ProbeTargetTCP)
	after := asModel(t, must(m.restartWithTarget(mustTarget(t, "other.test:443"), true)))
	if after.selected != 0 {
		t.Errorf("a new target left the cursor on row %d, want the top", after.selected)
	}
}
