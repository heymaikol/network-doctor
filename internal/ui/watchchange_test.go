// Watch mode's changes-first checks list: which rows a completed pass reports
// as different from the one before it, how they are drawn, and where a pass
// that differs is allowed to move the cursor.

package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// watchModel is a watched run against one target, which is the shape the
// change markers are for: a plan with a DNS rung and the target rungs behind
// it, so an upstream change has downstream rows to take with it.
func watchModel(t *testing.T) model {
	t.Helper()
	return NewWithSelection(mustTarget(t, "example.com:443"), nil, false, true, "", "test",
		diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)
}

func statusOr(status map[diagnostic.ProbeID]diagnostic.Status, id diagnostic.ProbeID) diagnostic.Status {
	if s, ok := status[id]; ok {
		return s
	}
	return diagnostic.StatusPass
}

// watchRun drives one whole watch pass through the real Update path: a pass
// already on screen is restarted first the way the watch tick restarts it,
// every probe but the last is filled in directly, and the last arrives as the
// probeDoneMsg that completes the pass. That message is where recordRun and
// the focus decision both live, so a test that took a shortcut around it would
// be testing neither. status names the probes that are not passing.
func watchRun(t *testing.T, m model, status map[diagnostic.ProbeID]diagnostic.Status) model {
	t.Helper()
	if m.allDone() {
		u, _ := m.Update(watchMsg{gen: m.generation})
		m = asModel(t, u)
	}
	last := m.probes[len(m.probes)-1]
	for _, p := range m.probes {
		m.started[p.ID] = true
		if p.ID == last.ID {
			continue
		}
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: statusOr(status, p.ID), Detail: "detail", Fix: "fix"}
	}
	u, _ := m.Update(probeDoneMsg{id: last.ID, gen: m.generation,
		res: diagnostic.ProbeResult{ID: last.ID, Status: statusOr(status, last.ID), Detail: "detail", Fix: "fix"}})
	return asModel(t, u)
}

// watchRow is the Checks panel's rendered row for one probe: glyph, name,
// sparkline and whatever labels the row carries. It matches on the name field
// alone, because a probe name can be a prefix of another one ("HTTP
// example.com" of "HTTPS example.com") and a plain substring search would
// return the wrong row.
func watchRow(t *testing.T, m model, v string, id diagnostic.ProbeID) string {
	t.Helper()
	name := m.probes[probeIndex(t, m, id)].Name
	for _, row := range checksRows(v) {
		text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(row), "›"))
		if _, rest, ok := strings.Cut(text, " "); ok && (rest == name || strings.HasPrefix(rest, name+"  ")) {
			return row
		}
	}
	return ""
}

// dnsOutage is the pass where the resolver stops answering and every rung
// behind it never gets to run: one changed cause and five changed
// consequences.
var dnsOutage = map[diagnostic.ProbeID]diagnostic.Status{
	diagnostic.ProbeDNS:       diagnostic.StatusFail,
	diagnostic.ProbeTargetTCP: diagnostic.StatusSkip,
	diagnostic.ProbePMTU:      diagnostic.StatusSkip,
	diagnostic.ProbeTLS:       diagnostic.StatusSkip,
	diagnostic.ProbeHTTP:      diagnostic.StatusSkip,
	diagnostic.ProbeHTTPS:     diagnostic.StatusSkip,
}

// TestFirstWatchPassMarksNothingChanged: the first pass has nothing to differ
// from, so marking its rows would call the whole screen news. The cursor still
// lands on the row the diagnosis blames, which is what a first result has
// always done.
func TestFirstWatchPassMarksNothingChanged(t *testing.T) {
	m := watchRun(t, watchModel(t), dnsOutage)
	nm, v := renderAt(t, m)
	if strings.Contains(ansi.Strip(v), changedLabel) {
		t.Errorf("the first watch pass already marks changed rows:\n%s", v)
	}
	if want := probeIndex(t, nm, diagnostic.ProbeDNS); nm.selected != want {
		t.Errorf("selected = %d, want the blamed row %d", nm.selected, want)
	}
}

// TestIdenticalWatchPassMarksNothingChanged: nothing happened, so the screen
// says nothing happened.
func TestIdenticalWatchPassMarksNothingChanged(t *testing.T) {
	m := watchRun(t, watchRun(t, watchModel(t), dnsOutage), dnsOutage)
	if _, v := renderAt(t, m); strings.Contains(ansi.Strip(v), changedLabel) {
		t.Errorf("an identical watch pass marks changed rows:\n%s", v)
	}
	if m.changedRow(diagnostic.ProbeDNS) {
		t.Error("a failure that is still failing is not a change")
	}
}

// TestWatchStatusTransitionsAreChanges walks the transitions the marker is
// defined over. A recovery counts exactly as loudly as a new failure: "this
// came back" is the thing the reader was waiting for.
func TestWatchStatusTransitionsAreChanges(t *testing.T) {
	for _, tc := range []struct {
		name     string
		from, to diagnostic.Status
		want     bool
	}{
		{"pass to fail", diagnostic.StatusPass, diagnostic.StatusFail, true},
		{"fail to pass", diagnostic.StatusFail, diagnostic.StatusPass, true},
		{"pass to warn", diagnostic.StatusPass, diagnostic.StatusWarn, true},
		{"warn to pass", diagnostic.StatusWarn, diagnostic.StatusPass, true},
		{"fail to skip", diagnostic.StatusFail, diagnostic.StatusSkip, true},
		{"skip to fail", diagnostic.StatusSkip, diagnostic.StatusFail, true},
		{"fail to fail", diagnostic.StatusFail, diagnostic.StatusFail, false},
		{"n/a to n/a", diagnostic.StatusNA, diagnostic.StatusNA, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// QUIC is a sibling of everything else on the plan, so moving it
			// moves exactly one row and the assertion is about that row.
			id := diagnostic.ProbeQUIC
			m := watchRun(t, watchModel(t), map[diagnostic.ProbeID]diagnostic.Status{id: tc.from})
			m = watchRun(t, m, map[diagnostic.ProbeID]diagnostic.Status{id: tc.to})
			history := m.runHistory[id]
			if len(history) != 2 || history[0] != tc.from || history[1] != tc.to {
				t.Fatalf("history = %v, want [%v %v]", history, tc.from, tc.to)
			}
			if got := m.changedRow(id); got != tc.want {
				t.Fatalf("changedRow = %v, want %v", got, tc.want)
			}
			_, v := renderAt(t, m)
			row := watchRow(t, m, v, id)
			if row == "" {
				// An unchanged N/A row is behind the compact summary, which
				// is the point: only a change pulls a row back out.
				if tc.want {
					t.Fatalf("a changed row was left behind the summary:\n%s", v)
				}
				if strings.Contains(ansi.Strip(v), changedLabel) {
					t.Fatalf("nothing changed and the view says otherwise:\n%s", v)
				}
				return
			}
			if got := strings.Contains(ansi.Strip(row), changedLabel); got != tc.want {
				t.Fatalf("row %q carries the label = %v, want %v", ansi.Strip(row), got, tc.want)
			}
		})
	}
}

// TestWatchChangeKeepsARecoveredRowOnScreen: the finished view collapses
// passing rows, and a check that just came back is a passing row. Collapsing
// it would hide the one line the reader was waiting for, so it stays for the
// pass it changed on. The rest of the passing rows still collapse, and the
// user's own expand state is not touched.
func TestWatchChangeKeepsARecoveredRowOnScreen(t *testing.T) {
	m := watchRun(t, watchModel(t), map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeQUIC: diagnostic.StatusFail})
	// The reader moves off the failing row first, so the recovered row cannot
	// stay on screen merely by being the row the cursor is on.
	m = press(t, m, "j")
	if m.selected == probeIndex(t, m, diagnostic.ProbeQUIC) {
		t.Fatal("the cursor did not leave the QUIC row")
	}
	m = watchRun(t, m, nil) // everything passes again
	nm, v := renderAt(t, m)
	if nm.selected == probeIndex(t, nm, diagnostic.ProbeQUIC) {
		t.Fatal("the pass took the cursor back to QUIC, so this proves nothing")
	}
	if nm.expanded {
		t.Fatal("the change marker must not expand the list on the reader's behalf")
	}
	row := watchRow(t, nm, v, diagnostic.ProbeQUIC)
	if row == "" || !strings.Contains(ansi.Strip(row), changedLabel) {
		t.Fatalf("the recovered row is not on screen as a change:\n%s", v)
	}
	if collapsedRow(v) == "" {
		t.Errorf("the other passing rows stopped collapsing:\n%s", v)
	}
	// The next pass repeats the recovery, so it is no longer news.
	next := watchRun(t, nm, nil)
	_, v = renderAt(t, next)
	if strings.Contains(ansi.Strip(v), changedLabel) {
		t.Errorf("the marker outlived the pass that earned it:\n%s", v)
	}
}

// TestWatchChangeMarkerSharesTheRowWithConsequence: a row can be both. The
// pass took QUIC down along with egress, so it is news and it is the same
// outage seen again, and the row has to say both without losing its sparkline.
func TestWatchChangeMarkerSharesTheRowWithConsequence(t *testing.T) {
	offline := map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeInternet:     diagnostic.StatusFail,
		diagnostic.ProbeQUIC:         diagnostic.StatusFail,
		diagnostic.ProbeDNS:          diagnostic.StatusFail,
		diagnostic.ProbeDNSEncrypted: diagnostic.StatusFail,
		diagnostic.ProbeTargetTCP:    diagnostic.StatusSkip,
		diagnostic.ProbePMTU:         diagnostic.StatusSkip,
		diagnostic.ProbeTLS:          diagnostic.StatusSkip,
		diagnostic.ProbeHTTP:         diagnostic.StatusSkip,
		diagnostic.ProbeHTTPS:        diagnostic.StatusSkip,
	}
	m := watchRun(t, watchRun(t, watchModel(t), nil), offline)
	nm, v := renderAt(t, m)
	row := ansi.Strip(watchRow(t, nm, v, diagnostic.ProbeQUIC))
	if row == "" {
		t.Fatalf("QUIC has no row:\n%s", v)
	}
	if !strings.Contains(row, changedLabel) || !strings.Contains(row, consequenceLabel) {
		t.Fatalf("row %q must carry both labels", row)
	}
	if spark := ansi.Strip(nm.statusSparkline(diagnostic.ProbeQUIC, 8)); !strings.Contains(row, spark) {
		t.Fatalf("row %q lost its sparkline %q", row, spark)
	}
}

// TestWatchChangeFocusesTheCausalRow: the resolver went down and took five
// rungs with it. The cursor belongs on the resolver, not on the first thing
// downstream of it that also changed.
func TestWatchChangeFocusesTheCausalRow(t *testing.T) {
	m := watchRun(t, watchRun(t, watchModel(t), nil), dnsOutage)
	if want := probeIndex(t, m, diagnostic.ProbeDNS); m.selected != want {
		t.Fatalf("selected = %d (%s), want the DNS row %d", m.selected, m.probes[m.selected].ID, want)
	}
	for _, id := range []diagnostic.ProbeID{diagnostic.ProbeTargetTCP, diagnostic.ProbeTLS, diagnostic.ProbeHTTPS} {
		if !m.changedRow(id) {
			t.Errorf("%s flipped to skip and is not marked: the downstream evidence is worth keeping", id)
		}
	}
}

// outage is the run with egress already down, which is what makes the rows on
// the dead rung read as consequences rather than as findings of their own. The
// proxy is unset so the egress failure is not downgraded to a warning, and the
// resolver still answers so the verdict is about egress rather than DNS.
func outage(extra map[diagnostic.ProbeID]diagnostic.Status) map[diagnostic.ProbeID]diagnostic.Status {
	status := map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeInternet: diagnostic.StatusFail,
		diagnostic.ProbeProxy:    diagnostic.StatusNA,
	}
	for id, s := range extra {
		status[id] = s
	}
	return status
}

// TestWatchChangeFocusSkipsRowsAlreadyExplainedAsConsequences: egress was
// already down and stayed down, so QUIC joining it is the same outage seen
// again and comes first in probe order. The path MTU coming back is the
// independent event, and that is the row worth the cursor.
func TestWatchChangeFocusSkipsRowsAlreadyExplainedAsConsequences(t *testing.T) {
	m := watchRun(t, watchModel(t), outage(map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbePMTU: diagnostic.StatusWarn,
	}))
	m = watchRun(t, m, outage(map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeQUIC: diagnostic.StatusFail,
	}))
	quic := probeIndex(t, m, diagnostic.ProbeQUIC)
	if !m.changedRow(diagnostic.ProbeQUIC) || !m.changedRow(diagnostic.ProbePMTU) {
		t.Fatalf("the pass did not change both rows: %v", m.runHistory)
	}
	if !diagnostic.Collateral(m.target, m.probeOrder(), m.results)[diagnostic.ProbeQUIC] {
		t.Fatal("QUIC is not a consequence in this shape, so this proves nothing")
	}
	if want := probeIndex(t, m, diagnostic.ProbePMTU); m.selected != want {
		t.Fatalf("selected = %d (%s), want the path MTU row %d, not the consequence at %d",
			m.selected, m.probes[m.selected].ID, want, quic)
	}
}

// TestWatchChangeFocusFallsBackToTheFirstChangedRow: when every changed row is
// already explained as a consequence of a failure that did not itself change,
// there is no causal row to prefer, so the first changed row is the answer.
// Marking nothing at all would lose the pass.
func TestWatchChangeFocusFallsBackToTheFirstChangedRow(t *testing.T) {
	m := watchRun(t, watchModel(t), outage(nil))
	m = watchRun(t, m, outage(map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeQUIC:         diagnostic.StatusFail,
		diagnostic.ProbeDNSEncrypted: diagnostic.StatusFail,
	}))
	collateral := diagnostic.Collateral(m.target, m.probeOrder(), m.results)
	for _, id := range []diagnostic.ProbeID{diagnostic.ProbeQUIC, diagnostic.ProbeDNSEncrypted} {
		if !m.changedRow(id) || !collateral[id] {
			t.Fatalf("%s must be a changed consequence for this to be the fallback case", id)
		}
	}
	if want := probeIndex(t, m, diagnostic.ProbeQUIC); m.selected != want {
		t.Fatalf("selected = %d (%s), want the first changed row %d", m.selected, m.probes[m.selected].ID, want)
	}
}

// TestWatchRefreshKeepsAUserMovedCursor is the regression this feature could
// most easily introduce: a pass that has something to say must still not take
// the cursor off the row the reader put it on.
func TestWatchRefreshKeepsAUserMovedCursor(t *testing.T) {
	m := watchRun(t, watchModel(t), nil)
	m = press(t, m, "j")
	if !m.selMoved {
		t.Fatal("the down key did not register as a cursor move")
	}
	where := m.selected
	m = watchRun(t, m, dnsOutage)
	if !m.selMoved || m.selected != where {
		t.Fatalf("selected = %d (moved = %v), want the reader's row %d", m.selected, m.selMoved, where)
	}
}

// TestUnchangedWatchPassLeavesTheCursorAlone: a change moves the cursor once,
// and the identical passes after it leave the reader where the change put
// them. Yanking the selection back on every tick is what made watch mode a
// table that refreshes rather than a monitor.
func TestUnchangedWatchPassLeavesTheCursorAlone(t *testing.T) {
	m := watchRun(t, watchModel(t), nil)
	m = watchRun(t, m, map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeQUIC: diagnostic.StatusFail})
	quic := probeIndex(t, m, diagnostic.ProbeQUIC)
	if m.selected != quic {
		t.Fatalf("selected = %d, want the changed row %d", m.selected, quic)
	}
	// Two more passes saying exactly the same thing.
	for pass := 0; pass < 2; pass++ {
		m = watchRun(t, m, map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeQUIC: diagnostic.StatusFail})
		if m.selected != quic {
			t.Fatalf("pass %d moved the cursor to %d", pass, m.selected)
		}
	}
}

// TestWatchChangeDoesNotDisturbOpenState: the pass lands underneath whatever
// the reader is in the middle of, so the open viewer, the LAN map and its
// opened device all survive it, and a reader inside the viewer does not have
// the list scrolled out from under them.
func TestWatchChangeDoesNotDisturbOpenState(t *testing.T) {
	m := watchRun(t, watchModel(t), nil)
	m.viewing, m.follow = true, true
	m.networkMap, m.mapSelected, m.networkCIDR = true, 2, "192.168.1.0/24"
	m.svc = serviceChoice{host: "192.168.1.5", name: "printer", done: true}
	where := m.selected
	m = watchRun(t, m, dnsOutage)
	if !m.viewing || !m.networkMap || m.mapSelected != 2 || m.networkCIDR != "192.168.1.0/24" {
		t.Fatalf("the pass disturbed open state: viewing=%v map=%v sel=%d cidr=%q",
			m.viewing, m.networkMap, m.mapSelected, m.networkCIDR)
	}
	if m.svc.host != "192.168.1.5" {
		t.Fatalf("the opened device was dropped: %+v", m.svc)
	}
	if m.selected != where {
		t.Fatalf("selected = %d, want %d: a reader inside the viewer keeps their row", m.selected, where)
	}
}

// TestInProgressWatchPassMarksNothingChanged: once the next pass starts, the
// rows on screen are its partial results while the history still describes the
// pass before them. Comparing across that boundary would flicker a marker onto
// a row that has not answered yet.
func TestInProgressWatchPassMarksNothingChanged(t *testing.T) {
	m := watchRun(t, watchRun(t, watchModel(t), nil), dnsOutage)
	if _, v := renderAt(t, m); !strings.Contains(ansi.Strip(v), changedLabel) {
		t.Fatalf("the completed pass marks nothing:\n%s", v)
	}
	u, _ := m.Update(watchMsg{gen: m.generation})
	running := asModel(t, u)
	running.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass}
	if running.changedRow(diagnostic.ProbeDNS) {
		t.Error("a pass still running already claims a row changed")
	}
	if _, v := renderAt(t, running); strings.Contains(ansi.Strip(v), changedLabel) {
		t.Errorf("the in-progress pass draws change markers:\n%s", v)
	}
}

// TestNoChangeMarkersOutsideWatchMode: a single run has no previous pass to
// mean anything, so the label belongs to watch mode alone.
func TestNoChangeMarkersOutsideWatchMode(t *testing.T) {
	m := offlineRun(t, nil)
	for _, p := range m.probes {
		m.runHistory[p.ID] = []diagnostic.Status{diagnostic.StatusPass, m.results[p.ID].Status}
	}
	if _, v := renderAt(t, m); strings.Contains(ansi.Strip(v), changedLabel) {
		t.Errorf("a single run marks changed rows:\n%s", v)
	}
}

// TestWatchChangeMarkerSurvivesNarrowTerminals: the labels are placed against
// the panel's own width, so a second one on a row never widens the block past
// the terminal and never leaves a panel border unclosed. The signal is read
// off stripped output, which is what a NO_COLOR terminal shows.
func TestWatchChangeMarkerSurvivesNarrowTerminals(t *testing.T) {
	for _, width := range []int{40, 60, 80, 100, 140} {
		m := watchRun(t, watchRun(t, watchModel(t), nil), dnsOutage)
		m.width, m.height = width, 40
		block := m.bodyView(false, 0)
		if got := lipgloss.Width(block); got > width {
			t.Errorf("width %d: the block is %d columns wide:\n%s", width, got, block)
		}
		if n := unclosedPanels(block); n != 0 {
			t.Errorf("width %d: %d panel border(s) left unclosed:\n%s", width, n, block)
		}
		if !strings.Contains(ansi.Strip(block), changedLabel) {
			t.Errorf("width %d: the change signal is gone without colour:\n%s", width, block)
		}
	}
}

// TestWatchChangeMarkerFitsConstrainedHeights: a marked row is still a row the
// block's budget has to price, wrap included.
func TestWatchChangeMarkerFitsConstrainedHeights(t *testing.T) {
	m := watchRun(t, watchRun(t, watchModel(t), nil), dnsOutage)
	for _, h := range []int{40, 30, 24, 20, 16, 14, 12, 10} {
		u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: h})
		nm := asModel(t, u)
		if rows := lipgloss.Height(nm.View()); rows > h {
			t.Errorf("height %d: the view is %d rows:\n%s", h, rows, nm.View())
		}
	}
}
