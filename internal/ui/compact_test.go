// The compact results view: which rows a finished run is worth showing, the
// one line the rest collapse into, and the expand action that brings them back.

package ui

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// sectionSpan is where one body section sits on screen: the display column its
// rule starts at, and how many columns wide that rule is. The sections are not
// boxed, so the rule under a heading is what says which columns belong to it.
type sectionSpan struct{ col, width int }

// ruleSpans is the runs of rule characters on one rendered line, or nil when
// the line is not a rule. A rule line carries nothing but rule characters and
// the gutter between two of them, so a row that happens to contain one is not
// mistaken for a section boundary.
func ruleSpans(line string) []sectionSpan {
	runes := []rune(ansi.Strip(line))
	var spans []sectionSpan
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '─':
			start := i
			for i < len(runes) && runes[i] == '─' {
				i++
			}
			spans = append(spans, sectionSpan{col: start, width: i - start})
			i--
		case ' ':
		default:
			return nil
		}
	}
	return spans
}

// sectionCell is the text one section's columns carry on a rendered line.
func sectionCell(line string, sp sectionSpan) string {
	plain := ansi.Strip(line)
	if sp.col >= ansi.StringWidth(plain) {
		return ""
	}
	return strings.TrimSpace(ansi.Cut(plain, sp.col, sp.col+sp.width))
}

// bodySections is the rendered body's sections keyed by their heading. The
// heading sits over a rule as wide as the section's own column, and the rows
// under it are that column's slice of the lines below, down to the blank row
// that closes the block or the rule that opens the next section. Reading the
// columns rather than the whole line matters side by side, where the Details
// section repeats probe names the Checks section is not showing as rows.
func bodySections(v string) map[string][]string {
	lines := strings.Split(v, "\n")
	out := map[string][]string{}
	for i, line := range lines {
		spans := ruleSpans(line)
		if len(spans) == 0 || i == 0 {
			continue
		}
		for _, sp := range spans {
			title := sectionCell(lines[i-1], sp)
			if title == "" {
				continue
			}
			rows := []string{}
			for j := i + 1; j < len(lines); j++ {
				if strings.TrimSpace(ansi.Strip(lines[j])) == "" || ruleSpans(lines[j]) != nil {
					break
				}
				if row := sectionCell(lines[j], sp); row != "" {
					rows = append(rows, row)
				}
			}
			out[title] = rows
		}
	}
	return out
}

// checksRows is the Checks section's rows as rendered, its heading and rule
// left out.
func checksRows(v string) []string { return bodySections(v)["Checks"] }

// rowProbes is the probes the Checks panel gives a row to, which is not every
// probe in the run: the Wi-Fi row is gone from the panel while its probe still
// runs for the context strip, the report and the JSON output.
func rowProbes(m model) []diagnostic.Probe {
	var probes []diagnostic.Probe
	for _, i := range m.checkRows() {
		probes = append(probes, m.probes[i])
	}
	return probes
}

// hasRow reports whether name is one of the Checks panel's own rows.
func hasRow(v, name string) bool {
	return slices.ContainsFunc(checksRows(v), func(row string) bool { return strings.Contains(row, name) })
}

// collapsedRow is the Checks panel's summary line, "" when it drew none. It
// matches on the expand hint rather than on the wording, because the summary
// names passing and not-applicable rows apart and a wording match would find
// only one of those phrasings.
func collapsedRow(v string) string {
	for _, row := range checksRows(v) {
		if strings.Contains(row, "expand)") {
			return row
		}
	}
	return ""
}

// renderAt is the view at a terminal size wide enough for two columns and
// tall enough that nothing is shed for want of rows.
func renderAt(t *testing.T, m model) (model, string) {
	t.Helper()
	u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	nm := asModel(t, u)
	return nm, nm.View()
}

// press sends one key through the real Update path.
func press(t *testing.T, m model, key string) model {
	t.Helper()
	u, _ := m.Update(keyMsg(key))
	return asModel(t, u)
}

// passingRowsOffScreen counts the probes that passed and are not rendered as
// their own row. It is computed from the view, so it cannot agree with a
// count the view derived some other way.
func passingRowsOffScreen(m model, v string) int {
	n := 0
	for _, probe := range rowProbes(m) {
		if m.results[probe.ID].Status == diagnostic.StatusPass && !hasRow(v, probe.Name) {
			n++
		}
	}
	return n
}

// healthyModel is a finished run in which every check passed.
func healthyModel(t *testing.T) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, "")
	return m
}

// TestCompactViewCollapsesPassingChecks is the healthy case: a run with
// nothing to say spends one row saying it, not thirteen.
func TestCompactViewCollapsesPassingChecks(t *testing.T) {
	m, v := renderAt(t, healthyModel(t))
	rows := checksRows(v)
	if len(rows) >= len(m.probes) {
		t.Fatalf("compact view still renders %d rows for %d probes:\n%s", len(rows), len(m.probes), v)
	}
	summary := collapsedRow(v)
	if summary == "" {
		t.Fatalf("no collapsed summary row:\n%s", v)
	}
	want := fmt.Sprintf("%d other checks passed", passingRowsOffScreen(m, v))
	if !strings.Contains(summary, want) {
		t.Errorf("summary = %q, want the hidden count %q", summary, want)
	}
	if !strings.Contains(summary, "a expand") {
		t.Errorf("summary = %q, want the key that expands it", summary)
	}
}

// TestCompactCountIsWhatTheViewActuallyHid pins the count to the rows the
// mechanism left out. A count of every passing row, or a hard-coded one,
// disagrees with it: the cursor row passed too and is on screen.
func TestCompactCountIsWhatTheViewActuallyHid(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) model
	}{
		{"healthy", healthyModel},
		{"one failure", func(t *testing.T) model {
			m := newModel(mustTarget(t, "example.com:443"), false)
			doneResults(&m, diagnostic.ProbeDNS)
			return m
		}},
		{"path mtu black hole", blackHoleModel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, v := renderAt(t, tc.build(t))
			hidden := passingRowsOffScreen(m, v)
			passed := 0
			for _, probe := range m.probes {
				if m.results[probe.ID].Status == diagnostic.StatusPass {
					passed++
				}
			}
			if hidden >= passed {
				t.Fatalf("every passing row is hidden (%d of %d), so the count cannot tell the two apart", hidden, passed)
			}
			summary := collapsedRow(v)
			if !strings.Contains(summary, fmt.Sprintf("%d other checks passed", hidden)) {
				t.Errorf("summary = %q, want %d hidden rows (%d passed in total):\n%s", summary, hidden, passed, v)
			}
		})
	}
}

// TestCompactViewKeepsFailingRow: the row the reader came for stays.
func TestCompactViewKeepsFailingRow(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, diagnostic.ProbeDNS)
	m, v := renderAt(t, m)

	name := probeName(t, m, diagnostic.ProbeDNS)
	if !hasRow(v, name) {
		t.Errorf("the failing row %q must stay visible:\n%s", name, v)
	}
	if collapsedRow(v) == "" {
		t.Errorf("the passing rows must still collapse around it:\n%s", v)
	}
}

// TestCompactViewKeepsWarnRow: a warning is not a pass, whether or not the
// verdict rests on it. This one does not: nothing blames the QUIC row.
func TestCompactViewKeepsWarnRow(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, "")
	m.results[diagnostic.ProbeQUIC] = diagnostic.ProbeResult{ID: diagnostic.ProbeQUIC, Status: diagnostic.StatusWarn}
	m, v := renderAt(t, m)

	if blamed := m.diagnosis().Focus(); blamed == diagnostic.ProbeQUIC {
		t.Fatalf("the diagnosis blames the QUIC row, so this no longer tests the Warn rule on its own")
	}
	name := probeName(t, m, diagnostic.ProbeQUIC)
	if !hasRow(v, name) {
		t.Errorf("the warning row %q must stay visible:\n%s", name, v)
	}
}

// TestCompactViewKeepsBlamedPathMTUWarn is the regression case. The Path MTU
// row is only a Warn, so severity alone hides it, and it is not the cursor
// row either: the one thing keeping it on screen is that the diagnosis blames
// it, and the banner sends the reader straight to it.
func TestCompactViewKeepsBlamedPathMTUWarn(t *testing.T) {
	m := blackHoleModel(t)
	if got := m.results[diagnostic.ProbePMTU].Status; got != diagnostic.StatusWarn {
		t.Fatalf("Path MTU is %v, want a Warn: the case no longer covers the downgraded blamed row", got)
	}
	if blamed := m.diagnosis().Focus(); blamed != diagnostic.ProbePMTU {
		t.Fatalf("the diagnosis blames %q, want the Path MTU row", blamed)
	}
	pmtu := slices.IndexFunc(m.probes, func(p diagnostic.Probe) bool { return p.ID == diagnostic.ProbePMTU })
	if m.selected == pmtu {
		t.Fatalf("the cursor is already on the Path MTU row, which would keep it visible on its own")
	}

	m, v := renderAt(t, m)
	name := probeName(t, m, diagnostic.ProbePMTU)
	if !hasRow(v, name) {
		t.Fatalf("the blamed row %q must stay visible even as a Warn:\n%s", name, v)
	}
	// It is on screen, so it is not one of the checks the summary says it hid.
	if hidden := passingRowsOffScreen(m, v); !strings.Contains(collapsedRow(v), fmt.Sprintf("%d other checks passed", hidden)) {
		t.Errorf("the blamed row leaked into the hidden count: summary = %q, hidden = %d", collapsedRow(v), hidden)
	}
	if !strings.Contains(v, "see the Path MTU row") {
		t.Errorf("the verdict still points at a row, so the row has to be there:\n%s", v)
	}
}

// TestBlamedRowIsAlwaysOnScreen is the invariant the Path MTU case is one
// instance of: whatever row the diagnosis sends the reader to, the compact
// view is showing it. The row comes from focusRow, so this holds however
// the diagnosis decides to point later, including at a row whose own
// status would not have earned it a place.
func TestBlamedRowIsAlwaysOnScreen(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) model
	}{
		{"healthy", healthyModel},
		{"one failure", func(t *testing.T) model {
			m := newModel(mustTarget(t, "example.com:443"), false)
			doneResults(&m, diagnostic.ProbeDNS)
			return m
		}},
		{"path mtu black hole", blackHoleModel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, v := renderAt(t, tc.build(t))
			blamed := m.focusRow()
			if blamed < 0 {
				return // the run blames no row at all
			}
			if !hasRow(v, m.probes[blamed].Name) {
				t.Errorf("the diagnosis blames %q, which the view hid:\n%s", m.probes[blamed].Name, v)
			}
		})
	}
}

// TestCompactViewKeepsEveryAbnormalRow: the blamed row is not a quota. Every
// Fail and Warn survives, not just the first one and not just the one the
// verdict names.
func TestCompactViewKeepsEveryAbnormalRow(t *testing.T) {
	m, v := renderAt(t, blackHoleModel(t))
	abnormal := 0
	for _, probe := range m.probes {
		status := m.results[probe.ID].Status
		if status != diagnostic.StatusFail && status != diagnostic.StatusWarn {
			continue
		}
		abnormal++
		if !hasRow(v, probe.Name) {
			t.Errorf("%v row %q must stay visible:\n%s", status, probe.Name, v)
		}
	}
	if abnormal < 3 {
		t.Fatalf("%d abnormal rows is not enough to tell 'every' from 'the first'", abnormal)
	}
}

// TestCompactViewKeepsRowsThatDidNotPass: a skipped check is not a passed
// one. It keeps its row, and it is not counted as a check that passed.
func TestCompactViewKeepsRowsThatDidNotPass(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, "")
	m.results[diagnostic.ProbeProxy] = diagnostic.ProbeResult{ID: diagnostic.ProbeProxy, Status: diagnostic.StatusSkip}
	m, v := renderAt(t, m)

	name := probeName(t, m, diagnostic.ProbeProxy)
	if !hasRow(v, name) {
		t.Errorf("the skipped row %q must stay visible:\n%s", name, v)
	}
	if hidden := passingRowsOffScreen(m, v); !strings.Contains(collapsedRow(v), fmt.Sprintf("%d other checks passed", hidden)) {
		t.Errorf("skipped rows leaked into the passed count: summary = %q, hidden = %d", collapsedRow(v), hidden)
	}
}

// TestNoCollapsedRowWhenNothingIsHidden: a run with nothing to collapse says
// nothing, rather than reporting that it collapsed zero checks.
func TestNoCollapsedRowWhenNothingIsHidden(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	for _, probe := range m.probes {
		m.results[probe.ID] = diagnostic.ProbeResult{ID: probe.ID, Status: diagnostic.StatusFail}
	}
	_, v := renderAt(t, m)
	if summary := collapsedRow(v); summary != "" {
		t.Errorf("nothing was hidden, so there is no summary to draw, got %q:\n%s", summary, v)
	}
	if strings.Contains(v, "0 other") {
		t.Errorf("the view reports hiding zero checks:\n%s", v)
	}
}

// TestNothingCollapsesWhileTheRunIsUnfinished: the progress list is the whole
// point while the checks are still running, and there is no verdict yet to
// decide what matters.
func TestNothingCollapsesWhileTheRunIsUnfinished(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	for _, probe := range m.probes[:3] {
		m.results[probe.ID] = diagnostic.ProbeResult{ID: probe.ID, Status: diagnostic.StatusPass}
	}
	m, v := renderAt(t, m)
	if collapsedRow(v) != "" {
		t.Errorf("an unfinished run must not collapse anything:\n%s", v)
	}
	for _, probe := range rowProbes(m) {
		if !hasRow(v, probe.Name) {
			t.Errorf("row %q disappeared mid-run:\n%s", probe.Name, v)
		}
	}
}

// TestCursorRowStaysVisibleInCompactView: the Details panel describes the
// cursor row, so a compact list that hid it would leave the panel talking
// about a row the reader cannot see or move off.
func TestCursorRowStaysVisibleInCompactView(t *testing.T) {
	m, _ := renderAt(t, healthyModel(t))
	for step := range m.probes {
		m = press(t, m, "j")
		_, v := renderAt(t, m)
		name := m.probes[m.selected].Name
		if !hasCursorRow(v, name) {
			t.Fatalf("step %d: the cursor row %q is not on screen:\n%s", step, name, v)
		}
		if !strings.Contains(v, "Details: "+name) {
			t.Fatalf("step %d: the Details panel is describing another row:\n%s", step, v)
		}
	}
}

// TestExpandRevealsExactlyTheHiddenRows: the action brings back the rows the
// summary stood for, in probe order, and takes them away again.
func TestExpandRevealsExactlyTheHiddenRows(t *testing.T) {
	compact, v := renderAt(t, healthyModel(t))
	var hiddenNames []string
	for _, probe := range rowProbes(compact) {
		if !hasRow(v, probe.Name) {
			hiddenNames = append(hiddenNames, probe.Name)
		}
	}
	if len(hiddenNames) == 0 {
		t.Fatal("nothing was hidden, so there is nothing for expand to reveal")
	}

	expanded, ev := renderAt(t, press(t, compact, "a"))
	if collapsedRow(ev) != "" {
		t.Errorf("the summary row must go when the rows it stood for come back:\n%s", ev)
	}
	for _, name := range hiddenNames {
		if !hasRow(ev, name) {
			t.Errorf("expand did not reveal %q:\n%s", name, ev)
		}
	}
	// Deterministic ordering: the rows read in probe order, the same order the
	// diagnosis walks them in.
	var want []string
	for _, probe := range rowProbes(expanded) {
		want = append(want, probe.Name)
	}
	var got []string
	for _, row := range checksRows(ev) {
		for _, probe := range expanded.probes {
			if strings.Contains(row, probe.Name) {
				got = append(got, probe.Name)
				break
			}
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("expanded row order = %v, want %v", got, want)
	}

	_, cv := renderAt(t, press(t, expanded, "a"))
	if collapsedRow(cv) == "" {
		t.Errorf("expand must toggle back to the compact view:\n%s", cv)
	}
}

// TestExpandIsPresentationOnly: the action moves no needle outside the view.
func TestExpandIsPresentationOnly(t *testing.T) {
	before := blackHoleModel(t)
	summary, verdict := before.diagnose(before.probeOrder())
	report := before.report()
	blamed := before.focusRow()
	// Copied out, not read back off the model: the two models share one
	// results map, so comparing them to each other would agree with any
	// change made through either.
	statuses := map[diagnostic.ProbeID]diagnostic.Status{}
	for _, probe := range before.probes {
		statuses[probe.ID] = before.results[probe.ID].Status
	}

	after := press(t, before, "a")
	if !after.expanded {
		t.Fatal("expand did not toggle the presentation state")
	}
	gotSummary, gotVerdict := after.diagnose(after.probeOrder())
	if gotSummary != summary || gotVerdict != verdict {
		t.Errorf("diagnosis changed: %q/%q, want %q/%q", gotSummary, gotVerdict, summary, verdict)
	}
	if got := after.focusRow(); got != blamed {
		t.Errorf("blamed row changed: %d, want %d", got, blamed)
	}
	if got := after.report(); got != report {
		t.Errorf("the report changed:\n%s\nwant\n%s", got, report)
	}
	for _, probe := range before.probes {
		if got := after.results[probe.ID].Status; got != statuses[probe.ID] {
			t.Errorf("result for %q changed: %v, want %v", probe.ID, got, statuses[probe.ID])
		}
	}
	if after.selected != before.selected || len(after.started) != len(before.started) {
		t.Errorf("expand touched cursor or probe execution state")
	}
}

func TestExpandKeyStaysOutOfThePersistentFooter(t *testing.T) {
	m := healthyModel(t)
	m.width = 100
	if bar := m.helpView(false); strings.Contains(bar, "expand") {
		t.Errorf("compact footer advertises expand: %q", bar)
	}
	expanded := press(t, m, "a")
	bar := expanded.helpView(false)
	if strings.Contains(bar, "collapse") {
		t.Errorf("expanded footer advertises collapse: %q", bar)
	}
}

// probeName is the display name of one probe in this run.
func probeName(t *testing.T, m model, id diagnostic.ProbeID) string {
	t.Helper()
	for _, probe := range m.probes {
		if probe.ID == id {
			return probe.Name
		}
	}
	t.Fatalf("probe %q is not in this run", id)
	return ""
}

// naProbeDetails are the not-applicable rows a real run produces on a machine
// with no proxy set and no reachable public resolver. The details are the
// strings the probes themselves write, so a test that finds one has found the
// probe's own evidence and not a fixture's invention.
//
// The Wi-Fi probe is N/A on the same machine and is deliberately not here: it
// has no Checks row to collapse, reveal or walk the cursor onto, so it says
// nothing about the mechanism these fixtures exercise.
var naProbeDetails = map[diagnostic.ProbeID]string{
	diagnostic.ProbeProxy:     "no proxy environment variables set",
	diagnostic.ProbeDNSPublic: "public DNS unavailable via 8.8.8.8: timeout",
}

// naModel is a finished run carrying those three not-applicable rows. failID
// fails, everything else passes.
func naModel(t *testing.T, failID diagnostic.ProbeID) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, failID)
	for id, detail := range naProbeDetails {
		r, ok := m.results[id]
		if !ok {
			t.Fatalf("probe %s is not in this run, so the fixture cannot make it N/A", id)
		}
		r.Status, r.Detail = diagnostic.StatusNA, detail
		m.results[id] = r
	}
	return m
}

// naRowsOffScreen counts the not-applicable probes with no row of their own.
func naRowsOffScreen(m model, v string) int {
	n := 0
	for _, probe := range rowProbes(m) {
		if m.results[probe.ID].Status == diagnostic.StatusNA && !hasRow(v, probe.Name) {
			n++
		}
	}
	return n
}

// TestCompactViewHidesNotApplicableRows: "not applicable" is not a call to
// action, so those rows do not spend a line of the default screen saying so.
// The row the reader came for is still there.
func TestCompactViewHidesNotApplicableRows(t *testing.T) {
	m, v := renderAt(t, naModel(t, diagnostic.ProbeDNS))
	for id, detail := range naProbeDetails {
		name := probeName(t, m, id)
		if hasRow(v, name) {
			t.Errorf("N/A row %q is still in the Checks view:\n%s", name, v)
		}
		if strings.Contains(v, detail) {
			t.Errorf("N/A evidence %q leaked out of Details:\n%s", detail, v)
		}
	}
	if !hasRow(v, probeName(t, m, diagnostic.ProbeDNS)) {
		t.Errorf("the failing row was hidden along with the N/A ones:\n%s", v)
	}
}

// TestCollapsedRowCountsPassedAndNAApart pins the summary to the rows the
// mechanism actually hid, and keeps the two kinds named apart: "passed" is a
// claim about the network, "N/A" is a claim about the question.
func TestCollapsedRowCountsPassedAndNAApart(t *testing.T) {
	t.Run("mixed", func(t *testing.T) {
		m, v := renderAt(t, naModel(t, diagnostic.ProbeDNS))
		pass, na := passingRowsOffScreen(m, v), naRowsOffScreen(m, v)
		if pass == 0 || na == 0 {
			t.Fatalf("fixture hid %d passing and %d N/A rows, so it cannot tell the wording apart", pass, na)
		}
		want := fmt.Sprintf("%d passed, %d N/A", pass, na)
		if summary := collapsedRow(v); !strings.Contains(summary, want) {
			t.Errorf("summary = %q, want %q:\n%s", summary, want, v)
		}
	})
	t.Run("only N/A hidden", func(t *testing.T) {
		m := naModel(t, "")
		// Everything that is not N/A fails, so no passing row is left to hide.
		for _, probe := range m.probes {
			if r := m.results[probe.ID]; r.Status == diagnostic.StatusPass {
				r.Status = diagnostic.StatusFail
				m.results[probe.ID] = r
			}
		}
		m, v := renderAt(t, m)
		na := naRowsOffScreen(m, v)
		if na == 0 {
			t.Fatalf("no N/A row was hidden:\n%s", v)
		}
		want := fmt.Sprintf("%d other checks N/A", na)
		if summary := collapsedRow(v); !strings.Contains(summary, want) {
			t.Errorf("summary = %q, want %q:\n%s", summary, want, v)
		}
	})
}

// TestCollapsedRowFitsThePanel: the summary sits in a 36-column panel, and a
// row that wraps costs the block a second display row no row count saw coming.
func TestCollapsedRowFitsThePanel(t *testing.T) {
	for _, tc := range []struct{ pass, na int }{{13, 0}, {0, 13}, {13, 13}, {1, 1}} {
		row := ansi.Strip(healthyModel(t).collapsedChecksRow(tc.pass, tc.na))
		if w := lipgloss.Width(row); w > 36 {
			t.Errorf("collapsedChecksRow(%d, %d) = %q, %d columns wide, want at most 36", tc.pass, tc.na, row, w)
		}
	}
}

// TestNotApplicableRowsStayReachableWithTheCursor is the discoverability
// contract. The cursor walks every probe, hidden or not, and the row it lands
// on comes back with the Details panel that carries the probe's evidence.
func TestNotApplicableRowsStayReachableWithTheCursor(t *testing.T) {
	m := naModel(t, diagnostic.ProbeDNS)
	m, _ = renderAt(t, m)
	for id, detail := range naProbeDetails {
		want := probeIndex(t, m, id)
		sel := m
		for sel.selected != want {
			sel = press(t, sel, "j")
		}
		v := sel.View()
		name := probeName(t, m, id)
		if !hasRow(v, name) {
			t.Errorf("cursor is on %q but the Checks view does not offer the row:\n%s", name, v)
		}
		if !strings.Contains(v, "Details: "+name) {
			t.Errorf("Details is not describing the selected N/A row %q:\n%s", name, v)
		}
		if !strings.Contains(v, detail) {
			t.Errorf("Details lost the N/A evidence %q:\n%s", detail, v)
		}
	}
}

// TestExpandRevealsNotApplicableRows: the other way back, the same one the
// hidden passing rows use.
func TestExpandRevealsNotApplicableRows(t *testing.T) {
	m, v := renderAt(t, naModel(t, diagnostic.ProbeDNS))
	if collapsedRow(v) == "" {
		t.Fatalf("nothing was hidden, so there is nothing for expand to reveal:\n%s", v)
	}
	_, ev := renderAt(t, press(t, m, "a"))
	for id := range naProbeDetails {
		if name := probeName(t, m, id); !hasRow(ev, name) {
			t.Errorf("expand did not reveal the N/A row %q:\n%s", name, ev)
		}
	}
}

// TestVisibleRowOrderAcrossMixedStatuses: hiding rows must not reorder the
// ones that stay, and must keep every Warn, Fail and Skip.
func TestVisibleRowOrderAcrossMixedStatuses(t *testing.T) {
	m := naModel(t, diagnostic.ProbeTLS)
	for id, status := range map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbePMTU: diagnostic.StatusWarn,
		diagnostic.ProbeHTTP: diagnostic.StatusSkip,
	} {
		r := m.results[id]
		r.Status = status
		m.results[id] = r
	}
	m, v := renderAt(t, m)

	var want []string
	for _, i := range m.checkRows() {
		probe := m.probes[i]
		switch status := m.results[probe.ID].Status; {
		case i == m.selected || i == m.focusRow():
			want = append(want, probe.Name)
		case status == diagnostic.StatusPass || status == diagnostic.StatusNA:
		default:
			want = append(want, probe.Name)
		}
	}
	var got []string
	for _, row := range checksRows(v) {
		for _, probe := range m.probes {
			if strings.Contains(row, probe.Name) {
				got = append(got, probe.Name)
				break
			}
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("visible row order = %v, want %v:\n%s", got, want, v)
	}
}

// TestCursorWalkKeepsDetailsAligned: hiding rows must not decouple the cursor
// from what describes it. Every step down is described by its own probe's
// Details panel, or, on the one row the answer block above the panels is
// already quoting, by that block.
func TestCursorWalkKeepsDetailsAligned(t *testing.T) {
	m, _ := renderAt(t, naModel(t, diagnostic.ProbeDNS))
	rows := m.checkRows()
	for step, i := range rows {
		if m.selected != i {
			t.Fatalf("step %d: cursor is on row %d, want %d", step, m.selected, i)
		}
		v := m.View()
		name := m.probes[i].Name
		described := strings.Contains(v, "Details: "+name)
		if i == m.answerRow() {
			// The answer block owns this row: it carries the finding, the
			// remedy and the evidence, so the panel is not a second place to
			// look for them. It comes back the moment the cursor leaves.
			line, _ := m.evidenceLine(m.results[m.probes[i].ID].Detail)
			described = strings.Contains(v, strings.TrimSpace(line))
		}
		if !described {
			t.Fatalf("row %d (%q) is described nowhere:\n%s", i, name, v)
		}
		if !hasRow(v, name) {
			t.Fatalf("the cursor row %q is not in the Checks view:\n%s", name, v)
		}
		if step+1 < len(rows) {
			m = press(t, m, "j")
		}
	}
}

// probeIndex is a probe's position in the run, which is also its cursor row.
func probeIndex(t *testing.T, m model, id diagnostic.ProbeID) int {
	t.Helper()
	for i, probe := range m.probes {
		if probe.ID == id {
			return i
		}
	}
	t.Fatalf("probe %s is not in this run", id)
	return -1
}
