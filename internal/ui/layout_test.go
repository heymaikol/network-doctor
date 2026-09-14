// The persistent conclusion area: the rule that the verdict, its remediation,
// the context strip and the help bar stay on screen while the results block
// underneath them scrolls or yields rows.

package ui

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// persistentLines is the block that must survive every size and every scroll
// position: the plain-English verdict and its drill-down hint. The diagnosis's
// own action is checked from the model in checkPersistent, since it is the line
// whose wording the diagnosis owns. The context strip is checked separately by
// hasLine, because the target it names also appears inside the verdict sentence.
// Full help is intentionally absent here: short terminals compact it before
// discarding selected evidence.
var persistentLines = []string{
	"path MTU black hole",
	"Next: press t for trace the path (traceroute)",
}

// hasCursorRow reports whether the Checks panel is showing the selected probe.
// A plain substring search would not do: the Details panel repeats the probe's
// name in its own title, so it answers yes even when the row scrolled away.
func hasCursorRow(v, name string) bool {
	for _, line := range strings.Split(v, "\n") {
		if strings.Contains(line, "› ") && strings.Contains(line, name) {
			return true
		}
	}
	return false
}

// hasLine reports whether the view renders want as a line of its own. Panels
// pad their rows out to the terminal width, so only trailing blanks are cut.
func hasLine(v, want string) bool {
	for _, line := range strings.Split(v, "\n") {
		if strings.TrimRight(line, " ") == want {
			return true
		}
	}
	return false
}

// checkPersistent asserts the whole persistent block is on screen.
func checkPersistent(t *testing.T, m model, where, v string) {
	t.Helper()
	for _, want := range persistentLines {
		if !strings.Contains(v, want) {
			t.Errorf("%s: %q must stay on screen:\n%s", where, want, v)
		}
	}
	if strip := m.headerView(); !hasLine(v, strip) {
		t.Errorf("%s: the context strip %q must stay on screen:\n%s", where, strip, v)
	}
	// What to do outranks every row below it, at every size: it is the second
	// of the two questions the screen exists to answer.
	if rem, ok := m.remediation(); ok && !strings.Contains(v, "Do: "+rem.Action) {
		t.Errorf("%s: %q must stay on screen:\n%s", where, "Do: "+rem.Action, v)
	}
}

// unclosedPanels counts panel borders the view opened without closing. The
// results block is not boxed, so what this guards is the surfaces that still
// are: the Actions menu, the forms, the pickers and the network map, any of
// which may be drawn over a body that is yielding rows underneath them.
func unclosedPanels(v string) int {
	return strings.Count(v, "╭") - strings.Count(v, "╰")
}

// TestPersistentBlockSurvivesLongResultList pins the whole point of splitting
// the conclusion off the results block: 13 probe rows do not fit under the
// verdict on a 24-row terminal, and it is the rows that have to give.
func TestPersistentBlockSurvivesLongResultList(t *testing.T) {
	m := blackHoleModel(t)
	if len(m.probes) < 10 {
		t.Fatalf("%d probes is not enough rows to force a scroll", len(m.probes))
	}
	for _, h := range []int{40, 30, 24, 20, 16, 14, 12, 10} {
		u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: h})
		nm := asModel(t, u)
		v := nm.View()
		if rows := lipgloss.Height(v); rows > h {
			t.Errorf("100x%d: view is %d display rows tall", h, rows)
		}
		checkPersistent(t, nm, fmt.Sprintf("100x%d", h), v)
		if n := unclosedPanels(v); n != 0 {
			t.Errorf("100x%d: %d panel border(s) left unclosed:\n%s", h, n, v)
		}
	}
}

// TestPersistentBlockUnchangedWhileScrolling moves the cursor to the bottom of
// a results block too tall to fit and asserts the conclusion did not move with
// it: the rows scroll, the conclusion does not.
func TestPersistentBlockUnchangedWhileScrolling(t *testing.T) {
	m := blackHoleModel(t)
	// Expanded, because the compact view collapses the passing rows into one
	// line and a list that short has nothing to scroll. Scrolling is the
	// expanded list's problem now.
	m.expanded = true
	u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	top := asModel(t, u)
	topView := top.View()
	if !hasCursorRow(topView, m.probes[0].Name) {
		t.Fatalf("the first probe row must be on screen at the top:\n%s", topView)
	}
	last := m.probes[len(m.probes)-1].Name
	if strings.Contains(topView, last) {
		t.Fatalf("%q already fits, so nothing here scrolls:\n%s", last, topView)
	}

	bottom := top
	for range len(bottom.probes) { // walk the cursor down to the last row
		u, _ = bottom.Update(keyMsg("j"))
		bottom = asModel(t, u)
	}
	bottomView := bottom.View()
	if bottom.selected != len(bottom.probes)-1 {
		t.Fatalf("the cursor stopped on row %d of %d", bottom.selected, len(bottom.probes))
	}
	if !hasCursorRow(bottomView, last) {
		t.Errorf("the results block must scroll the cursor into view:\n%s", bottomView)
	}
	checkPersistent(t, bottom, "after scrolling", bottomView)
	// The conclusion is rendered above the results block, so the lines before
	// the Checks heading must be byte-identical at both scroll positions.
	head := func(v string) string { before, _, _ := strings.Cut(v, "Checks"); return before }
	if head(topView) != head(bottomView) {
		t.Errorf("the conclusion changed while scrolling:\nbefore\n%s\nafter\n%s", head(topView), head(bottomView))
	}
	if n := unclosedPanels(bottomView); n != 0 {
		t.Errorf("%d panel border(s) left unclosed after scrolling:\n%s", n, bottomView)
	}
}

// TestConstrainedHeightDegradesCleanly walks every height a terminal can
// plausibly be, including ones too short for the conclusion itself. Nothing
// may panic, overflow the terminal, or leave a panel border hanging open, and
// the verdict has to outlive everything below it.
func TestConstrainedHeightDegradesCleanly(t *testing.T) {
	// withJobs runs the same sweep with a job pane whose strip is carrying a
	// ring of runs: the strip is a row inside a pane View already budgets, so
	// it must not buy itself one at the verdict's expense.
	for _, withJobs := range []bool{false, true} {
		for _, w := range []int{30, 60, 100} {
			for h := 1; h <= 26; h++ {
				m := blackHoleModel(t)
				if withJobs {
					m.cur = jobState{name: "ping the host", status: JobRunning, active: &job{}, start: time.Now()}
					m.otherJobs = []jobState{
						{name: "DNS lookup", status: JobDone},
						{name: "trace the path", status: JobFailed},
						{name: "reverse DNS lookup", status: JobTimedOut},
					}
					m.cur.lines = []string{"64 bytes from host", "64 bytes from host"}
				}
				u, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
				nm := asModel(t, u)
				v := nm.View()
				if rows := lipgloss.Height(v); rows > h {
					t.Errorf("%dx%d jobs=%v: view is %d display rows tall:\n%s", w, h, withJobs, rows, v)
				}
				for _, line := range strings.Split(v, "\n") {
					if got := lipgloss.Width(line); got > w {
						t.Errorf("%dx%d jobs=%v: line is %d wide: %q", w, h, withJobs, got, line)
					}
				}
				if n := unclosedPanels(v); n != 0 {
					t.Errorf("%dx%d jobs=%v: %d panel border(s) left unclosed:\n%s", w, h, withJobs, n, v)
				}
				// The verdict's first word survives at any height: it is the
				// top line, and everything below it, the strip included,
				// yields before it does.
				if !strings.Contains(v, "TCP reaches") {
					t.Errorf("%dx%d jobs=%v: the verdict must survive:\n%s", w, h, withJobs, v)
				}
			}
		}
	}
}

// TestResultsBlockHonorsRowBudget is the arithmetic the rest of the layout
// rests on. View hands the results block a row budget and then counts the rows
// it got back when it places the help bar, so a block one row taller than it
// was asked for pushes the help bar off the bottom of the screen. The widths
// straddle the point where the panels stop fitting side by side and the point
// where a probe row starts wrapping, because both change what a row costs.
func TestResultsBlockHonorsRowBudget(t *testing.T) {
	for _, w := range []int{26, 27, 28, 29, 30, 40, 59, 60, 79, 80, 81, 100, 120} {
		for _, sel := range []int{0, 6, 12} {
			m := blackHoleModel(t)
			m.width, m.height = w, 24
			m.selected = sel
			// The block yields rows down to a floor and then gives up its
			// panels entirely. It must not come back below that floor, and the
			// floor has to be low enough to reach on a short terminal.
			floor := 0
			for rows := 1; rows <= 20; rows++ {
				block := m.bodyView(false, rows)
				if got := lipgloss.Height(block); got > rows {
					t.Errorf("%d cols, budget %d rows, cursor on row %d: block is %d rows tall:\n%s", w, rows, sel, got, block)
				}
				if unclosedPanels(block) != 0 {
					t.Errorf("%d cols, budget %d rows: unclosed panel border:\n%s", w, rows, block)
				}
				if block == "" {
					if floor > 0 {
						t.Errorf("%d cols, cursor on row %d: the block rendered at %d rows but not at %d", w, sel, floor, rows)
					}
					continue
				}
				if floor == 0 {
					floor = rows
				}
				// Whatever else it drops, a block that renders at all is
				// showing the row the cursor is on. A narrow panel wraps that
				// row across two lines, so only the wider ones can be asked
				// for the name and the marker together.
				if !strings.Contains(block, "› ") {
					t.Errorf("%d cols, budget %d rows: the window lost the cursor on row %d:\n%s", w, rows, sel, block)
				}
				if w >= 80 && !hasCursorRow(block, m.probes[sel].Name) {
					t.Errorf("%d cols, budget %d rows: the window lost the cursor on row %d:\n%s", w, rows, sel, block)
				}
			}
			if floor == 0 || floor > 7 {
				t.Errorf("%d cols, cursor on row %d: the block needs %d rows before it renders at all", w, sel, floor)
			}
		}
	}
}

// TestWindowRowsKeepsTheCursor is the rule the windowing turns on, checked
// directly because the panel around it can hide a broken window behind its
// own wrapping. Growing outward from the cursor is only correct if the cursor
// is what the window is seeded with: seeding from a budget the cursor row does
// not fit into leaves a window of its neighbours instead, which points the
// reader at a row they did not select.
func TestWindowRowsKeepsTheCursor(t *testing.T) {
	for _, width := range []int{4, 7, 12, 20, 40} {
		for n := range 12 {
			rows := []string{"Checks"}
			for i := range n { // rows wide enough to wrap at these widths
				rows = append(rows, strings.Repeat("ab ", i%7+1))
			}
			for sel := -2; sel <= n+2; sel++ {
				for budget := -3; budget <= 12; budget++ {
					got := windowRows(defaultStyles, rows, sel, budget, width)
					if got[0] != rows[0] {
						t.Fatalf("width=%d n=%d sel=%d budget=%d: the title moved", width, n, sel, budget)
					}
					if n == 0 {
						continue
					}
					want := rows[1+min(max(sel, 0), n-1)]
					if !slices.Contains(got[1:], want) {
						t.Fatalf("width=%d n=%d sel=%d budget=%d: cursor row dropped:\n%q", width, n, sel, budget, got)
					}
					// Nothing beyond the cursor row itself may overrun.
					if floor := rowCost(rows[0], width) + rowCost(want, width); budget > 0 &&
						displayRows(got, width) > max(budget, floor) {
						t.Fatalf("width=%d n=%d sel=%d budget=%d: window costs %d rows:\n%q",
							width, n, sel, budget, displayRows(got, width), got)
					}
				}
			}
		}
	}
}

// TestRowBudgetSurvivesLongDetail is why the row cost is measured by rendering
// rather than by dividing a row's width by the panel's. Lip Gloss breaks lines
// on word boundaries, so a long Details line costs more rows than the division
// predicts, and a block that quietly overruns its budget is thrown away whole
// by fitBlock: the reader loses the entire results area rather than a few rows
// of it.
func TestRowBudgetSurvivesLongDetail(t *testing.T) {
	m := blackHoleModel(t)
	long := strings.Repeat("wxyz abcdefghij klmnopqrs ", 20)
	for _, p := range m.probes {
		r := m.results[p.ID]
		r.Detail, r.Fix = long, long
		m.results[p.ID] = r
	}
	for _, w := range []int{30, 57, 60, 72, 79, 80, 100} {
		for rows := 8; rows <= 26; rows++ {
			m.width, m.height = w, 24
			m.selected = 6
			block := m.bodyView(false, rows)
			if got := lipgloss.Height(block); got > rows {
				t.Errorf("%d cols, budget %d rows: block is %d rows tall:\n%s", w, rows, got, block)
			}
			if block == "" {
				t.Errorf("%d cols, budget %d rows: a long Details line threw the whole block away", w, rows)
			}
		}
	}
}

// TestResizeKeepsTheViewConsistent walks a terminal from large to tiny and
// back, moving the cursor at every size. There is no stored scroll offset to
// go stale, and this is what says so: nothing may panic, overrun the terminal
// or leave a border hanging open on the way through.
func TestResizeKeepsTheViewConsistent(t *testing.T) {
	nm := blackHoleModel(t)
	for _, size := range [][2]int{{200, 60}, {1, 1}, {80, 24}, {2, 40}, {120, 3}, {40, 2}, {0, 0}, {30, 8}, {100, 24}} {
		u, _ := nm.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		nm = asModel(t, u)
		for _, key := range []string{"j", "k"} {
			for range len(nm.probes) + 2 {
				u, _ = nm.Update(keyMsg(key))
				nm = asModel(t, u)
				v := nm.View()
				where := fmt.Sprintf("%dx%d after %q", size[0], size[1], key)
				if nm.height > 0 && lipgloss.Height(v) > nm.height {
					t.Fatalf("%s: view is %d rows tall:\n%s", where, lipgloss.Height(v), v)
				}
				if n := unclosedPanels(v); n != 0 {
					t.Fatalf("%s: %d panel border(s) left unclosed:\n%s", where, n, v)
				}
			}
		}
	}
	if nm.selected < 0 || nm.selected >= len(nm.probes) {
		t.Errorf("the cursor ended up on row %d of %d", nm.selected, len(nm.probes))
	}
}

// TestWatchRerenderKeepsTheConclusion is the rerun path: watch mode redraws
// with a sparkline on every probe row, which is extra width on exactly the
// rows the window is budgeting. The conclusion and the cursor both have to
// survive that.
func TestWatchRerenderKeepsTheConclusion(t *testing.T) {
	m := blackHoleModel(t)
	m.watch = true
	for _, p := range m.probes {
		m.runHistory[p.ID] = []diagnostic.Status{diagnostic.StatusPass, diagnostic.StatusFail, diagnostic.StatusPass}
	}
	u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	nm := asModel(t, u)
	for range len(nm.probes) {
		u, _ = nm.Update(keyMsg("j"))
		nm = asModel(t, u)
		v := nm.View()
		checkPersistent(t, nm, "watch mode", v)
		if lipgloss.Height(v) > 20 {
			t.Fatalf("watch mode: view is %d rows tall:\n%s", lipgloss.Height(v), v)
		}
		if !hasCursorRow(v, nm.probes[nm.selected].Name) {
			t.Errorf("watch mode lost the cursor row:\n%s", v)
		}
	}
}
