// The main diagnostic body's section treatment: Checks and Details are drawn
// as a heading over a short rule rather than inside a box, so what these tests
// hold is that the sections stay legible and stay inside their columns without
// a frame to close them, and that the surfaces that are still boxed still are.

package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// bodyStates are the shapes the diagnostic body has to render: a healthy run,
// a failure with evidence to show, an outage carrying consequence labels, a
// watch pass carrying a change marker beside its sparklines, a pass still in
// flight, and a target whose name is long enough to push the Checks rows past
// the width they are usually given.
func bodyStates(t *testing.T) []struct {
	name  string
	build func(t *testing.T) model
} {
	t.Helper()
	return []struct {
		name  string
		build func(t *testing.T) model
	}{
		{"healthy", wifiModel},
		{"failure with evidence", evidenceModel},
		{"consequences", func(t *testing.T) model { return offlineRun(t, mustTarget(t, "example.com:443")) }},
		{"blamed warn row", blackHoleModel},
		{"watch pass with a change", func(t *testing.T) model {
			return watchRun(t, watchRun(t, watchModel(t), nil), dnsOutage)
		}},
		{"still running", func(t *testing.T) model {
			m := newModel(mustTarget(t, "example.com:443"), false)
			for i, p := range m.probes {
				m.started[p.ID] = true
				if i < 3 {
					m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
				}
			}
			return m
		}},
		{"long target name", func(t *testing.T) model {
			m := newModel(mustTarget(t, "very-long-subdomain.service.example.internal:8443"), false)
			doneResults(&m, diagnostic.ProbeDNS)
			m.selected = probeIndex(t, m, diagnostic.ProbeDNS)
			return m
		}},
		{"expanded", func(t *testing.T) model { m := wifiModel(t); m.expanded = true; return m }},
	}
}

// boxDrawing is the border characters the sections used to be framed in. The
// body draws none of them now: the only rule character it uses is the short
// marker under a section heading, which chromeSpans reads.
const boxDrawing = "╭╮╰╯│┌┐└┘"

// TestBodyDrawsSectionsRatherThanBoxes is the shape of the change: at every
// size and in every state the results block is headings over rules, with no
// frame around either section and nothing drawn between them but space.
func TestBodyDrawsSectionsRatherThanBoxes(t *testing.T) {
	for _, s := range bodyStates(t) {
		t.Run(s.name, func(t *testing.T) {
			for _, size := range [][2]int{
				{120, 40}, {100, 30}, {80, 24}, {79, 24}, {70, 20},
				{60, 24}, {40, 20}, {80, 16}, {80, 12}, {80, 10},
			} {
				m := s.build(t)
				m.width, m.height = size[0], size[1]
				block := m.bodyView(false, 0)
				where := fmt.Sprintf("%dx%d", size[0], size[1])
				if i := strings.IndexAny(ansi.Strip(block), boxDrawing); i >= 0 {
					t.Errorf("%s: the body is still boxed at byte %d:\n%s", where, i, block)
				}
				if len(bodySections(block+"\n")) == 0 {
					t.Errorf("%s: no section heading over a rule:\n%s", where, block)
				}
			}
		})
	}
}

// TestBodySectionsStayInsideTheTerminal walks the widths either side of the
// two-column breakpoint. Nothing the section markers or the rows under them
// carry may run past the terminal.
func TestBodySectionsStayInsideTheTerminal(t *testing.T) {
	for _, s := range bodyStates(t) {
		t.Run(s.name, func(t *testing.T) {
			for w := 1; w <= 140; w++ {
				m := s.build(t)
				m.width, m.height = w, 40
				block := m.bodyView(false, 0)
				for _, line := range strings.Split(block, "\n") {
					if got := lipgloss.Width(line); got > w {
						t.Fatalf("%d cols: a body line is %d wide: %q", w, got, line)
					}
					for _, sp := range ruleSpans(line) {
						if sp.col+sp.width > w {
							t.Fatalf("%d cols: a section ends at column %d: %q", w, sp.col+sp.width, line)
						}
					}
				}
			}
		})
	}
}

// TestWideLayoutSetsTheSectionsSideBySide: past the breakpoint the two
// headings share a line and their short rules share the line under it. The
// Details column keeps its minimum width, and the columns account for the
// whole terminal rather than leaving space to a frame that is no longer drawn.
func TestWideLayoutSetsTheSectionsSideBySide(t *testing.T) {
	for _, w := range []int{80, 81, 100, 120, 200} {
		m := evidenceModel(t)
		m.width, m.height = w, 40
		block := m.bodyView(false, 0)
		var spans []sectionSpan
		for _, line := range strings.Split(block, "\n") {
			if s := ruleSpans(line); len(s) > 0 {
				spans = s
				break
			}
		}
		if len(spans) != 2 {
			t.Fatalf("%d cols: %d section rules on the first rule line, want 2:\n%s", w, len(spans), block)
		}
		checks, details := spans[0], spans[1]
		if got := details.col - (checks.col + checks.width); got != bodyGutter {
			t.Errorf("%d cols: %d columns between the sections, want %d:\n%s", w, got, bodyGutter, block)
		}
		if details.width < detailsMinWidth {
			t.Errorf("%d cols: Details is %d columns wide, want at least %d:\n%s", w, details.width, detailsMinWidth, block)
		}
		if got := checks.width + bodyGutter + details.width; got != w {
			t.Errorf("%d cols: the sections and their gutter account for %d columns:\n%s", w, got, block)
		}
	}
}

// TestNarrowLayoutStacksSectionsWithAGap: below the breakpoint the sections
// stack, and a blank row is the whole of what separates them. Without one the
// Details heading would read as another Checks row.
func TestNarrowLayoutStacksSectionsWithAGap(t *testing.T) {
	for _, w := range []int{40, 60, 79} {
		m := evidenceModel(t)
		m.width, m.height = w, 40
		block := m.bodyView(false, 0)
		lines := strings.Split(block, "\n")
		var rules []int
		for i, line := range lines {
			if s := ruleSpans(line); len(s) > 0 {
				if len(s) != 1 {
					t.Fatalf("%d cols: %d rules on one line, want the sections stacked:\n%s", w, len(s), block)
				}
				rules = append(rules, i)
			}
		}
		if len(rules) != 2 {
			t.Fatalf("%d cols: %d section rules, want Checks and Details:\n%s", w, len(rules), block)
		}
		if got := strings.TrimSpace(ansi.Strip(lines[rules[1]-2])); got != "" {
			t.Errorf("%d cols: %q sits between the sections, want a blank row:\n%s", w, got, block)
		}
		sections := bodySections(block + "\n")
		if len(sections["Checks"]) == 0 || len(detailsRows(block+"\n")) == 0 {
			t.Errorf("%d cols: stacked sections lost their rows: %v\n%s", w, sections, block)
		}
	}
}

// TestSectionHeadingsSurviveWithoutColour: the boundary between the sections is
// a heading and a short rule, both of them characters. Stripping every escape
// sequence, which is what NO_COLOR and a monochrome terminal leave, must not
// take the boundary with it, in any theme.
func TestSectionHeadingsSurviveWithoutColour(t *testing.T) {
	for _, theme := range themes {
		for _, w := range []int{60, 100} {
			m := evidenceModel(t)
			m.setTheme(theme)
			m.width, m.height = w, 40
			plain := ansi.Strip(m.bodyView(false, 0)) + "\n"
			sections := bodySections(plain)
			if len(sections["Checks"]) == 0 {
				t.Errorf("%s at %d cols: no Checks section without colour:\n%s", theme.Name, w, plain)
			}
			if len(detailsRows(plain)) == 0 {
				t.Errorf("%s at %d cols: no Details section without colour:\n%s", theme.Name, w, plain)
			}
		}
	}
}

// TestSectionChromeIsBounded keeps the supporting region structurally marked
// without allowing either rule to grow back into a terminal-wide band. The
// labels and selected-check identity carry orientation in every theme; the
// character rule and the stacked gap keep it when colour is unavailable.
func TestSectionChromeIsBounded(t *testing.T) {
	for _, theme := range themes {
		for w := 1; w <= sectionRuleMaxWidth; w++ {
			m := evidenceModel(t)
			m.setTheme(theme)
			headed := sectionHead(m.st, []string{m.st.panelTitle.Render("Checks"), "body"}, w)
			if len(headed) != 2 || lipgloss.Height(strings.Join(headed, "\n")) != 3 {
				t.Fatalf("%s at %d cols: heading is not exactly two rows: %q", theme.Name, w, headed)
			}
			spans := chromeSpans(strings.Split(headed[0], "\n")[1])
			if len(spans) != 1 || spans[0].width != w {
				t.Errorf("%s at %d cols: rule spans = %v, want one rule of width %d", theme.Name, w, spans, w)
			}
		}
		for _, w := range []int{60, 100} {
			m := evidenceModel(t)
			m.setTheme(theme)
			m.width, m.height = w, 40
			block := m.bodyView(false, 0)
			plain := ansi.Strip(block)
			selected := m.probes[m.selected].Name
			if !strings.Contains(plain, "Checks") || !strings.Contains(plain, "Details: "+selected) ||
				!hasCursorRow(plain, selected) {
				t.Errorf("%s at %d cols: headings or selected identity missing:\n%s", theme.Name, w, plain)
			}
			for _, line := range strings.Split(block, "\n") {
				for _, sp := range chromeSpans(line) {
					if sp.width < 1 || sp.width > sectionRuleMaxWidth {
						t.Errorf("%s at %d cols: rule width = %d, want 1..%d", theme.Name, w, sp.width, sectionRuleMaxWidth)
					}
					if w >= sectionRuleMaxWidth && sp.width != 12 {
						t.Errorf("%s at %d cols: rule width = %d, want 12", theme.Name, w, sp.width)
					}
				}
				if got := lipgloss.Width(line); got > w {
					t.Errorf("%s at %d cols: line is %d columns wide", theme.Name, w, got)
				}
			}
		}
	}
}

// TestToolOutputKeepsItsFullWidthRule protects the separate zero-row-cost
// title treatment. It is not evidence-section chrome and remains full width.
func TestToolOutputKeepsItsFullWidthRule(t *testing.T) {
	m := jobModel(t, 100, 40)
	line, _, _ := strings.Cut(ansi.Strip(m.jobView(20)), "\n")
	if !strings.HasPrefix(line, jobPaneTitle+" ") || lipgloss.Width(line) != m.width {
		t.Errorf("Tool output rule = %q (%d columns), want its title across %d columns", line, lipgloss.Width(line), m.width)
	}
}

// TestRowLabelsLandInsideTheChecksColumn: a "changed" or "consequence" label is
// set against the Checks section's own right edge. A label past that edge would
// read as part of the Details column beside it, and a row carrying both labels
// is the widest case there is.
func TestRowLabelsLandInsideTheChecksColumn(t *testing.T) {
	// Egress was already down and stays down; QUIC and encrypted DNS joining it
	// this pass are the same outage seen again, so those rows are changed and
	// consequences at once, which is the widest a Checks row gets.
	m := watchRun(t, watchModel(t), outage(nil))
	m = watchRun(t, m, outage(map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeQUIC:         diagnostic.StatusFail,
		diagnostic.ProbeDNSEncrypted: diagnostic.StatusFail,
	}))
	m.width, m.height = 100, 40
	block := m.bodyView(false, 0) + "\n"
	var checks sectionSpan
	for _, line := range strings.Split(block, "\n") {
		if s := ruleSpans(line); len(s) > 0 {
			checks = s[0]
			break
		}
	}
	rows := bodySections(block)["Checks"]
	if len(rows) == 0 {
		t.Fatalf("no Checks rows to read labels off:\n%s", block)
	}
	var labelled, both int
	for _, row := range rows {
		has := strings.Contains(row, changedLabel)
		if strings.Contains(row, consequenceLabel) {
			if has {
				both++
			}
			has = true
		}
		if !has {
			continue
		}
		labelled++
		// sectionCell already cut the row to the section's columns, so a label
		// still whole here is a label that fitted inside them.
		if strings.Contains(row, changedLabel) && !strings.HasSuffix(row, changedLabel) &&
			!strings.Contains(row, changedLabel+"  ") {
			t.Errorf("the change label is cut off by the Checks column: %q", row)
		}
	}
	if labelled == 0 || both == 0 {
		t.Fatalf("%d labelled rows, %d carrying both labels:\n%s", labelled, both, block)
	}
	if checks.width < 1 {
		t.Fatalf("no Checks section span to measure the column against:\n%s", block)
	}
	// QUIC is one of the rows carrying both labels. Its exact sparkline must
	// remain on that row, rather than merely leaving a status glyph elsewhere.
	spark := ansi.Strip(m.statusSparkline(diagnostic.ProbeQUIC, 8))
	if row := rowFor(block, m.probes[probeIndex(t, m, diagnostic.ProbeQUIC)].Name); !strings.Contains(row, spark) {
		t.Errorf("the labelled QUIC row %q lost its sparkline %q:\n%s", row, spark, block)
	}
}

// TestBoxedSurfacesKeepTheirBorders is the other half of the scope: quieting
// the diagnostic body must not flatten the surfaces that are genuinely
// contained. Each of these is an interactive or self-contained view, and a
// border is what holds it off the diagnosis it is drawn over.
func TestBoxedSurfacesKeepTheirBorders(t *testing.T) {
	for _, tc := range []struct {
		name   string
		render func(m model) string
	}{
		{"actions menu", func(m model) string { return m.actionsView(0) }},
		{"theme picker", func(m model) string { return m.themeView() }},
		{"restart prompt", func(m model) string { m.entering = true; return m.promptView(true) }},
		{"ssh form", func(m model) string { m.ssh.host = "192.168.1.50:22"; return m.sshFormView() }},
		{"tool confirmation", func(m model) string {
			m.confirmTool = &m.tools[0]
			return m.confirmView()
		}},
		{"network map", func(m model) string {
			m.networkCIDR = "192.168.1.0/24"
			return m.networkMapView()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := blackHoleModel(t)
			m.width, m.height = 100, 40
			v := tc.render(m)
			if !strings.ContainsAny(ansi.Strip(v), boxDrawing) {
				t.Errorf("%s lost its border:\n%s", tc.name, v)
			}
			if n := unclosedPanels(v); n != 0 {
				t.Errorf("%s: %d border(s) left unclosed:\n%s", tc.name, n, v)
			}
		})
	}
}

// TestBodyYieldsDetailsBeforeChecks is the vertical priority the budget model
// has to keep now that no rows are being spent on frames. Details never
// outlives the Checks rows at any width, and stacked, where the two really do
// compete for the same rows, it gives its section up first. The cursor row is
// the last thing standing in either layout.
func TestBodyYieldsDetailsBeforeChecks(t *testing.T) {
	for _, w := range []int{60, 100} {
		m := evidenceModel(t)
		m.width, m.height = w, 40
		var lostDetails, lostChecks int
		for rows := 20; rows >= 1; rows-- {
			block := m.bodyView(false, rows)
			if got := lipgloss.Height(block); block != "" && got > rows {
				t.Fatalf("%d cols, budget %d: block is %d rows tall:\n%s", w, rows, got, block)
			}
			plain := block + "\n"
			hasDetails, hasChecks := len(detailsRows(plain)) > 0, len(bodySections(plain)["Checks"]) > 0
			if hasDetails && !hasChecks {
				t.Errorf("%d cols, budget %d: Details outlived the Checks rows:\n%s", w, rows, block)
			}
			if !hasDetails && lostDetails == 0 {
				lostDetails = rows
			}
			if !hasChecks && lostChecks == 0 {
				lostChecks = rows
			}
			if hasChecks && !strings.Contains(block, "› ") {
				t.Errorf("%d cols, budget %d: the Checks section lost the cursor row:\n%s", w, rows, block)
			}
		}
		if lostDetails == 0 || lostChecks == 0 {
			t.Fatalf("%d cols: the block never gave up a section, so nothing yielded", w)
		}
		// Side by side the sections do not share rows, so only the stacked
		// layout can be asked which of them goes first.
		if w < 80 && lostDetails <= lostChecks {
			t.Errorf("%d cols: Details went at %d rows and Checks at %d, want Details to yield first",
				w, lostDetails, lostChecks)
		}
	}
}

// TestBodyKeepsTheAnswerFirst: the sections are quieter, but the hierarchy is
// unchanged. The verdict is still the top of the screen and the results block
// still starts below the context strip and the causal path, at every height
// the block yields rows at.
func TestBodyKeepsTheAnswerFirst(t *testing.T) {
	for h := 6; h <= 40; h++ {
		u, _ := blackHoleModel(t).Update(tea.WindowSizeMsg{Width: 100, Height: h})
		nm := asModel(t, u)
		v := nm.View()
		lines := viewLines(v)
		if got := lipgloss.Height(v); got > h {
			t.Fatalf("100x%d: view is %d rows tall:\n%s", h, got, v)
		}
		if !strings.Contains(v, "TCP reaches") {
			t.Fatalf("100x%d: the verdict is gone:\n%s", h, v)
		}
		if body := firstBodyLine(lines); body == 0 {
			t.Errorf("100x%d: the results block is the top line of the screen:\n%s", h, v)
		}
	}
}
