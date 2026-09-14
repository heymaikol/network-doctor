// Rendering: the View tree and its helpers. Nothing here mutates the
// model; every function takes a value receiver and returns a string.

package ui

import (
	"fmt"
	"net"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// wrap reflows a full-width block that no panel is wrapping for us. Without
// it the terminal hard-wraps mid-word, and the extra display rows aren't in
// View's newline budget, so the renderer eats the top of the screen.
func (m model) wrap(s string) string {
	if m.width <= 0 {
		return s
	}
	return ansi.Wrap(s, m.width, "")
}

// answerWrap reflows the answer block so a line indented to mark it
// subordinate keeps that indent when it wraps. Without it a long "Fix:"
// continues at column 0, where it reads as a new top-level statement rather
// than as the rest of the line above it, and the indent that carries the
// block's hierarchy on a monochrome terminal survives only on short lines.
//
// A line that already fits is returned exactly as it is, which is what keeps
// the pre-clipped evidence quote to the single row it was clipped to.
func (m model) answerWrap(block string) string {
	if m.width <= 0 {
		return block
	}
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		if lipgloss.Width(line) <= m.width {
			continue
		}
		// The answer block writes its indent outside the styling, so it can be
		// lifted off here and put back on every row the content wraps to. The
		// content is then wrapped in the columns that are actually left, which
		// is what stops an indented line from being charged for its indent
		// twice and breaking a row earlier than the terminal requires.
		body := strings.TrimLeft(line, " ")
		indent := len(line) - len(body)
		if indent == 0 || m.width <= indent*2 {
			lines[i] = ansi.Wrap(line, m.width, "")
			continue
		}
		pad := strings.Repeat(" ", indent)
		lines[i] = pad + strings.ReplaceAll(ansi.Wrap(body, m.width-indent, ""), "\n", "\n"+pad)
	}
	return strings.Join(lines, "\n")
}

// answerBlock is the whole primary block: the verdict, the remedy under it and
// the diagnosis's next action, wrapped so every one of those lines keeps its
// indent. It is the answer to "what is wrong" and "what do I do", and the
// layout below it yields rows to it rather than the other way round.
func (m model) answerBlock() string {
	block := m.banner()
	if rem := m.answerRemediation(); len(rem) > 0 {
		block += "\n" + strings.Join(rem, "\n")
	}
	return m.answerWrap(block)
}

func (m model) glyph(id diagnostic.ProbeID) string {
	r, ok := m.results[id]
	if !ok {
		if !m.started[id] {
			return m.st.faint.Render("·")
		}
		return m.spinner.View()
	}
	return m.st.status[r.Status].Render(probeGlyph(r.Status))
}

func probeGlyph(s diagnostic.Status) string {
	if s < diagnostic.StatusPass || s > diagnostic.StatusNA {
		return "?"
	}
	return [...]string{"✓", "!", "✗", "⊘", "–"}[s]
}

// networkLine is the connected-network label shown under the title: the Wi-Fi
// SSID when wireless, else the wired interface name. Empty until the interface
// and display-only SSID probes have completed.
func (m model) networkLine() string {
	r, ok := m.results[diagnostic.ProbeIface]
	if !ok || r.Status != diagnostic.StatusPass {
		return ""
	}
	network, ok := m.results[diagnostic.ProbeSSID]
	if !ok {
		return ""
	}
	if network.Network != "" {
		return "Wi-Fi: " + network.Network
	}
	if r.Iface != "" {
		return "Wired: " + r.Iface
	}
	return ""
}

func (m model) View() string {
	if m.helping {
		return m.helpOverlay()
	}
	if m.incidentViewing {
		return m.incidentView()
	}
	if m.detailsViewing {
		return m.detailsView()
	}
	if m.viewing {
		return m.outputView()
	}
	deferred := m.toolbox && !m.chainRan()

	// shrink re-renders the selected supporting region inside a row budget.
	// Both regions follow their existing cursor, so moving through a short
	// window never leaves the selection outside it.
	shrink := func(rows int) string { return m.bodyView(deferred, rows) }
	bodyFloor := bodyMinRows
	if m.networkMap {
		shrink = m.networkMapViewRows
		bodyFloor = mapMinRows
	}
	body := shrink(0)
	answer := m.answerBlock() + "\n"
	// The blank row under a multi-line answer is the boundary between what the
	// run concluded and everything that merely supports it: the context strip,
	// the causal path and the sections are all about the block above them, and
	// without a gap the six of them read as one undifferentiated list. A
	// one-line answer has no parts to hold together, so it buys nothing there
	// and is not charged for one.
	gap := ""
	if strings.Contains(strings.TrimSuffix(answer, "\n"), "\n") {
		gap = "\n"
	}
	header := ""
	if h := m.wrap(m.headerView()); h != "" {
		header = h + "\n"
	}
	// The causal strip sits between the context and the body sections: it is about
	// the answer above it, not about the row the cursor is on. It is already
	// laid out to the terminal width, so it is not wrapped again.
	path := ""
	if p := m.pathView(); p != "" {
		path = p + "\n"
	}
	help := m.helpView(deferred)
	if m.entering {
		help = m.promptView(true)
	}
	if m.sshPrompt {
		help = m.sshFormView()
	}
	if m.confirmTool != nil {
		help = m.confirmView()
	}
	if m.theming {
		help = m.themeView()
	}
	if m.actionsOpen {
		// The answer and the header outrank the menu, so it is given the rows
		// they leave rather than pushing them off the top of the screen.
		help = m.actionsView(m.height - strings.Count(answer+gap+header+path, "\n"))
	}
	tail := help + "\n"
	// Adaptive tail: the job pane gets whatever rows the rest doesn't use.
	// avail is a budget in newlines: jobView's output must add at most avail
	// of them, or the view exceeds the terminal and the renderer cuts the top.
	var fixed string
	var avail int
	budget := func() {
		fixed = answer + gap + header + path
		if body != "" {
			if m.networkMap {
				// The panel border already separates the map from its context. It
				// does not need the two blank rows the unboxed Checks body uses.
				fixed += body + "\n"
			} else {
				// Blank rows above and below: with no border around the sections,
				// the space is what holds the block off the context strip over it
				// and off the job pane under it.
				fixed += "\n" + body + "\n\n"
			}
		}
		avail = m.height - strings.Count(fixed, "\n") - strings.Count(tail, "\n") - 1
	}
	budget()
	if m.entering && m.confirmTool == nil && m.height > 0 {
		// The forms cheatsheet yields first: drop it when the view would
		// overflow, or when it would starve a live job pane below jobView's
		// 5-row minimum. m.height == 0 means size unknown, so keep the forms.
		if avail < 0 || (m.hasJob() && avail < 5) {
			tail = m.promptView(false) + "\n"
			budget()
		}
	}
	minAvail := 0
	if m.entering && m.hasJob() {
		minAvail = 5
	}
	// Short-terminal degradation contract: the answer and essential target
	// context stay pinned; full help chrome compacts first; substantial regions
	// window around their cursor; the causal strip and visual separator yield
	// before the selected evidence; and the final height clamp can only cut from
	// the bottom. The Check details view keeps the complete selected evidence
	// reachable when even the smallest body cannot share the screen.
	ordinaryHelp := !m.entering && !m.sshPrompt && m.confirmTool == nil && !m.theming && !m.actionsOpen
	if m.height > 0 && avail < minAvail && ordinaryHelp {
		tail = m.compactHelpView(deferred) + "\n"
		budget()
	}
	shrinkBody := func() {
		shrunken := shrink(max(lipgloss.Height(body)+avail-minAvail, bodyFloor))
		if shrunken != "" {
			body = shrunken
			budget()
		}
	}
	if m.height > 0 && avail < minAvail && body != "" {
		shrinkBody()
	}
	// The path summarizes the answer, so it yields before selected evidence.
	if m.height > 0 && avail < minAvail && path != "" {
		path = ""
		budget()
	}
	if m.height > 0 && avail < minAvail && body != "" {
		shrinkBody()
	}
	// The blank separator carries hierarchy but no information, so it yields
	// before a selected check or map row does.
	if m.height > 0 && avail < minAvail && gap != "" {
		gap = ""
		budget()
	}
	if m.height > 0 && avail < minAvail && body != "" {
		shrinkBody()
	}
	if m.height > 0 && avail < minAvail && body != "" {
		body = ""
		if ordinaryHelp {
			tail = m.hiddenRegionHelp(deferred) + "\n"
		}
		budget()
	}
	job := m.jobView(avail)
	if m.networkMap && m.cur.name == lanDiscoveryName {
		job = ""
	}
	out := fixed + job + tail
	if m.height > 0 {
		// Last resort: a terminal too short for the banner, the header and the
		// help bar together. Clip from the bottom: losing the help bar beats
		// the renderer eating the top of the screen, which is where the
		// verdict and the guidance under it live.
		out = lipgloss.NewStyle().MaxHeight(m.height).Render(out)
	}
	return out
}

// bodyMinRows is the shortest useful results block: the Checks heading with
// its rule, and one probe row. Below that the block is dropped rather than
// rendered as a heading with nothing under it.
const bodyMinRows = 3

// A constrained map needs its two border rows, title, freshness line and the
// selected host or service. Below this it yields whole rather than leaving an
// open border or an invisible cursor.
const mapMinRows = 5

// consequenceLabel marks a failed row the diagnosis has already explained as
// downstream of the failure it blames. It is spelled out rather than left to
// the dimmed glyph, because colour alone is not a distinction every reader or
// every terminal can see.
const consequenceLabel = "consequence"

// changedLabel marks a row whose status is not what it was in the previous
// completed watch pass, so a pass that differs reads as an event rather than
// as the same table drawn again. It is a word for the same reason the
// consequence label is: colour alone is not a distinction every reader or
// every terminal can see. A recovery earns it exactly as a new failure does.
const changedLabel = "changed"

// detailsMinWidth is the narrowest the Details section is allowed to be beside
// the Checks section. Below it the evidence lines wrap into unreadable stubs.
// It is columns of text: the sections are not boxed, so nothing is spent on a
// frame or on padding inside one.
const detailsMinWidth = 36

// checksWidth is the Checks section's usual width beside Details, wide enough
// for the longest probe name a targeted run draws plus its marker, glyph and
// watch sparkline. A row that comes to more than that, whether from a long
// target name, a grown sparkline or a label, claims the columns it needs, up
// to what Details is guaranteed.
const checksWidth = 36

// bodyGutter is the blank columns between the two sections in the side-by-side
// layout. Two is enough to read them apart without a rule between them, and it
// is all the body spends on separating them.
const bodyGutter = 2

// The orientation headings. Every region the cursor can be in opens with one
// of these, and a region nested inside another names the one it is nested in,
// so "where am I" is answered by the screen rather than by remembering which
// key was pressed to get here. They are words rather than colours or glyphs:
// a monochrome terminal has to carry the same answer.
const (
	mapTitle     = "Network map"
	viewerTitle  = "Full output"
	detailsTitle = "Check details"
	jobPaneTitle = "Tool output"
)

// ruleTitle names the block under it on the rule that already separated it,
// so the heading costs no row of its own. The job pane is the one region that
// is drawn without a panel border to hang a title on, and it is the region
// most easily mistaken for the full-output viewer, which opens with the same
// command row.
func (m model) ruleTitle(name string) string {
	label := m.st.panelTitle.Render(name)
	gap := m.width - lipgloss.Width(label) - 1
	if m.width <= 0 || gap < 1 {
		return label
	}
	return label + " " + m.st.faint.Render(strings.Repeat("─", gap))
}

// labelRight sets label against the right edge of a row in a section width
// columns wide, the way the network map pairs its title with the shared
// domain. A row too long to share its line keeps the label on a second one,
// still at the right edge, rather than dropping it or cutting the probe name.
// The pair stays one row as far as the section is concerned, so it scrolls as
// one and the block's budget prices both of its display rows.
func labelRight(row, label string, width int) string {
	if gap := width - lipgloss.Width(row) - lipgloss.Width(label); gap > 0 {
		return row + strings.Repeat(" ", gap) + label
	}
	return row + "\n" + lipgloss.NewStyle().Width(width).Align(lipgloss.Right).Render(label)
}

// targetHP is the target endpoint as host:port; JoinHostPort brackets IPv6
// literals so the rendered endpoint reads back as the same target.
func (m model) targetHP() string {
	return net.JoinHostPort(m.target.Host, strconv.Itoa(m.target.Port))
}

// headerView is the one-line context strip under the banner: target, connected
// network, watch mode, and this pass's progress while one is running. Empty
// when there is nothing to say, and the caller drops the line rather than
// rendering a blank one.
func (m model) headerView() string {
	var parts []string
	if m.target != nil {
		parts = append(parts, m.targetHP())
	}
	if n := m.networkLine(); n != "" {
		parts = append(parts, n)
	}
	if m.watch {
		parts = append(parts, "watch")
		if latest, ok := m.incidents.Latest(); ok {
			state := "last incident recovered after " + durationText(latest.Duration(m.incidentNow()))
			if latest.Active() {
				state = "incident active for " + durationText(latest.Duration(m.incidentNow()))
			}
			if count := len(m.incidents.Incidents()); count > 1 {
				state += fmt.Sprintf(" (%d recorded)", count)
			}
			parts = append(parts, state)
		}
	}
	// Progress is about the pass in flight, so it goes away with the pass: a
	// finished run says so with its verdict, and "12/12 complete" under it
	// would be the same fact a second time. No count claims a probe that is
	// only waiting on a dependency, and "running" is left off entirely while
	// nothing is dispatched rather than rounded up to look busy.
	if m.chainRan() && !m.allDone() {
		done, running := m.runProgress()
		parts = append(parts, fmt.Sprintf("%d/%d complete", done, len(m.probes)))
		if running > 0 {
			parts = append(parts, fmt.Sprintf("%d running", running))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return m.st.faint.Render(strings.Join(parts, "  ·  "))
}

// bodyView renders the Checks section and, beside it, the Details section when
// there is anything to put in one. They stack vertically when the terminal is
// too narrow for two columns. rows caps the block's display height; 0 means no
// cap. A capped block scrolls its probe list rather than being clipped from the
// bottom, because a clipped section ends on a row that does not say it was cut.
//
// Neither section is padded out to the other's height: each is as tall as its
// own content, and the block is as tall as the taller of the two.
func (m model) bodyView(deferred bool, rows int) string {
	shown, hiddenPass, hiddenNA := m.compactRows()
	// The cursor row is always in shown, so the windowed section still scrolls
	// to the row the Details section is describing.
	sel := max(slices.Index(shown, m.selected), 0)
	// Which of the failed rows the diagnosis has already explained as
	// downstream of another one. It is read from the current results on every
	// render, so a watch pass that repairs the path takes the labels with it.
	collateral := diagnostic.Collateral(m.target, m.probeOrder(), m.results)

	// The rows are built before the section has a width, because what the rows
	// come to is what decides that width, so the labels are placed in a second
	// pass. A row can carry both of them: a check that changed this pass and
	// is also downstream of another failure is two separate things worth
	// saying.
	changed, consequence := m.st.faint.Render(changedLabel), m.st.faint.Render(consequenceLabel)
	checks := make([]string, 0, len(shown))
	labels := make([]string, 0, len(shown))
	// want is the width the widest Checks row would need to stay on one line,
	// measured from the row as it will be drawn: marker, glyph, probe name and
	// watch sparkline are all in it already, and a label is a gap and a word
	// more. Measuring the whole row is the point. A width taken from the label
	// alone leaves every unlabelled row to wrap against the section's usual
	// width while the Details section beside it still has columns to spare.
	want := 0
	wantRow := func(row, label string) {
		w := lipgloss.Width(row)
		if label != "" {
			w += 1 + lipgloss.Width(label)
		}
		want = max(want, w)
	}
	for _, i := range shown {
		probe := m.probes[i]
		if deferred {
			row := m.st.faint.Render("  · " + probe.Name)
			checks = append(checks, row)
			labels = append(labels, "")
			wantRow(row, "")
			continue
		}
		marker, name := "  ", probe.Name
		if i == m.selected {
			marker, name = m.st.sel.Render("› "), m.st.sel.Render(name)
		}
		// A collateral failure keeps its glyph and its Fail status; only the
		// red comes off it, so the row still carrying red is the one the
		// reader has something to do about.
		glyph := m.glyph(probe.ID)
		if collateral[probe.ID] {
			glyph = m.st.faint.Render(probeGlyph(diagnostic.StatusFail))
		}
		row := marker + glyph + " " + name
		if m.watch && len(m.runHistory[probe.ID]) > 0 {
			row += "  " + m.statusSparkline(probe.ID, 8)
		}
		var label []string
		if m.changedRow(probe.ID) {
			label = append(label, changed)
		}
		if collateral[probe.ID] {
			label = append(label, consequence)
		}
		text := strings.Join(label, "  ")
		checks = append(checks, row)
		labels = append(labels, text)
		wantRow(row, text)
	}
	if hiddenPass+hiddenNA > 0 {
		wantRow(m.collapsedChecksRow(hiddenPass, hiddenNA), "")
	}
	// hangIndent is the marker and glyph a probe row opens with, so a
	// continuation indented by it lands under the probe name.
	const hangIndent = 4
	// hang wraps a row the section is too narrow to hold on one line, with its
	// continuation under the probe name rather than back at the left margin,
	// where the marker column reads it as a row of its own. Only a terminal
	// with no columns to spare gets here: a wider one gave those columns to
	// the section instead. ansi.Wrap leaves the row alone when it fits, and
	// the indent is dropped rather than eating the whole column when the
	// section is narrower than the indent itself.
	hang := func(row string, width int) string {
		if width <= hangIndent*2 || lipgloss.Width(row) <= width {
			return row
		}
		indent := strings.Repeat(" ", hangIndent)
		return strings.ReplaceAll(ansi.Wrap(row, width-hangIndent, ""), "\n", "\n"+indent)
	}
	// checksSection is the Checks rows under their heading once the section
	// width is settled: the labels are placed against that width, so they land
	// at its right edge.
	checksSection := func(width int) []string {
		out := make([]string, 0, len(checks)+2)
		out = append(out, m.st.panelTitle.Render("Checks"))
		for j, row := range checks {
			row = hang(row, width)
			if labels[j] != "" {
				row = labelRight(row, labels[j], width)
			}
			out = append(out, row)
		}
		if hiddenPass+hiddenNA > 0 {
			out = append(out, hang(m.collapsedChecksRow(hiddenPass, hiddenNA), width))
		}
		return sectionHead(m.st, out, width)
	}

	// detailsSection is the Details rows once the section width is settled.
	// Like checksSection above it is called from inside each layout branch
	// rather than before them, because the evidence packs its grouped
	// measurement lists against the column it actually landed in.
	detailsSection := func(width int) []string { return m.detailRows(deferred, width) }
	// column lays a section out in its own width, which is what wraps the rows
	// and what squares the block off for a side-by-side join.
	column := func(width int, rows []string) string {
		out := lipgloss.NewStyle().Width(width).Render(strings.Join(rows, "\n"))
		// cellbuf.Wrap can leave a trailing space on the line that breaks at a
		// hyphen, and lipgloss then pads the whole block out to that over-wide
		// line, so a "Run: ifconfig -a" row would spill a column past the
		// section at any width. Trim the ragged edge back to the column.
		lines := strings.Split(out, "\n")
		for i, l := range lines {
			lines[i] = strings.TrimRight(l, " ")
		}
		return strings.Join(lines, "\n")
	}

	if m.width < 80 { // too narrow for two columns, so stack
		// Full bleed: with no frame to pay for, the section is the terminal.
		// The fallback is for the first render, before a size is known.
		w := m.width
		if w <= 0 {
			w = 24
		}
		leftRows := checksSection(w)
		rightRows := sectionHead(m.st, detailsSection(w), w)
		stack := func(left, right []string) string {
			if len(right) == 0 {
				return column(w, left)
			}
			// A blank row between them: stacked, the gap is what says where
			// one section ends and the next begins.
			return column(w, left) + "\n\n" + column(w, right)
		}
		if rows <= 0 {
			return stack(leftRows, rightRows)
		}
		// Stacked, the gap row is the only chrome to pay for. Details keeps at
		// most half of what is left, so a long attempt list cannot squeeze the
		// checks out, and it gives its section up entirely when the two of them
		// still do not fit. Whether they fit is measured rather than predicted:
		// a probe row that wraps costs a display row no row count can see
		// coming.
		inner := rows - 1
		if right := sectionBody(fitRows(rightRows, max(inner/2, 1), w)); len(right) > 0 {
			both := stack(windowRows(m.st, leftRows, sel, inner-displayRows(right, w), w), right)
			if lipgloss.Height(both) <= rows {
				return both
			}
		}
		// Checks on its own, so there is no gap row to pay for.
		return fitBlock(stack(windowRows(m.st, leftRows, sel, rows, w), nil), rows)
	}
	leftW := checksWidth
	if want > leftW {
		// A long target name, a watch sparkline or a label pushes the widest
		// row past the section's usual width, and a row that wraps costs the
		// block a display row its budget never saw coming. Take the columns
		// those rows ask for, but never out of the width the Details section
		// is guaranteed beside them: a terminal with nothing to spare takes
		// the wrap instead.
		leftW = min(want, max(m.width-detailsMinWidth-bodyGutter, leftW))
	}
	leftRows := checksSection(leftW)
	rightW := max(m.width-leftW-bodyGutter, detailsMinWidth)
	rightRows := sectionHead(m.st, detailsSection(rightW), rightW)
	if rows > 0 {
		leftRows = windowRows(m.st, leftRows, sel, rows, leftW)
		rightRows = sectionBody(fitRows(rightRows, rows, rightW))
	}
	left := column(leftW, leftRows)
	if len(rightRows) == 0 {
		return fitBlock(left, rows)
	}
	return fitBlock(lipgloss.JoinHorizontal(lipgloss.Top, left,
		strings.Repeat(" ", bodyGutter), column(rightW, rightRows)), rows)
}

// sectionHead pins a section's title over a rule as wide as the section's own
// column, which is what marks the body's two areas off now that neither is
// drawn inside a border. The rule is a character rather than a colour, so the
// boundary survives NO_COLOR and a monochrome terminal.
//
// Title and rule are one entry in the row list: the windowing keeps the pair
// whole, and the block's budget prices both of its display rows. The title is
// cut to the column rather than wrapped inside it, so that pair is always
// exactly two rows and the two sections' rules stay on one line.
func sectionHead(st styles, rows []string, width int) []string {
	if len(rows) == 0 || width <= 0 {
		return rows
	}
	out := slices.Clone(rows)
	out[0] = ansi.Truncate(out[0], width, "…") + "\n" + st.faint.Render(strings.Repeat("─", width))
	return out
}

// detailRows is the Details section: its title row followed by the evidence for
// the cursor row, or nil when there is no evidence to show. A heading with
// nothing under it is left out rather than drawn empty, and it comes back the
// moment the cursor row has something to say.
func (m model) detailRows(deferred bool, width int) []string {
	if deferred {
		return []string{
			m.st.panelTitle.Render("Details"),
			m.st.faint.Render("Nothing to show yet: the checks haven't run."),
		}
	}
	// No row to describe: --check and --skip can between them select nothing
	// at all, and a run with no checks has no evidence to lay out.
	if m.selected < 0 || m.selected >= len(m.probes) {
		return nil
	}
	probe := m.probes[m.selected]
	if m.explaining && m.selected == m.answerRow() {
		why := m.whyLines()
		if len(why) > 1 {
			rows := append([]string{m.st.panelTitle.Render("Why: " + probe.Name)}, why[1:]...)
			return sectionBody(rows)
		}
	}
	var body strings.Builder
	if r, ok := m.results[probe.ID]; ok {
		// Outcome first, always: the status word and the finding it belongs to
		// are what the reader came for, and everything under them is read in
		// their light. It is unconditional so that the inline section and the
		// full-screen viewer open on the same sentence, and so that a warning
		// with a long elaboration under it cannot be mistaken for a failure.
		// The answer block above quotes this finding too on the one row the
		// diagnosis focuses, clipped to a single line; that is a pointer into
		// this section rather than a second copy of it, and the remedy it
		// carries is still never repeated here.
		body.WriteString(m.outcomeLine(r) + "\n")
		// Then what the row cannot say about itself: a failure the diagnosis
		// has already accounted for under another row is not a second problem,
		// and a row that prints only its own error reads like one. The causal
		// call is Collateral's, the same one the Checks marker is drawn from.
		if line := m.consequenceLine(probe.ID, r.Status); line != "" {
			body.WriteString(line + "\n")
		}
		// A working http:// proxy row keeps its earned status, so its advice
		// would otherwise never be shown: the cleartext observation is the one
		// non-failing result that carries a line worth reading.
		// The answered row keeps its hint here whenever the answer block gave
		// the diagnosis's action instead of it, which is the one thing the
		// quote above did leave out.
		answered := m.selected == m.answerRow()
		_, advised := m.remediation()
		if (!answered || advised) && (r.Status == diagnostic.StatusFail || r.Status == diagnostic.StatusWarn || r.ConnectCleartext) && r.Fix != "" {
			body.WriteString(m.st.skip.Render("Fix: ") + r.Fix + "\n")
		}
		// The remediation belongs to the diagnosis rather than to any one row,
		// so it is shown on the row the diagnosis focuses and nowhere else:
		// repeated under every cursor position it would read as advice about
		// whatever row the reader happened to land on. It goes here, above the
		// per-attempt evidence, because a run with sixteen connection attempts
		// must not push the one actionable block off the section.
		if answered {
			body.WriteString(m.remediationBlock())
		}
		// The mechanics last, under a word that says what they are. Nothing is
		// dropped: measurements a probe reported the same outcome for are said
		// once with a count and the list of everything that had it, which is a
		// rearrangement of the record rather than a cut of it. They are grouped
		// and labelled so that the interpretation above them is the part a
		// reader meets first, and so that a row with sixteen connection
		// attempts still reads as one block of measurements rather than as the
		// section itself.
		for _, line := range observedLines(r, width) {
			body.WriteString(m.st.faint.Render(line) + "\n")
		}
	} else {
		body.WriteString(m.spinner.View() + m.st.faint.Render(" checking…") + "\n")
	}
	if history := m.historyLine(probe.ID); history != "" {
		body.WriteString(history + "\n")
	}
	rows := append([]string{m.st.panelTitle.Render("Details: " + probe.Name)},
		strings.Split(strings.TrimRight(body.String(), "\n"), "\n")...)
	return sectionBody(rows)
}

// observedTitle labels the measurements a check collected, which is the last
// of the three things a selected row says: what happened, what it means, and
// then what was measured. It is a word rather than a rule or a colour, because
// the order has to survive a monochrome terminal and a 36-column section.
const observedTitle = "Observed"

// outcomeLine is a result's status word and the finding it belongs to. The
// status word stands alone when a probe recorded no prose, which is what a
// replayed or synthetic result can look like; "PASS:" with nothing after the
// colon is a line that promises a sentence it does not have.
func (m model) outcomeLine(r diagnostic.ProbeResult) string {
	line := m.st.status[r.Status].Render(r.Status.String())
	if r.Detail == "" {
		return line
	}
	return line + ": " + r.Detail
}

// consequenceLine names the failure a downstream row is already explained by,
// and "" for every other row. It is the same causal call the Checks section's
// "consequence" marker is drawn from, said in a sentence: the marker is over
// in the other section and the full-screen viewer has no marker at all, so a
// selected row that carries only its own error would read as an independent
// problem in both places.
//
// It states the relation and stops. Which check to fix, and how, belong to the
// answer block, and repeating either here would be a second diagnosis.
func (m model) consequenceLine(id diagnostic.ProbeID, status diagnostic.Status) string {
	// Only a failure is ever downstream of another one, and the question costs
	// a whole interpretation of the run to answer, so it is asked only of the
	// rows that can be answered yes.
	if status != diagnostic.StatusFail {
		return ""
	}
	if !diagnostic.Collateral(m.target, m.probeOrder(), m.results)[id] {
		return ""
	}
	blamed := m.diagnosis().Blamed
	if blamed == "" {
		return m.st.faint.Render("Consequence of another failing check, not a separate problem.")
	}
	return m.st.faint.Render("Consequence of " + m.probeLabel(blamed) + " failing, not a separate problem.")
}

// observedLines is everything a probe measured, as the Observed block: the
// label, then the measurements under it. Empty when the probe recorded no
// measurements at all, so no labelled block is drawn over nothing.
//
// Measurements that a probe reported the same outcome for are said once, with
// a count and the list of everything that had it, rather than once per line: a
// row that tried sixteen addresses and was refused by fifteen of them is one
// fact about fifteen addresses, and fifteen copies of one sentence bury the
// sixteenth line that is not a copy. Nothing is dropped to do it. Every
// address, every destination and every timing is still in the block, so the
// grouping is a rearrangement of the record rather than a summary standing in
// for one, and the full-screen viewer needs nothing extra to be complete.
func observedLines(r diagnostic.ProbeResult, width int) []string {
	var out []string
	if r.Portal != nil && r.Portal.RedirectURL != "" {
		out = append(out, "  portal "+r.Portal.RedirectURL)
	}
	if r.Source != nil {
		out = append(out, "  src "+r.Source.String()+" "+r.Iface)
	}
	out = append(out, observedRunLines(routeRuns(r.Routes), "destinations", width)...)
	out = append(out, observedRunLines(attemptRuns(r.Attempts), "addresses", width)...)
	if len(out) == 0 {
		return nil
	}
	return append([]string{observedTitle}, out...)
}

// observedRun is a run of consecutive measurements a probe reported the same
// outcome for. Members are in the order they were measured, and only
// neighbours are ever grouped, so the block never reorders the sequence: the
// address families are contiguous in a recorded run, and a family that stopped
// working part-way through stays two runs rather than becoming one.
type observedRun struct {
	outcome string   // what the probe reported, for every member of this run
	solo    string   // the whole line, for a run that has just one member
	members []string // one short entry per measurement, in measured order
}

// appendRun adds one measurement, extending the open run when it reported the
// same outcome and starting a new one when it did not.
func appendRun(runs []observedRun, outcome, solo, member string) []observedRun {
	if n := len(runs); n > 0 && runs[n-1].outcome == outcome {
		runs[n-1].members = append(runs[n-1].members, member)
		return runs
	}
	return append(runs, observedRun{outcome: outcome, solo: solo, members: []string{member}})
}

// routeRuns are the operating system's route decisions, grouped by the path
// they selected. Destinations that leave by the same interface and next hop
// are one answer about several addresses; a destination the platform could not
// answer for is left out entirely rather than drawn as a row of empty fields.
func routeRuns(routes []diagnostic.RouteDecision) []observedRun {
	var runs []observedRun
	for _, route := range routes {
		summary := route.Summary()
		if summary == "" {
			continue
		}
		destination := route.Destination.String()
		runs = appendRun(runs, summary, "route "+destination+": "+summary, destination)
	}
	return runs
}

// attemptRuns are the connection attempts, grouped by what came back.
func attemptRuns(attempts []diagnostic.Attempt) []observedRun {
	var runs []observedRun
	for _, a := range attempts {
		outcome := attemptOutcome(a)
		member := fmt.Sprintf("%s %dms", a.IP, diagnostic.Ms(a.Dur))
		runs = appendRun(runs, outcome, member+" "+outcome, member)
	}
	return runs
}

// attemptOutcome is what one connection attempt reported, with the leading
// part of the error that only restates this attempt's own address taken back
// off. Go spells a dial failure as "dial tcp6 [addr]:port: reason", so the
// address is already the first thing on the line: left in, it pushes the
// reason off the end of a narrow column, and it makes two addresses that
// failed for the same reason read as two unrelated failures.
//
// Only that one shape is recognised, and it is recognised from the attempt's
// own address rather than by matching a pattern: the cut is the text's first
// ": ", taken only when this attempt's address is in front of it, so an error
// that names the address somewhere later in a sentence keeps all of its text.
// An address family that writes ":" without a following space, which is every
// IPv6 literal, cannot move that cut.
func attemptOutcome(a diagnostic.Attempt) string {
	if a.Err == nil {
		return "ok"
	}
	text := a.Err.Error()
	cut := strings.Index(text, ": ")
	if cut < 0 || !strings.Contains(text[:cut], a.IP.String()) {
		return text
	}
	if rest := text[cut+2:]; strings.TrimSpace(rest) != "" {
		return rest
	}
	return text
}

// observedRunLines draws the runs: a lone measurement as the single line it
// has always been, and a repeated outcome as that outcome said once with a
// count, over the list of every measurement that had it. noun names what is
// being counted, because a count with no noun reads as a line number.
func observedRunLines(runs []observedRun, noun string, width int) []string {
	total := 0
	for _, run := range runs {
		total += len(run.members)
	}
	var out []string
	for _, run := range runs {
		if len(run.members) == 1 {
			out = append(out, "  "+run.solo)
			continue
		}
		out = append(out, "  "+run.outcome+" ("+observedCount(len(run.members), total, noun)+")")
		out = append(out, packEntries(run.members, width, "    ")...)
	}
	return out
}

// observedCount says how much of the record one run accounts for. It is words
// and digits rather than a colour or a glyph, so it survives a monochrome
// terminal, and it names the total whenever the run is not the whole of it:
// "15 of 16" is the reading that says the sixteenth was something else.
func observedCount(n, total int, noun string) string {
	if n == total {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d of %d %s", n, total, noun)
}

// observedListMinWidth floors the width the grouped member list is packed to,
// for the first render before a terminal size is known and for a column too
// narrow to hold an entry at all. Below it the list packs one entry per line,
// which is what it would have done anyway.
const observedListMinWidth = 24

// packEntries lays entries out as a comma list, breaking to a new line at
// width rather than per entry. Every entry is kept, in order.
func packEntries(entries []string, width int, indent string) []string {
	width = max(width, observedListMinWidth)
	var out []string
	line := indent
	for i, entry := range entries {
		if i < len(entries)-1 {
			entry += ","
		}
		switch {
		case line == indent:
			line += entry
		case len(line)+1+len(entry) <= width:
			line += " " + entry
		default:
			out, line = append(out, line), indent+entry
		}
	}
	return append(out, line)
}

func (m model) whyLines() []string {
	d := m.diagnosis()
	if len(d.Findings) == 0 || len(d.Findings[0].Evidence) == 0 {
		return nil
	}
	finding := d.Findings[0]
	lines := []string{"Why?"}
	// Confidence leads, because it qualifies everything under it: the same
	// evidence list reads differently once the reader knows whether it settled
	// the question or merely narrowed it. It appears only here, in the view
	// somebody opened to ask why, and never on the probe table.
	if label := confidenceLine(finding.Confidence); label != "" {
		lines = append(lines, "Confidence", "  "+label)
	}
	sections := []struct {
		kind  diagnostic.EvidenceKind
		title string
	}{
		{diagnostic.EvidenceSupport, "Evidence"},
		{diagnostic.EvidenceRuledOut, "Ruled out"},
		{diagnostic.EvidenceContradiction, "Against alternatives"},
		{diagnostic.EvidenceNotEvaluated, "Not evaluated"},
	}
	for _, section := range sections {
		start := len(lines)
		for _, evidence := range finding.Evidence {
			if evidence.Kind != section.kind {
				continue
			}
			if len(lines) == start {
				lines = append(lines, section.title)
			}
			lines = append(lines, "  "+m.causalEvidenceLine(evidence))
		}
	}
	return lines
}

// confidenceLine states how strongly the evidence below supports the
// conclusion, in the word and a short sentence of what that word means here. No
// percentage and no bar: the four values are epistemic categories, and drawing
// one as a quantity would invent a precision netdoc never claimed. Empty for a
// finding that carries no assessment, which is a finding from an artifact
// written before there was one.
func confidenceLine(c diagnostic.Confidence) string {
	switch c {
	case diagnostic.ConfidenceHigh:
		return "HIGH: specific evidence, with no alternative left open"
	case diagnostic.ConfidenceMedium:
		return "MEDIUM: the best explanation, with an ambiguity unresolved"
	case diagnostic.ConfidenceLow:
		return "LOW: the failure is named, its cause barely narrowed"
	case diagnostic.ConfidenceInsufficientEvidence:
		return "INSUFFICIENT EVIDENCE: this run cannot say what caused it"
	}
	return ""
}

func (m model) causalEvidenceLine(e diagnostic.CausalEvidence) string {
	observation := m.observationLine(e)
	switch e.Kind {
	case diagnostic.EvidenceRuledOut:
		return "✓ " + diagnosisLabel(e.Candidate) + ": " + observation
	case diagnostic.EvidenceContradiction:
		return "! " + diagnosisLabel(e.Candidate) + ": " + observation
	case diagnostic.EvidenceNotEvaluated:
		return "⊘ " + m.probeLabel(e.Check) + ": " + notEvaluatedLabel(e.Reason)
	default:
		return evidenceGlyph(e.Observation) + " " + observation
	}
}

func evidenceGlyph(observation diagnostic.ObservationID) string {
	switch observation {
	case diagnostic.ObservationStatusPass, diagnostic.ObservationDNSAnswers,
		diagnostic.ObservationFamilyReachable, diagnostic.ObservationAddressSucceeded,
		diagnostic.ObservationRouteDirect:
		return "✓"
	case diagnostic.ObservationStatusWarn, diagnostic.ObservationClockOffset,
		diagnostic.ObservationRouteTunneled, diagnostic.ObservationRoutePathDiffers,
		diagnostic.ObservationRouteNextHopDiffers, diagnostic.ObservationRouteTableDiffers,
		diagnostic.ObservationRouteFamilySplit, diagnostic.ObservationRouteInterfaceMTU:
		// A tunnel, a split path, another router, another routing table, and a
		// narrow link are observations about the path, not failures of the row
		// that recorded them.
		return "!"
	case diagnostic.ObservationStatusSkip, diagnostic.ObservationStatusNA:
		return "⊘"
	default:
		return "✗"
	}
}

// routeTunnelNamed reports whether the operating system itself called this
// row's route out of iface an encapsulating device, as opposed to the link
// merely looking like one. It is the difference between a sentence netdoc may
// state and one it may only suggest.
func routeTunnelNamed(r diagnostic.ProbeResult, iface string) bool {
	return slices.ContainsFunc(r.Routes, func(route diagnostic.RouteDecision) bool {
		return route.Iface == iface && route.Tunnel == diagnostic.TunnelKnown
	})
}

func (m model) observationLine(e diagnostic.CausalEvidence) string {
	name := m.probeLabel(e.Check)
	r, ok := m.results[e.Check]
	switch e.Observation {
	case diagnostic.ObservationStatusPass:
		return name + " passed"
	case diagnostic.ObservationStatusWarn:
		return name + " worked with a warning"
	case diagnostic.ObservationStatusFail:
		if ok && r.Detail != "" {
			return name + ": " + r.Detail
		}
		return name + " failed"
	case diagnostic.ObservationCause:
		if ok && r.Detail != "" {
			return name + ": " + r.Detail
		}
		return name + " identified the failure"
	case diagnostic.ObservationDNSAnswers:
		if e.Value != "" {
			return name + " returned " + e.Value
		}
		return name + " returned an address"
	case diagnostic.ObservationDNSNotFound:
		return name + " returned no A/AAAA records"
	case diagnostic.ObservationCaptivePortal:
		return name + " was intercepted by a network sign-in page"
	case diagnostic.ObservationTimeout:
		return name + " timed out"
	case diagnostic.ObservationClockOffset:
		return name + " measured a material clock offset"
	case diagnostic.ObservationStatusDowngraded:
		return name + " failed before another working path reduced its severity"
	case diagnostic.ObservationFamilyReachable:
		return name + " reached the target over " + addressFamilyLabel(e.Value)
	case diagnostic.ObservationFamilyFailed:
		return name + " could not reach the target over " + addressFamilyLabel(e.Value)
	case diagnostic.ObservationAddressSucceeded:
		return name + " reached " + e.Value
	case diagnostic.ObservationAddressFailed:
		return name + " could not reach " + e.Value
	case diagnostic.ObservationRouteTunneled:
		// How sure this sentence may sound is the row's own tunnel state. The
		// operating system naming the device an encapsulating kind is a fact
		// to repeat; a link that merely has the shape of a tunnel is a guess,
		// and a mobile broadband modem has the same shape.
		if e.Value == "" {
			return name + " left through a tunnel"
		}
		if ok && routeTunnelNamed(r, e.Value) {
			return name + " left through the tunnel " + e.Value
		}
		return name + " left over " + e.Value + ", which has the shape of a tunnel"
	case diagnostic.ObservationRouteDirect:
		// The counterpart claim, and a weaker one than it reads: nothing
		// classified this link as encapsulating, which is not the same as
		// having established that nothing encapsulates it. A VPN that presents
		// an ordinary Ethernet device lands here.
		if e.Value != "" {
			return name + " left over " + e.Value + ", which is not reported as a tunnel"
		}
		return name + " left over a link that is not reported as a tunnel"
	case diagnostic.ObservationRouteUnreachable:
		if e.Value != "" {
			return name + " has no route to " + e.Value
		}
		return name + " has no route to its destination"
	case diagnostic.ObservationRoutePathDiffers:
		if e.Value != "" {
			return name + " takes a different path from the target traffic on " + e.Value
		}
		return name + " takes a different path from the target traffic"
	case diagnostic.ObservationRouteNextHopDiffers:
		// The same link, a different router. The value names the other path's
		// next hop, which is the whole point: the interface names agreeing is
		// what made the two look like one path.
		if e.Value != "" {
			return name + " left through a next hop other than " + e.Value
		}
		return name + " left through a different next hop"
	case diagnostic.ObservationRouteTableDiffers:
		// A routing domain, and nothing about what sent the flow there. A rule,
		// a mark, a VRF, and an application policy all look identical from a
		// route lookup, so none of them is named.
		return name + " was routed out of a routing table that general traffic did not use"
	case diagnostic.ObservationRouteFamilySplit:
		return name + " reaches IPv4 and IPv6 over materially different routes"
	case diagnostic.ObservationRouteInterfaceMTU:
		// The link's own MTU against the general path's link MTU. Neither side
		// is a measured path MTU, and this never says it is.
		if e.Value != "" {
			return name + " left over " + e.Value + ", whose link MTU is smaller than the general path's"
		}
		return name + " left over a link whose MTU is smaller than the general path's"
	case diagnostic.ObservationStatusSkip:
		return name + " was skipped"
	case diagnostic.ObservationStatusNA:
		return name + " did not apply"
	}
	return name + " supplied evidence"
}

func addressFamilyLabel(value string) string {
	switch value {
	case "ipv4":
		return "IPv4"
	case "ipv6":
		return "IPv6"
	}
	return value
}

func (m model) probeLabel(id diagnostic.ProbeID) string {
	for _, probe := range m.probes {
		if probe.ID == id {
			return probe.Name
		}
	}
	switch id {
	case diagnostic.ProbeInternet:
		return "Egress to the reference endpoints"
	case diagnostic.ProbeTargetTCP:
		return "Target TCP connection"
	case diagnostic.ProbeDNS:
		return "System DNS"
	case diagnostic.ProbeDNSPublic:
		return "Independent DNS"
	}
	return "Relevant check"
}

func diagnosisLabel(id diagnostic.DiagnosisID) string {
	switch id {
	case diagnostic.DiagnosisOffline:
		return "General network outage"
	case diagnostic.DiagnosisDNSFailure:
		return "General DNS failure"
	case diagnostic.DiagnosisDNSNameNotFound:
		return "Missing DNS record"
	case diagnostic.DiagnosisSystemDNSFailure:
		return "Configured resolver problem"
	case diagnostic.DiagnosisLocalDeviceUnreachable:
		return "Device unreachable"
	case diagnostic.DiagnosisTargetUnreachable:
		return "Destination unreachable"
	case diagnostic.DiagnosisLocalEgressFailure:
		return "This machine's general network path"
	case diagnostic.DiagnosisDirectEgressBlocked:
		return "Direct egress blocked"
	case diagnostic.DiagnosisIPv4TargetUnreachable:
		return "IPv4 target connectivity"
	case diagnostic.DiagnosisIPv6TargetUnreachable:
		return "IPv6 target connectivity"
	case diagnostic.DiagnosisPartialReachability:
		return "Partial endpoint reachability"
	case diagnostic.DiagnosisTLSClockSkew:
		return "Wrong local clock"
	case diagnostic.DiagnosisTLSTCPUnreachable:
		return "TLS endpoint unreachable"
	case diagnostic.DiagnosisTLSHandshakeFailure:
		return "TLS handshake problem"
	}
	return "Alternative explanation"
}

func notEvaluatedLabel(reason diagnostic.NotEvaluatedReason) string {
	switch reason {
	case diagnostic.NotEvaluatedPrerequisite:
		return "a prerequisite failed"
	case diagnostic.NotEvaluatedNotSelected:
		return "the check was not selected"
	case diagnostic.NotEvaluatedNotApplicable:
		return "the check did not apply"
	case diagnostic.NotEvaluatedIncomplete:
		return "the check did not complete"
	}
	return "no observation was available"
}

// remediation is this run's structured next action, and false when the
// diagnosis supports none: an unfinished run, a healthy one, or a verdict
// about no single conclusion. It reads the model's one diagnosis, so the
// advice cannot point somewhere the banner and the cursor do not.
func (m model) remediation() (diagnostic.Remediation, bool) {
	return diagnostic.Remediate(m.diagnosis(), m.results, runtime.GOOS)
}

// answerRemediation is the acted-on half of the diagnosis's next action: what
// to do, the command that inspects it, and the key that asks the question
// again. It is part of the answer block rather than of the Details section,
// because "what do I do" is half of what the whole screen exists to answer,
// and beside the probe table it read as a footnote to whichever row the
// cursor happened to be on. Nil when the diagnosis supports no action.
//
// The elaboration stays in Details (see remediationBlock): why this action,
// the ways to carry it out, and what success looks like are all background to
// the three lines here, and a reader who wants them has a section to open.
//
// The command is shown, never run. netdoc is a diagnostic tool, and a
// remediation command is a thing to read and decide about, which is also why
// it is only ever a read-only inspection of local state.
func (m model) answerRemediation() []string {
	rem, ok := m.remediation()
	if !ok {
		return nil
	}
	// Indented by the same two columns as Fix and Next: everything under the
	// verdict sentence is subordinate to it, and the indent is what says so on
	// a terminal that renders no colour and no weight at all.
	lines := []string{"  " + m.st.skip.Render("Do: ") + rem.Action}
	if line := rem.CommandLine(); line != "" {
		lines = append(lines, "  "+m.st.faint.Render("Run: ")+line)
	}
	// The payoff line: the advice is only half a workflow without the way to
	// ask the same question again. Dropped when the action has no key, since a
	// custom keymap is free to leave it unbound.
	if m.keys.bound(ctxList, actRetest) {
		lines = append(lines, "  "+m.st.faint.Render("Then press ")+m.st.sel.Render(m.keys.label(ctxList, actRetest))+
			m.st.faint.Render(" to retest"))
	}
	return lines
}

// remediationBlock is the Details half of the same remediation, newline
// terminated and empty when there is nothing to advise: why the action is the
// right one, the ways to carry it out, and what confirms it worked. It is
// progressive disclosure rather than a screen of its own, and it deliberately
// repeats none of the three lines the answer block is already showing at the
// top of the screen, because a section that says again what the answer said
// reads as a second, competing answer.
func (m model) remediationBlock() string {
	rem, ok := m.remediation()
	if !ok {
		return ""
	}
	var b strings.Builder
	if rem.Why != "" {
		b.WriteString(m.st.faint.Render(rem.Why) + "\n")
	}
	for _, step := range rem.Steps {
		b.WriteString("· " + step + "\n")
	}
	if rem.Expect != "" {
		b.WriteString(m.st.faint.Render("Expect: "+rem.Expect) + "\n")
	}
	return b.String()
}

// sectionBody drops a section that has a title and nothing readable under it.
// Emptiness is measured on the text with its styling stripped, because a row
// of spaces or escape sequences alone still draws an orphaned heading.
func sectionBody(rows []string) []string {
	if len(rows) < 2 {
		return nil
	}
	for _, row := range rows[1:] {
		if strings.TrimSpace(ansi.Strip(row)) != "" {
			return rows
		}
	}
	return nil
}

// fitBlock is bodyView's last word on its own row budget: a block that still
// does not fit is dropped, because View counts the rows it hands back and a
// block clipped from the bottom ends on a row that does not say it was cut.
func fitBlock(block string, rows int) string {
	if rows > 0 && lipgloss.Height(block) > rows {
		return ""
	}
	return block
}

// displayRows is what rows cost on screen once a section width columns wide has
// wrapped them. Budgeting in logical rows instead undercounts every row that
// wraps, which is how a narrow terminal used to overflow its own row budget.
func displayRows(rows []string, width int) int {
	total := 0
	for _, r := range rows {
		total += rowCost(r, width)
	}
	return total
}

// rowCost is what one row costs on screen once a section width columns wide has
// wrapped it. Lip Gloss breaks on word boundaries, so dividing the row's width
// by the section's undercounts every row that has to break early at a space.
// Render it at that width and count instead: the renderer is the only oracle
// that cannot drift from what actually lands on screen.
func rowCost(row string, width int) int {
	if width <= 0 {
		return 1
	}
	return lipgloss.Height(lipgloss.NewStyle().Width(width).Render(row))
}

// fitRows keeps the longest prefix of rows that costs at most n display rows.
func fitRows(rows []string, n, width int) []string {
	spent := 0
	for i, r := range rows {
		if spent += rowCost(r, width); spent > n {
			return rows[:i]
		}
	}
	return rows
}

// windowRows fits a section's rows into n display rows in a section width
// columns wide. rows[0] is the section title and stays pinned; the list below
// it scrolls so that sel, an index into that list, is always on screen. A
// truncated list spends its last row saying how many it hid, since nothing
// else in the section admits that it goes on.
func windowRows(st styles, rows []string, sel, n, width int) []string {
	if len(rows) < 2 || displayRows(rows, width) <= n {
		return rows // a bare title has nothing to scroll
	}
	list := rows[1:]
	sel = min(max(sel, 0), len(list)-1)
	// The cursor row is not optional: a window that drops it to keep inside the
	// budget shows the reader a row they did not select, or no rows at all. So
	// it is spent first and the rest grows outward from it, downward first. A
	// cursor row that overruns the budget on its own leaves fitBlock to drop
	// the block, which beats a section pointing at the wrong row.
	budget := n - rowCost(rows[0], width) - rowCost(list[sel], width)
	lo, hi := sel, sel+1
	// The "… N more" line costs rows of its own, priced at the widest count it
	// could carry, and it yields to the last row the list can still show: a
	// section with the cursor in it beats one that only says how much it is
	// hiding.
	cost := rowCost(st.faint.Render(fmt.Sprintf("… %d more", len(list))), width)
	marker := budget >= cost
	if marker {
		budget -= cost
	}
	for grow := true; grow; {
		grow = false
		if hi < len(list) {
			if c := rowCost(list[hi], width); c <= budget {
				budget -= c
				hi++
				grow = true
			}
		}
		if lo == 0 {
			continue
		}
		if c := rowCost(list[lo-1], width); c <= budget {
			budget -= c
			lo--
			grow = true
		}
	}
	shown := append([]string{rows[0]}, list[lo:hi]...)
	if hidden := len(list) - (hi - lo); marker && hidden > 0 {
		shown = append(shown, st.faint.Render(fmt.Sprintf("… %d more", hidden)))
	}
	return shown
}

func (m model) historyLine(id diagnostic.ProbeID) string {
	history := m.runHistory[id]
	if len(history) == 0 {
		return ""
	}
	failed := 0
	for _, status := range history {
		if status == diagnostic.StatusFail {
			failed++
		}
	}
	return m.st.faint.Render("History: ") + m.statusSparkline(id, 0) +
		m.st.faint.Render(fmt.Sprintf("  ·  failed %d of %d runs", failed, len(history)))
}

func (m model) statusSparkline(id diagnostic.ProbeID, limit int) string {
	history := m.runHistory[id]
	if limit > 0 && len(history) > limit {
		history = history[len(history)-limit:]
	}
	var spark strings.Builder
	for _, status := range history {
		spark.WriteString(m.st.status[status].Render(probeGlyph(status)))
	}
	return spark.String()
}

func (m model) selectedPortalURL() string {
	if m.selected < 0 || m.selected >= len(m.probes) {
		return ""
	}
	r := m.results[m.probes[m.selected].ID]
	if r.Portal == nil {
		return ""
	}
	return r.Portal.RedirectURL
}

// upHostLine pulls the host field out of an nmap -oG "Host: … Status: Up" line.
func upHostLine(line string) (string, bool) {
	host, ok := strings.CutPrefix(line, "Host: ")
	if !ok {
		return "", false
	}
	host, status, ok := strings.Cut(host, "Status: ")
	if !ok || strings.TrimSpace(status) != "Up" {
		return "", false
	}
	return strings.TrimSpace(host), true
}

func (m model) networkHosts() []string {
	source, _ := m.discoveryNetwork()
	var hosts []string
	for _, line := range m.cur.lines {
		host, ok := upHostLine(line)
		if !ok || source != nil && strings.HasPrefix(host, source.String()+" ") {
			continue
		}
		host = strings.TrimSuffix(host, " ()")
		// An OS-resolved name beats whatever nmap's raw PTR race printed.
		if ip, _, _ := strings.Cut(host, " "); m.hostNames[ip] != "" {
			host = ip + " (" + m.hostNames[ip] + ")"
		}
		hosts = append(hosts, host)
	}
	return hosts
}

// discoveredIPs pulls the addresses of Up hosts out of nmap -oG output lines.
func discoveredIPs(lines []string) []string {
	var ips []string
	for _, line := range lines {
		host, ok := upHostLine(line)
		if !ok {
			continue
		}
		ip, _, _ := strings.Cut(host, " ")
		if net.ParseIP(ip) == nil {
			continue
		}
		ips = append(ips, ip)
	}
	return ips
}

// namePending reports whether address is still waiting on a name we'd rather
// show than nmap's: during the scan itself, or until its own lookup returns.
func (m model) namePending(address string) bool {
	return m.hostNames[address] == "" && (m.namesPending[address] || m.cur.active != nil)
}

// serviceChooserView renders what one opened device answered on the common
// service ports: the endpoints the checks can be pointed at, or, when there
// are none, exactly what was learned instead of guessing at one.
func (m model) serviceChooserView() string { return m.serviceChooserViewRows(0) }

func (m model) serviceChooserViewRows(rows int) string {
	fixed := []string{m.st.panelTitle.Render(mapTitle + " · Services on " + m.svc.name)}
	scan := m.svc.scan
	// Two things a reader cannot see from the list itself: the device is a row
	// of the snapshot rather than a live connection, and enter here does not
	// inspect the service, it points this run's checks at it.
	origin := "From the snapshot"
	if !m.cur.start.IsZero() {
		origin += " captured " + durationText(m.mapAge(m.cur.start.Add(m.cur.dur))) + " ago"
	}
	if m.svc.done && len(scan.Open) > 0 {
		origin += " · " + m.keys.label(ctxList, actOpen) + " restarts the checks against the selected service"
	}
	fixed = append(fixed, m.st.faint.Render(origin))
	var items []string
	switch {
	case !m.svc.done:
		fixed = append(fixed, m.spinner.View()+m.st.faint.Render(" checking common service ports…"))
	case len(scan.Open) > 0:
		for i, svc := range scan.Open {
			branch := "├─ "
			if i == len(scan.Open)-1 {
				branch = "└─ "
			}
			row := fmt.Sprintf("%-5d %s", svc.Port, svc.Name)
			marker := "  "
			if i == m.svc.sel {
				marker, row = m.st.sel.Render("› "), m.st.sel.Render(row)
			}
			items = append(items, marker+m.st.faint.Render(branch)+m.st.pass.Render("●")+" "+row)
		}
	case scan.Refused > 0:
		// A refusal is an answer: the device is there and reachable, and the
		// only thing missing is something listening.
		fixed = append(fixed,
			m.st.faint.Render(fmt.Sprintf("└─ No common service answered, but %d of %d ports refused the connection, so the device is on the network.", scan.Refused, scan.Checked())),
			m.st.faint.Render("Press "+m.keys.label(ctxList, actRestart)+" to name a port yourself."))
	default:
		fixed = append(fixed,
			m.st.faint.Render(fmt.Sprintf("└─ Nothing answered on any of the %d ports checked: the device may be powered off, may have left the network, or may be dropping connections.", scan.Checked())),
			m.st.faint.Render("Press "+m.keys.label(ctxList, actRestart)+" to name a port yourself."))
	}
	return m.mapPanel(fixed, fixed, items, m.svc.sel, rows)
}

// snapshotLine says what the device list under it is: a scan running now, or
// cached evidence from one that already finished, how old that evidence is,
// and how the scan ended. The first two words carry the live-or-cached answer
// on their own, so a monochrome terminal and a reader who has never met the
// job model are told the same thing as everyone else.
func (m model) snapshotLine(hosts bool) string {
	if m.cur.active != nil {
		return "Live scan · started " + durationText(m.mapAge(m.cur.start)) + " ago"
	}
	if m.cur.start.IsZero() {
		// No measurement was ever taken: the binary was missing, or the launch
		// itself failed. Naming a capture time here would invent one.
		return "Cached snapshot · scan " + m.cur.status.String()
	}
	at := m.cur.start.Add(m.cur.dur)
	when := durationText(m.mapAge(at)) + " ago (" + at.Format("2006-01-02 15:04:05 MST") + ")"
	if m.cur.status == JobDone {
		return "Cached snapshot · captured " + when
	}
	line := "Cached snapshot · scan " + m.cur.status.String() + " " + when
	if hosts {
		line += " · partial results"
	}
	return line
}

// mapAge is how long ago t was, floored at zero: a clock that stepped backwards
// must not report a capture from the future.
func (m model) mapAge(t time.Time) time.Duration { return max(m.incidentNow().Sub(t), 0) }

// lastSuccessfulScan is the newest completed LAN scan other than the one on
// screen. It exists for the states where the displayed scan is not one: while a
// fresh sweep runs, and after one fails, is canceled, or times out, the earlier
// evidence is still in the ring, and the map says so rather than leaving the
// reader to guess whether it was thrown away.
func (m *model) lastSuccessfulScan() *jobState {
	if m.cur.name == lanDiscoveryName && m.cur.active == nil && m.cur.status == JobDone {
		return nil // the displayed scan is the successful one
	}
	var newest *jobState
	for j := range m.jobs {
		if j == &m.cur || j.name != lanDiscoveryName || j.status != JobDone {
			continue
		}
		if newest == nil || j.start.After(newest.start) {
			newest = j
		}
	}
	return newest
}

// networkMapView renders hosts found by the LAN scan, or the services of the
// device opened from it.
func (m model) networkMapView() string { return m.networkMapViewRows(0) }

func (m model) networkMapViewRows(rows int) string {
	if m.svc.host != "" {
		return m.serviceChooserViewRows(rows)
	}
	source, _ := m.discoveryNetwork()
	hosts := m.networkHosts()
	// Only names that carry a domain vote here: a bare ssh alias like
	// "pihole" shouldn't veto stripping ".attlocal.net" off its neighbors.
	domains := map[string]int{}
	domainedHosts := 0
	for _, host := range hosts {
		if address, name, ok := strings.Cut(host, " ("); ok && !m.namePending(address) {
			if _, domain, ok := strings.Cut(strings.TrimSuffix(name, ")"), "."); ok {
				domainedHosts++
				domains[strings.ToLower(domain)]++
			}
		}
	}
	commonDomain := ""
	for domain, count := range domains {
		if count == domainedHosts {
			commonDomain = domain
		}
	}

	panelWidth := fitPanelWidth(m.st.panel, m.width)
	title := m.st.panelTitle.Render(mapTitle + ": " + lanDiscoveryName + " · " + m.networkCIDR)
	if commonDomain != "" {
		domain := m.st.faint.Render("Domain: " + commonDomain)
		contentWidth := panelWidth - m.st.panel.GetHorizontalPadding()
		if gap := contentWidth - lipgloss.Width(title) - lipgloss.Width(domain); gap > 0 {
			title += strings.Repeat(" ", gap) + domain
		} else {
			title += "\n" + lipgloss.NewStyle().Width(contentWidth).Align(lipgloss.Right).Render(domain)
		}
	}
	fixed := []string{title, m.st.faint.Render(m.snapshotLine(len(hosts) > 0))}
	full := slices.Clone(fixed)
	if prev := (&m).lastSuccessfulScan(); prev != nil {
		full = append(full, m.st.faint.Render("Earlier successful scan from "+durationText(m.mapAge(prev.start.Add(prev.dur)))+" ago is still in the job list ("+m.keys.label(ctxList, actSwitchJob)+")"))
	}
	thisDevice := m.st.sel.Render("◆") + " This device"
	if m.watch {
		thisDevice += " now"
	}
	if source != nil {
		thisDevice += " " + source.String()
	}
	full = append(full, thisDevice)

	var items []string
	for i, host := range hosts {
		address, name, named := strings.Cut(host, " (")
		if named {
			name = strings.TrimSuffix(name, ")")
			if short, domain, ok := strings.Cut(name, "."); ok && strings.EqualFold(domain, commonDomain) {
				host = address + " (" + short + ")"
			}
		}
		// A name we're still working on beats nmap's "unknownaabbcc" placeholder.
		if m.namePending(address) {
			host = address + " " + m.spinner.View()
		}
		branch := "├─ "
		if i == len(hosts)-1 {
			branch = "└─ "
		}
		marker := "  "
		if i == m.mapSelected {
			marker = m.st.sel.Render("› ")
			host = m.st.sel.Render(host)
		}
		items = append(items, marker+m.st.faint.Render(branch)+m.st.pass.Render("●")+" "+host)
	}
	if len(hosts) == 0 {
		switch {
		case m.cur.active != nil:
			full = append(full, m.spinner.View()+m.st.faint.Render(" discovering devices…"))
		case m.cur.status != JobDone:
			full = append(full, m.st.fail.Render("└─ Discovery "+m.cur.status.String()))
		default:
			full = append(full, m.st.faint.Render("└─ No other devices replied"))
		}
	}
	return m.mapPanel(full, fixed, items, m.mapSelected, rows)
}

// mapPanel renders a full device or service panel when it fits. Under a row
// budget it pins the orientation and freshness/context lines, then windows the
// selectable rows around the existing cursor. The cursor remains the source of
// truth; moving the window never changes selection.
func (m model) mapPanel(full, fixed, items []string, sel, rows int) string {
	panelWidth := fitPanelWidth(m.st.panel, m.width)
	contentWidth := max(panelWidth-m.st.panel.GetHorizontalPadding(), 1)
	render := func(content []string) string {
		return m.st.panel.Width(panelWidth).Render(strings.Join(content, "\n"))
	}
	complete := append(slices.Clone(full), items...)
	if view := render(complete); rows <= 0 || lipgloss.Height(view) <= rows {
		return view
	}
	budget := rows - m.st.panel.GetVerticalFrameSize()
	if len(items) == 0 {
		return fitBlock(render(fitRows(full, budget, contentWidth)), rows)
	}
	if displayRows(fixed, contentWidth) >= budget {
		return ""
	}
	items = slices.Clone(items)
	sel = min(max(sel, 0), len(items)-1)
	items[sel] = labelRight(items[sel], fmt.Sprintf("%d of %d", sel+1, len(items)), contentWidth)
	itemBudget := budget - displayRows(fixed, contentWidth)
	// Reuse the Checks windowing rule with an empty pinned row. Charging and
	// then removing that row lets the same display-width accounting keep the
	// selected map item and the textual hidden-count marker inside itemBudget.
	window := windowRows(m.st, append([]string{""}, items...), sel, itemBudget+1, contentWidth)
	content := append(slices.Clone(fixed), window[1:]...)
	return fitBlock(render(content), rows)
}

func (m model) discoveryNetwork() (net.IP, string) {
	for _, id := range []diagnostic.ProbeID{diagnostic.ProbeInternet, diagnostic.ProbeProxy, diagnostic.ProbeTargetTCP} {
		ip := m.results[id].Source
		if v4 := ip.To4(); v4 != nil && ip.IsPrivate() {
			// The source /24 is the sweep, not the interface's real prefix: a
			// /16 is 65k hosts, far past what the scan's 60s timeout can cover.
			return ip, v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
		}
	}
	return nil, ""
}

// joinChips joins styled chips with sep, normally wrapping at chip boundaries.
// A chip wider than the terminal wraps on its own rather than overrunning it.
func joinChips(width int, sep string, chips []string) string {
	var lines []string
	cur := ""
	for _, c := range chips {
		if width > 0 {
			c = ansi.Wrap(c, width, "")
		}
		switch {
		case cur == "":
			cur = c
		case strings.Contains(cur, "\n") || strings.Contains(c, "\n"):
			lines = append(lines, cur)
			cur = c
		case lipgloss.Width(cur)+lipgloss.Width(sep)+lipgloss.Width(c) <= width:
			cur += sep + c
		default:
			lines = append(lines, cur)
			cur = c
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return strings.Join(lines, "\n")
}

// fitPanelWidth returns the Lip Gloss width that fits a bordered style in the
// terminal. Style.Width includes padding but excludes borders and margins.
func fitPanelWidth(style lipgloss.Style, terminalWidth int) int {
	return max(terminalWidth-style.GetHorizontalBorderSize()-style.GetHorizontalMargins(), 0)
}

// helpKeys renders key/description pairs as a dim help bar with the keys
// highlighted, e.g. "r restart  ·  q quit", wrapped at pair boundaries.
func helpKeys(st styles, width int, kv ...string) string {
	parts := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, st.key.Render(kv[i])+" "+st.faint.Render(kv[i+1]))
	}
	return joinChips(width, st.faint.Render("  ·  "), parts)
}

// confirmView replaces the help bar with the pending advanced tool's exact
// command and a run/cancel gate, so the scan is always shown before it runs.
func (m model) confirmView() string {
	_, _, display := m.confirmTool.Build(m.target, m.selectedIP())
	body := m.st.panelTitle.Render("Run "+m.confirmTool.Name+"?") + "\n" +
		m.st.faint.Render("Actively probes the shown scope, and may trip intrusion detection.") + "\n" +
		"$ " + display
	w := min(fitPanelWidth(m.st.focusPanel, m.width), 76)
	return m.st.focusPanel.Width(w).Render(body) + "\n" + helpKeys(m.st, m.width, "y", "run", "esc", "cancel")
}

// promptView is the restart prompt panel, shown in place of the help bar.
// withForms includes the target-grammar cheatsheet; View drops it when the
// terminal is too short (the input and any job pane always outrank it).
func (m model) promptView(withForms bool) string {
	body := m.st.panelTitle.Render("Restart") + "\n" + m.input.View()
	if withForms {
		// Dedent the shared const: the two-space indent reads right under
		// "Target forms:" in --help but floats oddly inside the panel.
		forms := strings.TrimPrefix(strings.ReplaceAll(diagnostic.TargetForms, "\n  ", "\n"), "  ")
		body += "\n\n" + m.st.faint.Render(forms)
	}
	if m.inputErr != "" {
		body += "\n" + m.st.fail.Render("✗ "+m.inputErr)
	}
	// 88, not 76: the longest target-form line needs ~86 content cols to
	// render unwrapped on wide terminals.
	w := min(fitPanelWidth(m.st.focusPanel, m.width), 88)
	footer := m.quitNoticeFooter(helpKeys(m.st, m.width, "↑/↓", "history", "enter", "run", "esc", "back"))
	return m.st.focusPanel.Width(w).Render(body) + "\n" + footer
}

// sshFormView is the SSH login panel (S), shown in place of the help bar. The
// value receiver is doing real work here: the inputs are resized to the
// terminal on the copy, never on the model.
func (m model) sshFormView() string {
	w := min(fitPanelWidth(m.st.focusPanel, m.width), 76)
	// 6 = panel border + padding + the gutter the key row's ▸ marker sits in.
	inputW := func(prompt string) int { return max(w-6-lipgloss.Width(prompt), 8) }
	m.ssh.user.Width = inputW(m.ssh.user.Prompt)
	m.ssh.pass.Width = inputW(m.ssh.pass.Prompt)

	// The key row is a chooser, so it renders itself: the selected key, and
	// the ←/→ hint only while the row has the focus.
	key := m.st.key.Render("Key       ") + m.ssh.keyLabel()
	if len(m.ssh.keys) > 1 {
		key += m.st.faint.Render(fmt.Sprintf("  (%d of %d)", m.ssh.keyIdx+1, len(m.ssh.keys)))
		if m.ssh.focus == sshKey {
			key += m.st.faint.Render("  ←/→")
		}
	}
	if m.ssh.focus == sshKey {
		key = m.st.sel.Render("▸ ") + key
	} else {
		key = "  " + key
	}

	body := m.st.panelTitle.Render("SSH login to "+m.ssh.host) + "\n" +
		"  " + m.ssh.user.View() + "\n" +
		key + "\n" +
		"  " + m.ssh.pass.View() +
		"\n\n" + m.st.faint.Render("Leave a field blank and ssh asks you itself, as it does for a\nkey passphrase, a host-key check, or a 2FA code.")
	if m.ssh.err != "" {
		body += "\n" + m.st.fail.Render("✗ "+m.ssh.err)
	}
	if m.ssh.pending != nil {
		body += "\n" + m.spinner.View() + " checking ssh config…"
		return m.st.focusPanel.Width(w).Render(body) + "\n" + m.quitNoticeFooter(helpKeys(m.st, m.width, "esc", "back"))
	}
	return m.st.focusPanel.Width(w).Render(body) + "\n" +
		m.quitNoticeFooter(helpKeys(m.st, m.width, "tab", "next field", "enter", "connect", "esc", "back"))
}

// themeView is the theme picker. It is drawn where the help bar goes, like the
// confirm gate and the SSH form, rather than as a full-screen overlay: the
// checks, banner and panels stay visible, and moving the cursor repaints them
// in the highlighted theme, which is the whole point of previewing one.
func (m model) themeView() string {
	names := 0
	for _, t := range themes {
		names = max(names, lipgloss.Width(t.Name))
	}
	var b strings.Builder
	b.WriteString(m.st.panelTitle.Render("Theme") + "\n")
	for i, t := range themes {
		marker, name := "  ", t.Name
		if i == m.themeSel {
			marker, name = m.st.sel.Render("\u203a "), m.st.sel.Render(t.Name)
		}
		pad := strings.Repeat(" ", names-lipgloss.Width(t.Name)+2)
		b.WriteString(marker + name + pad + m.st.faint.Render(t.About) + "\n")
	}
	w := fitPanelWidth(m.st.focusPanel, m.width)
	return m.st.focusPanel.Width(w).Render(strings.TrimRight(b.String(), "\n")) + "\n" +
		m.quitNoticeFooter(helpKeys(m.st, m.width, "\u2191/\u2193", "preview", "enter", "keep", "esc", "cancel"))
}

// menuHeadings is how many group labels the window items[first:first+n) draws:
// one for the group it opens in and one wherever the group changes inside it.
// The menu's height budget has to pay for them alongside the rows.
func menuHeadings(items []actionItem, first, n int) int {
	count := 0
	for i := first; i < min(first+n, len(items)); i++ {
		if i == first || items[i].group != items[i-1].group {
			count++
		}
	}
	return count
}

// actionsView is the Actions menu (space): what the run can do right now, each
// row carrying the key that does it. Like the theme picker and the confirm
// gate it is drawn where the help bar goes rather than as an overlay, so the
// checks, banner and panels stay on screen behind it. The list is windowed to
// the terminal rather than allowed to push the verdict off the top of it, and
// the cursor row is marked as well as coloured, since colour alone is not a
// distinction every terminal or every reader has.
func (m model) actionsView(avail int) string {
	items := m.actionItems()
	sel := m.actionsRow(items)
	keyWidth := 0
	for _, item := range items {
		keyWidth = max(keyWidth, lipgloss.Width(item.key))
	}
	footer := m.quitNoticeFooter(helpKeys(m.st, m.width, m.keys.pairLabel(ctxList, actUp, actDown), "select", "enter", "run", "esc", "close"))
	// The window always starts far enough back that the selected row is the
	// last one in it, which is the rule that keeps the cursor on screen.
	windowStart := func(n int) int {
		if sel >= n {
			return sel - n + 1
		}
		return 0
	}
	// What is left for the list once the panel's own two borders, its title
	// and the footer under it are paid for. Headings come out of the same
	// budget as the rows they introduce, so the window shrinks until both fit.
	rows, labeled := len(items), true
	if m.height > 0 {
		budget := max(avail-3-lipgloss.Height(footer), 1)
		rows = min(rows, budget)
		// ponytail: a walk down from the whole list, at most one step per row
		// and a handful of groups, rather than solving for the window.
		for rows > 1 {
			headings := menuHeadings(items, windowStart(rows), rows)
			if rows+headings <= budget && rows >= 2*headings {
				break
			}
			rows--
		}
		// A heading earns its line by introducing rows. On a terminal short
		// enough that the labels would outnumber what they label two to one,
		// the menu drops them and spends every line it has on actions.
		if labeled = rows >= 2*menuHeadings(items, windowStart(rows), rows); !labeled {
			rows = min(len(items), budget)
		}
	}
	first := windowStart(rows)
	var b strings.Builder
	b.WriteString(m.st.panelTitle.Render("Actions"))
	if rows < len(items) {
		b.WriteString(m.st.faint.Render(fmt.Sprintf("  %d of %d", sel+1, len(items))))
	}
	b.WriteString("\n")
	for i := first; i < min(first+rows, len(items)); i++ {
		item := items[i]
		// The group the window opens in is labelled too, so a menu scrolled
		// into the middle of a group still says which one it is in.
		if labeled && (i == first || items[i-1].group != item.group) {
			b.WriteString(m.st.faint.Render(groupNames[item.group]) + "\n")
		}
		marker, key, name := "  ", m.st.key.Render(item.key), item.name
		if i == sel {
			marker, key, name = m.st.sel.Render("\u203a "), m.st.sel.Render(item.key), m.st.sel.Render(item.name)
		}
		pad := strings.Repeat(" ", max(keyWidth-lipgloss.Width(item.key), 0)+2)
		b.WriteString(marker + key + pad + name + "\n")
	}
	if len(items) == 0 {
		b.WriteString(m.st.faint.Render("nothing to do yet: the checks are still running") + "\n")
	}
	w := min(fitPanelWidth(m.st.focusPanel, m.width), 56)
	return m.st.focusPanel.Width(w).Render(strings.TrimRight(b.String(), "\n")) + "\n" + footer
}

// helpView is the bottom bar. It teaches the region on screen, never the whole
// keyboard: a chip earns its place only by answering one of three questions a
// reader has about what is in front of them right now, which is how do I move
// here, what does the primary key do to the thing I have selected, and how do
// I leave. Every other binding, including the ones the bar used to carry into
// screens they had nothing to do with, is one keypress away in the Actions
// menu and written out in full behind the help key, so the tail naming those
// two plus quit is the only part of the bar that is the same on every screen.
//
// The rule is what stops the bar growing back: an action is never added here
// because it is useful, only because the region on screen cannot be operated
// without knowing it.
func (m model) helpView(deferred bool) string {
	// Only the device-list branch cares how many devices there are, and
	// networkHosts walks the whole job line buffer, so don't pay for it on
	// every checks frame or while the services of one device are on screen.
	hosts := 0
	if m.networkMap && m.svc.host == "" {
		hosts = len(m.networkHosts())
	}
	// Every chip is looked up in the selected preset.
	var kv []string
	add := func(label, desc string) {
		if label != "" {
			kv = append(kv, label, desc)
		}
	}
	addAction := func(act keyAction) {
		help, ok := actionHelpFor(ctxList, act)
		if ok {
			add(m.keys.label(ctxList, act), help.bar)
		}
	}
	// Rescan is deliberately menu-only. On the map the bar spends its Actions
	// chip saying where a fresh snapshot lives, rather than growing a second
	// key for it, so "how do I refresh this" is answered where the keys are.
	addActions := func() {
		desc := "actions"
		if m.networkMap && m.actionAvailable(actRescanNetwork) {
			desc = "actions: rescan"
		}
		add(m.keys.label(ctxList, actActions), desc)
	}
	switch {
	case m.networkMap && m.svc.host != "":
		// An opened device is two levels deep, so both ways out are named:
		// leaving is what the reader came here needing, and a bar that showed
		// only one of them would make the other look unavailable.
		if len(m.svc.scan.Open) > 0 {
			add(m.keys.pairLabel(ctxList, actUp, actDown), "select service")
			add(m.keys.label(ctxList, actOpen), "diagnose it")
		}
		add(m.keys.label(ctxList, actCancelJob), "devices")
		add(m.keys.label(ctxList, actNetworkMap), "checks")
	case m.networkMap:
		if hosts > 0 {
			add(m.keys.pairLabel(ctxList, actUp, actDown), "select device")
			add(m.keys.label(ctxList, actOpen), "open device")
		}
		add(m.keys.label(ctxList, actNetworkMap), "checks")
	case deferred:
		// Nothing has run, so there is no region to move in: the bar's job is
		// to say what starts one.
		add(m.keys.label(ctxList, actRestart), "run the checks")
		if len(m.tools) > 0 {
			kv = append(kv, "letter", "runs that tool")
		}
		if m.actionAvailable(actOpen) {
			add(m.keys.label(ctxList, actOpen), "full output")
		}
		if m.actionAvailable(actSwitchJob) {
			addAction(actSwitchJob)
		}
	default:
		addPair := func(a, b keyAction) {
			help, ok := actionHelpFor(ctxList, a)
			if ok {
				add(m.keys.pairLabel(ctxList, a, b), help.bar)
			}
		}
		addPair(actUp, actDown)
		// The only key that acts on the selected check. enter is not it: it
		// opens the focused job's output, which is a different region and is
		// there whether or not a check is selected, so without this chip the
		// bar answers how to move and how to leave but never what the primary
		// key does to the thing under the cursor. Availability is the same
		// selection test the compact bar uses, so the route to selected
		// evidence stops appearing and disappearing with the terminal height.
		if m.actionAvailable(actCheckDetails) {
			addAction(actCheckDetails)
		}
		// What enter does here. The Tool output pane shows a tail, so once a
		// job exists the screen is already carrying output the reader cannot
		// read all of, and the route to the rest was named only by the bars a
		// short terminal swaps in: the tall window showed the pane and said
		// nothing. The predicate is the dispatch's own, so the chip cannot
		// promise a key that would do something else, and it is the job's
		// existence rather than the pane's visibility, which the layout takes
		// away and gives back as rows come and go.
		if m.actionAvailable(actOpen) {
			addAction(actOpen)
		}
	}
	addActions()
	addAction(actHelp)
	addAction(actQuit)
	help := m.chordHint(helpKeys(m.st, m.width, kv...))
	if notice := m.noticeView(); notice != "" {
		return notice + "\n" + help
	}
	return help
}

// compactHelpView keeps only the controls needed to navigate the region on
// screen and reach the Actions menu. It replaces the full help bar only under
// height pressure, so convenience commands spend no rows that could carry
// selected evidence.
func (m model) compactHelpView(deferred bool) string {
	var kv []string
	add := func(label, desc string) {
		if label != "" {
			kv = append(kv, label, desc)
		}
	}
	switch {
	case m.networkMap && m.svc.host != "":
		add(m.keys.pairLabel(ctxList, actUp, actDown), "select service")
		if len(m.svc.scan.Open) > 0 {
			add(m.keys.label(ctxList, actOpen), "diagnose it")
		}
		add(m.keys.label(ctxList, actCancelJob), "devices")
		add(m.keys.label(ctxList, actNetworkMap), "checks")
	case m.networkMap:
		hosts := m.networkHosts()
		if len(hosts) > 0 {
			add(m.keys.pairLabel(ctxList, actUp, actDown), "select device")
			add(m.keys.label(ctxList, actOpen), "open device")
		}
		add(m.keys.label(ctxList, actNetworkMap), "checks")
	case deferred:
		add(m.keys.label(ctxList, actRestart), "run the checks")
		add(m.keys.label(ctxList, actActions), "actions")
		add(m.keys.label(ctxList, actHelp), "help")
	default:
		add(m.keys.pairLabel(ctxList, actUp, actDown), "select")
		if m.actionAvailable(actCheckDetails) {
			add(m.keys.label(ctxList, actCheckDetails), "details")
		}
		if m.hasJob() {
			add(m.keys.label(ctxList, actOpen), "full output")
		} else {
			add(m.keys.label(ctxList, actActions), "actions")
		}
	}
	help := m.chordHint(helpKeys(m.st, m.width, kv...))
	if notice := m.noticeView(); notice != "" {
		return notice + "\n" + help
	}
	return help
}

// hiddenRegionHelp replaces a region that cannot fit with a one-line account
// of its current cursor and the keys that still operate it. The content stays
// navigable without asking the reader to move an invisible selection.
func (m model) hiddenRegionHelp(deferred bool) string {
	if deferred {
		return m.compactHelpView(true)
	}
	if m.networkMap {
		state := "Live"
		if m.cur.active == nil {
			state = "Cached"
			if m.cur.status != JobDone {
				state += " " + m.cur.status.String()
			}
		}
		var prefix, item, back string
		if m.svc.host != "" {
			open := m.svc.scan.Open
			if len(open) > 0 {
				sel := min(max(m.svc.sel, 0), len(open)-1)
				prefix = fmt.Sprintf("%s · Service %d/%d: ", mapTitle, sel+1, len(open))
				item = fmt.Sprintf("%d/%s", open[sel].Port, open[sel].Name)
			} else {
				prefix, item = mapTitle+" · Services: ", m.svc.name
			}
			back = m.keys.label(ctxList, actCancelJob) + " back"
		} else {
			hosts := m.networkHosts()
			if len(hosts) > 0 {
				sel := min(max(m.mapSelected, 0), len(hosts)-1)
				prefix = fmt.Sprintf("%s · Device %d/%d: ", mapTitle, sel+1, len(hosts))
				item = strings.SplitN(hosts[sel], " (", 2)[0]
			} else {
				prefix = mapTitle
			}
			back = m.keys.label(ctxList, actNetworkMap) + " back"
		}
		sep := " · "
		suffix := strings.Join([]string{state, m.keys.pairLabel(ctxList, actUp, actDown) + " move", back}, sep)
		if m.width > 0 {
			item = ansi.Truncate(item, max(m.width-lipgloss.Width(prefix)-lipgloss.Width(suffix)-2*lipgloss.Width(sep), 1), "…")
		}
		help := prefix + item + sep + suffix
		if notice := m.noticeView(); notice != "" {
			help = notice + "\n" + help
		}
		help = m.chordHint(help)
		if m.width > 0 {
			help = ansi.Truncate(help, m.width, "…")
		}
		return help
	}

	var context string
	var kv []string
	add := func(label, desc string) {
		if label != "" {
			kv = append(kv, label, desc)
		}
	}
	rows := m.checkRows()
	at := slices.Index(rows, m.selected)
	if at >= 0 {
		context = fmt.Sprintf("Check %d/%d: %s", at+1, len(rows), m.probes[m.selected].Name)
	}
	add(m.keys.pairLabel(ctxList, actUp, actDown), "move")
	if m.actionAvailable(actCheckDetails) {
		add(m.keys.label(ctxList, actCheckDetails), "details")
	}
	if m.hasJob() {
		add(m.keys.label(ctxList, actOpen), "full output")
	} else {
		add(m.keys.label(ctxList, actActions), "actions")
	}
	nav := helpKeys(m.st, m.width, kv...)
	sep := m.st.faint.Render("  ·  ")
	if m.width > 0 {
		context = ansi.Truncate(context, max(m.width-lipgloss.Width(nav)-lipgloss.Width(sep), 8), "…")
	}
	help := joinChips(m.width, sep, []string{m.st.faint.Render(context), nav})
	if notice := m.noticeView(); notice != "" {
		return notice + "\n" + help
	}
	return m.chordHint(help)
}

// chordHint prefixes the help bar with a half-typed chord, as vim's showcmd
// does, so the first key of one does not look like a dropped keypress.
func (m model) chordHint(help string) string {
	if len(m.pendingKeys) == 0 {
		return help
	}
	return m.st.key.Render(displaySeq(strings.Join(m.pendingKeys, " "))+"…") + m.st.faint.Render("  ·  ") + help
}

// helpContent is generated from the same actions and bindings used by dispatch.
func (m model) helpContent() string {
	keyWidth := 8
	for _, def := range actionDefs {
		for ctx := range def.help {
			keyWidth = max(keyWidth, lipgloss.Width(m.keys.label(ctx, def.act)))
		}
	}
	// A description wraps in its own column, with a hanging indent, rather than
	// running past the terminal: the display rows the terminal would hard-wrap
	// it into are not in MaxHeight's accounting, so they would push the bottom
	// of the sheet off the screen. A terminal narrower than that indent falls
	// back to wrapping the whole row.
	indent := strings.Repeat(" ", 2+keyWidth+2)
	row := func(k, desc string) string {
		prefix := "  " + m.st.key.Render(k) + strings.Repeat(" ", max(keyWidth-lipgloss.Width(k), 0)+2)
		desc = m.st.faint.Render(desc)
		if m.width > 0 && m.width <= len(indent) {
			return ansi.Wrap(prefix+desc, m.width, "") + "\n"
		}
		desc = ansi.Wrap(desc, m.width-len(indent), "")
		return prefix + strings.ReplaceAll(desc, "\n", "\n"+indent) + "\n"
	}
	// Both sections are generated from the same table dispatch indexes.
	listed := func(ctx keyContext, def actionDef) (actionHelp, bool) {
		help, ok := def.help[ctx]
		if !ok || !m.keys.bound(ctx, def.act) {
			return actionHelp{}, false
		}
		// SSH is the one row whose key is offered only where it applies, so a
		// sheet that listed it unconditionally would promise a login the run
		// has no host for.
		if def.act == actSSH && !m.sshDetected() {
			return actionHelp{}, false
		}
		return help, true
	}
	var b strings.Builder
	b.WriteString(m.wrap(m.st.panelTitle.Render("Keys")) + "\n")
	// The list context is sectioned by the same groups the Actions menu is
	// sorted into, so the sheet and the menu teach one hierarchy rather than
	// two orders of the same keys. It is also what separates the drill-down
	// tools from the built-in actions: as one flat list they read as more
	// vocabulary to learn rather than as the installed binaries they are.
	for group := range groupNames {
		var rows strings.Builder
		for _, def := range actionDefs {
			help, ok := listed(ctxList, def)
			if !ok || m.actionGroupFor(def.act) != actionGroup(group) {
				continue
			}
			rows.WriteString(row(m.keys.label(ctxList, def.act), help.details))
		}
		if actionGroup(group) == groupTools {
			for _, tool := range m.tools {
				rows.WriteString(row(tool.Key, "run "+tool.Name))
			}
		}
		if rows.Len() == 0 {
			continue
		}
		b.WriteString(m.wrap(m.st.faint.Render(groupNames[group])) + "\n" + rows.String())
	}
	b.WriteString("\n" + m.wrap(m.st.panelTitle.Render("Output viewer")) + "\n")
	for _, def := range actionDefs {
		if help, ok := listed(ctxViewer, def); ok {
			b.WriteString(row(m.keys.label(ctxViewer, def.act), help.details))
		}
	}
	return b.String()
}

func (m model) helpScrollFooter() string {
	var kv []string
	addPair := func(a, b keyAction, desc string) {
		if label := m.keys.pairLabel(ctxViewer, a, b); label != "" {
			kv = append(kv, label, desc)
		}
	}
	addPair(actUp, actDown, "scroll")
	addPair(actPageUp, actPageDown, "page")
	addPair(actHalfPageUp, actHalfPageDown, "half page")
	addPair(actTop, actBottom, "top/bottom")
	return helpKeys(m.st, m.width, append(kv, "other key", "close")...)
}

func (m model) helpFullView() string {
	return m.helpContent() + "\n" + helpKeys(m.st, m.width, "any key", "close")
}

func (m model) helpScrolls() bool {
	return m.height > 0 && lipgloss.Height(m.helpFullView()) > m.height
}

func (m *model) refreshHelpViewport(reset bool) {
	offset := m.helpVP.YOffset
	m.helpVP.Width = max(m.width, 1)
	m.helpVP.Height = 20
	if m.height > 0 {
		m.helpVP.Height = max(m.height-1-lipgloss.Height(m.helpScrollFooter()), 1)
	}
	m.helpVP.SetContent(m.helpContent())
	if reset {
		m.helpVP.GotoTop()
	} else {
		m.helpVP.SetYOffset(offset)
	}
}

// helpOverlay shows the complete sheet when it fits, otherwise the same
// viewport controls used by the output and incident viewers reveal every row.
func (m model) helpOverlay() string {
	if !m.helpScrolls() {
		return m.helpFullView()
	}
	if m.helpVP.TotalLineCount() == 0 {
		m.refreshHelpViewport(true)
	}
	total := m.helpVP.TotalLineCount()
	top := m.helpVP.YOffset + 1
	bottom := min(m.helpVP.YOffset+m.helpVP.Height, total)
	context := fmt.Sprintf("lines %d-%d of %d", min(top, bottom), bottom, total)
	if m.width > 0 {
		context = ansi.Truncate(context, m.width, "")
	}
	return m.helpVP.View() + "\n" + m.st.faint.Render(context) + "\n" + m.helpScrollFooter()
}

func (m model) detailsHeader() string {
	name, at, total := "selected check", 0, len(m.checkRows())
	if m.selected >= 0 && m.selected < len(m.probes) {
		name = m.probes[m.selected].Name
		at = slices.Index(m.checkRows(), m.selected) + 1
	}
	return m.wrap(m.st.panelTitle.Render(fmt.Sprintf("%s: %s · check %d of %d", detailsTitle, name, at, total)))
}

func (m model) detailsContent() string {
	rows := m.detailRows(false, max(m.width, 1))
	if len(rows) > 0 {
		rows = rows[1:]
	}
	// Nothing is assembled here: the viewer is the same rows the inline
	// section draws, minus the heading the header row already carries. One
	// renderer, so a reader who opens D cannot be shown a different reading of
	// the same check from the one they were just looking at.
	if len(rows) == 0 {
		rows = []string{m.st.faint.Render("Nothing to show yet.")}
	}
	return lipgloss.NewStyle().Width(max(m.width, 1)).Render(strings.Join(rows, "\n"))
}

func (m model) detailsFooter() string {
	var kv []string
	addPair := func(a, b keyAction, desc string) {
		if label := m.keys.pairLabel(ctxViewer, a, b); label != "" {
			kv = append(kv, label, desc)
		}
	}
	addPair(actUp, actDown, "scroll")
	addPair(actPageUp, actPageDown, "page")
	addPair(actTop, actBottom, "top/bottom")
	addPair(actClearFilter, actBack, "back")
	return m.chordHint(helpKeys(m.st, m.width, kv...))
}

func (m *model) refreshDetailsViewport(reset bool) {
	offset := m.detailsVP.YOffset
	m.detailsVP.Width = max(m.width, 1)
	height := 20
	if m.height > 0 {
		height = max(m.height-lipgloss.Height(m.detailsHeader())-1-lipgloss.Height(m.detailsFooter()), 1)
	}
	m.detailsVP.Height = height
	m.detailsVP.SetContent(m.detailsContent())
	if reset {
		m.detailsVP.GotoTop()
	} else {
		m.detailsVP.SetYOffset(offset)
	}
}

func (m model) detailsView() string {
	total := m.detailsVP.TotalLineCount()
	top := min(m.detailsVP.YOffset+1, total)
	bottom := min(m.detailsVP.YOffset+m.detailsVP.Height, total)
	context := fmt.Sprintf("lines %d-%d of %d", min(top, bottom), bottom, total)
	if m.width > 0 {
		context = ansi.Truncate(context, m.width, "")
	}
	return m.detailsHeader() + "\n" + m.detailsVP.View() + "\n" +
		m.st.faint.Render(context) + "\n" + m.detailsFooter()
}

func (m model) noticeView() string {
	if m.notice == "" {
		return ""
	}
	if m.notice == ctrlCNotice {
		return m.st.warn.Render("! " + m.notice)
	}
	if m.noticeOK {
		return m.st.pass.Render("✓ " + m.notice)
	}
	return m.st.fail.Render("✗ " + m.notice)
}

// quitNoticeFooter swaps a panel's own footer for the armed-quit notice. The
// overlays draw their footer where the help bar goes, and that footer must not
// be the reason an armed Ctrl+C goes unseen: the next one quits the whole
// program. Only the Ctrl+C notice takes the slot, so an overlay's keys are
// still on screen for every other notice, and they come back as it clears.
func (m model) quitNoticeFooter(footer string) string {
	if m.notice == ctrlCNotice {
		return m.noticeView()
	}
	return footer
}

// banner is the full-width guidance block under the header: what is happening,
// what it means in plain English, and, on a failure, what to do about it and
// which tool to reach for next.
func (m model) banner() string {
	if m.toolbox && !m.chainRan() {
		return "Welcome! Press " + m.st.sel.Render("r") + " to check your connection, or run a tool below."
	}
	if !m.allDone() {
		done, total := len(m.results), len(m.probes)
		return m.spinner.View() + " Checking your connection… " +
			progressBar(m.st, done, total, 20) + m.st.faint.Render(fmt.Sprintf(" %d of %d done", done, total))
	}
	summary, verdict := m.diagnose(m.probeOrder())
	st := verdictStatus(verdict)
	// Bold as well as coloured: the panel titles under this sentence are bold,
	// and the answer must not be the lighter of the two. A terminal that
	// renders no attributes at all drops both together, which is why the
	// hierarchy is carried by position, by the glyph and by the labels below,
	// and never by weight alone.
	lines := []string{m.st.status[st].Bold(true).Render(probeGlyph(st) + " " + summary)}
	// All three lines under the verdict follow the row the diagnosis blames
	// rather than the first failing row: a path MTU black hole fails TLS but
	// the evidence and the remedy are both on the Path MTU row, and a "Fix:"
	// taken from one row with a "Next:" taken from another sends the reader
	// two ways at once.
	i := m.answerRow()
	if i < 0 {
		// Nothing to fix and nothing to chase, which is the one moment there
		// is room to say what else netdoc can be pointed at.
		if hint := m.localDeviceHint(); hint != "" {
			return lines[0] + "\n  " + hint
		}
		return lines[0]
	}
	blamed := m.probes[i].ID
	// The row's own hint is shown here only when the diagnosis reached no
	// action of its own. Where it did, the two say the same thing one level
	// apart ("lower the interface MTU" against "Try a lower MTU on the path"),
	// and two adjacent lines of the same instruction make the primary answer
	// longer without making it say more. The hint is not dropped: it carries
	// the dates, names and commands only the probe held, so it moves down to
	// that row's Details, which is the row the cursor is already parked on.
	//
	// This is structural rather than a judgement about particular wordings.
	// Every diagnosis that blames a row also reaches a remediation about it,
	// so the pair appears together or not at all.
	_, advised := m.remediation()
	if fix := m.results[blamed].Fix; fix != "" && !advised {
		lines = append(lines, "  "+m.st.faint.Render("Fix: "+fix))
	}
	if next := m.nextStep(blamed); next != "" {
		lines = append(lines, "  "+next)
	}
	// The evidence comes last, because it is what supports the answer rather
	// than what the reader does about it. One row: it is quoted here to save
	// the reader a trip to the Checks panel for the "why", not to reproduce
	// the panel, and the cursor is already parked on the row that holds the
	// whole of it.
	if line, _ := m.evidenceLine(m.results[blamed].Detail); line != "" {
		lines = append(lines, m.st.faint.Render(line))
	}
	return strings.Join(lines, "\n")
}

// localDeviceHint is the way into the local-device workflow for a reader with
// no failure to chase. A finished targetless run on a private network has
// nothing else to suggest, and finding another device is the part of netdoc
// least likely to be stumbled upon. Empty everywhere else, including on a
// machine with no private IPv4 network to sweep, where the key would only
// answer that there is nothing to map.
func (m model) localDeviceHint() string {
	if m.target != nil || m.networkMap || !m.keys.bound(ctxList, actNetworkMap) {
		return ""
	}
	if _, cidr := m.discoveryNetwork(); cidr == "" {
		return ""
	}
	return "Next: press " + m.st.sel.Render(m.keys.label(ctxList, actNetworkMap)) + " to find a device on your network and diagnose it"
}

// evidenceLine is the answer block's quote of a probe's finding, clipped to one
// terminal row, plus whether the whole finding fit inside it. The clip is what
// holds the evidence to one line however long a probe's detail runs: some of
// them are a paragraph, and supporting evidence that reflows into six rows
// crowds out the answer it is supporting. The Details panel reads the second
// return to decide whether it still has the rest of that finding to add. Empty
// detail yields an empty line, and the caller drops it rather than labelling
// nothing.
func (m model) evidenceLine(detail string) (line string, whole bool) {
	if detail == "" {
		return "", true
	}
	line = "  Evidence: " + detail
	if m.width <= 0 {
		return line, true
	}
	clipped := ansi.Truncate(line, m.width, "…")
	return clipped, clipped == line
}

// answerRow is the probe row the answer block above the panels is quoting: the
// row the finished diagnosis blames, and -1 when the run is unfinished or the
// diagnosis blames no row. The Details panel reads it to avoid printing the
// same finding twice, a few rows apart, in two different places.
func (m model) answerRow() int {
	if !m.allDone() {
		return -1
	}
	return m.focusRow()
}

// probeOrder is the run's probe IDs in DAG order, which is what the diagnosis
// reads. It deliberately reports nothing about which row failed: the blamed
// row is the diagnosis's call alone, and focusRow is the only place that asks.
func (m model) probeOrder() []diagnostic.ProbeID {
	order := make([]diagnostic.ProbeID, len(m.probes))
	for i, probe := range m.probes {
		order[i] = probe.ID
	}
	return order
}

// verdictStatus is the presentation severity of a finished run, and the
// diagnosis verdict is the only thing that decides it. A degraded verdict may
// legitimately carry a failed row (QUIC blocked while TCP carries the traffic,
// encrypted DNS blocked while plain DNS resolves), so painting the banner red
// for any failed row would contradict the sentence printed next to it.
func verdictStatus(verdict string) diagnostic.Status {
	switch verdict {
	case diagnostic.VerdictOK:
		return diagnostic.StatusPass
	case diagnostic.VerdictDegraded:
		return diagnostic.StatusWarn
	}
	return diagnostic.StatusFail
}

// focusRow is the probe row a finished run should put the cursor on and take
// its drill-down from: the row the diagnosis blames, which is the row the
// verdict names when it names one and otherwise the first failing row. -1 when
// the run blames no row at all.
//
// The choice is the diagnosis's, not this function's: it asks for the blamed
// row and only maps it to a list index. The first-failure scan that remains is
// about the list rather than the diagnosis, for the case where the blamed probe
// has no row to put a cursor on.
func (m model) focusRow() int {
	blamed := m.diagnosis().Blamed
	first := -1
	for i, probe := range m.probes {
		// A probe with no row cannot be the row to send the reader to, and
		// putting the cursor there would leave the Details panel describing a
		// row the list does not offer.
		if !hasCheckRow(probe.ID) {
			continue
		}
		if probe.ID == blamed {
			return i
		}
		if first < 0 && m.results[probe.ID].Status == diagnostic.StatusFail {
			first = i
		}
	}
	return first
}

// changedRow reports whether a probe's status differs from the one it reported
// in the previous completed watch pass.
//
// It answers only for a pass that has finished. While the next one runs the
// rows on screen are that pass's partial results, and the history still
// describes the pass before them, so a marker placed then would label a row
// for a comparison it is not part of. Completion to the next restart is
// exactly the window where the two are the same thing.
//
// The history is the single source of truth: recordRun already appends one
// status per probe per pass, so the previous pass is the entry before the last
// one and there is no second copy of it to keep in step.
func (m model) changedRow(id diagnostic.ProbeID) bool {
	if !m.watch || !m.allDone() {
		return false
	}
	history := m.runHistory[id]
	return len(history) >= 2 && history[len(history)-1] != history[len(history)-2]
}

// changedFocus is the row a completed watch pass sends the cursor to: the
// first changed row in probe order that is not already explained as downstream
// of another one, and otherwise the first changed row. -1 when the pass
// changed nothing, which is what leaves an identical pass's cursor where the
// reader last saw it instead of yanking it back to the same verdict every few
// seconds.
//
// Downstream is read off what the run already decided rather than from a
// second diagnosis: the failures Collateral has already marked as the same
// outage seen again. The rest is probe order, which is the DAG's own order, so
// a rung that went down is already ahead of everything that never got to run
// behind it. That is what puts the cursor on DNS rather than on the target
// connect DNS took down with it.
func (m model) changedFocus() int {
	collateral := diagnostic.Collateral(m.target, m.probeOrder(), m.results)
	first := -1
	for i, probe := range m.probes {
		if !hasCheckRow(probe.ID) || !m.changedRow(probe.ID) {
			continue
		}
		if first < 0 {
			first = i
		}
		if collateral[probe.ID] {
			continue
		}
		return i
	}
	return first
}

// focusTarget is the row a completed run puts the cursor on. Outside watch
// mode, and on a watch pass with nothing yet to compare against, that is the
// row the diagnosis blames, which is what a single run has always done. Once a
// previous pass exists, a watch pass moves the cursor only for a change, so
// the ordinary case of nothing happening is a screen that holds still.
//
// recordRun appends one status per probe per pass, so any row's history length
// says whether there is a baseline at all, and a target switch clears the map
// so the first pass after it starts over without one.
func (m model) focusTarget() int {
	if !m.watch || len(m.probes) == 0 || len(m.runHistory[m.probes[0].ID]) < 2 {
		return m.focusRow()
	}
	return m.changedFocus()
}

// compactRows is the Checks panel's default row set: of the probes that have a
// row at all (see checkRows), the indices worth reading, and how many passing
// and not-applicable rows that left behind. A finished run keeps every Fail,
// Warn and Skip, the row the diagnosis blames
// (a path MTU black hole rests on a Warn, so severity alone would drop the one
// row the verdict sends the reader to), and the cursor row (the Details panel
// is showing it, and a panel describing a row the list does not offer is worse
// than the row it costs). Everything else is one summary line. Nothing is
// hidden while the run is still going, while the reader has expanded the list,
// or when the expand action has no key to reach it by.
//
// N/A rows collapse alongside the passing ones: an unset proxy or an
// unreachable second-opinion resolver is not something to act on, and the
// Checks panel answers what needs attention. Their evidence is not lost,
// because the cursor still walks every row and a hidden row the cursor lands
// on comes back with the Details panel that describes it.
//
// The blamed row comes from focusRow, so the list and the banner cannot
// disagree about which row matters. Every row the diagnosis can name today is
// also a Warn, so that clause currently keeps nothing the severity test would
// have dropped; it stays because the row worth reading is the diagnosis's
// call, not a severity comparison made over here.
func (m model) compactRows() (shown []int, hiddenPass, hiddenNA int) {
	all := m.checkRows()
	if m.expanded || !m.allDone() || !m.keys.bound(ctxList, actExpand) {
		return all, 0, 0
	}
	blamed := m.focusRow()
	for _, i := range all {
		probe := m.probes[i]
		// A row that changed this watch pass stays on screen whatever it
		// changed to: a check that just came back is the news of the pass, and
		// collapsing it because passing rows collapse would hide the one line
		// the reader was waiting for. It collapses again on the next pass that
		// leaves it alone, and none of this touches the expand state.
		if i == blamed || i == m.selected || m.changedRow(probe.ID) {
			shown = append(shown, i)
			continue
		}
		switch m.results[probe.ID].Status {
		case diagnostic.StatusPass:
			hiddenPass++
		case diagnostic.StatusNA:
			hiddenNA++
		default:
			shown = append(shown, i)
		}
	}
	return shown, hiddenPass, hiddenNA
}

// hasCheckRow reports whether a probe is worth a row in the Checks panel.
//
// The Wi-Fi probe is not. Its whole result is the network name, and the
// context strip under the banner already prints that name from the same
// result ("Wi-Fi: homewifi"), so the row is the same fact a second time. It
// carries no actionable finding to lose either: the probe reports Pass with
// the name or N/A without it, never a Warn or a Fail, and the interface row
// beside it is the one that speaks when the link itself is the problem. The
// probe keeps running: the context strip, the report, and the JSON output all
// read its result.
func hasCheckRow(id diagnostic.ProbeID) bool { return id != diagnostic.ProbeSSID }

// checkRows is the probe indices the Checks panel offers as rows, in probe
// order. It is also the list the cursor walks: an index that is not in here is
// a cursor position with no row under it and a Details panel describing
// something the reader cannot see.
func (m model) checkRows() []int {
	rows := make([]int, 0, len(m.probes))
	for i, probe := range m.probes {
		if hasCheckRow(probe.ID) {
			rows = append(rows, i)
		}
	}
	return rows
}

// collapsedChecksRow is the one line the hidden passing and not-applicable
// rows are worth. It counts what compactRows actually hid, never how many rows
// passed: the blamed row and the cursor row pass too and are still on screen.
// The two counts are named apart, because "passed" is a claim about the
// network and "N/A" is a claim about the question having no answer here.
//
// It sits in the marker column rather than indented with the probe rows,
// which is also what keeps it inside the columns the Checks section has:
// a row that wraps costs the section a second display row, and the block has
// a row budget to stay inside. That budget is why the mixed wording is the
// terse one and why "N/A" is not spelled out.
func (m model) collapsedChecksRow(hiddenPass, hiddenNA int) string {
	checks := func(n int) string {
		if n == 1 {
			return "check"
		}
		return "checks"
	}
	var summary string
	switch {
	case hiddenNA == 0:
		summary = fmt.Sprintf("%d other %s passed", hiddenPass, checks(hiddenPass))
	case hiddenPass == 0:
		summary = fmt.Sprintf("%d other %s N/A", hiddenNA, checks(hiddenNA))
	default:
		summary = fmt.Sprintf("%d passed, %d N/A", hiddenPass, hiddenNA)
	}
	return m.st.faint.Render(fmt.Sprintf("· %s (%s expand)", summary, m.keys.label(ctxList, actExpand)))
}

// probeNextTool maps a blamed probe to the tool hotkey that best
// investigates it.
var probeNextTool = map[diagnostic.ProbeID]string{
	diagnostic.ProbeInternet:  "p",
	diagnostic.ProbeDNS:       "d",
	diagnostic.ProbeTargetTCP: "t",
	diagnostic.ProbePMTU:      "t",
	diagnostic.ProbeTLS:       "c",
	diagnostic.ProbeHTTP:      "c",
	diagnostic.ProbeHTTPS:     "c",
	diagnostic.ProbeSSH:       "t",
	diagnostic.ProbeSMTP:      "t",
}

// nextStep suggests the tool key worth pressing after a failure, e.g.
// "Next: press d for DNS lookup (dig)". Empty when no tool applies or the
// binary is missing.
func (m model) nextStep(id diagnostic.ProbeID) string {
	key, ok := probeNextTool[id]
	if !ok {
		return ""
	}
	for _, t := range m.tools {
		if t.Key == key && t.Available {
			return "Next: press " + m.st.sel.Render(key) + " for " + t.Name + " (" + t.Bin + ")"
		}
	}
	return ""
}

// jobStatusLine is the "name: status" line for the selected run: a live
// spinner + timer while running, the total duration once it has finished. It
// is the selected run's tab in the strip below, and the strip is what the job
// pane and the output viewer both draw.
func (m model) jobStatusLine() string {
	s := m.st.faint.Render(m.cur.name+": ") + m.st.status[m.cur.status].Render(m.cur.status.String())
	if m.cur.active != nil {
		return s + " " + m.spinner.View() + m.st.faint.Render(fmt.Sprintf(" %.0fs", time.Since(m.cur.start).Seconds()))
	}
	if m.cur.dur > 0 && m.cur.dur < time.Second {
		s += m.st.faint.Render(fmt.Sprintf(" · %dms", m.cur.dur.Milliseconds()))
	} else if m.cur.dur >= time.Second {
		s += m.st.faint.Render(fmt.Sprintf(" · %.0fs", m.cur.dur.Seconds()))
	}
	return s
}

// jobTabNameWidth caps a parked run's name in the strip, so one long tool name
// cannot crowd every other tab off the row. Every built-in tool name but the
// longest fits whole.
const jobTabNameWidth = 14

// jobGlyphs is a run's lifecycle in one character, indexed by JobStatus and
// drawn from the alphabet the probe rows already use. A cancelled run takes
// the skip glyph, which is what cancelling one amounts to, and a run that ran
// out of its budget takes the warn glyph rather than a second failure mark, so
// the strip tells a timeout from a failure without asking the reader to see
// colour.
var jobGlyphs = [...]string{"·", "…", "✓", "✗", "⊘", "!"}

// jobGlyph is how far a run got: the shared spinner while it is still
// streaming, else its terminal glyph in that status's colour.
func (m model) jobGlyph(j *jobState) string {
	if j.active != nil {
		return m.spinner.View()
	}
	if j.status < 0 || int(j.status) >= len(jobGlyphs) {
		return "?"
	}
	return m.st.status[j.status].Render(jobGlyphs[j.status])
}

// jobStrip is the row of runs the job pane and the output viewer share, in the
// ring order tab walks: the selected run first, keeping the whole status line,
// then the parked ones as name + glyph chips. So tab selects the chip
// immediately right of the selected run, and switching rotates the row left.
// A lone run is the status line and nothing else, which leaves the "›" marker
// as the sign that there is anywhere to switch to. Only the selected run
// spells its status out, so no run's state is written twice on one row.
func (m model) jobStrip() string {
	line := m.jobStatusLine()
	if !m.hasJob() || len(m.otherJobs) == 0 {
		return line
	}
	line = m.st.sel.Render("› ") + line

	chips := make([]string, len(m.otherJobs))
	for i := range m.otherJobs {
		chips[i] = m.st.faint.Render(ansi.Truncate(m.otherJobs[i].name, jobTabNameWidth, "…")) +
			" " + m.jobGlyph(&m.otherJobs[i])
	}
	sep := m.st.faint.Render("  ·  ")
	used, sepW := lipgloss.Width(line), lipgloss.Width(sep)

	// Fill from the left in ring order, so the chips a narrow terminal keeps
	// are the ones tab reaches first, dropping one at a time until the row
	// fits with the counter for whatever is left over. Re-measuring the whole
	// row per drop keeps one definition of "does it fit", and maxParkedJobs
	// bounds how often it can run.
	n := len(chips)
	for m.width > 0 && n > 0 && jobStripWidth(used, sepW, chips, n) > m.width {
		n--
	}
	for _, c := range chips[:n] {
		line += sep + c
	}
	// The counter is the only sign the ring carries on past the last chip, so
	// it yields only to a terminal too narrow for the selected run itself.
	if hidden := len(chips) - n; hidden > 0 && (m.width <= 0 || jobStripWidth(used, sepW, chips, n) <= m.width) {
		line += sep + m.st.faint.Render(fmt.Sprintf("+%d", hidden))
	}
	return line
}

// jobStripWidth is the display width of the strip carrying the first n chips,
// counting the "+N" counter whenever that leaves any of them hidden.
func jobStripWidth(used, sepW int, chips []string, n int) int {
	total := used
	for _, c := range chips[:n] {
		total += sepW + lipgloss.Width(c)
	}
	if hidden := len(chips) - n; hidden > 0 {
		total += sepW + lipgloss.Width(fmt.Sprintf("+%d", hidden))
	}
	return total
}

// viewerHeader is the viewer's heading, the command line and the run status
// above the viewport, wrapped: nothing else reflows them, and vpHeight has to
// know how many rows they cost.
//
// The heading is what says which screen this is. Without it the viewer opens
// on the same "$ command" row the job pane on the main screen opens with, and
// the two are then told apart only by what is missing from one of them, which
// is not something a reader can check before pressing a key.
func (m model) viewerHeader() string {
	return m.wrap(m.st.panelTitle.Render(viewerTitle)) + "\n" +
		m.wrap(m.st.title.Render("$ "+m.cur.display)) + "\n" + m.wrap(m.jobStrip())
}

// outputView is the full-screen scrollable output viewer (Enter).
func (m model) outputView() string {
	var b strings.Builder
	b.WriteString(m.viewerHeader() + "\n")
	b.WriteString(m.vp.View() + "\n")
	// The context line is budgeted at exactly one row, so trim it rather than
	// wrap it, since a long filter is the usual way it outgrows the terminal.
	ctx := m.vpContext()
	if m.width > 0 {
		ctx = ansi.Truncate(ctx, m.width, "")
	}
	b.WriteString(m.st.faint.Render(ctx) + "\n")
	b.WriteString(m.viewerFooter())
	return b.String()
}

func (m model) viewerFooter() string {
	if m.filtering {
		return m.filterInput.View() + "\n" + m.quitNoticeFooter(helpKeys(m.st, m.width, "enter", "apply", "esc", "clear"))
	}
	if notice := m.noticeView(); notice != "" {
		return notice
	}
	var kv []string
	add := func(label, desc string) {
		if label != "" {
			kv = append(kv, label, desc)
		}
	}
	addAction := func(act keyAction) {
		if help, ok := actionHelpFor(ctxViewer, act); ok {
			add(m.keys.label(ctxViewer, act), help.bar)
		}
	}
	addPair := func(a, b keyAction) {
		if help, ok := actionHelpFor(ctxViewer, a); ok {
			add(m.keys.pairLabel(ctxViewer, a, b), help.bar)
		}
	}
	addPair(actUp, actDown)
	addPair(actPageUp, actPageDown)
	addPair(actHalfPageUp, actHalfPageDown)
	addPair(actTop, actBottom)
	addAction(actFilter)
	if len(m.otherJobs) > 0 {
		addAction(actSwitchJob)
	}
	addAction(actCopy)
	addAction(actSave)
	// With a filter applied the two exits do different things, so they stop
	// sharing a chip and say which is which.
	if m.filter != "" {
		addAction(actClearFilter)
		addAction(actBack)
		return m.chordHint(helpKeys(m.st, m.width, kv...))
	}
	addPair(actClearFilter, actBack)
	return m.chordHint(helpKeys(m.st, m.width, kv...))
}

// vpContext is the viewport position line, in wrapped display-line numbers:
// "lines 420–450 of 500 · 37 older lines discarded · following".
func (m model) vpContext() string {
	total := m.vp.TotalLineCount()
	top := m.vp.YOffset + 1
	bot := m.vp.YOffset + m.vp.Height
	if bot > total {
		bot = total
	}
	if top > bot {
		top = bot
	}
	s := fmt.Sprintf("lines %d–%d of %d", top, bot, total)
	if m.filter != "" {
		s += " · filter: " + m.filter
	}
	if m.cur.evicted > 0 {
		s += fmt.Sprintf(" · %d older lines discarded", m.cur.evicted)
	}
	if m.cur.dropped > 0 {
		s += fmt.Sprintf(" · %d dropped (channel overflow)", m.cur.dropped)
	}
	if m.cur.active != nil {
		if m.follow {
			s += " · following"
		} else {
			s += " · follow paused, scroll to bottom to resume"
		}
	}
	return s
}

// progressBar is a w-cell block bar, filled proportionally to done/total.
func progressBar(st styles, done, total, w int) string {
	if total <= 0 || w <= 0 {
		return ""
	}
	filled := min(done*w/total, w)
	return st.sel.Render(strings.Repeat("█", filled)) + st.faint.Render(strings.Repeat("░", w-filled))
}

// jobView renders the job pane with an adaptive tail: avail is the screen
// height left over for this pane; unknown height falls back to jobTailLines.
func (m model) jobView(avail int) string {
	if !m.hasJob() {
		return ""
	}
	if m.height > 0 && avail < 5 {
		return "" // not even rule+title+status+note fit, so drop the pane
	}
	title := m.wrap(m.st.title.Render("$ " + m.cur.display))
	status := m.wrap(m.jobStrip())
	tailN := jobTailLines
	if m.height > 0 {
		// rule, context note, trailing blank, plus however many rows the
		// title and status took after wrapping.
		tailN = avail - 3 - lipgloss.Height(title) - lipgloss.Height(status)
		if tailN < 0 {
			tailN = 0
		}
	}
	var b strings.Builder
	b.WriteString(m.ruleTitle(jobPaneTitle) + "\n")
	b.WriteString(title + "\n")
	b.WriteString(status + "\n")

	shown := m.cur.lines
	if len(shown) > tailN {
		shown = shown[len(shown)-tailN:]
	}
	for _, ln := range shown {
		// Truncate rather than wrap: tool output routinely runs past the
		// terminal, and every extra display row is a row tailN never budgeted
		// for. The pane already offers enter to scroll for the whole line.
		if m.width > 0 {
			ln = ansi.Truncate(ln, m.width, "")
		}
		b.WriteString(ln + "\n")
	}
	older := len(m.cur.lines) - len(shown) + m.cur.evicted
	if older > 0 || m.cur.dropped > 0 {
		var notes []string
		if older > 0 {
			notes = append(notes, fmt.Sprintf("… %d earlier lines, enter to scroll", older))
		}
		if m.cur.dropped > 0 {
			notes = append(notes, fmt.Sprintf("%d dropped (channel overflow)", m.cur.dropped))
		}
		b.WriteString(m.st.faint.Render("("+strings.Join(notes, " · ")+")") + "\n")
	}
	return b.String() + "\n"
}
