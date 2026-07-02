package ui

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// scheduleMsg asks Update to dispatch any newly-runnable probes for generation
// gen. A stale gen is ignored.
type scheduleMsg struct{ gen int }

// probeDoneMsg carries a finished probe's result. Accepted only when gen matches.
type probeDoneMsg struct {
	id  ProbeID
	gen int
	res ProbeResult
}

// pendingAction is a state change deferred until the active job's terminal event
// arrives, so Update never blocks waiting on it (that would deadlock — Update is
// the goroutine that consumes the event).
type pendingKind int

const (
	pendQuit pendingKind = iota
	pendRerun
	pendTool
)

type pendingAction struct {
	kind pendingKind
	tool Tool
}

const (
	maxJobLines  = 5000
	jobTailLines = 14 // main-screen tail fallback when the terminal height is unknown
)

// outLine is one captured output line tagged with its source stream. Lines are
// kept in arrival order — best-effort interleaving, since the kernel buffers
// stdout and stderr pipes independently.
type outLine struct {
	stream Stream
	text   string
}

type model struct {
	target *Target
	probes []Probe
	order  []ProbeID
	byID   map[ProbeID]Probe

	// results + started are owned exclusively by Update; probe goroutines get an
	// immutable snapshot, never the live map.
	results map[ProbeID]ProbeResult
	started map[ProbeID]bool

	selected int
	spinner  spinner.Model

	generation int
	// Generation context; cancel kills all in-flight probes and the active job on
	// rerun/quit. Kept alive after the chain completes so tools can run under it.
	ctx    context.Context
	cancel context.CancelFunc

	// Drill-down job state (Phase 2).
	tools      []Tool
	activeJob  *job
	pending    *pendingAction
	jobStatus  JobStatus
	jobToolKey string
	jobName    string
	jobDisplay string
	jobLines   []outLine
	jobDropped int64 // channel-overflow drops, reported by ToolDoneMsg
	jobEvicted int   // oldest lines evicted from the jobLines ring buffer
	jobStart   time.Time
	facts      []Fact

	// Output viewport (Enter). follow sticks to the tail while output arrives;
	// scrolling up turns it off, scrolling back to the bottom re-enables it.
	viewing bool
	follow  bool
	vp      viewport.Model

	toolbox bool // --toolbox: chain deferred until 'r'

	width, height int
}

var (
	passStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	failStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	skipStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	faintStyle = lipgloss.NewStyle().Faint(true)
	titleStyle = lipgloss.NewStyle().Bold(true)
	selStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
)

var statusGlyphs = map[Status]rune{StatusPass: '✓', StatusFail: '✗', StatusSkip: '⊘', StatusNA: '–'}

func newModel(t *Target) model {
	probes := buildProbes(t)
	order := make([]ProbeID, len(probes))
	byID := make(map[ProbeID]Probe, len(probes))
	for i, p := range probes {
		order[i] = p.ID
		byID[p.ID] = p
	}
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return model{
		target:    t,
		probes:    probes,
		order:     order,
		byID:      byID,
		results:   map[ProbeID]ProbeResult{},
		started:   map[ProbeID]bool{},
		tools:     toolsFor(t, runtime.GOOS),
		jobStatus: JobQueued,
		spinner:   sp,
		width:     100,
	}
}

func (m model) Init() tea.Cmd {
	if m.toolbox {
		return m.spinner.Tick // chain deferred until 'r'; tick drives the job timer
	}
	return tea.Batch(m.spinner.Tick, func() tea.Msg { return scheduleMsg{gen: 0} })
}

// chainRan reports whether the diagnostic chain has been started this session.
func (m model) chainRan() bool { return len(m.started) > 0 }

func (m model) allDone() bool { return len(m.results) == len(m.probes) }

// spinnerActive reports whether the spinner tick chain should keep running:
// while probes are pending or a drill-down job is live.
func (m model) spinnerActive() bool { return !m.allDone() || m.activeJob != nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if m.viewing {
			m.refreshViewport()
		}
		return m, nil

	case tea.KeyMsg:
		if m.viewing {
			return m.handleViewKey(msg)
		}
		return m.handleKey(msg)

	case scheduleMsg:
		if msg.gen != m.generation {
			return m, nil
		}
		if m.ctx == nil {
			m.ctx, m.cancel = context.WithCancel(context.Background())
		}
		return m, tea.Batch(m.scheduleStep()...)

	case probeDoneMsg:
		if msg.gen != m.generation {
			return m, nil // stale rerun
		}
		res := msg.res
		res.ID = msg.id
		m.results[msg.id] = res
		return m, tea.Batch(m.scheduleStep()...)

	case ToolOutputMsg:
		if m.activeJob == nil || msg.Generation != m.generation || msg.JobID != m.activeJob.id {
			return m, nil // stale job message
		}
		m.appendJobLine(msg.Stream, msg.Line)
		if m.viewing {
			m.refreshViewport()
		}
		return m, waitForMsg(m.activeJob.ch)

	case ToolDoneMsg:
		if m.activeJob == nil || msg.Generation != m.generation || msg.JobID != m.activeJob.id {
			return m, nil
		}
		m.jobStatus, m.jobDropped, m.activeJob = msg.Status, msg.Dropped, nil
		m.facts = extractFacts(m.jobToolKey, runtime.GOOS, m.stdoutLines())
		if m.pending != nil {
			p := m.pending
			m.pending = nil
			return m.runPending(p)
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		if !m.spinnerActive() {
			return m, nil
		}
		return m, cmd
	}

	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		if m.activeJob != nil {
			m.activeJob.cancel() // non-blocking; quit on the terminal event
			m.pending = &pendingAction{kind: pendQuit}
			return m, nil
		}
		m.clearCancel()
		return m, tea.Quit
	case "r":
		if m.activeJob != nil {
			m.activeJob.cancel()
			m.pending = &pendingAction{kind: pendRerun}
			return m, nil
		}
		return m, m.doRerun()
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
		return m, nil
	case "down", "j":
		if m.selected < len(m.order)-1 {
			m.selected++
		}
		return m, nil
	case "enter":
		if len(m.jobLines) == 0 {
			return m, nil
		}
		m.viewing, m.follow = true, true
		m.vp = viewport.New(m.vpWidth(), m.vpHeight())
		m.refreshViewport()
		return m, nil
	}
	// Tool hotkeys (contextual toolbox).
	for _, tool := range m.tools {
		if msg.String() == tool.Key {
			if m.activeJob != nil {
				m.activeJob.cancel()
				m.pending = &pendingAction{kind: pendTool, tool: tool} // last write wins
				return m, nil
			}
			return m, m.launchTool(tool)
		}
	}
	return m, nil
}

// handleViewKey handles keys while the output viewport is open. Everything not
// handled here scrolls the viewport; leaving the bottom disables follow mode.
func (m model) handleViewKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		m.viewing = false
		return m, nil
	case "q", "ctrl+c":
		return m.handleKey(msg) // quit path, incl. deferred quit under an active job
	}
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	m.follow = m.vp.AtBottom()
	return m, cmd
}

func (m *model) runPending(p *pendingAction) (tea.Model, tea.Cmd) {
	switch p.kind {
	case pendQuit:
		m.clearCancel()
		return m, tea.Quit
	case pendRerun:
		return m, m.doRerun()
	case pendTool:
		return m, m.launchTool(p.tool)
	}
	return m, nil
}

// doRerun bumps the generation (invalidating outstanding probe/job messages),
// clears run + job state, resets the context, and reschedules from the root.
func (m *model) doRerun() tea.Cmd {
	wasTicking := m.spinnerActive()
	m.clearCancel()
	m.ctx = nil
	m.generation++
	m.results = map[ProbeID]ProbeResult{}
	m.started = map[ProbeID]bool{}
	m.activeJob, m.pending = nil, nil
	m.jobStatus, m.jobLines, m.facts, m.jobDropped, m.jobEvicted = JobQueued, nil, nil, 0, 0
	if m.viewing {
		m.refreshViewport()
	}
	gen := m.generation
	cmds := []tea.Cmd{func() tea.Msg { return scheduleMsg{gen: gen} }}
	if !wasTicking {
		cmds = append(cmds, m.spinner.Tick)
	}
	return tea.Batch(cmds...)
}

func (m *model) launchTool(tool Tool) tea.Cmd {
	if !tool.Available() {
		m.jobName, m.jobToolKey, m.jobStatus = tool.Name, tool.Key, JobFailed
		m.jobLines, m.facts = []outLine{{StreamStderr, tool.Bin + " not found — install it"}}, nil
		m.jobDisplay = tool.Name
		return nil
	}
	wasTicking := m.spinnerActive()
	args, env, display := tool.Build(m.target)
	id := fmt.Sprintf("%s-%d-%d", tool.Key, m.generation, time.Now().UnixNano())
	// Toolbox mode: a tool can launch before the first 'r' creates the
	// generation context — initialize it lazily, exactly as scheduleMsg does.
	if m.ctx == nil {
		m.ctx, m.cancel = context.WithCancel(context.Background())
	}
	j, cmd, err := startTool(m.ctx, m.generation, id, tool.Bin, args, env, tool.Timeout)
	if err != nil {
		m.jobName, m.jobToolKey, m.jobStatus = tool.Name, tool.Key, JobFailed
		m.jobLines, m.jobDisplay = []outLine{{StreamStderr, sanitize(err.Error())}}, display
		return nil
	}
	m.activeJob, m.jobStatus = j, JobRunning
	m.jobLines, m.facts, m.jobDropped, m.jobEvicted = nil, nil, 0, 0
	if m.viewing {
		m.refreshViewport()
	}
	m.jobName, m.jobToolKey, m.jobDisplay, m.jobStart = tool.Name, tool.Key, display, time.Now()
	if !wasTicking {
		return tea.Batch(cmd, m.spinner.Tick)
	}
	return cmd
}

// scheduleStep marks newly-skippable probes (a dependency failed) and returns run
// commands for newly-runnable probes, repeating until no further progress so
// skips propagate through dependents in one pass. Mutates results/started.
func (m *model) scheduleStep() []tea.Cmd {
	var cmds []tea.Cmd
	for progress := true; progress; {
		progress = false
		for _, p := range m.probes {
			if m.started[p.ID] {
				continue
			}
			ready, blocked := depsState(p.Deps, m.results)
			if !ready {
				continue
			}
			m.started[p.ID] = true
			progress = true
			if blocked {
				m.results[p.ID] = skipResult(p)
				continue
			}
			cmds = append(cmds, m.runProbe(p))
		}
	}
	return cmds
}

// depsState reports whether all deps completed (ready) and whether any completed
// dep blocks this probe. A dep blocks on Fail or Skip (no output); a Pass or an
// applicable NotApplicable (which still produced output) satisfies.
func depsState(deps []ProbeID, res map[ProbeID]ProbeResult) (ready, blocked bool) {
	for _, d := range deps {
		r, ok := res[d]
		if !ok {
			return false, false
		}
		if r.Status == StatusFail || r.Status == StatusSkip {
			blocked = true
		}
	}
	return true, blocked
}

func skipResult(p Probe) ProbeResult {
	return ProbeResult{ID: p.ID, Status: StatusSkip, Detail: "skipped — a prerequisite failed"}
}

// runProbe builds the tea.Cmd for a probe, capturing the generation, the parent
// context, and an immutable snapshot of just its dependency outputs.
func (m *model) runProbe(p Probe) tea.Cmd {
	gen, parent, run, id := m.generation, m.ctx, p.Run, p.ID
	snap := snapshot(m.results, p.Deps)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(parent, probeTimeout)
		defer cancel()
		return probeDoneMsg{id: id, gen: gen, res: run(ctx, snap)}
	}
}

// snapshot copies just the requested dependency results into a fresh map so the
// probe goroutine never touches the live, Update-owned map.
func snapshot(res map[ProbeID]ProbeResult, deps []ProbeID) map[ProbeID]ProbeResult {
	out := make(map[ProbeID]ProbeResult, len(deps))
	for _, d := range deps {
		if r, ok := res[d]; ok {
			out[d] = r
		}
	}
	return out
}

// appendJobLine appends one output line to the ring buffer, counting evictions
// separately from channel-overflow drops (jobDropped) so the viewport context
// line stays accurate.
func (m *model) appendJobLine(s Stream, text string) {
	m.jobLines = append(m.jobLines, outLine{s, text})
	if n := len(m.jobLines) - maxJobLines; n > 0 {
		m.jobEvicted += n
		m.jobLines = m.jobLines[n:]
	}
}

// stdoutLines returns just the stdout side of the stream, for fact extraction.
func (m model) stdoutLines() []string {
	var out []string
	for _, ln := range m.jobLines {
		if ln.stream == StreamStdout {
			out = append(out, ln.text)
		}
	}
	return out
}

// jobContent renders the interleaved stream wrapped to w columns, stderr faint
// with a "! " marker. Line numbers in the context line refer to these wrapped
// display lines.
func (m model) jobContent(w int) string {
	if w <= 0 {
		w = 80
	}
	var b strings.Builder
	for i, ln := range m.jobLines {
		if i > 0 {
			b.WriteByte('\n')
		}
		if ln.stream == StreamStderr {
			b.WriteString(faintStyle.Render("! " + ln.text))
		} else {
			b.WriteString(ln.text)
		}
	}
	return lipgloss.NewStyle().Width(w).Render(b.String())
}

// refreshViewport resizes and re-renders the open viewport, sticking to the
// tail in follow mode.
// ponytail: full content rebuild per line while open; fine at the 5000-line
// cap, switch to incremental append if it ever lags.
func (m *model) refreshViewport() {
	m.vp.Width, m.vp.Height = m.vpWidth(), m.vpHeight()
	m.vp.SetContent(m.jobContent(m.vpWidth()))
	if m.follow {
		m.vp.GotoBottom()
	}
}

func (m model) vpWidth() int {
	if m.width > 0 {
		return m.width
	}
	return 80
}

func (m model) vpHeight() int {
	if m.height <= 0 {
		return 20
	}
	h := m.height - 4 // header + status above, context + help below
	if h < 3 {
		h = 3
	}
	return h
}

func (m *model) clearCancel() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}

func statusGlyph(status Status) rune {
	if glyph, ok := statusGlyphs[status]; ok {
		return glyph
	}
	return '?'
}

func (m model) glyph(id ProbeID) string {
	r, ok := m.results[id]
	if !ok {
		return m.spinner.View()
	}
	glyph := string(statusGlyph(r.Status))
	switch r.Status {
	case StatusPass:
		return passStyle.Render(glyph)
	case StatusFail:
		return failStyle.Render(glyph)
	case StatusSkip:
		return skipStyle.Render(glyph)
	case StatusNA:
		return faintStyle.Render(glyph)
	}
	return "?"
}

// networkLine is the connected-network label shown under the title: the Wi-Fi
// SSID when wireless, else the wired interface name. Empty until the interface
// probe has passed.
func (m model) networkLine() string {
	r, ok := m.results[pIface]
	if !ok || r.Status != StatusPass {
		return ""
	}
	if r.Network != "" {
		return "Wi-Fi: " + r.Network
	}
	if r.Iface != "" {
		return "Wired: " + r.Iface
	}
	return ""
}

func (m model) View() string {
	if m.viewing {
		return m.outputView()
	}
	leftW := 40
	rightW := m.width - leftW - 3
	if rightW < 36 {
		rightW = 36
	}

	deferred := m.toolbox && !m.chainRan()

	var left strings.Builder
	left.WriteString(titleStyle.Render("Network Doctor") + "\n")
	if n := m.networkLine(); n != "" {
		left.WriteString(faintStyle.Render(n) + "\n")
	}
	left.WriteString("\n")
	if deferred {
		left.WriteString(faintStyle.Render("Toolbox mode.\nChain not run.\nPress r to run checks.") + "\n")
	} else {
		for i, id := range m.order {
			name := m.byID[id].Name
			if i == m.selected {
				name = selStyle.Render("› " + name)
			} else {
				name = "  " + name
			}
			left.WriteString(m.glyph(id) + " " + name + "\n")
		}
	}

	var right strings.Builder
	right.WriteString(titleStyle.Render("Diagnosis") + "\n\n")
	if deferred {
		right.WriteString("Toolbox mode — press r to run the diagnostic chain, or pick a tool below.\n")
	} else {
		if summary := diagnose(m.target, m.order, m.results); summary != "" {
			right.WriteString(summary + "\n\n")
		}
		id := m.order[m.selected]
		right.WriteString(titleStyle.Render(m.byID[id].Name) + "\n")
		if r, ok := m.results[id]; ok {
			right.WriteString(r.Status.String() + " — " + r.Detail + "\n")
			if r.Status == StatusFail && r.Fix != "" {
				right.WriteString(faintStyle.Render("Fix: "+r.Fix) + "\n")
			}
			if r.Source != nil {
				right.WriteString(faintStyle.Render("src "+r.Source.String()+" "+r.Iface) + "\n")
			}
			for _, a := range r.Attempts {
				st := "ok"
				if a.Err != nil {
					st = sanitize(a.Err.Error())
				}
				right.WriteString(faintStyle.Render(fmt.Sprintf("  %s %dms %s", a.IP, a.Dur.Milliseconds(), st)) + "\n")
			}
		} else {
			right.WriteString(faintStyle.Render("pending…") + "\n")
		}
	}

	leftBox := lipgloss.NewStyle().Width(leftW).Render(left.String())
	rightBox := lipgloss.NewStyle().Width(rightW).Render(right.String())
	body := lipgloss.JoinHorizontal(lipgloss.Top, leftBox, rightBox)

	help := faintStyle.Render("↑/↓ select · r rerun · q quit")
	toolbox := m.toolboxView()
	// Adaptive tail: the job pane gets whatever height the rest doesn't use.
	used := strings.Count(body, "\n") + strings.Count(toolbox, "\n") + strings.Count(help, "\n") + 2
	return body + "\n" + toolbox + "\n" + m.jobView(m.height-used) + help + "\n"
}

// outputView is the full-screen scrollable output viewer (Enter).
func (m model) outputView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("$ "+m.jobDisplay) + "\n")
	status := m.jobName + " — " + m.jobStatus.String()
	if m.activeJob != nil {
		status += fmt.Sprintf(" (%.0fs)", time.Since(m.jobStart).Seconds())
	}
	b.WriteString(faintStyle.Render(status) + "\n")
	b.WriteString(m.vp.View() + "\n")
	b.WriteString(faintStyle.Render(m.vpContext()) + "\n")
	b.WriteString(faintStyle.Render("↑/↓ scroll · esc back · q quit"))
	return b.String()
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
	if m.jobEvicted > 0 {
		s += fmt.Sprintf(" · %d older lines discarded", m.jobEvicted)
	}
	if m.jobDropped > 0 {
		s += fmt.Sprintf(" · %d dropped (channel overflow)", m.jobDropped)
	}
	if m.activeJob != nil {
		if m.follow {
			s += " · following"
		} else {
			s += " · follow paused — scroll to bottom to resume"
		}
	}
	return s
}

func (m model) toolboxView() string {
	if len(m.tools) == 0 {
		return faintStyle.Render("Tools: (target-dependent — pass a host)") + "\n"
	}
	parts := make([]string, len(m.tools))
	for i, t := range m.tools {
		label := "[" + t.Key + "] " + t.Name
		if !t.Available() {
			label = faintStyle.Render(label + " (missing)")
		}
		parts[i] = label
	}
	return "Tools: " + strings.Join(parts, "  ") + "\n"
}

// jobView renders the job pane with an adaptive tail: avail is the screen
// height left over for this pane; unknown height falls back to jobTailLines.
func (m model) jobView(avail int) string {
	if m.activeJob == nil && m.jobStatus == JobQueued {
		return ""
	}
	tailN := jobTailLines
	if m.height > 0 {
		overhead := 4 // title, status, context note, trailing blank
		if len(m.facts) > 0 {
			overhead += 1 + len(m.facts)
		}
		if tailN = avail - overhead; tailN < 3 {
			tailN = 3
		}
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("$ "+m.jobDisplay) + "\n")
	status := m.jobName + " — " + m.jobStatus.String()
	if m.activeJob != nil {
		status += fmt.Sprintf(" (%.0fs)", time.Since(m.jobStart).Seconds())
	}
	b.WriteString(faintStyle.Render(status) + "\n")

	shown := tail(m.jobLines, tailN)
	for _, ln := range shown {
		if ln.stream == StreamStderr {
			b.WriteString(faintStyle.Render("! "+ln.text) + "\n")
		} else {
			b.WriteString(ln.text + "\n")
		}
	}
	if len(m.facts) > 0 {
		b.WriteString(titleStyle.Render("Extracted:") + "\n")
		for _, f := range m.facts {
			b.WriteString("  " + f.Key + ": " + f.Value + "\n")
		}
	}
	older := len(m.jobLines) - len(shown) + m.jobEvicted
	if older > 0 || m.jobDropped > 0 {
		var notes []string
		if older > 0 {
			notes = append(notes, fmt.Sprintf("… %d earlier lines — enter to scroll", older))
		}
		if m.jobDropped > 0 {
			notes = append(notes, fmt.Sprintf("%d dropped (channel overflow)", m.jobDropped))
		}
		b.WriteString(faintStyle.Render("("+strings.Join(notes, " · ")+")") + "\n")
	}
	return b.String() + "\n"
}

func tail[T any](lines []T, n int) []T {
	if len(lines) > n {
		return lines[len(lines)-n:]
	}
	return lines
}
