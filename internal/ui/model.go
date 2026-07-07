package ui

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mplaczek99/network-doctor/internal/diagnostic"
	"github.com/mplaczek99/network-doctor/internal/textsafe"
)

// scheduleMsg asks Update to dispatch any newly-runnable probes for generation
// gen. A stale gen is ignored.
type scheduleMsg struct{ gen int }

// probeDoneMsg carries a finished probe's result. Accepted only when gen matches.
type probeDoneMsg struct {
	id  diagnostic.ProbeID
	gen int
	res diagnostic.ProbeResult
}

// pendingAction is a state change deferred until the active job's terminal event
// arrives, so Update never blocks waiting on it (that would deadlock — Update is
// the goroutine that consumes the event).
type pendingKind int

const (
	pendQuit pendingKind = iota
	pendRerun
	pendTool
	pendFix
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
	target *diagnostic.Target
	probes []diagnostic.Probe

	// results + started are owned exclusively by Update; probe goroutines get an
	// immutable snapshot, never the live map.
	results map[diagnostic.ProbeID]diagnostic.ProbeResult
	started map[diagnostic.ProbeID]bool

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
	jobDur     time.Duration // total runtime of the last finished job
	facts      []Fact

	// Output viewport (Enter). follow sticks to the tail while output arrives;
	// scrolling up turns it off, scrolling back to the bottom re-enables it.
	viewing bool
	follow  bool
	vp      viewport.Model

	// Rerun prompt (r): an editable network-doctor command line. Enter parses
	// and reruns; esc closes without touching the current run.
	entering bool
	input    textinput.Model
	inputErr string

	// Confirm gate: a tool marked Confirm (nmap) is held here after its hotkey,
	// showing the exact command until 'y' runs it or any other key cancels.
	confirmTool *Tool

	// Auto-fix (f): fixing marks the active job as a fix command — when its
	// terminal event arrives the chain reruns to verify the fix. verifying
	// labels that rerun's verdict in the banner.
	fixing    bool
	verifying bool

	toolbox bool // --toolbox: chain deferred until 'r'

	// notice is one-line feedback from the last export (y/w): saved path,
	// copy confirmation, or the error. Sticky until the next export or rerun.
	notice   string
	noticeOK bool

	width, height int
}

// The palette sticks to the 16 ANSI colors so it follows the user's terminal
// theme, and every status is also carried by a glyph or word — color is never
// the only signal (NO_COLOR and monochrome terminals stay usable).
var (
	accentColor = lipgloss.Color("6")
	borderColor = lipgloss.Color("8")

	passStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	failStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	skipStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	warnStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)
	faintStyle      = lipgloss.NewStyle().Faint(true)
	titleStyle      = lipgloss.NewStyle().Bold(true)
	selStyle        = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	keyStyle        = lipgloss.NewStyle().Foreground(accentColor)
	panelStyle      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(borderColor).Padding(0, 1)
	focusPanelStyle = panelStyle.BorderForeground(accentColor) // input focus lives here
	panelTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
)

func newModel(t *diagnostic.Target) model {
	probes := diagnostic.BuildProbes(t)
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	return model{
		target:    t,
		probes:    probes,
		results:   map[diagnostic.ProbeID]diagnostic.ProbeResult{},
		started:   map[diagnostic.ProbeID]bool{},
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

// reportReady reports whether there is a finished report to export: every
// check has a result and a tool command actually ran to the end (done or
// failed — not never-run, still streaming, or canceled).
func (m model) reportReady() bool {
	return m.allDone() && m.activeJob == nil &&
		(m.jobStatus == JobDone || m.jobStatus == JobFailed)
}

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
		// Runes read from stdin in one batch arrive as a single KeyMsg
		// ("jjj"), which matches no binding; replay them one key at a time.
		if msg.Type == tea.KeyRunes && !msg.Paste && len(msg.Runes) > 1 {
			var cmds []tea.Cmd
			cur := tea.Model(m)
			for _, r := range msg.Runes {
				var cmd tea.Cmd
				cur, cmd = cur.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
				cmds = append(cmds, cmd)
			}
			return cur, tea.Batch(cmds...)
		}
		if m.confirmTool != nil {
			return m.handleConfirmKey(msg)
		}
		if m.entering {
			return m.handlePromptKey(msg)
		}
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
		if m.allDone() {
			diagnostic.DowngradeEgress(m.results)
		}
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
		m.jobDur = time.Since(m.jobStart)
		m.facts = extractFacts(m.jobToolKey, runtime.GOOS, m.stdoutLines())
		if m.pending != nil {
			p := m.pending
			m.pending, m.fixing = nil, false // a deferred action overrides the fix flow
			return m.runPending(p)
		}
		if m.fixing {
			m.fixing = false
			cmd := m.doRerun() // verification rerun — the fix's real verdict
			m.verifying = true
			return m, cmd
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
		// Open the rerun prompt; an active job keeps streaming until Enter commits.
		m.entering, m.inputErr = true, ""
		ti := textinput.New()
		ti.Prompt = "network-doctor "
		ti.PromptStyle = keyStyle
		ti.Placeholder = "host[:port] or http(s)://host — empty checks the connection"
		if m.target != nil {
			ti.SetValue(m.target.Raw)
		}
		ti.Focus()
		ti.CursorEnd()
		m.input = ti
		return m, textinput.Blink
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
		return m, nil
	case "down", "j":
		if m.selected < len(m.probes)-1 {
			m.selected++
		}
		return m, nil
	case "enter":
		if m.activeJob == nil && m.jobStatus == JobQueued {
			return m, nil // no job has run; nothing to view
		}
		m.viewing, m.follow = true, true
		m.vp = viewport.New(m.vpWidth(), m.vpHeight())
		m.refreshViewport()
		return m, nil
	case "y", "w":
		if !m.reportReady() {
			return m, nil
		}
		m.notice, m.noticeOK = exportReport(m.report(), msg.String() == "w")
		return m, nil
	case "f":
		fix := m.fixTool()
		if fix == nil || m.fixing {
			return m, nil // no fix, or the fix is already running
		}
		if m.activeJob != nil {
			m.activeJob.cancel()
			m.pending = &pendingAction{kind: pendFix, tool: *fix}
			return m, nil
		}
		cmd := m.launchTool(*fix)
		m.fixing = m.activeJob != nil // only a job that actually started can verify
		return m, cmd
	}
	// Tool hotkeys (contextual toolbox).
	for _, tool := range m.tools {
		if msg.String() == tool.Key {
			if tool.Confirm {
				t := tool // hold for the confirm gate; run happens on 'y'
				m.confirmTool = &t
				return m, nil
			}
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

// handleConfirmKey handles keys while an advanced tool's command is shown: 'y'
// runs it (deferred if a job is still live), ctrl+c quits, and any other key —
// including esc — cancels without running the scan.
func (m model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	tool := *m.confirmTool
	m.confirmTool = nil
	switch msg.String() {
	case "y":
		if m.activeJob != nil {
			m.activeJob.cancel()
			m.pending = &pendingAction{kind: pendTool, tool: tool}
			return m, nil
		}
		return m, m.launchTool(tool)
	case "ctrl+c":
		return m.handleKey(msg) // quit path, incl. deferred quit under an active job
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

// handlePromptKey handles keys while the rerun prompt is open. Enter parses
// the line and reruns (deferred if a job is still running), esc closes, and
// everything else edits the input.
func (m model) handlePromptKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.entering = false
		return m, nil
	case "ctrl+c":
		m.entering = false
		return m.handleKey(msg) // quit path, incl. deferred quit under an active job
	case "enter":
		t, err := parseRunArgs(m.input.Value())
		if err != nil {
			m.inputErr = err.Error()
			return m, nil
		}
		m.entering = false
		m.applyTarget(t)
		if m.activeJob != nil {
			m.activeJob.cancel()
			m.pending = &pendingAction{kind: pendRerun}
			return m, nil
		}
		return m, m.doRerun()
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.inputErr = ""
	return m, cmd
}

// parseRunArgs parses the rerun prompt as a network-doctor command line: an
// optional leading "network-doctor", then at most one target argument. An
// empty line means a general, targetless run.
func parseRunArgs(line string) (*diagnostic.Target, error) {
	fields := strings.Fields(line)
	if len(fields) > 0 && fields[0] == "network-doctor" {
		fields = fields[1:]
	}
	switch {
	case len(fields) == 0:
		return nil, nil
	case len(fields) > 1:
		return nil, errors.New("one target only, e.g. example.com:443")
	case strings.HasPrefix(fields[0], "-"):
		return nil, errors.New("flags aren't supported here — enter a target")
	}
	return diagnostic.ParseTarget(fields[0])
}

// applyTarget swaps the run target and rebuilds everything derived from it.
func (m *model) applyTarget(t *diagnostic.Target) {
	m.target = t
	m.probes = diagnostic.BuildProbes(t)
	m.tools = toolsFor(t, runtime.GOOS)
	m.selected = 0
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
	case pendFix:
		cmd := m.launchTool(p.tool)
		m.fixing = m.activeJob != nil
		return m, cmd
	}
	return m, nil
}

// fixTool returns the auto-fix for the first failed probe, or nil when the run
// isn't finished, nothing failed, or no safe local fix exists.
func (m model) fixTool() *Tool {
	if !m.allDone() {
		return nil
	}
	for _, p := range m.probes {
		if m.results[p.ID].Status == diagnostic.StatusFail {
			return fixFor(p.ID, runtime.GOOS)
		}
	}
	return nil
}

// doRerun bumps the generation (invalidating outstanding probe/job messages),
// clears run + job state, resets the context, and reschedules from the root.
func (m *model) doRerun() tea.Cmd {
	wasTicking := m.spinnerActive()
	m.clearCancel()
	m.ctx = nil
	m.generation++
	m.results = map[diagnostic.ProbeID]diagnostic.ProbeResult{}
	m.started = map[diagnostic.ProbeID]bool{}
	m.activeJob, m.pending = nil, nil
	m.fixing, m.verifying = false, false
	m.notice = ""
	m.jobStatus, m.jobLines, m.facts, m.jobDropped, m.jobEvicted = JobQueued, nil, nil, 0, 0
	m.jobDur = 0
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
		m.jobLines, m.facts, m.jobDur = []outLine{{StreamStderr, tool.Bin + " not found — install it"}}, nil, 0
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
		m.jobLines, m.jobDisplay, m.jobDur = []outLine{{StreamStderr, textsafe.Clean(err.Error())}}, display, 0
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
// dep blocks this probe. A dep blocks on Fail or Skip (no output); a Pass, a
// Warn (degraded but produced output), or an applicable NotApplicable satisfies.
func depsState(deps []diagnostic.ProbeID, res map[diagnostic.ProbeID]diagnostic.ProbeResult) (ready, blocked bool) {
	for _, d := range deps {
		r, ok := res[d]
		if !ok {
			return false, false
		}
		if r.Status == diagnostic.StatusFail || r.Status == diagnostic.StatusSkip {
			blocked = true
		}
	}
	return true, blocked
}

func skipResult(p diagnostic.Probe) diagnostic.ProbeResult {
	return diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusSkip, Detail: "skipped — a prerequisite failed"}
}

// runProbe builds the tea.Cmd for a probe, capturing the generation, the parent
// context, and an immutable snapshot of just its dependency outputs.
func (m *model) runProbe(p diagnostic.Probe) tea.Cmd {
	gen, parent, run, id := m.generation, m.ctx, p.Run, p.ID
	snap := snapshot(m.results, p.Deps)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(parent, diagnostic.ProbeTimeout)
		defer cancel()
		return probeDoneMsg{id: id, gen: gen, res: run(ctx, snap)}
	}
}

// snapshot copies just the requested dependency results into a fresh map so the
// probe goroutine never touches the live, Update-owned map.
func snapshot(res map[diagnostic.ProbeID]diagnostic.ProbeResult, deps []diagnostic.ProbeID) map[diagnostic.ProbeID]diagnostic.ProbeResult {
	out := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(deps))
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
	if len(m.jobLines) == 0 {
		return lipgloss.NewStyle().Width(w).Render(faintStyle.Render("(no output yet)"))
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

func (m model) glyph(id diagnostic.ProbeID) string {
	r, ok := m.results[id]
	if !ok {
		return m.spinner.View()
	}
	switch r.Status {
	case diagnostic.StatusPass:
		return passStyle.Render("✓")
	case diagnostic.StatusWarn:
		return warnStyle.Render("!")
	case diagnostic.StatusFail:
		return failStyle.Render("✗")
	case diagnostic.StatusSkip:
		return skipStyle.Render("⊘")
	case diagnostic.StatusNA:
		return faintStyle.Render("–")
	}
	return "?"
}

// networkLine is the connected-network label shown under the title: the Wi-Fi
// SSID when wireless, else the wired interface name. Empty until the interface
// probe has passed.
func (m model) networkLine() string {
	r, ok := m.results[diagnostic.ProbeIface]
	if !ok || r.Status != diagnostic.StatusPass {
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
	deferred := m.toolbox && !m.chainRan()

	header := m.headerView()
	body := m.bodyView(deferred)
	help := m.helpView(deferred)
	if m.entering {
		help = m.promptView()
	}
	if m.confirmTool != nil {
		help = m.confirmView()
	}
	toolbox := m.toolboxView()
	top := header + "\n" + m.banner() + "\n\n"
	// Adaptive tail: the job pane gets whatever rows the rest doesn't use.
	// avail is a budget in newlines: jobView's output must add at most avail
	// of them, or the view exceeds the terminal and the renderer cuts the top.
	fixed := top + body + "\n" + toolbox + "\n"
	tail := help + "\n"
	avail := m.height - strings.Count(fixed, "\n") - strings.Count(tail, "\n") - 1
	return fixed + m.jobView(avail) + tail
}

// headerView is the one-line masthead: app name, target, connected network.
func (m model) headerView() string {
	h := selStyle.Render("◆ ") + titleStyle.Render("Network Doctor")
	if m.target != nil {
		h += faintStyle.Render(fmt.Sprintf("  %s:%d", m.target.Host, m.target.Port))
	}
	if n := m.networkLine(); n != "" {
		h += faintStyle.Render("  ·  " + n)
	}
	return h
}

// bodyView renders the Checks and Details panels side by side, stacking them
// vertically when the terminal is too narrow for two columns.
func (m model) bodyView(deferred bool) string {
	var left strings.Builder
	left.WriteString(panelTitleStyle.Render("Checks") + "\n")
	for i, probe := range m.probes {
		if deferred {
			left.WriteString(faintStyle.Render("  · "+probe.Name) + "\n")
			continue
		}
		marker, name := "  ", probe.Name
		if i == m.selected {
			marker, name = selStyle.Render("› "), selStyle.Render(name)
		}
		left.WriteString(marker + m.glyph(probe.ID) + " " + name + "\n")
	}

	var right strings.Builder
	if deferred {
		right.WriteString(panelTitleStyle.Render("Details") + "\n")
		right.WriteString(faintStyle.Render("Nothing to show yet — the checks haven't run.") + "\n")
	} else {
		probe := m.probes[m.selected]
		right.WriteString(panelTitleStyle.Render("Details — "+probe.Name) + "\n")
		if r, ok := m.results[probe.ID]; ok {
			right.WriteString(styledProbeStatus(r.Status) + " — " + r.Detail + "\n")
			if (r.Status == diagnostic.StatusFail || r.Status == diagnostic.StatusWarn) && r.Fix != "" {
				right.WriteString(skipStyle.Render("Fix: ") + r.Fix + "\n")
			}
			if r.Source != nil {
				right.WriteString(faintStyle.Render("src "+r.Source.String()+" "+r.Iface) + "\n")
			}
			for _, a := range r.Attempts {
				st := "ok"
				if a.Err != nil {
					st = textsafe.Clean(a.Err.Error())
				}
				right.WriteString(faintStyle.Render(fmt.Sprintf("  %s %dms %s", a.IP, a.Dur.Milliseconds(), st)) + "\n")
			}
		} else {
			right.WriteString(m.spinner.View() + faintStyle.Render(" checking…") + "\n")
		}
	}

	leftStr := strings.TrimRight(left.String(), "\n")
	rightStr := strings.TrimRight(right.String(), "\n")

	if m.width < 80 { // too narrow for two columns — stack
		w := max(m.width-2, 24)
		return lipgloss.JoinVertical(lipgloss.Left,
			panelStyle.Width(w).Render(leftStr),
			panelStyle.Width(w).Render(rightStr))
	}
	leftW := 38
	rightW := max(m.width-leftW-5, 36)
	h := max(lipgloss.Height(leftStr), lipgloss.Height(rightStr))
	return lipgloss.JoinHorizontal(lipgloss.Top,
		panelStyle.Width(leftW).Height(h).Render(leftStr),
		" ",
		panelStyle.Width(rightW).Height(h).Render(rightStr))
}

// joinChips joins styled chips with sep, wrapping to width only at chip
// boundaries so a "[k] label" pair is never split mid-word.
func joinChips(width int, sep string, chips []string) string {
	if width <= 0 {
		width = 80
	}
	var lines []string
	cur := ""
	for _, c := range chips {
		switch {
		case cur == "":
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

// helpKeys renders key/description pairs as a dim help bar with the keys
// highlighted, e.g. "r restart  ·  q quit", wrapped at pair boundaries.
func helpKeys(width int, kv ...string) string {
	parts := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, keyStyle.Render(kv[i])+" "+faintStyle.Render(kv[i+1]))
	}
	return joinChips(width, faintStyle.Render("  ·  "), parts)
}

// confirmView replaces the help bar with the pending advanced tool's exact
// command and a run/cancel gate, so the scan is always shown before it runs.
func (m model) confirmView() string {
	_, _, display := m.confirmTool.Build(m.target)
	body := panelTitleStyle.Render("Run "+m.confirmTool.Name+"?") + "\n" +
		faintStyle.Render("Actively scans "+m.target.Host+" — may trip its intrusion detection.") + "\n" +
		"$ " + display
	w := max(min(m.width-2, 76), 24)
	return focusPanelStyle.Width(w).Render(body) + "\n" + helpKeys(m.width, "y", "run", "any other key", "cancel")
}

// promptView is the rerun prompt panel, shown in place of the help bar.
func (m model) promptView() string {
	body := panelTitleStyle.Render("Run again") + "\n" + m.input.View()
	if m.inputErr != "" {
		body += "\n" + failStyle.Render("✗ "+m.inputErr)
	}
	w := max(min(m.width-2, 76), 24)
	return focusPanelStyle.Width(w).Render(body) + "\n" + helpKeys(m.width, "enter", "run", "esc", "back")
}

func (m model) helpView(deferred bool) string {
	// Enter opens the output viewer whenever a job pane exists (same condition
	// as jobView), so the hint tracks exactly when the key does something.
	hasJob := m.activeJob != nil || m.jobStatus != JobQueued
	if deferred {
		kv := []string{"r", "run the checks"}
		if len(m.tools) > 0 {
			kv = append(kv, "letter", "runs that tool")
		}
		if hasJob {
			kv = append(kv, "enter", "full output")
		}
		return helpKeys(m.width, append(kv, "q", "quit")...)
	}
	kv := []string{"↑/↓", "pick a check"}
	if hasJob {
		kv = append(kv, "enter", "full output")
	}
	if m.fixTool() != nil && !m.fixing {
		kv = append(kv, "f", "try a fix")
	}
	if m.reportReady() {
		kv = append(kv, "y", "copy report", "w", "save report")
	}
	kv = append(kv, "r", "restart", "q", "quit")
	help := helpKeys(m.width, kv...)
	if m.notice != "" {
		n := failStyle.Render("✗ " + m.notice)
		if m.noticeOK {
			n = passStyle.Render("✓ " + m.notice)
		}
		help = n + "\n" + help
	}
	return help
}

// banner is the full-width guidance block under the header: what is happening,
// what it means in plain English, and — on a failure — what to do about it and
// which tool to reach for next.
func (m model) banner() string {
	if m.toolbox && !m.chainRan() {
		return "Welcome! Press " + selStyle.Render("r") + " to check your connection, or run a tool below."
	}
	if !m.allDone() {
		done, total := len(m.results), len(m.probes)
		return m.spinner.View() + " Checking your connection… " +
			progressBar(done, total, 20) + faintStyle.Render(fmt.Sprintf(" %d of %d done", done, total))
	}
	order := make([]diagnostic.ProbeID, len(m.probes))
	var firstFail *diagnostic.ProbeResult
	anyWarn := false
	for i, probe := range m.probes {
		order[i] = probe.ID
		r := m.results[probe.ID]
		if firstFail == nil && r.Status == diagnostic.StatusFail {
			rr := r
			firstFail = &rr
		}
		anyWarn = anyWarn || r.Status == diagnostic.StatusWarn
	}
	summary := diagnostic.Diagnose(m.target, order, m.results)
	if firstFail == nil {
		if anyWarn {
			if summary == "" {
				summary = "Checks passed with warnings — see the ! row for details."
			}
			if m.verifying {
				summary = "Fix verified: " + summary
			}
			return warnStyle.Render("! " + summary)
		}
		if summary == "" {
			summary = "All checks passed — no problems found."
			if m.target != nil {
				summary = fmt.Sprintf("All checks passed — %s:%d looks healthy.", m.target.Host, m.target.Port)
			}
		}
		if m.verifying {
			summary = "Fix verified: " + summary
		}
		return passStyle.Render("✓ " + summary)
	}
	if summary == "" {
		summary = "A check failed — see the ✗ row for details."
	}
	if m.verifying {
		summary = "Fix didn't help: " + summary
	}
	lines := []string{failStyle.Render("✗ " + summary)}
	if firstFail.Fix != "" {
		lines = append(lines, faintStyle.Render("  Fix: "+firstFail.Fix))
	}
	if fix := m.fixTool(); fix != nil {
		_, _, display := fix.Build(m.target)
		lines = append(lines, "  Press "+selStyle.Render("f")+" to try a fix ("+display+") — the checks rerun to verify.")
	}
	if next := m.nextStep(firstFail.ID); next != "" {
		lines = append(lines, "  "+next)
	}
	return strings.Join(lines, "\n")
}

// probeNextTool maps a failed probe to the toolbox hotkey that best
// investigates it.
var probeNextTool = map[diagnostic.ProbeID]string{
	diagnostic.ProbeInternet:  "p",
	diagnostic.ProbeDNS:       "d",
	diagnostic.ProbeTargetTCP: "t",
	diagnostic.ProbeTLS:       "c",
	diagnostic.ProbeHTTP:      "c",
	diagnostic.ProbeHTTPS:     "c",
	diagnostic.ProbeSSH:       "t",
	diagnostic.ProbeSMTP:      "t",
}

// nextStep suggests the toolbox key worth pressing after a failure, e.g.
// "Next: press d — DNS lookup (dig)". Empty when no tool applies or the
// binary is missing.
func (m model) nextStep(id diagnostic.ProbeID) string {
	key, ok := probeNextTool[id]
	if !ok {
		return ""
	}
	for _, t := range m.tools {
		if t.Key == key && t.Available() {
			return "Next: press " + selStyle.Render(key) + " — " + toolPurpose[key] + " (" + t.Name + ")"
		}
	}
	return ""
}

func styledProbeStatus(s diagnostic.Status) string {
	switch s {
	case diagnostic.StatusPass:
		return passStyle.Render(s.String())
	case diagnostic.StatusWarn:
		return warnStyle.Render(s.String())
	case diagnostic.StatusFail:
		return failStyle.Render(s.String())
	case diagnostic.StatusSkip:
		return skipStyle.Render(s.String())
	}
	return s.String()
}

// styledStatus colors the job status word: green done, red failed/timed out,
// yellow canceled.
func styledStatus(s JobStatus) string {
	switch s {
	case JobDone:
		return passStyle.Render(s.String())
	case JobFailed, JobTimedOut:
		return failStyle.Render(s.String())
	case JobCanceled:
		return skipStyle.Render(s.String())
	}
	return s.String()
}

// jobStatusLine is the "name — status" line shared by the job pane and the
// output viewer: a live spinner + timer while running, the total duration
// once the job has finished.
func (m model) jobStatusLine() string {
	s := faintStyle.Render(m.jobName+" — ") + styledStatus(m.jobStatus)
	if m.activeJob != nil {
		return s + " " + m.spinner.View() + faintStyle.Render(fmt.Sprintf(" %.0fs", time.Since(m.jobStart).Seconds()))
	}
	if m.jobDur >= time.Second {
		s += faintStyle.Render(fmt.Sprintf(" · %.0fs", m.jobDur.Seconds()))
	}
	return s
}

// outputView is the full-screen scrollable output viewer (Enter).
func (m model) outputView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("$ "+m.jobDisplay) + "\n")
	b.WriteString(m.jobStatusLine() + "\n")
	b.WriteString(m.vp.View() + "\n")
	b.WriteString(faintStyle.Render(m.vpContext()) + "\n")
	b.WriteString(helpKeys(m.width, "↑/↓", "scroll", "pgup/pgdn", "page", "esc", "back", "q", "quit"))
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

// toolPurpose is the plain-English toolbox label per hotkey. Hotkeys are
// stable across OSes; the real command is shown in the job pane once run.
var toolPurpose = map[string]string{
	"i": "route table",
	"s": "open sockets",
	"p": "ping the host",
	"d": "DNS lookup",
	"c": "web check",
	"t": "trace the path",
	"m": "path quality",
	"n": "port scan",
}

// progressBar is a w-cell block bar, filled proportionally to done/total.
func progressBar(done, total, w int) string {
	if total <= 0 || w <= 0 {
		return ""
	}
	filled := min(done*w/total, w)
	return selStyle.Render(strings.Repeat("█", filled)) + faintStyle.Render(strings.Repeat("░", w-filled))
}

func (m model) toolboxView() string {
	if len(m.tools) == 0 {
		return faintStyle.Render("Tools need a host — press ") + keyStyle.Render("r") + faintStyle.Render(" to set one") + "\n"
	}
	parts := make([]string, len(m.tools))
	for i, t := range m.tools {
		purpose := toolPurpose[t.Key]
		if purpose == "" {
			purpose = t.Name
		}
		if t.Available() {
			parts[i] = keyStyle.Render("["+t.Key+"]") + " " + purpose
		} else {
			parts[i] = faintStyle.Render("[" + t.Key + "] " + purpose + " — " + t.Bin + " missing")
		}
	}
	// The title rides on the first chip so line 1's width math includes it;
	// wrapping happens only between chips, never inside one.
	parts[0] = titleStyle.Render("Dig deeper") + "  " + parts[0]
	return joinChips(m.vpWidth(), faintStyle.Render("  ·  "), parts) + "\n"
}

// jobTailN is how many output lines the job pane can show given avail height;
// unknown terminal height falls back to jobTailLines.
func (m model) jobTailN(avail int) int {
	tailN := jobTailLines
	if m.height > 0 {
		overhead := 5 // rule, title, status, context note, trailing blank
		if tailN = avail - overhead; tailN < 0 {
			tailN = 0
		}
	}
	return tailN
}

// jobView renders the job pane with an adaptive tail: avail is the screen
// height left over for this pane; unknown height falls back to jobTailLines.
func (m model) jobView(avail int) string {
	if m.activeJob == nil && m.jobStatus == JobQueued {
		return ""
	}
	if m.height > 0 && avail < 5 {
		return "" // not even rule+title+status+note fit — drop the pane
	}
	tailN := m.jobTailN(avail)
	var b strings.Builder
	b.WriteString(faintStyle.Render(strings.Repeat("─", m.vpWidth())) + "\n")
	b.WriteString(titleStyle.Render("$ "+m.jobDisplay) + "\n")
	b.WriteString(m.jobStatusLine() + "\n")

	shown := m.jobLines
	if len(shown) > tailN {
		shown = shown[len(shown)-tailN:]
	}
	for _, ln := range shown {
		if ln.stream == StreamStderr {
			b.WriteString(faintStyle.Render("! "+ln.text) + "\n")
		} else {
			b.WriteString(ln.text + "\n")
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
