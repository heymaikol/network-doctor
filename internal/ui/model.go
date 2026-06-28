package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
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
	maxJobLines  = 500
	jobTailLines = 14
)

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
	jobOut     []string
	jobErr     []string
	jobDropped int64
	jobStart   time.Time
	facts      []Fact

	toolbox   bool   // --toolbox: chain deferred until 'r'
	exportMsg string // last export result, shown in the footer

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
		tools:     toolsFor(t),
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
		return m, nil

	case tea.KeyMsg:
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
		if msg.Stream == StreamStderr {
			m.jobErr = appendCapped(m.jobErr, msg.Line)
		} else {
			m.jobOut = appendCapped(m.jobOut, msg.Line)
		}
		return m, waitForMsg(m.activeJob.ch)

	case ToolDoneMsg:
		if m.activeJob == nil || msg.Generation != m.generation || msg.JobID != m.activeJob.id {
			return m, nil
		}
		m.jobStatus, m.jobDropped, m.activeJob = msg.Status, msg.Dropped, nil
		m.facts = extractFacts(m.jobToolKey, m.jobOut)
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
	case "e":
		if path, err := exportReport(m); err != nil {
			m.exportMsg = "export failed: " + err.Error()
		} else {
			m.exportMsg = "exported → " + path
		}
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
	m.jobStatus, m.jobOut, m.jobErr, m.facts, m.jobDropped = JobQueued, nil, nil, nil, 0
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
		m.jobOut, m.jobErr, m.facts = nil, []string{tool.Bin + " not found — install it"}, nil
		m.jobDisplay = tool.Name
		return nil
	}
	wasTicking := m.spinnerActive()
	args, env, display := tool.Build(m.target)
	id := fmt.Sprintf("%s-%d-%d", tool.Key, m.generation, time.Now().UnixNano())
	j, cmd, err := startTool(m.ctx, m.generation, id, tool.Bin, args, env)
	if err != nil {
		m.jobName, m.jobToolKey, m.jobStatus = tool.Name, tool.Key, JobFailed
		m.jobOut, m.jobErr, m.jobDisplay = nil, []string{sanitize(err.Error())}, display
		return nil
	}
	m.activeJob, m.jobStatus = j, JobRunning
	m.jobOut, m.jobErr, m.facts, m.jobDropped = nil, nil, nil, 0
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

func appendCapped(lines []string, line string) []string {
	lines = append(lines, line)
	if len(lines) > maxJobLines {
		lines = lines[len(lines)-maxJobLines:]
	}
	return lines
}

func targetHost(t *Target) string {
	if t == nil {
		return ""
	}
	return t.Host
}

func (m *model) clearCancel() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}

func statusGlyph(status Status) rune {
	switch status {
	case StatusPass:
		return '✓'
	case StatusFail:
		return '✗'
	case StatusSkip:
		return '⊘'
	case StatusNA:
		return '–'
	}
	return '?'
}

func (m model) glyph(id ProbeID) string {
	r, ok := m.results[id]
	if !ok {
		return m.spinner.View()
	}
	mark := string(statusGlyph(r.Status))
	switch r.Status {
	case StatusPass:
		return passStyle.Render(mark)
	case StatusFail:
		return failStyle.Render(mark)
	case StatusSkip:
		return skipStyle.Render(mark)
	case StatusNA:
		return faintStyle.Render(mark)
	}
	return mark
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
		right.WriteString(diagnose(m.target, m.order, m.results) + "\n\n")
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

	help := faintStyle.Render("↑/↓ select · r rerun · e export · q quit")
	if m.exportMsg != "" {
		help = faintStyle.Render(m.exportMsg) + "\n" + help
	}
	return body + "\n" + m.toolboxView() + "\n" + m.jobView() + help + "\n"
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

func (m model) jobView() string {
	if m.activeJob == nil && m.jobStatus == JobQueued {
		return ""
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("$ "+m.jobDisplay) + "\n")
	status := m.jobName + " — " + m.jobStatus.String()
	if m.activeJob != nil {
		status += fmt.Sprintf(" (%.0fs)", time.Since(m.jobStart).Seconds())
	}
	b.WriteString(faintStyle.Render(status) + "\n")

	for _, ln := range tail(m.jobOut, jobTailLines) {
		b.WriteString(ln + "\n")
	}
	for _, ln := range tail(m.jobErr, 4) {
		b.WriteString(faintStyle.Render("! "+ln) + "\n")
	}
	if len(m.facts) > 0 {
		b.WriteString(titleStyle.Render("Extracted:") + "\n")
		for _, f := range m.facts {
			b.WriteString("  " + f.Key + ": " + f.Value + "\n")
		}
	}
	if m.jobDropped > 0 {
		b.WriteString(faintStyle.Render(fmt.Sprintf("(%d output lines dropped)", m.jobDropped)) + "\n")
	}
	return b.String() + "\n"
}

func tail(lines []string, n int) []string {
	if len(lines) > n {
		return lines[len(lines)-n:]
	}
	return lines
}
