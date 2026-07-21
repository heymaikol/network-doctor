package ui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// scheduleMsg asks Update to dispatch any newly-runnable probes for generation
// gen. A stale gen is ignored.
type scheduleMsg struct{ gen int }

type noticeDoneMsg struct{ deadline time.Time }

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
	pendRestart
)

type pendingAction struct {
	kind   pendingKind
	target *diagnostic.Target
}

// ponytail: the selected job stays in model's legacy fields to contain this
// change; move every run into []jobState when job controls grow.
// jobState is one tool run's process and display state. The model's existing
// job fields are the selected run; unselected runs live here until Tab selects
// them.
type jobState struct {
	active  *job
	status  JobStatus
	name    string
	display string
	lines   []string
	dropped int64
	evicted int
	start   time.Time
	dur     time.Duration
}

const (
	maxJobLines  = 5000 // ring-buffer cap: older lines become a "discarded" count, not a memory bill
	jobTailLines = 14   // main-screen tail fallback when the terminal height is unknown
	ctrlCWindow  = 2 * time.Second
	noticeWindow = 4 * time.Second
	ctrlCNotice  = "Press Ctrl+C again (or q) to quit"
)

type model struct {
	target *diagnostic.Target
	probes []diagnostic.Probe

	// results + started are owned exclusively by Update; probe goroutines get an
	// immutable snapshot, never the live map.
	results map[diagnostic.ProbeID]diagnostic.ProbeResult
	started map[diagnostic.ProbeID]bool

	selected    int
	networkMap  bool
	mapSelected int
	networkCIDR string
	spinner     spinner.Model

	generation int
	// Generation context; cancel kills all in-flight probes and the active job on
	// restart/quit. Kept alive after the chain completes so tools can run under it.
	ctx    context.Context
	cancel context.CancelFunc

	// Drill-down job state (Phase 2).
	tools      []Tool
	activeJob  *job
	pending    *pendingAction
	jobStatus  JobStatus
	jobName    string
	jobDisplay string
	jobLines   []string
	jobDropped int64 // channel-overflow drops, reported by ToolDoneMsg
	jobEvicted int   // oldest lines evicted from the jobLines ring buffer
	jobStart   time.Time
	jobDur     time.Duration // total runtime of the selected finished job
	otherJobs  []jobState

	// Output viewport (Enter). follow sticks to the tail while output arrives;
	// scrolling up turns it off, scrolling back to the bottom re-enables it.
	viewing bool
	follow  bool
	vp      viewport.Model

	// Restart prompt (r): an editable netdoc command line. Enter parses
	// and restarts; esc closes without touching the current run.
	entering bool
	input    textinput.Model
	inputErr string

	// Confirm gate: a tool marked Confirm (nmap) is held here after its hotkey,
	// showing the exact command until 'y' runs it or any other key cancels.
	confirmTool *Tool

	toolbox bool // --toolbox: chain deferred until 'r'

	// notice is one-line feedback from export or the Ctrl+C quit hint.
	notice         string
	noticeOK       bool
	noticeDeadline time.Time

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
	statusStyles    = map[fmt.Stringer]lipgloss.Style{
		diagnostic.StatusPass: passStyle, diagnostic.StatusWarn: warnStyle,
		diagnostic.StatusFail: failStyle, diagnostic.StatusSkip: skipStyle, diagnostic.StatusNA: faintStyle,
		JobDone: passStyle, JobFailed: failStyle, JobTimedOut: failStyle, JobCanceled: skipStyle,
	}
)

// New constructs the terminal application.
func New(t *diagnostic.Target, toolbox bool) tea.Model {
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
		toolbox:   toolbox,
		width:     100, // placeholder until the terminal introduces itself (WindowSizeMsg)
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

// reportReady reports whether every check has a result and no tool is running.
func (m model) reportReady() bool {
	return m.allDone() && !m.jobsRunning() && m.jobStatus != JobRunning
}

// spinnerActive reports whether the spinner tick chain should keep running:
// while a started probe chain is pending or a drill-down job is live.
func (m model) spinnerActive() bool {
	return ((!m.toolbox || m.generation > 0 || m.chainRan()) && !m.allDone()) || m.jobsRunning()
}

// setNotice shows one-line feedback and schedules its expiry. The expiry tick
// carries the deadline it was armed with, so a leftover tick from an earlier
// notice can't blank a newer one — equality is the identity check.
func (m *model) setNotice(msg string, ok bool) tea.Cmd {
	window := noticeWindow
	if msg == ctrlCNotice {
		window = ctrlCWindow
	}
	m.notice, m.noticeOK = msg, ok
	m.noticeDeadline = time.Now().Add(window)
	deadline := m.noticeDeadline
	if m.viewing {
		m.refreshViewport()
	}
	return tea.Tick(window, func(time.Time) tea.Msg { return noticeDoneMsg{deadline: deadline} })
}

// Update is the only goroutine that touches model state; probes and jobs talk
// to it strictly through messages. Async messages carry the generation they
// were born in, so a restart doesn't have to chase them down — it just bumps
// the counter and lets the stale ones bounce off.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if m.viewing {
			m.refreshViewport()
		}
		return m, nil

	case tea.KeyMsg:
		// Ctrl+C while the confirm gate is up cancels the gate, not the app.
		if msg.Type == tea.KeyCtrlC && m.confirmTool != nil {
			return m.handleConfirmKey(msg)
		}
		if msg.Type == tea.KeyCtrlC {
			if m.notice == ctrlCNotice && time.Now().Before(m.noticeDeadline) {
				return m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
			}
			return m, m.setNotice(ctrlCNotice, false)
		}
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

	case tea.MouseMsg:
		if m.confirmTool != nil || m.entering {
			return m, nil
		}
		if m.viewing {
			var cmd tea.Cmd
			m.vp, cmd = m.vp.Update(msg)
			m.follow = m.vp.AtBottom()
			return m, cmd
		}
		if msg.Action != tea.MouseActionPress {
			return m, nil
		}
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			return m.handleKey(tea.KeyMsg{Type: tea.KeyUp})
		case tea.MouseButtonWheelDown:
			return m.handleKey(tea.KeyMsg{Type: tea.KeyDown})
		}
		return m, nil

	case noticeDoneMsg:
		if msg.deadline.Equal(m.noticeDeadline) {
			m.noticeDeadline = time.Time{}
			m.notice = ""
			if m.viewing {
				m.refreshViewport()
			}
		}
		return m, nil

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
			return m, nil // stale restart
		}
		res := msg.res
		res.ID = msg.id // scheduler identity wins over whatever the probe wrote on its own name tag
		m.results[msg.id] = res
		// scheduleStep first: it records skip results synchronously, which can
		// be what completes the run.
		cmds := m.scheduleStep()
		if m.allDone() {
			diagnostic.DowngradeEgress(m.results)
			for i, p := range m.probes {
				if m.results[p.ID].Status == diagnostic.StatusFail {
					m.selected = i
					break
				}
			}
		}
		return m, tea.Batch(cmds...)

	case ToolOutputMsg:
		if msg.Generation != m.generation {
			return m, nil
		}
		if m.activeJob != nil && msg.JobID == m.activeJob.id {
			m.appendJobLine(msg.Line)
			if m.viewing {
				m.refreshViewport()
			}
			return m, waitForMsg(m.activeJob.ch)
		}
		for i := range m.otherJobs {
			j := &m.otherJobs[i]
			if j.active != nil && msg.JobID == j.active.id {
				appendJobLine(&j.lines, &j.evicted, msg.Line)
				return m, waitForMsg(j.active.ch)
			}
		}
		return m, nil

	case ToolDoneMsg:
		if msg.Generation != m.generation {
			return m, nil
		}
		found := false
		if m.activeJob != nil && msg.JobID == m.activeJob.id {
			m.jobStatus, m.jobDropped, m.activeJob = msg.Status, msg.Dropped, nil
			m.jobDur = time.Since(m.jobStart)
			found = true
		} else {
			for i := range m.otherJobs {
				j := &m.otherJobs[i]
				if j.active != nil && msg.JobID == j.active.id {
					j.status, j.dropped, j.active = msg.Status, msg.Dropped, nil
					j.dur = time.Since(j.start)
					found = true
					break
				}
			}
		}
		if !found {
			return m, nil
		}
		if m.pending != nil && !m.jobsRunning() {
			p := m.pending
			m.pending = nil
			return m.runPending(p)
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		// Bubble Tea spinners run on a self-perpetuating tick: each TickMsg
		// schedules the next. Returning nil here ends the chain when nothing
		// is animating; launchTool/doRestart re-seed it (wasTicking) later.
		if !m.spinnerActive() {
			return m, nil
		}
		return m, cmd
	}

	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		if m.jobsRunning() {
			m.cancelJobs() // non-blocking; quit after every terminal event
			m.pending = &pendingAction{kind: pendQuit}
			return m, nil
		}
		m.clearCancel()
		return m, tea.Quit
	case "r":
		// Open the restart prompt; an active job keeps streaming until Enter commits.
		m.entering, m.inputErr = true, ""
		ti := textinput.New()
		ti.Prompt = "netdoc "
		ti.Placeholder = "example.com:443 — empty for a general check"
		ti.PromptStyle = keyStyle
		if m.target != nil {
			ti.SetValue(m.target.Raw)
		}
		ti.Focus()
		ti.CursorEnd()
		m.input = ti
		return m, textinput.Blink
	case "v":
		if m.networkMap {
			m.networkMap = false
			return m, nil
		}
		if m.jobName == lanDiscoveryName {
			m.networkMap = true
			return m, nil
		}
		_, cidr := m.discoveryNetwork()
		if cidr == "" {
			return m, m.setNotice("local private IPv4 network not available yet", false)
		}
		tool := cacheAvailability([]Tool{lanDiscoveryTool(quoterFor(runtime.GOOS), cidr)})[0]
		if !tool.Available() {
			return m, m.setNotice("network discovery needs nmap", false)
		}
		m.networkCIDR = cidr
		return m, m.launchTool(tool)
	case "tab":
		return m, m.switchJob()
	case "up", "k":
		if m.networkMap {
			if m.mapSelected > 0 {
				m.mapSelected--
			}
			return m, nil
		}
		if m.selected > 0 {
			m.selected--
		}
		return m, nil
	case "down", "j":
		if m.networkMap {
			if m.mapSelected < len(m.networkHosts())-1 {
				m.mapSelected++
			}
			return m, nil
		}
		if m.selected < len(m.probes)-1 {
			m.selected++
		}
		return m, nil
	case "enter":
		if hosts := m.networkHosts(); m.networkMap && len(hosts) > 0 {
			address, _, _ := strings.Cut(hosts[m.mapSelected], " ")
			t, err := diagnostic.ParseTarget(address)
			if err != nil {
				return m, m.setNotice("invalid discovered target: "+err.Error(), false)
			}
			return m.restartWithTarget(t)
		}
		if m.activeJob == nil && m.jobStatus == JobQueued {
			return m, nil // no job has run; nothing to view
		}
		m.viewing, m.follow = true, true
		m.vp = viewport.New(m.vpWidth(), m.vpHeight())
		// Zero-value bindings disable everything else (j/k, b/f/space, u/d).
		m.vp.KeyMap = viewport.KeyMap{
			Up:       key.NewBinding(key.WithKeys("up")),
			Down:     key.NewBinding(key.WithKeys("down")),
			PageUp:   key.NewBinding(key.WithKeys("pgup")),
			PageDown: key.NewBinding(key.WithKeys("pgdown")),
		}
		m.refreshViewport()
		return m, nil
	case "y", "w":
		if !m.reportReady() {
			return m, nil
		}
		notice, ok := exportReport(m.report(), msg.String() == "w")
		return m, m.setNotice(notice, ok)
	}
	// Tool hotkeys (contextual toolbox).
	for _, tool := range m.tools {
		if msg.String() == tool.Key {
			if tool.Confirm {
				t := tool // hold for the confirm gate; run happens on 'y'
				m.confirmTool = &t
				return m, nil
			}
			return m, m.launchTool(tool)
		}
	}
	return m, nil
}

// handleConfirmKey handles keys while an advanced tool's command is shown: 'y'
// runs it (deferred if a job is still live), and any other key — including esc —
// cancels without running the scan.
func (m model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	tool := *m.confirmTool
	m.confirmTool = nil
	if msg.String() == "y" {
		return m, m.launchTool(tool)
	}
	return m, nil
}

// handleViewKey handles keys while the output viewport is open. Everything not
// handled here scrolls the viewport; leaving the bottom disables follow mode.
func (m model) handleViewKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.viewing = false
		return m, nil
	case "y":
		notice, ok := "output copied to clipboard", true
		if err := copyReport(m.jobOutput()); err != nil {
			notice, ok = "copy failed: "+err.Error(), false
		}
		return m, m.setNotice(notice, ok)
	case "home":
		m.vp.GotoTop()
		m.follow = false
		return m, nil
	case "end":
		m.vp.GotoBottom()
		m.follow = true
		return m, nil
	case "tab":
		return m, m.switchJob()
	}
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	m.follow = m.vp.AtBottom()
	return m, cmd
}

// handlePromptKey handles keys while the restart prompt is open. Enter parses
// the line and restarts (deferred if a job is still running), esc closes, and
// everything else edits the input.
func (m model) handlePromptKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.entering = false
		return m, nil
	case "enter":
		t, err := parseRunArgs(m.input.Value())
		if err != nil {
			m.inputErr = err.Error()
			return m, nil
		}
		m.entering = false
		return m.restartWithTarget(t)
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.inputErr = ""
	return m, cmd
}

func (m model) restartWithTarget(t *diagnostic.Target) (tea.Model, tea.Cmd) {
	if m.jobsRunning() {
		m.cancelJobs()
		m.pending = &pendingAction{kind: pendRestart, target: t}
		return m, nil
	}
	m.applyTarget(t)
	return m, m.doRestart()
}

// parseRunArgs parses the restart prompt as a netdoc command line: an optional
// leading binary name, then at most one target argument. An
// empty line means a general, targetless run.
func parseRunArgs(line string) (*diagnostic.Target, error) {
	fields := strings.Fields(line)
	if len(fields) > 0 && (fields[0] == "netdoc" || fields[0] == "network-doctor") {
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

// applyTarget swaps the run target and rebuilds its probes.
func (m *model) applyTarget(t *diagnostic.Target) {
	m.target = t
	m.probes = diagnostic.BuildProbes(t)
	m.selected = 0
}

func (m model) runPending(p *pendingAction) (tea.Model, tea.Cmd) {
	switch p.kind {
	case pendQuit:
		m.clearCancel()
		return m, tea.Quit
	case pendRestart:
		m.applyTarget(p.target)
		return m, m.doRestart()
	}
	return m, nil
}

// doRestart bumps the generation (invalidating outstanding probe/job messages),
// clears run state and old tool output, resets the context, and reschedules
// from the root.
func (m *model) doRestart() tea.Cmd {
	wasTicking := m.spinnerActive()
	m.clearCancel()
	m.ctx = nil
	m.tools = toolsFor(m.target, runtime.GOOS)
	m.generation++
	m.results = map[diagnostic.ProbeID]diagnostic.ProbeResult{}
	m.started = map[diagnostic.ProbeID]bool{}
	m.activeJob, m.pending, m.confirmTool = nil, nil, nil
	m.otherJobs = nil
	m.jobStatus, m.jobName, m.jobDisplay, m.jobDur = JobQueued, "", "", 0
	m.jobLines, m.jobDropped, m.jobEvicted = nil, 0, 0
	m.networkMap, m.mapSelected, m.networkCIDR = false, 0, ""
	m.notice = ""
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
	m.stashJob()
	m.networkMap = tool.Key == "v"
	if m.networkMap {
		m.mapSelected = 0
	}
	if !tool.Available() {
		m.jobName, m.jobStatus = tool.Name, JobFailed
		m.jobLines, m.jobDropped, m.jobEvicted = []string{tool.Bin + " not found — install it"}, 0, 0
		m.jobDur = 0
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
		m.jobName, m.jobStatus = tool.Name, JobFailed
		m.jobLines, m.jobDropped, m.jobEvicted = []string{textsafe.Clean(err.Error())}, 0, 0
		m.jobDisplay, m.jobDur = display, 0
		return nil
	}
	m.activeJob, m.jobStatus = j, JobRunning
	m.jobLines, m.jobDropped, m.jobEvicted = nil, 0, 0
	if m.viewing {
		m.refreshViewport()
	}
	m.jobName, m.jobDisplay, m.jobStart = tool.Name, display, time.Now()
	if !wasTicking {
		return tea.Batch(cmd, m.spinner.Tick)
	}
	return cmd
}

func (m model) selectedJob() jobState {
	return jobState{m.activeJob, m.jobStatus, m.jobName, m.jobDisplay, m.jobLines,
		m.jobDropped, m.jobEvicted, m.jobStart, m.jobDur}
}

func (m *model) loadJob(j jobState) {
	m.activeJob, m.jobStatus, m.jobName, m.jobDisplay, m.jobLines = j.active, j.status, j.name, j.display, j.lines
	m.jobDropped, m.jobEvicted, m.jobStart, m.jobDur = j.dropped, j.evicted, j.start, j.dur
}

func (m *model) stashJob() {
	if m.activeJob != nil || m.jobStatus != JobQueued {
		m.otherJobs = append(m.otherJobs, m.selectedJob())
		m.loadJob(jobState{status: JobQueued})
	}
}

func (m *model) switchJob() tea.Cmd {
	if len(m.otherJobs) == 0 {
		return nil
	}
	current := m.selectedJob()
	next := m.otherJobs[0]
	m.otherJobs = append(m.otherJobs[1:], current)
	m.loadJob(next)
	m.networkMap = false
	if m.viewing {
		m.follow = true
	}
	// Keep the armed quit intact so the next Ctrl+C still quits.
	if m.notice == ctrlCNotice && time.Now().Before(m.noticeDeadline) {
		if m.viewing {
			m.refreshViewport()
		}
		return nil
	}
	return m.setNotice("switched to "+m.jobName, true)
}

func (m model) jobsRunning() bool {
	if m.activeJob != nil {
		return true
	}
	for _, j := range m.otherJobs {
		if j.active != nil {
			return true
		}
	}
	return false
}

func (m *model) cancelJobs() {
	if m.activeJob != nil && m.activeJob.cancel != nil {
		m.activeJob.cancel()
	}
	for _, j := range m.otherJobs {
		if j.active != nil && j.active.cancel != nil {
			j.active.cancel()
		}
	}
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
				m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusSkip, Detail: "skipped — a prerequisite failed"}
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
func (m *model) appendJobLine(text string) {
	oldLen := len(m.jobLines)
	var evictedLine string
	if oldLen == maxJobLines {
		evictedLine = m.jobLines[0]
	}
	appendJobLine(&m.jobLines, &m.jobEvicted, text)
	if len(m.jobLines) == oldLen && m.viewing && !m.follow {
		h := lipgloss.Height(lipgloss.NewStyle().Width(m.vpWidth()).Render(evictedLine))
		m.vp.SetYOffset(m.vp.YOffset - h)
	}
}

func appendJobLine(lines *[]string, evicted *int, text string) {
	*lines = append(*lines, text)
	if n := len(*lines) - maxJobLines; n > 0 {
		*evicted += n
		*lines = (*lines)[n:]
	}
}

// jobContent renders the interleaved stream wrapped to w columns. Line numbers
// in the context line refer to these wrapped display lines.
func (m model) jobContent(w int) string {
	if len(m.jobLines) == 0 {
		return lipgloss.NewStyle().Width(w).Render(faintStyle.Render("(no output yet)"))
	}
	return lipgloss.NewStyle().Width(w).Render(m.jobOutput())
}

func (m model) jobOutput() string {
	return strings.Join(m.jobLines, "\n")
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
	h := m.height - 3 - lipgloss.Height(m.viewerFooter()) // header + status above, context below
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
		if !m.started[id] {
			return faintStyle.Render("·")
		}
		return m.spinner.View()
	}
	return statusStyles[r.Status].Render(probeGlyph(r.Status))
}

func probeGlyph(s diagnostic.Status) string {
	if s < diagnostic.StatusPass || s > diagnostic.StatusNA {
		return "?"
	}
	return [...]string{"✓", "!", "✗", "⊘", "–"}[s]
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
	if m.networkMap {
		body = m.networkMapView()
	}
	help := m.helpView(deferred)
	if m.entering {
		help = m.promptView(true)
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
	if m.entering && m.confirmTool == nil && m.height > 0 {
		// The forms cheatsheet yields first: drop it when the view would
		// overflow, or when it would starve a live job pane below jobView's
		// 5-row minimum. m.height == 0 means size unknown — keep the forms.
		hasJob := m.activeJob != nil || m.jobStatus != JobQueued
		if avail < 0 || (hasJob && avail < 5) {
			tail = m.promptView(false) + "\n"
			avail = m.height - strings.Count(fixed, "\n") - strings.Count(tail, "\n") - 1
		}
	}
	if m.height > 0 && avail < 0 {
		body = lipgloss.NewStyle().MaxHeight(max(lipgloss.Height(body)+avail, 1)).Render(body)
		fixed = top + body + "\n" + toolbox + "\n"
		avail = m.height - strings.Count(fixed, "\n") - strings.Count(tail, "\n") - 1
	}
	job := m.jobView(avail)
	if m.networkMap && m.jobName == lanDiscoveryName {
		job = ""
	}
	return fixed + job + tail
}

// targetHP is the target endpoint as host:port; JoinHostPort brackets IPv6
// literals so the rendered endpoint reads back as the same target.
func (m model) targetHP() string {
	return net.JoinHostPort(m.target.Host, strconv.Itoa(m.target.Port))
}

// headerView is the one-line masthead: app name, target, connected network.
func (m model) headerView() string {
	h := selStyle.Render("◆ ") + titleStyle.Render("Network Doctor")
	if m.target != nil {
		h += faintStyle.Render("  " + m.targetHP())
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
			right.WriteString(styled(r.Status) + " — " + r.Detail + "\n")
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

func (m model) networkHosts() []string {
	source, _ := m.discoveryNetwork()
	var hosts []string
	for _, line := range m.jobLines {
		host, ok := strings.CutPrefix(line, "Host: ")
		if !ok {
			continue
		}
		host, status, ok := strings.Cut(host, "Status: ")
		if !ok {
			continue
		}
		host = strings.TrimSpace(host)
		if strings.TrimSpace(status) != "Up" || source != nil && strings.HasPrefix(host, source.String()+" ") {
			continue
		}
		host = strings.TrimSuffix(host, " ()")
		hosts = append(hosts, host)
	}
	return hosts
}

// networkMapView renders hosts found by the LAN scan.
func (m model) networkMapView() string {
	source, _ := m.discoveryNetwork()
	hosts := m.networkHosts()
	domains := map[string]int{}
	namedHosts := 0
	for _, host := range hosts {
		if _, name, ok := strings.Cut(host, " ("); ok {
			namedHosts++
			if _, domain, ok := strings.Cut(strings.TrimSuffix(name, ")"), "."); ok {
				domains[strings.ToLower(domain)]++
			}
		}
	}
	commonDomain := ""
	for domain, count := range domains {
		if namedHosts > 1 && count == namedHosts {
			commonDomain = domain
		}
	}

	panelWidth := max(m.width-2, 24)
	title := panelTitleStyle.Render("Network map — " + lanDiscoveryName + " — " + m.networkCIDR)
	if commonDomain != "" {
		domain := faintStyle.Render("Domain: " + commonDomain)
		contentWidth := panelWidth - panelStyle.GetHorizontalPadding()
		if gap := contentWidth - lipgloss.Width(title) - lipgloss.Width(domain); gap > 0 {
			title += strings.Repeat(" ", gap) + domain
		} else {
			title += "\n" + lipgloss.NewStyle().Width(contentWidth).Align(lipgloss.Right).Render(domain)
		}
	}
	var b strings.Builder
	b.WriteString(title + "\n")
	b.WriteString(selStyle.Render("◆") + " This device")
	if source != nil {
		b.WriteString(" " + source.String())
	}
	b.WriteString("\n")

	for i, host := range hosts {
		if address, name, ok := strings.Cut(host, " ("); ok {
			name = strings.TrimSuffix(name, ")")
			if short, domain, ok := strings.Cut(name, "."); ok && strings.EqualFold(domain, commonDomain) {
				host = address + " (" + short + ")"
			}
		}
		branch := "├─ "
		if i == len(hosts)-1 {
			branch = "└─ "
		}
		marker := "  "
		if i == m.mapSelected {
			marker = selStyle.Render("› ")
			host = selStyle.Render(host)
		}
		b.WriteString(marker + faintStyle.Render(branch) + passStyle.Render("●") + " " + host + "\n")
	}
	if len(hosts) == 0 {
		switch {
		case m.activeJob != nil:
			b.WriteString(m.spinner.View() + faintStyle.Render(" discovering devices…") + "\n")
		case m.jobStatus != JobDone:
			b.WriteString(failStyle.Render("└─ Discovery "+m.jobStatus.String()) + "\n")
		case m.jobStatus == JobDone:
			b.WriteString(faintStyle.Render("└─ No other devices replied") + "\n")
		}
	}

	return panelStyle.Width(panelWidth).Render(strings.TrimRight(b.String(), "\n"))
}

func (m model) discoveryNetwork() (net.IP, string) {
	for _, id := range []diagnostic.ProbeID{diagnostic.ProbeInternet, diagnostic.ProbeProxy, diagnostic.ProbeTargetTCP} {
		ip := m.results[id].Source
		if v4 := ip.To4(); v4 != nil && ip.IsPrivate() {
			// ponytail: cap discovery at the source /24; widen only if larger LANs matter.
			return ip, net.IP(v4.Mask(net.CIDRMask(24, 32))).String() + "/24"
		}
	}
	return nil, ""
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
		faintStyle.Render("Actively probes the shown scope — may trip intrusion detection.") + "\n" +
		"$ " + display
	w := max(min(m.width-2, 76), 24)
	return focusPanelStyle.Width(w).Render(body) + "\n" + helpKeys(m.width, "y", "run", "any other key", "cancel")
}

// promptView is the restart prompt panel, shown in place of the help bar.
// withForms includes the target-grammar cheatsheet; View drops it when the
// terminal is too short (the input and any job pane always outrank it).
func (m model) promptView(withForms bool) string {
	body := panelTitleStyle.Render("Restart") + "\n" + m.input.View()
	if withForms {
		// Dedent the shared const: the two-space indent reads right under
		// "Target forms:" in --help but floats oddly inside the panel.
		forms := strings.TrimPrefix(strings.ReplaceAll(diagnostic.TargetForms, "\n  ", "\n"), "  ")
		body += "\n\n" + faintStyle.Render(forms)
	}
	if m.inputErr != "" {
		body += "\n" + failStyle.Render("✗ "+m.inputErr)
	}
	// 88, not 76: the longest target-form line needs ~86 content cols to
	// render unwrapped on wide terminals.
	w := max(min(m.width-2, 88), 24)
	footer := helpKeys(m.width, "enter", "run", "esc", "back")
	if m.notice == ctrlCNotice {
		footer = m.noticeView()
	}
	return focusPanelStyle.Width(w).Render(body) + "\n" + footer
}

func (m model) helpView(deferred bool) string {
	// Enter opens the output viewer whenever a job pane exists (same condition
	// as jobView), so the hint tracks exactly when the key does something.
	hasJob := m.activeJob != nil || m.jobStatus != JobQueued
	if deferred {
		if m.networkMap {
			kv := []string{"v", "checks"}
			if len(m.networkHosts()) > 0 {
				kv = append([]string{"↑/↓", "select device", "enter", "set target"}, kv...)
			} else if hasJob {
				kv = append(kv, "enter", "full output")
			}
			if len(m.otherJobs) > 0 {
				kv = append(kv, "tab", "switch job")
			}
			return helpKeys(m.width, append(kv, "r", "run the checks", "q", "quit")...)
		}
		view := "network map"
		kv := []string{"r", "run the checks", "v", view}
		if len(m.tools) > 0 {
			kv = append(kv, "letter", "runs that tool")
		}
		if hasJob {
			kv = append(kv, "enter", "full output")
		}
		if len(m.otherJobs) > 0 {
			kv = append(kv, "tab", "switch job")
		}
		return helpKeys(m.width, append(kv, "q", "quit")...)
	}
	view := "network map"
	kv := []string{"↑/↓", "scroll", "v", view}
	if m.networkMap {
		kv = []string{"v", "checks"}
		if len(m.networkHosts()) > 0 {
			kv = append([]string{"↑/↓", "select device", "enter", "set target"}, kv...)
		}
	}
	if hasJob && (!m.networkMap || len(m.networkHosts()) == 0) {
		kv = append(kv, "enter", "full output")
	}
	if len(m.otherJobs) > 0 {
		kv = append(kv, "tab", "switch job")
	}
	if m.reportReady() {
		kv = append(kv, "y", "copy report", "w", "save report")
	}
	kv = append(kv, "r", "restart", "q", "quit")
	help := helpKeys(m.width, kv...)
	if notice := m.noticeView(); notice != "" {
		help = notice + "\n" + help
	}
	return help
}

func (m model) noticeView() string {
	if m.notice == "" {
		return ""
	}
	if m.notice == ctrlCNotice {
		return warnStyle.Render("! " + m.notice)
	}
	if m.noticeOK {
		return passStyle.Render("✓ " + m.notice)
	}
	return failStyle.Render("✗ " + m.notice)
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
	order, firstFail, anyWarn := m.resultState()
	summary := diagnostic.Diagnose(m.target, order, m.results)
	if firstFail == nil {
		if anyWarn {
			return warnStyle.Render("! " + summary)
		}
		return passStyle.Render("✓ " + summary)
	}
	lines := []string{failStyle.Render("✗ " + summary)}
	if firstFail.Fix != "" {
		lines = append(lines, faintStyle.Render("  Fix: "+firstFail.Fix))
	}
	if next := m.nextStep(firstFail.ID); next != "" {
		lines = append(lines, "  "+next)
	}
	return strings.Join(lines, "\n")
}

// resultState collects the ordered probe IDs and the severity flags shared by
// the styled banner and plain-text report verdict.
func (m model) resultState() (order []diagnostic.ProbeID, firstFail *diagnostic.ProbeResult, anyWarn bool) {
	order = make([]diagnostic.ProbeID, len(m.probes))
	for i, probe := range m.probes {
		order[i] = probe.ID
		r := m.results[probe.ID]
		if firstFail == nil && r.Status == diagnostic.StatusFail {
			rr := r
			firstFail = &rr
		}
		anyWarn = anyWarn || r.Status == diagnostic.StatusWarn
	}
	return order, firstFail, anyWarn
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
			return "Next: press " + selStyle.Render(key) + " — " + t.Purpose + " (" + t.Name + ")"
		}
	}
	return ""
}

func styled(s fmt.Stringer) string {
	return statusStyles[s].Render(s.String())
}

// jobStatusLine is the "name — status" line shared by the job pane and the
// output viewer: a live spinner + timer while running, the total duration
// once the job has finished.
func (m model) jobStatusLine() string {
	s := faintStyle.Render(m.jobName+" — ") + styled(m.jobStatus)
	if len(m.otherJobs) > 0 {
		s += faintStyle.Render(fmt.Sprintf(" · %d jobs · tab to switch", len(m.otherJobs)+1))
	}
	if m.activeJob != nil {
		return s + " " + m.spinner.View() + faintStyle.Render(fmt.Sprintf(" %.0fs", time.Since(m.jobStart).Seconds()))
	}
	if m.jobDur > 0 && m.jobDur < time.Second {
		s += faintStyle.Render(fmt.Sprintf(" · %dms", m.jobDur.Milliseconds()))
	} else if m.jobDur >= time.Second {
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
	b.WriteString(m.viewerFooter())
	return b.String()
}

func (m model) viewerFooter() string {
	if notice := m.noticeView(); notice != "" {
		return notice
	}
	kv := []string{"↑/↓", "scroll", "pgup/pgdn", "page", "home/end", "top/bottom"}
	if len(m.otherJobs) > 0 {
		kv = append(kv, "tab", "switch job")
	}
	return helpKeys(m.width, append(kv, "y", "copy output", "esc/q", "back")...)
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
		if t.Available() {
			parts[i] = keyStyle.Render("["+t.Key+"]") + " " + t.Purpose
		} else {
			parts[i] = faintStyle.Render("[" + t.Key + "] " + t.Purpose + " — " + t.Bin + " missing")
		}
	}
	// The title rides on the first chip so line 1's width math includes it;
	// wrapping happens only between chips, never inside one.
	parts[0] = titleStyle.Render("Dig deeper") + "  " + parts[0]
	return joinChips(m.vpWidth(), faintStyle.Render("  ·  "), parts) + "\n"
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
	tailN := jobTailLines
	if m.height > 0 {
		tailN = avail - 5 // rule, title, status, context note, trailing blank
		if tailN < 0 {
			tailN = 0
		}
	}
	var b strings.Builder
	b.WriteString(faintStyle.Render(strings.Repeat("─", m.vpWidth())) + "\n")
	b.WriteString(titleStyle.Render("$ "+m.jobDisplay) + "\n")
	b.WriteString(m.jobStatusLine() + "\n")

	shown := m.jobLines
	if len(shown) > tailN {
		shown = shown[len(shown)-tailN:]
	}
	for _, ln := range shown {
		b.WriteString(ln + "\n")
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
