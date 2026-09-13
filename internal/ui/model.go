package ui

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/incident"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// scheduleMsg asks Update to dispatch any newly-runnable probes for generation
// gen. A stale gen is ignored.
type scheduleMsg struct{ gen int }

// watchMsg starts the next pass after a completed watched run.
type watchMsg struct{ gen int }

type noticeDoneMsg struct{ deadline time.Time }

// probeDoneMsg carries a finished probe's result. Accepted only when gen matches.
type probeDoneMsg struct {
	id  diagnostic.ProbeID
	gen int
	res diagnostic.ProbeResult
}

// lanNamesMsg carries the advertised names and ssh aliases for the LAN-scan
// IPs, which arrive as one batch. They override nmap's own reverse-DNS guesses
// in the network map (see networkHosts). ips is the full scanned set, so Update
// knows which addresses still need a reverse lookup.
type lanNamesMsg struct {
	gen   int
	ips   []string
	names map[string]string
}

// mergeLANNames combines platform-advertised names with the user's ssh
// aliases into one freshly allocated map. AdvertisedNames legitimately
// returns nil on non-Linux systems and several Linux error paths, so the
// result must never depend on either input being non-nil. Aliases are
// copied last: the user's own ssh config outranks whatever DNS thinks.
func mergeLANNames(advertised, aliases map[string]string) map[string]string {
	names := make(map[string]string, len(advertised)+len(aliases))
	maps.Copy(names, advertised)
	maps.Copy(names, aliases)
	return names
}

// lanNameMsg is one address's reverse-DNS result, empty name included: it also
// means "stop spinning for this row".
type lanNameMsg struct {
	gen  int
	ip   string
	name string
}

// lanServicesMsg carries what one opened map device answered on its common
// service ports. host is checked as well as gen, so a scan the user has
// already moved on from cannot repaint the device they moved to.
type lanServicesMsg struct {
	gen  int
	host string
	scan diagnostic.ServiceScan
}

// serviceChoice is the network map's second step: the services one discovered
// device answered on, and which of them the cursor is on. It is what keeps
// "diagnose this device" from silently meaning "test HTTPS on it", since a
// device is not an endpoint and only the device is what the map knows.
//
// host is empty whenever no device has been opened, which is the whole of the
// "is the chooser showing" question.
type serviceChoice struct {
	host string
	name string // the map's label for the device, for the panel title
	scan diagnostic.ServiceScan
	done bool // the scan landed, so an empty Open means "none", not "not yet"
	sel  int
}

// pendingAction is a state change deferred until the active job's terminal event
// arrives, so Update never blocks waiting on it (that would deadlock, since
// Update is the goroutine that consumes the event).
type pendingKind int

const (
	pendQuit pendingKind = iota
	pendRestart
)

type pendingAction struct {
	kind   pendingKind
	target *diagnostic.Target
}

// jobState is one tool run's process and display state. The selected run is
// model.cur; unselected runs wait in otherJobs until Tab selects them. Reach
// for the helpers in joblist.go rather than walking both fields.
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
	// maxActiveJobs caps live subprocesses. A held-down hotkey is one keypress
	// per repeat, and every one of them used to fork.
	maxActiveJobs = 4
	// maxParkedJobs caps the tab ring. Each parked run still owns its output
	// buffer, so an unbounded ring is a memory bill nobody asked for.
	maxParkedJobs = 12
	ctrlCWindow   = 2 * time.Second
	noticeWindow  = 4 * time.Second
	watchRuns     = 20
	ctrlCNotice   = "Press Ctrl+C again to quit"
)

// WatchEvery is the gap between repeat passes in watch mode, shared so the TUI
// and the headless -json -watch loop can't drift apart. A var so tests don't
// have to sleep through it.
var WatchEvery = 5 * time.Second

type model struct {
	target  *diagnostic.Target
	probes  []diagnostic.Probe
	sources *diagnostic.SourceAddresses
	// selection is reapplied whenever a target switch rebuilds the probe DAG.
	selection diagnostic.ProbeSelection
	// publicDNS is the second-opinion resolver IP the run was started with, or
	// "" when it is disabled; every probe rebuild reuses it. publicDNSAuto
	// travels with it because a rebuilt DAG has to ask the same question the
	// first one did, including whether the resolver was named or defaulted.
	publicDNS     string
	publicDNSAuto bool
	version       string
	// snapshotCheck and snapshotSkip preserve the user's selection spelling
	// for incident artifacts. The applied selection maps above have no order.
	snapshotCheck []string
	snapshotSkip  []string
	// probeTimeout bounds one probe. It belongs to this model, so a second
	// diagnosis elsewhere in the process cannot change what this run uses.
	probeTimeout time.Duration

	// results + started are owned exclusively by Update; probe goroutines get an
	// immutable snapshot, never the live map.
	results map[diagnostic.ProbeID]diagnostic.ProbeResult
	started map[diagnostic.ProbeID]bool

	selected int
	// selMoved: the user touched the cursor this run, so completion must not
	// yank it to the first failure.
	selMoved    bool
	networkMap  bool
	mapSelected int
	networkCIDR string
	// hostNames maps discovered IPs to resolved or advertised names; entries
	// beat the names nmap printed.
	hostNames map[string]string
	// namesPending holds the IPs whose name lookup is still in flight; those
	// rows show a spinner instead of nmap's PTR guess.
	namesPending map[string]bool
	// svc is the opened device's service list, the step between picking a
	// device on the map and pointing the checks at one endpoint on it.
	svc     serviceChoice
	spinner spinner.Model

	generation int
	// Generation context; cancel kills all in-flight probes and the active job on
	// restart/quit. Kept alive after the chain completes so tools can run under it.
	ctx    context.Context
	cancel context.CancelFunc

	// Drill-down job state (Phase 2).
	tools     []Tool
	pending   *pendingAction
	cur       jobState // the selected run; zero value means none yet
	otherJobs []jobState

	// Output viewport (Enter). follow sticks to the tail while output arrives;
	// scrolling up turns it off, scrolling back to the bottom re-enables it.
	viewing bool
	follow  bool
	vp      viewport.Model
	// Filter (/): while filtering, filterInput has focus and mirrors into
	// filter on every keystroke; the committed value stays applied until
	// esc while typing or leaving the viewer clears it.
	filtering   bool
	filter      string
	filterInput textinput.Model

	// Restart prompt (r): an editable netdoc command line. Enter parses
	// and restarts; esc closes without touching the current run. Up/down
	// walk this session's past targets, shell-style; histDraft keeps the
	// line being typed while browsing.
	entering  bool
	input     textinput.Model
	inputErr  string
	history   []string
	histIdx   int
	histDraft string
	histPath  string // ""; disables persistence (tests, or no config dir)

	// SSH login form (S): host, username, key file, password. Enter hands the
	// terminal to ssh; esc closes it. Every S starts a fresh form, so a typed
	// password lives only as long as the form is open.
	sshPrompt  bool
	ssh        sshForm
	sshRequest uint64

	// Confirm gate: a tool marked Confirm (nmap) is held here after its hotkey,
	// showing the exact command until 'y' runs it or esc cancels.
	confirmTool *Tool

	helping bool // ?: full-screen key cheatsheet; any key closes it

	// Actions menu (space): the actions and tools that fit the current state,
	// drawn where the help bar goes. actionsSelID is the action the cursor is
	// on and actionsSel the row it was last on, the fallback for when that
	// action stops applying. It is discovery, not a second command system:
	// every row runs through the same dispatch its key does.
	actionsOpen  bool
	actionsSel   int
	actionsSelID actionID

	// theme is this model's own palette and the styles every view draws
	// with. Both are values rather than package state, so a second model or a
	// parallel test cannot repaint this one. It is presentation and nothing
	// else: no probe, diagnosis, report, or snapshot path reads either.
	theme     Theme
	st        styles
	themePath string // ""; disables persistence (tests, or no config dir)
	// Theme picker (T): themeSel is the previewed row, applied as the cursor
	// moves, and themeWas is the theme esc puts back.
	theming  bool
	themeSel int
	themeWas Theme

	// keys resolves keypresses to actions. The zero value is the default
	// keymap, so a model built without one behaves as netdoc always has.
	// pendingKeys is the unfinished start of a chord ("g" of "gg") waiting
	// for the key that completes it.
	keys        Keymap
	pendingKeys []string

	// expanded is presentation state and nothing else: the finished-run view
	// collapses the passing checks behind one summary line, and the expand
	// action toggles that. No probe, diagnosis, or report path reads it.
	expanded bool
	// explaining swaps the focused Details panel to the diagnosis's typed
	// causal evidence. It changes no result, diagnosis, or report.
	explaining bool

	toolbox    bool // --toolbox: chain deferred until 'r'
	watch      bool
	runHistory map[diagnostic.ProbeID][]diagnostic.Status
	incidents  incident.Timeline
	// Incident inspection is a small read-only viewer alongside the existing
	// job-output viewer. The timeline itself remains owned by Update.
	incidentViewing  bool
	incidentSelected int
	incidentVP       viewport.Model
	now              func() time.Time

	// notice is one-line feedback from export or the Ctrl+C quit hint.
	notice         string
	noticeOK       bool
	noticeDeadline time.Time

	width, height int
}

// Option adjusts a new model without growing its positional constructor.
type Option func(*model)

// WithKeymap runs the TUI on a resolved keymap instead of the default one.
func WithKeymap(km Keymap) Option {
	return func(m *model) { m.keys = km }
}

// WithThemeFile persists the selected theme to path and reads the startup
// preference from it. "" keeps the choice to this session, which is what
// tests and a machine with no config directory get.
func WithThemeFile(path string) Option {
	return func(m *model) { m.themePath = path }
}

// WithProbeTimeout overrides the per-probe budget for this model only.
// Non-positive values are ignored, leaving DefaultProbeTimeout in place.
func WithProbeTimeout(d time.Duration) Option {
	return func(m *model) {
		if d > 0 {
			m.probeTimeout = d
		}
	}
}

// WithSnapshotSelection preserves the CLI spelling in incident artifacts.
func WithSnapshotSelection(check, skip []string) Option {
	return func(m *model) {
		m.snapshotCheck = append([]string(nil), check...)
		m.snapshotSkip = append([]string(nil), skip...)
	}
}

// NewWithSelection applies a validated CLI probe policy to this run and every
// target switch made from it.
func NewWithSelection(t *diagnostic.Target, sources *diagnostic.SourceAddresses, toolbox, watch bool, histFile, version, publicDNS string, publicDNSAuto bool, selection diagnostic.ProbeSelection, opts ...Option) tea.Model {
	probes := selection.BuildProbesFromSources(t, sources, publicDNS, publicDNSAuto)
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	m := model{
		target:        t,
		probes:        probes,
		sources:       sources,
		selection:     selection,
		publicDNS:     publicDNS,
		publicDNSAuto: publicDNSAuto,
		results:       map[diagnostic.ProbeID]diagnostic.ProbeResult{},
		started:       map[diagnostic.ProbeID]bool{},
		tools:         toolsFor(t, runtime.GOOS, bindFor(sources)),
		spinner:       sp,
		toolbox:       toolbox,
		watch:         watch,
		runHistory:    map[diagnostic.ProbeID][]diagnostic.Status{},
		histPath:      histFile,
		version:       version,
		probeTimeout:  diagnostic.DefaultProbeTimeout,
		now:           time.Now,
		width:         100, // placeholder until the terminal introduces itself (WindowSizeMsg)
	}
	for _, opt := range opts {
		opt(&m)
	}
	// After the options, since one of them names the preference file.
	m.setTheme(loadTheme(m.themePath))
	m.history = loadHistory(histFile)
	if t != nil {
		if n := len(m.history); n == 0 || m.history[n-1] != t.Raw {
			m.history = append(m.history, t.Raw)
		}
		saveHistory(histFile, m.history) // launch targets count as history too
	}
	return m
}

// setTheme swaps this model's palette and everything derived from it, the
// spinner included. It touches nothing but presentation.
func (m *model) setTheme(t Theme) {
	m.theme, m.st = t, newStyles(t)
	m.spinner.Style = m.st.spinner
}

// diagnosis is this model's one reading of the current results. Everything the
// app says about what the run means, the banner sentence, the verdict colour,
// the row the cursor lands on, and which failures are collateral, comes out of
// this single structure, so two panels can never diagnose the same run
// differently.
func (m model) diagnosis() diagnostic.Diagnosis {
	return diagnostic.Interpret(m.target, m.probeOrder(), m.results)
}

func (m model) diagnose(order []diagnostic.ProbeID) (string, string) {
	d := diagnostic.Interpret(m.target, order, m.results)
	return d.Summary, d.Verdict
}

// Target history persists as one line per target, oldest first. Everything
// here is best-effort: history is a convenience, never worth failing a run
// over, so errors just leave it empty.
const histMax = 50

func loadHistory(path string) []string {
	if path == "" {
		return nil
	}
	// #nosec G304 -- production passes the current-user history path; this unprivileged read may follow a caller-selected symlink, but every consumed line is sanitized below.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var hist []string
	for line := range strings.SplitSeq(string(b), "\n") {
		// Clean guards the prompt against a garbled or tampered file.
		if line = strings.TrimSpace(textsafe.Clean(line)); line != "" {
			hist = append(hist, line)
		}
	}
	if len(hist) > histMax {
		hist = hist[len(hist)-histMax:]
	}
	return hist
}

func saveHistory(path string, hist []string) {
	if path == "" || len(hist) == 0 {
		return
	}
	if len(hist) > histMax {
		hist = hist[len(hist)-histMax:]
	}
	writeConfigFile(path, strings.Join(hist, "\n")+"\n")
}

// writeConfigFile replaces one small convenience file in the config directory.
// Shared by the target history and the theme preference, both of which are
// nice to have and neither of which is worth failing a run over, so every
// error path here simply leaves the file as it was.
func writeConfigFile(path, content string) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	// os.WriteFile would follow a symlink planted at path and truncate whatever
	// it points at. Renaming a sibling temp file over the name replaces the link
	// itself, and costs nothing beyond the write we were doing anyway.
	f, err := os.CreateTemp(dir, filepath.Base(path)+"-*") // 0600 by definition
	if err != nil {
		return
	}
	defer func() { _ = os.Remove(f.Name()) }() // no-op once the rename lands
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return
	}
	if err := f.Close(); err != nil {
		return
	}
	_ = os.Rename(f.Name(), path)
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

// runProgress counts this pass over the plan it is actually running: done is a
// probe the scheduler has produced a final result for (pass, warn, fail, skip,
// and n/a all count once they exist), running is one it dispatched that has
// not answered yet. Everything else is pending on a dependency, and neither
// count claims it. Counting over m.probes is what makes --check, --skip, and a
// target switch move the denominator, and what makes a watch pass describe
// itself: doRestart empties both maps.
func (m model) runProgress() (done, running int) {
	for _, p := range m.probes {
		if _, ok := m.results[p.ID]; ok {
			done++
		} else if m.started[p.ID] {
			running++
		}
	}
	return done, running
}

// hasJob reports whether the current slot holds a job pane worth showing:
// either a running process or a finished/failed one still displaying output.
func (m model) hasJob() bool { return m.cur.active != nil || m.cur.status != JobQueued }

// reportReady reports whether every check has a result and no tool is running.
func (m model) reportReady() bool {
	return m.allDone() && !m.jobsRunning() && m.cur.status != JobRunning
}

// sshDetected reports whether this run found an SSH server to log in to: the
// banner probe passed, i.e. the port answered with an SSH- identification
// string. A warn is deliberately not enough: that one means the port answered
// with silence, and ssh always speaks first.
//
// Presence first: a target with no SSH rung has no entry here at all, and the
// zero ProbeResult a missing key returns carries StatusPass (the first iota).
func (m model) sshDetected() bool {
	r, ok := m.results[diagnostic.ProbeSSH]
	return ok && r.Status == diagnostic.StatusPass
}

// spinnerActive reports whether the spinner tick chain should keep running for
// probes, jobs, name lookups, a device's service check, or SSH configuration
// resolution.
func (m model) spinnerActive() bool {
	return ((!m.toolbox || m.generation > 0 || m.chainRan()) && !m.allDone()) || m.jobsRunning() ||
		len(m.namesPending) > 0 || m.svcPending() || m.ssh.pending != nil
}

// svcPending reports whether an opened device's service check is still in
// flight, which is the one thing on the map with nothing else to animate it.
func (m model) svcPending() bool { return m.svc.host != "" && !m.svc.done }

// setNotice shows one-line feedback and schedules its expiry. The expiry tick
// carries the deadline it was armed with, so a leftover tick from an earlier
// notice can't blank a newer one, since equality is the identity check.
func (m *model) setNotice(msg string, ok bool) tea.Cmd {
	window := noticeWindow
	if msg == ctrlCNotice {
		window = ctrlCWindow
	}
	m.notice, m.noticeOK = textsafe.Clean(msg), ok
	m.noticeDeadline = time.Now().Add(window)
	deadline := m.noticeDeadline
	if m.viewing {
		m.refreshViewport()
	}
	return tea.Tick(window, func(time.Time) tea.Msg { return noticeDoneMsg{deadline: deadline} })
}

// Update is the only goroutine that touches model state; probes and jobs talk
// to it strictly through messages. Async messages carry the generation they
// were born in, so a restart doesn't have to chase them down; it just bumps
// the counter and lets the stale ones bounce off.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if m.incidentViewing {
			m.refreshIncidentViewport(false)
		}
		if m.viewing {
			m.refreshViewport()
		}
		return m, nil

	case tea.KeyMsg:
		if m.helping {
			m.helping = false
			return m, nil
		}
		// Runes read from stdin in one batch arrive as a single KeyMsg ("jjj"), which
		// matches no binding; replay them one at a time, so a fast chord and a
		// slow chord behave identically.
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
		// Ctrl+C while the confirm gate is up cancels the gate, not the app.
		if msg.Type == tea.KeyCtrlC && m.confirmTool != nil {
			return m.handleConfirmKey(msg)
		}
		if msg.Type == tea.KeyCtrlC {
			// Ctrl+C reaches quit directly rather than through the quit
			// binding: it is the terminal's own way out, and rebinding quit
			// must not take it away.
			if m.notice == ctrlCNotice && time.Now().Before(m.noticeDeadline) {
				return m.quit()
			}
			return m, m.setNotice(ctrlCNotice, false)
		}
		if m.confirmTool != nil {
			return m.handleConfirmKey(msg)
		}
		if m.theming {
			return m.handleThemeKey(msg)
		}
		if m.sshPrompt {
			return m.handleSSHKey(msg)
		}
		if m.entering {
			return m.handlePromptKey(msg)
		}
		if m.incidentViewing {
			return m.handleIncidentKey(msg)
		}
		if m.viewing {
			return m.handleViewKey(msg)
		}
		if m.actionsOpen {
			return m.handleActionsKey(msg)
		}
		return m.handleKey(msg)

	case noticeDoneMsg:
		if msg.deadline.Equal(m.noticeDeadline) {
			m.noticeDeadline = time.Time{}
			m.notice = ""
			if m.viewing {
				m.refreshViewport()
			}
		}
		return m, nil

	case sshDoneMsg:
		// The session's own screen is gone the moment the TUI repaints, so
		// whatever ssh said lands in a job pane like any other tool's output.
		m.stashJob()
		m.cur = jobState{name: "SSH login", display: msg.display, status: JobDone}
		for line := range strings.SplitSeq(strings.TrimRight(msg.output, "\n"), "\n") {
			if line != "" {
				m.appendJobLine(textsafe.Clean(line))
			}
		}
		notice := "ssh session ended"
		if msg.err != nil {
			m.cur.status = JobFailed
			m.appendJobLine(textsafe.Clean(msg.err.Error()))
			notice = "ssh failed: press enter for the output"
		}
		if m.viewing {
			m.refreshViewport()
		}
		return m, m.setNotice(notice, msg.err == nil)

	case sshResolvedMsg:
		if !m.sshPrompt || m.ssh.pending == nil || msg.id != m.ssh.pending.id {
			return m, nil
		}
		pending := m.ssh.pending
		m.ssh.pending = nil
		if msg.err != nil {
			m.ssh.err = textsafe.Clean(msg.err.Error())
			return m, nil
		}
		args, env := sshAskpass(pending.args, m.ssh.pass.Value(), pending.self, msg.host, msg.proxied)
		m.sshPrompt = false
		// The password is in env now, so the form has no reason to keep it.
		// Go strings cannot be wiped; this only shortens the window.
		m.ssh.pass.SetValue("")
		return m, runSSH(args, env)

	case scheduleMsg:
		if msg.gen != m.generation {
			return m, nil
		}
		if m.ctx == nil {
			m.ctx, m.cancel = context.WithCancel(context.Background())
		}
		cmds := m.scheduleStep()
		if m.watch && m.allDone() {
			cmds = append(cmds, m.watchCmd())
		}
		return m, tea.Batch(cmds...)

	case watchMsg:
		if !m.watch || msg.gen != m.generation || !m.allDone() {
			return m, nil
		}
		if m.jobsRunning() {
			return m, m.watchCmd()
		}
		// A watch pass refreshes results underneath the user, so it must leave
		// everything they are mid-way through alone: open modals and their
		// typed contents, the last notice, a cursor they moved themselves, the
		// LAN map and the device opened on it, the parked tool output the map
		// is drawn from, and an open explanation of the diagnosis. That is
		// restartRun without resetPresentation, so the set is not a list this
		// branch has to keep in step with doRestart.
		//
		// Nothing stale survives it: every one of those views is recomputed
		// from the new run each frame. The explanation in particular holds no
		// copy of the evidence it showed, so it redraws from this pass's
		// diagnosis, and the panel falls back to Details by itself once the
		// cursor is no longer on the row the new diagnosis blames.
		cmd := m.restartRun()
		if m.viewing {
			m.refreshViewport()
		}
		return m, cmd

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
			diagnostic.Finalize(m.results)
			// recordRun comes before the focus decision, not after it: a watch
			// pass moves the cursor for what changed since the previous pass,
			// and appending this pass's statuses is what makes the two
			// comparable.
			if m.watch {
				m.recordRun()
				cmds = append(cmds, m.watchCmd())
			}
			if !m.selMoved && !m.viewing {
				if i := m.focusTarget(); i >= 0 {
					m.selected = i
				}
			}
		}
		return m, tea.Batch(cmds...)

	case ToolOutputMsg:
		if msg.Generation != m.generation {
			return m, nil
		}
		j := m.jobByID(msg.JobID)
		if j == nil {
			return m, nil
		}
		// The selected run appends through the model: only its buffer is on
		// screen, so only it has to keep the open viewport's offset honest.
		if j == &m.cur {
			m.appendJobLine(msg.Line)
			if m.viewing {
				m.refreshViewport()
			}
		} else {
			j.appendLine(msg.Line)
		}
		return m, waitForMsg(j.active.ch)

	case ToolDoneMsg:
		if msg.Generation != m.generation {
			return m, nil
		}
		done := m.jobByID(msg.JobID)
		if done == nil {
			return m, nil
		}
		done.status, done.dropped, done.active = msg.Status, msg.Dropped, nil
		done.dur = time.Since(done.start)
		if m.pending != nil && !m.jobsRunning() {
			p := m.pending
			m.pending = nil
			return m.runPending(p)
		}
		if done.name == lanDiscoveryName && msg.Status == JobDone {
			if ips := discoveredIPs(done.lines); len(ips) > 0 {
				ctx, gen := m.ctx, m.generation
				m.namesPending = make(map[string]bool, len(ips))
				for _, ip := range ips {
					m.namesPending[ip] = true
				}
				return m, func() tea.Msg {
					names := mergeLANNames(diagnostic.AdvertisedNames(ctx, ips), diagnostic.SSHHostAliases())
					return lanNamesMsg{gen: gen, ips: ips, names: names}
				}
			}
		}
		return m, nil

	case lanNamesMsg:
		if msg.gen != m.generation {
			return m, nil
		}
		if m.hostNames == nil {
			m.hostNames = msg.names
		} else {
			maps.Copy(m.hostNames, msg.names)
		}
		// Reverse DNS runs only for what advertised nothing, one command per
		// address: each row stops spinning as its own name lands, and no row
		// ever shows a PTR guess that an advertised name would then replace.
		var cmds []tea.Cmd
		for _, ip := range msg.ips {
			if m.hostNames[ip] != "" {
				delete(m.namesPending, ip)
				continue
			}
			ctx, gen := m.ctx, m.generation
			cmds = append(cmds, func() tea.Msg {
				return lanNameMsg{gen: gen, ip: ip, name: diagnostic.ReverseName(ctx, ip)}
			})
		}
		return m, tea.Batch(cmds...)

	case lanServicesMsg:
		// The device is checked as well as the generation: esc and a second
		// device both leave an in-flight scan behind, and its reply must not
		// land on whatever is on screen by the time it arrives.
		if msg.gen != m.generation || msg.host != m.svc.host {
			return m, nil
		}
		m.svc.scan, m.svc.done, m.svc.sel = msg.scan, true, 0
		return m, nil

	case lanNameMsg:
		if msg.gen != m.generation {
			return m, nil
		}
		delete(m.namesPending, msg.ip)
		if msg.name != "" {
			if m.hostNames == nil {
				m.hostNames = map[string]string{}
			}
			m.hostNames[msg.ip] = msg.name
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

func (m *model) clearCancel() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}

func (m *model) recordRun() {
	for _, p := range m.probes {
		history := append(m.runHistory[p.ID], m.results[p.ID].Status)
		if len(history) > watchRuns {
			history = history[len(history)-watchRuns:]
		}
		m.runHistory[p.ID] = history
	}
	m.recordIncident(m.incidentNow())
}

func (m model) watchCmd() tea.Cmd {
	gen := m.generation
	return tea.Tick(WatchEvery, func(time.Time) tea.Msg { return watchMsg{gen: gen} })
}
