package ui

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/incident"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
	"github.com/heymaikol/network-doctor/v2/internal/update"
)

// updateMsg carries one update-check answer from the background command.
type updateMsg struct{ res update.Result }

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

// lanNamesMsg carries the initial labels for one LAN scan.
type lanNamesMsg struct {
	gen   int
	job   string
	names map[string]lanName
}

type lanName struct {
	label    string
	sshAlias bool
}

func mergeLANNames(advertised, aliases map[string]string) map[string]lanName {
	names := make(map[string]lanName, len(advertised)+len(aliases))
	for ip, label := range advertised {
		names[ip] = lanName{label: label}
	}
	for ip, label := range aliases {
		names[ip] = lanName{label: label, sshAlias: true}
	}
	return names
}

// lanNameMsg is one address's reverse-DNS result, empty name included: it also
// means "stop spinning for this row".
type lanNameMsg struct {
	gen  int
	job  string
	ip   string
	name string
}

// lanServicesMsg carries replies for one address in one LAN snapshot.
type lanServicesMsg struct {
	gen     int
	job     string
	request uint64
	scan    diagnostic.ServiceScan
	err     error
}

// serviceChoice is the network map's second step: the services one discovered
// device answered on, and which of them the cursor is on. It is what keeps
// "diagnose this device" from silently meaning "test HTTPS on it", since a
// device is not an endpoint and only the device is what the map knows.
//
// host is empty whenever no device has been opened, which is the whole of the
// "is the chooser showing" question.
type serviceChoice struct {
	host    string
	name    string // the map's label for the device, for the panel title
	binding diagnostic.LANBinding
	scan    diagnostic.ServiceScan
	err     string
	done    bool // the scan landed, so an empty Open means "none", not "not yet"
	sel     int
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
	// newQuestion travels with the deferred restart because it is the caller's
	// intent, not a property of the target: a retest and a restart prompt
	// holding the same target want opposite things from the watch session.
	newQuestion bool
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

	networkCIDR string
	lanSource   netip.Addr
	lanBinding  diagnostic.LANBinding
	lanHosts    []diagnostic.LANObservation
	lanLimited  bool
	lanID       string
	lanNames    map[string]lanName
	lanPending  map[string]bool
}

const (
	maxJobLines  = 5000 // ring-buffer cap: older lines become a "discarded" count, not a memory bill
	jobTailLines = 14   // main-screen tail fallback when the terminal height is unknown
	// maxActiveJobs caps live tools. A held-down hotkey repeats the launch.
	maxActiveJobs = 4
	// maxParkedJobs caps the tab ring. Each parked run still owns its output
	// buffer, so an unbounded ring is a memory bill nobody asked for.
	maxParkedJobs = 12
	ctrlCWindow   = 2 * time.Second
	noticeWindow  = 4 * time.Second
	watchRuns     = 20
	ctrlCNotice   = "Press Ctrl+C again to quit"
)

// WatchEvery is the default gap between repeat passes in watch mode, shared so
// the TUI and the headless -json -watch loop can't drift apart. A var so tests
// don't have to sleep through it.
var WatchEvery = 5 * time.Second

// MinWatchInterval is the shortest gap --watch-interval accepts. A shorter one
// would have the probes and the reference services answer every few hundred
// milliseconds.
const MinWatchInterval = time.Second

// ValidateWatchInterval refuses a gap below MinWatchInterval, which covers zero
// and negative durations.
func ValidateWatchInterval(d time.Duration) error {
	if d < MinWatchInterval {
		return fmt.Errorf("-watch-interval must be at least %s, not %s", MinWatchInterval, d)
	}
	return nil
}

// Replaced after each result revision; readers never modify its slices or map.
type resultAnalysis struct {
	order       []diagnostic.ProbeID
	diagnosis   diagnostic.Diagnosis
	collateral  map[diagnostic.ProbeID]bool
	explanation diagnostic.Explanation
}

type model struct {
	target  *diagnostic.Target
	probes  []diagnostic.Probe
	sources *diagnostic.SourceAddresses
	// selection is reapplied whenever a target switch rebuilds the probe DAG.
	selection diagnostic.ProbeSelection
	// graph builds the probe DAG for a target: every target switch and every
	// Watch pass goes through it, so a test can count the graphs a pass builds.
	graph func(*diagnostic.Target) []diagnostic.Probe
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
	// Like started, scheduler is Update-owned across model value copies.
	// A new generation replaces it rather than reusing mutable pass state.
	scheduler     *diagnostic.ProbeScheduler
	analysis      resultAnalysis
	analysisReady bool

	selected int
	// selMoved: the user touched the cursor this run, so completion must not
	// yank it to the first failure.
	selMoved    bool
	networkMap  bool
	mapSelected int
	// svc is the opened device's service list, the step between picking a
	// device on the map and pointing the checks at one endpoint on it.
	svc        serviceChoice
	svcRequest uint64
	spinner    spinner.Model

	generation int
	jobSeq     uint64 // unique job IDs within a run, independent of clock resolution
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

	// Selected check details. The main view keeps the
	// answer pinned while this viewport is the explicit route to evidence that
	// cannot share a short terminal with it.
	detailsViewing bool
	detailsVP      viewport.Model

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

	// Confirm gate: a tool marked Confirm (nmap) is held here after its hotkey,
	// showing the exact command until 'y' runs it or esc cancels.
	confirmTool *Tool

	helping bool // ?: full-screen key cheatsheet
	helpVP  viewport.Model

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

	// SSH credential check (S). verifying is whether the panel is open,
	// verify its state, and verifySeq numbers each panel so a result for one
	// closed meanwhile is dropped.
	verifying bool
	verify    verifyPanel
	verifySeq uint64

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

	toolbox bool // --toolbox: chain deferred until 'r'
	watch   bool
	// watchEvery is the gap this run waits after a completed pass. Zero means
	// WatchEvery, read when the wait is armed.
	watchEvery time.Duration
	// routeEvents says each Watch session the model builds follows the platform's
	// route-change notifications. It is set by WithRouteEvents, so tests that
	// build models never open a netlink socket.
	routeEvents bool
	// watchSession decides which rows a Watch pass reuses, and pass is the pass
	// the current graph belongs to, decided when it completes. Both are nil
	// outside a Watch run.
	watchSession *diagnostic.WatchSession
	pass         *diagnostic.WatchPass
	runHistory   map[diagnostic.ProbeID][]diagnostic.Status
	incidents    incident.Timeline
	// Incident inspection is a small read-only viewer alongside the existing
	// job-output viewer. The timeline itself remains owned by Update.
	incidentViewing  bool
	incidentSelected int
	incidentVP       viewport.Model
	now              func() time.Time

	// updateCheck, when set, asks whether a newer stable release exists. It runs
	// as a command, never in Init, so it cannot delay a probe.
	updateCheck func() update.Result
	// updateLatest is the newer release the header names, "" when there is none.
	updateLatest string

	// notice is one-line feedback from export or the Ctrl+C quit hint.
	notice         string
	noticeOK       bool
	noticeDeadline time.Time

	width, height int
}

// Option adjusts a new model without growing its positional constructor.
type Option func(*model)

// WithUpdateNotice starts one update check when the view opens. check runs in
// a background command, and the header names a newer stable release only when
// check reports one.
func WithUpdateNotice(check func() update.Result) Option {
	return func(m *model) { m.updateCheck = check }
}

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

// WithWatchInterval sets the gap between the passes of this run's Watch. A
// non-positive value leaves WatchEvery in place, like WithProbeTimeout.
func WithWatchInterval(d time.Duration) Option {
	return func(m *model) {
		if d > 0 {
			m.watchEvery = d
		}
	}
}

// WithRouteEvents makes the Watch session follow route, address, link, rule and
// nexthop change notifications where the platform has them. Without it, Watch
// reuses rows only within their max age.
func WithRouteEvents() Option {
	return func(m *model) { m.routeEvents = true }
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
	graph := func(t *diagnostic.Target) []diagnostic.Probe {
		return selection.BuildProbesFromSources(t, sources, publicDNS, publicDNSAuto)
	}
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	m := model{
		target:        t,
		sources:       sources,
		selection:     selection,
		graph:         graph,
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
	if watch {
		m.watchSession = m.newWatchSession()
	}
	m.buildPass()
	// After the options, since one of them names the preference file.
	m.setTheme(loadTheme(m.themePath))
	m.history = loadHistory(histFile)
	if t != nil {
		if n := len(m.history); n == 0 || m.history[n-1] != t.Raw {
			m.history = append(m.history, t.Raw)
		}
		saveHistory(histFile, m.history) // launch targets count as history too
	}
	m.refreshAnalysis()
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
	return m.currentAnalysis().diagnosis
}

func (m model) diagnose() (string, string) {
	d := m.diagnosis()
	return d.Summary, d.Verdict
}

func (m *model) refreshAnalysis() {
	order := diagnostic.ProbeOrder(m.probes)
	d := diagnostic.Interpret(m.target, order, m.results)
	m.analysis = resultAnalysis{order: order, diagnosis: d,
		collateral: d.Collateral(order, m.results), explanation: d.Explain(m.target, order, m.results)}
	m.analysisReady = true
}

// Low-level callers can assemble inputs without Update. A render prepares its
// own copy once; production stores analysis after each write, before rendering.
func (m model) currentAnalysis() resultAnalysis {
	if !m.analysisReady {
		m.refreshAnalysis()
	}
	return m.analysis
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
	cmd := m.chainInit()
	if m.updateCheck == nil {
		return cmd
	}
	check := m.updateCheck
	return tea.Batch(cmd, func() tea.Msg { return updateMsg{res: check()} })
}

func (m model) chainInit() tea.Cmd {
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

// sshDetected reports whether this run found an SSH server to check: the
// banner probe passed, i.e. the port answered with an SSH- identification
// string. A warn is deliberately not enough: that one means the port answered
// with silence, and ssh always speaks first.
func (m model) sshDetected() bool {
	r, ok := m.results[diagnostic.ProbeSSH]
	return ok && r.Status == diagnostic.StatusPass
}

// spinnerActive reports whether the spinner tick chain should keep running for
// probes, jobs, name lookups, or a device's service check.
func (m model) spinnerActive() bool {
	if ((!m.toolbox || m.generation > 0 || m.chainRan()) && !m.allDone()) ||
		m.jobsRunning() || m.svcPending() || (m.verifying && m.verify.busy) {
		return true
	}
	for job := range m.jobs {
		if len(job.lanPending) > 0 {
			return true
		}
	}
	return false
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
		if m.helping {
			m.refreshHelpViewport(false)
		}
		if m.incidentViewing {
			m.refreshIncidentViewport(false)
		}
		if m.viewing {
			m.refreshViewport()
		}
		if m.detailsViewing {
			m.refreshDetailsViewport(false)
		}
		return m, nil

	case tea.KeyMsg:
		if m.helping {
			return m.handleHelpKey(msg)
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
		if m.verifying {
			return m.handleVerifyKey(msg)
		}
		if m.theming {
			return m.handleThemeKey(msg)
		}
		if m.entering {
			return m.handlePromptKey(msg)
		}
		if m.incidentViewing {
			return m.handleIncidentKey(msg)
		}
		if m.detailsViewing {
			return m.handleDetailsKey(msg)
		}
		if m.viewing {
			return m.handleViewKey(msg)
		}
		if m.actionsOpen {
			return m.handleActionsKey(msg)
		}
		return m.handleKey(msg)

	case verifyResolvedMsg, verifyResultMsg, verifyKeysMsg:
		next, cmd, _ := m.handleVerifyMsg(msg)
		return next, cmd
	case updateMsg:
		m.updateLatest = ""
		if msg.res.Status == update.UpdateAvailable {
			m.updateLatest = msg.res.Latest
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
		cmds := m.scheduleStep()
		if !m.analysisReady {
			m.refreshAnalysis()
		}
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
		// The graph is rebuilt, not reused: its route and interface caches
		// belong to the graph, so a reused one would answer this pass from the
		// last one. Headless Watch rebuilds on every pass for the same reason.
		m.applyTarget(m.target, false)
		cmd := m.restartRun()
		if m.viewing {
			m.refreshViewport()
		}
		if m.detailsViewing {
			m.refreshDetailsViewport(false)
		}
		return m, cmd

	case probeDoneMsg:
		if msg.gen != m.generation {
			return m, nil // stale restart
		}
		res := msg.res
		res.ID = msg.id // scheduler identity wins over whatever the probe wrote on its own name tag
		// Keep a value-copied model's results and analysis on the same revision.
		m.results = maps.Clone(m.results)
		m.analysisReady = false
		m.results[msg.id] = res
		if m.scheduler != nil {
			m.scheduler.Complete(res)
		}
		// scheduleStep first: it records skip results synchronously, which can
		// be what completes the run.
		cmds := m.scheduleStep()
		if m.allDone() {
			diagnostic.Finalize(m.results)
		}
		m.refreshAnalysis()
		if m.allDone() && m.pass != nil && !m.pass.Publish(m.results) {
			// The pass reused a row and changed a status or cause, so it is
			// evidence to confirm, not a result: it is not recorded. The next
			// pass runs fresh at once.
			m.applyTarget(m.target, false)
			return m, tea.Batch(append(cmds, m.restartRun())...)
		}
		if m.allDone() {
			// recordRun comes before the focus decision, not after it: a watch
			// pass moves the cursor for what changed since the previous pass,
			// and appending this pass's statuses is what makes the two
			// comparable.
			if m.watch {
				cmds = append(cmds, m.recordRun(), m.watchCmd())
			}
			if !m.selMoved && !m.viewing && !m.detailsViewing {
				if i := m.focusTarget(); i >= 0 {
					m.selected = i
				}
			}
		}
		if m.detailsViewing {
			m.refreshDetailsViewport(false)
		}
		return m, tea.Batch(cmds...)

	case lanBindingMsg:
		if msg.gen != m.generation {
			return m, nil
		}
		job := m.jobByID(msg.job)
		if job == nil {
			return m, nil
		}
		job.lanBinding = msg.binding
		return m, waitForMsg(job.active.ch)

	case ToolOutputMsg:
		if msg.Generation != m.generation {
			return m, nil
		}
		j := m.jobByID(msg.JobID)
		if j == nil {
			return m, nil
		}
		if msg.LAN.IP.IsValid() {
			i := 0
			for i < len(j.lanHosts) && j.lanHosts[i].IP != msg.LAN.IP {
				i++
			}
			if i == len(j.lanHosts) {
				j.lanHosts = append(j.lanHosts, msg.LAN)
			} else {
				j.lanHosts[i] = msg.LAN
			}
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
		done.lanLimited = msg.LANLimited
		done.dur = time.Since(done.start)
		if m.pending != nil && !m.jobsRunning() {
			p := m.pending
			m.pending = nil
			return m.runPending(p)
		}
		if done.lanID != "" && msg.Status == JobDone && len(done.lanHosts) > 0 {
			ips := make([]string, 0, len(done.lanHosts))
			done.lanPending = make(map[string]bool, len(done.lanHosts))
			for _, host := range done.lanHosts {
				ip := host.IP.String()
				ips = append(ips, ip)
				done.lanPending[ip] = true
			}
			ctx, gen := m.ctx, m.generation
			return m, func() tea.Msg {
				names := mergeLANNames(diagnostic.AdvertisedNames(ctx, ips), diagnostic.SSHHostAliases())
				return lanNamesMsg{gen: gen, job: msg.JobID, names: names}
			}
		}
		return m, nil

	case lanNamesMsg:
		if msg.gen != m.generation {
			return m, nil
		}
		job := m.lanJobByID(msg.job)
		if job == nil || len(job.lanPending) == 0 {
			return m, nil
		}
		if job.lanNames == nil {
			job.lanNames = make(map[string]lanName)
		}
		var cmds []tea.Cmd
		for _, host := range job.lanHosts {
			ip := host.IP.String()
			if !job.lanPending[ip] {
				continue
			}
			if name := msg.names[ip]; name.label != "" {
				job.lanNames[ip] = name
				delete(job.lanPending, ip)
				continue
			}
			ctx, gen := m.ctx, m.generation
			cmds = append(cmds, func() tea.Msg {
				return lanNameMsg{gen: gen, job: msg.job, ip: ip, name: diagnostic.ReverseName(ctx, ip)}
			})
		}
		return m, tea.Batch(cmds...)

	case lanServicesMsg:
		if msg.gen != m.generation || msg.job != m.cur.lanID || msg.request != m.svcRequest || m.svc.host == "" {
			return m, nil
		}
		m.svc.scan, m.svc.done, m.svc.sel = msg.scan, true, 0
		if msg.err != nil {
			m.svc.err = textsafe.Clean(msg.err.Error())
		}
		return m, nil

	case lanNameMsg:
		if msg.gen != m.generation {
			return m, nil
		}
		job := m.lanJobByID(msg.job)
		if job == nil || !job.lanPending[msg.ip] {
			return m, nil
		}
		delete(job.lanPending, msg.ip)
		if msg.name != "" {
			job.lanNames[msg.ip] = lanName{label: msg.name}
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

// recordRun records a published pass in the status history, and in the incident
// timeline when the pass measured every row. The timeline keeps passes as
// Before, During, and Recovered, so a reused row there would be an earlier
// measurement presented as this pass's. A pass with a reused row is still shown
// and still counts in the history. It is just not evidence of the whole graph.
func (m *model) recordRun() tea.Cmd {
	for _, p := range m.probes {
		history := append(m.runHistory[p.ID], m.results[p.ID].Status)
		if len(history) > watchRuns {
			history = history[len(history)-watchRuns:]
		}
		m.runHistory[p.ID] = history
	}
	if m.pass != nil && !m.pass.Fresh() {
		return nil
	}
	return m.recordIncident(m.incidentNow())
}

// newWatchSession starts a Watch session for the current target. With route
// events on, it follows the platform's notifications. A platform without them
// keeps the session's max-age bound, so a failed subscription is not an error
// the run has to show.
func (m *model) newWatchSession() *diagnostic.WatchSession {
	s := diagnostic.NewWatchSession(m.now)
	if m.routeEvents {
		_ = s.FollowRouteEvents()
	}
	return s
}

// buildPass builds the probe graph for the current target. In a Watch run the
// graph is wrapped by a new pass, which decides when its results are shown.
func (m *model) buildPass() {
	probes := m.graph(m.target)
	m.pass = nil
	if m.watchSession != nil {
		m.pass = m.watchSession.Begin(probes, m.probeTimeout)
		probes = m.pass.Probes()
	}
	m.probes = probes
}

func (m model) watchCmd() tea.Cmd {
	gen := m.generation
	return tea.Tick(m.watchInterval(), func(time.Time) tea.Msg { return watchMsg{gen: gen} })
}

// watchInterval is the gap this run waits after a completed pass.
func (m model) watchInterval() time.Duration {
	return cmp.Or(m.watchEvery, WatchEvery)
}
