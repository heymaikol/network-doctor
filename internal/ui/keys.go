// Key handling and the actions keys dispatch: restarts, tool launches, and
// job selection/cancellation. Handlers take a value receiver and return the
// updated model; the action helpers take a pointer and mutate in place.

package ui

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/incident"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// resolveKey folds msg into whatever chord is already in flight and resolves
// the result in ctx. It returns the action to run (actNone for none) and the
// prefix still waiting for its next key.
func (m model) resolveKey(ctx keyContext, key string) (keyAction, []string) {
	seq := append(slices.Clone(m.pendingKeys), key)
	if act, ok := m.keys.lookup(ctx, seq); ok {
		return act, nil
	}
	if m.keys.isPrefix(ctx, seq) {
		return actNone, seq
	}
	// The key that killed a chord still gets the turn it would have had alone.
	if len(m.pendingKeys) > 0 {
		if act, ok := m.keys.lookup(ctx, []string{key}); ok {
			return act, nil
		}
		if m.keys.isPrefix(ctx, []string{key}) {
			return actNone, []string{key}
		}
	}
	return actNone, nil
}

// quit is the stop-everything path, reached by its binding and by the second
// Ctrl+C. Running jobs are cancelled first and the quit deferred until their
// terminal events land.
func (m model) quit() (tea.Model, tea.Cmd) {
	if m.jobsRunning() {
		m.cancelJobs() // non-blocking; quit after every terminal event
		m.pending = &pendingAction{kind: pendQuit}
		return m, m.setNotice("stopping jobs, then quitting", true)
	}
	m.clearCancel()
	return m, tea.Quit
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	act, pending := m.resolveKey(ctxList, msg.String())
	m.pendingKeys = pending
	if act == actNone {
		// A chord waiting for its next key owns the keyboard, or a tool hotkey would
		// fork a subprocess on the way to a movement key. A chord that just died is
		// not waiting: resolveKey has already given the key that killed it its turn.
		if len(pending) > 0 {
			return m, nil
		}
		// Tool hotkeys are checked after built-in actions.
		if tool, ok := m.toolForKey(msg.String()); ok {
			return m.runTool(tool)
		}
		return m, nil
	}
	return m.runAction(act)
}

// toolForKey is the tool half of dispatch: the tool a key runs, if any. Every
// caller resolves the built-in actions first, so a tool hotkey can never shadow one.
func (m model) toolForKey(key string) (Tool, bool) {
	for _, tool := range m.tools {
		if tool.Key == key {
			return tool, true
		}
	}
	return Tool{}, false
}

// runTool starts a tool, or holds it at the confirm gate when it is one of the
// active scans that has to show its command first. Both the hotkey and the
// Actions menu come through here, so neither can skip the gate.
func (m model) runTool(tool Tool) (tea.Model, tea.Cmd) {
	if tool.Confirm {
		t := tool // hold for the confirm gate; run happens on 'y'
		m.confirmTool = &t
		return m, nil
	}
	return m, m.launchTool(tool)
}

// runAction performs one resolved action. It is split from handleKey because a
// key is not the only way to ask for one: the Actions menu runs its selected
// row through this same switch rather than owning a dispatch of its own.
func (m model) runAction(act keyAction) (tea.Model, tea.Cmd) {
	switch act {
	case actQuit:
		return m.quit()
	case actRestart:
		// Open the restart prompt; an active job keeps streaming until Enter commits.
		m.entering, m.sshPrompt, m.inputErr = true, false, ""
		ti := textinput.New()
		ti.Prompt = "netdoc "
		ti.Placeholder = "example.com:443, or empty for a general check"
		ti.PromptStyle = m.st.key
		if m.target != nil {
			ti.SetValue(m.target.Raw)
		}
		m.histIdx, m.histDraft = len(m.history), ""
		ti.Focus()
		ti.CursorEnd()
		m.input = ti
		return m, textinput.Blink
	case actRetest:
		return m.retest()
	case actSSH:
		// The SSH login form is offered for every target, unlike the 'c'
		// handshake check, which only fits an SSH one. It logs in to the
		// machine under test, so it needs a target and takes the host from it.
		if m.target == nil {
			return m, m.setNotice("SSH needs a target: press r to set one", false)
		}
		if _, err := toolLookPath("ssh"); err != nil {
			return m, m.setNotice("ssh not found: install an OpenSSH client", false)
		}
		m.sshPrompt, m.ssh = true, newSSHForm(m.st, m.target)
		return m, textinput.Blink
	case actNetworkMap:
		if m.networkMap {
			m.networkMap = false
			return m, nil
		}
		if m.cur.name == lanDiscoveryName {
			m.networkMap = true
			return m, nil
		}
		// A scan parked in the ring still has a map; re-show it instead of
		// gating a fresh sweep.
		for i := range m.otherJobs {
			if m.otherJobs[i].name != lanDiscoveryName {
				continue
			}
			m.selectJob(i)
			m.networkMap = true
			return m, nil
		}
		_, cidr := m.discoveryNetwork()
		if cidr == "" {
			return m, m.setNotice("local private IPv4 network not available yet", false)
		}
		tool := lanDiscoveryTool(quoterFor(runtime.GOOS), cidr)
		if _, err := toolLookPath(tool.Bin); err != nil {
			return m, m.setNotice("network discovery needs nmap", false)
		}
		tool.Available = true
		m.networkCIDR = cidr
		// Same confirm gate as nmap: a /24 sweep is an active scan too.
		m.confirmTool = &tool
		return m, nil
	case actExpand:
		// Presentation only: what the Checks panel draws, never
		// what ran, what the diagnosis concluded, or what the report carries.
		m.expanded = !m.expanded
		return m, nil
	case actExplain:
		d := m.diagnosis()
		if !m.allDone() || len(d.Findings) == 0 || len(d.Findings[0].Evidence) == 0 {
			return m, m.setNotice("no diagnosis explanation is available yet", false)
		}
		m.explaining = !m.explaining
		if m.explaining {
			if i := m.focusRow(); i >= 0 {
				m.selected = i
			}
		}
		return m, nil
	case actIncidents:
		if !m.watch {
			return m, m.setNotice("incident history is available in watch mode", false)
		}
		if len(m.incidents.Incidents()) == 0 {
			return m, m.setNotice("no incidents recorded", false)
		}
		m.openIncidentViewer()
		return m, nil
	case actCancelJob:
		// On an opened device, esc is the way back to the device list before
		// it is anything else: the job it would otherwise cancel is the
		// finished scan that produced that list.
		if m.networkMap && m.svc.host != "" {
			m.svc = serviceChoice{}
			return m, nil
		}
		// Cancel only the focused job (tab picks which); quit remains the
		// nuke-everything path. The terminal event arrives as JobCanceled.
		if m.cur.active != nil && m.cur.active.cancel != nil {
			m.cur.active.cancel()
			return m, m.setNotice("canceling "+m.cur.name, true)
		}
		return m, nil
	case actSwitchJob:
		return m, m.switchJob()
	case actUp:
		m.explaining = false
		if m.networkMap {
			m.moveMap(-1)
			return m, nil
		}
		m.moveRow(-1)
		return m, nil
	case actDown:
		m.explaining = false
		if m.networkMap {
			m.moveMap(1)
			return m, nil
		}
		m.moveRow(1)
		return m, nil
	case actTop:
		m.explaining = false
		if m.networkMap {
			at, _ := m.mapCursor()
			*at = 0
			return m, nil
		}
		m.moveRow(-len(m.probes))
		return m, nil
	case actBottom:
		m.explaining = false
		if m.networkMap {
			at, n := m.mapCursor()
			*at = max(n-1, 0)
			return m, nil
		}
		m.moveRow(len(m.probes))
		return m, nil
	case actOpen:
		// Two steps, because a device is not an endpoint: the first opens the
		// selected device and asks it which services it has, the second points
		// the checks at one of them.
		if m.networkMap {
			if m.svc.host != "" {
				return m.diagnoseService()
			}
			if hosts := m.networkHosts(); len(hosts) > 0 {
				m.mapSelected = min(m.mapSelected, len(hosts)-1)
				return m.openDevice(hosts[m.mapSelected])
			}
		}
		if !m.hasJob() {
			return m, m.setNotice("nothing to view yet", false)
		}
		m.viewing, m.follow = true, true
		m.vp = viewport.New(m.width, m.vpHeight())
		// handleViewKey dispatches the viewer through the bindings; leaving the
		// viewport's built-in map armed would give b/f/space/u/d a second owner.
		m.vp.KeyMap = viewport.KeyMap{}
		m.refreshViewport()
		return m, nil
	case actCopy, actSave:
		if portalURL := m.selectedPortalURL(); portalURL != "" && act == actCopy {
			notice, ok := "portal URL sent to clipboard (OSC 52)", true
			if err := copyReport(portalURL); err != nil {
				notice, ok = "copy failed: "+err.Error(), false
			}
			return m, m.setNotice(notice, ok)
		}
		if !m.reportReady() {
			return m, m.setNotice("report not ready until checks finish", false)
		}
		notice, ok := exportReport(m.report(), act == actSave)
		return m, m.setNotice(notice, ok)
	case actTheme:
		// The picker is drawn where the help bar goes, so the run behind it
		// stays on screen: that screen is the preview.
		m.theming, m.themeWas = true, m.theme
		m.themeSel = themeIndex(m.theme.Name)
		return m, nil
	case actActions:
		m.actionsOpen, m.actionsSel = true, 0
		return m, nil
	case actHelp:
		m.helping = true
		return m, nil
	}
	return m, nil
}

// mapCursor is the network map's cursor and the length of the list it walks:
// the opened device's services when one is showing, the discovered devices
// otherwise. Returned as a pointer so the movement keys stay one branch rather
// than one per list.
func (m *model) mapCursor() (*int, int) {
	if m.svc.host != "" {
		return &m.svc.sel, len(m.svc.scan.Open)
	}
	return &m.mapSelected, len(m.networkHosts())
}

// moveMap walks the map's cursor by delta and clamps it at both ends.
func (m *model) moveMap(delta int) {
	at, n := m.mapCursor()
	*at = min(max(*at+delta, 0), max(n-1, 0))
}

// discoverServices is the seam the device step dials through, so the model's
// own tests can drive the whole flow without a network under them.
var discoverServices = diagnostic.DiscoverServices

// openDevice asks one discovered device which of the common service ports it
// answers on, so the endpoint the checks run against comes from the device
// rather than from a default port that has nothing to do with it.
//
// row is a line the LAN scan printed, and it is parsed rather than trusted:
// past this point the address is a target like any other.
func (m model) openDevice(row string) (tea.Model, tea.Cmd) {
	address, _, _ := strings.Cut(row, " ")
	t, err := diagnostic.ParseTarget(address)
	if err != nil {
		return m, m.setNotice("invalid discovered device: "+err.Error(), false)
	}
	wasTicking := m.spinnerActive()
	m.svc = serviceChoice{host: t.Host, name: row}
	// The scan can be the first thing a --toolbox session does, before any
	// generation context exists, so initialize it lazily as launchTool does.
	if m.ctx == nil {
		m.ctx, m.cancel = context.WithCancel(context.Background())
	}
	ctx, gen, host, sources, timeout := m.ctx, m.generation, t.Host, m.sources, m.probeTimeout
	cmd := func() tea.Msg {
		return lanServicesMsg{gen: gen, host: host, scan: discoverServices(ctx, sources, host, timeout)}
	}
	if wasTicking {
		return m, cmd
	}
	return m, tea.Batch(cmd, m.spinner.Tick)
}

// diagnoseService restarts the checks against the selected service on the
// opened device. The endpoint is spelled the way a person would type it and
// re-parsed, so a service found here reaches the probe DAG through the same
// target grammar and the same protocol inference as one typed at the prompt.
func (m model) diagnoseService() (tea.Model, tea.Cmd) {
	open := m.svc.scan.Open
	if len(open) == 0 {
		return m, m.setNotice("no service answered on "+m.svc.host+": press "+m.keys.label(ctxList, actRestart)+" to name a port yourself", false)
	}
	svc := open[min(m.svc.sel, len(open)-1)]
	t, err := diagnostic.ParseTarget(svc.Target(m.svc.host))
	if err != nil {
		return m, m.setNotice("invalid discovered target: "+err.Error(), false)
	}
	return m.restartWithTarget(t)
}

// moveRow walks the cursor delta rows through the Checks panel's row list and
// clamps it at both ends. It steps through that list rather than through
// m.probes, because a probe with no row of its own is not a place the cursor
// can stop: the Details panel would be left describing a row the reader cannot
// see or move off. A delta wider than the list is how top and bottom are spelled.
//
// The cursor stays an index into m.probes, so an empty list leaves it where it
// was rather than selecting row -1; the check list is empty for as long as the
// first probe takes to arrive.
func (m *model) moveRow(delta int) {
	m.selMoved = true
	rows := m.checkRows()
	if len(rows) == 0 {
		return
	}
	at := slices.Index(rows, m.selected)
	if at < 0 {
		at = 0 // cursor on a rowless probe: the row list is where it belongs
	}
	m.selected = rows[min(max(at+delta, 0), len(rows)-1)]
}

// handleConfirmKey handles keys while an advanced tool's command is shown: 'y'
// runs it (deferred if a job is still live), esc cancels, and anything else is
// ignored, since a stray j/k mid-browse shouldn't silently eat the prompt.
func (m model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y":
		tool := *m.confirmTool
		m.confirmTool = nil
		return m, m.launchTool(tool)
	case "esc", "ctrl+c":
		m.confirmTool = nil
	}
	return m, nil
}

// handleThemeKey drives the theme picker. Moving the cursor applies the
// highlighted theme at once, so the screen behind the picker is the preview;
// enter keeps it and writes the preference; esc puts back the theme that was
// active when the picker opened. Nothing here touches probes, results, or the
// diagnosis: the picker only repaints what is already on screen.
func (m model) handleThemeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.themeSel = max(m.themeSel-1, 0)
		m.setTheme(themes[m.themeSel])
	case "down", "j":
		m.themeSel = min(m.themeSel+1, len(themes)-1)
		m.setTheme(themes[m.themeSel])
	case "enter":
		m.theming = false
		saveTheme(m.themePath, m.theme.Name)
		return m, m.setNotice("theme: "+m.theme.Name, true)
	case "esc":
		m.theming = false
		m.setTheme(m.themeWas)
	}
	return m, nil
}

// handleViewKey handles keys while the output viewport is open. Everything not
// handled here scrolls the viewport; leaving the bottom disables follow mode.
func (m model) handleViewKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.filtering {
		switch msg.String() {
		case "esc":
			m.filtering = false
			m.filter = ""
			m.refreshViewport()
			return m, nil
		case "enter":
			m.filtering = false
			return m, nil
		}
		var cmd tea.Cmd
		m.filterInput, cmd = m.filterInput.Update(msg)
		m.filter = m.filterInput.Value()
		m.refreshViewport()
		return m, cmd
	}
	act, pending := m.resolveKey(ctxViewer, msg.String())
	m.pendingKeys = pending
	switch act {
	case actClearFilter:
		if m.filter != "" {
			// A filter is cleared before the viewer is left, so the key that
			// removes it doesn't also throw away the output it was hiding.
			m.filter = ""
			m.refreshViewport()
			return m, nil
		}
		fallthrough
	case actBack:
		m.viewing = false
		m.filter = "" // a stale filter reopening as a blank screen reads as lost output
		return m, nil
	case actFilter:
		m.filtering = true
		ti := textinput.New()
		ti.Prompt = "/"
		ti.PromptStyle = m.st.key
		ti.SetValue(m.filter)
		ti.Focus()
		ti.CursorEnd()
		m.filterInput = ti
		m.refreshViewport()
		return m, textinput.Blink
	case actCopy:
		notice, ok := "output sent to clipboard (OSC 52)", true
		if m.keys.bound(ctxViewer, actSave) {
			notice += "; " + m.keys.label(ctxViewer, actSave) + " saves a file"
		}
		if err := copyReport(strings.Join(m.visibleJobLines(), "\n")); err != nil {
			notice, ok = "copy failed: "+err.Error(), false
		}
		return m, m.setNotice(notice, ok)
	case actSave:
		notice, ok := exportReport(strings.Join(m.visibleJobLines(), "\n"), true)
		notice = strings.Replace(notice, "report saved", "output saved", 1)
		return m, m.setNotice(notice, ok)
	case actTop:
		m.vp.GotoTop()
		m.follow = false
		return m, nil
	case actBottom:
		m.vp.GotoBottom()
		m.follow = true
		return m, nil
	case actSwitchJob:
		return m, m.switchJob()
	// Scrolling reads follow back off the viewport rather than setting it:
	// any move that happens to land on the last line resumes following, and
	// the amount a key scrolls is the viewport's business, not this switch's.
	case actUp:
		m.vp.ScrollUp(1)
	case actDown:
		m.vp.ScrollDown(1)
	case actPageUp:
		m.vp.PageUp()
	case actPageDown:
		m.vp.PageDown()
	case actHalfPageUp:
		m.vp.HalfPageUp()
	case actHalfPageDown:
		m.vp.HalfPageDown()
	default:
		return m, nil
	}
	m.follow = m.vp.AtBottom()
	return m, nil
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
		if v := strings.TrimSpace(m.input.Value()); v != "" {
			if n := len(m.history); n == 0 || m.history[n-1] != v {
				m.history = append(m.history, v)
				saveHistory(m.histPath, m.history)
			}
		}
		m.entering = false
		return m.restartWithTarget(t)
	case "up":
		if m.histIdx == 0 {
			return m, nil
		}
		if m.histIdx == len(m.history) {
			m.histDraft = m.input.Value()
		}
		m.histIdx--
		m.input.SetValue(m.history[m.histIdx])
		m.input.CursorEnd()
		return m, nil
	case "down":
		if m.histIdx >= len(m.history) {
			return m, nil
		}
		m.histIdx++
		if m.histIdx == len(m.history) {
			m.input.SetValue(m.histDraft)
		} else {
			m.input.SetValue(m.history[m.histIdx])
		}
		m.input.CursorEnd()
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.inputErr = ""
	return m, cmd
}

// retest reruns the diagnosis the user is already looking at, which is the
// other half of remediation: act on the advice, then ask the same question
// again. It is deliberately the same restart path a new target takes, so a
// retest inherits the whole of it: the generation bump that makes the previous
// run's in-flight probe and job messages bounce, the cancellation of the
// generation context, the cleared results, and the deferral until a running
// tool's terminal event lands. What it does not do is ask for a target, so
// every part of the run configuration stays exactly as it was.
//
// The notice is set after the restart, since doRestart clears the last one on
// its way out, and it is the only thing on screen that says a second run
// started: the checks it reruns are the same ones that were already listed.
func (m model) retest() (tea.Model, tea.Cmd) {
	next, cmd := m.restartWithTarget(m.target)
	restarted, ok := next.(model)
	if !ok {
		return next, cmd
	}
	what := "the general checks"
	if restarted.target != nil {
		what = restarted.targetHP()
	}
	notice := restarted.setNotice("retesting "+what, true)
	return restarted, tea.Batch(cmd, notice)
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
		return nil, errors.New("flags aren't supported here: enter a target")
	}
	return diagnostic.ParseTarget(fields[0])
}

// applyTarget swaps the run target and rebuilds its probes.
func (m *model) applyTarget(t *diagnostic.Target) {
	m.target = t
	m.probes = m.selection.BuildProbesFromSources(t, m.sources, m.publicDNS, m.publicDNSAuto)
	m.selected = 0
	m.runHistory = map[diagnostic.ProbeID][]diagnostic.Status{}
	m.incidents = incident.Timeline{}
	m.incidentViewing, m.incidentSelected = false, 0
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
	m.tools = toolsFor(m.target, runtime.GOOS, bindFor(m.sources))
	m.generation++
	m.selMoved = false
	m.explaining = false
	m.results = map[diagnostic.ProbeID]diagnostic.ProbeResult{}
	m.started = map[diagnostic.ProbeID]bool{}
	m.pending, m.confirmTool, m.sshPrompt = nil, nil, false
	m.dropJobs()
	m.networkMap, m.mapSelected, m.networkCIDR = false, 0, ""
	m.svc = serviceChoice{}
	m.hostNames, m.namesPending = nil, nil
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
	// Refuse before stashing: stashJob clears the slot, so a late bail would
	// blank the pane the user is looking at. A missing binary spawns nothing,
	// so "not found" still gets through at the limit.
	if tool.Available && m.runningJobs() >= maxActiveJobs {
		return m.setNotice(fmt.Sprintf("%d tools already running: wait for one to finish", maxActiveJobs), false)
	}
	m.stashJob()
	m.networkMap = tool.Key == "v"
	if m.networkMap {
		// A fresh sweep replaces the device list, so whatever device was open
		// on the last one is not a row of this one.
		m.mapSelected, m.svc = 0, serviceChoice{}
	}
	if !tool.Available {
		m.cur.name, m.cur.status = tool.Name, JobFailed
		m.cur.lines, m.cur.dropped, m.cur.evicted = []string{tool.Bin + " not found: install it"}, 0, 0
		m.cur.dur = 0
		m.cur.display = tool.Name
		return nil
	}
	wasTicking := m.spinnerActive()
	args, env, display := tool.Build(m.target, m.selectedIP())
	id := fmt.Sprintf("%s-%d-%d", tool.Key, m.generation, time.Now().UnixNano())
	// Toolbox mode: a tool can launch before the first 'r' creates the
	// generation context, so initialize it lazily, exactly as scheduleMsg does.
	if m.ctx == nil {
		m.ctx, m.cancel = context.WithCancel(context.Background())
	}
	j, cmd, err := startTool(m.ctx, m.generation, id, tool.Bin, args, env, tool.Timeout)
	if err != nil {
		m.cur.name, m.cur.status = tool.Name, JobFailed
		m.cur.lines, m.cur.dropped, m.cur.evicted = []string{textsafe.Clean(err.Error())}, 0, 0
		m.cur.display, m.cur.dur = display, 0
		return nil
	}
	m.cur.active, m.cur.status = j, JobRunning
	m.cur.lines, m.cur.dropped, m.cur.evicted = nil, 0, 0
	if m.viewing {
		m.refreshViewport()
	}
	m.cur.name, m.cur.display, m.cur.start = tool.Name, display, time.Now()
	if !wasTicking {
		return tea.Batch(cmd, m.spinner.Tick)
	}
	return cmd
}
