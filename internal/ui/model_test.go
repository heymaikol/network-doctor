package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func asModel(t *testing.T, m tea.Model) model {
	t.Helper()
	mm, ok := m.(model)
	if !ok {
		t.Fatalf("expected model, got %T", m)
	}
	return mm
}

func newModel(t *diagnostic.Target, toolbox bool) model { return New(t, toolbox).(model) }

func keyMsg(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

func TestReportReadyWithoutToolRun(t *testing.T) {
	m := newModel(nil, false)
	doneResults(&m, "")
	if !m.reportReady() {
		t.Error("completed checks must be exportable without running a tool")
	}
}

// A probeDoneMsg from a stale generation is dropped (mirrors the gen guard).
func TestStaleProbeDropped(t *testing.T) {
	m := newModel(nil, false)
	m.generation = 5
	u, cmd := m.Update(probeDoneMsg{id: diagnostic.ProbeIface, gen: 0, res: diagnostic.ProbeResult{Status: diagnostic.StatusPass}})
	nm := asModel(t, u)
	if _, ok := nm.results[diagnostic.ProbeIface]; ok {
		t.Error("stale probe must not store a result")
	}
	if cmd != nil {
		t.Error("stale probe must issue no cmd")
	}
}

// The nmap hotkey holds the exact command in a confirm gate instead of
// launching; the gate shows the command, and any non-'y' key cancels without
// ever starting a scan.
func TestNmapConfirmGate(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	u, cmd := m.Update(keyMsg("n"))
	nm := asModel(t, u)
	if nm.confirmTool == nil || nm.confirmTool.Key != "n" {
		t.Fatal("n must open the confirm gate for nmap")
	}
	if nm.activeJob != nil || cmd != nil {
		t.Error("confirm gate must not launch a job yet")
	}
	if !strings.Contains(nm.View(), "nmap ") {
		t.Error("confirm gate must show the nmap command before running")
	}
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	nm = asModel(t, u)
	if nm.confirmTool != nil {
		t.Error("ctrl+c must close the confirm gate")
	}
	if nm.activeJob != nil {
		t.Error("ctrl+c must not launch a scan")
	}
}

// 'r' opens the restart prompt; Enter bumps the generation, clears run state,
// and resets the context.
func TestRestartResets(t *testing.T) {
	m := newModel(nil, false)
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.started[diagnostic.ProbeIface] = true
	gen0 := m.generation
	u, _ := m.Update(keyMsg("r"))
	nm := asModel(t, u)
	if !nm.entering {
		t.Fatal("r must open the restart prompt")
	}
	u, cmd := nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm = asModel(t, u)
	if nm.entering {
		t.Error("enter must close the prompt")
	}
	if nm.generation != gen0+1 {
		t.Errorf("generation = %d, want %d", nm.generation, gen0+1)
	}
	if len(nm.results) != 0 || len(nm.started) != 0 {
		t.Error("restart must clear results/started")
	}
	if nm.ctx != nil {
		t.Error("restart must reset ctx to nil")
	}
	if cmd == nil {
		t.Fatal("restart must issue a cmd")
	}
}

// The restart prompt: prefilled with the current target, esc cancels, a bad
// line errors and stays open, a good line swaps the target and restarts.
// It is titled "Restart" and shows the target-forms cheatsheet: before any
// WindowSizeMsg (height 0 = size unknown), on a roomy terminal, and alongside
// a validation error.
func TestRestartPrompt(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), false)
	u, _ := m.Update(keyMsg("r"))
	nm := asModel(t, u)
	if !nm.entering {
		t.Fatal("r must open the restart prompt")
	}
	if nm.input.Value() != "github.com" {
		t.Errorf("prefill = %q, want github.com", nm.input.Value())
	}
	if !strings.Contains(nm.View(), "network-doctor") {
		t.Error("prompt view must show the command line")
	}
	if !strings.Contains(nm.View(), "Restart") {
		t.Error("prompt panel must be titled Restart")
	}
	// Width is 0 here, so the panel wraps hard; assert the five example
	// targets (short tokens survive word wrap) rather than whole lines.
	for _, form := range []string{"example.com", "example.com:8022", "https://example.com/x", "192.0.2.1", "[2001:db8::1]:443", "(nothing)"} {
		if !strings.Contains(nm.View(), form) {
			t.Errorf("prompt before WindowSizeMsg must show target form %q", form)
		}
	}

	// On a roomy terminal the panel is 88 wide and each form line renders
	// unwrapped, annotation and all.
	u, _ = nm.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	nm = asModel(t, u)
	formLines := []string{
		"example.com            hostname (default port 443)",
		"example.com:8022       hostname with port (protocol inferred from the port)",
		"https://example.com/x  URL (scheme sets protocol and default port; path ignored)",
		"192.0.2.1, 2001:db8::1 IP literal",
		"[2001:db8::1]:443      IP literal with port (IPv6 needs the brackets)",
		"(nothing)              no target — runs the generic checks",
	}
	for _, line := range formLines {
		if !strings.Contains(nm.View(), line) {
			t.Errorf("roomy prompt must show form line %q", line)
		}
	}

	// A validation error joins the forms; it must not displace them.
	nm.input.SetValue("one two")
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	errView := asModel(t, u).View()
	if !strings.Contains(errView, "one target only") {
		t.Error("bad line must show the validation error")
	}
	for _, line := range formLines {
		if !strings.Contains(errView, line) {
			t.Errorf("forms must stay visible alongside the error, missing %q", line)
		}
	}

	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if esc := asModel(t, u); esc.entering || esc.generation != 0 {
		t.Error("esc must close the prompt without a restart")
	}

	nm.input.SetValue("one two")
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	bad := asModel(t, u)
	if !bad.entering || bad.inputErr == "" {
		t.Error("a bad line must keep the prompt open with an error")
	}

	bad.input.SetValue("network-doctor example.com:22")
	u, cmd := bad.Update(tea.KeyMsg{Type: tea.KeyEnter})
	good := asModel(t, u)
	if good.entering {
		t.Error("a good line must close the prompt")
	}
	if good.target == nil || good.target.Host != "example.com" || good.target.Port != 22 {
		t.Errorf("target = %+v, want example.com:22", good.target)
	}
	if good.generation != 1 || cmd == nil {
		t.Error("commit must restart")
	}
}

func TestQuit(t *testing.T) {
	m := newModel(nil, false)
	u, cmd := m.Update(keyMsg("q"))
	_ = asModel(t, u)
	if cmd == nil {
		t.Fatal("quit must return a cmd")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg, got %T", cmd())
	}
}

func TestViewerEscAndQGoBack(t *testing.T) {
	m := newModel(nil, false)
	m.jobStatus = JobDone
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm := asModel(t, u)
	if got := nm.View(); !strings.Contains(got, keyStyle.Render("esc/q")) {
		t.Errorf("viewer footer must offer esc/q back, got %q", got)
	}

	u, cmd := nm.Update(keyMsg("q"))
	nm = asModel(t, u)
	if nm.viewing || cmd != nil {
		t.Error("q in viewer must go back")
	}
	u, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm = asModel(t, u)
	u, cmd = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	nm = asModel(t, u)
	if nm.viewing || cmd != nil {
		t.Error("esc in viewer must go back")
	}
}

func TestViewerCopiesFullOutput(t *testing.T) {
	oldLookPath, oldRun := clipboardLookPath, clipboardRun
	t.Cleanup(func() { clipboardLookPath, clipboardRun = oldLookPath, oldRun })
	clipboardLookPath = func(string) (string, error) { return "wl-copy", nil }
	var copied string
	clipboardRun = func(_ string, _ []string, output string) error {
		copied = output
		return nil
	}

	m := newModel(nil, false)
	m.jobStatus = JobDone
	m.jobLines = []outLine{{text: "first"}, {stderr: true, text: "second"}}
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm := asModel(t, u)
	if !strings.Contains(nm.View(), keyStyle.Render("y")) {
		t.Fatal("viewer footer must offer y to copy output")
	}

	u, cmd := nm.Update(keyMsg("y"))
	nm = asModel(t, u)
	if copied != "first\nsecond" || cmd == nil || nm.notice != "output copied to clipboard" {
		t.Fatalf("copied = %q, notice = %q, cmd nil = %v", copied, nm.notice, cmd == nil)
	}
}

func TestCtrlCWarnsThenQuits(t *testing.T) {
	m := newModel(nil, false)
	canceled := false
	m.activeJob = &job{cancel: func() { canceled = true }}

	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	nm := asModel(t, u)
	if cmd == nil {
		t.Fatal("first ctrl+c must schedule the notice timeout")
	}
	if canceled {
		t.Error("first ctrl+c must not cancel the active job")
	}
	if nm.pending != nil {
		t.Errorf("first ctrl+c pending action = %v, want nil", nm.pending.kind)
	}
	if !strings.Contains(nm.View(), "Press Ctrl+C again (or q) to quit") {
		t.Error("first ctrl+c must show the quit hint")
	}

	expired, _ := nm.Update(noticeDoneMsg{deadline: nm.ctrlCDeadline})
	if strings.Contains(asModel(t, expired).View(), "Press Ctrl+C again (or q) to quit") {
		t.Error("quit hint must clear after the timeout")
	}

	nm.activeJob = nil
	u, cmd = nm.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	_ = asModel(t, u)
	if cmd == nil {
		t.Fatal("second ctrl+c must quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("second ctrl+c command = %T, want tea.QuitMsg", cmd())
	}
}

func TestReportNoticeExpires(t *testing.T) {
	oldLookPath, oldRun := clipboardLookPath, clipboardRun
	t.Cleanup(func() { clipboardLookPath, clipboardRun = oldLookPath, oldRun })
	clipboardLookPath = func(string) (string, error) { return "wl-copy", nil }
	clipboardRun = func(string, []string, string) error { return nil }

	m := newModel(nil, false)
	doneResults(&m, "")
	u, cmd := m.Update(keyMsg("y"))
	nm := asModel(t, u)
	if cmd == nil || nm.notice != "report copied to clipboard" {
		t.Fatalf("copy notice = %q, cmd nil = %v", nm.notice, cmd == nil)
	}

	expired, _ := nm.Update(noticeDoneMsg{deadline: nm.noticeDeadline})
	if got := asModel(t, expired).notice; got != "" {
		t.Errorf("notice after timeout = %q, want empty", got)
	}
}

// scheduleMsg creates the generation context and dispatches only the root probe.
func TestScheduleStartsRoot(t *testing.T) {
	m := newModel(nil, false)
	u, cmd := m.Update(scheduleMsg{gen: 0})
	nm := asModel(t, u)
	if nm.ctx == nil {
		t.Error("scheduleMsg must create the generation context")
	}
	if !nm.started[diagnostic.ProbeIface] {
		t.Error("iface (root) should be dispatched")
	}
	if nm.started[diagnostic.ProbeInternet] || nm.started[diagnostic.ProbeDNS] {
		t.Error("dependants of iface must wait")
	}
	if cmd == nil {
		t.Error("expected a dispatch cmd")
	}
}

func TestSelectionClamp(t *testing.T) {
	m := newModel(nil, false) // 4 rows
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if asModel(t, u).selected != 0 {
		t.Error("up at top must stay 0")
	}
	for i := 0; i < 5; i++ {
		u, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = asModel(t, u)
	}
	if m.selected != 3 {
		t.Errorf("selected = %d, want clamp at 3", m.selected)
	}
	u, _ = m.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp})
	m = asModel(t, u)
	if m.selected != 2 {
		t.Errorf("wheel up selected = %d, want 2", m.selected)
	}
	u, _ = m.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	if selected := asModel(t, u).selected; selected != 3 {
		t.Errorf("wheel down selected = %d, want 3", selected)
	}
}

func TestExitCode(t *testing.T) {
	m := newModel(nil, false)
	if ExitCode(m) != 1 {
		t.Error("unfinished chain must exit 1")
	}
	for _, probe := range m.probes {
		m.results[probe.ID] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	}
	if ExitCode(m) != 0 {
		t.Error("all-pass must exit 0")
	}
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{Status: diagnostic.StatusFail}
	if ExitCode(m) != 1 {
		t.Error("a fail must exit 1")
	}
}

// Runes batched into one KeyMsg by a fast stdin read ("xxr") are replayed one
// key at a time instead of matching no binding and being dropped.
func TestBatchedRunesReplayed(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	u, _ := m.Update(keyMsg("xxr"))
	nm := asModel(t, u)
	if !nm.entering {
		t.Error("batched xxr not replayed; trailing r should open the restart prompt")
	}
}

// Enter opens the output viewer while a job is running even before any output
// has arrived (e.g. mtr --report buffers everything until exit).
func TestEnterViewerBeforeOutput(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.activeJob = &job{}
	m.jobStatus = JobRunning
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm := asModel(t, u)
	if !nm.viewing {
		t.Fatal("enter must open the viewer for a running job with no output yet")
	}
	if !strings.Contains(nm.View(), "no output yet") {
		t.Error("empty viewer must show the (no output yet) placeholder")
	}
}

// A running job with lots of output must never grow the view past the
// terminal height: the renderer drops the top lines, which reads as the
// whole UI scrolling.
func TestViewFitsTerminal(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.jobStatus = JobRunning
	m.jobDisplay = "ping example.com"
	for range 200 {
		m.jobLines = append(m.jobLines, outLine{text: "reply from 1.2.3.4"})
	}
	for _, size := range []tea.WindowSizeMsg{
		{Width: 120, Height: 40},
		{Width: 100, Height: 24},
		{Width: 80, Height: 20},
	} {
		u, _ := m.Update(size)
		nm := asModel(t, u)
		if rows := strings.Count(nm.View(), "\n") + 1; rows > nm.height {
			t.Errorf("%dx%d: view is %d rows, terminal is %d", size.Width, size.Height, rows, nm.height)
		}
	}
	// Same invariant with the restart prompt (and its forms cheatsheet) open.
	for _, size := range []tea.WindowSizeMsg{
		{Width: 120, Height: 40},
		{Width: 100, Height: 24},
	} {
		u, _ := m.Update(size)
		nm := asModel(t, u)
		u, _ = nm.Update(keyMsg("r"))
		nm = asModel(t, u)
		if rows := strings.Count(nm.View(), "\n") + 1; rows > nm.height {
			t.Errorf("prompt open %dx%d: view is %d rows, terminal is %d", size.Width, size.Height, rows, nm.height)
		}
	}
}

// On a short terminal the forms cheatsheet is dropped but the input survives.
func TestPromptFormsDroppedWhenShort(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	u, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	nm := asModel(t, u)
	u, _ = nm.Update(keyMsg("r"))
	nm = asModel(t, u)
	v := nm.View()
	if strings.Contains(v, "hostname (default port 443)") {
		t.Error("80x12: forms cheatsheet must be dropped")
	}
	if !strings.Contains(v, "network-doctor") || !strings.Contains(v, "Restart") {
		t.Error("80x12: the input line must survive")
	}
}

// The forms never starve a live job pane below jobView's 5-row minimum: at a
// height where they would squeeze avail to 1-4 rows, the pane wins.
func TestPromptFormsYieldToJobPane(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.jobStatus = JobRunning
	m.jobDisplay = "ping example.com"
	for range 200 {
		m.jobLines = append(m.jobLines, outLine{text: "reply from 1.2.3.4"})
	}
	u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	nm := asModel(t, u)
	u, _ = nm.Update(keyMsg("r"))
	nm = asModel(t, u)
	v := nm.View()
	if !strings.Contains(v, "$ ping example.com") {
		t.Error("100x30: the job pane must still render")
	}
	if strings.Contains(v, "hostname (default port 443)") {
		t.Error("100x30: forms must yield to the job pane")
	}
}

// At 40 cols the prompt panel wraps its content instead of overflowing
// horizontally. Tested on promptView in isolation: the whole view has a
// pre-existing wide banner out of scope here.
func TestPromptViewNarrowNoOverflow(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	u, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
	nm := asModel(t, u)
	u, _ = nm.Update(keyMsg("r"))
	nm = asModel(t, u)
	for _, line := range strings.Split(nm.promptView(true), "\n") {
		if w := lipgloss.Width(line); w > 40 {
			t.Errorf("prompt line %d cols wide, terminal is 40: %q", w, line)
		}
	}
}
