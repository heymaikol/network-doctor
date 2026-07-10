package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mplaczek99/network-doctor/internal/diagnostic"
)

func asModel(t *testing.T, m tea.Model) model {
	t.Helper()
	mm, ok := m.(model)
	if !ok {
		t.Fatalf("expected model, got %T", m)
	}
	return mm
}

func keyMsg(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// A probeDoneMsg from a stale generation is dropped (mirrors the gen guard).
func TestStaleProbeDropped(t *testing.T) {
	m := newModel(nil)
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
	m := newModel(mustTarget(t, "example.com:443"))
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
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	nm = asModel(t, u)
	if nm.confirmTool != nil {
		t.Error("esc must close the confirm gate")
	}
	if nm.activeJob != nil {
		t.Error("esc must not launch a scan")
	}
}

// 'r' opens the rerun prompt; Enter bumps the generation, clears run state,
// and resets the context.
func TestRerunResets(t *testing.T) {
	m := newModel(nil)
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.started[diagnostic.ProbeIface] = true
	gen0 := m.generation
	u, _ := m.Update(keyMsg("r"))
	nm := asModel(t, u)
	if !nm.entering {
		t.Fatal("r must open the rerun prompt")
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
		t.Error("rerun must clear results/started")
	}
	if nm.ctx != nil {
		t.Error("rerun must reset ctx to nil")
	}
	if cmd == nil {
		t.Fatal("rerun must issue a cmd")
	}
}

// The rerun prompt: prefilled with the current target, esc cancels, a bad
// line errors and stays open, a good line swaps the target and reruns.
func TestRerunPrompt(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"))
	u, _ := m.Update(keyMsg("r"))
	nm := asModel(t, u)
	if !nm.entering {
		t.Fatal("r must open the rerun prompt")
	}
	if nm.input.Value() != "github.com" {
		t.Errorf("prefill = %q, want github.com", nm.input.Value())
	}
	if !strings.Contains(nm.View(), "network-doctor") {
		t.Error("prompt view must show the command line")
	}

	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if esc := asModel(t, u); esc.entering || esc.generation != 0 {
		t.Error("esc must close the prompt without a rerun")
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
		t.Error("commit must rerun")
	}
}

func TestQuit(t *testing.T) {
	m := newModel(nil)
	u, cmd := m.Update(keyMsg("q"))
	_ = asModel(t, u)
	if cmd == nil {
		t.Fatal("quit must return a cmd")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg, got %T", cmd())
	}
}

func TestCtrlCDoesNotQuitOrCancel(t *testing.T) {
	m := newModel(nil)
	canceled := false
	m.activeJob = &job{cancel: func() { canceled = true }}

	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	nm := asModel(t, u)
	if cmd != nil {
		t.Fatal("ctrl+c must not return a command")
	}
	if canceled {
		t.Error("ctrl+c must not cancel the active job")
	}
	if nm.pending != nil {
		t.Errorf("ctrl+c pending action = %v, want nil", nm.pending.kind)
	}
}

// scheduleMsg creates the generation context and dispatches only the root probe.
func TestScheduleStartsRoot(t *testing.T) {
	m := newModel(nil)
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
	m := newModel(nil) // 4 rows
	u, _ := m.Update(keyMsg("k"))
	if asModel(t, u).selected != 0 {
		t.Error("up at top must stay 0")
	}
	for i := 0; i < 5; i++ {
		u, _ = m.Update(keyMsg("j"))
		m = asModel(t, u)
	}
	if m.selected != 3 {
		t.Errorf("selected = %d, want clamp at 3", m.selected)
	}
}

func TestExitCode(t *testing.T) {
	m := newModel(nil)
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

// Runes batched into one KeyMsg by a fast stdin read ("jjj") are replayed one
// key at a time instead of matching no binding and being dropped.
func TestBatchedRunesReplayed(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"))
	u, _ := m.Update(keyMsg("jjj"))
	nm := asModel(t, u)
	if nm.selected != 3 {
		t.Errorf("selected = %d after batched jjj, want 3", nm.selected)
	}
}

// Enter opens the output viewer while a job is running even before any output
// has arrived (e.g. mtr --report buffers everything until exit).
func TestEnterViewerBeforeOutput(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"))
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
	m := newModel(mustTarget(t, "example.com:443"))
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
}
