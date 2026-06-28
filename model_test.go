package main

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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
	u, cmd := m.Update(probeDoneMsg{id: pIface, gen: 0, res: ProbeResult{Status: StatusPass}})
	nm := asModel(t, u)
	if _, ok := nm.results[pIface]; ok {
		t.Error("stale probe must not store a result")
	}
	if cmd != nil {
		t.Error("stale probe must issue no cmd")
	}
}

// 'r' bumps the generation, clears run state, and resets the context.
func TestRerunResets(t *testing.T) {
	m := newModel(nil)
	m.results[pIface] = ProbeResult{Status: StatusPass}
	m.started[pIface] = true
	gen0 := m.generation
	u, cmd := m.Update(keyMsg("r"))
	nm := asModel(t, u)
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

func TestQuit(t *testing.T) {
	m := newModel(nil)
	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	_ = asModel(t, u)
	if cmd == nil {
		t.Fatal("quit must return a cmd")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg, got %T", cmd())
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
	if !nm.started[pIface] {
		t.Error("iface (root) should be dispatched")
	}
	if nm.started[pInternet] || nm.started[pDNS] {
		t.Error("dependants of iface must wait")
	}
	if cmd == nil {
		t.Error("expected a dispatch cmd")
	}
}

func TestSelectionClamp(t *testing.T) {
	m := newModel(nil) // 3 rows
	u, _ := m.Update(keyMsg("k"))
	if asModel(t, u).selected != 0 {
		t.Error("up at top must stay 0")
	}
	for i := 0; i < 5; i++ {
		u, _ = m.Update(keyMsg("j"))
		m = asModel(t, u)
	}
	if m.selected != 2 {
		t.Errorf("selected = %d, want clamp at 2", m.selected)
	}
}

func TestExitCode(t *testing.T) {
	m := newModel(nil)
	if exitCode(m) != 1 {
		t.Error("unfinished chain must exit 1")
	}
	for _, id := range m.order {
		m.results[id] = ProbeResult{Status: StatusPass}
	}
	if exitCode(m) != 0 {
		t.Error("all-pass must exit 0")
	}
	m.results[pDNS] = ProbeResult{Status: StatusFail}
	if exitCode(m) != 1 {
		t.Error("a fail must exit 1")
	}
}
