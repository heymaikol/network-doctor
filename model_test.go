package main

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// testModel builds a model with n fake checks that all pass without touching
// the network or honoring ctx (Update never actually runs the cmds here).
func testModel(n int) model {
	cs := make([]Check, n)
	for i := range cs {
		cs[i] = Check{Name: "c", Run: func(ctx context.Context) Result {
			return Result{Status: Pass}
		}}
	}
	return newModel(cs)
}

func asModel(t *testing.T, m tea.Model) model {
	t.Helper()
	mm, ok := m.(model)
	if !ok {
		t.Fatalf("expected model, got %T", m)
	}
	return mm
}

// A startCheckMsg from a stale generation is ignored entirely.
func TestStaleGenStartIgnored(t *testing.T) {
	m := testModel(3)
	m.generation = 5
	u, cmd := m.Update(startCheckMsg{idx: 0, gen: 0})
	nm := asModel(t, u)
	if nm.running {
		t.Error("stale start should not set running")
	}
	if nm.cancel != nil {
		t.Error("stale start should not create a context")
	}
	if cmd != nil {
		t.Error("stale start should issue no cmd")
	}
}

// A checkDoneMsg for the wrong index (or stale gen) is ignored — it can't
// cancel or store against the live check.
func TestWrongDoneIgnored(t *testing.T) {
	m := testModel(3)
	u, _ := m.Update(startCheckMsg{idx: 0, gen: 0})
	m = asModel(t, u)
	ctx0 := m.ctx

	// wrong index
	u, cmd := m.Update(checkDoneMsg{idx: 1, gen: 0, res: Result{Status: Pass}})
	nm := asModel(t, u)
	if nm.rows[1].result != nil || nm.rows[0].result != nil {
		t.Error("wrong-index done must not store a result")
	}
	if cmd != nil || !nm.running {
		t.Error("wrong-index done must be a no-op on flow")
	}
	if ctx0.Err() != nil {
		t.Error("wrong-index done must not cancel the live context")
	}

	// stale generation
	u, cmd = m.Update(checkDoneMsg{idx: 0, gen: 99, res: Result{Status: Pass}})
	nm = asModel(t, u)
	if nm.rows[0].result != nil || cmd != nil {
		t.Error("stale-gen done must be ignored")
	}
}

// Happy path: each completion stores its result, cancels its context, advances,
// and the tick chain self-terminates after the last check.
func TestCompletesAdvancesAndCancels(t *testing.T) {
	m := testModel(2)

	u, _ := m.Update(startCheckMsg{idx: 0, gen: 0})
	m = asModel(t, u)
	if !m.running || m.inFlight != 0 || m.cancel == nil {
		t.Fatal("first start should be running with a live context")
	}
	ctx0 := m.ctx

	u, cmd := m.Update(checkDoneMsg{idx: 0, gen: 0, res: Result{Status: Pass, Detail: "ok"}})
	m = asModel(t, u)
	if m.rows[0].result == nil || !m.rows[0].result.Status {
		t.Fatal("result for check 0 not stored")
	}
	if ctx0.Err() != context.Canceled {
		t.Error("completing a check must cancel its context")
	}
	if m.cancel != nil {
		t.Error("cancel must be cleared after completion")
	}
	if cmd == nil {
		t.Fatal("expected a start cmd for the next check")
	}

	next, ok := cmd().(startCheckMsg)
	if !ok || next.idx != 1 || next.gen != 0 {
		t.Fatalf("expected startCheckMsg{1,0}, got %#v", cmd())
	}

	u, _ = m.Update(next)
	m = asModel(t, u)
	if m.inFlight != 1 || !m.running || m.cancel == nil {
		t.Fatal("second check should be in flight")
	}
	ctx1 := m.ctx

	u, cmd = m.Update(checkDoneMsg{idx: 1, gen: 0, res: Result{Status: Pass}})
	m = asModel(t, u)
	if m.rows[1].result == nil {
		t.Fatal("result for check 1 not stored")
	}
	if m.running {
		t.Error("running should be false after the last check")
	}
	if ctx1.Err() != context.Canceled || m.cancel != nil {
		t.Error("last check's context must be cancelled and cleared")
	}
	if cmd != nil {
		t.Error("no cmd should follow the final check")
	}
}

// 'r' cancels the live check, bumps generation, resets to pending, restarts at
// 0, and leaves running untouched (the startCheckMsg handler owns the tick).
func TestRerunCancelsAndRestarts(t *testing.T) {
	m := testModel(2)
	u, _ := m.Update(startCheckMsg{idx: 0, gen: 0})
	m = asModel(t, u)
	ctx0 := m.ctx
	gen0 := m.generation

	u, cmd := m.Update(keyMsg("r"))
	m = asModel(t, u)
	if ctx0.Err() != context.Canceled {
		t.Error("'r' must cancel the in-flight context")
	}
	if m.cancel != nil {
		t.Error("'r' must clear cancel")
	}
	if m.generation != gen0+1 {
		t.Errorf("generation = %d, want %d", m.generation, gen0+1)
	}
	for i, row := range m.rows {
		if row.result != nil {
			t.Errorf("row %d not reset to pending", i)
		}
	}
	if m.inFlight != 0 {
		t.Error("'r' must reset inFlight to 0")
	}
	if cmd == nil {
		t.Fatal("'r' must issue a restart cmd")
	}
	restart, ok := cmd().(startCheckMsg)
	if !ok || restart.idx != 0 || restart.gen != gen0+1 {
		t.Fatalf("expected startCheckMsg{0,%d}, got %#v", gen0+1, cmd())
	}
}

// After all checks finish (running==false), 'r' then startCheckMsg restarts the
// run — running goes true again and a fresh context is created.
func TestRerunAfterCompletionRestarts(t *testing.T) {
	m := testModel(1)
	u, _ := m.Update(startCheckMsg{idx: 0, gen: 0})
	m = asModel(t, u)
	u, _ = m.Update(checkDoneMsg{idx: 0, gen: 0, res: Result{Status: Pass}})
	m = asModel(t, u)
	if m.running {
		t.Fatal("precondition: running should be false after completion")
	}

	u, cmd := m.Update(keyMsg("r"))
	m = asModel(t, u)
	restart := cmd().(startCheckMsg)

	u, cmd = m.Update(restart)
	m = asModel(t, u)
	if !m.running || m.inFlight != 0 || m.cancel == nil {
		t.Fatal("post-completion rerun must restart the run")
	}
	if cmd == nil {
		t.Error("restart should issue cmds (runCheck + seeded tick)")
	}
}

// 'q' / ctrl+c cancel the live check and quit.
func TestQuitCancels(t *testing.T) {
	m := testModel(2)
	u, _ := m.Update(startCheckMsg{idx: 0, gen: 0})
	m = asModel(t, u)
	ctx0 := m.ctx

	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = asModel(t, u)
	if ctx0.Err() != context.Canceled || m.cancel != nil {
		t.Error("quit must cancel and clear the live context")
	}
	if cmd == nil {
		t.Fatal("quit must return a cmd")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg, got %T", cmd())
	}
}

// The spinner tick reschedules only while running; the chain stops otherwise.
func TestSpinnerTickGate(t *testing.T) {
	m := testModel(1)
	tick := m.spinner.Tick() // a real spinner.TickMsg with the right id

	m.running = true
	_, cmd := m.Update(tick)
	if cmd == nil {
		t.Error("tick should reschedule while running")
	}

	m.running = false
	_, cmd = m.Update(tick)
	if cmd != nil {
		t.Error("tick should not reschedule once stopped")
	}
}

func keyMsg(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}
