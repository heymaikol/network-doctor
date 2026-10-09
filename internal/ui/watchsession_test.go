package ui

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// tuiLink is the network under a TUI Watch test. While down, the target's TCP
// connect fails and the rows behind it are skipped.
type tuiLink struct {
	down atomic.Bool
	// targets counts the target connects that ran, so a test can tell how many
	// passes ran, not only how many were recorded.
	targets atomic.Int32
	// runs counts every probe that ran, for the rows a pass executed.
	runs atomic.Int64
}

// tuiFakeProbes is the production row shape with each row replaced by a fake
// that passes, except the target connect while the link is down.
func tuiFakeProbes(target *diagnostic.Target, link *tuiLink) []diagnostic.Probe {
	probes := diagnostic.ProbePlan(target, diagnostic.DefaultPublicDNS, true)
	for i := range probes {
		id := probes[i].ID
		probes[i].Run = func(_ context.Context, _ map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
			link.runs.Add(1)
			if id == diagnostic.ProbeTargetTCP {
				link.targets.Add(1)
				if link.down.Load() {
					return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Cause: "timeout"}
				}
			}
			return diagnostic.ProbeResult{Status: diagnostic.StatusPass}
		}
	}
	return probes
}

// settleWait caps one command. A fake probe finishes in microseconds, so a
// command that is still running after this is a timer: a notice expiry or a
// Watch tick. Timers are dropped rather than waited for.
const settleWait = 500 * time.Millisecond

func runCmd(c tea.Cmd) tea.Msg {
	done := make(chan tea.Msg, 1)
	go func() { done <- c() }()
	select {
	case msg := <-done:
		return msg
	case <-time.After(settleWait):
		return nil
	}
}

// settleWatch runs the commands an Update returned, as the program does, and
// feeds each probe and schedule message back through Update until no work is
// left. Watch ticks, notice timers, and spinner frames are dropped: each pass in
// these tests is started by the test, not by a tick.
func settleWatch(t *testing.T, m model, cmds ...tea.Cmd) model {
	t.Helper()
	queue := append([]tea.Cmd(nil), cmds...)
	for steps := 0; len(queue) > 0; steps++ {
		if steps > 1000 {
			t.Fatal("commands did not settle")
		}
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		switch msg := runCmd(c).(type) {
		case tea.BatchMsg:
			queue = append(queue, msg...)
		case scheduleMsg, probeDoneMsg:
			u, next := m.Update(msg)
			m = asModel(t, u)
			queue = append(queue, next)
		}
	}
	return m
}

// startWatchPass starts the next pass the way a Watch tick does, once the last
// pass is done. A discarded pass starts the one after it inside the same call.
func startWatchPass(t *testing.T, m model) model {
	t.Helper()
	if !m.allDone() {
		t.Fatal("previous pass is still running")
	}
	u, cmd := m.Update(watchMsg{gen: m.generation})
	return settleWatch(t, asModel(t, u), cmd)
}

// The TUI runs the real probe commands through the Watch session. A pass that
// reused a row and changed the target's status is not recorded. Its confirmation
// pass is recorded once, so the recorded history has one entry per published
// pass, and a discarded pass leaves no trace in it.
func TestWatchSessionRecordsOnlyPublishedPassesThroughTheTUI(t *testing.T) {
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	target := mustTarget(t, "example.com:443")
	link := &tuiLink{}
	m := watchModel(t)
	m.graph = func(*diagnostic.Target) []diagnostic.Probe { return tuiFakeProbes(target, link) }
	m.buildPass()

	m = settleWatch(t, m, m.Init())
	if !m.allDone() {
		t.Fatal("first pass did not finish")
	}
	if got := m.runHistory[diagnostic.ProbeTargetTCP]; !reflect.DeepEqual(got, []diagnostic.Status{diagnostic.StatusPass}) {
		t.Fatalf("after the first pass, target history = %v, want one pass", got)
	}

	before := link.runs.Load()
	m = startWatchPass(t, m)
	if ran := link.runs.Load() - before; ran >= int64(len(m.probes)) {
		t.Errorf("stable pass ran %d of %d rows, want fewer: passing rows are reused", ran, len(m.probes))
	}
	if got := m.runHistory[diagnostic.ProbeTargetTCP]; len(got) != 2 {
		t.Fatalf("after a stable pass, target history = %v, want two entries", got)
	}

	link.down.Store(true)
	beforeTargets := link.targets.Load()
	m = startWatchPass(t, m)
	if ran := link.targets.Load() - beforeTargets; ran != 2 {
		t.Errorf("fault took %d target connects, want 2: the discarded pass and its fresh confirmation", ran)
	}
	wantFault := []diagnostic.Status{diagnostic.StatusPass, diagnostic.StatusPass, diagnostic.StatusFail}
	if got := m.runHistory[diagnostic.ProbeTargetTCP]; !reflect.DeepEqual(got, wantFault) {
		t.Errorf("after the fault, target history = %v, want %v: the discarded pass must not record", got, wantFault)
	}
	if got := m.results[diagnostic.ProbeTargetTCP].Status; got != diagnostic.StatusFail {
		t.Errorf("shown target status = %v, want fail from the confirmed pass", got)
	}

	link.down.Store(false)
	beforeTargets = link.targets.Load()
	m = startWatchPass(t, m)
	if ran := link.targets.Load() - beforeTargets; ran != 2 {
		t.Errorf("recovery took %d target connects, want 2", ran)
	}
	wantRecovered := []diagnostic.Status{diagnostic.StatusPass, diagnostic.StatusPass, diagnostic.StatusFail, diagnostic.StatusPass}
	if got := m.runHistory[diagnostic.ProbeTargetTCP]; !reflect.DeepEqual(got, wantRecovered) {
		t.Errorf("after recovery, target history = %v, want %v", got, wantRecovered)
	}
}

// A retest asks for fresh evidence. Every row runs, including the rows a stable
// pass would have reused.
func TestWatchRetestRunsEveryRowThroughTheTUI(t *testing.T) {
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	target := mustTarget(t, "example.com:443")
	link := &tuiLink{}
	m := watchModel(t)
	m.graph = func(*diagnostic.Target) []diagnostic.Probe { return tuiFakeProbes(target, link) }
	m.buildPass()
	m = settleWatch(t, m, m.Init())
	m = startWatchPass(t, m)

	before := link.runs.Load()
	u, cmd := m.retest()
	m = settleWatch(t, asModel(t, u), cmd)
	if ran := link.runs.Load() - before; ran != int64(len(m.probes)) {
		t.Errorf("retest ran %d rows, want all %d", ran, len(m.probes))
	}
}
