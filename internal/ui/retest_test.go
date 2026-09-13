// The retest key: asking the identical question again once the user has acted
// on what the finished run told them.

package ui

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// pinnedRun is a finished run whose diagnosis is a missing default route: a
// case with a stable cause, so the remediation it reaches is the cause-specific
// one rather than the conclusion's general answer.
func pinnedRun(t *testing.T, target *diagnostic.Target) model {
	t.Helper()
	m := newModel(target, false)
	for _, p := range m.probes {
		status := diagnostic.StatusSkip
		switch p.ID {
		case diagnostic.ProbeIface:
			status = diagnostic.StatusPass
		case diagnostic.ProbeInternet, diagnostic.ProbeDNS:
			status = diagnostic.StatusFail
		}
		r := diagnostic.ProbeResult{ID: p.ID, Status: status, Detail: "detail", Fix: "fix"}
		if p.ID == diagnostic.ProbeInternet {
			r.Cause = diagnostic.RouteCauseNoDefaultRoute
		}
		m.results[p.ID] = r
	}
	diagnostic.Finalize(m.results)
	if i := m.focusRow(); i >= 0 {
		m.selected = i
	}
	m.width, m.height = 120, 40
	return m
}

// TestRetestPreservesTheRunConfiguration is the whole contract of the retest
// key: the same question, asked again. Everything that decided what the run
// asked has to survive it, since a retest that quietly changed the target, the
// probe selection, the interface, the timeout or the resolver would answer a
// different question than the one the remediation was about.
func TestRetestPreservesTheRunConfiguration(t *testing.T) {
	sources := &diagnostic.SourceAddresses{IPv4: net.ParseIP("10.7.0.2"), Iface: "wg0"}
	selection := diagnostic.ProbeSelection{Skip: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeQUIC: {}}}
	target := mustTarget(t, "example.com:443")
	m := NewWithSelection(target, sources, false, false, "", "test", "9.9.9.9", false, selection,
		WithProbeTimeout(1234)).(model)
	before := probeIDs(m)
	if slices.Contains(before, diagnostic.ProbeQUIC) {
		t.Fatal("the selection was not applied to the first run")
	}
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusFail}
	m.started[diagnostic.ProbeIface] = true
	m.selMoved, m.expanded = true, true

	after := asModel(t, pressed(t, m, keyMsg("R")))
	if after.target != target {
		t.Errorf("retest changed the target to %v", after.target)
	}
	if after.publicDNS != "9.9.9.9" || after.probeTimeout != 1234 {
		t.Errorf("retest changed the resolver or timeout: %q %v", after.publicDNS, after.probeTimeout)
	}
	if after.sources != sources {
		t.Errorf("retest changed the interface selection to %+v", after.sources)
	}
	if !slices.Equal(probeIDs(after), before) {
		t.Errorf("retest rebuilt a different probe set: %v, want %v", probeIDs(after), before)
	}
	if len(after.results) != 0 || len(after.started) != 0 {
		t.Errorf("retest kept stale run state: %d results, %d started", len(after.results), len(after.started))
	}
	if after.generation != m.generation+1 {
		t.Errorf("generation = %d, want %d", after.generation, m.generation+1)
	}
	if !strings.Contains(after.notice, "retesting example.com:443") {
		t.Errorf("notice = %q", after.notice)
	}
}

// TestRetestWorksWithoutATarget: the generic run is a diagnosis too, and its
// remediation is just as worth rechecking.
func TestRetestWorksWithoutATarget(t *testing.T) {
	m := pinnedRun(t, nil)
	after := asModel(t, pressed(t, m, keyMsg("R")))
	if after.target != nil {
		t.Errorf("retest invented a target: %v", after.target)
	}
	if !slices.Equal(probeIDs(after), probeIDs(m)) {
		t.Error("retest changed the generic probe set")
	}
	if len(after.results) != 0 {
		t.Error("retest kept the previous generic results")
	}
	if !strings.Contains(after.notice, "retesting the general checks") {
		t.Errorf("notice = %q", after.notice)
	}
}

// TestRetestDropsThePreviousRunsResults: a probe still in flight when the
// retest starts answers into the old generation, and its result must not land
// in the new run. Mixing the two is how a repaired rung would keep showing the
// failure that was already fixed.
func TestRetestDropsThePreviousRunsResults(t *testing.T) {
	m := pinnedRun(t, mustTarget(t, "example.com:443"))
	stale := m.generation
	after := asModel(t, pressed(t, m, keyMsg("R")))

	late, _ := after.Update(probeDoneMsg{id: diagnostic.ProbeDNS, gen: stale,
		res: diagnostic.ProbeResult{Status: diagnostic.StatusFail, Detail: "from the previous run"}})
	got := asModel(t, late)
	if len(got.results) != 0 {
		t.Errorf("a result from generation %d landed in generation %d: %v", stale, got.generation, got.results)
	}

	// The current generation's results are accepted as normal.
	fresh, _ := got.Update(probeDoneMsg{id: diagnostic.ProbeIface, gen: got.generation,
		res: diagnostic.ProbeResult{Status: diagnostic.StatusPass}})
	if r, ok := asModel(t, fresh).results[diagnostic.ProbeIface]; !ok || r.Status != diagnostic.StatusPass {
		t.Error("the retest refused its own generation's result")
	}
}

// TestRepeatedRetestsStayClean: pressing it over and over must not accumulate
// state, leave the context of an earlier run alive, or leave the run history
// growing behind the screen.
func TestRepeatedRetestsStayClean(t *testing.T) {
	m := pinnedRun(t, mustTarget(t, "example.com:443"))
	var canceled []context.Context
	for i := range 5 {
		m.ctx, m.cancel = context.WithCancel(context.Background())
		canceled = append(canceled, m.ctx)
		m = asModel(t, pressed(t, m, keyMsg("R")))
		if len(m.results) != 0 || len(m.started) != 0 {
			t.Fatalf("retest %d left %d results and %d started", i, len(m.results), len(m.started))
		}
		if m.ctx != nil {
			t.Fatalf("retest %d kept the previous generation's context", i)
		}
		if len(m.otherJobs) != 0 || m.cur.active != nil {
			t.Fatalf("retest %d left jobs behind", i)
		}
	}
	for i, ctx := range canceled {
		if ctx.Err() == nil {
			t.Errorf("retest %d left the previous context uncancelled", i)
		}
	}
	if m.generation == 0 {
		t.Error("the generation never moved")
	}
}

// TestRetestDefersUntilRunningWorkStops: a tool is a subprocess, so the retest
// waits for its terminal event rather than restarting on top of it, exactly as
// a restart with a new target does.
func TestRetestDefersUntilRunningWorkStops(t *testing.T) {
	m := pinnedRun(t, mustTarget(t, "example.com:443"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.ctx, m.cancel = ctx, cancel
	m.cur = jobState{name: "port scan", status: JobRunning, active: &job{cancel: func() {}}}

	held := asModel(t, pressed(t, m, keyMsg("R")))
	if held.pending == nil || held.pending.kind != pendRestart {
		t.Fatal("a retest with a job running must be deferred, not dropped")
	}
	if held.pending.target != m.target {
		t.Errorf("the deferred retest carries target %v, want %v", held.pending.target, m.target)
	}
	if held.generation != m.generation {
		t.Error("the deferred retest bumped the generation before the job finished")
	}

	held.cur.active, held.cur.status = nil, JobCanceled
	next, _ := held.runPending(held.pending)
	ran := asModel(t, next)
	if ran.target != m.target || ran.generation != m.generation+1 || len(ran.results) != 0 {
		t.Errorf("the deferred retest ran differently: target %v gen %d results %d",
			ran.target, ran.generation, len(ran.results))
	}
}

func TestRetestRemainsDiscoverableWithoutClutteringTheFooter(t *testing.T) {
	m := pinnedRun(t, nil)
	m.started[diagnostic.ProbeIface] = true
	if bar := ansi.Strip(m.helpView(false)); strings.Contains(bar, "retest") {
		t.Errorf("a finished run advertises retest in the footer: %q", bar)
	}
	if !slices.Contains(menuNames(m), "Retest checks") {
		t.Errorf("the Actions menu is missing Retest: %v", menuNames(m))
	}
	if sheet := ansi.Strip(m.helpOverlay()); !strings.Contains(sheet, "rerun the same checks on the same target") {
		t.Errorf("the cheatsheet is missing retest: %q", sheet)
	}

	unfinished := newModel(nil, false)
	if bar := ansi.Strip(unfinished.helpView(false)); strings.Contains(bar, "retest") {
		t.Errorf("an unfinished run advertised retest: %q", bar)
	}
}

func probeIDs(m model) []diagnostic.ProbeID {
	ids := make([]diagnostic.ProbeID, len(m.probes))
	for i, p := range m.probes {
		ids[i] = p.ID
	}
	return ids
}
