// The context strip owns aggregate progress and active-work counts: what counts
// as complete, what counts as running, and when the strip stops saying either.

package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// contextStrip is the header context strip with its styling taken off.
func contextStrip(m model) string { return ansi.Strip(m.headerView()) }

// midRun is a run with the interface probe answered, the system resolver in
// flight, and everything downstream of them still waiting on a dependency.
func midRun(t *testing.T) model {
	t.Helper()
	m := newModel(mustTarget(t, "github.com:443"), false)
	m.started[diagnostic.ProbeIface] = true
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass}
	m.started[diagnostic.ProbeDNS] = true
	return m
}

// The banner says that work is active, while the context strip owns the one
// exact aggregate count. Probe rows keep their local activity glyphs.
func TestAggregateProgressHasOneOwnerDuringActiveRun(t *testing.T) {
	m := midRun(t)
	plain := ansi.Strip(m.View())
	progress := fmt.Sprintf("1/%d complete", len(m.probes))
	if got := strings.Count(plain, progress); got != 1 {
		t.Fatalf("active view carries %q %d times, want exactly once:\n%s", progress, got, plain)
	}
	if old := fmt.Sprintf("1 of %d done", len(m.probes)); strings.Contains(plain, old) {
		t.Errorf("active view still carries the banner's duplicate %q:\n%s", old, plain)
	}
	if got, want := ansi.Strip(m.banner()), ansi.Strip(m.spinner.View())+" Checking your connection…"; got != want {
		t.Errorf("running banner = %q, want qualitative active state %q", got, want)
	}
	if got := m.glyph(diagnostic.ProbeDNS); got != m.spinner.View() {
		t.Errorf("running probe glyph = %q, want spinner %q", got, m.spinner.View())
	}
}

// One answered probe, one dispatched, and a dozen probes that have not been
// dispatched because their dependencies have not answered. Only the first two
// are counted, and the rest are pending rather than running.
func TestProgressCountsCompleteAndRunning(t *testing.T) {
	m := midRun(t)
	want := fmt.Sprintf("1/%d complete  ·  1 running", len(m.probes))
	if got := contextStrip(m); !strings.Contains(got, want) {
		t.Fatalf("context strip = %q, want it to carry %q", got, want)
	}
	if m.started[diagnostic.ProbeTLS] {
		t.Fatal("the fixture dispatched a probe that should still be waiting on a dependency")
	}
}

// Nothing has been dispatched yet, so nothing may be described as running.
func TestProgressIsSilentBeforeTheRunStarts(t *testing.T) {
	m := newModel(mustTarget(t, "github.com:443"), false)
	if got := contextStrip(m); strings.Contains(got, "running") || strings.Contains(got, "complete") {
		t.Fatalf("context strip = %q, want no progress before the chain starts", got)
	}
}

// A pass with work behind it and nothing in flight is a truthful state: the
// completed count stands and no running count is invented to look busy.
func TestProgressOmitsRunningWhenNothingIsInFlight(t *testing.T) {
	m := midRun(t)
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{ID: diagnostic.ProbeDNS, Status: diagnostic.StatusPass}
	got := contextStrip(m)
	if want := fmt.Sprintf("2/%d complete", len(m.probes)); !strings.Contains(got, want) {
		t.Fatalf("context strip = %q, want it to carry %q", got, want)
	}
	if strings.Contains(got, "running") {
		t.Errorf("context strip = %q, want no running count while nothing is dispatched", got)
	}
}

// Skip and N/A are results, so they finish their probe the moment the
// scheduler emits them, exactly as a pass or a fail does.
func TestProgressCountsSkipAndNAAsComplete(t *testing.T) {
	m := newModel(mustTarget(t, "github.com:443"), false)
	for _, id := range []diagnostic.ProbeID{diagnostic.ProbeIface, diagnostic.ProbeInternet} {
		m.started[id] = true
		m.results[id] = diagnostic.ProbeResult{ID: id, Status: diagnostic.StatusPass}
	}
	m.started[diagnostic.ProbeSSID] = true
	m.results[diagnostic.ProbeSSID] = diagnostic.ProbeResult{ID: diagnostic.ProbeSSID, Status: diagnostic.StatusNA}
	// A failed resolver skips the whole target rung through the real scheduler,
	// so the skips counted here are the ones the run actually emitted.
	m.started[diagnostic.ProbeDNS] = true
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail}
	m.scheduleStep()
	if m.results[diagnostic.ProbeTargetTCP].Status != diagnostic.StatusSkip {
		t.Fatal("the fixture did not produce a dependency-driven skip")
	}
	done, running := m.runProgress()
	var wantDone int
	for _, p := range m.probes {
		if _, ok := m.results[p.ID]; ok {
			wantDone++
		}
	}
	if done != wantDone {
		t.Errorf("complete = %d, want every emitted result counted (%d)", done, wantDone)
	}
	if done+running > len(m.probes) {
		t.Errorf("complete+running = %d, more than the %d probes in the plan", done+running, len(m.probes))
	}
	if got := contextStrip(m); !strings.Contains(got, fmt.Sprintf("%d/%d complete", done, len(m.probes))) {
		t.Errorf("context strip = %q, want the emitted results counted", got)
	}
}

// The denominator is this run's plan, not everything netdoc can check: --check
// and --skip both move it.
func TestProgressDenominatorIsTheCurrentPlan(t *testing.T) {
	full := len(newModel(mustTarget(t, "example.com:443"), false).probes)
	for _, tc := range []struct {
		name string
		sel  diagnostic.ProbeSelection
	}{
		{"check", diagnostic.ProbeSelection{Check: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeTLS: {}}}},
		{"skip", diagnostic.ProbeSelection{Skip: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeDNSEncrypted: {}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "test", diagnostic.DefaultPublicDNS, true, tc.sel).(model)
			if len(m.probes) >= full {
				t.Fatalf("selection did not reduce the plan: %d of %d probes", len(m.probes), full)
			}
			m.started[diagnostic.ProbeIface] = true
			if got, want := contextStrip(m), fmt.Sprintf("0/%d complete", len(m.probes)); !strings.Contains(got, want) {
				t.Fatalf("context strip = %q, want %q", got, want)
			}
		})
	}
}

// The verdict already says the run finished, so the strip stops repeating it
// rather than parking a permanent "13/13 complete  ·  0 running" under it.
func TestProgressDisappearsWhenTheRunCompletes(t *testing.T) {
	for _, failID := range []diagnostic.ProbeID{"", diagnostic.ProbeDNS} {
		m := newModel(mustTarget(t, "github.com:443"), false)
		for _, p := range m.probes {
			m.started[p.ID] = true
		}
		doneResults(&m, failID)
		strip, view := contextStrip(m), ansi.Strip(m.View())
		if strings.Contains(strip, "complete") || strings.Contains(strip, "running") {
			t.Fatalf("context strip = %q, want no progress on a finished run", strip)
		}
		if !strings.Contains(strip, "github.com:443") {
			t.Errorf("context strip = %q, want it to keep its target", strip)
		}
		summary, _ := m.diagnose(m.probeOrder())
		if !strings.Contains(view, summary) {
			t.Errorf("finished view lost diagnosis %q:\n%s", summary, view)
		}
		for _, stale := range []string{fmt.Sprintf("%d/%d complete", len(m.probes), len(m.probes)), fmt.Sprintf("%d of %d done", len(m.probes), len(m.probes))} {
			if strings.Contains(view, stale) {
				t.Errorf("finished view retained progress %q:\n%s", stale, view)
			}
		}
	}
}

// A watch pass describes itself. The previous pass's counts go with its
// results, and the new pass starts from nothing dispatched.
func TestWatchPassDoesNotInheritStaleProgress(t *testing.T) {
	m := newModel(mustTarget(t, "github.com:443"), false)
	m.watch = true
	for _, p := range m.probes {
		m.started[p.ID] = true
	}
	doneResults(&m, "")
	total := len(m.probes)

	next := asModel(t, must(m.Update(watchMsg{gen: m.generation})))
	if got := contextStrip(next); strings.Contains(got, "complete") || strings.Contains(got, "running") {
		t.Fatalf("context strip = %q, want the finished pass's counts gone with its results", got)
	}
	// The first schedule step of the new pass: its own roots, its own zero.
	next = asModel(t, must(next.Update(scheduleMsg{gen: next.generation})))
	if got, want := contextStrip(next), fmt.Sprintf("0/%d complete", total); !strings.Contains(got, want) {
		t.Fatalf("context strip = %q, want the new pass to start at %q", got, want)
	}
	if got := contextStrip(next); !strings.Contains(got, "1 running") {
		t.Errorf("context strip = %q, want the new pass's root counted as running", got)
	}
}

// Progress joins the strip the rest of the context is already on: it does not
// displace the target, the network, or the watch and incident state, and it
// does not add a row of its own.
func TestProgressComposesWithTheRestOfTheStrip(t *testing.T) {
	// onWireless answers the Wi-Fi probe as well as the interface one, so two
	// of this pass's probes are complete and the resolver is still in flight.
	m := onWireless(midRun(t))
	m.watch = true
	got := contextStrip(m)
	for _, want := range []string{"github.com:443", "Wi-Fi: homewifi", "watch", fmt.Sprintf("2/%d complete", len(m.probes)), "1 running"} {
		if !strings.Contains(got, want) {
			t.Fatalf("context strip = %q, want it to carry %q", got, want)
		}
	}
	if strings.Contains(got, "\n") {
		t.Errorf("context strip grew a second row: %q", got)
	}
	rendered, v := renderAt(t, m)
	if !hasLine(v, rendered.headerView()) {
		t.Errorf("the context strip is not on screen:\n%s", v)
	}
}

// The strip can wrap, but it stays the sole progress owner at every supported
// short-terminal size and under both key presets.
func TestProgressStripFitsNarrowTerminals(t *testing.T) {
	m := onWireless(midRun(t))
	m.watch = true
	for _, preset := range []string{"default", "vim"} {
		m.keys, _ = PresetKeymap(preset)
		for _, size := range [][2]int{{120, 40}, {100, 30}, {80, 24}, {70, 20}, {80, 16}, {80, 12}, {80, 10}} {
			nm := asModel(t, must(m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})))
			v, plain := nm.View(), ansi.Strip(nm.View())
			if lipgloss.Height(v) > nm.height {
				t.Errorf("%s %dx%d: view is %d rows tall:\n%s", preset, size[0], size[1], lipgloss.Height(v), v)
			}
			for _, line := range strings.Split(v, "\n") {
				if width := lipgloss.Width(line); width > nm.width {
					t.Errorf("%s %dx%d: line is %d columns wide: %q", preset, size[0], size[1], width, line)
				}
			}
			if got := strings.Count(plain, fmt.Sprintf("2/%d complete", len(nm.probes))); got != 1 {
				t.Errorf("%s %dx%d: aggregate progress appears %d times, want once:\n%s", preset, size[0], size[1], got, plain)
			}
			if n := unclosedPanels(v); n != 0 {
				t.Errorf("%s %dx%d: %d panel border(s) left unclosed:\n%s", preset, size[0], size[1], n, v)
			}
		}
	}
}

func TestMonochromeStillNamesActiveProgress(t *testing.T) {
	m := midRun(t)
	m.setTheme(resolveTheme("monochrome"))
	plain := ansi.Strip(m.View())
	for _, want := range []string{"Checking your connection", fmt.Sprintf("1/%d complete", len(m.probes)), "1 running"} {
		if !strings.Contains(plain, want) {
			t.Errorf("monochrome active view lost %q:\n%s", want, plain)
		}
	}
}

// Retest clears the old diagnosis, reports its new pass, then gives ownership
// straight back to the diagnosis when that pass completes.
func TestRetestCompletionLeavesNoStaleProgress(t *testing.T) {
	m := newModel(mustTarget(t, "github.com:443"), false)
	doneResults(&m, diagnostic.ProbeDNS)
	next := asModel(t, must(m.retest()))
	next = asModel(t, must(next.Update(scheduleMsg{gen: next.generation})))
	if got := contextStrip(next); !strings.Contains(got, fmt.Sprintf("0/%d complete", len(next.probes))) || !strings.Contains(got, "1 running") {
		t.Fatalf("retest in progress = %q, want current-pass aggregate and active work", got)
	}
	doneResults(&next, "")
	plain := ansi.Strip(next.View())
	if strings.Contains(plain, fmt.Sprintf("%d/%d complete", len(next.probes), len(next.probes))) || strings.Contains(plain, " running") {
		t.Errorf("completed retest retained progress:\n%s", plain)
	}
	summary, _ := next.diagnose(next.probeOrder())
	if !strings.Contains(plain, summary) {
		t.Errorf("completed retest lost diagnosis %q:\n%s", summary, plain)
	}
}
