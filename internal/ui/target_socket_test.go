package ui

import (
	"slices"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// Every run starts on a probe graph whose target socket can still be handed
// along, and the graph it replaces can no longer hand its socket to anyone.
// Each path that starts or ends a run is checked against both.

// requireFreshTargetSocket fails unless the replaced graph is closed to
// handoffs and the graph that replaces it accepts one.
func requireFreshTargetSocket(t *testing.T, replaced, next []diagnostic.Probe, path string) {
	t.Helper()
	if diagnostic.TargetSocketOpen(replaced) {
		t.Errorf("%s: the replaced graph still accepts a target socket", path)
	}
	if !diagnostic.TargetSocketOpen(next) {
		t.Errorf("%s: the new run has no open target socket, so TLS and HTTPS cannot reuse Target TCP's", path)
	}
}

func TestFirstRunStartsWithOpenTargetSocket(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	if !diagnostic.TargetSocketOpen(m.probes) {
		t.Fatal("the first run has no open target socket")
	}
}

func TestTargetSwitchStartsWithOpenTargetSocket(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	replaced := m.probes
	u, _ := m.restartWithTarget(mustTarget(t, "example.org:443"), true)
	requireFreshTargetSocket(t, replaced, asModel(t, u).probes, "target switch")
}

func TestRetestStartsWithOpenTargetSocket(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	replaced := m.probes
	u, _ := m.retest()
	requireFreshTargetSocket(t, replaced, asModel(t, u).probes, "retest")
}

func TestWatchPassStartsWithOpenTargetSocket(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch = true
	doneResults(&m, "")
	replaced := m.probes
	u, _ := m.Update(watchMsg{gen: m.generation})
	requireFreshTargetSocket(t, replaced, asModel(t, u).probes, "watch pass")
}

// Watch passes now build their graph again. The rows must keep their order, or
// a preserved cursor index would point at a different row after a pass.
func TestWatchPassKeepsRowOrder(t *testing.T) {
	sel := diagnostic.ProbeSelection{Check: map[diagnostic.ProbeID]struct{}{
		diagnostic.ProbeDNS: {}, diagnostic.ProbeTargetTCP: {}, diagnostic.ProbeTLS: {}, diagnostic.ProbeHTTPS: {},
	}}
	m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "test", diagnostic.DefaultPublicDNS, true, sel).(model)
	m.watch = true
	doneResults(&m, "")
	want := diagnostic.ProbeOrder(m.probes)
	for pass := range 5 {
		u, _ := m.Update(watchMsg{gen: m.generation})
		m = asModel(t, u)
		if got := diagnostic.ProbeOrder(m.probes); !slices.Equal(got, want) {
			t.Fatalf("pass %d reordered the rows: %v, want %v", pass+1, got, want)
		}
		doneResults(&m, "")
	}
}

func TestQuitClosesTargetSocket(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	u, cmd := m.quit()
	if cmd == nil {
		t.Fatal("quit returned no command")
	}
	if diagnostic.TargetSocketOpen(asModel(t, u).probes) {
		t.Error("quit left the target socket open for an abandoned run")
	}
}

// countBuilds counts the probe graphs m builds from here on.
func countBuilds(m *model) *int {
	n := new(int)
	build := m.graph
	m.graph = func(t *diagnostic.Target) []diagnostic.Probe {
		*n++
		return build(t)
	}
	return n
}

// A Watch session wraps every pass in a pass that owns the graph's rows. Each
// restart still builds exactly one graph, and that graph gets a socket of its
// own. A retest keeps the session, and a target switch starts it over.
func TestWatchSessionRestartsBuildOneFreshGraph(t *testing.T) {
	m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, true, "", "test",
		diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)
	if m.pass == nil || m.watchSession == nil {
		t.Fatal("a Watch run has no pass or no session")
	}
	builds := countBuilds(&m)

	doneResults(&m, "")
	replaced := m.probes
	watched := asModel(t, must(m.Update(watchMsg{gen: m.generation})))
	requireFreshTargetSocket(t, replaced, watched.probes, "watch pass")
	if *builds != 1 {
		t.Fatalf("watch pass built %d graphs, want 1", *builds)
	}

	*builds = 0
	session := watched.watchSession
	retested := asModel(t, must(watched.retest()))
	requireFreshTargetSocket(t, watched.probes, retested.probes, "retest")
	if retested.watchSession != session {
		t.Error("retest replaced the Watch session, so its forced pass starts without the session's history")
	}
	if *builds != 1 {
		t.Fatalf("retest built %d graphs, want 1", *builds)
	}

	*builds = 0
	switched := asModel(t, must(retested.restartWithTarget(mustTarget(t, "example.org:443"), true)))
	requireFreshTargetSocket(t, retested.probes, switched.probes, "target switch")
	if switched.watchSession == session {
		t.Error("target switch kept the Watch session from the previous question")
	}
	if *builds != 1 {
		t.Fatalf("target switch built %d graphs, want 1", *builds)
	}
	// The pass runs the rows the model holds. Closing the pass's socket must
	// close the one the model's rows would hand along. Last, since it closes it.
	diagnostic.ReleaseProbes(switched.pass.Probes())
	if diagnostic.TargetSocketOpen(switched.probes) {
		t.Error("the model's rows are not the pass's rows, so they hold a socket the pass cannot close")
	}
}
