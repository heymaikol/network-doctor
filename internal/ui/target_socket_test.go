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
