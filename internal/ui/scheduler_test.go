package ui

import (
	"net"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func mustTarget(t *testing.T, s string) *diagnostic.Target {
	t.Helper()
	target, err := diagnostic.ParseTarget(s)
	if err != nil {
		t.Fatalf("parseTarget(%q): %v", s, err)
	}
	return target
}

// Generic mode: egress, proxy egress, and DNS are siblings — an egress
// failure must not skip DNS, so DNS-down-but-internet-up remains diagnosable.
func TestSiblingIndependence(t *testing.T) {
	m := newModel(nil)
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass}
	m.started[diagnostic.ProbeIface] = true
	cmds := m.scheduleStep()
	if len(cmds) != 3 {
		t.Fatalf("want 3 dispatched (internet, proxy, dns), got %d", len(cmds))
	}
	if !m.started[diagnostic.ProbeInternet] || !m.started[diagnostic.ProbeProxy] || !m.started[diagnostic.ProbeDNS] {
		t.Fatal("internet+proxy+dns should all be dispatched")
	}
	if _, ok := m.results[diagnostic.ProbeDNS]; ok {
		t.Error("dns must be dispatched, not skipped by an egress failure")
	}
}

func TestSkipPropagation(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"))
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeInternet] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{Status: diagnostic.StatusFail}
	m.started[diagnostic.ProbeIface], m.started[diagnostic.ProbeInternet], m.started[diagnostic.ProbeDNS] = true, true, true
	m.scheduleStep()
	if m.results[diagnostic.ProbeTargetTCP].Status != diagnostic.StatusSkip {
		t.Fatalf("target_tcp = %v, want Skip", m.results[diagnostic.ProbeTargetTCP].Status)
	}
	if m.results[diagnostic.ProbeTLS].Status != diagnostic.StatusSkip || m.results[diagnostic.ProbeHTTP].Status != diagnostic.StatusSkip || m.results[diagnostic.ProbeHTTPS].Status != diagnostic.StatusSkip {
		t.Error("skip must propagate through TLS, HTTP, and HTTPS")
	}
}

// When the last real probe result arrives and the run only completes via the
// skip cascade inside scheduleStep, DowngradeEgress must still run — otherwise
// a proxy-only network shows internet FAIL in the TUI but WARN in -json.
func TestDowngradeRunsWhenSkipsFinishRun(t *testing.T) {
	m := newModel(mustTarget(t, "github.com:443"))
	pass := func(id diagnostic.ProbeID) {
		m.results[id] = diagnostic.ProbeResult{ID: id, Status: diagnostic.StatusPass}
		m.started[id] = true
	}
	fail := func(id diagnostic.ProbeID) {
		m.results[id] = diagnostic.ProbeResult{ID: id, Status: diagnostic.StatusFail}
		m.started[id] = true
	}
	pass(diagnostic.ProbeIface)
	fail(diagnostic.ProbeInternet)
	pass(diagnostic.ProbeProxy)
	pass(diagnostic.ProbeDNS)
	fail(diagnostic.ProbeHTTP)
	m.started[diagnostic.ProbeTargetTCP] = true // in flight; its done-msg arrives below

	u, _ := m.Update(probeDoneMsg{id: diagnostic.ProbeTargetTCP, gen: 0, res: diagnostic.ProbeResult{Status: diagnostic.StatusFail}})
	nm := asModel(t, u)
	if !nm.allDone() {
		t.Fatal("run should complete via the tls/https skip cascade")
	}
	if got := nm.results[diagnostic.ProbeInternet].Status; got != diagnostic.StatusWarn {
		t.Fatalf("internet = %v, want Warn (proxy works, egress downgraded)", got)
	}
}

func TestNADoesNotBlock(t *testing.T) {
	m := newModel(mustTarget(t, "1.1.1.1"))
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeInternet] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{Status: diagnostic.StatusNA, Addrs: []net.IP{net.ParseIP("1.1.1.1")}}
	m.started[diagnostic.ProbeIface], m.started[diagnostic.ProbeInternet], m.started[diagnostic.ProbeDNS] = true, true, true
	m.scheduleStep()
	if _, ok := m.results[diagnostic.ProbeTargetTCP]; ok {
		t.Fatal("an NA dependency must not skip target_tcp")
	}
	if !m.started[diagnostic.ProbeTargetTCP] {
		t.Fatal("target_tcp should be dispatched after an NA dependency")
	}
}
