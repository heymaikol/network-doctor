package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func mustTarget(t *testing.T, s string) *Target {
	t.Helper()
	tg, err := parseTarget(s)
	if err != nil {
		t.Fatalf("parseTarget(%q): %v", s, err)
	}
	return tg
}

// Generic mode: egress and DNS are siblings — an egress failure must NOT skip
// DNS (the "DNS-down-but-internet-up" case stays diagnosable).
func TestSiblingIndependence(t *testing.T) {
	m := newModel(nil)
	m.results[pIface] = ProbeResult{ID: pIface, Status: StatusPass}
	m.started[pIface] = true
	cmds := m.scheduleStep()
	if len(cmds) != 2 {
		t.Fatalf("want 2 dispatched (internet, dns), got %d", len(cmds))
	}
	if !m.started[pInternet] || !m.started[pDNS] {
		t.Fatal("internet+dns should both be dispatched")
	}
	if _, ok := m.results[pDNS]; ok {
		t.Error("dns must be dispatched, not skipped by an egress failure")
	}
}

// A failed dependency skips its dependents, and the skip propagates downstream.
func TestSkipPropagation(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"))
	m.results[pIface] = ProbeResult{Status: StatusPass}
	m.results[pInternet] = ProbeResult{Status: StatusPass}
	m.results[pDNS] = ProbeResult{Status: StatusFail}
	m.started[pIface], m.started[pInternet], m.started[pDNS] = true, true, true
	m.scheduleStep()
	if m.results[pTargetTCP].Status != StatusSkip {
		t.Fatalf("target_tcp = %v, want Skip", m.results[pTargetTCP].Status)
	}
	if m.results[pTLS].Status != StatusSkip {
		t.Errorf("tls = %v, want Skip (propagated)", m.results[pTLS].Status)
	}
	if m.results[pHTTP].Status != StatusSkip {
		t.Errorf("http = %v, want Skip (propagated)", m.results[pHTTP].Status)
	}
}

// NotApplicable (IP-literal DNS) still produced output, so it must NOT skip
// Target TCP — satisfaction is about output, not row status.
func TestNADoesNotBlock(t *testing.T) {
	m := newModel(mustTarget(t, "1.1.1.1"))
	m.results[pIface] = ProbeResult{Status: StatusPass}
	m.results[pInternet] = ProbeResult{Status: StatusPass}
	m.results[pDNS] = ProbeResult{Status: StatusNA, Addrs: []net.IP{net.ParseIP("1.1.1.1")}}
	m.started[pIface], m.started[pInternet], m.started[pDNS] = true, true, true
	m.scheduleStep()
	if _, ok := m.results[pTargetTCP]; ok {
		t.Fatal("an NA dependency must not skip target_tcp")
	}
	if !m.started[pTargetTCP] {
		t.Fatal("target_tcp should be dispatched after an NA dependency")
	}
}

func TestBuildProbesShape(t *testing.T) {
	if got := len(buildProbes(nil)); got != 3 {
		t.Errorf("generic probes = %d, want 3", got)
	}
	if got := len(buildProbes(mustTarget(t, "github.com"))); got != 6 {
		t.Errorf("https target probes = %d, want 6", got)
	}
	if got := len(buildProbes(mustTarget(t, "host:22"))); got != 5 {
		t.Errorf("ssh target probes = %d, want 5", got)
	}
}

func TestRemaining(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if d := remaining(ctx); d <= 0 || d > 2*time.Second {
		t.Errorf("remaining = %v, want (0,2s]", d)
	}
	if d := remaining(context.Background()); d != probeTimeout {
		t.Errorf("remaining(no deadline) = %v, want %v", d, probeTimeout)
	}
}
