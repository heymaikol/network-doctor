package main

import "testing"

func TestToolsFor(t *testing.T) {
	// Generic mode: target-independent tools only (ip, ss).
	if got := len(toolsFor(nil)); got != 2 {
		t.Errorf("toolsFor(nil) = %d, want 2 (ip, ss)", got)
	}
	// Target mode: + ping, dig, curl, traceroute, mtr.
	if got := len(toolsFor(mustTarget(t, "github.com"))); got != 7 {
		t.Errorf("toolsFor(target) = %d, want 7", got)
	}
}

func TestToolHotkeysUnique(t *testing.T) {
	seen := map[string]bool{}
	reserved := map[string]bool{"q": true, "r": true, "e": true, "j": true, "k": true}
	for _, tool := range toolsFor(mustTarget(t, "github.com")) {
		if seen[tool.Key] {
			t.Errorf("duplicate tool hotkey %q", tool.Key)
		}
		if reserved[tool.Key] {
			t.Errorf("tool hotkey %q collides with a reserved key", tool.Key)
		}
		seen[tool.Key] = true
	}
}

// Toolbox mode with no chain run exits 0.
func TestToolboxExitZero(t *testing.T) {
	m := newModel(nil)
	m.toolbox = true
	if exitCode(m) != 0 {
		t.Error("toolbox mode, no chain run, must exit 0")
	}
	// Once the chain runs and a probe fails, normal rules apply.
	m.started[pIface] = true
	for _, id := range m.order {
		m.results[id] = ProbeResult{Status: StatusPass}
	}
	m.results[pDNS] = ProbeResult{Status: StatusFail}
	if exitCode(m) != 1 {
		t.Error("toolbox mode after a failed chain must exit 1")
	}
}
