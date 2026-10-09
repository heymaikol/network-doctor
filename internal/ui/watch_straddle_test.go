package ui

import (
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// A route change that lands while a pass is in flight makes that pass straddle.
// A healthy straddled pass must not become the incident's Before, because its
// rows describe two network states. The healthy pass before it stays the Before.
func TestWatchStraddledHealthyPassIsNotTheBaseline(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch, m.width, m.height = true, 100, 40
	session := diagnostic.NewWatchSession(func() time.Time { return start })
	m.watchSession = session

	recordWatchPass(&m, start, false, "wlan0")

	m.pass = session.Begin(m.probes)
	session.Invalidate()
	recordWatchPass(&m, start.Add(5*time.Second), false, "wg0")
	m.pass = nil

	recordWatchPass(&m, start.Add(10*time.Second), true, "wlan0")
	active, ok := m.incidents.Active()
	if !ok || active.Before == nil {
		t.Fatal("the failing pass opened no incident with a Before")
	}
	if !active.Before.At.Equal(start) {
		t.Errorf("Before is the pass at %v, want the healthy pass at %v: a straddled pass must not be the baseline", active.Before.At, start)
	}
}

// A failing pass that straddles a route change still opens its incident. The
// change must not hide the failure.
func TestWatchStraddledFailingPassStillOpensAnIncident(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch, m.width, m.height = true, 100, 40
	session := diagnostic.NewWatchSession(func() time.Time { return start })
	m.watchSession = session

	recordWatchPass(&m, start, false, "wlan0")

	m.pass = session.Begin(m.probes)
	session.Invalidate()
	recordWatchPass(&m, start.Add(5*time.Second), true, "wg0")
	m.pass = nil

	if _, ok := m.incidents.Active(); !ok {
		t.Fatal("a failing straddled pass opened no incident")
	}
}
