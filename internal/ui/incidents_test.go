package ui

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/incident"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	ndoc "github.com/heymaikol/network-doctor/internal/snapshot"
)

// recordWatchPass records one finished watch pass. Each also takes the run's
// evidence before it is finalized, which is how a test varies a reading other
// than the interface without a second pass being recorded for it.
func recordWatchPass(m *model, at time.Time, failing bool, iface string, also ...func(map[diagnostic.ProbeID]diagnostic.ProbeResult)) {
	m.results = make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(m.probes))
	for _, probe := range m.probes {
		status := diagnostic.StatusPass
		if failing && probe.ID == diagnostic.ProbeTargetTCP {
			status = diagnostic.StatusFail
		}
		m.results[probe.ID] = diagnostic.ProbeResult{ID: probe.ID, Status: status, Dur: time.Millisecond}
	}
	result := m.results[diagnostic.ProbeTargetTCP]
	result.Iface = iface
	m.results[diagnostic.ProbeTargetTCP] = result
	for _, apply := range also {
		apply(m.results)
	}
	diagnostic.Finalize(m.results)
	m.now = func() time.Time { return at }
	m.recordRun()
}

func TestWatchCapturesAndDisplaysOneContinuingIncident(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 3, 41, 0, time.UTC)
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch, m.width, m.height = true, 100, 40
	recordWatchPass(&m, start, false, "wlan0")
	recordWatchPass(&m, start.Add(5*time.Second), true, "wg0")
	recordWatchPass(&m, start.Add(10*time.Second), true, "wg0")
	recordWatchPass(&m, start.Add(15*time.Second), false, "wlan0")

	items := m.incidents.Incidents()
	if len(items) != 1 || items[0].Passes != 2 || items[0].Active() || items[0].Duration(start.Add(time.Minute)) != 10*time.Second {
		t.Fatalf("incidents = %+v, want one recovered incident with two failing passes", items)
	}
	if help := m.helpView(false); strings.Contains(help, "incidents") {
		t.Fatalf("watch footer advertises incident inspection: %s", help)
	}
	if header := m.headerView(); !strings.Contains(header, "last incident recovered after 10s") {
		t.Fatalf("watch header does not summarize the latest incident: %s", header)
	}

	u, _ := m.Update(keyMsg("i"))
	shown := asModel(t, u)
	view := shown.View()
	for _, want := range []string{
		"Watch incidents", "state: recovered", "pre-failure state:", "Changes at failure onset",
		"target_tcp interface changed", "does not establish", "Diagnosis", "causal evidence:",
		"While failing",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("incident view is missing %q:\n%s", want, view)
		}
	}
	u, _ = shown.Update(keyPress("end"))
	shown = asModel(t, u)
	if view = shown.View(); !strings.Contains(view, "Recovery") || !strings.Contains(view, "Changes when connectivity returned") {
		t.Errorf("incident recovery is not reachable by scrolling to the end:\n%s", view)
	}
	if u, _ = shown.Update(keyMsg("q")); asModel(t, u).incidentViewing {
		t.Error("q did not close incident inspection")
	}
}

func TestWatchSupportsMultipleIncidentNavigation(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch, m.width, m.height = true, 100, 30
	for n := 0; n < 2; n++ {
		base := start.Add(time.Duration(n*20) * time.Second)
		recordWatchPass(&m, base, false, "wlan0")
		recordWatchPass(&m, base.Add(5*time.Second), true, "wg0")
		recordWatchPass(&m, base.Add(10*time.Second), false, "wlan0")
	}
	m.openIncidentViewer()
	if m.incidentSelected != 1 || !strings.Contains(m.incidentView(), "2 of 2") {
		t.Fatalf("viewer did not open on latest incident: selected=%d", m.incidentSelected)
	}
	u, _ := m.handleIncidentKey(keyPress("left"))
	m = asModel(t, u)
	if m.incidentSelected != 0 || !strings.Contains(m.incidentView(), "1 of 2") {
		t.Fatalf("left did not select the earlier incident: selected=%d", m.incidentSelected)
	}
}

func TestIncidentExportIsCompatibleNdoc(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch, m.width, m.height = true, 100, 30
	recordWatchPass(&m, start, false, "wlan0")
	recordWatchPass(&m, start.Add(5*time.Second), true, "wg0")
	recordWatchPass(&m, start.Add(10*time.Second), false, "wlan0")
	m.openIncidentViewer()

	original := incidentWriteFile
	t.Cleanup(func() { incidentWriteFile = original })
	var path string
	var data []byte
	incidentWriteFile = func(name string, content []byte, _ os.FileMode) error {
		path, data = name, append([]byte(nil), content...)
		return nil
	}
	u, _ := m.handleIncidentKey(keyMsg("w"))
	m = asModel(t, u)
	if !strings.HasSuffix(path, ndoc.Extension) || !strings.Contains(m.notice, "incident saved") {
		t.Fatalf("export path/notice = %q / %q", path, m.notice)
	}
	got, err := ndoc.Decode(data)
	if err != nil {
		t.Fatalf("exported incident does not decode: %v\n%s", err, data)
	}
	if got.Incident == nil || got.Incident.Passes != 1 || got.Incident.Before == nil || got.Incident.Recovered == nil {
		t.Fatalf("exported incident = %+v", got.Incident)
	}
}

func TestCancelDuringIncidentKeepsItActive(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch = true
	recordWatchPass(&m, start, false, "wlan0")
	recordWatchPass(&m, start.Add(5*time.Second), true, "wg0")
	m.doRestart()
	final, _ := m.quit()
	m = asModel(t, final)
	active, ok := m.incidents.Active()
	if !ok || !active.Active() || active.Recovered != nil || active.Passes != 1 {
		t.Fatalf("active incident after cancellation = %+v, present=%v", active, ok)
	}
	if ExitCode(m) != 1 {
		t.Error("cancellation during a failing incident lost the last completed failing exit state")
	}
}

// A TUI run outlives the flags that started it: it rebuilds the probe graph on
// every target switch and writes its own artifacts from Watch Mode. Both have
// to ask the question the run was started with, and whether anyone named the
// second-opinion resolver is part of that question, not something either one
// can re-derive from the address.
func TestTargetSwitchAndIncidentKeepHowThePublicResolverWasChosen(t *testing.T) {
	for _, tc := range []struct {
		name      string
		publicDNS string
		auto      bool
		wantRow   string
	}{
		{"nobody named it", diagnostic.DefaultPublicDNS, true, "DNS (public)"},
		{"the user named it", diagnostic.DefaultPublicDNS, false, "DNS (public 8.8.8.8)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "test",
				tc.publicDNS, tc.auto, diagnostic.ProbeSelection{}).(model)
			m.watch, m.width, m.height = true, 100, 40
			if got := publicRowName(&m); got != tc.wantRow {
				t.Errorf("public DNS row = %q, want %q", got, tc.wantRow)
			}
			m.applyTarget(mustTarget(t, "other.test:443"), true)
			if got := publicRowName(&m); got != tc.wantRow {
				t.Errorf("after a target switch the public DNS row = %q, want %q", got, tc.wantRow)
			}
			start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
			recordWatchPass(&m, start, false, "wlan0")
			recordWatchPass(&m, start.Add(5*time.Second), true, "wlan0")
			active, ok := m.incidents.Active()
			if !ok || active.Before == nil {
				t.Fatalf("watch recorded no incident to carry the setting")
			}
			got := active.Before.Snap.Options
			if got.PublicDNS != tc.publicDNS || got.PublicDNSAuto != tc.auto {
				t.Errorf("incident options = %+v, want %q auto=%v", got, tc.publicDNS, tc.auto)
			}
		})
	}
}

func publicRowName(m *model) string {
	for _, p := range m.probes {
		if p.ID == diagnostic.ProbeDNSPublic {
			return p.Name
		}
	}
	return ""
}

// resolverTargets sets the DNS row's dialed resolver service addresses, which
// is what a change of nameserver looks like in a snapshot.
func resolverTargets(target string) func(map[diagnostic.ProbeID]diagnostic.ProbeResult) {
	return func(results map[diagnostic.ProbeID]diagnostic.ProbeResult) {
		dns := results[diagnostic.ProbeDNS]
		dns.ResolverTargets = []string{target}
		results[diagnostic.ProbeDNS] = dns
	}
}

func TestIncidentReportsAResolverTargetChangeAsEnvironmental(t *testing.T) {
	start := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch, m.width, m.height = true, 100, 40
	// The interface is held still, so the resolver targets are the only thing
	// about the path that moves between the two passes.
	recordWatchPass(&m, start, false, "wlan0", resolverTargets("192.168.1.1:53"))
	recordWatchPass(&m, start.Add(5*time.Second), true, "wlan0", resolverTargets("10.0.0.53:53"))

	selected, ok := m.incidents.Latest()
	if !ok {
		t.Fatal("no incident was recorded")
	}
	report := incidentReport(selected, 1, 1, start.Add(5*time.Second))
	environment, outcomes, found := strings.Cut(report, "Diagnostic outcome changes")
	if !found {
		t.Fatalf("incident report has no outcome section:\n%s", report)
	}
	if !strings.Contains(environment, "resolver target tried 10.0.0.53:53") ||
		!strings.Contains(environment, "resolver target tried 192.168.1.1:53") {
		t.Errorf("recorded path and configuration changes omit the resolver targets:\n%s", report)
	}
	if strings.Contains(outcomes, "resolver target tried") {
		t.Errorf("resolver targets are reported as diagnostic outcomes as well:\n%s", report)
	}
	if strings.Contains(report, "No recorded change in how this machine reaches the network") {
		t.Errorf("incident claims a steady environment while reporting a resolver change:\n%s", report)
	}
}

// The session's list is bounded: the eleventh incident drops the first, which
// slides every remaining one down a row. A viewer that held only the row
// number would then be showing a different failure than the one it was opened
// on, silently, while its header still claimed the old position.
func TestIncidentViewerFollowsTheIncidentPastTheRetentionBound(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.watch, m.width, m.height = true, 100, 30
	cycle := func(n int) {
		base := start.Add(time.Duration(n*20) * time.Second)
		recordWatchPass(&m, base, false, "wlan0")
		recordWatchPass(&m, base.Add(5*time.Second), true, "wg0")
		recordWatchPass(&m, base.Add(10*time.Second), false, "wlan0")
	}
	// Ten fills the list exactly, so the next one has to discard the oldest.
	for n := range 10 {
		cycle(n)
	}
	m.openIncidentViewer()
	u, _ := m.handleIncidentKey(keyPress("left"))
	m = asModel(t, u)
	was, ok := m.selectedIncident()
	if !ok || m.incidentSelected != 8 {
		t.Fatalf("the viewer opened on incident %d of %d", m.incidentSelected, len(m.incidents.Incidents()))
	}

	cycle(10)
	if dropped := m.incidents.Dropped(); dropped != 1 {
		t.Fatalf("the retention bound discarded %d incidents, want 1", dropped)
	}
	now, _ := m.selectedIncident()
	if !now.Started.Equal(was.Started) {
		t.Errorf("the reader was moved from the incident at %s to the one at %s", was.Started, now.Started)
	}
	if m.incidentSelected != 7 {
		t.Errorf("the incident is on row %d after the list slid down one", m.incidentSelected)
	}
	// The header counts rows, so it has to agree with where the cursor is.
	if view := m.incidentView(); !strings.Contains(view, "8 of 10") {
		t.Errorf("the header does not read 8 of 10:\n%s", view)
	}

	// It holds for as long as that incident is retained, and when the bound
	// finally discards the one being read the cursor stays in range.
	for n := 11; n < 20; n++ {
		cycle(n)
		items := m.incidents.Incidents()
		if m.incidentSelected < 0 || m.incidentSelected >= len(items) {
			t.Fatalf("cycle %d: row %d of %d incidents", n, m.incidentSelected, len(items))
		}
		retained := slices.ContainsFunc(items, func(i incident.Incident) bool { return i.Started.Equal(was.Started) })
		if now, _ = m.selectedIncident(); now.Started.Equal(was.Started) != retained {
			t.Fatalf("cycle %d: the cursor is on the incident at %s, the one being read is retained=%v",
				n, now.Started, retained)
		}
	}
}
