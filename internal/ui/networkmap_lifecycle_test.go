package ui

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func lanLifecycleModel(t *testing.T) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, "")
	r := m.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("192.168.12.34")
	m.results[diagnostic.ProbeInternet] = r
	m.width, m.height = 100, 40
	m.networkCIDR = "192.168.12.0/24"
	return m
}

func lanSnapshot(at time.Time, status JobStatus, host string) jobState {
	j := jobState{name: lanDiscoveryName, status: status, start: at, dur: 2 * time.Second}
	if host != "" {
		j.lines = []string{"Host: " + host + " ()\tStatus: Up"}
	}
	return j
}

func TestNetworkMapCacheAndRescanLifecycle(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(string) (string, error) { return "nmap", nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	m := lanLifecycleModel(t)
	u, cmd := m.Update(keyMsg("v"))
	first := asModel(t, u)
	if first.confirmTool == nil || first.confirmTool.Name != lanDiscoveryName || cmd != nil || first.hasJob() {
		t.Fatal("first v must confirm discovery without launching it")
	}
	if slices.Contains(menuNames(m), "Rescan network") {
		t.Error("Rescan must not appear before a LAN scan exists")
	}

	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.FixedZone("CDT", -5*60*60))
	m.cur = lanSnapshot(at, JobDone, "192.168.12.1")
	u, cmd = m.Update(keyMsg("v"))
	cached := asModel(t, u)
	if cmd != nil || !cached.networkMap || cached.confirmTool != nil || cached.cur.start != at || len(cached.otherJobs) != 0 {
		t.Fatalf("cached v changed or relaunched the scan: cur=%+v parked=%d", cached.cur, len(cached.otherJobs))
	}

	if key, ok := menuKey(cached, "Rescan network"); !ok || key != "" {
		t.Fatalf("Rescan network must be a menu-only row, key=%q found=%v", key, ok)
	}
	for _, preset := range presets {
		if keys := preset.preset[ctxList][actRescanNetwork]; len(keys) != 0 {
			t.Errorf("%s gives menu-only Rescan a global binding: %v", preset.name, keys)
		}
	}

	cached.watch = true
	r := cached.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("10.0.0.8")
	cached.results[diagnostic.ProbeInternet] = r
	confirm := sendKey(t, selectMenu(t, cached, "Rescan network"), "enter")
	if confirm.confirmTool == nil || confirm.confirmTool.Name != lanDiscoveryName || !confirm.networkMap {
		t.Fatal("Rescan must use the LAN confirmation without hiding the cached map")
	}
	canceled := sendKey(t, confirm, "esc")
	if canceled.confirmTool != nil || !canceled.networkMap || canceled.cur.start != at || canceled.networkCIDR != "192.168.12.0/24" || len(canceled.otherJobs) != 0 {
		t.Fatal("canceling Rescan must leave the cached scan intact")
	}

	confirm = sendKey(t, selectMenu(t, canceled, "Rescan network"), "enter")
	confirm.confirmTool.Bin = os.Args[0]
	confirm.confirmTool.Timeout = 5 * time.Second
	confirm.confirmTool.Build = func(*diagnostic.Target, net.IP) ([]string, []string, string) {
		return []string{"-test.run=TestHelperProcess"},
			append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE=sleep"), "test LAN scan"
	}
	u, cmd = confirm.Update(keyMsg("y"))
	fresh := asModel(t, u)
	if cmd == nil || fresh.cur.active == nil || fresh.cur.name != lanDiscoveryName || !fresh.networkMap || fresh.networkCIDR != "10.0.0.0/24" {
		t.Fatal("confirming Rescan must start a fresh LAN job")
	}
	if len(fresh.otherJobs) != 1 || fresh.otherJobs[0].start != at || len(fresh.otherJobs[0].lines) != 1 {
		t.Fatalf("fresh discovery lost the previous evidence: %+v", fresh.otherJobs)
	}
	fresh.cur.active.cancel()
	_, done := drain(t, fresh.cur.active.ch)
	u, _ = fresh.Update(done)
	fresh = asModel(t, u)
	u, _ = fresh.Update(tea.KeyMsg{Type: tea.KeyTab})
	previous := asModel(t, u)
	if previous.cur.start != at || !slices.Equal(discoveredIPs(previous.cur.lines), []string{"192.168.12.1"}) {
		t.Fatalf("tab cannot reach the previous scan evidence: %+v", previous.cur)
	}
}

func TestNetworkMapAlwaysSelectsNewestScan(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	m := lanLifecycleModel(t)
	m.cur = jobState{name: "ping", status: JobDone, start: base.Add(10 * time.Second)}
	m.otherJobs = []jobState{
		lanSnapshot(base, JobDone, "192.168.12.1"),
		lanSnapshot(base.Add(2*time.Second), JobFailed, "192.168.12.2"),
	}

	for i := 3; i <= 6; i++ {
		m.networkMap = false
		u, cmd := m.Update(keyMsg("v"))
		m = asModel(t, u)
		if cmd != nil || !m.networkMap || !slices.Equal(discoveredIPs(m.cur.lines), []string{fmt.Sprintf("192.168.12.%d", i-1)}) {
			t.Fatalf("v did not select rescan %d as newest: start=%s lines=%v", i-2, m.cur.start, m.cur.lines)
		}
		m.networkMap = false
		m.otherJobs = append(m.otherJobs, lanSnapshot(base.Add(time.Duration(i)*time.Second), JobDone, fmt.Sprintf("192.168.12.%d", i)))
	}
}

func TestNetworkMapShowsCaptureTimeAndTerminalOutcome(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.FixedZone("CDT", -5*60*60))
	for _, status := range []JobStatus{JobDone, JobFailed, JobCanceled, JobTimedOut} {
		t.Run(status.String(), func(t *testing.T) {
			m := lanLifecycleModel(t)
			m.networkMap = true
			m.cur = lanSnapshot(at, status, "192.168.12.50")
			m.now = func() time.Time { return at.Add(3 * time.Minute) }
			view := ansi.Strip(m.networkMapView())
			// The capture instant stays absolute and tied to this job; the age
			// beside it is what answers "how fresh is this" without arithmetic.
			want := "Cached snapshot · captured 2m58s ago (2026-09-13 12:34:58 CDT)"
			if status != JobDone {
				want = "Cached snapshot · scan " + status.String() + " 2m58s ago (2026-09-13 12:34:58 CDT)"
			}
			if !strings.Contains(view, want) {
				t.Fatalf("map omits deterministic capture metadata %q:\n%s", want, view)
			}
			partial := strings.Contains(view, "partial results")
			if partial != (status != JobDone) {
				t.Errorf("%s partial label=%v:\n%s", status, partial, view)
			}
			if status == JobDone && slices.Contains(menuNames(m), "Rescan network") == false {
				t.Error("a completed scan must offer Rescan")
			}
		})
	}

	for _, status := range []JobStatus{JobFailed, JobCanceled, JobTimedOut} {
		m := lanLifecycleModel(t)
		m.cur = lanSnapshot(at, status, "")
		if !slices.Contains(menuNames(m), "Rescan network") {
			t.Errorf("%s LAN scan cannot be rescanned", status)
		}
	}
	running := lanLifecycleModel(t)
	running.cur = lanSnapshot(at, JobRunning, "")
	running.cur.active = &job{}
	if slices.Contains(menuNames(running), "Rescan network") {
		t.Error("a running LAN scan must not offer another Rescan")
	}
}

func TestNetworkMapSnapshotContextAndNarrowRendering(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC)
	m := lanLifecycleModel(t)
	m.watch, m.networkMap = true, true
	m.cur = lanSnapshot(at, JobFailed, "192.168.12.50")
	r := m.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("10.0.0.8")
	m.results[diagnostic.ProbeInternet] = r
	view := ansi.Strip(m.networkMapView())
	if !strings.Contains(view, "192.168.12.0/24") || !strings.Contains(view, "This device now 10.0.0.8") || !strings.Contains(view, "Cached snapshot · scan failed") {
		t.Fatalf("Watch Mode silently presents old discovery as current:\n%s", view)
	}
	for _, width := range []int{40, 30, 20, 10} {
		m.width = width
		assertFitsWidth(t, m.networkMapView(), width)
	}
}

func TestRescanRowKeepsActionsSelectionIdentity(t *testing.T) {
	m := selectMenu(t, menuModel(t), "Theme")
	if got := highlighted(t, m); got != "Theme" {
		t.Fatalf("menu opened on %q", got)
	}
	m.otherJobs = append(m.otherJobs, lanSnapshot(time.Now(), JobDone, "192.168.1.1"))
	if got := highlighted(t, m); got != "Theme" {
		t.Errorf("Rescan appearing moved the selection to %q", got)
	}
	m.otherJobs[len(m.otherJobs)-1].active = &job{}
	m.otherJobs[len(m.otherJobs)-1].status = JobRunning
	if got := highlighted(t, m); got != "Theme" {
		t.Errorf("Rescan disappearing moved the selection to %q", got)
	}
	if run := sendKey(t, m, "enter"); !run.theming {
		t.Error("enter no longer ran the visibly selected Theme action")
	}
}

func TestLANScanEvictionKeepsNewestMeasurementAndRestartDropsAll(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	m := lanLifecycleModel(t)
	for i := maxParkedJobs; i >= 0; i-- {
		m.otherJobs = append(m.otherJobs, lanSnapshot(base.Add(time.Duration(i)*time.Second), JobDone, "192.168.12.1"))
	}
	m.trimJobs()
	if len(m.otherJobs) != maxParkedJobs {
		t.Fatalf("ring has %d jobs, want %d", len(m.otherJobs), maxParkedJobs)
	}
	newest, _ := m.newestJob(lanDiscoveryName)
	if newest == nil || !newest.start.Equal(base.Add(maxParkedJobs*time.Second)) {
		t.Fatalf("eviction lost the newest LAN measurement: %+v", newest)
	}
	u, cmd := m.Update(keyMsg("v"))
	m = asModel(t, u)
	if cmd != nil || !m.networkMap || !m.cur.start.Equal(base.Add(maxParkedJobs*time.Second)) {
		t.Fatal("v fell back to an older LAN scan after ring eviction")
	}
	u, _ = m.retest()
	m = asModel(t, u)
	if m.hasJob() || len(m.otherJobs) != 0 || m.networkMap || m.networkCIDR != "" {
		t.Fatal("Retest/restart must discard cached LAN scan state")
	}
}

// The map's second line is the whole freshness model: a reader has to be able
// to tell a sweep running right now from evidence a finished one left behind,
// without knowing that the map is a rendering of a parked tool run.
func TestNetworkMapSaysWhetherItIsLiveOrCached(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC)
	live := lanLifecycleModel(t)
	live.networkMap = true
	live.cur = lanSnapshot(at, JobRunning, "192.168.12.50")
	live.cur.active = &job{}
	live.now = func() time.Time { return at.Add(8 * time.Second) }
	view := ansi.Strip(live.networkMapView())
	if !strings.Contains(view, "Live scan · started 8s ago") || strings.Contains(view, "Cached snapshot") {
		t.Fatalf("a running sweep does not say it is live:\n%s", view)
	}

	cached := live
	cached.cur.active, cached.cur.status = nil, JobDone
	view = ansi.Strip(cached.networkMapView())
	if !strings.Contains(view, "Cached snapshot · captured 6s ago") || strings.Contains(view, "Live scan") {
		t.Fatalf("a finished sweep still reads as live:\n%s", view)
	}
}

// A fresh sweep that fails must not be able to borrow the devices an earlier
// one found, and must not bury the fact that the earlier one is still around.
func TestFailedScanNeitherClaimsNorHidesEarlierEvidence(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		fresh jobState
	}{
		{"no devices", lanSnapshot(base.Add(time.Minute), JobFailed, "")},
		{"partial devices", lanSnapshot(base.Add(time.Minute), JobTimedOut, "192.168.12.2")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := lanLifecycleModel(t)
			m.networkMap = true
			m.otherJobs = []jobState{lanSnapshot(base, JobDone, "192.168.12.1")}
			m.cur = tc.fresh
			m.now = func() time.Time { return base.Add(2 * time.Minute) }
			view := ansi.Strip(m.networkMapView())
			if strings.Contains(view, "192.168.12.1") {
				t.Errorf("the failed sweep is showing the earlier sweep's device:\n%s", view)
			}
			if !strings.Contains(view, "Cached snapshot · scan "+tc.fresh.status.String()) {
				t.Errorf("the failed sweep reads as a healthy snapshot:\n%s", view)
			}
			if !strings.Contains(view, "Earlier successful scan from 1m58s ago is still in the job list (tab)") {
				t.Errorf("the surviving successful scan is not mentioned:\n%s", view)
			}
		})
	}

	done := lanLifecycleModel(t)
	done.networkMap = true
	done.otherJobs = []jobState{lanSnapshot(base, JobDone, "192.168.12.1")}
	done.cur = lanSnapshot(base.Add(time.Minute), JobDone, "192.168.12.9")
	done.now = func() time.Time { return base.Add(2 * time.Minute) }
	view := ansi.Strip(done.networkMapView())
	if strings.Contains(view, "Earlier successful scan") {
		t.Errorf("a successful sweep points at an older one it replaced:\n%s", view)
	}
	if !strings.Contains(view, "192.168.12.9") || strings.Contains(view, "192.168.12.1 ") {
		t.Errorf("the newest successful sweep is not the displayed one:\n%s", view)
	}
}

// The freshness cues are words, and they are above the device list, so they
// survive a terminal with no colour and one too short for the whole map.
func TestNetworkMapCuesSurviveMonochromeAndConstrainedTerminals(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC)
	mono := themes[len(themes)-1]
	if mono.Name != "monochrome" {
		t.Fatalf("expected the monochrome theme last, got %q", mono.Name)
	}
	// The four sizes the map has to serve whole, then two too short for it: a
	// clipped map loses device rows from the bottom, never the cue above them,
	// and a terminal short enough to shed the map entirely misleads nobody.
	for _, size := range [][3]int{{120, 40, 1}, {100, 30, 1}, {80, 24, 1}, {70, 20, 1}, {80, 12, 0}, {60, 8, 0}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			m := lanLifecycleModel(t)
			m.setTheme(mono)
			m.networkMap = true
			m.width, m.height = size[0], size[1]
			m.cur = lanSnapshot(at, JobDone, "192.168.12.50")
			m.now = func() time.Time { return at.Add(3 * time.Minute) }
			view := m.View()
			assertFitsWidth(t, view, m.width)
			if got := lipgloss.Height(view); got > m.height {
				t.Errorf("map view is %d rows tall in a %d-row terminal", got, m.height)
			}
			plain := ansi.Strip(view)
			cue := strings.Contains(plain, "Cached snapshot · captured 2m58s ago")
			devices := strings.Contains(plain, "192.168.12.50")
			if devices && !cue {
				t.Errorf("devices are on screen with nothing saying they are cached:\n%s", plain)
			}
			if size[2] == 1 && !(cue && devices) {
				t.Errorf("cue=%v devices=%v, want both at this size:\n%s", cue, devices, plain)
			}
		})
	}
}

// An opened device is a row of the snapshot, and enter on one of its services
// repoints this run's checks. Neither is visible from the service list itself.
func TestOpenedDeviceNamesTheSnapshotAndWhatEnterDoes(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC)
	m := mapModel(t)
	m.cur.start, m.cur.dur = at, 2*time.Second
	m.now = func() time.Time { return at.Add(90 * time.Second) }
	opened := openedDevice(t, m)
	view := ansi.Strip(opened.View())
	if !strings.Contains(view, "From the snapshot captured 1m28s ago") {
		t.Errorf("the device panel does not say where the device came from:\n%s", view)
	}
	if !strings.Contains(view, "enter restarts the checks against the selected service") {
		t.Errorf("the device panel does not say what diagnosing a service does:\n%s", view)
	}
	// Back-navigation is unchanged: esc to the devices, the map key to checks.
	back := sendKey(t, opened, "esc")
	if back.svc.host != "" || !back.networkMap {
		t.Fatal("esc must return from services to the device list")
	}
	if checks := sendKey(t, back, "v"); checks.networkMap {
		t.Fatal("the map key must return from the device list to the checks")
	}
}

// Retest reruns this run's checks; Rescan takes a fresh LAN snapshot. They stay
// two rows, in two groups, doing two things.
func TestRetestAndRescanStayDistinct(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC)
	m := lanLifecycleModel(t)
	m.networkMap = true
	m.started[diagnostic.ProbeIface] = true
	m.cur = lanSnapshot(at, JobDone, "192.168.12.50")
	names := menuNames(m)
	if !slices.Contains(names, "Retest checks") || !slices.Contains(names, "Rescan network") {
		t.Fatalf("the two network actions are not both offered: %v", names)
	}

	oldLookPath := toolLookPath
	toolLookPath = func(string) (string, error) { return "nmap", nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })
	rescan := sendKey(t, selectMenu(t, m, "Rescan network"), "enter")
	if rescan.confirmTool == nil || rescan.confirmTool.Name != lanDiscoveryName || rescan.generation != m.generation {
		t.Fatal("Rescan must confirm fresh discovery without restarting the checks")
	}

	retest := sendKey(t, selectMenu(t, m, "Retest checks"), "enter")
	if retest.confirmTool != nil || retest.generation != m.generation+1 || retest.target != m.target {
		t.Fatal("Retest must rerun the same checks rather than scan the network")
	}
	if retest.networkMap || retest.hasJob() {
		t.Fatal("Retest starts a new run, so it leaves the cached map behind")
	}
}

// Rescan stays menu-only, so the map's help bar has to say where it lives.
func TestMapHelpBarPointsAtRescan(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC)
	m := lanLifecycleModel(t)
	m.networkMap = true
	m.cur = lanSnapshot(at, JobDone, "192.168.12.50")
	if bar := ansi.Strip(m.helpView(false)); !strings.Contains(bar, "actions: rescan") {
		t.Errorf("the map's help bar does not route to a fresh scan: %q", bar)
	}
	running := m
	running.cur.active, running.cur.status = &job{}, JobRunning
	if bar := ansi.Strip(running.helpView(false)); strings.Contains(bar, "rescan") {
		t.Errorf("a running sweep offers another one: %q", bar)
	}
	checks := m
	checks.networkMap = false
	if bar := ansi.Strip(checks.helpView(false)); strings.Contains(bar, "rescan") {
		t.Errorf("the checks screen advertises a map action: %q", bar)
	}
}
