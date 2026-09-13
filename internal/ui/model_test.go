// Key handling and view behavior: restart, quit, the confirm gate, the output
// viewer, notices, and terminal-height clamping.

package ui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func asModel(t *testing.T, m tea.Model) model {
	t.Helper()
	mm, ok := m.(model)
	if !ok {
		t.Fatalf("expected model, got %T", m)
	}
	return mm
}

func newModel(t *diagnostic.Target, toolbox bool) model {
	return NewWithSelection(t, nil, toolbox, false, "", "test", diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)
}

func keyMsg(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// doneResults fills every probe with a result: failID fails, the rest pass.
// An empty failID means an all-pass run.
func doneResults(m *model, failID diagnostic.ProbeID) {
	for _, p := range m.probes {
		status := diagnostic.StatusPass
		if p.ID == failID {
			status = diagnostic.StatusFail
		}
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: status}
	}
}

func TestHelpOverlay(t *testing.T) {
	m := newModel(nil, false)
	m.width, m.height = 100, 40
	u, _ := m.Update(keyMsg("?"))
	hm := asModel(t, u)
	view := ansi.Strip(hm.View())
	if !hm.helping || !strings.Contains(view, "Output viewer") || !strings.Contains(view, "any key close") {
		t.Fatal("? must show the key cheatsheet")
	}
	if strings.Contains(view, "lines 1-") {
		t.Error("a complete cheatsheet must not show scrolling controls")
	}
	u, _ = hm.Update(keyMsg("x"))
	if asModel(t, u).helping {
		t.Error("any key must close the cheatsheet")
	}
}

func TestHelpOverlayScrolls(t *testing.T) {
	open := func(width, height int) model {
		m := newModel(nil, false)
		u, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
		u, _ = asModel(t, u).Update(keyMsg("?"))
		return asModel(t, u)
	}
	press := func(m model, key tea.KeyMsg) model {
		u, _ := m.Update(key)
		return asModel(t, u)
	}

	for _, height := range []int{32, 30, 24, 20, 16, 10} {
		t.Run(fmt.Sprintf("100x%d", height), func(t *testing.T) {
			m := open(100, height)
			top := ansi.Strip(m.View())
			if !strings.Contains(top, "lines 1-") || !strings.Contains(top, "scroll") {
				t.Fatalf("short help has no continuation indication:\n%s", top)
			}
			seen := top
			for range 20 {
				m = press(m, keyPress("pgdown"))
				seen += "\n" + ansi.Strip(m.View())
			}
			if !strings.Contains(seen, "Output viewer") {
				t.Fatalf("paging never reached the Output viewer section:\n%s", seen)
			}
			m = press(m, keyPress("end"))
			bottom := ansi.Strip(m.View())
			if !m.helping || !strings.Contains(bottom, "clear the filter, or back when none is set") ||
				!strings.Contains(bottom, "close") {
				t.Fatalf("bottom of help is not reachable:\n%s", bottom)
			}
			if got := ansi.Strip(press(m, keyPress("down")).View()); got != bottom {
				t.Error("help scrolled beyond the bottom")
			}
			m = press(m, keyPress("home"))
			if got := ansi.Strip(m.View()); got != top {
				t.Error("home did not return help to the top")
			}
			if got := ansi.Strip(press(m, keyPress("up")).View()); got != top {
				t.Error("help scrolled beyond the top")
			}
		})
	}

	m := open(100, 24)
	m = press(m, keyPress("end"))
	m = press(m, keyMsg("x"))
	if m.helping {
		t.Fatal("ordinary key did not close scrolled help")
	}
	m = press(m, keyMsg("?"))
	if view := ansi.Strip(m.View()); !strings.Contains(view, "lines 1-") {
		t.Fatalf("reopened help did not reset to the top:\n%s", view)
	}
	for _, key := range []tea.KeyMsg{keyPress("esc"), keyMsg("q"), keyMsg("?"), {Type: tea.KeyCtrlC}} {
		m := open(100, 24)
		if m = press(m, key); m.helping {
			t.Errorf("%s did not close help", key.String())
		}
	}
}

func TestHelpOverlayResize(t *testing.T) {
	m := newModel(nil, false)
	u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	u, _ = asModel(t, u).Update(keyMsg("?"))
	m = asModel(t, u)

	u, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	m = asModel(t, u)
	if view := ansi.Strip(m.View()); !strings.Contains(view, "lines 1-") {
		t.Fatalf("tall-to-short resize did not make help scrollable:\n%s", view)
	}
	u, _ = m.Update(keyPress("end"))
	m = asModel(t, u)
	u, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	m = asModel(t, u)
	view := ansi.Strip(m.View())
	if !strings.Contains(view, "Keys\n") || !strings.Contains(view, "any key close") || regexp.MustCompile(`(?m)^lines `).MatchString(view) {
		t.Fatalf("short-to-tall resize did not reveal complete help:\n%s", view)
	}
}

// TestHelpOverlayFitsNarrowTerminal renders the cheatsheet at the widths the
// rest of the TUI supports, for every preset. No row may be wider than the
// terminal: the terminal would hard-wrap it into display rows MaxHeight never
// counted. A description that wraps must still read against its own key.
func TestHelpOverlayFitsNarrowTerminal(t *testing.T) {
	// A continuation row is indented past the key column; an entry row is not.
	continuation := regexp.MustCompile(`\n {3,}(\S)`)
	noSpace := func(s string) string { return strings.ReplaceAll(s, " ", "") }
	for _, preset := range KeyPresets() {
		km, err := PresetKeymap(preset)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range [][2]int{{100, 40}, {100, 32}, {100, 30}, {100, 24}, {100, 20}, {100, 16}, {100, 10}, {60, 40}, {40, 40}, {30, 40}, {24, 40}, {40, 24}} {
			w, h := size[0], size[1]
			m := newModel(nil, false)
			m.keys = km
			u, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
			u, _ = asModel(t, u).Update(keyMsg("?"))
			m = asModel(t, u)
			v := m.View()
			if lipgloss.Height(v) > m.height {
				t.Errorf("%s %dx%d: view is %d display rows tall:\n%s", preset, w, h, lipgloss.Height(v), v)
			} else {
				for _, line := range strings.Split(v, "\n") {
					if got := lipgloss.Width(line); got > w {
						t.Errorf("%s %dx%d: line is %d columns wide: %q", preset, w, h, got, ansi.Strip(line))
					}
				}
			}
			bottom := ansi.Strip(v)
			if !strings.Contains(bottom, "any key close") {
				u, _ = m.Update(keyPress("end"))
				bottom = ansi.Strip(asModel(t, u).View())
			}
			if !regexp.MustCompile(`(?m)^  q +back *$`).MatchString(bottom) || !strings.Contains(bottom, "close") {
				t.Errorf("%s %dx%d: final help is not reachable:\n%s", preset, w, h, bottom)
			}
			m.height = 0 // unclipped: every entry must survive wrapping
			sheet := ansi.Strip(m.helpOverlay())
			for _, line := range strings.Split(sheet, "\n") {
				if got := lipgloss.Width(line); got > w {
					t.Errorf("%s width %d: line is %d wide: %q", preset, w, got, line)
				}
			}
			if !strings.HasPrefix(sheet, "Keys\n") || !strings.Contains(sheet, "\nOutput viewer\n") || !strings.HasSuffix(sheet, "\nany key close") {
				t.Errorf("%s width %d: headings or close hint lost:\n%s", preset, w, sheet)
			}
			// Rejoin each wrapped description and compare it to its metadata
			// ignoring spaces, since a word too long for the column is split.
			// Anchoring to the row start pins the description to its key.
			joined := noSpace(continuation.ReplaceAllString(sheet, "$1"))
			expect := func(key, desc string) {
				t.Helper()
				if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(noSpace(key+desc)) + `$`).MatchString(joined) {
					t.Errorf("%s width %d: %q is not followed by %q:\n%s", preset, w, key, desc, sheet)
				}
			}
			for _, def := range actionDefs {
				for ctx, help := range def.help {
					if km.bound(ctx, def.act) && def.act != actSSH {
						expect(km.label(ctx, def.act), help.details)
					}
				}
			}
			for _, tool := range m.tools {
				expect(tool.Key, "run "+tool.Name)
			}
		}
	}
}

func TestNetworkMapToggle(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(string) (string, error) { return "nmap", nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, diagnostic.ProbeDNS)
	r := m.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("192.168.12.34")
	m.results[diagnostic.ProbeInternet] = r
	r.Source = net.ParseIP("203.0.113.34")
	m.results[diagnostic.ProbeInternet] = r
	if _, cidr := m.discoveryNetwork(); cidr != "" {
		t.Fatalf("public source produced discovery scope %q", cidr)
	}
	r.Source = net.ParseIP("192.168.12.34")
	m.results[diagnostic.ProbeInternet] = r
	if help := m.helpView(false); strings.Contains(help, "network map") {
		t.Fatalf("normal footer still advertises network map: %s", help)
	}

	u, cmd := m.Update(keyMsg("v"))
	nm := asModel(t, u)
	if nm.confirmTool == nil || nm.confirmTool.Key != "v" || cmd != nil || nm.networkMap {
		t.Fatal("v must open the confirm gate before sweeping the LAN")
	}
	if !strings.Contains(nm.View(), "-sn") {
		t.Error("confirm gate must show the discovery command")
	}
	u, _ = nm.Update(keyMsg("y"))
	nm = asModel(t, u)
	if nm.confirmTool != nil || nm.cur.name != lanDiscoveryName || nm.cur.status == JobQueued || !nm.networkMap || nm.networkCIDR != "192.168.12.0/24" || !strings.Contains(nm.View(), "LAN scan") {
		t.Fatalf("y must run the LAN scan on the local /24:\n%s", nm.View())
	}

	nm.cur.active = nil
	nm.cur.name, nm.cur.status = lanDiscoveryName, JobDone
	nm.cur.lines = []string{
		"Host: 192.168.12.1 (router.lan.example)\tStatus: Up",
		"Host: 192.168.12.50 (living-room-tv.lan.example)\tStatus: Up",
		"Host: 192.168.12.51 ()\tStatus: Up",
	}
	view := nm.View()
	if !nm.networkMap || !strings.Contains(view, "192.168.12.1 (router)") || !strings.Contains(view, "192.168.12.50 (living-room-tv)") || !strings.Contains(view, "Domain: lan.example") || !strings.Contains(view, "192.168.12.51") || strings.Contains(view, "Host:") {
		t.Fatalf("LAN scan must render discovered devices in the network map:\n%s", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if at := strings.Index(line, "Domain:"); at >= 0 && lipgloss.Width(line[:at]) <= nm.width/2 {
			t.Fatalf("domain must be right-aligned in the network map:\n%s", view)
		}
	}

	nm.cur.lines = append(nm.cur.lines, "Host: 192.168.12.52 (printer.office.example)\tStatus: Up")
	view = nm.View()
	if !strings.Contains(view, "router.lan.example") || !strings.Contains(view, "living-room-tv.lan.example") || !strings.Contains(view, "printer.office.example") || strings.Contains(view, "Domain:") {
		t.Fatalf("mixed domains must remain visible in the network map:\n%s", view)
	}

	// The map stands in for the LAN scan's raw output, so the job pane stays
	// hidden while it is up, and the job strip inside that pane with it. A run
	// parked behind the map must not be leaked onto the map by the strip.
	nm.otherJobs = []jobState{{name: "parked run", status: JobDone}}
	view = nm.View()
	if strings.Contains(view, "parked run") || strings.Contains(ansi.Strip(view), "› "+lanDiscoveryName) {
		t.Fatalf("the network map must keep the raw LAN job pane hidden:\n%s", view)
	}
	// Hidden is not unreachable: tab still selects the parked run, and leaving
	// the map brings the strip back with both runs on it.
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyTab})
	tabbed := asModel(t, u)
	if tabbed.networkMap || tabbed.cur.name != "parked run" {
		t.Fatalf("tab must still reach the run parked behind the map, got %q (map=%v)", tabbed.cur.name, tabbed.networkMap)
	}
	strip := ansi.Strip(tabbed.jobStrip())
	if !strings.HasPrefix(strip, "› parked run") || !strings.Contains(strip, lanDiscoveryName) {
		t.Fatalf("leaving the map must show both runs on the strip: %q", strip)
	}
	nm.otherJobs = nil

	u, _ = nm.Update(keyMsg("v"))
	nm = asModel(t, u)
	if nm.networkMap || !strings.Contains(nm.View(), "Details:") {
		t.Fatal("second v must return to the checks view")
	}
}

func TestNetworkMapRecalledFromOtherJobs(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(string) (string, error) { return "nmap", nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, "")
	r := m.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("192.168.12.34")
	m.results[diagnostic.ProbeInternet] = r
	m.cur = jobState{name: lanDiscoveryName, status: JobDone, lines: []string{
		"Host: 192.168.12.1 (router.lan.example)\tStatus: Up",
	}}
	m.otherJobs = []jobState{{name: "ping", status: JobDone}}
	m.networkCIDR = "192.168.12.0/24"

	// Tab parks the finished scan; v must fetch it back, not re-gate a sweep.
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm := asModel(t, u)
	if nm.cur.name != "ping" {
		t.Fatalf("tab must switch to ping, got %q", nm.cur.name)
	}
	u, _ = nm.Update(keyMsg("v"))
	nm = asModel(t, u)
	if nm.confirmTool != nil || !nm.networkMap || nm.cur.name != lanDiscoveryName {
		t.Fatalf("v must re-show the parked scan, got cur=%q confirm=%v", nm.cur.name, nm.confirmTool != nil)
	}
	if len(nm.otherJobs) != 1 || nm.otherJobs[0].name != "ping" {
		t.Fatalf("ping must stay reachable in otherJobs, got %v", nm.otherJobs)
	}
}

func TestNetworkMapPrefersResolvedNames(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:22"), false)
	m.networkMap = true
	m.networkCIDR = "192.168.12.0/24"
	m.cur.name, m.cur.status = lanDiscoveryName, JobDone
	m.cur.lines = []string{
		"Host: 192.168.12.1 (isp-cpe-4471.example)\tStatus: Up",
		"Host: 192.168.12.50 ()\tStatus: Up",
		"Host: 192.168.12.60 (asleep.lan)\tStatus: Down",
	}

	if got := discoveredIPs(m.cur.lines); len(got) != 2 || got[0] != "192.168.12.1" || got[1] != "192.168.12.50" {
		t.Fatalf("discoveredIPs = %v, want the two Up addresses", got)
	}

	u, _ := m.Update(lanNamesMsg{gen: 0, names: map[string]string{"192.168.12.1": "pihole"}})
	m = asModel(t, u)
	if hosts := m.networkHosts(); len(hosts) != 2 || hosts[0] != "192.168.12.1 (pihole)" || hosts[1] != "192.168.12.50" {
		t.Fatalf("networkHosts = %v, want the resolved name to beat nmap's", hosts)
	}

	u, _ = m.Update(lanNamesMsg{gen: 1, names: map[string]string{"192.168.12.50": "stale"}})
	m = asModel(t, u)
	if hosts := m.networkHosts(); hosts[1] != "192.168.12.50" {
		t.Fatalf("stale-generation names must be ignored: %v", hosts)
	}
}

func TestNetworkMapDomainIgnoresBareAliases(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:22"), false)
	m.width = 100
	m.networkMap = true
	m.networkCIDR = "192.168.1.0/24"
	m.cur.name, m.cur.status = lanDiscoveryName, JobDone
	m.cur.lines = []string{
		"Host: 192.168.1.1 ()\tStatus: Up",
		"Host: 192.168.1.7 (unknownaabbcc.attlocal.net)\tStatus: Up",
		"Host: 192.168.1.8 (unknownddeeff.attlocal.net)\tStatus: Up",
	}
	m.hostNames = map[string]string{"192.168.1.1": "pihole"}

	view := m.View()
	if !strings.Contains(view, "Domain: attlocal.net") || !strings.Contains(view, "192.168.1.7 (unknownaabbcc)") || !strings.Contains(view, "192.168.1.1 (pihole)") || strings.Contains(view, "attlocal.net)") {
		t.Fatalf("bare aliases must not veto domain stripping:\n%s", view)
	}
}

// Selecting a device opens that device; it does not silently decide the device
// is an HTTPS server on 443, which is what it used to amount to.
func TestNetworkMapSelectsDeviceNotADefaultService(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:22"), false)
	m.networkMap = true
	m.networkCIDR = "192.168.12.0/24"
	m.cur.name, m.cur.status = lanDiscoveryName, JobDone
	m.cur.lines = []string{
		"Host: 192.168.12.1 (router.lan)\tStatus: Up",
		"Host: 192.168.12.50 (printer.lan)\tStatus: Up",
	}

	u, _ := m.Update(keyMsg("j"))
	m = asModel(t, u)
	if m.mapSelected != 1 || !strings.Contains(m.helpView(false), "open device") {
		t.Fatalf("map selection = %d, help = %q", m.mapSelected, m.helpView(false))
	}

	before := m.target
	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	if m.target != before || m.generation != 0 {
		t.Fatalf("target = %+v (generation %d), want the run left alone until a service is picked", m.target, m.generation)
	}
	if m.svc.host != "192.168.12.50" || m.svc.done || cmd == nil {
		t.Fatalf("device = %q done=%v cmd=%v, want the selected device opened and its services asked for", m.svc.host, m.svc.done, cmd != nil)
	}
	if view := m.View(); !strings.Contains(view, "Services on 192.168.12.50 (printer.lan)") || !strings.Contains(view, "checking common service ports") {
		t.Fatalf("the opened device must say what it is doing:\n%s", view)
	}
}

func TestNetworkMapEnterClampsAfterShrink(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:22"), false)
	m.networkMap = true
	m.networkCIDR = "192.168.12.0/24"
	m.cur.name, m.cur.status = lanDiscoveryName, JobDone
	m.cur.lines = []string{"Host: 192.168.12.1 (router.lan)\tStatus: Up"}
	m.mapSelected = 3 // list shrank under the cursor

	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	if m.svc.host != "192.168.12.1" {
		t.Fatalf("opened device = %q, want the last remaining host", m.svc.host)
	}
}

func TestReportReadyWithoutToolRun(t *testing.T) {
	m := newModel(nil, false)
	doneResults(&m, "")
	if !m.reportReady() {
		t.Error("completed checks must be exportable without running a tool")
	}
}

func TestProbeSelectionPreservesDiagnosis(t *testing.T) {
	target := mustTarget(t, "1.1.1.1:81")
	baseline := newModel(target, false)
	doneResults(&baseline, diagnostic.ProbeTargetTCP)
	order := baseline.probeOrder()
	wantSummary, wantVerdict := baseline.diagnose(order)

	selection := diagnostic.ProbeSelection{Skip: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeSSID: {}}}
	selected := NewWithSelection(target, nil, false, false, "", "test", diagnostic.DefaultPublicDNS, true, selection).(model)
	doneResults(&selected, diagnostic.ProbeTargetTCP)
	order = selected.probeOrder()
	if summary, verdict := selected.diagnose(order); summary != wantSummary || verdict != wantVerdict {
		t.Fatalf("skipping SSID changed diagnosis from %q/%q to %q/%q", wantSummary, wantVerdict, summary, verdict)
	}
}

// A probeDoneMsg from a stale generation is dropped (mirrors the gen guard).
func TestStaleProbeDropped(t *testing.T) {
	m := newModel(nil, false)
	m.generation = 5
	u, cmd := m.Update(probeDoneMsg{id: diagnostic.ProbeIface, gen: 0, res: diagnostic.ProbeResult{Status: diagnostic.StatusPass}})
	nm := asModel(t, u)
	if _, ok := nm.results[diagnostic.ProbeIface]; ok {
		t.Error("stale probe must not store a result")
	}
	if cmd != nil {
		t.Error("stale probe must issue no cmd")
	}
}

// The nmap hotkey holds the exact command in a confirm gate instead of
// launching; the gate shows the command, and any non-'y' key cancels without
// ever starting a scan.
func TestNmapConfirmGate(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	u, cmd := m.Update(keyMsg("n"))
	nm := asModel(t, u)
	if nm.confirmTool == nil || nm.confirmTool.Key != "n" {
		t.Fatal("n must open the confirm gate for nmap")
	}
	if nm.cur.active != nil || cmd != nil {
		t.Error("confirm gate must not launch a job yet")
	}
	if !strings.Contains(nm.View(), "nmap ") {
		t.Error("confirm gate must show the nmap command before running")
	}
	u, _ = nm.Update(keyMsg("j"))
	nm = asModel(t, u)
	if nm.confirmTool == nil {
		t.Error("a stray key must not dismiss the confirm gate")
	}
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	nm = asModel(t, u)
	if nm.confirmTool != nil {
		t.Error("esc must close the confirm gate")
	}
	u, _ = nm.Update(keyMsg("n"))
	nm = asModel(t, u)
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	nm = asModel(t, u)
	if nm.confirmTool != nil {
		t.Error("ctrl+c must close the confirm gate")
	}
	if nm.cur.active != nil {
		t.Error("ctrl+c must not launch a scan")
	}
}

// 'r' opens the restart prompt; Enter bumps the generation, clears run state,
// and resets the context.
func TestRestartResets(t *testing.T) {
	m := newModel(nil, false)
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.started[diagnostic.ProbeIface] = true
	m.cur.status, m.cur.name, m.cur.display, m.cur.dur = JobDone, "ping", "ping example.com", 1
	m.cur.lines = []string{"reply from example.com"}
	m.hostNames = map[string]string{"192.168.1.1": "old-router"}
	gen0 := m.generation
	u, _ := m.Update(keyMsg("r"))
	nm := asModel(t, u)
	if !nm.entering {
		t.Fatal("r must open the restart prompt")
	}
	u, cmd := nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm = asModel(t, u)
	if nm.entering {
		t.Error("enter must close the prompt")
	}
	if nm.generation != gen0+1 {
		t.Errorf("generation = %d, want %d", nm.generation, gen0+1)
	}
	if len(nm.results) != 0 || len(nm.started) != 0 {
		t.Error("restart must clear results/started")
	}
	if len(nm.hostNames) != 0 {
		t.Error("restart must clear resolved LAN names")
	}
	if nm.ctx != nil {
		t.Error("restart must reset ctx to nil")
	}
	if nm.cur.status != JobQueued || nm.cur.name != "" || nm.cur.display != "" || nm.cur.dur != 0 || len(nm.cur.lines) != 0 {
		t.Error("restart must clear the previous job")
	}
	if pane := nm.jobView(10); pane != "" {
		t.Errorf("restart left a stale job pane: %q", pane)
	}
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if asModel(t, u).viewing {
		t.Error("enter must not open the output viewer after restart")
	}
	if cmd == nil {
		t.Fatal("restart must issue a cmd")
	}
}

func TestRestartClosesNmapConfirmGate(t *testing.T) {
	for _, target := range []string{"", "example.com:2222"} {
		t.Run(target, func(t *testing.T) {
			m := newModel(mustTarget(t, "example.com:443"), false)
			u, _ := m.Update(keyMsg("n"))
			m = asModel(t, u)

			var next *diagnostic.Target
			if target != "" {
				next = mustTarget(t, target)
			}
			m.applyTarget(next, true)
			m.doRestart()

			if m.confirmTool != nil {
				t.Fatal("restart must close the stale nmap confirmation gate")
			}
			m.View() // A stale gate panicked here after a targetless restart.
		})
	}
}

// The restart prompt: prefilled with the current target, esc cancels, a bad
// line errors and stays open, a good line swaps the target and restarts.
// It is titled "Restart" and shows the target-forms cheatsheet: before any
// WindowSizeMsg (height 0 = size unknown), on a roomy terminal, and alongside
// a validation error.
func TestRestartPrompt(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), false)
	u, _ := m.Update(keyMsg("r"))
	nm := asModel(t, u)
	if !nm.entering {
		t.Fatal("r must open the restart prompt")
	}
	if nm.input.Value() != "github.com" {
		t.Errorf("prefill = %q, want github.com", nm.input.Value())
	}
	if !strings.Contains(nm.View(), "netdoc") {
		t.Error("prompt view must show the command line")
	}
	if !strings.Contains(nm.View(), "Restart") {
		t.Error("prompt panel must be titled Restart")
	}
	// Width is 0 here, so the panel wraps hard; assert the five example
	// targets (short tokens survive word wrap) rather than whole lines.
	for _, form := range []string{"example.com", "example.com:8022", "ssh://example.com:8022", "192.0.2.1", "[2001:db8::1]:443", "(nothing)"} {
		if !strings.Contains(nm.View(), form) {
			t.Errorf("prompt before WindowSizeMsg must show target form %q", form)
		}
	}

	// On a roomy terminal the panel is 88 wide and each form line renders
	// unwrapped, annotation and all.
	u, _ = nm.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	nm = asModel(t, u)
	formLines := []string{
		"example.com            hostname (default port 443)",
		"example.com:8022       hostname with port (protocol inferred from the port)",
		"ssh://example.com:8022 URL (scheme sets protocol and default port; path ignored)",
		"192.0.2.1, 2001:db8::1 IP literal",
		"[2001:db8::1]:443      IP literal with port (IPv6 needs the brackets)",
		"(nothing)              no target, runs the generic checks",
	}
	for _, line := range formLines {
		if !strings.Contains(nm.View(), line) {
			t.Errorf("roomy prompt must show form line %q", line)
		}
	}

	// A validation error joins the forms; it must not displace them.
	nm.input.SetValue("one two")
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	errView := asModel(t, u).View()
	if !strings.Contains(errView, "one target only") {
		t.Error("bad line must show the validation error")
	}
	for _, line := range formLines {
		if !strings.Contains(errView, line) {
			t.Errorf("forms must stay visible alongside the error, missing %q", line)
		}
	}

	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if esc := asModel(t, u); esc.entering || esc.generation != 0 {
		t.Error("esc must close the prompt without a restart")
	}

	nm.input.SetValue("one two")
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	bad := asModel(t, u)
	if !bad.entering || bad.inputErr == "" {
		t.Error("a bad line must keep the prompt open with an error")
	}

	bad.input.SetValue("netdoc example.com:22")
	u, cmd := bad.Update(tea.KeyMsg{Type: tea.KeyEnter})
	good := asModel(t, u)
	if good.entering {
		t.Error("a good line must close the prompt")
	}
	if good.target == nil || good.target.Host != "example.com" || good.target.Port != 22 {
		t.Errorf("target = %+v, want example.com:22", good.target)
	}
	if good.generation != 1 || cmd == nil {
		t.Error("commit must restart")
	}
}

func TestQuit(t *testing.T) {
	m := newModel(nil, false)
	u, cmd := m.Update(keyMsg("q"))
	_ = asModel(t, u)
	if cmd == nil {
		t.Fatal("quit must return a cmd")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("expected tea.QuitMsg, got %T", cmd())
	}
}

func TestViewerEscAndQGoBack(t *testing.T) {
	m := newModel(nil, false)
	m.cur.status = JobDone
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm := asModel(t, u)
	if got := nm.View(); !strings.Contains(got, defaultStyles.key.Render("esc/q")) {
		t.Errorf("viewer footer must offer esc/q back, got %q", got)
	}

	u, cmd := nm.Update(keyMsg("q"))
	nm = asModel(t, u)
	if nm.viewing || cmd != nil {
		t.Error("q in viewer must go back")
	}
	u, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm = asModel(t, u)
	u, cmd = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	nm = asModel(t, u)
	if nm.viewing || cmd != nil {
		t.Error("esc in viewer must go back")
	}
}

func TestViewerCopiesFullOutput(t *testing.T) {
	t.Setenv("TMUX", "")
	done := captureStderr(t)

	m := newModel(nil, false)
	m.cur.status = JobDone
	m.cur.lines = []string{"first", "second"}
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm := asModel(t, u)
	if !strings.Contains(nm.View(), defaultStyles.key.Render("y")) {
		t.Fatal("viewer footer must offer y to copy output")
	}

	u, cmd := nm.Update(keyMsg("y"))
	nm = asModel(t, u)
	if got, want := done(), osc52Sequence("first\nsecond"); got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
	if cmd == nil || nm.notice != "output sent to clipboard (OSC 52); w saves a file" {
		t.Fatalf("notice = %q, cmd nil = %v", nm.notice, cmd == nil)
	}
}

func TestViewerSavesFilteredOutput(t *testing.T) {
	oldWriteFile := reportWriteFile
	t.Cleanup(func() { reportWriteFile = oldWriteFile })

	var saved string
	reportWriteFile = func(_ string, data []byte, perm os.FileMode) error {
		if perm != 0o600 {
			t.Errorf("mode = %o, want 600", perm)
		}
		saved = string(data)
		return nil
	}

	m := newModel(nil, false)
	m.cur.status = JobDone
	m.cur.lines = []string{"keep first", "drop", "keep second"}
	m.viewing = true
	m.filter = "keep"
	m.refreshViewport()
	if !strings.Contains(m.View(), defaultStyles.key.Render("w")) {
		t.Fatal("viewer footer must offer w to save output")
	}

	u, cmd := m.Update(keyMsg("w"))
	nm := asModel(t, u)
	if saved != "keep first\nkeep second" {
		t.Errorf("saved output = %q", saved)
	}
	if cmd == nil || !strings.HasPrefix(nm.notice, "output saved to ") {
		t.Fatalf("notice = %q, cmd nil = %v", nm.notice, cmd == nil)
	}
}

func TestViewerFilterLifecycle(t *testing.T) {
	m := newModel(nil, false)
	m.cur.status = JobDone
	m.cur.lines = []string{"alpha", "beta"}
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm := asModel(t, u)

	u, _ = nm.Update(keyMsg("/"))
	nm = asModel(t, u)
	if !nm.filtering {
		t.Fatal("/ must start filtering")
	}

	u, _ = nm.Update(keyMsg("a"))
	nm = asModel(t, u)
	if nm.filter != "a" {
		t.Fatalf("typing must update the live filter, got %q", nm.filter)
	}

	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm = asModel(t, u)
	if nm.filtering || nm.filter != "a" {
		t.Fatalf("enter must commit the filter, filtering=%v filter=%q", nm.filtering, nm.filter)
	}

	// Esc is two-stage once a filter is committed: clear first, leave second.
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	nm = asModel(t, u)
	if nm.filter != "" || !nm.viewing {
		t.Fatalf("first esc must clear the filter and stay, filter=%q viewing=%v", nm.filter, nm.viewing)
	}
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if asModel(t, u).viewing {
		t.Error("second esc must leave the viewer")
	}
}

func TestViewerFilterEscAbandonsEntry(t *testing.T) {
	m := newModel(nil, false)
	m.cur.status = JobDone
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm := asModel(t, u)
	for _, k := range []tea.KeyMsg{keyMsg("/"), keyMsg("x"), {Type: tea.KeyEsc}} {
		u, _ = nm.Update(k)
		nm = asModel(t, u)
	}
	if nm.filtering || nm.filter != "" || !nm.viewing {
		t.Fatalf("esc mid-entry must drop the filter but stay, filtering=%v filter=%q viewing=%v",
			nm.filtering, nm.filter, nm.viewing)
	}
}

func TestTabSwitchNotice(t *testing.T) {
	for _, tc := range []struct {
		name    string
		viewing bool
	}{
		{"main", false},
		{"viewer", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newModel(nil, false)
			m.cur.name, m.cur.display, m.cur.status = "current tool", "current", JobDone
			m.cur.lines = []string{"current output"}
			m.otherJobs = []jobState{{name: "next tool", display: "next", status: JobDone, lines: []string{"next output"}}}
			m.networkMap = true
			u, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
			m = asModel(t, u)
			if tc.viewing {
				u, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
				m = asModel(t, u)
				m.follow = false
				if lipgloss.Height(m.viewerFooter()) <= 1 {
					t.Fatal("narrow viewer help must wrap before the notice")
				}
			}

			u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyTab})
			nm := asModel(t, u)
			if cmd == nil || nm.notice != "switched to next tool" || !nm.noticeOK {
				t.Fatalf("notice = %q, ok = %v, cmd nil = %v", nm.notice, nm.noticeOK, cmd == nil)
			}
			if nm.networkMap || tc.viewing && !nm.follow {
				t.Fatal("switch state must update before showing the notice")
			}
			if !strings.Contains(nm.View(), "switched to next tool") {
				t.Fatal("switched job notice must render")
			}
			if tc.viewing && nm.vp.Height != nm.vpHeight() {
				t.Fatalf("viewport height after notice = %d, want %d", nm.vp.Height, nm.vpHeight())
			}

			u, _ = nm.Update(noticeDoneMsg{deadline: nm.noticeDeadline})
			cleared := asModel(t, u)
			if cleared.notice != "" {
				t.Fatalf("notice after timeout = %q, want empty", cleared.notice)
			}
			if tc.viewing && cleared.vp.Height != cleared.vpHeight() {
				t.Fatalf("viewport height after notice clears = %d, want %d", cleared.vp.Height, cleared.vpHeight())
			}
		})
	}
}

func TestEscCancelsFocusedJob(t *testing.T) {
	m := newModel(nil, false)
	canceled := false
	m.cur.active = &job{cancel: func() { canceled = true }}
	otherCanceled := false
	m.otherJobs = []jobState{{name: "other", active: &job{cancel: func() { otherCanceled = true }}}}

	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	nm := asModel(t, u)
	if !canceled {
		t.Error("esc must cancel the focused job")
	}
	if otherCanceled {
		t.Error("esc must not cancel background jobs")
	}
	if !strings.Contains(nm.View(), "canceling") {
		t.Error("esc must show a canceling notice")
	}

	// No job running: esc is a no-op, not a crash.
	nm.cur.active = nil
	if _, cmd := nm.Update(tea.KeyMsg{Type: tea.KeyEsc}); cmd != nil {
		t.Error("esc with no active job must do nothing")
	}
}

func TestCtrlCWarnsThenQuits(t *testing.T) {
	m := newModel(nil, false)
	canceled := false
	m.cur.active = &job{cancel: func() { canceled = true }}

	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	nm := asModel(t, u)
	if cmd == nil {
		t.Fatal("first ctrl+c must schedule the notice timeout")
	}
	if canceled {
		t.Error("first ctrl+c must not cancel the active job")
	}
	if nm.pending != nil {
		t.Errorf("first ctrl+c pending action = %v, want nil", nm.pending.kind)
	}
	if !strings.Contains(nm.View(), ctrlCNotice) {
		t.Error("first ctrl+c must show the quit hint")
	}

	expired, _ := nm.Update(noticeDoneMsg{deadline: nm.noticeDeadline})
	if strings.Contains(asModel(t, expired).View(), ctrlCNotice) {
		t.Error("quit hint must clear after the timeout")
	}

	nm.cur.active = nil
	u, cmd = nm.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	_ = asModel(t, u)
	if cmd == nil {
		t.Fatal("second ctrl+c must quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("second ctrl+c command = %T, want tea.QuitMsg", cmd())
	}
}

// TestCtrlCNoticeVisibleInOverlays pins the armed-quit invariant: whenever
// Ctrl+C has armed the whole-program quit, the screen the reader is actually
// looking at has to say so. These overlays draw their own footer where the
// help bar goes, so each one is checked through View() rather than through
// m.notice: the state was always set, it was the rendering that dropped it.
func TestCtrlCNoticeVisibleInOverlays(t *testing.T) {
	cases := []struct {
		name string
		open func(m *model)
		// footer is a word from the overlay's own footer, which must be back
		// once the notice clears.
		footer string
	}{
		{"theme picker", func(m *model) { m.theming = true }, "preview"},
		{"actions menu", func(m *model) { m.actionsOpen = true }, "close"},
		{"ssh form", func(m *model) { m.sshPrompt = true; m.ssh.host = "host" }, "connect"},
		{"ssh form checking config", func(m *model) {
			m.sshPrompt, m.ssh.host, m.ssh.pending = true, "host", &sshPending{}
		}, "back"},
		{"restart prompt", func(m *model) { m.entering = true }, "history"},
		{"output viewer filtering", func(m *model) { m.viewing, m.filtering = true, true }, "apply"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newModel(nil, false)
			m.width, m.height = 100, 40
			tc.open(&m)
			if before := m.View(); !strings.Contains(before, tc.footer) {
				t.Fatalf("overlay footer %q missing before the notice", tc.footer)
			}

			u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
			armed := asModel(t, u)
			if cmd == nil {
				t.Fatal("first ctrl+c must schedule the notice timeout")
			}
			if !strings.Contains(armed.View(), ctrlCNotice) {
				t.Errorf("armed quit is invisible: View() lacks %q", ctrlCNotice)
			}

			// The notice takes the footer's slot rather than sitting under it,
			// so the overlay's keys come back only once it clears.
			expired, _ := armed.Update(noticeDoneMsg{deadline: armed.noticeDeadline})
			cleared := asModel(t, expired)
			if strings.Contains(cleared.View(), ctrlCNotice) {
				t.Errorf("quit notice must clear after the timeout")
			}
			if !strings.Contains(cleared.View(), tc.footer) {
				t.Errorf("overlay footer %q did not come back after the notice cleared", tc.footer)
			}

			// Second ctrl+c inside the window still quits the program.
			u, cmd = armed.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
			_ = asModel(t, u)
			if cmd == nil {
				t.Fatal("second ctrl+c must quit")
			}
			if _, ok := cmd().(tea.QuitMsg); !ok {
				t.Errorf("second ctrl+c command = %T, want tea.QuitMsg", cmd())
			}
		})
	}
}

func TestReportNoticeExpires(t *testing.T) {
	restore := captureStderr(t)
	defer restore()

	m := newModel(nil, false)
	doneResults(&m, "")
	u, cmd := m.Update(keyMsg("y"))
	nm := asModel(t, u)
	if cmd == nil || nm.notice != "report sent to clipboard (OSC 52); w saves a file" {
		t.Fatalf("copy notice = %q, cmd nil = %v", nm.notice, cmd == nil)
	}

	expired, _ := nm.Update(noticeDoneMsg{deadline: nm.noticeDeadline})
	if got := asModel(t, expired).notice; got != "" {
		t.Errorf("notice after timeout = %q, want empty", got)
	}
}

func TestSetNoticeSanitizesText(t *testing.T) {
	m := newModel(nil, false)
	m.setNotice("\x1b[31msave failed\x1b[0m: \u202eLIAF\u202c", false)
	if got, want := m.notice, "save failed: LIAF"; got != want {
		t.Errorf("notice = %q, want %q", got, want)
	}
}

// scheduleMsg creates the generation context and dispatches only the root probe.
func TestScheduleStartsRoot(t *testing.T) {
	m := newModel(nil, false)
	u, cmd := m.Update(scheduleMsg{gen: 0})
	nm := asModel(t, u)
	if nm.ctx == nil {
		t.Error("scheduleMsg must create the generation context")
	}
	if !nm.started[diagnostic.ProbeIface] {
		t.Error("iface (root) should be dispatched")
	}
	if nm.started[diagnostic.ProbeInternet] || nm.started[diagnostic.ProbeDNS] {
		t.Error("dependants of iface must wait")
	}
	if cmd == nil {
		t.Error("expected a dispatch cmd")
	}
}

func TestCancelJobsReachesOtherJobs(t *testing.T) {
	m := newModel(nil, false)
	var curCancelled, otherCancelled bool
	m.cur.active = &job{cancel: func() { curCancelled = true }}
	m.otherJobs = []jobState{
		{}, // finished job: nil active must not panic
		{active: &job{cancel: func() { otherCancelled = true }}},
	}
	m.cancelJobs()
	if !curCancelled || !otherCancelled {
		t.Fatalf("cancel called: cur=%v other=%v", curCancelled, otherCancelled)
	}
}

func TestRunProbeSnapshotIndependence(t *testing.T) {
	m := newModel(nil, false)
	m.ctx = context.Background()
	var seen diagnostic.ProbeResult
	p := diagnostic.Probe{
		ID:   "probe",
		Deps: []diagnostic.ProbeID{"dep"},
		Run: func(_ context.Context, deps map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
			seen = deps["dep"]
			deps["dep"] = diagnostic.ProbeResult{Detail: "scribbled"}
			return diagnostic.ProbeResult{ID: "probe", Status: diagnostic.StatusPass}
		},
	}
	m.results["dep"] = diagnostic.ProbeResult{ID: "dep", Status: diagnostic.StatusPass, Detail: "before"}
	cmd := m.runProbe(p)
	// Mutations after dispatch must not leak into the probe, nor its writes back.
	m.results["dep"] = diagnostic.ProbeResult{ID: "dep", Status: diagnostic.StatusFail, Detail: "after"}
	cmd()
	if seen.Detail != "before" {
		t.Errorf("probe saw %q, want pre-dispatch snapshot %q", seen.Detail, "before")
	}
	if m.results["dep"].Detail != "after" {
		t.Errorf("probe write leaked into live map: %q", m.results["dep"].Detail)
	}
}

// The cursor clamps at the ends of the Checks panel's row list, which is not
// the end of the probe list: the Wi-Fi probe has no row, and here it is the
// last probe of the run, so the cursor must stop on the row before it rather
// than park on a probe the panel is not showing.
func TestSelectionClamp(t *testing.T) {
	m := newModel(nil, false)
	rows := m.checkRows()
	last := rows[len(rows)-1]
	if last == len(m.probes)-1 {
		t.Fatalf("every probe has a row, so this no longer covers the clamp past a rowless one")
	}
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if asModel(t, u).selected != rows[0] {
		t.Error("up at top must stay on the first row")
	}
	for i := 0; i < len(m.probes); i++ {
		u, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = asModel(t, u)
	}
	if m.selected != last {
		t.Errorf("selected = %d, want clamp at the last row %d", m.selected, last)
	}
}

// Completion jumps to the first failure only if the user never moved the cursor.
func TestCompletionKeepsMovedSelection(t *testing.T) {
	m := newModel(nil, false)
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = asModel(t, u)
	for _, p := range m.probes {
		m.started[p.ID] = true
		m.results[p.ID] = diagnostic.ProbeResult{Status: diagnostic.StatusFail}
	}
	last := m.probes[len(m.probes)-1]
	u, _ = m.Update(probeDoneMsg{id: last.ID, gen: 0, res: diagnostic.ProbeResult{Status: diagnostic.StatusFail}})
	if got := asModel(t, u).selected; got != 1 {
		t.Errorf("selected = %d, want 1 (user cursor kept)", got)
	}
}

// A finished run parks the cursor on the row the verdict blames, which is not
// always the first failure: a path MTU black hole fails TLS, HTTP, and HTTPS,
// but the evidence and the remediation are on the Path MTU row, so leaving the
// cursor (and therefore the Details pane) on TLS contradicts the banner.
func TestCompletionSelectsBlamedRow(t *testing.T) {
	// A TLS handshake that ran out of time, which is what the black-hole
	// verdict correlates with the Path MTU warning.
	stall := func(r *diagnostic.ProbeResult) {
		r.Status, r.Cause = diagnostic.StatusFail, diagnostic.TLSCauseTimeout
	}
	breakTLS := func(r *diagnostic.ProbeResult) { r.Status = diagnostic.StatusFail }

	tests := []struct {
		name    string
		results map[diagnostic.ProbeID]func(*diagnostic.ProbeResult)
		want    diagnostic.ProbeID
	}{
		{
			name: "path MTU black hole",
			results: map[diagnostic.ProbeID]func(*diagnostic.ProbeResult){
				diagnostic.ProbePMTU:  func(r *diagnostic.ProbeResult) { r.Status = diagnostic.StatusWarn },
				diagnostic.ProbeTLS:   stall,
				diagnostic.ProbeHTTP:  breakTLS,
				diagnostic.ProbeHTTPS: breakTLS,
			},
			want: diagnostic.ProbePMTU,
		},
		{
			// No redirected blame: the ordinary first-failure rule still holds.
			name:    "plain TLS failure",
			results: map[diagnostic.ProbeID]func(*diagnostic.ProbeResult){diagnostic.ProbeTLS: breakTLS},
			want:    diagnostic.ProbeTLS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newModel(mustTarget(t, "example.com:443"), false)
			m.tools = toolsFor(m.target, "linux", toolBind{})
			var last diagnostic.Probe
			for _, p := range m.probes {
				r := diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Detail: string(p.ID) + " detail"}
				if mut, ok := tt.results[p.ID]; ok {
					mut(&r)
				}
				m.started[p.ID] = true
				m.results[p.ID] = r
				last = p
			}
			// The real completion path: the last probe reporting in is what
			// finalizes the run and moves the cursor.
			u, _ := m.Update(probeDoneMsg{id: last.ID, gen: m.generation, res: m.results[last.ID]})
			done := asModel(t, u)
			if got := done.probes[done.selected].ID; got != tt.want {
				t.Fatalf("selected row = %s, want %s", got, tt.want)
			}
			// The blamed row is the one the answer block quotes, so that is
			// where its finding, its remedy and its evidence are: the Details
			// panel deliberately does not print them a second time.
			line, _ := done.evidenceLine(done.results[tt.want].Detail)
			if banner := done.banner(); !strings.Contains(banner, strings.TrimSpace(line)) {
				t.Errorf("the answer block does not quote %s:\n%s", tt.want, banner)
			}
		})
	}
}

// The banner's drill-down must not send a path MTU black hole to curl, which
// stalls for exactly the reason the protocol rows did.
func TestBlackHoleBannerAvoidsCurl(t *testing.T) {
	m := blackHoleModel(t)
	banner := m.banner()
	if !strings.Contains(banner, "path MTU black hole") {
		t.Fatalf("banner is not the path MTU verdict:\n%s", banner)
	}
	if !strings.Contains(banner, "press t for trace the path") {
		t.Errorf("banner does not offer the path tool:\n%s", banner)
	}
	if strings.Contains(banner, "web check") {
		t.Errorf("banner still sends the reader to curl:\n%s", banner)
	}
}

func TestExitCode(t *testing.T) {
	m := newModel(nil, false)
	if ExitCode(m) != 1 {
		t.Error("unfinished chain must exit 1")
	}
	for _, probe := range m.probes {
		m.results[probe.ID] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	}
	if ExitCode(m) != 0 {
		t.Error("all-pass must exit 0")
	}
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{Status: diagnostic.StatusFail}
	if ExitCode(m) != 1 {
		t.Error("a fail must exit 1")
	}
	m.watch = true
	m.results = map[diagnostic.ProbeID]diagnostic.ProbeResult{}
	for _, probe := range m.probes {
		m.runHistory[probe.ID] = []diagnostic.Status{diagnostic.StatusPass}
	}
	if ExitCode(m) != 0 {
		t.Error("an interrupted watch pass must use the last completed run")
	}
}

// Runes batched into one KeyMsg by a fast stdin read ("xxr") are replayed one
// key at a time instead of matching no binding and being dropped.
func TestBatchedRunesReplayed(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	u, _ := m.Update(keyMsg("xxr"))
	nm := asModel(t, u)
	if !nm.entering {
		t.Error("batched xxr not replayed; trailing r should open the restart prompt")
	}
}

// Enter opens the output viewer while a job is running even before any output
// has arrived (e.g. mtr --report buffers everything until exit).
func TestEnterViewerBeforeOutput(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.cur.active = &job{}
	m.cur.status = JobRunning
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm := asModel(t, u)
	if !nm.viewing {
		t.Fatal("enter must open the viewer for a running job with no output yet")
	}
	if !strings.Contains(nm.View(), "no output yet") {
		t.Error("empty viewer must show the (no output yet) placeholder")
	}
}

// A running job with lots of output must never grow the view past the
// terminal height: the renderer drops the top lines, which reads as the
// whole UI scrolling.
func TestViewFitsTerminal(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.cur.status = JobRunning
	m.cur.display = "ping example.com"
	for range 200 {
		m.cur.lines = append(m.cur.lines, "reply from 1.2.3.4")
	}
	for _, size := range []tea.WindowSizeMsg{
		{Width: 120, Height: 40},
		{Width: 100, Height: 24},
		{Width: 80, Height: 20},
	} {
		u, _ := m.Update(size)
		nm := asModel(t, u)
		if rows := strings.Count(nm.View(), "\n") + 1; rows > nm.height {
			t.Errorf("%dx%d: view is %d rows, terminal is %d", size.Width, size.Height, rows, nm.height)
		}
	}
	// Same invariant with the restart prompt (and its forms cheatsheet) open.
	for _, size := range []tea.WindowSizeMsg{
		{Width: 120, Height: 40},
		{Width: 100, Height: 24},
	} {
		u, _ := m.Update(size)
		nm := asModel(t, u)
		u, _ = nm.Update(keyMsg("r"))
		nm = asModel(t, u)
		if rows := strings.Count(nm.View(), "\n") + 1; rows > nm.height {
			t.Errorf("prompt open %dx%d: view is %d rows, terminal is %d", size.Width, size.Height, rows, nm.height)
		}
	}
}

// A short or narrow terminal scrolls the panels down, then drops them outright.
// The banner never yields:
// it carries the plain-English verdict, and it is the first thing the renderer
// would eat. See TestPersistentBlockSurvivesLongResultList for the header and
// the help bar, which outlive the panels for the same reason.
func TestShortTerminalKeepsBanner(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.cur.status = JobRunning
	m.cur.display = "ping example.com"
	for range 50 {
		m.cur.lines = append(m.cur.lines, "reply from 1.2.3.4")
	}
	for _, size := range []tea.WindowSizeMsg{
		{Width: 40, Height: 17}, {Width: 40, Height: 10}, {Width: 40, Height: 6},
		{Width: 60, Height: 8}, {Width: 80, Height: 8}, {Width: 120, Height: 7},
		{Width: 30, Height: 4},
	} {
		u, _ := m.Update(size)
		nm := asModel(t, u)
		v := nm.View()
		if rows := strings.Count(v, "\n") + 1; rows > nm.height {
			t.Errorf("%dx%d: view is %d rows, terminal is %d", size.Width, size.Height, rows, nm.height)
		}
		if !strings.Contains(v, "Checking your connection") {
			t.Errorf("%dx%d: banner must survive:\n%s", size.Width, size.Height, v)
		}
	}
}

func TestViewClampsLongDetailsToTerminal(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.results[m.probes[0].ID] = diagnostic.ProbeResult{
		Status:   diagnostic.StatusWarn,
		Detail:   "some addresses failed",
		Attempts: make([]diagnostic.Attempt, 16),
	}
	u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	nm := asModel(t, u)
	view := nm.View()
	if rows := strings.Count(view, "\n") + 1; rows > nm.height {
		t.Errorf("view is %d rows, terminal is %d", rows, nm.height)
	}
	if !strings.Contains(view, "Checking your connection") {
		t.Error("height clamp must preserve the banner")
	}
}

// On a short terminal the forms cheatsheet is dropped but the input survives.
func TestPromptFormsDroppedWhenShort(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	u, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	nm := asModel(t, u)
	u, _ = nm.Update(keyMsg("r"))
	nm = asModel(t, u)
	v := nm.View()
	if strings.Contains(v, "hostname (default port 443)") {
		t.Error("80x12: forms cheatsheet must be dropped")
	}
	if !strings.Contains(v, "netdoc") || !strings.Contains(v, "Restart") {
		t.Error("80x12: the input line must survive")
	}
}

// The forms never starve a live job pane below jobView's 5-row minimum: at a
// height where they would squeeze avail to 1-4 rows, the pane wins.
func TestPromptFormsYieldToJobPane(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	for i := range m.tools {
		m.tools[i].Available = false
	}
	m.cur.status = JobRunning
	m.cur.display = "ping example.com"
	for range 200 {
		m.cur.lines = append(m.cur.lines, "reply from 1.2.3.4")
	}
	u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	nm := asModel(t, u)
	u, _ = nm.Update(keyMsg("r"))
	nm = asModel(t, u)
	v := nm.View()
	if !strings.Contains(v, "$ ping example.com") {
		t.Error("100x30: the job pane must still render")
	}
	if strings.Contains(v, "hostname (default port 443)") {
		t.Error("100x30: forms must yield to the job pane")
	}
}

// Nothing View writes may run past a narrow terminal: the terminal's own hard
// wrap would break words and blow View's row budget. Prose the TUI writes
// itself gets wrapped; tool output gets truncated (see TestJobPaneFitsHeight).
func TestViewWrapsToNarrowTerminal(t *testing.T) {
	for _, w := range []int{40, 60, 79} {
		m := newModel(mustTarget(t, "example.com:443"), false)
		u, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: 24})
		nm := asModel(t, u)
		for _, line := range strings.Split(nm.View(), "\n") {
			if got := lipgloss.Width(line); got > w {
				t.Errorf("%d cols: line is %d wide: %q", w, got, line)
			}
		}
	}
}

// The job pane budgets its tail in logical lines, so an output line wider than
// the terminal would cost display rows nobody counted, and ss and traceroute
// produce those routinely. Truncating keeps the frame inside the terminal.
func TestJobPaneFitsHeight(t *testing.T) {
	for _, h := range []int{24, 40, 50} {
		m := newModel(mustTarget(t, "example.com:443"), false)
		m.cur.status = JobRunning
		m.cur.display = "ss -tunp"
		for range 200 {
			m.cur.lines = append(m.cur.lines, strings.Repeat("x", 200))
		}
		u, _ := m.Update(tea.WindowSizeMsg{Width: 60, Height: h})
		nm := asModel(t, u)
		v := nm.View()
		if rows := lipgloss.Height(v); rows > h {
			t.Errorf("60x%d: view is %d display rows tall", h, rows)
		}
		for _, line := range strings.Split(v, "\n") {
			if got := lipgloss.Width(line); got > 60 {
				t.Errorf("60x%d: line is %d wide: %q", h, got, line)
			}
		}
	}
}

// The viewer's own header has the same problem the job pane had: a command
// line wider than the terminal costs display rows the viewport height never
// budgeted for, so the frame runs off the bottom of the screen.
func TestOutputViewerFitsHeight(t *testing.T) {
	for _, h := range []int{24, 40} {
		m := newModel(mustTarget(t, "example.com:443"), false)
		m.cur.status = JobRunning
		m.cur.display = "mtr --report --report-cycles 5 example.com --show-ips --no-dns"
		m.cur.name = "traceroute (mtr)"
		m.cur.lines = []string{"line one", "line two"}
		m.filter = strings.Repeat("z", 80) // pushes the context line past 60 cols too
		u, _ := m.Update(tea.WindowSizeMsg{Width: 60, Height: h})
		nm := asModel(t, u)
		u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
		nm = asModel(t, u)
		if !nm.viewing {
			t.Fatal("enter must open the viewer")
		}
		v := nm.View()
		if rows := lipgloss.Height(v); rows > h {
			t.Errorf("60x%d: viewer is %d display rows tall", h, rows)
		}
		for _, line := range strings.Split(v, "\n") {
			if got := lipgloss.Width(line); got > 60 {
				t.Errorf("60x%d: line is %d wide: %q", h, got, line)
			}
		}
	}
}

// At 40 cols the prompt panel wraps its content instead of overflowing
// horizontally.
func TestPromptViewNarrowNoOverflow(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	u, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 24})
	nm := asModel(t, u)
	u, _ = nm.Update(keyMsg("r"))
	nm = asModel(t, u)
	for _, line := range strings.Split(nm.promptView(true), "\n") {
		if w := lipgloss.Width(line); w > 40 {
			t.Errorf("prompt line %d cols wide, terminal is 40: %q", w, line)
		}
	}
}

// An interactive ssh session ends by taking over the selected job slot, which
// is the slot the network map draws from. The map must detach rather than read
// the ssh exit as the LAN scan's outcome.
func sshMapModel(t *testing.T) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:22"), false)
	doneResults(&m, "")
	r := m.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("192.168.12.34")
	m.results[diagnostic.ProbeInternet] = r
	m.width, m.height = 100, 30
	m.networkMap, m.networkCIDR = true, "192.168.12.0/24"
	m.cur = jobState{name: lanDiscoveryName, status: JobDone, lines: []string{
		"Host: 192.168.12.1 (router.lan)\tStatus: Up",
		"Host: 192.168.12.50 (printer.lan)\tStatus: Up",
	}}
	return m
}

func TestNetworkMapDetachesWhenSSHFinishes(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  sshDoneMsg
	}{
		{"ssh fails", sshDoneMsg{
			err:     errors.New("exit status 255"),
			display: "ssh alice@example.com",
			output:  "alice@example.com: Permission denied (publickey).\n",
		}},
		{"ssh succeeds", sshDoneMsg{display: "ssh alice@example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := sshMapModel(t)
			u, _ := m.Update(tc.msg)
			nm := asModel(t, u)
			if nm.networkMap {
				t.Fatalf("the map stayed open over the %q job", nm.cur.name)
			}
			view := ansi.Strip(nm.View())
			if strings.Contains(view, "Discovery ") || strings.Contains(view, "No other devices replied") {
				t.Fatalf("an ssh exit was reported as a LAN discovery outcome:\n%s", view)
			}
			// The scan itself is untouched: v brings its devices straight back.
			u, _ = nm.Update(keyMsg("v"))
			back := asModel(t, u)
			if back.confirmTool != nil || !back.networkMap || back.cur.name != lanDiscoveryName {
				t.Fatalf("v must re-show the parked scan, got cur=%q confirm=%v", back.cur.name, back.confirmTool != nil)
			}
			if got := ansi.Strip(back.View()); !strings.Contains(got, "192.168.12.1 (router)") || !strings.Contains(got, "192.168.12.50 (printer)") {
				t.Fatalf("the recalled map lost the discovered devices:\n%s", got)
			}
		})
	}
}

// Whatever the map does when ssh finishes, it does every time: a second and a
// third session must not find it attached to the ssh job.
func TestNetworkMapDetachesOnRepeatedSSH(t *testing.T) {
	m := sshMapModel(t)
	for i := range 3 {
		u, _ := m.Update(sshDoneMsg{err: errors.New("exit status 255"), display: "ssh alice@example.com"})
		m = asModel(t, u)
		if m.networkMap {
			t.Fatalf("attempt %d left the map open over %q", i+1, m.cur.name)
		}
		if view := ansi.Strip(m.View()); strings.Contains(view, "Discovery ") || strings.Contains(view, "No other devices replied") {
			t.Fatalf("attempt %d reported ssh as a LAN discovery outcome:\n%s", i+1, view)
		}
		u, _ = m.Update(keyMsg("v"))
		m = asModel(t, u)
		if !m.networkMap || m.cur.name != lanDiscoveryName {
			t.Fatalf("attempt %d could not re-show the scan, got cur=%q", i+1, m.cur.name)
		}
	}
}

// Tab walks the ring; no stop on it may bring the map back up over a job that
// is not the scan.
func TestJobSwitchingNeverRevivesStaleMap(t *testing.T) {
	m := sshMapModel(t)
	m.otherJobs = []jobState{{name: "ping", status: JobDone}}
	u, _ := m.Update(sshDoneMsg{err: errors.New("exit status 255"), display: "ssh alice@example.com"})
	m = asModel(t, u)
	for i := range 4 {
		u, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = asModel(t, u)
		if m.networkMap {
			t.Fatalf("tab %d reopened the map on %q", i+1, m.cur.name)
		}
		if view := ansi.Strip(m.View()); strings.Contains(view, "Network map:") {
			t.Fatalf("tab %d drew the map over %q:\n%s", i+1, m.cur.name, view)
		}
	}
}
