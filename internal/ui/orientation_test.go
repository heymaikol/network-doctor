// Orientation: what every screen says about where the reader is before they
// press a key. The rule under test is one line: each region the cursor can be
// in opens with a heading naming it, a nested region names the region it is
// nested in, and none of that is allowed to cost the diagnosis a row.

package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// jobModel is a finished run with one tool's output parked beside it, which is
// the state the job pane and the output viewer are both reached from.
func jobModel(t *testing.T, width, height int) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.width, m.height = width, height
	doneResults(&m, diagnostic.ProbeDNS)
	m.cur = jobState{name: "ping the host", display: "ping -c 4 example.com", status: JobDone, dur: 2 * time.Second}
	for i := range 40 {
		m.cur.lines = append(m.cur.lines, fmt.Sprintf("64 bytes from example.com: icmp_seq=%d time=1%d ms", i, i))
	}
	return m
}

func openViewer(t *testing.T, m model) model {
	t.Helper()
	u, _ := m.Update(keyPress("enter"))
	v := asModel(t, u)
	if !v.viewing {
		t.Fatal("enter must open the output viewer")
	}
	return v
}

// openedDevice is the third level of the map sequence: checks, network map,
// device. The scan is stubbed, so nothing here touches a network.
func openedDevice(t *testing.T, m model) model {
	t.Helper()
	stubServices(t, scanOf(
		diagnostic.LocalService{Port: 80, Name: "HTTP", Scheme: "http"},
		diagnostic.LocalService{Port: 22, Name: "SSH"},
	))
	u, cmd := m.Update(keyPress("enter"))
	opened := asModel(t, u)
	for _, msg := range msgsFrom(t, cmd) {
		u, _ = opened.Update(msg)
		opened = asModel(t, u)
	}
	if opened.svc.host == "" {
		t.Fatal("enter on the map must open the selected device")
	}
	return opened
}

// Every region the cursor can be in says what it is. The viewer and the job
// pane matter most: they open on the same "$ command" row, so without their
// headings the only difference is what is absent from one of them.
func TestEveryNavigableRegionNamesItself(t *testing.T) {
	cases := []struct {
		name  string
		build func(*testing.T) model
		want  string
	}{
		{"checks", func(t *testing.T) model { return jobModel(t, 100, 40) }, "Checks"},
		{"job pane", func(t *testing.T) model { return jobModel(t, 100, 40) }, jobPaneTitle},
		{"full output", func(t *testing.T) model { return openViewer(t, jobModel(t, 100, 40)) }, viewerTitle},
		{"network map", func(t *testing.T) model { return mapModel(t) }, mapTitle},
		{"opened device", func(t *testing.T) model { return openedDevice(t, mapModel(t)) }, mapTitle},
		{"actions menu", func(t *testing.T) model {
			u, _ := jobModel(t, 100, 40).Update(keyMsg(" "))
			return asModel(t, u)
		}, "Actions"},
		// Already named before this rule existed; pinned so it stays that way.
		{"incident viewer", func(t *testing.T) model {
			m := newModel(mustTarget(t, "example.com:443"), false)
			m.width, m.height, m.watch = 100, 30, true
			doneResults(&m, diagnostic.ProbeDNS)
			m.recordRun()
			m.openIncidentViewer()
			return m
		}, "Watch incidents"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			view := ansi.Strip(c.build(t).View())
			if !strings.Contains(view, c.want) {
				t.Errorf("region is not named %q on screen:\n%s", c.want, view)
			}
		})
	}
}

// The device step keeps the device it opened on screen. Without it "diagnose
// this service" is an instruction with no subject: the map knows several
// devices and the list of ports alone does not say which one answered.
func TestOpenedDeviceKeepsDeviceIdentity(t *testing.T) {
	opened := openedDevice(t, mapModel(t))
	view := ansi.Strip(opened.View())
	if !strings.Contains(view, "192.168.12.1 (router.lan)") {
		t.Errorf("the opened device must stay named while its services are listed:\n%s", view)
	}
	// The level it is nested in is named on the same heading, so the reader can
	// tell a service list from the device list without pressing anything.
	head := ansi.Strip(opened.serviceChooserView())
	title, _, _ := strings.Cut(strings.TrimLeft(head, "╭─╮\n│ "), "\n")
	if !strings.HasPrefix(strings.TrimSpace(title), mapTitle) {
		t.Errorf("the service list heading must name the map it is nested in, got %q", title)
	}
}

// The viewer and the check list are different screens, and a reader deciding
// what ↑/↓ will move has to be able to tell which one is up.
func TestOutputViewerIsDistinguishableFromTheCheckList(t *testing.T) {
	m := jobModel(t, 100, 40)
	list := ansi.Strip(m.View())
	if !strings.Contains(list, "Checks") || strings.Contains(list, viewerTitle) {
		t.Errorf("the main screen must show the check list and not the viewer heading:\n%s", list)
	}
	viewer := ansi.Strip(openViewer(t, m).View())
	if !strings.Contains(viewer, viewerTitle) {
		t.Errorf("the viewer must name itself:\n%s", viewer)
	}
	if strings.Contains(viewer, "Checks") {
		t.Errorf("the viewer must not look like the check list:\n%s", viewer)
	}
	// The job pane is the same output under a different heading, which is the
	// whole reason the heading has to be there.
	if !strings.Contains(list, jobPaneTitle) || strings.Contains(viewer, jobPaneTitle) {
		t.Errorf("the job pane and the viewer must not share a heading:\nlist:\n%s\nviewer:\n%s", list, viewer)
	}
}

// A filter hides lines, so the viewer has to say one is on. Pressing the clear
// key must then put the hidden lines back rather than leave the viewer.
func TestFilteredOutputSaysItIsFiltered(t *testing.T) {
	v := openViewer(t, jobModel(t, 100, 40))
	u, _ := v.Update(keyMsg("/"))
	f := asModel(t, u)
	for _, r := range "icmp_seq=7" {
		u, _ = f.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		f = asModel(t, u)
	}
	u, _ = f.Update(keyPress("enter"))
	applied := asModel(t, u)
	view := ansi.Strip(applied.View())
	if !strings.Contains(view, "filter: icmp_seq=7") {
		t.Errorf("an applied filter must be named on screen:\n%s", view)
	}
	if !strings.Contains(view, viewerTitle) {
		t.Errorf("filtering must not cost the viewer its heading:\n%s", view)
	}
	// What the bar offers is what the key does: clear first, leave second.
	if !strings.Contains(view, "clear filter") || !strings.Contains(view, "back") {
		t.Errorf("a filtered viewer must offer clearing and leaving separately:\n%s", view)
	}
	u, _ = applied.Update(keyPress("esc"))
	cleared := asModel(t, u)
	if cleared.filter != "" || !cleared.viewing {
		t.Errorf("clear must clear the filter and stay in the viewer, got filter=%q viewing=%v", cleared.filter, cleared.viewing)
	}
}

// The words on the map's help bar are promises about the keys. Each one is
// pressed here and the level it lands on is checked, so the wording cannot
// drift away from what dispatch actually does.
func TestMapBackWordingAgreesWithDispatch(t *testing.T) {
	opened := openedDevice(t, mapModel(t))
	bar := ansi.Strip(opened.helpView(false))
	if !strings.Contains(bar, "devices") || !strings.Contains(bar, "checks") {
		t.Fatalf("the opened device must offer both ways back:\n%s", bar)
	}
	u, _ := opened.Update(keyPress("esc"))
	back := asModel(t, u)
	if back.svc.host != "" || !back.networkMap {
		t.Errorf("esc says devices, so it must land on the device list, got svc=%q map=%v", back.svc.host, back.networkMap)
	}
	if view := ansi.Strip(back.View()); strings.Contains(view, "Services on") {
		t.Errorf("the device list must not still show a device's services:\n%s", view)
	}
	u, _ = opened.Update(keyMsg("v"))
	checks := asModel(t, u)
	if checks.networkMap {
		t.Error("v says checks, so it must leave the map")
	}
	if view := ansi.Strip(checks.View()); !strings.Contains(view, "Checks") {
		t.Errorf("leaving the map must land on the check list:\n%s", view)
	}
}

// Orientation is text, not colour: the monochrome theme drops every colour and
// the headings still have to answer "where am I".
func TestOrientationSurvivesMonochrome(t *testing.T) {
	mono := themes[len(themes)-1]
	if mono.Name != "monochrome" {
		t.Fatalf("expected the monochrome theme last, got %q", mono.Name)
	}
	m := jobModel(t, 100, 40)
	m.setTheme(mono)
	for _, want := range []string{"Checks", jobPaneTitle} {
		if view := ansi.Strip(m.View()); !strings.Contains(view, want) {
			t.Errorf("monochrome lost %q:\n%s", want, view)
		}
	}
	v := openViewer(t, m)
	if view := ansi.Strip(v.View()); !strings.Contains(view, viewerTitle) {
		t.Errorf("monochrome lost the viewer heading:\n%s", view)
	}
	opened := openedDevice(t, func() model { mm := mapModel(t); mm.setTheme(mono); return mm }())
	if view := ansi.Strip(opened.View()); !strings.Contains(view, mapTitle+" · Services on") {
		t.Errorf("monochrome lost the map nesting:\n%s", view)
	}
}

// Orientation is worth a row only while the answer still has all of its own.
// The job pane's heading costs none, and the pane is dropped whole before the
// diagnosis gives anything up, so a short terminal keeps the verdict and its
// remediation no matter what is running behind them.
func TestOrientationYieldsBeforeTheDiagnosis(t *testing.T) {
	for _, size := range [][2]int{{120, 40}, {100, 30}, {80, 24}, {70, 20}, {80, 14}, {80, 10}, {80, 8}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			m := jobModel(t, size[0], size[1])
			m.cur.active = &job{}
			m.cur.status, m.cur.start = JobRunning, time.Now()
			view := ansi.Strip(m.View())
			if !strings.Contains(view, "Cannot resolve example.com") {
				t.Errorf("the verdict must survive:\n%s", view)
			}
			if !strings.Contains(view, "Then press R to retest") {
				t.Errorf("the remediation must survive:\n%s", view)
			}
			// The heading rides on the rule the pane already drew, so it is
			// present exactly when the pane is and never on its own.
			if strings.Contains(view, jobPaneTitle) != strings.Contains(view, "$ ping -c 4 example.com") {
				t.Errorf("the pane heading and the pane must appear together:\n%s", view)
			}
		})
	}
}

// No orientation heading is allowed to push a view past the terminal: the
// renderer clips from the top, which is where the verdict lives.
func TestOrientedViewsFitTheTerminal(t *testing.T) {
	for _, size := range [][2]int{{120, 40}, {100, 30}, {80, 24}, {70, 20}, {80, 14}, {80, 10}} {
		for _, c := range []struct {
			name  string
			build func(*testing.T, int, int) model
		}{
			{"job pane", jobModel},
			{"viewer", func(t *testing.T, w, h int) model { return openViewer(t, jobModel(t, w, h)) }},
			{"filtered viewer", func(t *testing.T, w, h int) model {
				v := openViewer(t, jobModel(t, w, h))
				v.filter = "icmp_seq=1"
				v.refreshViewport()
				return v
			}},
			{"network map", func(t *testing.T, w, h int) model {
				mm := mapModel(t)
				u, _ := mm.Update(tea.WindowSizeMsg{Width: w, Height: h})
				return asModel(t, u)
			}},
			{"opened device", func(t *testing.T, w, h int) model {
				mm := mapModel(t)
				u, _ := mm.Update(tea.WindowSizeMsg{Width: w, Height: h})
				return openedDevice(t, asModel(t, u))
			}},
		} {
			t.Run(fmt.Sprintf("%s %dx%d", c.name, size[0], size[1]), func(t *testing.T) {
				m := c.build(t, size[0], size[1])
				view := m.View()
				if got := lipgloss.Height(view); got > size[1] {
					t.Errorf("view is %d rows, terminal is %d:\n%s", got, size[1], ansi.Strip(view))
				}
				for _, line := range strings.Split(ansi.Strip(view), "\n") {
					if got := lipgloss.Width(line); got > size[0] {
						t.Errorf("line is %d cells, terminal is %d: %q", got, size[0], line)
					}
				}
			})
		}
	}
}

// The viewer's heading is orientation; its footer is the keymap. Both presets
// bind the viewer's own movement keys, so the bar must name the bound keys and
// the heading must be there either way.
func TestViewerOrientationHoldsUnderEveryPreset(t *testing.T) {
	for _, preset := range KeyPresets() {
		t.Run(preset, func(t *testing.T) {
			km, err := PresetKeymap(preset)
			if err != nil {
				t.Fatalf("PresetKeymap(%q): %v", preset, err)
			}
			m := jobModel(t, 100, 30)
			m.keys = km
			v := openViewer(t, m)
			view := ansi.Strip(v.View())
			if !strings.Contains(view, viewerTitle) {
				t.Errorf("%s lost the viewer heading:\n%s", preset, view)
			}
			// Every key the bar offers is a key this preset actually binds in
			// the viewer, so the wording and the dispatch cannot drift.
			for _, act := range []keyAction{actUp, actDown, actBack, actFilter} {
				label := km.label(ctxViewer, act)
				if label == "" {
					t.Fatalf("%s binds nothing for viewer action %d", preset, act)
				}
				if !strings.Contains(view, strings.Split(label, "/")[0]) {
					t.Errorf("%s: the viewer bar does not name %q:\n%s", preset, label, view)
				}
			}
		})
	}
}

// Orientation names the interaction state and leaves the domain state alone:
// the viewer says which output it is showing, not which target the run is
// about, since the run is not what the cursor is in.
func TestOrientationDoesNotRepeatDomainContext(t *testing.T) {
	v := openViewer(t, jobModel(t, 100, 40))
	head := ansi.Strip(v.viewerHeader())
	if strings.Contains(head, "watch") || strings.Contains(head, "Wi-Fi") {
		t.Errorf("the viewer heading must not carry the run's context strip: %q", head)
	}
	// One heading per region, not one per line of it.
	if n := strings.Count(head, viewerTitle); n != 1 {
		t.Errorf("the viewer heading is written %d times, want once: %q", n, head)
	}
	m := jobModel(t, 100, 40)
	if n := strings.Count(ansi.Strip(m.View()), jobPaneTitle); n != 1 {
		t.Errorf("the job pane heading is written more than once:\n%s", ansi.Strip(m.View()))
	}
}
