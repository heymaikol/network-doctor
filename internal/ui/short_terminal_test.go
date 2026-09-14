package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

var shortSizes = [][2]int{
	{120, 40}, {100, 30}, {80, 24}, {70, 20}, {80, 16}, {80, 12}, {80, 10},
}

func assertViewFits(t *testing.T, m model) {
	t.Helper()
	view := m.View()
	if got := lipgloss.Height(view); m.height > 0 && got > m.height {
		t.Errorf("view is %d rows high on a %d-row terminal:\n%s", got, m.height, ansi.Strip(view))
	}
	for _, line := range strings.Split(view, "\n") {
		if got := lipgloss.Width(line); m.width > 0 && got > m.width {
			t.Errorf("line is %d columns wide on a %d-column terminal: %q", got, m.width, ansi.Strip(line))
		}
	}
}

func openCheckDetails(t *testing.T, m model) model {
	t.Helper()
	u, _ := m.Update(keyMsg("D"))
	m = asModel(t, u)
	if !m.detailsViewing {
		t.Fatal("the Check details action did not open its viewer")
	}
	return m
}

func TestCheckDetailsActionContract(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "| `D` | open the selected check's complete evidence") {
		t.Fatal("docs/reference.md does not document the Check details binding")
	}

	for _, preset := range KeyPresets() {
		t.Run(preset, func(t *testing.T) {
			km, err := PresetKeymap(preset)
			if err != nil {
				t.Fatal(err)
			}
			if act, pending := resolvedAction(km, ctxList, "D"); act != actCheckDetails || pending != nil {
				t.Fatalf("D = (%d, %v), want Check details", act, pending)
			}

			m := evidenceModel(t)
			m.width, m.height, m.keys = 120, 40, km
			keyboard := openCheckDetails(t, m)
			menu := sendKey(t, selectMenu(t, m, "Check details"), "enter")
			if !menu.detailsViewing || menu.detailsHeader() != keyboard.detailsHeader() {
				t.Errorf("keyboard and Actions disagree: keyboard=%q menu=%q", keyboard.detailsHeader(), menu.detailsHeader())
			}
			help := ansi.Strip(m.helpOverlay())
			if !strings.Contains(help, "D") || !strings.Contains(help, "open the selected check's complete evidence") {
				t.Errorf("help does not expose Check details:\n%s", help)
			}
		})
	}
}

func TestShortTerminalKeepsAnswerAndCheckEvidenceReachable(t *testing.T) {
	base := evidenceModel(t)
	for _, size := range shortSizes {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			u, _ := base.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			m := asModel(t, u)
			main := ansi.Strip(m.View())
			for _, line := range strings.Split(ansi.Strip(m.answerBlock()), "\n") {
				if line != "" && !strings.Contains(main, strings.TrimSpace(line)) {
					t.Errorf("the answer lost %q:\n%s", line, main)
				}
			}
			if !slices.Contains(menuNames(m), "Check details") {
				t.Fatalf("the selected evidence has no route from Actions: %v", menuNames(m))
			}
			if size[1] <= 16 && !strings.Contains(main, "D details") {
				t.Fatalf("the constrained main view does not show the direct evidence route:\n%s", main)
			}

			details := openCheckDetails(t, m)
			assertViewFits(t, details)
			if view := ansi.Strip(details.View()); !strings.Contains(view, detailsTitle) || !strings.Contains(view, "scroll") || !strings.Contains(view, "back") {
				t.Errorf("the evidence viewer does not say what it is or how to navigate:\n%s", view)
			}
			u, _ = details.Update(keyPress("end"))
			bottom := asModel(t, u)
			if view := ansi.Strip(bottom.View()); !strings.Contains(view, "198.51.100.10 34ms connection refused") {
				t.Errorf("the last selected-check evidence is unreachable:\n%s", view)
			}
			u, _ = bottom.Update(keyPress("esc"))
			if back := asModel(t, u); back.detailsViewing || back.selected != m.selected {
				t.Errorf("back changed the check selection: viewing=%v selected=%d, want %d", back.detailsViewing, back.selected, m.selected)
			}
		})
	}
}

func TestShortChecksWindowFollowsEveryCursorPosition(t *testing.T) {
	for _, width := range []int{70, 80, 100} {
		for _, height := range []int{18, 19, 20, 21, 22, 24} {
			m := blackHoleModel(t)
			m.expanded, m.width, m.height = true, width, height
			for _, selected := range m.checkRows() {
				m.selected = selected
				before := m.selected
				view := m.View()
				assertViewFits(t, m)
				if strings.Contains(ansi.Strip(view), "Checks") && !hasCursorRow(view, m.probes[selected].Name) {
					t.Errorf("%dx%d selected %d: the window lost its cursor:\n%s", width, height, selected, ansi.Strip(view))
				}
				if m.selected != before {
					t.Errorf("%dx%d: rendering moved selection from %d to %d", width, height, before, m.selected)
				}
			}
		}
	}
}

func manyHostMap(t *testing.T) model {
	t.Helper()
	m := blackHoleModel(t)
	m.networkMap, m.networkCIDR = true, "192.0.2.0/24"
	m.cur.name, m.cur.status = lanDiscoveryName, JobDone
	m.cur.start = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	m.cur.dur = 2 * time.Second
	m.now = func() time.Time { return time.Date(2026, 9, 13, 12, 3, 0, 0, time.UTC) }
	m.cur.lines = nil
	for i := 1; i <= 24; i++ {
		m.cur.lines = append(m.cur.lines, fmt.Sprintf("Host: 192.0.2.%d (device-%02d.lab)\tStatus: Up", i, i))
	}
	return m
}

func TestShortNetworkMapWindowsHostsAroundSelection(t *testing.T) {
	for _, height := range []int{10, 12, 16, 18, 19, 20, 21, 22, 24} {
		for _, selected := range []int{0, 12, 23} {
			m := manyHostMap(t)
			m.width, m.height, m.mapSelected = 80, height, selected
			view := ansi.Strip(m.View())
			assertViewFits(t, m)
			for _, want := range []string{mapTitle, "Cached", fmt.Sprintf("192.0.2.%d", selected+1)} {
				if !strings.Contains(view, want) {
					t.Errorf("80x%d selected %d lost %q:\n%s", height, selected, want, view)
				}
			}
			if slash, words := fmt.Sprintf("%d/24", selected+1), fmt.Sprintf("%d of 24", selected+1); !strings.Contains(view, slash) && !strings.Contains(view, words) {
				t.Errorf("80x%d selected %d lost its position:\n%s", height, selected, view)
			}
			if m.mapSelected != selected {
				t.Errorf("rendering moved map selection from %d to %d", selected, m.mapSelected)
			}
		}
	}
}

func TestNetworkMapKeepsCheckDetailsOutOfItsNavigation(t *testing.T) {
	m := manyHostMap(t)
	if slices.Contains(menuNames(m), "Check details") {
		t.Fatalf("the map Actions menu offers hidden check details: %v", menuNames(m))
	}
	u, _ := m.Update(keyMsg("D"))
	if next := asModel(t, u); next.detailsViewing || !next.networkMap {
		t.Errorf("D left the map or opened hidden check details: details=%v map=%v", next.detailsViewing, next.networkMap)
	}
}

func TestShortMapNavigationMatchesEveryPresetInMonochrome(t *testing.T) {
	for _, preset := range KeyPresets() {
		t.Run(preset, func(t *testing.T) {
			km, err := PresetKeymap(preset)
			if err != nil {
				t.Fatal(err)
			}
			m := manyHostMap(t)
			m.width, m.height, m.keys = 80, 12, km
			m.setTheme(themes[len(themes)-1])
			view := ansi.Strip(m.View())
			if label := km.pairLabel(ctxList, actUp, actDown); label == "" || !strings.Contains(view, label) ||
				(!strings.Contains(view, "select device") && !strings.Contains(view, "move")) {
				t.Fatalf("%s map does not show its bound movement keys:\n%s", preset, view)
			}
			u, _ := m.Update(keyPress("down"))
			next := asModel(t, u)
			if next.mapSelected != 1 || !strings.Contains(ansi.Strip(next.View()), "192.0.2.2") {
				t.Errorf("%s movement did not keep the selected device visible:\n%s", preset, ansi.Strip(next.View()))
			}
			assertViewFits(t, next)
		})
	}
}

func TestShortNetworkMapWindowsServicesAndReturnsToDevice(t *testing.T) {
	m := manyHostMap(t)
	m.width, m.mapSelected = 80, 23
	m.svc = serviceChoice{host: "192.0.2.24", name: "192.0.2.24 (device-24.lab)", done: true}
	for i := 1; i <= 15; i++ {
		m.svc.scan.Open = append(m.svc.scan.Open, diagnostic.LocalService{Port: 8000 + i, Name: fmt.Sprintf("service-%02d", i)})
	}
	for _, height := range []int{10, 12, 16, 20} {
		m.height = height
		for _, selected := range []int{0, 7, 14} {
			m.svc.sel = selected
			view := ansi.Strip(m.View())
			assertViewFits(t, m)
			for _, want := range []string{mapTitle, fmt.Sprintf("service-%02d", selected+1)} {
				if !strings.Contains(view, want) {
					t.Errorf("80x%d selected service %d lost %q:\n%s", height, selected, want, view)
				}
			}
			if slash, words := fmt.Sprintf("%d/15", selected+1), fmt.Sprintf("%d of 15", selected+1); !strings.Contains(view, slash) && !strings.Contains(view, words) {
				t.Errorf("80x%d selected service %d lost its position:\n%s", height, selected, view)
			}
		}
	}
	m.height = 20
	u, _ := m.Update(keyPress("esc"))
	back := asModel(t, u)
	if back.svc.host != "" || back.mapSelected != 23 {
		t.Fatalf("returning to devices changed selection: device=%q selected=%d", back.svc.host, back.mapSelected)
	}
	if view := ansi.Strip(back.View()); !strings.Contains(view, "192.0.2.24") || !strings.Contains(view, "24 of 24") {
		t.Errorf("the returned device is not visible:\n%s", view)
	}
}

func TestConstrainedJobPanePointsToExistingFullOutput(t *testing.T) {
	for _, height := range []int{10, 12, 16} {
		m := jobModel(t, 80, height)
		main := ansi.Strip(m.View())
		assertViewFits(t, m)
		if strings.Contains(main, jobPaneTitle) {
			t.Fatalf("80x%d no longer constrains the inline job pane:\n%s", height, main)
		}
		if !strings.Contains(main, "enter full output") {
			t.Fatalf("80x%d constrained pane has no visible escape hatch:\n%s", height, main)
		}
		u, _ := m.Update(keyPress("enter"))
		viewer := asModel(t, u)
		if !viewer.viewing || !strings.Contains(ansi.Strip(viewer.View()), viewerTitle) {
			t.Fatalf("80x%d enter did not open the existing output viewer:\n%s", height, ansi.Strip(viewer.View()))
		}
		assertViewFits(t, viewer)
	}
}

func TestWatchEvidenceUsesTheSameShortTerminalContract(t *testing.T) {
	m := watchHistoryModel(t, watchRuns)
	m.width, m.height = 80, 12
	main := ansi.Strip(m.View())
	assertViewFits(t, m)
	if !strings.Contains(main, "Cannot resolve") || !strings.Contains(main, "watch") {
		t.Fatalf("watch lost its diagnosis or essential context:\n%s", main)
	}
	viewer := openCheckDetails(t, m)
	u, _ := viewer.Update(keyPress("end"))
	if view := ansi.Strip(asModel(t, u).View()); !strings.Contains(view, "failed 7 of 20 runs") {
		t.Errorf("the retained watch history is unreachable:\n%s", view)
	}
}

func TestCheckDetailsNavigationMatchesEveryPresetInMonochrome(t *testing.T) {
	for _, preset := range KeyPresets() {
		t.Run(preset, func(t *testing.T) {
			km, err := PresetKeymap(preset)
			if err != nil {
				t.Fatal(err)
			}
			m := evidenceModel(t)
			m.width, m.height, m.keys = 80, 12, km
			m.setTheme(themes[len(themes)-1])
			viewer := openCheckDetails(t, m)
			view := ansi.Strip(viewer.View())
			for _, act := range []keyAction{actUp, actDown, actPageDown, actTop, actBottom, actBack} {
				label := km.label(ctxViewer, act)
				if label == "" || !strings.Contains(view, strings.Split(label, "/")[0]) {
					t.Errorf("footer does not show %s binding %q:\n%s", preset, label, view)
				}
			}
			if !strings.Contains(view, detailsTitle) || !strings.Contains(view, "lines 1-") {
				t.Errorf("monochrome lost textual orientation or window state:\n%s", view)
			}
			assertViewFits(t, viewer)
		})
	}
}

func TestCheckDetailsKeepsItsCheckThroughWatchResizeAndBack(t *testing.T) {
	m := watchHistoryModel(t, watchRuns)
	m.width, m.height, m.selMoved = 80, 12, false
	viewer := openCheckDetails(t, m)
	selected := viewer.selected
	name := viewer.probes[selected].Name

	viewer.detailsVP.GotoBottom()
	u, _ := viewer.Update(tea.WindowSizeMsg{Width: 70, Height: 10})
	resized := asModel(t, u)
	if resized.selected != selected || !strings.Contains(ansi.Strip(resized.detailsHeader()), "Check details: "+name) {
		t.Fatalf("resize changed the viewed check: selected=%d heading=%q", resized.selected, ansi.Strip(resized.detailsHeader()))
	}
	assertViewFits(t, resized)

	updated := watchRun(t, resized, map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeTargetTCP: diagnostic.StatusFail,
	})
	if !updated.detailsViewing || updated.selected != selected || !strings.Contains(ansi.Strip(updated.detailsHeader()), "Check details: "+name) {
		t.Fatalf("watch update switched the viewed check: viewing=%v selected=%d heading=%q", updated.detailsViewing, updated.selected, ansi.Strip(updated.detailsHeader()))
	}
	assertViewFits(t, updated)

	for _, key := range []string{"q", "esc"} {
		back := openCheckDetails(t, updated)
		u, _ := back.Update(keyPress(key))
		closed := asModel(t, u)
		if closed.detailsViewing || closed.selected != selected {
			t.Errorf("%s back left viewing=%v selected=%d, want false/%d", key, closed.detailsViewing, closed.selected, selected)
		}
	}
}
