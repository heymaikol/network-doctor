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

type focusedPanelCase struct {
	name  string
	build func(*testing.T) model
}

func focusedPanelCases() []focusedPanelCase {
	base := func(t *testing.T) model {
		m := blackHoleModel(t)
		m.height = 80
		return m
	}
	return []focusedPanelCase{
		{"network map", func(t *testing.T) model { return mapModel(t) }},
		{"service chooser", func(t *testing.T) model {
			m := mapModel(t)
			m.svc = serviceChoice{
				host: "192.168.12.50", name: "printer.lan", done: true,
				scan: diagnostic.ServiceScan{Open: []diagnostic.LocalService{{Port: 443, Name: "HTTPS", Scheme: "https"}}},
			}
			return m
		}},
		{"confirmation", func(t *testing.T) model {
			m := base(t)
			m.confirmTool = &m.tools[0]
			return m
		}},
		{"theme picker", func(t *testing.T) model { m := base(t); m.theming = true; return m }},
		{"restart prompt", func(t *testing.T) model { m := base(t); m.entering = true; return m }},
		{"SSH form", func(t *testing.T) model {
			m := base(t)
			m.sshPrompt, m.ssh = true, newSSHForm(m.st, m.target)
			return m
		}},
		{"Actions menu", func(t *testing.T) model { m := base(t); m.actionsOpen = true; return m }},
	}
}

func renderFocusedPanel(m model) string {
	switch {
	case m.networkMap && m.svc.host != "":
		return m.serviceChooserView()
	case m.networkMap:
		return m.networkMapView()
	case m.confirmTool != nil:
		return m.confirmView()
	case m.theming:
		return m.themeView()
	case m.entering:
		return m.promptView(true)
	case m.sshPrompt:
		return m.sshFormView()
	case m.actionsOpen:
		return m.actionsView(80)
	default:
		return ""
	}
}

func assertFitsWidth(t *testing.T, view string, width int) {
	t.Helper()
	for _, line := range strings.Split(view, "\n") {
		if got := lipgloss.Width(line); got > width {
			t.Errorf("line is %d columns wide, want at most %d: %q", got, width, ansi.Strip(line))
		}
	}
}

func assertClosedBorder(t *testing.T, view string) {
	t.Helper()
	plain := ansi.Strip(view)
	if strings.Count(plain, "╭") != 1 || strings.Count(plain, "╮") != 1 ||
		strings.Count(plain, "╰") != 1 || strings.Count(plain, "╯") != 1 {
		t.Errorf("panel border is incomplete:\n%s", plain)
	}
}

func TestFocusedPanelsFitTerminalWidth(t *testing.T) {
	for _, tc := range focusedPanelCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, width := range []int{40, 30, 26, 25, 24, 20, 16, 10} {
				t.Run(fmt.Sprintf("%d_columns", width), func(t *testing.T) {
					m := tc.build(t)
					m.width = width
					view := renderFocusedPanel(m)
					assertFitsWidth(t, view, width)
					assertClosedBorder(t, view)
				})
			}
		})
	}
}

func TestFocusedPanelsKeepOrdinaryWidths(t *testing.T) {
	want := map[string]map[int]int{
		"network map": {80: 80, 100: 100}, "service chooser": {80: 80, 100: 100},
		"confirmation": {80: 78, 100: 78}, "theme picker": {80: 80, 100: 100},
		"restart prompt": {80: 80, 100: 90}, "SSH form": {80: 78, 100: 78},
		"Actions menu": {80: 58, 100: 58},
	}
	for _, tc := range focusedPanelCases() {
		for _, width := range []int{80, 100} {
			m := tc.build(t)
			m.width = width
			view := renderFocusedPanel(m)
			if got := lipgloss.Width(strings.Split(view, "\n")[0]); got != want[tc.name][width] {
				t.Errorf("%s at %d columns is %d columns wide, want %d", tc.name, width, got, want[tc.name][width])
			}
			assertFitsWidth(t, view, width)
			assertClosedBorder(t, view)
		}
	}
}

func TestFocusedPanelsSurviveResizeToTinyAndBack(t *testing.T) {
	for _, tc := range focusedPanelCases() {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.build(t)
			resize := func(width int) {
				t.Helper()
				u, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: 80})
				m = asModel(t, u)
				assertFitsWidth(t, m.View(), width)
				assertClosedBorder(t, renderFocusedPanel(m))
			}
			resize(100)
			before := m.View()
			resize(10)
			resize(100)
			if after := m.View(); after != before {
				t.Errorf("100-column view changed after a tiny resize:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

func TestOtherFocusedViewsFitTerminalWidth(t *testing.T) {
	views := []focusedPanelCase{
		{"incident viewer", func(t *testing.T) model {
			at := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
			m := newModel(mustTarget(t, "example.com:443"), false)
			m.watch, m.width, m.height = true, 100, 80
			recordWatchPass(&m, at, false, "wlan0")
			recordWatchPass(&m, at.Add(time.Second), true, "wg0")
			m.openIncidentViewer()
			return m
		}},
		{"help overlay", func(t *testing.T) model {
			m := newModel(nil, false)
			m.width, m.height = 100, 80
			u, _ := m.Update(keyMsg("?"))
			return asModel(t, u)
		}},
		{"output viewer", func(t *testing.T) model {
			m := newModel(nil, false)
			m.width, m.height = 100, 80
			m.cur = jobState{name: "route table", display: "ip route show", status: JobDone, lines: []string{"default via 192.168.1.1"}}
			u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
			return asModel(t, u)
		}},
	}
	for _, tc := range views {
		t.Run(tc.name, func(t *testing.T) {
			for _, width := range []int{40, 30, 26, 25, 24, 20, 16, 10} {
				m := tc.build(t)
				u, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: 80})
				assertFitsWidth(t, asModel(t, u).View(), width)
			}
		})
	}
}
