package ui

import (
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// The default theme is the palette netdoc drew with before the picker existed:
// the 16 ANSI colors, so it follows whatever the user's terminal is set to.
// Pinned through the style getters rather than through rendered output, which
// carries no color when the test binary's stdout is not a terminal.
func TestDefaultThemeIsTheHistoricalPalette(t *testing.T) {
	s := defaultStyles
	fg := []struct {
		name  string
		style lipgloss.Style
		want  string
		bold  bool
	}{
		{"pass", s.pass, "2", false},
		{"fail", s.fail, "1", false},
		{"skip", s.skip, "3", false},
		{"warn", s.warn, "3", true},
		{"sel", s.sel, "6", true},
		{"key", s.key, "6", false},
		{"panelTitle", s.panelTitle, "6", true},
		{"spinner", s.spinner, "6", false},
	}
	for _, tt := range fg {
		if got := tt.style.GetForeground(); got != lipgloss.Color(tt.want) {
			t.Errorf("%s foreground = %#v, want ANSI %s", tt.name, got, tt.want)
		}
		if tt.style.GetBold() != tt.bold {
			t.Errorf("%s bold = %v, want %v", tt.name, tt.style.GetBold(), tt.bold)
		}
	}
	// faint carries the terminal's own dim attribute and no color of its own,
	// which is what keeps it readable whatever the background is.
	if !s.faint.GetFaint() || s.faint.GetForeground() != (lipgloss.NoColor{}) {
		t.Errorf("faint = faint:%v fg:%#v, want faint with no color", s.faint.GetFaint(), s.faint.GetForeground())
	}
	if !s.title.GetBold() || s.title.GetForeground() != (lipgloss.NoColor{}) {
		t.Errorf("title = bold:%v fg:%#v, want bold with no color", s.title.GetBold(), s.title.GetForeground())
	}
	if got := s.panel.GetBorderTopForeground(); got != lipgloss.Color("8") {
		t.Errorf("panel border = %#v, want ANSI 8", got)
	}
	if got := s.focusPanel.GetBorderTopForeground(); got != lipgloss.Color("6") {
		t.Errorf("focus panel border = %#v, want ANSI 6", got)
	}
	if l, r := s.panel.GetPaddingLeft(), s.panel.GetPaddingRight(); l != 1 || r != 1 {
		t.Errorf("panel padding = %d/%d, want 1/1", l, r)
	}
	// Every status still maps to the style it always did, and none of them is
	// left unstyled by an incomplete table.
	want := map[string]lipgloss.Style{
		diagnostic.StatusPass.String(): s.pass, diagnostic.StatusWarn.String(): s.warn,
		diagnostic.StatusFail.String(): s.fail, diagnostic.StatusSkip.String(): s.skip,
		diagnostic.StatusNA.String(): s.faint,
		JobDone.String():             s.pass, JobFailed.String(): s.fail,
		JobTimedOut.String(): s.fail, JobCanceled.String(): s.skip,
	}
	if len(s.status) != len(want) {
		t.Errorf("status styles cover %d states, want %d", len(s.status), len(want))
	}
	for key, style := range s.status {
		if w, ok := want[key.String()]; !ok || !reflect.DeepEqual(style, w) {
			t.Errorf("status style for %s is not the historical one", key)
		}
	}
}

func TestBuiltInThemesAreUniqueAndStable(t *testing.T) {
	want := []string{"terminal", "harbor", "ember", "contrast", "monochrome"}
	var got []string
	for _, th := range themes {
		got = append(got, th.Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("built-in themes = %v, want %v", got, want)
	}
	if defaultTheme.Name != want[0] {
		t.Errorf("default theme = %q, want %q", defaultTheme.Name, want[0])
	}
	seen := map[string]bool{}
	for i, th := range themes {
		if th.Name == "" || th.About == "" {
			t.Errorf("theme %d has an empty name or description", i)
		}
		if seen[th.Name] {
			t.Errorf("theme name %q appears twice", th.Name)
		}
		seen[th.Name] = true
		if resolveTheme(th.Name).Name != th.Name || themeIndex(th.Name) != i {
			t.Errorf("theme %q does not resolve back to itself at index %d", th.Name, i)
		}
		// A palette with a hole would render part of the UI unstyled.
		for name, c := range map[string]lipgloss.TerminalColor{
			"accent": th.Accent, "border": th.Border, "pass": th.Pass,
			"fail": th.Fail, "warn": th.Warn, "skip": th.Skip,
		} {
			if c == nil {
				t.Errorf("theme %q has no %s color", th.Name, name)
			}
		}
	}
}

func TestMonochromeUsesNoColorsAndKeepsEmphasis(t *testing.T) {
	mono := resolveTheme("monochrome")
	for name, color := range map[string]lipgloss.TerminalColor{
		"accent": mono.Accent, "border": mono.Border, "pass": mono.Pass,
		"fail": mono.Fail, "warn": mono.Warn, "skip": mono.Skip,
	} {
		if color != (lipgloss.NoColor{}) {
			t.Errorf("monochrome %s = %#v, want no color", name, color)
		}
	}
	if mono.Muted != nil {
		t.Errorf("monochrome muted = %#v, want terminal faint", mono.Muted)
	}

	s := newStyles(mono)
	for name, style := range map[string]lipgloss.Style{
		"pass": s.pass, "fail": s.fail, "skip": s.skip, "warn": s.warn,
		"selection": s.sel, "key": s.key, "panel title": s.panelTitle, "spinner": s.spinner,
	} {
		if color := style.GetForeground(); color != (lipgloss.NoColor{}) {
			t.Errorf("monochrome %s foreground = %#v, want no color", name, color)
		}
	}
	for name, style := range map[string]lipgloss.Style{"panel": s.panel, "focus panel": s.focusPanel} {
		if color := style.GetBorderTopForeground(); color != (lipgloss.NoColor{}) {
			t.Errorf("monochrome %s border = %#v, want no color", name, color)
		}
	}
	if !s.title.GetBold() || !s.sel.GetBold() || !s.panelTitle.GetBold() || !s.warn.GetBold() || !s.faint.GetFaint() {
		t.Error("monochrome lost bold or faint emphasis")
	}
}

func TestContrastThemeRemainsHighContrast(t *testing.T) {
	want := Theme{
		Name:   "contrast",
		About:  "high contrast, with dim text at full strength",
		Accent: lipgloss.AdaptiveColor{Light: "#00308f", Dark: "#00ffff"},
		Border: lipgloss.AdaptiveColor{Light: "#000000", Dark: "#ffffff"},
		Pass:   lipgloss.AdaptiveColor{Light: "#005f00", Dark: "#00ff5f"},
		Fail:   lipgloss.AdaptiveColor{Light: "#870000", Dark: "#ff5f5f"},
		Warn:   lipgloss.AdaptiveColor{Light: "#5f3f00", Dark: "#ffd700"},
		Skip:   lipgloss.AdaptiveColor{Light: "#5f00af", Dark: "#d7afff"},
		Muted:  lipgloss.AdaptiveColor{Light: "#000000", Dark: "#ffffff"},
	}
	if got := resolveTheme("contrast"); !reflect.DeepEqual(got, want) {
		t.Errorf("contrast theme changed:\n got %#v\nwant %#v", got, want)
	}
}

func TestMonochromeKeepsStatusAndJobMeaning(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.setTheme(resolveTheme("monochrome"))
	for status := diagnostic.StatusPass; status <= diagnostic.StatusNA; status++ {
		want := probeGlyph(status) + " " + status.String()
		if got := ansi.Strip(m.st.status[status].Render(want)); got != want {
			t.Errorf("status %s rendered as %q, want %q", status, got, want)
		}
	}

	seen := map[string]JobStatus{}
	for status := JobQueued; status <= JobTimedOut; status++ {
		run := jobState{name: "job", status: status}
		if status == JobRunning {
			run.active = &job{}
		}
		glyph := ansi.Strip(m.jobGlyph(&run))
		if glyph == "" {
			t.Errorf("job status %s has no glyph", status)
		} else if other, duplicate := seen[glyph]; duplicate {
			t.Errorf("job statuses %s and %s share glyph %q", status, other, glyph)
		}
		seen[glyph] = status
		m.cur = run
		if got := ansi.Strip(m.jobStatusLine()); !strings.Contains(got, status.String()) {
			t.Errorf("job status line %q does not name %s", got, status)
		}
	}
}

// Lip Gloss is the rendering layer that turns the model's styles into ANSI.
// Its pinned termenv output reads NO_COLOR when the renderer is created, before
// Bubble Tea writes that rendered view to the terminal.
func TestLipGlossRendererHonorsNOColor(t *testing.T) {
	for _, tt := range []struct {
		name, value string
		wantANSI    bool
	}{
		{"non-empty suppresses color", "1", false},
		{"empty keeps color", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", tt.value)
			t.Setenv("CLICOLOR", "")
			t.Setenv("CLICOLOR_FORCE", "1")
			renderer := lipgloss.NewRenderer(io.Discard)
			got := lipgloss.NewStyle().Renderer(renderer).Foreground(lipgloss.Color("1")).Render("status")
			if hasANSI := strings.Contains(got, "\x1b["); hasANSI != tt.wantANSI {
				t.Errorf("rendered %q, ANSI present = %v, want %v", got, hasANSI, tt.wantANSI)
			}
			if plain := ansi.Strip(got); plain != "status" {
				t.Errorf("visible text = %q, want status", plain)
			}
		})
	}
}

func TestThemePreferenceFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, tt := range []struct {
		name string
		path string
	}{
		{"persistence off", ""},
		{"missing file", filepath.Join(dir, "absent")},
		{"unknown name", write("unknown", "solarized\n")},
		{"obsolete name", write("obsolete", "terminal-v1\n")},
		{"empty file", write("empty", "")},
		{"control bytes around an unknown name", write("garbled", "\x1b[31msolarized\x00\n")},
		{"a whole file of noise", write("noise", strings.Repeat("x", 4096))},
	} {
		if got := loadTheme(tt.path); got.Name != defaultTheme.Name {
			t.Errorf("%s: loadTheme = %q, want %q", tt.name, got.Name, defaultTheme.Name)
		}
	}
	// A directory in place of the file is the unreadable case: still the
	// default, and still no error out of a convenience read.
	if got := loadTheme(dir); got.Name != defaultTheme.Name {
		t.Errorf("unreadable path: loadTheme = %q, want %q", got.Name, defaultTheme.Name)
	}
	// A tampered file cannot smuggle an escape sequence into the UI: the name
	// is sanitized first, and what is left is matched against the built-ins.
	if got := loadTheme(write("escapes", "\x1b[31mharbor\x00\n")); got.Name != "harbor" {
		t.Errorf("sanitized name = %q, want harbor", got.Name)
	}
}

func TestSavedThemePreferenceIsRestored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netdoc", "theme")
	saveTheme(path, "harbor")
	if got := loadTheme(path); got.Name != "harbor" {
		t.Fatalf("loadTheme = %q, want harbor", got.Name)
	}
	// Surrounding whitespace is a hand-edited file, not a different theme.
	if err := os.WriteFile(path, []byte("  ember  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadTheme(path); got.Name != "ember" {
		t.Fatalf("loadTheme = %q, want ember", got.Name)
	}
	// A new session starts on the saved theme.
	m := NewWithSelection(nil, nil, false, false, "", "test", "", false, diagnostic.ProbeSelection{}, WithThemeFile(path)).(model)
	if m.theme.Name != "ember" || !reflect.DeepEqual(m.st, newStyles(resolveTheme("ember"))) {
		t.Fatalf("new model theme = %q, want ember with matching styles", m.theme.Name)
	}
	if m.spinner.Style.GetForeground() != m.st.spinner.GetForeground() {
		t.Error("the spinner kept a color the theme did not choose")
	}
	// No preference file at all is the default, and writing one is refused
	// rather than guessed at a path.
	plain := newModel(nil, false)
	if plain.theme.Name != defaultTheme.Name {
		t.Errorf("model without a preference file = %q, want %q", plain.theme.Name, defaultTheme.Name)
	}
	// Two live models, two palettes: the styles are values on each model rather
	// than package state, so neither one repaints the other or the package's own
	// default.
	if !reflect.DeepEqual(plain.st, defaultStyles) || !reflect.DeepEqual(m.st, newStyles(resolveTheme("ember"))) {
		t.Error("one model's theme leaked into another's styles")
	}
	saveTheme("", "harbor") // must not panic or write anywhere
}

// The picker previews as the cursor moves, enter keeps and persists, esc puts
// back whatever was active when it opened.
func TestThemePickerPreviewAcceptAndCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netdoc", "theme")
	open := func() model {
		m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "test", "", false,
			diagnostic.ProbeSelection{}, WithThemeFile(path)).(model)
		m.width, m.height = 100, 40
		return m
	}

	m := open()
	before := m.theme
	m = pressed(t, m, keyPress("T"))
	if !m.theming || m.themeSel != 0 || m.themeWas.Name != before.Name {
		t.Fatalf("T left theming=%v sel=%d was=%q", m.theming, m.themeSel, m.themeWas.Name)
	}
	if view := ansi.Strip(m.View()); !strings.Contains(view, "Theme") || !strings.Contains(view, "monochrome") {
		t.Error("the picker is not on screen")
	}

	// Moving previews at once, in both directions and with either key set.
	press := func(key string) {
		t.Helper()
		u, _ := m.handleThemeKey(keyPress(key))
		m = asModel(t, u)
	}
	press("down")
	if m.themeSel != 1 || m.theme.Name != themes[1].Name {
		t.Fatalf("down = sel %d theme %q, want 1 %q", m.themeSel, m.theme.Name, themes[1].Name)
	}
	press("j")
	if m.themeSel != 2 || m.theme.Name != themes[2].Name {
		t.Fatalf("j = sel %d theme %q, want 2 %q", m.themeSel, m.theme.Name, themes[2].Name)
	}
	press("k")
	press("up")
	if m.themeSel != 0 || m.theme.Name != defaultTheme.Name {
		t.Fatalf("back to the top = sel %d theme %q", m.themeSel, m.theme.Name)
	}
	press("up") // clamps rather than wrapping
	if m.themeSel != 0 {
		t.Errorf("up past the first theme = sel %d", m.themeSel)
	}
	for range len(themes) + 2 {
		press("down")
	}
	if m.themeSel != len(themes)-1 {
		t.Errorf("down past the last theme = sel %d, want %d", m.themeSel, len(themes)-1)
	}

	// esc restores the theme the picker opened on, and writes nothing.
	press("esc")
	if m.theming || m.theme.Name != before.Name {
		t.Fatalf("esc left theming=%v theme=%q, want the pre-picker %q", m.theming, m.theme.Name, before.Name)
	}
	if !reflect.DeepEqual(m.st, newStyles(before)) {
		t.Error("esc restored the theme name but not its styles")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("esc wrote a preference file: %v", err)
	}

	// enter keeps the previewed theme and persists it.
	m = pressed(t, m, keyPress("T"))
	for range len(themes) {
		press("down")
	}
	press("enter")
	if m.theming || m.theme.Name != themes[len(themes)-1].Name {
		t.Fatalf("enter left theming=%v theme=%q, want %q", m.theming, m.theme.Name, themes[len(themes)-1].Name)
	}
	saved, err := os.ReadFile(path) // #nosec G304 -- path is this test's own temp dir
	if err != nil || strings.TrimSpace(string(saved)) != themes[len(themes)-1].Name {
		t.Fatalf("saved preference = %q (%v), want %q", saved, err, themes[len(themes)-1].Name)
	}
	if !strings.Contains(m.notice, themes[len(themes)-1].Name) {
		t.Errorf("notice = %q, want it to name the theme", m.notice)
	}
	// A picker opened again starts on the theme now in force.
	m = pressed(t, m, keyPress("T"))
	if m.themeSel != len(themes)-1 {
		t.Errorf("reopened picker = sel %d, want %d", m.themeSel, len(themes)-1)
	}
}

// The picker repaints and nothing else: no probe, result, diagnosis, cursor,
// or run state moves because the user looked at a theme.
func TestThemeSelectionLeavesDiagnosticStateAlone(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.width, m.height = 100, 40
	doneResults(&m, diagnostic.ProbeDNS)
	diagnostic.Finalize(m.results)
	wantResults := maps.Clone(m.results)
	wantDiagnosis := m.diagnosis()
	wantOrder := m.probeOrder()
	wantRows := m.checkRows()
	wantSelected, wantReport := m.selected, m.report()

	m = pressed(t, m, keyPress("T"))
	for range len(themes) {
		u, _ := m.handleThemeKey(keyPress("down"))
		m = asModel(t, u)
	}
	u, _ := m.handleThemeKey(keyPress("enter"))
	m = asModel(t, u)

	if !reflect.DeepEqual(m.results, wantResults) {
		t.Error("theme selection changed the probe results")
	}
	if !reflect.DeepEqual(m.diagnosis(), wantDiagnosis) {
		t.Error("theme selection changed the diagnosis")
	}
	if !slices.Equal(m.probeOrder(), wantOrder) || !slices.Equal(m.checkRows(), wantRows) {
		t.Error("theme selection changed the row order")
	}
	if m.selected != wantSelected {
		t.Errorf("theme selection moved the cursor to %d, want %d", m.selected, wantSelected)
	}
	if got := m.report(); got != wantReport {
		t.Error("theme selection changed the exported report")
	}
}

// A theme changes color and nothing else. Stripping the styling off the same UI
// state must leave every theme saying exactly the same words, in the same
// glyphs, rows, and layout, which is also what a NO_COLOR or monochrome
// terminal sees.
func TestThemesRenderIdenticalVisibleContent(t *testing.T) {
	build := func(theme Theme) model {
		m := newModel(mustTarget(t, "example.com:443"), false)
		m.width, m.height = 100, 40
		m.setTheme(theme)
		return m
	}
	states := map[string]func(model) string{
		"running":  func(m model) string { return m.View() },
		"finished": func(m model) string { doneResults(&m, diagnostic.ProbeDNS); return m.View() },
		"expanded": func(m model) string {
			doneResults(&m, "")
			m.expanded = true
			return m.View()
		},
		"cheatsheet": func(m model) string { m.helping = true; return m.View() },
		"picker":     func(m model) string { m.theming, m.themeSel = true, 2; return m.View() },
		"job viewer": func(m model) string {
			m.cur.name, m.cur.display, m.cur.status = "ping the host", "ping example.com", JobDone
			m.appendJobLine("64 bytes from 192.0.2.1: icmp_seq=1 ttl=57 time=9.9 ms")
			m.viewing, m.follow = true, true
			m.refreshViewport()
			return m.View()
		},
		"help bar": func(m model) string { doneResults(&m, ""); return m.helpView(false) },
		"detail rows": func(m model) string {
			doneResults(&m, diagnostic.ProbeDNS)
			return strings.Join(m.detailRows(false, max(m.width, 1)), "\n")
		},
		"theme picker": func(m model) string { m.themeSel = 3; return m.themeView() },
		"actions menu": func(m model) string { m.actionsOpen = true; return m.View() },
		"watch change": func(m model) string {
			m.watch = true
			doneResults(&m, diagnostic.ProbeDNS)
			for _, probe := range m.probes {
				m.runHistory[probe.ID] = []diagnostic.Status{diagnostic.StatusPass, m.results[probe.ID].Status}
			}
			return m.View()
		},
		"confirmation": func(m model) string {
			u, _ := m.Update(keyMsg("n"))
			return asModel(t, u).View()
		},
		"restart input": func(m model) string {
			u, _ := m.runAction(actRestart)
			return asModel(t, u).View()
		},
		"incident": func(m model) string {
			start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
			m.watch = true
			recordWatchPass(&m, start, false, "wlan0")
			recordWatchPass(&m, start.Add(5*time.Second), true, "wg0")
			recordWatchPass(&m, start.Add(10*time.Second), false, "wlan0")
			m.openIncidentViewer()
			return m.View()
		},
	}
	// The comparison is only worth making because the themes really do paint
	// differently; a test binary whose stdout is not a terminal renders without
	// color, so the styles are checked directly rather than through the output.
	for _, theme := range themes[1:] {
		if reflect.DeepEqual(newStyles(theme), defaultStyles) {
			t.Fatalf("theme %q is indistinguishable from the default", theme.Name)
		}
	}
	for name, render := range states {
		t.Run(name, func(t *testing.T) {
			want := ansi.Strip(render(build(defaultTheme)))
			if strings.TrimSpace(want) == "" {
				t.Fatalf("%s rendered nothing to compare", name)
			}
			for _, theme := range themes[1:] {
				if got := ansi.Strip(render(build(theme))); got != want {
					t.Errorf("theme %q changed the visible content:\n got %q\nwant %q", theme.Name, got, want)
				}
			}
		})
	}
}

// A tool hotkey must not take a key something else already owns: the built-in
// actions and the drill-down tool hotkeys share one keyboard, and the actions
// are dispatched first, so a collision would silently swallow a tool. A key
// that only begins a chord swallows it just as completely, because handleKey
// holds the keyboard for the rest of the chord instead of reaching the tools.
func TestListBindingsDoNotCollideWithToolHotkeys(t *testing.T) {
	tgt := mustTarget(t, "example.com:443")
	for _, preset := range presets {
		km := newKeymap(preset.preset)
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, tool := range toolsFor(tgt, goos, toolBind{}) {
				if act, ok := km.lookup(ctxList, []string{tool.Key}); ok {
					t.Errorf("%s/%s: tool %q is shadowed by action %d", preset.name, goos, tool.Key, act)
				}
				if km.isPrefix(ctxList, []string{tool.Key}) {
					t.Errorf("%s/%s: tool %q is swallowed by a chord that starts with it", preset.name, goos, tool.Key)
				}
			}
		}
	}
	// Every tool hotkey has to survive the real dispatch, not just the tables.
	// An unavailable binary spawns nothing, so the pane naming the tool is the
	// proof the key reached it.
	for _, preset := range presets {
		km := newKeymap(preset.preset)
		for _, tool := range newModel(tgt, false).tools {
			m := newModel(tgt, false)
			m.keys = km
			for i := range m.tools {
				m.tools[i].Available = false
			}
			m = pressed(t, m, keyPress(tool.Key))
			if m.confirmTool != nil {
				continue // gated tools stop at the confirmation, which is reaching them
			}
			if m.cur.name != tool.Name {
				t.Errorf("%s: %q opened %q, want %q", preset.name, tool.Key, m.cur.name, tool.Name)
			}
		}
	}
	// The theme picker in particular, since "t" is traceroute's.
	km, _ := PresetKeymap("")
	if act, _ := km.lookup(ctxList, []string{"T"}); act != actTheme {
		t.Errorf("T dispatches to %d, want the theme picker", act)
	}
	if act, ok := km.lookup(ctxList, []string{"t"}); ok {
		t.Errorf("t was taken from traceroute by action %d", act)
	}
}
