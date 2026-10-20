// Themes are values, never package state: a model owns its palette and the
// styles derived from it, so two models, or two parallel tests, cannot repaint
// each other. Only presentation lives here. Every status keeps its glyph and
// its word, so no theme makes colour the sole carrier of meaning, and the
// default theme is the 16 ANSI colours netdoc has always used, which follow
// whatever the user's terminal is set to.

package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// Theme is one palette. Muted is the secondary-text colour, and a nil one
// means "no colour at all, use the terminal's own faint attribute", which is
// what the default theme does and what keeps it readable on a terminal whose
// background netdoc cannot know.
type Theme struct {
	Name  string
	About string

	Accent lipgloss.TerminalColor
	Border lipgloss.TerminalColor
	Pass   lipgloss.TerminalColor
	Fail   lipgloss.TerminalColor
	Warn   lipgloss.TerminalColor
	Skip   lipgloss.TerminalColor
	Muted  lipgloss.TerminalColor
}

// themes are the built-in palettes in picker order. The first is the default,
// and it is exactly the palette netdoc shipped before the picker existed.
// The rest use adaptive colours, since a terminal's background is a user
// setting rather than something to assume.
var themes = []Theme{
	{
		Name:   "terminal",
		About:  "your terminal's own 16 colours",
		Accent: lipgloss.Color("6"),
		Border: lipgloss.Color("8"),
		Pass:   lipgloss.Color("2"),
		Fail:   lipgloss.Color("1"),
		Warn:   lipgloss.Color("3"),
		Skip:   lipgloss.Color("3"),
	},
	{
		Name:   "harbor",
		About:  "cool teal and slate",
		Accent: lipgloss.AdaptiveColor{Light: "#0e6f78", Dark: "#5fd7d7"},
		Border: lipgloss.AdaptiveColor{Light: "#93a2ab", Dark: "#4c5c66"},
		Pass:   lipgloss.AdaptiveColor{Light: "#0f6b52", Dark: "#5fd7a4"},
		Fail:   lipgloss.AdaptiveColor{Light: "#a12a2a", Dark: "#ff8787"},
		Warn:   lipgloss.AdaptiveColor{Light: "#8a5f00", Dark: "#f0c674"},
		Skip:   lipgloss.AdaptiveColor{Light: "#5f6b73", Dark: "#a8b4bc"},
		Muted:  lipgloss.AdaptiveColor{Light: "#6b757c", Dark: "#8a949c"},
	},
	{
		Name:   "ember",
		About:  "warm amber and rust",
		Accent: lipgloss.AdaptiveColor{Light: "#9a4a10", Dark: "#ffaf5f"},
		Border: lipgloss.AdaptiveColor{Light: "#b09a8a", Dark: "#6b5548"},
		Pass:   lipgloss.AdaptiveColor{Light: "#4a6b12", Dark: "#b8d75f"},
		Fail:   lipgloss.AdaptiveColor{Light: "#a02020", Dark: "#ff7b72"},
		Warn:   lipgloss.AdaptiveColor{Light: "#8a5a00", Dark: "#ffd75f"},
		Skip:   lipgloss.AdaptiveColor{Light: "#75665c", Dark: "#c0aa9a"},
		Muted:  lipgloss.AdaptiveColor{Light: "#7a6a5f", Dark: "#a8968a"},
	},
	{
		Name:   "contrast",
		About:  "high contrast, with dim text at full strength",
		Accent: lipgloss.AdaptiveColor{Light: "#00308f", Dark: "#00ffff"},
		Border: lipgloss.AdaptiveColor{Light: "#000000", Dark: "#ffffff"},
		Pass:   lipgloss.AdaptiveColor{Light: "#005f00", Dark: "#00ff5f"},
		Fail:   lipgloss.AdaptiveColor{Light: "#870000", Dark: "#ff5f5f"},
		Warn:   lipgloss.AdaptiveColor{Light: "#5f3f00", Dark: "#ffd700"},
		Skip:   lipgloss.AdaptiveColor{Light: "#5f00af", Dark: "#d7afff"},
		Muted:  lipgloss.AdaptiveColor{Light: "#000000", Dark: "#ffffff"},
	},
	{
		Name:   "monochrome",
		About:  "no colours, with bold and faint emphasis",
		Accent: lipgloss.NoColor{},
		Border: lipgloss.NoColor{},
		Pass:   lipgloss.NoColor{},
		Fail:   lipgloss.NoColor{},
		Warn:   lipgloss.NoColor{},
		Skip:   lipgloss.NoColor{},
	},
}

var defaultTheme = themes[0]

// themeIndex is the one place a stored name is matched. An unknown, obsolete,
// or malformed one lands on the default, since a preference file is
// convenience state and never a reason to refuse to draw.
func themeIndex(name string) int {
	for i, t := range themes {
		if t.Name == name {
			return i
		}
	}
	return 0
}

func resolveTheme(name string) Theme { return themes[themeIndex(name)] }

// styles is one theme rendered into the styles the views draw with, built once
// per theme change rather than per frame.
type styles struct {
	pass, fail, skip, warn, faint lipgloss.Style
	title, sel, key               lipgloss.Style
	panel, focusPanel, panelTitle lipgloss.Style
	spinner                       lipgloss.Style
	status                        map[fmt.Stringer]lipgloss.Style
}

func newStyles(t Theme) styles {
	faint := lipgloss.NewStyle().Faint(true)
	if t.Muted != nil {
		faint = lipgloss.NewStyle().Foreground(t.Muted)
	}
	s := styles{
		pass:       lipgloss.NewStyle().Foreground(t.Pass),
		fail:       lipgloss.NewStyle().Foreground(t.Fail),
		skip:       lipgloss.NewStyle().Foreground(t.Skip),
		warn:       lipgloss.NewStyle().Foreground(t.Warn).Bold(true),
		faint:      faint,
		title:      lipgloss.NewStyle().Bold(true),
		sel:        lipgloss.NewStyle().Bold(true).Foreground(t.Accent),
		key:        lipgloss.NewStyle().Foreground(t.Accent),
		panel:      lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(t.Border).Padding(0, 1),
		panelTitle: lipgloss.NewStyle().Bold(true).Foreground(t.Accent),
		spinner:    lipgloss.NewStyle().Foreground(t.Accent),
	}
	s.focusPanel = s.panel.BorderForeground(t.Accent) // input focus lives here
	s.status = map[fmt.Stringer]lipgloss.Style{
		diagnostic.StatusPass: s.pass, diagnostic.StatusWarn: s.warn,
		diagnostic.StatusFail: s.fail, diagnostic.StatusSkip: s.skip, diagnostic.StatusNA: s.faint,
		JobDone: s.pass, JobFailed: s.fail, JobTimedOut: s.fail, JobCanceled: s.skip,
	}
	return s
}

// defaultStyles is the palette a model gets before any preference is read, and
// the one the package's own tests compare against.
var defaultStyles = newStyles(defaultTheme)

// The theme preference persists as one line beside the target history, under
// the same config-directory policy. Everything here is best-effort: a missing
// file, an unreadable one, or a failed write leaves the default in place and
// never interrupts a diagnosis.
func loadTheme(path string) Theme {
	if path == "" {
		return defaultTheme
	}
	// #nosec G304 -- production passes the current-user preference path; this unprivileged read may follow a caller-selected symlink, and the one line it consumes is sanitized and then matched against the built-in names.
	b, err := os.ReadFile(path)
	if err != nil {
		return defaultTheme
	}
	return resolveTheme(strings.TrimSpace(textsafe.Clean(string(b))))
}

func saveTheme(path, name string) {
	if path == "" {
		return
	}
	writeConfigFile(path, name+"\n")
}
