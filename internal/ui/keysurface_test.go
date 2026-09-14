// The keyboard surface as a contract. Network Doctor binds more keys than a
// reader can hold in their head, and that is deliberate: the Actions menu and
// the cheatsheet exist so nobody has to. What has to stay true is the division
// of labour between the three. The help bar teaches only the region on screen,
// the menu is the authoritative list of what can be done now, and the sheet is
// the complete vocabulary. These tests fail when an accelerator creeps back
// onto the bar, when the sheet and the menu file the same action differently,
// or when the documented surface stops matching the bound one.

package ui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// barChips is the help bar as (key, description) pairs, which is how the rule
// is stated: a chip earns its place by what it says about the current region,
// not by which key happens to be free.
func barChips(t *testing.T, m model, deferred bool) map[string]string {
	t.Helper()
	chips := map[string]string{}
	// The bar wraps onto more rows rather than dropping a chip, so the rows
	// are read as one list.
	bar := strings.ReplaceAll(ansi.Strip(m.helpView(deferred)), "\n", "  ·  ")
	for _, chip := range strings.Split(bar, "·") {
		chip = strings.TrimSpace(chip)
		if chip == "" {
			continue
		}
		key, desc, ok := strings.Cut(chip, " ")
		if !ok {
			t.Fatalf("help chip %q is not a key and a description", chip)
		}
		chips[strings.TrimSpace(desc)] = key
	}
	return chips
}

// barScreens are the screens the help bar has a branch for, each built from a
// deterministic fixture so the expected vocabulary is exact.
func barScreens(t *testing.T) []struct {
	name     string
	deferred bool
	build    func(t *testing.T) model
	want     []string
} {
	t.Helper()
	return []struct {
		name     string
		deferred bool
		build    func(t *testing.T) model
		want     []string
	}{
		{"checks", false, func(t *testing.T) model { return evidenceModel(t) },
			[]string{"select", "actions", "help", "quit"}},
		{"network map", false, func(t *testing.T) model { return mapModel(t) },
			[]string{"select device", "open device", "checks", "actions: rescan", "help", "quit"}},
		{"opened device", false, func(t *testing.T) model { return openedDevice(t, mapModel(t)) },
			[]string{"select service", "diagnose it", "devices", "checks", "actions: rescan", "help", "quit"}},
		{"toolbox", true, func(t *testing.T) model { return newModel(mustTarget(t, "example.com:443"), true) },
			[]string{"run the checks", "runs that tool", "actions", "help", "quit"}},
	}
}

// TestHelpBarCarriesOnlyItsRegionAndTheDiscoveryKeys is the help-bar rule. A
// chip is there to say how to move in the region on screen, what the primary
// key does to the selected thing, or how to leave; the rest of the bar is the
// fixed tail that names where everything else lives. Every accelerator the bar
// does not carry stays bound and stays reachable, which the menu test below
// proves, so this is about what the bar teaches, never about what works.
func TestHelpBarCarriesOnlyItsRegionAndTheDiscoveryKeys(t *testing.T) {
	for _, preset := range KeyPresets() {
		km, err := PresetKeymap(preset)
		if err != nil {
			t.Fatal(err)
		}
		for _, screen := range barScreens(t) {
			m := screen.build(t)
			m.width, m.height, m.keys = 120, 40, km
			got := barChips(t, m, screen.deferred)
			var descs []string
			for desc := range got {
				descs = append(descs, desc)
			}
			slices.Sort(descs)
			want := slices.Clone(screen.want)
			slices.Sort(want)
			if !slices.Equal(descs, want) {
				t.Errorf("%s/%s help bar says %v, want %v", preset, screen.name, descs, want)
			}
			// The discovery tail is what makes an unadvertised binding
			// findable, so it is never the part that yields.
			for _, must := range []string{"actions", "help", "quit"} {
				if _, ok := got[must]; !ok && !(must == "actions" && got["actions: rescan"] != "") {
					t.Errorf("%s/%s help bar dropped the %q chip", preset, screen.name, must)
				}
			}
		}
	}
}

// TestHelpBarKeysMatchTheActivePreset: the bar reads its keys from the keymap,
// so a preset that rebinds a key must move the chip with it rather than
// printing the default's.
func TestHelpBarKeysMatchTheActivePreset(t *testing.T) {
	km, err := PresetKeymap("vim")
	if err != nil {
		t.Fatal(err)
	}
	m := mapModel(t)
	m.width, m.height, m.keys = 120, 40, km
	chips := barChips(t, m, false)
	want := map[string]string{
		"select device": m.keys.pairLabel(ctxList, actUp, actDown),
		"open device":   m.keys.label(ctxList, actOpen),
		"checks":        m.keys.label(ctxList, actNetworkMap),
		"help":          m.keys.label(ctxList, actHelp),
		"quit":          m.keys.label(ctxList, actQuit),
	}
	for desc, key := range want {
		got := chips[desc]
		if got == "" {
			t.Fatalf("the map bar lost the %q chip", desc)
		}
		if got != key {
			t.Errorf("chip %q shows %q, want the preset's %q", desc, got, key)
		}
	}
}

// TestHelpBarNeverExceedsTerminalWidth: the bar wraps onto another row rather
// than running off the side or being cut, so no chip is ever half-rendered and
// none is silently lost at a narrow width.
func TestHelpBarNeverExceedsTerminalWidth(t *testing.T) {
	for _, width := range []int{40, 60, 70, 80, 100, 120} {
		for _, screen := range barScreens(t) {
			m := screen.build(t)
			m.width, m.height = width, 40
			for _, line := range strings.Split(ansi.Strip(m.helpView(screen.deferred)), "\n") {
				if got := lipgloss.Width(line); got > width {
					t.Errorf("%s at %d columns: help line is %d wide: %q", screen.name, width, got, line)
				}
			}
			// The compact bar replaces the full one under height pressure and
			// is bound by the same promise.
			for _, line := range strings.Split(ansi.Strip(m.compactHelpView(screen.deferred)), "\n") {
				if got := lipgloss.Width(line); got > width {
					t.Errorf("%s at %d columns: compact help line is %d wide: %q", screen.name, width, got, line)
				}
			}
		}
	}
}

// TestUnadvertisedAcceleratorsStayReachable: the bar stopped naming most of
// the direct actions, so the menu has to name every one of them. An action
// that is neither on the bar nor in the menu would be a key only the
// cheatsheet knows about, which is the memorisation this design is against.
func TestUnadvertisedAcceleratorsStayReachable(t *testing.T) {
	m := evidenceModel(t)
	m.width, m.height, m.watch = 120, 40, true
	for i := range m.tools {
		m.tools[i].Available = true
	}
	onBar := barChips(t, m, false)
	var menu []keyAction
	for _, item := range m.actionItems() {
		menu = append(menu, item.act)
	}
	for _, def := range actionDefs {
		help, ok := def.help[ctxList]
		if !ok || !m.keys.bound(ctxList, def.act) || def.group == groupMove {
			continue
		}
		if _, shown := onBar[help.bar]; shown {
			continue
		}
		if !m.actionAvailable(def.act) {
			continue // nothing to reach: the action does not apply here
		}
		if !slices.Contains(menu, def.act) {
			t.Errorf("%s is bound, unavailable on the help bar, and missing from Actions", def.name)
		}
	}
}

// TestCheatsheetIsGroupedLikeTheActionsMenu: the menu and the sheet are the
// two discovery paths, and a reader who learns the menu's hierarchy should
// find the sheet already sorted into it. The tools in particular have to be
// visibly a group of their own rather than more built-in vocabulary.
func TestCheatsheetIsGroupedLikeTheActionsMenu(t *testing.T) {
	for _, preset := range KeyPresets() {
		t.Run(preset, func(t *testing.T) { cheatsheetGroups(t, preset) })
	}
}

func cheatsheetGroups(t *testing.T, preset string) {
	t.Helper()
	km, err := PresetKeymap(preset)
	if err != nil {
		t.Fatal(err)
	}
	m := evidenceModel(t)
	m.width, m.height, m.keys = 120, 40, km
	for i := range m.tools {
		m.tools[i].Available = true
	}
	sheet := ansi.Strip(m.helpContent())
	keysPart, viewerPart, ok := strings.Cut(sheet, "Output viewer")
	if !ok {
		t.Fatal("the cheatsheet lost its output viewer section")
	}
	// Group headings appear in the menu's order, each above its own rows.
	var at []int
	for _, name := range groupNames {
		i := strings.Index(keysPart, "\n"+name+"\n")
		if i < 0 {
			t.Fatalf("the cheatsheet has no %q section:\n%s", name, keysPart)
		}
		at = append(at, i)
	}
	if !slices.IsSorted(at) {
		t.Errorf("cheatsheet groups are not in the menu's order: %v", at)
	}
	// Every menu row's key is filed under that row's group in the sheet.
	for _, item := range m.actionItems() {
		section := sheetSection(t, keysPart, groupNames[item.group])
		if !strings.Contains(section, "  "+item.key+" ") {
			t.Errorf("Actions files %q under %q, the cheatsheet does not:\n%s",
				item.name, groupNames[item.group], section)
		}
	}
	// Movement is navigation, not an action, so it is the one group the menu
	// never carries and the sheet always must.
	if move := sheetSection(t, keysPart, groupNames[groupMove]); !strings.Contains(move, m.keys.label(ctxList, actUp)) {
		t.Errorf("the cheatsheet's %q section does not say how to move:\n%s", groupNames[groupMove], move)
	}
	for _, want := range []string{"filter lines", "back"} {
		if !strings.Contains(viewerPart, want) {
			t.Errorf("the viewer section lost %q:\n%s", want, viewerPart)
		}
	}
}

// sheetSection is the rows under one cheatsheet heading.
func sheetSection(t *testing.T, sheet, name string) string {
	t.Helper()
	_, rest, ok := strings.Cut(sheet, "\n"+name+"\n")
	if !ok {
		t.Fatalf("the cheatsheet has no %q section:\n%s", name, sheet)
	}
	var out []string
	for _, line := range strings.Split(rest, "\n") {
		if line != "" && !strings.HasPrefix(line, " ") {
			break // the next heading
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// TestCheatsheetGroupsSurviveMonochrome: the headings are the sheet's
// hierarchy, and colour is not a distinction every terminal or every reader
// has. They are indented differently from the rows they introduce, so the
// structure has to survive every colour being stripped.
func TestCheatsheetGroupsSurviveMonochrome(t *testing.T) {
	m := evidenceModel(t)
	m.width, m.height = 120, 40
	m.setTheme(themes[themeIndex("monochrome")])
	sheet := ansi.Strip(m.helpContent())
	for _, name := range groupNames {
		heading := "\n" + name + "\n"
		if name == groupNames[groupTools] && len(m.tools) == 0 {
			continue
		}
		if !strings.Contains(sheet, heading) {
			t.Errorf("monochrome lost the %q heading:\n%s", name, sheet)
		}
	}
	for _, row := range strings.Split(sheet, "\n") {
		for _, name := range groupNames {
			if strings.TrimSpace(row) == name && strings.HasPrefix(row, " ") {
				t.Errorf("heading %q is indented like a key row: %q", name, row)
			}
		}
	}
}

// TestCaseVariantKeysStayDistinct audits the four action/tool pairs that
// differ only in shift, plus restart and retest. Each half has to resolve to
// its own owner and neither may start a chord, since a chord prefix would hold
// the keyboard instead of reaching the tool.
func TestCaseVariantKeysStayDistinct(t *testing.T) {
	pairs := []struct{ lower, upper string }{
		{"i", "I"}, {"d", "D"}, {"t", "T"}, {"s", "S"}, {"r", "R"},
	}
	tgt := mustTarget(t, "example.com:443")
	for _, preset := range KeyPresets() {
		km, err := PresetKeymap(preset)
		if err != nil {
			t.Fatal(err)
		}
		m := newModel(tgt, false)
		m.keys = km
		for _, pair := range pairs {
			owner := func(key string) string {
				if act, ok := km.lookup(ctxList, []string{key}); ok {
					for _, def := range actionDefs {
						if def.act == act {
							return "action " + def.name
						}
					}
				}
				if tool, ok := m.toolForKey(key); ok {
					return "tool " + tool.Name
				}
				return ""
			}
			low, up := owner(pair.lower), owner(pair.upper)
			if low == "" || up == "" {
				t.Errorf("%s: %q/%q own %q and %q: both halves must be live", preset, pair.lower, pair.upper, low, up)
			}
			if low == up {
				t.Errorf("%s: %q and %q both run %s", preset, pair.lower, pair.upper, low)
			}
			for _, key := range []string{pair.lower, pair.upper} {
				if km.isPrefix(ctxList, []string{key}) {
					t.Errorf("%s: %q starts a chord, so its own action never fires alone", preset, key)
				}
			}
		}
	}
}

// TestDocumentedKeysMatchTheDefaultPreset: the default bindings are the public
// surface. Every one of them has to be written down, or a reader who goes
// looking for a key the sheet showed them finds nothing.
func TestDocumentedKeysMatchTheDefaultPreset(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	table, _, ok := strings.Cut(string(doc), "`--keys vim` adds")
	if !ok {
		t.Fatal("docs/reference.md no longer carries the key binding table")
	}
	_, table, ok = strings.Cut(table, "The TUI's default key bindings:")
	if !ok {
		t.Fatal("docs/reference.md no longer introduces the key binding table")
	}
	// The table spells two keys the way a reader sees them rather than the way
	// the keymap names them.
	spelled := map[string]string{"up": "↑", "down": "↓", " ": "space"}
	km, err := PresetKeymap("")
	if err != nil {
		t.Fatal(err)
	}
	for _, def := range actionDefs {
		if _, ok := def.help[ctxList]; !ok {
			continue
		}
		for _, seq := range km.keysFor(ctxList, def.act) {
			key := seq
			if s, ok := spelled[seq]; ok {
				key = s
			}
			if !strings.Contains(table, "`"+key+"`") {
				t.Errorf("%s is bound to %q, which docs/reference.md does not document", def.name, key)
			}
		}
	}
	for _, tool := range newModel(mustTarget(t, "example.com:443"), false).tools {
		if !strings.Contains(string(doc), "| `"+tool.Key+"` |") {
			t.Errorf("tool %q (%s) is not in the documented hotkey table", tool.Key, tool.Name)
		}
	}
}
