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

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// barChips is the help bar as (key, description) pairs, which is how the rule
// is stated: a chip earns its place by what it says about the current region,
// not by which key happens to be free.
func barChips(t *testing.T, m model, deferred bool) map[string]string {
	t.Helper()
	return chipsIn(t, m.helpView(deferred))
}

// chipsIn reads any of the help bars as (description, key) pairs. The compact
// and hidden-region bars are parsed by the same rule as the full one, which is
// what lets a test state that all three agree about an action.
func chipsIn(t *testing.T, rendered string) map[string]string {
	t.Helper()
	chips := map[string]string{}
	// The bar wraps onto more rows rather than dropping a chip, so the rows
	// are read as one list.
	bar := strings.ReplaceAll(ansi.Strip(rendered), "\n", "  ·  ")
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
			[]string{"select", "details", "actions", "help", "quit"}},
		// The same screen once a tool has run: enter is spent on that tool's
		// output, so the bar names what it opens beside the selected check's
		// own key. Both regions are on screen, and neither chip is a bare key.
		{"checks with a job", false, checkAndJob,
			[]string{"select", "details", "full output", "actions", "help", "quit"}},
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
				if _, ok := got[must]; !ok && (must != "actions" || got["actions: rescan"] == "") {
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

// detailsKey is how the Check details chip reads on the bar under the active
// preset, which is what a test asserting discoverability has to look for: the
// key is the preset's, never a hardcoded "D".
func detailsKey(m model) string { return m.keys.label(ctxList, actCheckDetails) }

// TestCheckDetailsIsAdvertisedAtEveryHeight is the point of the rule. The
// route to a selected check's complete evidence is the one the reader needs
// most on a short terminal and is useful on a tall one, so it may not be a
// chip the layout hands out: shrinking the window used to reveal it, and the
// evidence compaction that frees rows used to take it away again. The bar the
// layout picks changes with height; what it says about the selection does not.
func TestCheckDetailsIsAdvertisedAtEveryHeight(t *testing.T) {
	for _, size := range [][2]int{{120, 40}, {100, 30}, {80, 24}, {70, 20}, {80, 16}, {80, 12}, {80, 10}} {
		m := evidenceModel(t)
		u, _ := m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		nm := asModel(t, u)
		want := detailsKey(nm) + " details"
		if got := ansi.Strip(nm.View()); !strings.Contains(got, want) {
			t.Errorf("%dx%d: the Checks bar does not name %q:\n%s", size[0], size[1], want, got)
		}
	}
}

// detailsScreens are the states the chip's rule has to be stated against. The
// predicate is meant to be one thing, that the cursor is on a check, so every
// axis that is not the selection appears here to prove it does not move the
// chip: a finished job takes enter for its own output, watch mode keeps
// redrawing underneath the cursor, and a check that passed is still evidence.
func detailsScreens(t *testing.T) []struct {
	name  string
	build func(t *testing.T) model
	want  bool
} {
	t.Helper()
	withJob := func(t *testing.T) model {
		m := evidenceModel(t)
		m.cur = jobState{name: "ping the host", display: "ping -c 4 example.com", status: JobDone}
		return m
	}
	return []struct {
		name  string
		build func(t *testing.T) model
		want  bool
	}{
		{"failed check selected", evidenceModel, true},
		{"healthy check selected", func(t *testing.T) model {
			m := evidenceModel(t)
			m.selected = probeIndex(t, m, diagnostic.ProbeInternet)
			return m
		}, true},
		// enter is spent on the job's output here, so the selected check has
		// no other key at all: the chip matters more in this state, not less.
		{"job present", withJob, true},
		{"watch mode", func(t *testing.T) model {
			m := withJob(t)
			m.watch = true
			return m
		}, true},
		// Nothing is selected, so there is nothing for the key to open.
		{"no check selected", func(t *testing.T) model {
			m := evidenceModel(t)
			m.selected = -1
			return m
		}, false},
		// The map's selection is a device or a service, never a check.
		{"network map", mapModel, false},
		{"opened device", func(t *testing.T) model { return openedDevice(t, mapModel(t)) }, false},
	}
}

// TestCheckDetailsChipFollowsTheSelection: the chip answers what the primary
// key does to the selected thing, so it is on screen exactly when the selected
// thing is a check. It is not a reward for a failure, not a consolation for a
// missing job, and not something the network map inherits by being in the same
// bar function.
func TestCheckDetailsChipFollowsTheSelection(t *testing.T) {
	for _, screen := range detailsScreens(t) {
		m := screen.build(t)
		m.width, m.height = 120, 40
		_, shown := barChips(t, m, false)["details"]
		if shown != screen.want {
			t.Errorf("%s: Check details on the bar = %v, want %v", screen.name, shown, screen.want)
		}
		if got := m.actionAvailable(actCheckDetails); got != screen.want {
			t.Errorf("%s: the chip and the action disagree: available = %v, want %v", screen.name, got, screen.want)
		}
	}
}

// TestHelpBarsAgreeAboutCheckDetails: the full bar, the compact bar the layout
// swaps in under height pressure, and the one-line bar that replaces a region
// too short to draw all read the same predicate. Any of them deciding on its
// own is how the key became discoverable only on a small terminal.
func TestHelpBarsAgreeAboutCheckDetails(t *testing.T) {
	for _, screen := range detailsScreens(t) {
		m := screen.build(t)
		m.width, m.height = 80, 40
		full := barChips(t, m, false)["details"]
		compact := chipsIn(t, m.compactHelpView(false))["details"]
		if full != compact {
			t.Errorf("%s: full bar says details=%q, compact bar says %q", screen.name, full, compact)
		}
		if m.networkMap {
			continue // the hidden-region bar names the map's own cursor
		}
		if hidden := chipsIn(t, m.hiddenRegionHelp(false))["details"]; hidden != full {
			t.Errorf("%s: hidden-region bar says details=%q, full bar says %q", screen.name, hidden, full)
		}
	}
}

// TestCheckDetailsChipUsesTheActivePreset: the chip is looked up in the
// keymap like every other one, so a rebinding preset moves it.
func TestCheckDetailsChipUsesTheActivePreset(t *testing.T) {
	for _, preset := range KeyPresets() {
		km, err := PresetKeymap(preset)
		if err != nil {
			t.Fatal(err)
		}
		m := evidenceModel(t)
		m.width, m.height, m.keys = 120, 40, km
		if got, want := barChips(t, m, false)["details"], km.label(ctxList, actCheckDetails); got != want {
			t.Errorf("%s: the details chip shows %q, want the preset's %q", preset, got, want)
		}
	}
}

// TestChecksBarKeepsTheDiscoveryTailWhenItWraps: the chip costs the bar width,
// and a bar that answered "what can I do here" by pushing "how do I leave" off
// the screen would have traded one discoverability problem for a worse one.
func TestChecksBarKeepsTheDiscoveryTailWhenItWraps(t *testing.T) {
	for _, width := range []int{120, 100, 80, 70, 60, 50} {
		m := evidenceModel(t)
		m.width, m.height = width, 40
		chips := barChips(t, m, false)
		for _, desc := range []string{"select", "details", "actions", "help", "quit"} {
			if _, ok := chips[desc]; !ok {
				t.Errorf("at %d columns the Checks bar dropped the %q chip:\n%s",
					width, desc, ansi.Strip(m.helpView(false)))
			}
		}
	}
}

// checkAndJob is the state both contextual chips apply to at once: a check is
// selected, so Check details has something to open, and a tool has run, so
// enter is spent on that tool's output. The two act on different regions of
// the same screen, which is the wording the bar has to keep unambiguous.
func checkAndJob(t *testing.T) model {
	t.Helper()
	m := evidenceModel(t)
	m.cur = jobState{name: "ping the host", display: "ping -c 4 example.com", status: JobDone,
		lines: []string{"64 bytes from example.com: icmp_seq=1 time=11 ms"}}
	return m
}

// outputKey is the key the active preset binds to the output viewer.
func outputKey(m model) string { return m.keys.label(ctxList, actOpen) }

// outputScreens are the states the Full output chip's rule is stated against.
// The rule is the dispatch's: the chip is on the bar exactly when enter would
// open the focused job's output, which is why the map screens are here. A job
// is running behind every one of them, and on those screens enter belongs to
// the device or the service under the cursor instead.
func outputScreens(t *testing.T) []struct {
	name  string
	build func(t *testing.T) model
	want  bool
} {
	t.Helper()
	return []struct {
		name  string
		build func(t *testing.T) model
		want  bool
	}{
		// Nothing has run a tool, so there is no output to open.
		{"no job", evidenceModel, false},
		{"completed job", checkAndJob, true},
		{"active job", func(t *testing.T) model {
			m := checkAndJob(t)
			m.cur.status, m.cur.active = JobRunning, &job{}
			return m
		}, true},
		// A tail of a running job is the case the chip matters most in, and
		// the case a predicate watching the pane would flicker on.
		{"multiple jobs", func(t *testing.T) model {
			m := checkAndJob(t)
			m.otherJobs = []jobState{{name: "trace the path", display: "traceroute example.com", status: JobDone}}
			return m
		}, true},
		// mapModel's selected job is the LAN scan that drew the map: the job
		// exists, and enter still opens the device under the cursor.
		{"network map", mapModel, false},
		{"opened device", func(t *testing.T) model { return openedDevice(t, mapModel(t)) }, false},
	}
}

// TestFullOutputChipFollowsTheDispatch: the Tool output pane shows a tail, so
// a screen carrying one is a screen the reader cannot read all of, and the
// route to the rest used to be named only by the bars a short terminal swaps
// in. The chip is now on the ordinary bar under the same condition that makes
// enter open the viewer, so it cannot advertise a key that would do something
// else: on the network map enter opens a device, and the bar says so instead.
func TestFullOutputChipFollowsTheDispatch(t *testing.T) {
	for _, screen := range outputScreens(t) {
		m := screen.build(t)
		m.width, m.height = 120, 40
		chips := barChips(t, m, false)
		key, shown := chips["full output"]
		if shown != screen.want {
			t.Errorf("%s: Full output on the bar = %v, want %v", screen.name, shown, screen.want)
		}
		if shown && key != outputKey(m) {
			t.Errorf("%s: the chip shows %q, want the bound %q", screen.name, key, outputKey(m))
		}
		if !m.networkMap {
			continue
		}
		// enter is never unexplained: the map spends it on its own cursor.
		if chips["open device"] == "" && chips["diagnose it"] == "" {
			t.Errorf("%s: the bar names neither what enter opens nor the job: %v", screen.name, chips)
		}
	}
}

// TestFullOutputChipAndCheckDetailsNameTheirOwnRegion: both contextual chips
// are on the bar at once whenever a check is selected and a tool has run. The
// pair only works if each says what it opens, so a reader is never left
// guessing which of two live regions a key acts on.
func TestFullOutputChipAndCheckDetailsNameTheirOwnRegion(t *testing.T) {
	m := checkAndJob(t)
	m.width, m.height = 120, 40
	chips := barChips(t, m, false)
	if got, want := chips["details"], detailsKey(m); got != want {
		t.Errorf("the Check details chip shows %q, want %q", got, want)
	}
	if got, want := chips["full output"], outputKey(m); got != want {
		t.Errorf("the Full output chip shows %q, want %q", got, want)
	}
	for desc := range chips {
		// "open" is the wording this chip used to carry in the action table:
		// a key with no object, on a screen holding two of them.
		if desc == "open" || desc == "view" {
			t.Errorf("the bar names a key without naming what it opens: %q", desc)
		}
	}
}

// TestHelpBarsAgreeAboutFullOutput: the full bar, the compact bar the layout
// swaps in under height pressure, and the one-line bar that replaces a region
// too short to draw all answer the same question the same way. The full bar
// being the only one that stayed quiet is the inconsistency this fixes.
func TestHelpBarsAgreeAboutFullOutput(t *testing.T) {
	for _, screen := range outputScreens(t) {
		m := screen.build(t)
		m.width, m.height = 80, 40
		full := barChips(t, m, false)["full output"]
		if compact := chipsIn(t, m.compactHelpView(false))["full output"]; compact != full {
			t.Errorf("%s: full bar says full output=%q, compact bar says %q", screen.name, full, compact)
		}
		if m.networkMap {
			continue // the hidden-region bar names the map's own cursor
		}
		if hidden := chipsIn(t, m.hiddenRegionHelp(false))["full output"]; hidden != full {
			t.Errorf("%s: hidden-region bar says full output=%q, full bar says %q", screen.name, hidden, full)
		}
	}
}

// TestFullOutputIsAdvertisedAtEveryHeight: which bar the layout picks changes
// with height, and the inline job pane disappears entirely on a short
// terminal. What the screen says about reaching the whole output does not
// change with either. Monochrome is checked with it because the chip is a
// word, so the answer cannot depend on colour.
func TestFullOutputIsAdvertisedAtEveryHeight(t *testing.T) {
	for _, size := range [][2]int{{120, 40}, {100, 30}, {80, 24}, {70, 20}, {80, 16}, {80, 12}, {80, 10}} {
		for _, theme := range []string{"terminal", "monochrome"} {
			m := checkAndJob(t)
			m.setTheme(resolveTheme(theme))
			u, _ := m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			nm := asModel(t, u)
			want := outputKey(nm) + " full output"
			if got := ansi.Strip(nm.View()); !strings.Contains(got, want) {
				t.Errorf("%dx%d %s: the screen does not name %q:\n%s", size[0], size[1], theme, want, got)
			}
		}
	}
}

// TestFullOutputChipUsesTheActivePreset: the chip is looked up in the keymap
// like every other one, so a rebinding preset moves it.
func TestFullOutputChipUsesTheActivePreset(t *testing.T) {
	for _, preset := range KeyPresets() {
		km, err := PresetKeymap(preset)
		if err != nil {
			t.Fatal(err)
		}
		m := checkAndJob(t)
		m.width, m.height, m.keys = 120, 40, km
		if got, want := barChips(t, m, false)["full output"], km.label(ctxList, actOpen); got != want {
			t.Errorf("%s: the Full output chip shows %q, want the preset's %q", preset, got, want)
		}
	}
}

// TestChecksBarWithAJobKeepsEveryChip: the chip costs the bar width on a
// screen that already spends some on the selected check. The bar wraps at a
// chip boundary rather than dropping the selection's key or the tail that says
// where everything else lives.
func TestChecksBarWithAJobKeepsEveryChip(t *testing.T) {
	for _, width := range []int{120, 100, 80, 70, 60, 50} {
		m := checkAndJob(t)
		m.width, m.height = width, 40
		bar := ansi.Strip(m.helpView(false))
		chips := barChips(t, m, false)
		for _, desc := range []string{"select", "details", "full output", "actions", "help", "quit"} {
			if _, ok := chips[desc]; !ok {
				t.Errorf("at %d columns the Checks bar dropped the %q chip:\n%s", width, desc, bar)
			}
		}
		for _, line := range strings.Split(bar, "\n") {
			if got := lipgloss.Width(line); got > width {
				t.Errorf("at %d columns a bar line is %d wide: %q", width, got, line)
			}
		}
	}
}

// TestEnterOpensTheJobTheScreenNames: the chip says "full output" without
// saying whose, so the pane, the viewer and the key have to agree on which job
// that is, before and after tab moves the selection.
func TestEnterOpensTheJobTheScreenNames(t *testing.T) {
	m := checkAndJob(t)
	m.otherJobs = []jobState{{name: "trace the path", display: "traceroute example.com", status: JobDone,
		lines: []string{"1  192.168.1.1  1.1 ms"}}}
	u, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = asModel(t, u)
	for _, want := range []string{"ping -c 4 example.com", "traceroute example.com"} {
		main := ansi.Strip(m.View())
		if !strings.Contains(main, jobPaneTitle) || !strings.Contains(main, "$ "+want) {
			t.Fatalf("the Tool output pane does not show %q:\n%s", want, main)
		}
		if _, ok := barChips(t, m, false)["full output"]; !ok {
			t.Fatalf("the bar stopped naming Full output while %q was focused:\n%s", want, main)
		}
		viewer := openViewer(t, m)
		view := ansi.Strip(viewer.View())
		if !strings.Contains(view, viewerTitle) || !strings.Contains(view, "$ "+want) {
			t.Fatalf("enter opened something other than %q:\n%s", want, view)
		}
		back, _ := viewer.Update(keyPress("esc"))
		if m = asModel(t, back); m.viewing {
			t.Fatal("esc did not leave the output viewer")
		}
		next, _ := m.Update(keyPress("tab"))
		m = asModel(t, next)
	}
}
