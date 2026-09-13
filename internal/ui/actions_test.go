// The Actions menu: its binding, what it offers in a given state, and the
// promise that every row is the action the keyboard already runs rather than a
// second copy of it.

package ui

import (
	"maps"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// sendKey drives one key through Update, which is where the open menu takes
// ownership of the keyboard, so these tests exercise the real routing.
func sendKey(t *testing.T, m model, key string) model {
	t.Helper()
	u, _ := m.Update(keyPress(key))
	return asModel(t, u)
}

// menuModel is a finished run with a full tool set, the state with the most to
// offer. The tool table is pinned to one GOOS so the rows are the same
// wherever the suite runs.
func menuModel(t *testing.T) model {
	t.Helper()
	m := blackHoleModel(t)
	m.tools = toolsFor(m.target, "linux", toolBind{})
	// The fixture writes results straight into the map; retest is offered for
	// a chain that ran, so say that it did.
	for _, p := range m.probes {
		m.started[p.ID] = true
	}
	m.width, m.height = 100, 40
	return m
}

func menuNames(m model) []string {
	items := m.actionItems()
	names := make([]string, len(items))
	for i, item := range items {
		names[i] = item.name
	}
	return names
}

func menuKey(m model, name string) (string, bool) {
	for _, item := range m.actionItems() {
		if item.name == name {
			return item.key, true
		}
	}
	return "", false
}

// selectMenu puts the cursor on the named row, failing when the menu is not
// offering it at all.
func selectMenu(t *testing.T, m model, name string) model {
	t.Helper()
	i := slices.Index(menuNames(m), name)
	if i < 0 {
		t.Fatalf("the Actions menu has no %q row: %v", name, menuNames(m))
	}
	m.actionsOpen = true
	m.selectRow(m.actionItems(), i)
	return m
}

// The menu is reached through the ordinary keymap, so space has to resolve to
// it in every preset and stay out of the viewer, which never opens it.
func TestActionsMenuIsBoundToSpaceInEveryPreset(t *testing.T) {
	for _, preset := range presets {
		km, err := PresetKeymap(preset.name)
		if err != nil {
			t.Fatal(err)
		}
		if act, pending := resolvedAction(km, ctxList, " "); act != actActions || pending != nil {
			t.Errorf("%s: space = (%d, %v), want the Actions menu", preset.name, act, pending)
		}
		if act, ok := km.lookup(ctxViewer, []string{" "}); ok {
			t.Errorf("%s: space in the output viewer took action %d", preset.name, act)
		}
		if label := km.label(ctxList, actActions); label != "space" {
			t.Errorf("%s: the menu's key reads %q", preset.name, label)
		}
	}
}

func TestActionsMenuOpensAndCloses(t *testing.T) {
	m := menuModel(t)
	m = sendKey(t, m, " ")
	if !m.actionsOpen || m.actionsSel != 0 {
		t.Fatalf("space left open=%v sel=%d", m.actionsOpen, m.actionsSel)
	}
	if closed := sendKey(t, m, "esc"); closed.actionsOpen {
		t.Error("esc must close the menu")
	}
	if toggled := sendKey(t, m, " "); toggled.actionsOpen {
		t.Error("space must close the menu it opened")
	}
	// Closing acts on nothing: esc is the job cancel key outside the menu.
	canceled := false
	m.cur.active = &job{cancel: func() { canceled = true }}
	if sendKey(t, m, "esc"); canceled {
		t.Error("esc closed the menu and cancelled the job underneath it")
	}
}

func TestActionsMenuNavigatesAndRunsTheSelectedRow(t *testing.T) {
	m := menuModel(t)
	names := menuNames(m)
	m = sendKey(t, m, " ")
	for _, key := range []string{"down", "j", "up"} {
		m = sendKey(t, m, key)
	}
	if m.actionsSel != 1 {
		t.Fatalf("down, j, up left the cursor on row %d, want 1", m.actionsSel)
	}
	if m = sendKey(t, m, "up"); m.actionsSel != 0 {
		t.Fatalf("the cursor walked off the top to row %d", m.actionsSel)
	}
	for range len(names) + 3 {
		m = sendKey(t, m, "down")
	}
	if m.actionsSel != len(names)-1 {
		t.Fatalf("the cursor walked off the bottom to row %d of %d", m.actionsSel, len(names))
	}

	// Enter runs the selected row, and the row is what its name says.
	run := sendKey(t, selectMenu(t, m, "Theme"), "enter")
	if run.actionsOpen || !run.theming {
		t.Errorf("enter on Theme left open=%v theming=%v", run.actionsOpen, run.theming)
	}
	run = sendKey(t, selectMenu(t, m, "Restart"), "enter")
	if run.actionsOpen || !run.entering {
		t.Errorf("enter on Restart left open=%v entering=%v", run.actionsOpen, run.entering)
	}
	run = sendKey(t, selectMenu(t, m, "Ping the host"), "enter")
	if run.actionsOpen || run.cur.name != "ping the host" {
		t.Errorf("enter on Ping the host left open=%v job=%q", run.actionsOpen, run.cur.name)
	}
}

// A row that stopped applying under an open menu must not leave the cursor
// pointing past the end of the list.
func TestActionsMenuCursorSurvivesAShrinkingList(t *testing.T) {
	m := menuModel(t)
	m.actionsOpen, m.actionsSel = true, len(menuNames(m))-1
	m.tools = nil
	m.width, m.height = 100, 40
	if v := m.View(); !strings.Contains(v, "Actions") {
		t.Fatalf("the menu stopped rendering:\n%s", v)
	}
	m = sendKey(t, m, "enter")
	if m.actionsOpen {
		t.Error("enter must close the menu even after the list shrank")
	}
}

// Availability is the whole point of the menu.
func TestActionsMenuOffersOnlyWhatTheStateCanDo(t *testing.T) {
	running := newModel(mustTarget(t, "example.com:443"), false)
	running.width, running.height = 100, 40
	for _, name := range []string{"Retest", "Save report", "Switch job", "Explain why", "Full output", "Cancel job", "Incidents", "SSH login"} {
		if slices.Contains(menuNames(running), name) {
			t.Errorf("an unfinished run offers %q: %v", name, menuNames(running))
		}
	}
	// Restart and quit are always there, or the menu could open on nothing.
	for _, name := range []string{"Restart", "Theme", "Help", "Quit", "Network map"} {
		if !slices.Contains(menuNames(running), name) {
			t.Errorf("an unfinished run hides %q: %v", name, menuNames(running))
		}
	}

	done := menuModel(t)
	for _, name := range []string{"Retest", "Save report", "Copy report", "Explain why"} {
		if !slices.Contains(menuNames(done), name) {
			t.Errorf("a finished run hides %q: %v", name, menuNames(done))
		}
	}
	// A finished run has no job pane and no second job yet.
	for _, name := range []string{"Full output", "Switch job", "Cancel job"} {
		if slices.Contains(menuNames(done), name) {
			t.Errorf("a finished run with no job offers %q", name)
		}
	}

	jobs := menuModel(t)
	jobs.cur.name, jobs.cur.status = "ping the host", JobDone
	jobs.cur.active = &job{cancel: func() {}}
	jobs.otherJobs = []jobState{{name: "trace the path", status: JobDone}}
	for _, name := range []string{"Full output", "Switch job", "Cancel job"} {
		if !slices.Contains(menuNames(jobs), name) {
			t.Errorf("a run with two jobs hides %q: %v", name, menuNames(jobs))
		}
	}
}

func TestChecksFooterIsCompactAndUsesTheActiveKeymap(t *testing.T) {
	secondary := []string{
		"network map", "expand", "collapse", "copy", "save", "restart",
		"retest", "theme", "ssh", "incidents", "why", "full output",
	}
	for _, preset := range presets {
		t.Run(preset.name, func(t *testing.T) {
			km, err := PresetKeymap(preset.name)
			if err != nil {
				t.Fatal(err)
			}
			m := menuModel(t)
			m.keys, m.width = km, 200
			bar := ansi.Strip(m.helpView(false))
			var kv []string
			for _, act := range []keyAction{actActions, actHelp, actQuit} {
				help, _ := actionHelpFor(ctxList, act)
				kv = append(kv, km.label(ctxList, act), help.bar)
			}
			movement, _ := actionHelpFor(ctxList, actUp)
			kv = append([]string{km.pairLabel(ctxList, actUp, actDown), movement.bar}, kv...)
			if want := ansi.Strip(helpKeys(m.st, m.width, kv...)); bar != want {
				t.Errorf("footer = %q, want %q", bar, want)
			}
			for _, hidden := range secondary {
				if strings.Contains(bar, hidden) {
					t.Errorf("footer contains secondary action %q: %q", hidden, bar)
				}
			}
			for _, width := range []int{120, 80, 30} {
				m.width = width
				footer := m.helpView(false)
				for _, line := range strings.Split(footer, "\n") {
					if got := lipgloss.Width(line); got > width {
						t.Errorf("%d-column footer has a %d-column line: %q", width, got, line)
					}
				}
				if rows := lipgloss.Height(footer); width >= 80 && rows != 1 || width == 30 && rows > 2 {
					t.Errorf("%d-column footer uses %d rows: %q", width, rows, ansi.Strip(footer))
				}
			}
		})
	}
}

// Wording follows the state where the action itself does, which is the reason
// the menu names rows rather than repeating the cheatsheet.
func TestActionsMenuNamesFollowTheState(t *testing.T) {
	m := menuModel(t)
	m.results[m.probes[m.selected].ID] = diagnostic.ProbeResult{
		ID:     m.probes[m.selected].ID,
		Status: diagnostic.StatusWarn,
		Portal: &diagnostic.Portal{RedirectURL: "http://portal.example/login"},
	}
	if !slices.Contains(menuNames(m), "Copy portal URL") || slices.Contains(menuNames(m), "Copy report") {
		t.Errorf("a selected portal row must offer its URL: %v", menuNames(m))
	}

	collapsed := menuModel(t)
	if !slices.Contains(menuNames(collapsed), "Expand checks") {
		t.Errorf("a collapsed run must offer the expansion: %v", menuNames(collapsed))
	}
	collapsed.expanded = true
	if !slices.Contains(menuNames(collapsed), "Collapse checks") {
		t.Errorf("an expanded run must offer the way back: %v", menuNames(collapsed))
	}
}

// Every key in the menu is read from the active preset, never spelled out in
// the menu itself.
func TestActionsMenuKeysComeFromTheActivePreset(t *testing.T) {
	m := menuModel(t)
	if key, _ := menuKey(m, "Retest"); key != "R" {
		t.Errorf("Retest shows key %q, want R", key)
	}
	rebound := clonePreset(defaultPreset)
	rebound[ctxList][actRetest] = []string{"X"}
	rebound[ctxList][actExplain] = nil
	m.keys = newKeymap(rebound)
	if key, _ := menuKey(m, "Retest"); key != "X" {
		t.Errorf("the rebound Retest shows key %q, want X", key)
	}
	// An action the preset does not bind cannot be run from the menu either.
	if slices.Contains(menuNames(m), "Explain why") {
		t.Errorf("an unbound action is still on the menu: %v", menuNames(m))
	}
	if v := m.actionsView(30); !strings.Contains(ansi.Strip(v), "X  Retest") {
		t.Errorf("the rendered menu ignores the preset:\n%s", v)
	}
}

// Tool rows come straight from their metadata, with no duplicate main-view row.
func TestActionsMenuToolsComeFromToolMetadata(t *testing.T) {
	m := menuModel(t)
	if v := m.View(); strings.Contains(v, "Dig deeper") {
		t.Fatalf("the main view duplicates the Actions menu tools:\n%s", v)
	}
	var want []string
	for _, tool := range m.tools {
		want = append(want, strings.ToUpper(tool.Name[:1])+tool.Name[1:])
	}
	// The tools are one run of rows under one heading, in their table's order.
	// Where that run sits is the hierarchy's business, tested separately; what
	// matters here is that every installed tool is in it and nothing else is.
	names, got := menuNames(m), groupOnly(m, groupTools)
	if !slices.Equal(got, want) {
		t.Errorf("tool rows = %v, want %v (menu: %v)", got, want, names)
	}
	if at := slices.Index(names, want[0]); !slices.Equal(names[at:at+len(want)], want) {
		t.Errorf("the tool rows are not contiguous: %v", names)
	}
	for _, tool := range m.tools {
		key, ok := menuKey(m, strings.ToUpper(tool.Name[:1])+tool.Name[1:])
		if !ok || key != tool.Key {
			t.Errorf("tool %q shows key %q (found=%v), want %q", tool.Name, key, ok, tool.Key)
		}
	}
	// A tool whose binary is missing has a chip that says so; it is not
	// something the menu can run.
	m.tools[0].Available = false
	if slices.Contains(menuNames(m), strings.ToUpper(m.tools[0].Name[:1])+m.tools[0].Name[1:]) {
		t.Errorf("a missing binary is still offered: %v", menuNames(m))
	}
}

// The confirm gate belongs to the tool, not to the key that reached it.
func TestActionsMenuKeepsTheConfirmationGate(t *testing.T) {
	m := selectMenu(t, menuModel(t), "Port scan")
	m = sendKey(t, m, "enter")
	if m.actionsOpen || m.confirmTool == nil || m.confirmTool.Name != "port scan" {
		t.Fatalf("the port scan skipped its gate: open=%v confirm=%v", m.actionsOpen, m.confirmTool)
	}
	if m.cur.status == JobRunning {
		t.Error("the scan started before it was confirmed")
	}
	if run := sendKey(t, m, "y"); run.confirmTool != nil {
		t.Error("the gate did not hand the tool on to y")
	}
}

// An open menu is still the ordinary keyboard: a reader who knows a shortcut
// presses it and gets what it always does.
func TestActionsMenuPassesShortcutsThrough(t *testing.T) {
	m := menuModel(t)
	m.actionsOpen = true
	if themed := sendKey(t, m, "T"); themed.actionsOpen || !themed.theming {
		t.Errorf("T left open=%v theming=%v", themed.actionsOpen, themed.theming)
	}
	if scan := sendKey(t, m, "n"); scan.actionsOpen || scan.confirmTool == nil {
		t.Errorf("the tool hotkey left open=%v confirm=%v", scan.actionsOpen, scan.confirmTool)
	}
	if tool := sendKey(t, m, "p"); tool.actionsOpen || tool.cur.name != "ping the host" {
		t.Errorf("the tool hotkey left open=%v job=%q", tool.actionsOpen, tool.cur.name)
	}
	// A chord still owns the keyboard until it completes, and it moves the
	// menu's own cursor rather than the checks underneath it.
	km, _ := PresetKeymap("vim")
	vim := menuModel(t)
	vim.keys, vim.actionsOpen, vim.actionsSel = km, true, 4
	vim = sendKey(t, vim, "g")
	if !slices.Equal(vim.pendingKeys, []string{"g"}) || vim.actionsSel != 4 {
		t.Fatalf("the first g moved the cursor to %d (pending %v)", vim.actionsSel, vim.pendingKeys)
	}
	vim = sendKey(t, vim, "g")
	if vim.actionsSel != 0 || !vim.actionsOpen {
		t.Errorf("gg left the cursor on row %d, open=%v", vim.actionsSel, vim.actionsOpen)
	}
	vim = sendKey(t, vim, "G")
	if vim.actionsSel != len(menuNames(vim))-1 {
		t.Errorf("G left the cursor on row %d", vim.actionsSel)
	}
}

// The menu is drawn where the help bar goes, so the run behind it has to stay
// on screen and the view has to stay inside the terminal. The theme picker is
// the yardstick: it is the same kind of panel in the same place, so a size it
// survives is a size the menu has to survive, however many rows the menu would
// rather have had.
func TestActionsMenuFitsTheTerminal(t *testing.T) {
	for _, width := range []int{30, 46, 80, 120} {
		for _, height := range []int{6, 8, 10, 12, 16, 24, 40} {
			m := menuModel(t)
			m.width, m.height = width, height
			acts, picker := m, m
			acts.actionsOpen, acts.actionsSel = true, 12
			picker.theming, picker.themeSel = true, 1
			av, pv := acts.View(), picker.View()

			if rows := lipgloss.Height(av); rows > height {
				t.Errorf("%dx%d: the menu made the view %d rows tall", width, height, rows)
			}
			// The top of the screen carries the verdict, and nothing the menu
			// does may push it off.
			// Trailing blanks only: the view pads its rows out to the width.
			want := strings.Split(m.wrap(m.banner()), "\n")[0]
			if got := strings.TrimRight(strings.Split(av, "\n")[0], " "); got != want {
				t.Errorf("%dx%d: the view now opens on %q, want the verdict %q", width, height, got, want)
			}
			if n, limit := unclosedPanels(av), unclosedPanels(pv); n > limit {
				t.Errorf("%dx%d: %d panel border(s) left unclosed, the theme picker leaves %d:\n%s", width, height, n, limit, av)
			}
			if strings.Contains(ansi.Strip(pv), "esc cancel") && !strings.Contains(ansi.Strip(av), "esc close") {
				t.Errorf("%dx%d: the menu lost the footer the theme picker keeps:\n%s", width, height, av)
			}
		}
	}
}

// The way in has to be visible on the surfaces a lost reader looks at, and
// both of those are generated from the same metadata dispatch uses.
func TestHelpAdvertisesTheActionsMenu(t *testing.T) {
	m := menuModel(t)
	help, _ := actionHelpFor(ctxList, actActions)
	for name, surface := range map[string]string{
		"help bar":   ansi.Strip(m.helpView(false)),
		"deferred":   ansi.Strip(m.helpView(true)),
		"cheatsheet": ansi.Strip(m.helpOverlay()),
	} {
		if !strings.Contains(surface, "space") {
			t.Errorf("%s does not mention the menu's key:\n%s", name, surface)
		}
	}
	if !strings.Contains(ansi.Strip(m.helpView(false)), "space "+help.bar) {
		t.Errorf("the help bar chip does not come from the action metadata:\n%s", m.helpView(false))
	}
	if !strings.Contains(ansi.Strip(m.helpOverlay()), help.details) {
		t.Error("the cheatsheet does not come from the action metadata")
	}
}

// Opening the menu must not take the keyboard away from the modals that own
// it, and it must not follow the reader into the output viewer.
func TestActionsMenuYieldsToTheOtherModals(t *testing.T) {
	m := menuModel(t)
	m.cur.name, m.cur.status = "ping the host", JobDone
	m.appendJobLine("64 bytes from 192.0.2.1")
	viewing := sendKey(t, m, "enter")
	if !viewing.viewing {
		t.Fatal("enter did not open the output viewer")
	}
	if opened := sendKey(t, viewing, " "); opened.actionsOpen {
		t.Error("space opened the menu inside the output viewer")
	}
	entering := sendKey(t, m, "r")
	if space := sendKey(t, entering, " "); space.actionsOpen || space.input.Value() == entering.input.Value() {
		t.Error("space in the restart prompt opened the menu instead of typing")
	}
	theming := sendKey(t, m, "T")
	if space := sendKey(t, theming, " "); space.actionsOpen {
		t.Error("space opened the menu behind the theme picker")
	}
}

// highlighted is the row the reader can see is selected: the one the menu
// draws its cursor marker on. Tests that pair it with what enter runs are
// checking the promise that the two cannot disagree.
func highlighted(t *testing.T, m model) string {
	t.Helper()
	m.actionsOpen = true
	// The menu is drawn where the help bar goes, under the checks, which carry
	// a cursor marker of their own, so the menu's is the last one on screen.
	lines := strings.Split(ansi.Strip(m.View()), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		at := strings.Index(lines[i], "› ")
		if at < 0 {
			continue
		}
		// The row reads: marker, key, padding, name, then the panel border.
		row := strings.TrimRight(lines[i][at+len("› "):], " │")
		_, name, _ := strings.Cut(row, "  ")
		return strings.TrimSpace(name)
	}
	t.Fatalf("the menu drew no cursor:\n%s", ansi.Strip(m.View()))
	return ""
}

// finish is the asynchronous half of the bug: the checks complete under an
// open menu, which is when the rows that need a finished run appear, all of
// them above the tools.
func finish(m model) model {
	for _, p := range m.probes {
		if _, ok := m.results[p.ID]; !ok {
			m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusFail}
		}
	}
	return m
}

func unfinish(m model) model {
	m.results = maps.Clone(m.results)
	delete(m.results, m.probes[len(m.probes)-1].ID)
	return m
}

// The menu's rows come and go with the state behind it: Copy report, Save
// report, Expand checks, Explain why and Retest all appear when the run
// finishes, and every one of them sorts above the drill-down tools. A cursor
// that remembered only its row number would slide onto whatever moved into
// that slot, so a reader who picked a tool mid-run and waited would press
// enter on something they never chose. Quit is five rows below Web check here,
// which is how this was found.
func TestActionsMenuCursorFollowsTheActionNotTheRow(t *testing.T) {
	m := unfinish(menuModel(t))
	m = selectMenu(t, m, "Web check")
	if got := highlighted(t, m); got != "Web check" {
		t.Fatalf("the menu opened on %q", got)
	}

	done := finish(m)
	if got := highlighted(t, done); got != "Web check" {
		t.Errorf("the run finishing moved the cursor to %q with no keypress", got)
	}
	run := sendKey(t, done, "enter")
	if run.cur.name != "web check" {
		t.Errorf("enter ran %q, want the web check the menu was showing", run.cur.name)
	}
	if run.actionsOpen {
		t.Error("enter left the menu open")
	}
}

// A watch pass empties the results map and fills it again every few seconds,
// so the rows that need a finished run appear and disappear on a cadence for
// as long as the session runs. An open menu must sit still through all of it.
func TestActionsMenuCursorHoldsThroughWatchPasses(t *testing.T) {
	m := menuModel(t)
	m.watch = true
	m = selectMenu(t, m, "Trace the path")
	for pass := range 6 {
		m = unfinish(m)
		if got := highlighted(t, m); got != "Trace the path" {
			t.Fatalf("pass %d: mid-pass the cursor read %q", pass, got)
		}
		m = finish(m)
		if got := highlighted(t, m); got != "Trace the path" {
			t.Fatalf("pass %d: the finished pass moved the cursor to %q", pass, got)
		}
	}
	if run := sendKey(t, m, "enter"); run.cur.name != "trace the path" {
		t.Errorf("enter ran %q after six passes", run.cur.name)
	}
}

// When the selected action genuinely stops applying there is nothing to
// follow, so the cursor falls back to the row it was on, clamped into the
// shorter list. What matters is that the fallback is not a quiet
// misdispatch: enter still runs the row the menu is drawing its cursor on.
func TestActionsMenuFallsBackWhenTheSelectedActionGoesAway(t *testing.T) {
	m := selectMenu(t, menuModel(t), "Retest")
	// Retest is offered for a chain that ran; an unrun chain withdraws it.
	m.started = nil

	if slices.Contains(menuNames(m), "Retest") {
		t.Fatal("Retest is still on the menu, so this proves nothing")
	}
	shown := highlighted(t, m)
	run := sendKey(t, m, "enter")
	if i := slices.Index(menuNames(m), shown); i < 0 {
		t.Fatalf("the cursor landed on %q, which is not on the menu: %v", shown, menuNames(m))
	}
	// The fallback is the row, so it stays next to where the reader left it:
	// Retest is the last of "This run" here, and the row that slides into its
	// slot is the first of "This network".
	if shown != "Network map" {
		t.Fatalf("the cursor fell back to %q, want the row Retest vacated", shown)
	}
	// And enter runs that row rather than the one the index used to name: this
	// fixture has no private source address, so the map says so and nothing
	// about the theme the old index pointed at changes.
	if !strings.Contains(run.notice, "private IPv4 network") || run.theming || run.actionsOpen {
		t.Errorf("enter on the fallback row left notice=%q theming=%v open=%v", run.notice, run.theming, run.actionsOpen)
	}
}

// The list is rebuilt on every keypress and every frame, so a cursor left over
// from a longer list must never index past a shorter one, however many times
// the list changes shape underneath it.
func TestActionsMenuCursorStaysInRangeAcrossRepeatedChanges(t *testing.T) {
	m := menuModel(t)
	m.actionsOpen = true
	m.selectRow(m.actionItems(), len(menuNames(m))-1)
	for round := range 8 {
		switch round % 4 {
		case 0:
			m = unfinish(m)
		case 1:
			m.tools = nil
		case 2:
			m = finish(m)
		case 3:
			m.tools = toolsFor(m.target, "linux", toolBind{})
		}
		items := m.actionItems()
		if row := m.actionsRow(items); row < 0 || row > max(len(items)-1, 0) {
			t.Fatalf("round %d: row %d of %d items", round, row, len(items))
		}
		m = sendKey(t, m, "down")
		m = sendKey(t, m, "up")
		if _, ok := m.View(), true; !ok {
			t.Fatal("unreachable")
		}
	}
	// An empty list is the degenerate case: nothing to select, nothing to run.
	m.tools, m.results, m.started = nil, nil, nil
	m.probes = nil
	if run := sendKey(t, m, "enter"); run.actionsOpen {
		t.Error("enter must close the menu even with nothing on it")
	}
}

// groupOnly is the menu narrowed to one group, so a test can name the run of
// rows a heading introduces without hard-coding where it starts.
func groupOnly(m model, g actionGroup) []string {
	var kept []string
	for _, item := range m.actionItems() {
		if item.group == g {
			kept = append(kept, item.name)
		}
	}
	return kept
}

// menuGroups is the sequence of groups the rows fall into, collapsed to one
// entry per run: the hierarchy as a reader scanning down the menu meets it.
func menuGroups(m model) []actionGroup {
	var out []actionGroup
	for i, item := range m.actionItems() {
		if i == 0 || item.group != out[len(out)-1] {
			out = append(out, item.group)
		}
	}
	return out
}

// The ordering rule: every row is filed under what it acts on, the groups run
// in a fixed order, and a group appears at most once. A reader who has found
// where the report actions live has found where they will always live.
func TestActionsMenuGroupsRunInOrderAndOnlyOnce(t *testing.T) {
	states := map[string]model{
		"running": func() model {
			m := newModel(mustTarget(t, "example.com:443"), false)
			m.width, m.height = 100, 40
			return m
		}(),
		"finished": menuModel(t),
		"no tools": func() model { m := menuModel(t); m.tools = nil; return m }(),
		"map":      func() model { m := mapModel(t); m.tools = toolsFor(m.target, "linux", toolBind{}); return m }(),
		"jobs": func() model {
			m := menuModel(t)
			m.cur.name, m.cur.status, m.cur.active = "ping the host", JobRunning, &job{cancel: func() {}}
			m.otherJobs = []jobState{{name: "trace the path", status: JobDone}}
			return m
		}(),
	}
	for name, m := range states {
		groups := menuGroups(m)
		if !slices.IsSorted(groups) {
			t.Errorf("%s: the groups are out of order: %v (%v)", name, groups, menuNames(m))
		}
		// Sorted plus no repeats is exactly "each group is one run of rows",
		// which is what lets a single heading stand for the whole run.
		if len(slices.Compact(slices.Clone(groups))) != len(groups) {
			t.Errorf("%s: a group is split across the menu: %v (%v)", name, groups, menuNames(m))
		}
	}
}

// The point of the hierarchy: the things that move the diagnosis forward are
// reachable before the things that only manage the application.
func TestActionsMenuRanksDiagnosisAboveHousekeeping(t *testing.T) {
	m := menuModel(t)
	names := menuNames(m)
	rank := func(name string) int {
		i := slices.Index(names, name)
		if i < 0 {
			t.Fatalf("the menu has no %q row: %v", name, names)
		}
		return i
	}
	for _, next := range []string{"Explain why", "Expand checks", "Retest"} {
		for _, chrome := range []string{"Copy report", "Save report", "Restart", "Theme", "Help", "Quit"} {
			if rank(next) > rank(chrome) {
				t.Errorf("%q sorts below %q: %v", next, chrome, names)
			}
		}
	}
	// And the installed tools are next-step actions too, so they outrank the
	// report and session utilities rather than trailing them.
	for _, chrome := range []string{"Copy report", "Theme", "Quit"} {
		if rank("Ping the host") > rank(chrome) {
			t.Errorf("the tools sort below %q: %v", chrome, names)
		}
	}
	// Quit is the floor: nothing useful is below the way out.
	if rank("Quit") != len(names)-1 {
		t.Errorf("Quit is not the last row: %v", names)
	}
}

// The two actions whose wording follows the screen change what they act on
// with it, so they change group with it too and never appear twice.
func TestActionsMenuFilesMapActionsUnderTheNetwork(t *testing.T) {
	off := menuModel(t)
	off.cur.name, off.cur.status, off.cur.active = "ping the host", JobRunning, &job{cancel: func() {}}
	for _, name := range []string{"Full output", "Cancel job"} {
		i := slices.Index(menuNames(off), name)
		if i < 0 || off.actionItems()[i].group != groupRun {
			t.Errorf("off the map %q is not filed under this run: %v", name, menuNames(off))
		}
	}

	on := mapModel(t)
	on.svc.host, on.svc.done = "192.168.12.1", true
	on.svc.scan = diagnostic.ServiceScan{Open: []diagnostic.LocalService{{Port: 80, Name: "http"}}}
	for _, name := range []string{"Diagnose service", "Back to devices", "Back to checks", "Rescan network"} {
		i := slices.Index(menuNames(on), name)
		if i < 0 || on.actionItems()[i].group != groupNetwork {
			t.Errorf("on the map %q is not filed under the network: %v", name, menuNames(on))
		}
	}
}

// Every available action is on the menu exactly once, and the sort invents
// nothing: the grouped list is a permutation of the ungrouped one.
func TestActionsMenuRowsAppearExactlyOnce(t *testing.T) {
	for _, m := range []model{menuModel(t), mapModel(t), newModel(mustTarget(t, "example.com:443"), false)} {
		names := menuNames(m)
		if seen := slices.Compact(slices.Sorted(slices.Values(names))); len(seen) != len(names) {
			t.Errorf("a row is on the menu twice: %v", names)
		}
		ids := map[actionID]bool{}
		for _, item := range m.actionItems() {
			if ids[item.id()] {
				t.Errorf("action %+v is on the menu twice: %v", item.id(), names)
			}
			ids[item.id()] = true
		}
		// Nothing the state can do went missing on the way through the sort.
		for _, def := range actionDefs {
			want := def.menu != "" && (def.act == actRescanNetwork || m.keys.bound(ctxList, def.act)) && m.actionAvailable(def.act)
			if got := ids[actionID{act: def.act}]; got != want {
				t.Errorf("%s: on the menu=%v, available=%v: %v", def.name, got, want, names)
			}
		}
	}
}

// A group with nothing in it prints no heading, because the headings come off
// the rows rather than from a list of groups that might be empty.
func TestActionsMenuDrawsNoHeadingForAnEmptyGroup(t *testing.T) {
	m := menuModel(t)
	m.tools = nil
	m.actionsOpen = true
	v := ansi.Strip(m.View())
	if strings.Contains(v, groupNames[groupTools]) {
		t.Errorf("a run with no installed tools still prints the tools heading:\n%s", v)
	}
	for _, g := range []actionGroup{groupRun, groupNetwork, groupReport, groupSession} {
		if !strings.Contains(v, groupNames[g]) {
			t.Errorf("the %q heading is missing from a menu that has its rows:\n%s", groupNames[g], v)
		}
	}
	// Headings are drawn, not selectable: the cursor and enter only ever see
	// actions, so walking the whole list can never land on one.
	items := m.actionItems()
	for i := range items {
		m.selectRow(items, i)
		if got := highlighted(t, m); got != items[i].name {
			t.Fatalf("row %d highlighted %q, want %q", i, got, items[i].name)
		}
	}
	if slices.ContainsFunc(items, func(it actionItem) bool {
		return slices.Contains(groupNames[:], it.name)
	}) {
		t.Errorf("a heading leaked into the selectable rows: %v", menuNames(m))
	}
}

// The headings have to survive a theme with no colour at all, so the structure
// has to be in the text: a heading sits in the marker column the rows indent
// past, and carries no key.
func TestActionsMenuGroupingSurvivesMonochrome(t *testing.T) {
	m := menuModel(t)
	m.st = newStyles(resolveTheme("monochrome"))
	m.actionsOpen = true
	m.selectRow(m.actionItems(), 0)
	var headings, rows int
	for _, line := range strings.Split(ansi.Strip(m.View()), "\n") {
		body, ok := strings.CutPrefix(line, "│ ")
		if !ok {
			continue
		}
		body = strings.TrimRight(body, " │")
		switch {
		case body == "" || strings.HasPrefix(body, "Actions"):
		case slices.Contains(groupNames[:], body):
			headings++
		default:
			if !strings.HasPrefix(body, "  ") && !strings.HasPrefix(body, "› ") {
				t.Errorf("row %q does not indent past the heading column", body)
			}
			rows++
		}
	}
	if headings != 5 || rows != len(menuNames(m)) {
		t.Errorf("monochrome menu drew %d headings and %d rows, want 5 and %d", headings, rows, len(menuNames(m)))
	}
}

// menuPanelLines is the body of the menu panel: its rows and headings, without
// the border, the title, or the footer under it.
func menuPanelLines(v string) []string {
	var out []string
	for _, line := range strings.Split(ansi.Strip(v), "\n") {
		body, ok := strings.CutPrefix(line, "│ ")
		if !ok {
			continue
		}
		if body = strings.TrimRight(body, " │"); body != "" && !strings.HasPrefix(body, "Actions") {
			out = append(out, body)
		}
	}
	return out
}

// A short terminal has to spend its rows on actions, not on labels. The menu
// windows down to the selected row and, once the labels would outnumber what
// they label, drops them entirely rather than clipping the list to a heading.
func TestActionsMenuHierarchyDegradesOnShortTerminals(t *testing.T) {
	for _, height := range []int{40, 30, 24, 20, 16, 14, 12, 10, 8, 6} {
		for _, sel := range []int{0, 6, 17} {
			m := menuModel(t)
			m.width, m.height = 80, height
			m.actionsOpen = true
			m.selectRow(m.actionItems(), sel)
			v := m.View()
			if rows := lipgloss.Height(v); rows > height {
				t.Errorf("80x%d sel=%d: the view is %d rows tall", height, sel, rows)
			}
			body := menuPanelLines(v)
			var headings, actions int
			for _, line := range body {
				if slices.Contains(groupNames[:], line) {
					headings++
					continue
				}
				actions++
			}
			// Below a certain height the answer above the menu needs every row
			// and the panel is clipped away wholesale, which is the behavior
			// the theme picker has always had here. What must not happen is a
			// menu that draws headings and no actions.
			if len(body) == 0 {
				continue
			}
			if actions == 0 {
				t.Errorf("80x%d sel=%d: the menu drew headings and no actions:\n%v", height, sel, body)
			}
			// The selected action is the one row that must never be windowed
			// out, whatever the labels cost.
			if want := menuNames(m)[sel]; !slices.ContainsFunc(body, func(l string) bool {
				return strings.HasPrefix(l, "› ") && strings.HasSuffix(l, want)
			}) {
				t.Errorf("80x%d sel=%d: %q is not on screen:\n%v", height, sel, want, body)
			}
			// Labels are drawn only while they explain more rows than they cost.
			if headings > 0 && actions < 2*headings {
				t.Errorf("80x%d sel=%d: %d headings over %d actions:\n%v", height, sel, headings, actions, body)
			}
			// A window that opens inside a group still says which group, so a
			// scrolled menu is never a list of rows with no heading above them.
			if headings == 0 && actions > 1 && height >= 20 {
				t.Errorf("80x%d sel=%d: a roomy menu dropped its headings:\n%v", height, sel, body)
			}
			if headings > 0 && !slices.Contains(groupNames[:], body[0]) {
				t.Errorf("80x%d sel=%d: the window opens on a row with no heading:\n%v", height, sel, body)
			}
		}
	}
}

// The whole point of anchoring: groups appearing and disappearing underneath
// an open menu move rows around, and the cursor has to stay on the action the
// reader aimed at rather than on the row number it happened to have.
func TestActionsMenuSelectionSurvivesGroupsComingAndGoing(t *testing.T) {
	m := menuModel(t)
	m = selectMenu(t, m, "Quit")
	for round := range 8 {
		switch round % 4 {
		case 0: // the tools group vanishes from the middle of the menu
			m.tools = nil
		case 1: // the report group vanishes with the finished run
			m = unfinish(m)
		case 2:
			m.tools = toolsFor(m.target, "linux", toolBind{})
		case 3:
			m = finish(m)
		}
		if got := highlighted(t, m); got != "Quit" {
			t.Fatalf("round %d: the cursor moved to %q", round, got)
		}
	}
	u, cmd := m.Update(keyPress("enter"))
	if asModel(t, u).actionsOpen {
		t.Error("enter left the menu open")
	}
	if msgs := msgsFrom(t, cmd); !slices.ContainsFunc(msgs, func(msg tea.Msg) bool {
		_, ok := msg.(tea.QuitMsg)
		return ok
	}) {
		t.Errorf("enter ran something other than Quit after the groups churned: %v", msgs)
	}

	// The same holds for a row whose own group is the one that empties: it has
	// nowhere to follow to, so the cursor falls back to the row and enter
	// still runs what the reader can see is selected.
	tool := selectMenu(t, menuModel(t), "Port scan")
	tool.tools = nil
	shown := highlighted(t, tool)
	if !slices.Contains(menuNames(tool), shown) {
		t.Fatalf("the cursor landed on %q, which is not on the menu: %v", shown, menuNames(tool))
	}
}
