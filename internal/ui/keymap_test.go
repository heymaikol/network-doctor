package ui

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func keyPress(name string) tea.KeyMsg {
	types := map[string]tea.KeyType{
		"up": tea.KeyUp, "down": tea.KeyDown, "enter": tea.KeyEnter,
		"esc": tea.KeyEsc, "tab": tea.KeyTab, "home": tea.KeyHome,
		"end": tea.KeyEnd, "pgup": tea.KeyPgUp, "pgdown": tea.KeyPgDown,
		"ctrl+b": tea.KeyCtrlB, "ctrl+d": tea.KeyCtrlD,
		"ctrl+f": tea.KeyCtrlF, "ctrl+u": tea.KeyCtrlU,
	}
	if typ, ok := types[name]; ok {
		return tea.KeyMsg{Type: typ}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(name)}
}

func resolvedAction(km Keymap, ctx keyContext, keys ...string) (keyAction, []string) {
	m := model{keys: km}
	var act keyAction
	for _, key := range keys {
		act, m.pendingKeys = m.resolveKey(ctx, key)
	}
	return act, m.pendingKeys
}

func TestDefaultPresetKeepsHistoricalBindings(t *testing.T) {
	km, err := PresetKeymap("")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ctx  keyContext
		key  string
		want keyAction
	}{
		{ctxList, "up", actUp}, {ctxList, "k", actUp},
		{ctxList, "down", actDown}, {ctxList, "j", actDown},
		{ctxList, "enter", actOpen}, {ctxList, "esc", actCancelJob},
		{ctxList, "tab", actSwitchJob}, {ctxList, "y", actCopy},
		{ctxList, "w", actSave}, {ctxList, "r", actRestart},
		{ctxList, "v", actNetworkMap},
		{ctxList, "e", actExplain}, {ctxList, "i", actIncidents},
		{ctxList, "?", actHelp}, {ctxList, "q", actQuit},
		{ctxViewer, "up", actUp}, {ctxViewer, "k", actUp},
		{ctxViewer, "down", actDown}, {ctxViewer, "j", actDown},
		{ctxViewer, "home", actTop}, {ctxViewer, "end", actBottom},
		{ctxViewer, "pgup", actPageUp}, {ctxViewer, "pgdown", actPageDown},
		{ctxViewer, "esc", actClearFilter}, {ctxViewer, "q", actBack},
		{ctxViewer, "tab", actSwitchJob}, {ctxViewer, "y", actCopy},
		{ctxViewer, "w", actSave}, {ctxViewer, "/", actFilter},
		// Vim-only keys must not change default behavior.
		{ctxList, "home", actNone}, {ctxList, "end", actNone},
		{ctxList, "g", actNone}, {ctxList, "G", actNone},
		{ctxViewer, "g", actNone}, {ctxViewer, "G", actNone},
		{ctxViewer, "ctrl+b", actNone}, {ctxViewer, "ctrl+d", actNone},
		{ctxViewer, "ctrl+f", actNone}, {ctxViewer, "ctrl+u", actNone},
		{ctxViewer, "?", actNone},
	}
	for _, tt := range tests {
		act, pending := resolvedAction(km, tt.ctx, tt.key)
		if act != tt.want || pending != nil {
			t.Errorf("context %d key %q = (%d, %v), want (%d, nil)", tt.ctx, tt.key, act, pending, tt.want)
		}
	}

	named, err := PresetKeymap("default")
	if err != nil || !reflect.DeepEqual(km.keys, named.keys) {
		t.Errorf("empty and named default differ: err=%v", err)
	}
}

func TestVimPresetMotions(t *testing.T) {
	km, err := PresetKeymap("vim")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ctx  keyContext
		keys []string
		want keyAction
	}{
		{ctxList, []string{"g", "g"}, actTop},
		{ctxList, []string{"G"}, actBottom},
		{ctxViewer, []string{"g", "g"}, actTop},
		{ctxViewer, []string{"G"}, actBottom},
		{ctxViewer, []string{"ctrl+b"}, actPageUp},
		{ctxViewer, []string{"ctrl+f"}, actPageDown},
		{ctxViewer, []string{"ctrl+u"}, actHalfPageUp},
		{ctxViewer, []string{"ctrl+d"}, actHalfPageDown},
		// The preset adds Vim motions without removing familiar keys.
		{ctxList, []string{"down"}, actDown},
		{ctxViewer, []string{"home"}, actTop},
		{ctxViewer, []string{"pgdown"}, actPageDown},
		{ctxList, []string{"q"}, actQuit},
	}
	for _, tt := range tests {
		act, pending := resolvedAction(km, tt.ctx, tt.keys...)
		if act != tt.want || pending != nil {
			t.Errorf("context %d keys %v = (%d, %v), want (%d, nil)", tt.ctx, tt.keys, act, pending, tt.want)
		}
	}
}

func TestChordResolutionAndReplay(t *testing.T) {
	km, _ := PresetKeymap("vim")
	m := model{keys: km}
	act, pending := m.resolveKey(ctxList, "g")
	if act != actNone || !slices.Equal(pending, []string{"g"}) {
		t.Fatalf("first g = (%d, %v), want (none, [g])", act, pending)
	}
	m.pendingKeys = pending
	if act, pending = m.resolveKey(ctxList, "j"); act != actDown || pending != nil {
		t.Fatalf("g then j = (%d, %v), want (down, nil)", act, pending)
	}
	m.pendingKeys = []string{"g"}
	if act, pending = m.resolveKey(ctxList, "g"); act != actTop || pending != nil {
		t.Fatalf("gg = (%d, %v), want (top, nil)", act, pending)
	}

	// A tool key that kills a chord still reaches the toolbox.
	m = newModel(mustTarget(t, "example.com"), true)
	m.keys = km
	m = pressed(t, m, keyPress("g"))
	if !slices.Equal(m.pendingKeys, []string{"g"}) {
		t.Fatalf("pendingKeys = %v, want [g]", m.pendingKeys)
	}
	m = pressed(t, m, keyPress("n"))
	if m.pendingKeys != nil || m.confirmTool == nil {
		t.Fatalf("g then n left pending=%v confirm=%v", m.pendingKeys, m.confirmTool)
	}
}

func TestVimMotionsDispatch(t *testing.T) {
	km, _ := PresetKeymap("vim")
	m := newModel(mustTarget(t, "example.com"), false)
	m.keys = km
	m.selected = len(m.probes) - 1
	m = pressed(t, pressed(t, m, keyPress("g")), keyPress("g"))
	if m.selected != 0 {
		t.Errorf("gg selected row %d, want 0", m.selected)
	}
	m = pressed(t, m, keyPress("G"))
	if m.selected != len(m.probes)-1 {
		t.Errorf("G selected row %d, want %d", m.selected, len(m.probes)-1)
	}

	m.width, m.height = 80, 24
	m.cur.name, m.cur.status = "tool", JobDone
	for i := range 200 {
		m.appendJobLine(fmt.Sprintf("line %d", i))
	}
	m = pressed(t, m, keyPress("enter"))
	view := func(key string) {
		t.Helper()
		u, _ := m.handleViewKey(keyPress(key))
		m = asModel(t, u)
	}
	view("g")
	if m.vp.YOffset == 0 {
		t.Fatal("the first g moved before the chord completed")
	}
	view("g")
	if m.vp.YOffset != 0 || m.follow {
		t.Errorf("gg left offset %d follow=%v", m.vp.YOffset, m.follow)
	}
	view("ctrl+d")
	if m.vp.YOffset == 0 {
		t.Error("ctrl+d did not scroll")
	}
	view("G")
	if m.vp.YOffset == 0 || !m.follow {
		t.Errorf("G left offset %d follow=%v", m.vp.YOffset, m.follow)
	}
}

func TestBuiltInPresetsHaveNoConflicts(t *testing.T) {
	for _, preset := range presets {
		t.Run(preset.name, func(t *testing.T) {
			for ctx := range numContexts {
				owner := map[string]string{}
				for _, def := range actionDefs {
					for _, seq := range preset.preset[ctx][def.act] {
						if held := owner[seq]; held != "" {
							t.Errorf("%q is bound to both %s and %s", seq, held, def.name)
						}
						owner[seq] = def.name
					}
				}
				for seq, action := range owner {
					for other, otherAction := range owner {
						if seq != other && strings.HasPrefix(other, seq+" ") {
							t.Errorf("%s's %q hides %s's %q", action, seq, otherAction, other)
						}
					}
				}
			}
			if len(preset.preset[ctxList][actQuit]) == 0 ||
				(len(preset.preset[ctxViewer][actBack]) == 0 && len(preset.preset[ctxViewer][actClearFilter]) == 0) {
				t.Error("preset is missing an exit")
			}
		})
	}
}

func TestKeyPresetsAreStableAndResolvable(t *testing.T) {
	want := []string{"default", "vim"}
	got := KeyPresets()
	if !slices.Equal(got, want) {
		t.Fatalf("KeyPresets() = %v, want %v", got, want)
	}
	got[0] = "changed"
	if !slices.Equal(KeyPresets(), want) {
		t.Fatalf("mutating KeyPresets() changed later calls: %v", KeyPresets())
	}
	for _, name := range KeyPresets() {
		if _, err := PresetKeymap(name); err != nil {
			t.Errorf("PresetKeymap(%q): %v", name, err)
		}
	}
}

func TestActionMetadataMatchesDispatchAndHelp(t *testing.T) {
	km, _ := PresetKeymap("vim")
	m := newModel(nil, false)
	m.keys, m.width = km, 200
	help := m.helpOverlay()
	seen := map[keyAction]bool{}
	for _, def := range actionDefs {
		if seen[def.act] || len(def.help) == 0 {
			t.Errorf("invalid metadata for action %q", def.name)
		}
		seen[def.act] = true
		for ctx, metadata := range def.help {
			for _, seq := range km.keysFor(ctx, def.act) {
				parts := splitSeq(seq)
				if act, ok := km.lookup(ctx, parts); !ok || act != def.act {
					t.Errorf("%s %q dispatches to %d, ok=%v", def.name, seq, act, ok)
				}
			}
			if km.bound(ctx, def.act) &&
				(!strings.Contains(help, km.label(ctx, def.act)) || !strings.Contains(help, metadata.details)) {
				t.Errorf("help is missing %s in context %d", def.name, ctx)
			}
		}
	}
	for act := actNone + 1; act <= actQuit; act++ {
		if !seen[act] {
			t.Errorf("action %d has no metadata", act)
		}
	}
}

func TestPresetKeymapRejectsUnknownName(t *testing.T) {
	want := fmt.Sprintf("unknown key preset %q (have: %s)", "emacs", strings.Join(KeyPresets(), ", "))
	if _, err := PresetKeymap("emacs"); err == nil || err.Error() != want {
		t.Fatalf("PresetKeymap(emacs) error = %v, want %q", err, want)
	}
}

func pressed(t *testing.T, m model, msg tea.KeyMsg) model {
	t.Helper()
	u, _ := m.handleKey(msg)
	return asModel(t, u)
}
