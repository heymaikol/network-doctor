// Key bindings as data: one table drives dispatch, the help bar, and the
// cheatsheet so the three cannot drift.

package ui

import (
	"fmt"
	"maps"
	"strings"
)

type keyAction int

const (
	actNone keyAction = iota
	actUp
	actDown
	actTop
	actBottom
	actPageUp
	actPageDown
	actHalfPageUp
	actHalfPageDown
	actOpen
	actBack
	actClearFilter
	actCancelJob
	actSwitchJob
	actCopy
	actSave
	actFilter
	actRestart
	actRetest
	actSSH
	actNetworkMap
	actRescanNetwork
	actExpand
	actExplain
	actCheckDetails
	actIncidents
	actActions
	actTheme
	actHelp
	actQuit
)

type keyContext int

const (
	ctxList keyContext = iota
	ctxViewer
	numContexts
)

type actionDef struct {
	act  keyAction
	name string
	// menu is the Actions menu's wording for this action. An empty one keeps
	// the action off the menu, which is where the movement keys belong: they
	// move the menu itself.
	menu string
	// group is what the action acts on. The Actions menu sorts by it and the
	// cheatsheet sections by it, so both teach one hierarchy. The zero value,
	// groupMove, is navigation, which is also where the viewer-only actions
	// sit unread: the cheatsheet's viewer section is not grouped.
	group actionGroup
	help  map[keyContext]actionHelp
}

type actionHelp struct {
	bar     string
	details string
}

// actionDefs is the shared dispatch context, help text, menu wording, and
// cheatsheet order.
var actionDefs = []actionDef{
	{actUp, "up", "", groupMove, map[keyContext]actionHelp{
		ctxList:   {"select", "previous check, or device/service on the network map"},
		ctxViewer: {"scroll", "scroll up"},
	}},
	{actDown, "down", "", groupMove, map[keyContext]actionHelp{
		ctxList:   {"select", "next check, or device/service on the network map"},
		ctxViewer: {"scroll", "scroll down"},
	}},
	{actTop, "top", "", groupMove, map[keyContext]actionHelp{
		ctxList:   {"first/last", "first check, or device/service on the network map"},
		ctxViewer: {"top/bottom", "jump to top"},
	}},
	{actBottom, "bottom", "", groupMove, map[keyContext]actionHelp{
		ctxList:   {"first/last", "last check, or device/service on the network map"},
		ctxViewer: {"top/bottom", "jump to bottom (re-enables follow)"},
	}},
	{actPageUp, "page-up", "", groupMove, map[keyContext]actionHelp{ctxViewer: {"page", "page up"}}},
	{actPageDown, "page-down", "", groupMove, map[keyContext]actionHelp{ctxViewer: {"page", "page down"}}},
	{actHalfPageUp, "half-page-up", "", groupMove, map[keyContext]actionHelp{ctxViewer: {"half page", "half page up"}}},
	{actHalfPageDown, "half-page-down", "", groupMove, map[keyContext]actionHelp{ctxViewer: {"half page", "half page down"}}},
	{actOpen, "open", "Full output", groupRun, map[keyContext]actionHelp{ctxList: {"open", "full output; on the network map, open a device then diagnose one of its services"}}},
	{actFilter, "filter", "", groupMove, map[keyContext]actionHelp{ctxViewer: {"filter", "filter lines"}}},
	{actCopy, "copy", "Copy report", groupReport, map[keyContext]actionHelp{
		ctxList:   {"copy", "copy selected portal URL, otherwise report"},
		ctxViewer: {"copy output", "copy output (filtered if a filter is on)"},
	}},
	{actSave, "save", "Save report", groupReport, map[keyContext]actionHelp{
		ctxList:   {"save report", "save report"},
		ctxViewer: {"save output", "save output (filtered if a filter is on)"},
	}},
	{actSwitchJob, "switch-job", "Switch job", groupRun, map[keyContext]actionHelp{
		ctxList:   {"switch job", "switch job"},
		ctxViewer: {"switch job", "switch job"},
	}},
	{actCancelJob, "cancel-job", "Cancel job", groupRun, map[keyContext]actionHelp{ctxList: {"cancel job", "cancel the focused job, or leave an opened device on the network map"}}},
	{actNetworkMap, "network-map", "Network map", groupNetwork, map[keyContext]actionHelp{ctxList: {"network map", "show the latest LAN snapshot, or discover the local network when none exists"}}},
	{actRescanNetwork, "rescan-network", "Rescan network", groupNetwork, map[keyContext]actionHelp{ctxList: {"", "run fresh LAN discovery from the Actions menu"}}},
	{actExpand, "expand", "Expand checks", groupRun, map[keyContext]actionHelp{ctxList: {"expand", "show the collapsed passing checks"}}},
	{actExplain, "explain", "Explain why", groupRun, map[keyContext]actionHelp{ctxList: {"why", "show why the selected diagnosis follows from the observed checks"}}},
	{actCheckDetails, "check-details", "Check details", groupRun, map[keyContext]actionHelp{ctxList: {"details", "open the selected check's complete evidence"}}},
	{actIncidents, "incidents", "Incidents", groupRun, map[keyContext]actionHelp{ctxList: {"incidents", "inspect failures recorded during this watch session"}}},
	{actRestart, "restart", "Restart", groupSession, map[keyContext]actionHelp{ctxList: {"restart", "restart with a new target"}}},
	{actRetest, "retest", "Retest checks", groupRun, map[keyContext]actionHelp{ctxList: {"retest", "rerun the same checks on the same target, after acting on the remediation"}}},
	{actSSH, "ssh", "SSH login", groupNetwork, map[keyContext]actionHelp{ctxList: {"ssh login", "log in to a host, handing the terminal to ssh"}}},
	{actClearFilter, "clear-filter", "", groupMove, map[keyContext]actionHelp{ctxViewer: {"clear filter", "clear the filter, or back when none is set"}}},
	{actBack, "back", "", groupMove, map[keyContext]actionHelp{ctxViewer: {"back", "back"}}},
	{actActions, "actions", "", groupSession, map[keyContext]actionHelp{ctxList: {"actions", "list what the run can do right now, and run one without knowing its key"}}},
	{actTheme, "theme", "Theme", groupSession, map[keyContext]actionHelp{ctxList: {"theme", "pick a colour theme, previewed as you move and remembered between sessions"}}},
	{actHelp, "help", "Help", groupSession, map[keyContext]actionHelp{ctxList: {"help", "full-screen key cheatsheet"}}},
	{actQuit, "quit", "Quit", groupSession, map[keyContext]actionHelp{ctxList: {"quit", "quit"}}},
}

// actionGroupOf is what act acts on, independent of what is on screen.
func actionGroupOf(act keyAction) actionGroup {
	for _, def := range actionDefs {
		if def.act == act {
			return def.group
		}
	}
	return groupMove
}

func actionHelpFor(ctx keyContext, act keyAction) (actionHelp, bool) {
	for _, def := range actionDefs {
		help, ok := def.help[ctx]
		if def.act == act {
			return help, ok
		}
	}
	return actionHelp{}, false
}

type actionBindings map[keyAction][]string
type keyPreset [numContexts]actionBindings

// defaultPreset preserves the existing TUI key bindings as the default.
var defaultPreset = keyPreset{
	ctxList: {
		actUp:           {"up", "k"},
		actDown:         {"down", "j"},
		actOpen:         {"enter"},
		actCancelJob:    {"esc"},
		actSwitchJob:    {"tab"},
		actCopy:         {"y"},
		actSave:         {"w"},
		actRestart:      {"r"},
		actRetest:       {"R"},
		actSSH:          {"S"},
		actNetworkMap:   {"v"},
		actExpand:       {"a"},
		actExplain:      {"e"},
		actCheckDetails: {"D"},
		actIncidents:    {"i"},
		actActions:      {" "},
		actTheme:        {"T"},
		actHelp:         {"?"},
		actQuit:         {"q"},
	},
	ctxViewer: {
		actUp:          {"up", "k"},
		actDown:        {"down", "j"},
		actTop:         {"home"},
		actBottom:      {"end"},
		actPageUp:      {"pgup"},
		actPageDown:    {"pgdown"},
		actBack:        {"q"},
		actClearFilter: {"esc"},
		actSwitchJob:   {"tab"},
		actCopy:        {"y"},
		actSave:        {"w"},
		actFilter:      {"/"},
	},
}

var vimPreset = func() keyPreset {
	p := clonePreset(defaultPreset)
	p[ctxList][actTop] = []string{"g g"}
	p[ctxList][actBottom] = []string{"G"}
	p[ctxViewer][actTop] = []string{"g g", "home"}
	p[ctxViewer][actBottom] = []string{"G", "end"}
	p[ctxViewer][actPageUp] = []string{"ctrl+b", "pgup"}
	p[ctxViewer][actPageDown] = []string{"ctrl+f", "pgdown"}
	p[ctxViewer][actHalfPageUp] = []string{"ctrl+u"}
	p[ctxViewer][actHalfPageDown] = []string{"ctrl+d"}
	return p
}()

var presets = []struct {
	name   string
	preset keyPreset
}{
	{"default", defaultPreset},
	{"vim", vimPreset},
}

// KeyPresets lists the built-in presets in user-facing order.
func KeyPresets() []string {
	names := make([]string, len(presets))
	for i, preset := range presets {
		names[i] = preset.name
	}
	return names
}

func clonePreset(p keyPreset) keyPreset {
	var out keyPreset
	for ctx, bindings := range p {
		out[ctx] = maps.Clone(bindings)
	}
	return out
}

// PresetKeymap resolves one built-in preset. Empty selects the default.
func PresetKeymap(name string) (Keymap, error) {
	if name == "" {
		name = presets[0].name
	}
	for _, preset := range presets {
		if preset.name == name {
			return newKeymap(preset.preset), nil
		}
	}
	return Keymap{}, fmt.Errorf("unknown key preset %q (have: %s)", name, strings.Join(KeyPresets(), ", "))
}

// Keymap resolves keys to actions. Its zero value is the default keymap.
type Keymap struct {
	keys   keyPreset
	byKey  [numContexts]map[string]keyAction
	prefix [numContexts]map[string]bool
}

func newKeymap(bindings keyPreset) Keymap {
	km := Keymap{keys: clonePreset(bindings)}
	for ctx := range numContexts {
		km.byKey[ctx] = map[string]keyAction{}
		km.prefix[ctx] = map[string]bool{}
	}
	for _, def := range actionDefs {
		for ctx := range def.help {
			for _, seq := range bindings[ctx][def.act] {
				km.byKey[ctx][seq] = def.act
				parts := splitSeq(seq)
				for i := 1; i < len(parts); i++ {
					km.prefix[ctx][strings.Join(parts[:i], " ")] = true
				}
			}
		}
	}
	return km
}

var defaultKeymap = newKeymap(defaultPreset)

func (k Keymap) resolved() Keymap {
	if k.keys[ctxList] == nil {
		return defaultKeymap
	}
	return k
}

func (k Keymap) lookup(ctx keyContext, seq []string) (keyAction, bool) {
	act, ok := k.resolved().byKey[ctx][strings.Join(seq, " ")]
	return act, ok
}

func (k Keymap) isPrefix(ctx keyContext, seq []string) bool {
	return k.resolved().prefix[ctx][strings.Join(seq, " ")]
}

func (k Keymap) keysFor(ctx keyContext, act keyAction) []string {
	return k.resolved().keys[ctx][act]
}

func (k Keymap) bound(ctx keyContext, act keyAction) bool {
	return len(k.keysFor(ctx, act)) > 0
}

func (k Keymap) label(ctx keyContext, act keyAction) string {
	seqs := k.keysFor(ctx, act)
	out := make([]string, len(seqs))
	for i, seq := range seqs {
		out[i] = displaySeq(seq)
	}
	return strings.Join(out, "/")
}

func (k Keymap) pairLabel(ctx keyContext, a, b keyAction) string {
	first := func(act keyAction) string {
		if seqs := k.keysFor(ctx, act); len(seqs) > 0 {
			return displaySeq(seqs[0])
		}
		return ""
	}
	x, y := first(a), first(b)
	switch {
	case x == "":
		return y
	case y == "":
		return x
	default:
		return x + "/" + y
	}
}

// splitSeq is the keys one binding is made of. A chord is spelled with spaces
// between its keys, so the space binding is its own case rather than something
// Fields could tell apart from a separator.
func splitSeq(seq string) []string {
	if seq == " " {
		return []string{" "}
	}
	return strings.Fields(seq)
}

func displaySeq(seq string) string {
	var b strings.Builder
	for _, key := range splitSeq(seq) {
		switch key {
		case " ":
			b.WriteString("space")
		case "up":
			b.WriteString("↑")
		case "down":
			b.WriteString("↓")
		case "left":
			b.WriteString("←")
		case "right":
			b.WriteString("→")
		default:
			b.WriteString(key)
		}
	}
	return b.String()
}
