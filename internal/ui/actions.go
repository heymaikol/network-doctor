// The Actions menu: one list of what the run can do right now, so a reader who
// has not learned the keys can still find them. It owns no commands of its
// own. Every row is an action from the shared key table or a drill-down tool,
// it carries whatever key the active preset binds, and running one
// goes through the same dispatch the keyboard does.

package ui

import (
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// actionGroup is what an action acts on, and it is the menu's hierarchy: rows
// are sorted by it, and each run of one group is introduced by that group's
// heading.
//
// The order of the constants is the order of the menu, derived from how far
// the action is from the question a reader opens the menu with, "what do I do
// about this run?". The run itself answers it directly; the network it sits on
// is the next ring out; the external tools look closer still but cost a job to
// find out; the report is what you do once the answer is in hand; and the
// session is the application rather than the run at all. Nothing here is
// ordered by how the keys happen to be laid out.
type actionGroup int

const (
	groupRun actionGroup = iota
	groupNetwork
	groupTools
	groupReport
	groupSession
)

// groupNames are the menu's headings. They are indented differently from the
// rows they introduce and carry no key column, so the hierarchy survives a
// terminal with no colour and a reader who never sees the bold.
var groupNames = [...]string{
	groupRun:     "This run",
	groupNetwork: "This network",
	groupTools:   "Drill down",
	groupReport:  "Report",
	groupSession: "Session",
}

// actionItem is one row of the Actions menu: what to call it, the key that
// runs it under the active preset, which action or tool it is, and the group
// it is filed under. A tool row leaves act zero; enter finds the tool by that
// key, the way the keyboard does.
//
// Every item is selectable. The headings are drawn from the group field at
// render time rather than being rows of their own, so there is nothing in the
// list the cursor has to learn to skip and nothing enter has to refuse.
type actionItem struct {
	name  string
	key   string
	act   keyAction
	group actionGroup
}

// actionID names the logical action a row runs, which is what the cursor is
// attached to: the keyAction for a built-in, the hotkey for a drill-down tool,
// which carries none. The zero value names no action, so a cursor that was
// never anchored falls back to its row.
type actionID struct {
	act keyAction
	key string
}

func (i actionItem) id() actionID {
	if i.act != actNone {
		return actionID{act: i.act}
	}
	return actionID{key: i.key}
}

// actionsRow is the row the cursor is on now. The list is rebuilt from live
// state, so checks finishing or a watch pass landing under an open menu can
// insert and remove rows above the cursor. Following the selected action
// rather than its index is what keeps the highlight, and enter with it, on the
// action the reader aimed at. The remembered row is only the fallback for when
// that action genuinely stops applying, clamped so it cannot point past the
// end.
func (m model) actionsRow(items []actionItem) int {
	if m.actionsSelID != (actionID{}) {
		for i, item := range items {
			if item.id() == m.actionsSelID {
				return i
			}
		}
	}
	return min(max(m.actionsSel, 0), max(len(items)-1, 0))
}

// selectRow puts the cursor on row i and anchors it to that row's action, so
// the row and the action it names are always written together.
func (m *model) selectRow(items []actionItem, i int) {
	i = min(max(i, 0), max(len(items)-1, 0))
	m.actionsSel, m.actionsSelID = i, actionID{}
	if i < len(items) {
		m.actionsSelID = items[i].id()
	}
}

// actionAvailable reports whether act would do something in the current state.
// It is the single answer both the help bar and the Actions menu ask, so what
// a reader is offered cannot drift from what the key actually does.
func (m model) actionAvailable(act keyAction) bool {
	switch act {
	case actOpen:
		// Mirrors the dispatch: on the map enter opens a device or diagnoses a
		// service, and only an empty device list leaves it free for the job pane.
		if m.networkMap {
			if m.svc.host != "" {
				return len(m.svc.scan.Open) > 0
			}
			if len(m.networkHosts()) > 0 {
				return true
			}
		}
		return m.hasJob()
	case actCancelJob:
		return m.networkMap && m.svc.host != "" || m.cur.active != nil
	case actSwitchJob:
		return len(m.otherJobs) > 0
	case actExplain:
		d := m.diagnosis()
		return m.allDone() && len(d.Findings) > 0 && len(d.Findings[0].Evidence) > 0
	case actIncidents:
		return m.watch && len(m.incidents.Incidents()) > 0
	case actCopy:
		return m.selectedPortalURL() != "" || m.reportReady()
	case actSave:
		return m.reportReady()
	case actRetest:
		// Offered once there is a finished run to rerun. Before that the chain
		// is either already running or waiting on the restart key, and a second
		// way to start it would only be a second name for restart.
		return m.allDone() && m.chainRan()
	case actSSH:
		return m.sshDetected()
	case actRescanNetwork:
		j, _ := (&m).newestJob(lanDiscoveryName)
		return j != nil && j.active == nil
	case actExpand:
		if m.expanded {
			return m.allDone()
		}
		_, hiddenPass, hiddenNA := m.compactRows()
		return hiddenPass+hiddenNA > 0
	case actNetworkMap, actRestart, actActions, actTheme, actHelp, actQuit:
		return true
	}
	return false
}

// actionName is the menu's wording for a built-in action: the table's name,
// specialised where the action itself changes with what is on screen.
func (m model) actionName(def actionDef) string {
	switch def.act {
	case actOpen:
		if m.networkMap {
			if m.svc.host != "" {
				return "Diagnose service"
			}
			if len(m.networkHosts()) > 0 {
				return "Open device"
			}
		}
	case actCancelJob:
		if m.networkMap && m.svc.host != "" {
			return "Back to devices"
		}
	case actNetworkMap:
		if m.networkMap {
			return "Back to checks"
		}
	case actCopy:
		if m.selectedPortalURL() != "" {
			return "Copy portal URL"
		}
	case actExpand:
		if m.expanded {
			return "Collapse checks"
		}
	}
	return def.menu
}

// actionGroupFor files a built-in under what it acts on. Two actions change
// what they act on with the screen, and both change their wording for the same
// reason, so this reads the same state actionName does: on the network map,
// enter walks the device list and esc steps back through it, which makes both
// of them map actions rather than actions on this run's own job pane.
func (m model) actionGroupFor(act keyAction) actionGroup {
	switch act {
	case actOpen:
		if m.networkMap && (m.svc.host != "" || len(m.networkHosts()) > 0) {
			return groupNetwork
		}
		return groupRun
	case actCancelJob:
		if m.networkMap && m.svc.host != "" {
			return groupNetwork
		}
		return groupRun
	case actSwitchJob, actExpand, actExplain, actIncidents, actRetest:
		return groupRun
	case actNetworkMap, actRescanNetwork, actSSH:
		return groupNetwork
	case actCopy, actSave:
		return groupReport
	}
	// Restart, Theme, Help and Quit: the application, not the run.
	return groupSession
}

// actionItems is what the current state can do: available built-ins and the
// drill-down tools whose binary is installed, sorted into the menu's groups.
// Built-ins require a list binding except for the explicitly menu-only Rescan.
//
// The sort is stable over the shared table's order, so within a group the rows
// keep the order the cheatsheet and help bar give them. That is what stops an
// action sliding around relative to its neighbours as other rows come and go:
// state can move a row between groups, never inside one.
func (m model) actionItems() []actionItem {
	var items []actionItem
	for _, def := range actionDefs {
		// Rescan is intentionally menu-only. Every other built-in menu row
		// still requires a list-context binding.
		if def.menu == "" || (def.act != actRescanNetwork && !m.keys.bound(ctxList, def.act)) || !m.actionAvailable(def.act) {
			continue
		}
		items = append(items, actionItem{
			name:  m.actionName(def),
			key:   m.keys.label(ctxList, def.act),
			act:   def.act,
			group: m.actionGroupFor(def.act),
		})
	}
	for _, tool := range m.tools {
		// The menu lists only tools it can run now.
		if !tool.Available {
			continue
		}
		items = append(items, actionItem{
			name:  strings.ToUpper(tool.Name[:1]) + tool.Name[1:],
			key:   tool.Key,
			group: groupTools,
		})
	}
	slices.SortStableFunc(items, func(a, b actionItem) int { return int(a.group) - int(b.group) })
	return items
}

// handleActionsKey drives the Actions menu. Enter runs the selected row and esc
// closes, as they do in the theme picker; everything else is resolved through
// the list bindings, so a reader who already knows a shortcut can press it here
// and get exactly what it does outside the menu.
func (m model) handleActionsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	items := m.actionItems()
	last := max(len(items)-1, 0)
	// Resolve the selection against the list as it is right now, and re-anchor
	// it: dispatch below acts on this same resolved row, so what enter runs is
	// what the frame the reader is looking at has highlighted.
	sel := m.actionsRow(items)
	m.selectRow(items, sel)
	switch msg.String() {
	case "enter":
		m.actionsOpen = false
		if len(items) == 0 {
			return m, nil
		}
		item := items[sel]
		if item.act == actNone {
			if tool, ok := m.toolForKey(item.key); ok {
				return m.runTool(tool)
			}
			return m, nil
		}
		return m.runAction(item.act)
	case "esc":
		m.actionsOpen = false
		return m, nil
	}
	act, pending := m.resolveKey(ctxList, msg.String())
	m.pendingKeys = pending
	switch act {
	case actNone:
		if len(pending) > 0 {
			return m, nil // a chord owns the keyboard until it completes
		}
		if tool, ok := m.toolForKey(msg.String()); ok {
			m.actionsOpen = false
			return m.runTool(tool)
		}
	case actActions:
		m.actionsOpen = false
	case actUp:
		m.selectRow(items, sel-1)
	case actDown:
		m.selectRow(items, sel+1)
	case actTop:
		m.selectRow(items, 0)
	case actBottom:
		m.selectRow(items, last)
	default:
		m.actionsOpen = false
		return m.runAction(act)
	}
	return m, nil
}
