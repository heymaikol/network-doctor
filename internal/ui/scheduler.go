// Probe scheduling: dependency gating, skip propagation, and the per-probe
// tea.Cmd that isolates a probe goroutine from the live results map.

package ui

import (
	"context"
	"maps"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// scheduleStep marks newly-skippable probes (a dependency failed) and returns run
// commands for newly-runnable probes, repeating until no further progress so
// skips propagate through dependents in one pass. Mutates results/started.
func (m *model) scheduleStep() []tea.Cmd {
	var cmds []tea.Cmd
	for progress := true; progress; {
		progress = false
		for _, p := range m.probes {
			if m.started[p.ID] {
				continue
			}
			ready, blocked := diagnostic.DepsState(p.Deps, m.results)
			if !ready {
				continue
			}
			m.started[p.ID] = true
			progress = true
			if blocked {
				if m.analysisReady {
					m.results = maps.Clone(m.results)
					m.analysisReady = false
				}
				m.results[p.ID] = diagnostic.SkipPrereq(p.ID)
				continue
			}
			cmds = append(cmds, m.runProbe(p))
		}
	}
	return cmds
}

// runProbe builds the tea.Cmd for a probe, capturing the generation, the parent
// context, this model's probe timeout, and an immutable snapshot of just its
// dependency outputs.
func (m *model) runProbe(p diagnostic.Probe) tea.Cmd {
	gen, parent, run, id, timeout := m.generation, m.ctx, p.Run, p.ID, m.probeTimeout
	snap := snapshot(m.results, p.Deps)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		return probeDoneMsg{id: id, gen: gen, res: run(ctx, snap)}
	}
}

// snapshot copies just the requested dependency results into a fresh map so the
// probe goroutine never touches the live, Update-owned map.
func snapshot(res map[diagnostic.ProbeID]diagnostic.ProbeResult, deps []diagnostic.ProbeID) map[diagnostic.ProbeID]diagnostic.ProbeResult {
	out := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(deps))
	for _, d := range deps {
		if r, ok := res[d]; ok {
			out[d] = r
		}
	}
	return out
}
