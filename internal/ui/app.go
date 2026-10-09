// Package ui owns the Bubble Tea application, rendering, and tool execution.
// Network semantics live in the diagnostic package.
package ui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// Cleanup stops everything the final model still owns, and waits for the kills
// to land. Quitting through the UI already does this, but Bubble Tea also
// returns on paths Update never sees (a signal, stdin closing on a non-tty, a
// renderer failure, a recovered panic) and on those the generation context is
// still live, which leaves tool subprocesses and their descendants running
// after netdoc is gone. Safe to call twice; cancelling a dead context is a
// no-op and a finished job has already sent its terminal event.
func Cleanup(final tea.Model) {
	m, ok := final.(model)
	if !ok {
		return
	}
	m.cancelJobs()
	m.clearCancel()
	if m.watchSession != nil {
		m.watchSession.Close()
	}
	// One deadline for all of them: a job that somehow won't die must not be
	// able to hold the exit open job by job. It has to be a closed channel, not
	// a timer channel, since the latter fires exactly once, so the first stuck job
	// would eat it and the rest would wait forever.
	ctx, cancel := context.WithTimeout(context.Background(), exitGrace)
	defer cancel()
	for j := range m.jobs {
		j.active.waitDone(ctx.Done())
	}
}

// ExitCode returns 0 in toolbox mode when the chain never ran; 1 if any probe
// failed or the chain did not finish; otherwise 0. Warn (degraded but
// functional) and Skip/N/A are not failures.
func ExitCode(final tea.Model) int {
	m, ok := final.(model)
	if !ok {
		return 1
	}
	if m.toolbox && !m.chainRan() {
		return 0
	}
	if len(m.results) < len(m.probes) {
		if !m.watch {
			return 1
		}
		for _, probe := range m.probes {
			history := m.runHistory[probe.ID]
			if len(history) == 0 || history[len(history)-1] == diagnostic.StatusFail {
				return 1
			}
		}
		return 0
	}
	for _, probe := range m.probes {
		if m.results[probe.ID].Status == diagnostic.StatusFail {
			return 1
		}
	}
	return 0
}
