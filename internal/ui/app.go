// Package ui owns the Bubble Tea application, rendering, and tool execution.
// Network semantics live in the diagnostic package.
package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mplaczek99/network-doctor/internal/diagnostic"
)

// New constructs the terminal application.
func New(target *diagnostic.Target, toolbox bool) tea.Model {
	m := newModel(target)
	m.toolbox = toolbox
	return m
}

// ExitCode returns 0 in toolbox mode when the chain never ran; 1 if any probe
// failed or the chain did not finish; otherwise 0. Skip/N/A are not failures.
func ExitCode(final tea.Model) int {
	m, ok := final.(model)
	if !ok {
		return 1
	}
	if m.toolbox && !m.chainRan() {
		return 0
	}
	if len(m.results) < len(m.probes) {
		return 1
	}
	for _, id := range m.order {
		if m.results[id].Status == StatusFail {
			return 1
		}
	}
	return 0
}
