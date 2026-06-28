package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	toolbox := false
	arg := ""
	for _, a := range os.Args[1:] {
		if a == "--toolbox" {
			toolbox = true
			continue
		}
		arg = a // last non-flag wins
	}

	var t *Target
	if arg != "" {
		parsed, err := parseTarget(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "network-doctor:", err)
			os.Exit(2) // bad args / validation reject
		}
		t = parsed
	}

	m := newModel(t)
	m.toolbox = toolbox
	p := tea.NewProgram(m, tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "network-doctor:", err)
		os.Exit(1)
	}
	os.Exit(exitCode(final))
}

// exitCode derives the process status from the final model: 0 in toolbox mode
// when the chain never ran; 1 if any probe Failed or the chain didn't finish
// (early quit); else 0. Skip/NotApplicable are not failures.
func exitCode(final tea.Model) int {
	m, ok := final.(model)
	if !ok {
		return 1
	}
	if m.toolbox && !m.chainRan() {
		return 0 // toolbox mode, no chain run
	}
	if len(m.results) < len(m.probes) {
		return 1 // quit before the chain finished
	}
	for _, id := range m.order {
		if m.results[id].Status == StatusFail {
			return 1
		}
	}
	return 0
}
