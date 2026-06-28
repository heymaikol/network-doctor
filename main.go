package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	target := ""
	if len(os.Args) > 1 {
		target = normalizeTarget(os.Args[1])
	}
	p := tea.NewProgram(newModel(checks(target)))
	final, err := p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "network-doctor:", err)
		os.Exit(1)
	}
	os.Exit(exitCode(final))
}

// exitCode derives the process exit status from the final model returned by
// Run (Bubble Tea's value-update means the original model var is stale).
// Nonzero if any check failed or any check is still pending (early quit).
func exitCode(final tea.Model) int {
	m, ok := final.(model)
	if !ok {
		return 1
	}
	for _, row := range m.rows {
		if row.result == nil || !row.result.Status {
			return 1
		}
	}
	return 0
}
