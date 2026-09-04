package app

import (
	"io"
	"os"
	"path/filepath"

	"github.com/charmbracelet/x/term"
)

// termIsTerminal is stubbed in tests, which have no terminal of their own.
var termIsTerminal = term.IsTerminal

// stdoutIsTerminal reports whether the TUI has a terminal to render on. Only
// stdout is asked about, and deliberately: bubbletea draws there, while for
// input it opens /dev/tty itself when stdin is redirected, so a piped stdin is
// still a working interactive run. The check goes through the same term
// package bubbletea uses, so the answer matches its own on every platform.
func stdoutIsTerminal(w io.Writer) bool {
	f, ok := w.(term.File)
	return ok && termIsTerminal(f.Fd())
}

// historyFile is where target history persists between sessions. "" is the
// UI's existing "in-memory only" path: it neither loads nor writes the file,
// and leaves any existing one alone, so -no-history is just that path taken
// on purpose rather than a second opt-out mechanism.
func historyFile(disabled bool) string {
	dir, err := os.UserConfigDir()
	if disabled || err != nil {
		return ""
	}
	return filepath.Join(dir, "netdoc", "history")
}

// themeFile is where the TUI's theme choice persists between sessions, under
// the same config-directory policy as the target history. "" is the UI's
// in-memory path: the default theme, and nothing written. It is deliberately
// not tied to -no-history, which is about the targets you type.
func themeFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "netdoc", "theme")
}
