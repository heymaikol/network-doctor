package ui

import (
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// New wires the model and ExitCode reads it back. Toolbox mode with no chain run
// exits 0 through the public surface.
func TestNewAndExitCode(t *testing.T) {
	app := New(nil, true)
	if ExitCode(app) != 0 {
		t.Error("toolbox app with no chain run must ExitCode 0")
	}

	tg, _ := diagnostic.ParseTarget("github.com")
	if New(tg, false) == nil {
		t.Error("New must return a model for a target")
	}
}

// Init returns a non-nil command in both modes (the spinner tick must always run).
func TestInit(t *testing.T) {
	if newModel(nil).Init() == nil {
		t.Error("normal Init must return a cmd")
	}
	tb := newModel(nil)
	tb.toolbox = true
	if tb.Init() == nil {
		t.Error("toolbox Init must still return the spinner tick")
	}
}
