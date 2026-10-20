// Toolbox mode: the exit code.

package ui

import (
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// Toolbox mode with no chain run exits 0.
func TestToolboxExitZero(t *testing.T) {
	m := newModel(nil, true)
	if ExitCode(m) != 0 {
		t.Error("toolbox mode, no chain run, must exit 0")
	}
	// Once the chain runs and a probe fails, normal rules apply.
	m.started[diagnostic.ProbeIface] = true
	for _, probe := range m.probes {
		m.results[probe.ID] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	}
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{Status: diagnostic.StatusFail}
	if ExitCode(m) != 1 {
		t.Error("toolbox mode after a failed chain must exit 1")
	}
}
