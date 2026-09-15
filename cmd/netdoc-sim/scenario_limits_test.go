package main

// The scenario resource budget, at the command line. The library owns the
// limits themselves; what these prove is the boundary: the director refuses an
// over-budget scenario with a usage error, before it has asked for a backend,
// which is what every namespace, interface, route and listener is created
// behind.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// overBudgetScenario is a scenario whose only problem is its size: 65 nodes,
// one past the supported maximum, each of them otherwise valid.
func overBudgetScenario() string {
	var b strings.Builder
	b.WriteString("name: over-budget\ntopology:\n  nodes:\n")
	b.WriteString("    - {name: n0, role: client, address: 10.77.0.10, gateway: 10.77.0.1}\n")
	for i := 1; i < 65; i++ {
		fmt.Fprintf(&b, "    - {name: n%d, address: 10.77.0.%d}\n", i, 10+i)
	}
	b.WriteString("tests:\n  - {node: n0, target: example.test:80}\nexpect:\n  verdict: ok\n")
	return b.String()
}

// oversizedScenarioFile is a scenario that would run if it were smaller. The
// padding is comment lines, so size is the only thing left to object to.
func oversizedScenarioFile() string {
	var b strings.Builder
	b.WriteString("name: oversized\ntopology:\n  nodes:\n")
	b.WriteString("    - {name: client, role: client, address: 10.77.0.10}\n")
	b.WriteString("tests:\n  - {node: client, target: example.test:80}\nexpect:\n  verdict: ok\n")
	padding := strings.Repeat("#", 120) + "\n"
	for b.Len() <= 1<<20 {
		b.WriteString(padding)
	}
	return b.String()
}

func TestDirectRejectsAnOverBudgetScenarioBeforeAskingForABackend(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct {
		name      string
		yaml      string
		stderrHas string
	}{
		{"too many nodes", overBudgetScenario(), "topology.nodes: 65 entries, supported maximum is 64"},
		{"too large", oversizedScenarioFile(), "exceeds the supported maximum of 1048576 bytes"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			backends := stubBackends(t, true)
			var stdout, stderr bytes.Buffer
			if code := run([]string{directorCommand, "--", path}, &stdout, &stderr); code != exitUsage {
				t.Errorf("code = %d, want %d (stderr %q)", code, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.stderrHas) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.stderrHas)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", stdout.String())
			}
			if len(backends.calls) != 0 {
				t.Errorf("an over-budget scenario still asked for a backend: %+v", backends.calls)
			}
		})
	}
}
