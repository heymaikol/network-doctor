//go:build netns_integration

package simulation

import (
	"context"
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

var netnsExecutedScenarios sync.Map

func noteNetnsScenarioExecution(name string, reports ...*Report) {
	if !slices.Contains(LibraryNames(), name) {
		return
	}
	for _, report := range reports {
		if report != nil && len(report.Tests) > 0 {
			netnsExecutedScenarios.Store(name, struct{}{})
			return
		}
	}
}

func noteNetnsCampaignExecution(name string, result *CampaignResult) {
	for _, outcome := range result.Outcomes {
		noteNetnsScenarioExecution(name, outcome.Report)
	}
}

func missingNetnsScenarioExecutions(library, executed []string) []string {
	seen := make(map[string]bool, len(executed))
	for _, name := range executed {
		seen[name] = true
	}
	var missing []string
	for _, name := range library {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

func executedNetnsScenarios() []string {
	var names []string
	netnsExecutedScenarios.Range(func(key, _ any) bool {
		names = append(names, key.(string))
		return true
	})
	return names
}

func TestMissingNetnsScenarioExecutions(t *testing.T) {
	executed := LibraryNames()
	library := append(slices.Clone(executed), "future-z", "future-a")
	got := missingNetnsScenarioExecutions(
		library,
		append(executed, executed[0], "not-in-library"),
	)
	want := []string{"future-a", "future-z"}
	if !slices.Equal(got, want) {
		t.Fatalf("missing scenarios = %v, want %v", got, want)
	}
}

// TestMain checks execution after the complete suite because library scenarios
// are spread across scenario, campaign, and hunt tests. Filtered runs are
// intentionally partial and cannot establish full-suite coverage.
func TestMain(m *testing.M) {
	// A test that re-executes this binary as its own director makes the
	// backend spawn node holders from it too, the way netdoc-sim does.
	if len(os.Args) == 3 && os.Args[1] == NodeCommand {
		if err := RunNode(context.Background(), os.Args[2], os.Stdin, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, "node:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	code := m.Run()
	if code != 0 || testFlagSet("run") || testFlagSet("skip") ||
		!DefaultBackend(false, nil).Capabilities(context.Background()).Supported {
		os.Exit(code)
	}
	if missing := missingNetnsScenarioExecutions(LibraryNames(), executedNetnsScenarios()); len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "netns integration did not execute library scenarios: %s\n", strings.Join(missing, ", "))
		code = 1
	}
	os.Exit(code)
}

func testFlagSet(name string) bool {
	f := flag.Lookup("test." + name)
	return f != nil && f.Value.String() != ""
}
