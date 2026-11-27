//go:build integration && unix

package sshverify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Match exec in the configuration runs when OpenSSH reads the configuration. The route read refuses
// such a route, and it must not read the configuration a second time, which would run the command
// again. The command appends one line to a file each time it runs, so the file counts the runs.
func TestRouteReadRunsAMatchExecOnlyOnce(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	counter := filepath.Join(l.dir, "exec-count")
	cfg := filepath.Join(l.dir, "ssh_config_match_exec")
	body := l.baseConfig(l.known, "") + "Match exec \"echo run >> '" + counter + "'\"\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	route, err := ReadRoute(context.Background(), oshTool(t, "ssh"), []string{"-G", "-F", cfg, "--", "127.0.0.1"})
	if err != nil {
		t.Fatalf("route read: %v", err)
	}
	if route.Kind != RouteUnknown {
		t.Fatalf("route kind = %v (%s), want unknown for a Match exec", route.Kind, route.Reason)
	}
	runs := 0
	if b, err := os.ReadFile(counter); err == nil { // #nosec G304 -- a counter file this test wrote in its own directory
		runs = strings.Count(string(b), "run")
	}
	if runs != 1 {
		t.Fatalf("the configuration's Match exec ran %d time(s) in one route read, want 1", runs)
	}
}
