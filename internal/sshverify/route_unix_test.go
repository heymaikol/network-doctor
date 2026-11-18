//go:build unix

package sshverify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A configuration that changes between the two reads of one route read is unknown,
// because the two reads did not see the same configuration. The fake client rewrites
// its file on the second run, the way a file changed mid-read would look.
func TestRouteReadTwiceAndChangedIsUnknown(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(cfg, []byte("Host *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	counter := filepath.Join(dir, "runs")
	script := "#!/bin/sh\n" +
		"if [ ! -e \"" + counter + "\" ]; then echo 1 > \"" + counter + "\"; else printf 'Host changed\\n' > \"" + cfg + "\"; fi\n" +
		"echo \"debug1: Reading configuration data " + cfg + "\" >&2\n" +
		"echo \"hostname 127.0.0.1\"\n"
	client := filepath.Join(dir, "ssh")
	if err := os.WriteFile(client, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable fake client on purpose
		t.Fatal(err)
	}
	useFakeClient(t, client, 10*time.Second)

	route, err := ReadRoute(context.Background(), client, []string{"-G", "--", "host"})
	if err != nil {
		t.Fatalf("the read failed: %v", err)
	}
	if route.Kind != RouteUnknown || !strings.Contains(route.Reason, "changed while netdoc read it") {
		t.Fatalf("a configuration changed between the reads gave %s (%q); want unknown", route.Kind, route.Reason)
	}
}

// The positive control: a configuration that does not change between the reads is
// read as direct.
func TestRouteReadTwiceAndStableIsDirect(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(cfg, []byte("Host *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"echo \"debug1: Reading configuration data " + cfg + "\" >&2\n" +
		"echo \"canonicalizehostname false\"\n" +
		"echo \"hostname 127.0.0.1\"\n"
	client := filepath.Join(dir, "ssh")
	if err := os.WriteFile(client, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable fake client on purpose
		t.Fatal(err)
	}
	useFakeClient(t, client, 10*time.Second)

	route, err := ReadRoute(context.Background(), client, []string{"-G", "--", "host"})
	if err != nil {
		t.Fatalf("the read failed: %v", err)
	}
	if route.Kind != RouteDirect {
		t.Fatalf("a stable configuration gave %s (%q); want direct", route.Kind, route.Reason)
	}
}
