package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeCredentialProbe installs a fake command that answers token-present when
// any GitHub credential variable is set, and token-absent otherwise. It never
// prints a value, only which answer applies.
func writeCredentialProbe(t *testing.T, dir, name string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake command is a POSIX shell script")
	}
	script := "#!/bin/sh\n" +
		`if [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}${GH_ENTERPRISE_TOKEN:-}${GITHUB_ENTERPRISE_TOKEN:-}" ]; then` + "\n" +
		"  echo token-present\nelse\n  echo token-absent\nfi\n"
	path := filepath.Join(dir, name)
	// #nosec G306 -- this test-owned fake command must be executable.
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// The launcher keeps its GitHub credential. realGH runs gh from the launcher,
// and authorized issue creation authenticates through that call.
func TestRealGHKeepsItsCredential(t *testing.T) {
	dir := t.TempDir()
	writeCredentialProbe(t, dir, "gh")
	t.Setenv("PATH", dir)
	t.Setenv("GH_TOKEN", "dummy-gh-token")
	out, err := realGH(context.Background(), "issue", "list")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "token-present" {
		t.Errorf("gh answered %q, want its credential present", got)
	}
}

// netdocVersion runs the binary under test from the launcher. That binary is
// a simulator child and must not inherit the launcher's GitHub credential.
func TestNetdocVersionDoesNotReceiveGitHubToken(t *testing.T) {
	bin := writeCredentialProbe(t, t.TempDir(), "netdoc")
	t.Setenv("GH_TOKEN", "dummy-gh-token")
	got, err := netdocVersion(context.Background(), bin)
	if err != nil {
		t.Fatal(err)
	}
	if got != "token-absent" {
		t.Errorf("netdoc answered %q, want no GitHub credential", got)
	}
}
