// The go install entrypoint: go install
// github.com/heymaikol/network-doctor/v2/cmd/netdoc@latest must put a binary
// named netdoc on the PATH, and that binary must be this CLI, not a second
// implementation. The name follows from the last element of the import path,
// so the test builds the package the same way go install would and checks
// the executable it produces.

package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/app"
)

func TestCmdNetdocBuildsTheSameCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "netdoc")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// #nosec G204 -- bin is this test's own temporary output path.
	build := exec.Command("go", "build", "-o", bin, "./cmd/netdoc")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/netdoc: %v\n%s", err, out)
	}

	// The exact version depends on the checkout: a tagged one stamps a
	// pseudo-version into a go build binary, a plain clone says "dev". What
	// must hold is the name and the shape.
	// #nosec G204 -- bin is this test's own built binary.
	versionOut, err := exec.Command(bin, "--version").Output()
	if err != nil {
		t.Fatalf("%s --version: %v", bin, err)
	}
	if !strings.HasPrefix(string(versionOut), "netdoc ") || !strings.HasSuffix(string(versionOut), "\n") ||
		strings.TrimSuffix(strings.TrimPrefix(string(versionOut), "netdoc "), "\n") == "" {
		t.Errorf("--version = %q, want \"netdoc <version>\\n\"", versionOut)
	}

	var wantHelp bytes.Buffer
	if code := app.Run(version, []string{"--help"}, &wantHelp, &bytes.Buffer{}); code != 0 {
		t.Fatalf("app.Run(--help) = %d, want 0", code)
	}
	// #nosec G204 -- bin is this test's own built binary.
	helpOut, err := exec.Command(bin, "--help").Output()
	if err != nil {
		t.Fatalf("%s --help: %v", bin, err)
	}
	if !bytes.Equal(helpOut, wantHelp.Bytes()) {
		t.Errorf("--help output differs from the root CLI:\n%s\nwant:\n%s", helpOut, wantHelp.Bytes())
	}
	if !strings.HasPrefix(wantHelp.String(), "Usage: netdoc ") {
		t.Errorf("usage no longer introduces the CLI as netdoc:\n%s", wantHelp.String())
	}
}
