package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The fast contributor gate is a shell script, so nothing the Go build does
// would notice it rotting. These tests pin the parts that would rot silently:
// its committed executable mode, the checks it is documented to run, the ones
// it is documented to leave to CI, that --race stays opt-in, that --help still
// describes the options the parser accepts, and that CI runs the script.
//
// They assert on the script's content rather than running it, with one
// exception: --help is checked by executing it, which is safe because usage()
// prints and exits before the first check step. Running the script bare from a
// test would recurse, because its own `go test ./...` step runs this file.

const checkScript = "scripts/check"

func readCheckScript(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(checkScript)
	if err != nil {
		t.Fatalf("read %s: %v", checkScript, err)
	}
	return string(body)
}

// readCheckScriptCode returns the script with comment lines and the usage()
// here-document removed, so an assertion that a command is absent is not
// satisfied or defeated by prose. The script explains what it leaves to CI by
// naming those tools, in both places, and a naive substring search over the
// whole file reads that explanation as a call.
func readCheckScriptCode(t *testing.T) string {
	t.Helper()
	var code strings.Builder
	inUsage := false
	for _, line := range strings.Split(readCheckScript(t), "\n") {
		trimmed := strings.TrimSpace(line)
		// The usage() here-document is prose for the same reason a comment
		// is: it names the tools the script leaves to CI in order to explain
		// the split, and a substring search would read those names as calls.
		if strings.HasPrefix(trimmed, "cat <<") {
			inUsage = true
			continue
		}
		if inUsage {
			if trimmed == "EOF" {
				inUsage = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	return code.String()
}

func TestCheckScriptIsCommittedExecutable(t *testing.T) {
	// The documented invocation is `./scripts/check`, which needs the execute
	// bit in the committed tree. The filesystem mode cannot be asserted here:
	// a Windows checkout does not carry it. git's index does, so ask git.
	out, err := exec.Command("git", "ls-files", "--stage", "--", checkScript).Output()
	if err != nil {
		t.Skipf("git unavailable, or this is not a checkout: %v", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatalf("%s is not tracked by git", checkScript)
	}
	if fields[0] != "100755" {
		t.Errorf("%s is committed as mode %s, want 100755: ./%s would not be "+
			"directly executable for a contributor who just cloned",
			checkScript, fields[0], checkScript)
	}
}

func TestCheckScriptRunsTheFastChecksItDocuments(t *testing.T) {
	script := readCheckScriptCode(t)
	for _, want := range []string{
		"gofmt -l",
		"go vet ./...",
		"CGO_ENABLED=0 go build ./...",
		"GOOS=darwin go build ./...",
		"GOOS=windows go build ./...",
		"GOOS=freebsd go build ./...",
		"go test ./...",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("%s no longer runs %q", checkScript, want)
		}
	}
}

func TestCheckScriptTakesTheGofmtFileListFromGit(t *testing.T) {
	// gofmt walks every directory that does not start with "." or "_", so a
	// bare `gofmt -l .` also reports node_modules and the vendor/ tree a local
	// goreleaser run leaves behind: untracked third-party sources that
	// `go build ./...` and golangci-lint both skip. That failed the gate on
	// code no contributor can fix, so the file list comes from git.
	script := readCheckScriptCode(t)
	if !strings.Contains(script, "git ls-files") {
		t.Errorf("%s no longer takes the gofmt file list from git, so it can "+
			"fail on untracked vendor/ or node_modules/ sources", checkScript)
	}
}

func TestCheckScriptRunsTheOptionalModesItDocuments(t *testing.T) {
	// --race and the help aliases are part of the documented command, and the
	// test above would stay green if any of them were dropped: they are not
	// among the checks it runs by default.
	script := readCheckScriptCode(t)
	for _, want := range []string{
		"--race) race=1",
		"go test -race ./...",
		"-h | --help)",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("%s no longer handles %q", checkScript, want)
		}
	}
}

func TestCheckScriptKeepsTheRaceDetectorOptIn(t *testing.T) {
	// The point of the fast check is that it is fast, and -race roughly
	// doubles it. Asserting only that `go test -race ./...` appears somewhere
	// stays green if it is promoted into the default path, so pin that it
	// sits inside the `if [ "$race" -eq 1 ]` guard and nowhere else.
	script := readCheckScriptCode(t)
	const guard = `if [ "$race" -eq 1 ]; then`
	beforeGuard, afterGuard, ok := strings.Cut(script, guard)
	if !ok {
		t.Fatalf("%s no longer guards the race step with %q", checkScript, guard)
	}
	guarded, _, ok := strings.Cut(afterGuard, "\nfi")
	if !ok {
		t.Fatalf("%s: the %q block is never closed", checkScript, guard)
	}
	if !strings.Contains(guarded, "go test -race ./...") {
		t.Errorf("%s no longer runs the race detector inside the --race guard", checkScript)
	}
	if strings.Contains(beforeGuard, "go test -race") {
		t.Errorf("%s runs the race detector before the --race guard, so it is "+
			"no longer opt-in and the fast check is no longer fast", checkScript)
	}
}

func TestCheckScriptUsageMatchesTheOptionsItAccepts(t *testing.T) {
	// Assert on what --help actually prints rather than on a slice of the
	// file, so adding a header line cannot change the help text without
	// this test noticing, and an option cannot be added to the parser
	// without reaching the usage text.
	//
	// Running --help does not recurse the way running the script bare would:
	// usage() prints and exits before the first check step.
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("no POSIX shell on this machine: %v", err)
	}
	out, err := exec.Command("sh", checkScript, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("%s --help: %v\n%s", checkScript, err, out)
	}
	help := string(out)
	for _, want := range []string{"./scripts/check", "--race", "--help"} {
		if !strings.Contains(help, want) {
			t.Errorf("the usage text printed by --help does not mention %q:\n%s", want, help)
		}
	}
	// The network caveat is what a contributor on a cold module cache is
	// most likely to be bitten by, so it has to survive a header edit too.
	if !strings.Contains(help, "Network:") {
		t.Errorf("--help no longer says when the Go toolchain needs the network:\n%s", help)
	}
}

func TestContributingStatesWhatTheCheckScriptNeedsToRun(t *testing.T) {
	// The script is #!/bin/sh, so a Go toolchain alone is not enough on
	// Windows. Saying otherwise sends a contributor looking for a bug in
	// their setup.
	body, err := os.ReadFile("CONTRIBUTING.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(body)
	if !strings.Contains(doc, "POSIX shell") {
		t.Error("CONTRIBUTING.md does not say the script needs a POSIX shell")
	}
	if strings.Contains(doc, "it behaves the same on Linux, macOS and Windows") {
		t.Error("CONTRIBUTING.md claims the script runs the same everywhere; " +
			"a Windows contributor needs Git Bash or WSL to run /bin/sh")
	}
}

func TestCheckScriptLeavesTheExpensiveGateToCI(t *testing.T) {
	// The value of a fast check is that it is fast. If one of these ever moves
	// into it, that should be a deliberate edit to this list rather than a
	// contributor quietly discovering the script now takes ten minutes.
	script := readCheckScriptCode(t)
	for _, unwanted := range []string{
		"-tags integration",
		"-tags netns_integration",
		"-tags acceptance",
		"-tags container",
		"-fuzz=",
		"golangci-lint",
		"govulncheck",
		"goreleaser",
	} {
		if strings.Contains(script, unwanted) {
			t.Errorf("%s runs %q, which belongs in CI: it is slow, "+
				"platform-specific, or needs the network", checkScript, unwanted)
		}
	}
}

func TestCheckScriptNeedsNoPrivileges(t *testing.T) {
	script := readCheckScriptCode(t)
	for _, unwanted := range []string{"sudo", "sysctl", "docker ", "podman "} {
		if strings.Contains(script, unwanted) {
			t.Errorf("%s uses %q; the fast check must run unprivileged and "+
				"without a container runtime", checkScript, unwanted)
		}
	}
}

func TestContinuousIntegrationRunsTheCheckScript(t *testing.T) {
	// Without this the script is documentation that compiles nothing: it could
	// break and no contributor would find out until they ran it.
	workflow, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	if !strings.Contains(string(workflow), "./"+checkScript) {
		t.Fatalf("ci.yml does not run ./%s, so it can rot unnoticed", checkScript)
	}
}

func TestContributingAndREADMEPointAtTheCheckScript(t *testing.T) {
	for _, doc := range []string{"CONTRIBUTING.md", "README.md"} {
		// #nosec G304 -- doc comes from the fixed list on the line above.
		body, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		if !strings.Contains(string(body), checkScript) {
			t.Errorf("%s does not mention %s", doc, checkScript)
		}
	}
}
