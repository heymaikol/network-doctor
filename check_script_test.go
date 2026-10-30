package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
// exception: --help and unknown options are checked by executing it, which is
// safe because the parser prints and exits before the first check step.
// Running the script bare from a test would recurse, because its own
// `go test ./...` step runs this file.
//
// scripts/check is the compatibility wrapper older callers still invoke. Its
// forwarding is tested against a stub check.sh, for the same reason.

const (
	checkScript  = "scripts/check.sh"
	checkWrapper = "scripts/check"
)

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
	// The documented invocation is `./scripts/check.sh`, and older callers use
	// `./scripts/check`, so both need the execute bit in the committed tree.
	// The filesystem mode cannot be asserted here: a Windows checkout does not
	// carry it. git's index does, so ask git.
	for _, path := range []string{checkScript, checkWrapper} {
		// #nosec G204 -- path comes from the fixed list on the line above.
		out, err := exec.Command("git", "ls-files", "--stage", "--", path).Output()
		if err != nil {
			t.Skipf("git unavailable, or this is not a checkout: %v", err)
		}
		fields := strings.Fields(string(out))
		if len(fields) == 0 {
			t.Fatalf("%s is not tracked by git", path)
		}
		if fields[0] != "100755" {
			t.Errorf("%s is committed as mode %s, want 100755: ./%s would not be "+
				"directly executable for a contributor who just cloned",
				path, fields[0], path)
		}
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
	for _, want := range []string{"./scripts/check.sh", "--race", "--help"} {
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

// runSh runs script under sh from dir. The script path is made absolute so dir
// can be a directory the script does not live in; ToSlash keeps it usable by
// the Git Bash sh on Windows.
func runSh(t *testing.T, dir, script string, env []string, args ...string) (out string, code int) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("no POSIX shell on this machine: %v", err)
	}
	abs, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- script is a path this test built, args are literals.
	cmd := exec.Command("sh", append([]string{filepath.ToSlash(abs)}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	b, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatalf("run %s: %v", script, err)
	}
	return string(b), code
}

// copyScripts copies the committed scripts into a scratch repository layout and
// returns the scripts directory. Running the copies rather than the originals
// means a wrapper that stops forwarding its arguments runs check.sh bare in a
// directory with no repository, which fails fast, instead of recursing into
// this test through the real gate's `go test ./...`.
func copyScripts(t *testing.T, names ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "scripts")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		// #nosec G304 -- name comes from literals in this file's calls.
		body, err := os.ReadFile(filepath.Join("scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		// #nosec G703 -- dir is inside t.TempDir and name is a literal.
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCheckScriptAndWrapperAgreeFromAnotherDirectory(t *testing.T) {
	// --help and an unknown option both exit before the script changes into the
	// repository root, so the committed scripts can be run from a directory
	// that is neither their own nor the repository. The wrapper has to find
	// check.sh from its own path, not from the working directory, and must not
	// add or lose a byte of output or change the exit status.
	scripts := copyScripts(t, "check", "check.sh")
	elsewhere := t.TempDir()
	for _, tc := range []struct {
		name     string
		args     []string
		wantCode int
		wantText string
	}{
		{"help", []string{"--help"}, 0, "./scripts/check.sh --race"},
		{"short help", []string{"-h"}, 0, "./scripts/check.sh --race"},
		{"unknown option", []string{"--bogus"}, 2, "check.sh: unknown option --bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			direct, directCode := runSh(t, elsewhere, filepath.Join(scripts, "check.sh"), nil, tc.args...)
			wrapped, wrappedCode := runSh(t, elsewhere, filepath.Join(scripts, "check"), nil, tc.args...)
			if directCode != tc.wantCode || wrappedCode != tc.wantCode {
				t.Errorf("exit codes: check.sh=%d, check=%d, want %d\n%s\n%s",
					directCode, wrappedCode, tc.wantCode, direct, wrapped)
			}
			if !strings.Contains(direct, tc.wantText) {
				t.Errorf("check.sh %v output lacks %q:\n%s", tc.args, tc.wantText, direct)
			}
			if wrapped != direct {
				t.Errorf("check output differs from check.sh:\n%s\n--- vs ---\n%s", wrapped, direct)
			}
		})
	}
}

func TestCheckWrapperForwardsArgumentsAndExitStatus(t *testing.T) {
	// Copy the committed wrapper next to a stub check.sh that echoes each
	// argument on its own line and exits with a chosen status. That proves the
	// forwarding without running the real gate, which would recurse.
	scripts := copyScripts(t, "check")
	stub := "for arg in \"$@\"; do printf '[%s]\\n' \"$arg\"; done\nexit \"$STUB_EXIT\"\n"
	if err := os.WriteFile(filepath.Join(scripts, "check.sh"), []byte(stub), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		exit string
		want string
		code int
	}{
		{"race passes and succeeds", []string{"--race"}, "0", "[--race]\n", 0},
		{"awkward arguments survive", []string{"--race", "a b", ""}, "7", "[--race]\n[a b]\n[]\n", 7},
		{"no arguments", nil, "3", "", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runSh(t, t.TempDir(), filepath.Join(scripts, "check"),
				[]string{"STUB_EXIT=" + tc.exit}, tc.args...)
			if out != tc.want || code != tc.code {
				t.Errorf("got exit %d and %q, want exit %d and %q", code, out, tc.code, tc.want)
			}
		})
	}
}

func TestCheckScriptChangesIntoTheRepositoryRoot(t *testing.T) {
	// The checks run against the repository, not the caller's directory. That
	// is what lets ./scripts/check.sh work from anywhere, and it cannot be
	// proved by running the script, so pin the line that does it.
	if !strings.Contains(readCheckScriptCode(t), `cd "$(dirname "$0")/.."`) {
		t.Errorf("%s no longer changes into the repository root before its checks", checkScript)
	}
}
