package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/simulation"
)

// The two process seams, faked. Between them they are every namespace this
// tool would create, so a test that swaps both can drive any command to its
// end on a host with no privileges, and can see exactly what each command
// asked the host for.

// stubBackend answers the capability question and builds nothing. A backend
// that reports the host cannot simulate is enough to reach the far side of
// every command: the runner still produces a report, and the caller still
// picks its exit code from it.
type stubBackend struct{ supported bool }

func (b stubBackend) Capabilities(context.Context) simulation.Capabilities {
	return simulation.Capabilities{Backend: "stub", Supported: b.supported,
		Reason: "stub backend: this host cannot simulate"}
}

func (b stubBackend) Prepare(context.Context, *simulation.Scenario, string) (simulation.Env, error) {
	return nil, errors.New("stub backend builds nothing")
}

type backendCall struct {
	dry bool
	log io.Writer
}

type fakeBackends struct {
	supported bool
	calls     []backendCall
}

// stubBackends replaces the backend constructor for the test and records how
// each command asked for one: dry or live, logging or silent.
func stubBackends(t *testing.T, supported bool) *fakeBackends {
	t.Helper()
	f := &fakeBackends{supported: supported}
	old := newBackend
	newBackend = func(dry bool, log io.Writer) simulation.Backend {
		f.calls = append(f.calls, backendCall{dry: dry, log: log})
		return stubBackend{supported: f.supported}
	}
	t.Cleanup(func() { newBackend = old })
	return f
}

type directorCall struct {
	self string
	argv []string
}

// fakeDirectors stands in for re-executing this binary inside fresh
// namespaces: it records the command line the launcher built, writes what the
// real director would have written, and returns a scripted exit.
type fakeDirectors struct {
	calls  []directorCall
	stdout string
	code   int
	err    error
	// stdin records whether the launcher offered the director a terminal. Only
	// Challenge Mode does; every automated command must hand it nil.
	stdin []bool
}

func stubDirectors(t *testing.T, d *fakeDirectors) *fakeDirectors {
	t.Helper()
	old := launchDirector
	launchDirector = func(_ context.Context, self string, argv []string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
		d.calls = append(d.calls, directorCall{self: self, argv: slices.Clone(argv)})
		d.stdin = append(d.stdin, stdin != nil)
		if d.stdout != "" {
			if _, err := io.WriteString(stdout, d.stdout); err != nil {
				return 0, err
			}
		}
		return d.code, d.err
	}
	t.Cleanup(func() { launchDirector = old })
	return d
}

// dispatchCase is one command line a dispatch test expects to be turned away.
type dispatchCase struct {
	name      string
	supported bool
	args      []string
	code      int
	stderr    string // exact, when the whole message is the contract
	stderrHas string
	stdoutHas string
}

func (tt dispatchCase) check(t *testing.T, stdout, stderr *bytes.Buffer) {
	t.Helper()
	if tt.stderr != "" && stderr.String() != tt.stderr {
		t.Errorf("stderr = %q, want %q", stderr.String(), tt.stderr)
	}
	if tt.stderrHas != "" && !strings.Contains(stderr.String(), tt.stderrHas) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.stderrHas)
	}
	if tt.stdoutHas != "" && !strings.Contains(stdout.String(), tt.stdoutHas) {
		t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.stdoutHas)
	}
}

// runRejections is the launcher half's contract: everything a launcher can
// check cheaply, it checks before it asks for a namespace. PATH is emptied so
// only the netdoc dropped in the working directory can ever be found.
func runRejections(t *testing.T, tests []dispatchCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeNetdoc(t)
			t.Setenv("PATH", "")
			stubBackends(t, tt.supported)
			directors := stubDirectors(t, &fakeDirectors{})
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != tt.code {
				t.Errorf("code = %d, want %d (stderr %q)", code, tt.code, stderr.String())
			}
			tt.check(t, &stdout, &stderr)
			if len(directors.calls) != 0 {
				t.Errorf("a rejected command still created namespaces: %+v", directors.calls)
			}
		})
	}
}

// runDirectorRejections is the far half's contract: the namespaces already
// exist, so what a rejected director must not do is build a topology inside
// them or write anything to stdout that a caller could mistake for a report.
func runDirectorRejections(t *testing.T, tests []dispatchCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backends := stubBackends(t, tt.supported)
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != tt.code {
				t.Errorf("code = %d, want %d (stderr %q)", code, tt.code, stderr.String())
			}
			tt.check(t, &stdout, &stderr)
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", stdout.String())
			}
			if len(backends.calls) != 0 {
				t.Errorf("a rejected run still asked for a backend: %+v", backends.calls)
			}
		})
	}
}

func TestRunDispatch(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	scenarios := strings.Join(simulation.LibraryNames(), "\n") + "\n"
	tests := []struct {
		name           string
		args           []string
		code           int
		stdout         string
		stdoutContains string
		stderr         string
	}{
		{name: "no arguments", code: exitUsage, stdoutContains: "Usage: netdoc-sim <command> [arguments]"},
		{name: "unknown command", args: []string{"bogus"}, code: exitUsage,
			stderr: "netdoc-sim: unknown command \"bogus\"\nrun 'netdoc-sim help' for usage\n"},
		{name: "validate missing scenario", args: []string{"validate"}, code: exitUsage,
			stderr: "netdoc-sim: validate takes one scenario\n"},
		{name: "validate extra scenario", args: []string{"validate", "healthy", "healthy"}, code: exitUsage,
			stderr: "netdoc-sim: validate takes one scenario\n"},
		{name: "validate scenario", args: []string{"validate", "healthy"}, code: exitOK,
			stdout: "ok: healthy-network (3 node(s), 0 fault(s), 1 test(s), 6 expected check(s))\n"},
		{name: "inspect missing id", args: []string{"inspect"}, code: exitUsage,
			stderr: "netdoc-sim: inspect takes one simulation id\n"},
		{name: "cleanup all with id", args: []string{"cleanup", "-all", "123"}, code: exitUsage,
			stderr: "netdoc-sim: -all takes no simulation id\n"},
		{name: "scenarios", args: []string{"scenarios"}, code: exitOK, stdout: scenarios},
		{name: "list empty", args: []string{"list"}, code: exitOK,
			stdout: "no simulations are being kept alive\n"},
		{name: "cleanup all empty", args: []string{"cleanup", "-all"}, code: exitOK,
			stdout: "nothing to clean up\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != tt.code {
				t.Errorf("code = %d, want %d", code, tt.code)
			}
			if tt.stdoutContains != "" {
				if !strings.Contains(stdout.String(), tt.stdoutContains) {
					t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.stdoutContains)
				}
			} else if stdout.String() != tt.stdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.stdout)
			}
			if stderr.String() != tt.stderr {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.stderr)
			}
		})
	}
}

// The run launcher deliberately receives the subcommand name and removes it
// before parsing. Pin both the scenario and its trailing flag so another argv
// slice cannot silently shift or drop either one.
func TestRunDispatchKeepsArgvAligned(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "healthy", "-repeat", "0"}, &stdout, &stderr)
	if code != exitUsage || stdout.Len() != 0 || stderr.String() != "netdoc-sim: -repeat must be at least 1\n" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

// netdoc-sim answers for its own build, the way netdoc does. Anything that
// packages the two together, whether a Linux package or the container image, has to be
// able to prove it shipped one release rather than two, and asking each binary
// is the only check that reads the binaries instead of the packaging.
func TestRunDispatchVersion(t *testing.T) {
	for _, arg := range []string{"version", "-version", "--version"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{arg}, &stdout, &stderr); code != exitOK {
			t.Errorf("%s returned %d, stderr = %q", arg, code, stderr.String())
		}
		if got, want := stdout.String(), "netdoc-sim "+version+"\n"; got != want {
			t.Errorf("%s printed %q, want %q", arg, got, want)
		}
	}
}

func TestRunDispatchCapabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"capabilities"}, &stdout, &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"Backend:", "Supported:", "A run will:", "It will not touch the host's interfaces"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want it to contain %q", out, want)
		}
	}
	switch {
	case strings.Contains(out, "Supported: true") && code != exitOK:
		t.Errorf("supported host returned code %d", code)
	case strings.Contains(out, "Supported: false") && code != exitError:
		t.Errorf("unsupported host returned code %d", code)
	case !strings.Contains(out, "Supported: true") && !strings.Contains(out, "Supported: false"):
		t.Errorf("stdout has no supported status: %q", out)
	}
}

// The launcher resolves the netdoc binary in the user's own working directory
// and $PATH, then hands the director a command line built from what it parsed.
// These tests pin that hand-off: the director must receive the resolved
// absolute path and nothing that could override it, with every other flag and
// the scenario reference arriving unchanged.

// A stand-in netdoc has to be a real executable on every OS the tests run on,
// because the challenge launcher now runs it: it resolves the binary and asks
// that binary for its version. A shell script is not that on Windows, and
// building one would need a toolchain mid-test, so the stand-in is a copy of
// this test binary. TestMain turns any copy with a .version file beside it into
// a fake netdoc, and each copy reports the version written next to it, which
// is what lets one test give two binaries two different identities.

const fakeNetdocDefaultVersion = "netdoc v0.0.0-fake"

func TestMain(m *testing.M) {
	if version, ok := fakeNetdocRole(); ok {
		fmt.Println(version)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeNetdocRole reports whether this process was started as a stand-in netdoc,
// and what it should answer. It also appends the argv it was called with to a
// .invoked log beside itself, so a test can prove which of two binaries ran
// rather than inferring it from the version that came back.
//
// os.Args[0], not os.Executable: the question is which path the caller chose to
// execute, and two hard links to one inode are two answers to that.
func fakeNetdocRole() (string, bool) {
	// #nosec G703 -- os.Args[0] is the test executable path selected by this test.
	version, err := os.ReadFile(os.Args[0] + ".version")
	if err != nil {
		return "", false
	}
	// #nosec G703 -- os.Args[0] is the test executable path selected by this test.
	log, err := os.OpenFile(os.Args[0]+".invoked", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		fmt.Fprintln(log, strings.Join(os.Args[1:], " "))
		_ = log.Close()
	}
	return strings.TrimSpace(string(version)), true
}

// writeFakeNetdoc installs a stand-in netdoc in dir that answers -version with
// version, and returns its path. Windows recognizes an executable only by its
// PATHEXT suffix, so the file needs .exe there for a plain "netdoc" to resolve.
func writeFakeNetdoc(t *testing.T, dir, version string) string {
	t.Helper()
	name := "netdoc"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	// Windows cannot remove a hard link to this running test executable, so copy
	// there. Elsewhere, link when the filesystems allow it and copy when not.
	linked := runtime.GOOS != "windows" && os.Link(self, path) == nil
	if !linked {
		// #nosec G304 -- self comes from os.Executable, not external input.
		body, err := os.ReadFile(self)
		if err != nil {
			t.Fatal(err)
		}
		// #nosec G306 G703 -- this test-owned path must be executable as a fake binary.
		if err := os.WriteFile(path, body, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path+".version", []byte(version+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeNetdocInvocations reports the argv slices a stand-in netdoc was executed
// with, newest last, and nil when it was never run at all.
func fakeNetdocInvocations(t *testing.T, path string) []string {
	t.Helper()
	// #nosec G304 -- path is the fake binary this test created.
	log, err := os.ReadFile(path + ".invoked")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(log), "\n"), "\n")
}

// fakeNetdoc drops a stand-in netdoc in a fresh directory and makes it the
// working directory, so a relative -netdoc has something real to resolve.
func fakeNetdoc(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	name := filepath.Base(writeFakeNetdoc(t, dir, fakeNetdocDefaultVersion))
	t.Chdir(dir)
	// t.TempDir can sit behind a symlink; compare against what Abs will produce.
	abs, err := filepath.Abs(name)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// findNetdoc is the whole binary-selection contract, and every result that
// records which netdoc ran depends on it picking the same one the launcher then
// executes. The order is documented in `netdoc-sim help`: -netdoc, else a
// sibling of netdoc-sim, else $PATH.
func TestFindNetdocSearchOrder(t *testing.T) {
	// An unrelated netdoc on $PATH throughout: every case below either has to
	// prefer something else or fail outright, and none may quietly land here.
	pathDir := t.TempDir()
	onPath := writeFakeNetdoc(t, pathDir, "netdoc v0.0.0-on-path")
	t.Setenv("PATH", pathDir)

	siblingDir := t.TempDir()
	sibling := writeFakeNetdoc(t, siblingDir, "netdoc v0.0.0-sibling")
	self := filepath.Join(siblingDir, "netdoc-sim")

	elsewhere := t.TempDir()
	explicit := writeFakeNetdoc(t, elsewhere, "netdoc v0.0.0-explicit")

	t.Run("explicit absolute path wins", func(t *testing.T) {
		got, err := findNetdoc(explicit, self)
		if err != nil || got != explicit {
			t.Fatalf("findNetdoc(%q) = %q, %v", explicit, got, err)
		}
	})

	// A relative -netdoc is resolved against the working directory and returned
	// absolute, because it is forwarded into a re-execution that no longer
	// shares it.
	t.Run("explicit relative path resolves to an absolute one", func(t *testing.T) {
		t.Chdir(elsewhere)
		got, err := findNetdoc("./"+filepath.Base(explicit), self)
		if err != nil {
			t.Fatal(err)
		}
		if !filepath.IsAbs(got) {
			t.Fatalf("findNetdoc returned %q, which is not absolute", got)
		}
		if filepath.Base(got) != filepath.Base(explicit) || filepath.Dir(got) != filepath.Dir(explicit) {
			t.Fatalf("findNetdoc = %q, want %q", got, explicit)
		}
	})

	// A bare name has no directory in it, so it means what it means to a shell:
	// look it up on $PATH. This is why the flag is documented as a path.
	t.Run("explicit bare name is a $PATH lookup", func(t *testing.T) {
		t.Chdir(t.TempDir())
		got, err := findNetdoc(filepath.Base(onPath), self)
		if err != nil || got != onPath {
			t.Fatalf("findNetdoc(%q) = %q, %v, want %q", filepath.Base(onPath), got, err, onPath)
		}
	})

	t.Run("explicit missing path is an error, not a fallback", func(t *testing.T) {
		missing := filepath.Join(elsewhere, "no-such-netdoc")
		got, err := findNetdoc(missing, self)
		if err == nil {
			t.Fatalf("findNetdoc(%q) = %q, want an error rather than some other netdoc", missing, got)
		}
		if !strings.Contains(err.Error(), "-netdoc") {
			t.Errorf("error %q does not name the flag that caused it", err)
		}
	})

	t.Run("a sibling of netdoc-sim beats $PATH", func(t *testing.T) {
		got, err := findNetdoc("", self)
		if err != nil || got != sibling {
			t.Fatalf("findNetdoc(\"\") = %q, %v, want the sibling %q", got, err, sibling)
		}
	})

	t.Run("$PATH is used when there is no sibling", func(t *testing.T) {
		got, err := findNetdoc("", filepath.Join(t.TempDir(), "netdoc-sim"))
		if err != nil || got != onPath {
			t.Fatalf("findNetdoc(\"\") = %q, %v, want the one on $PATH %q", got, err, onPath)
		}
	})

	t.Run("nothing anywhere is an actionable error", func(t *testing.T) {
		t.Setenv("PATH", "")
		got, err := findNetdoc("", filepath.Join(t.TempDir(), "netdoc-sim"))
		if err == nil {
			t.Fatalf("findNetdoc(\"\") = %q, want an error", got)
		}
		for _, want := range []string{"cannot find the netdoc binary", "go build -o netdoc", "-netdoc"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not say %q", err, want)
			}
		}
	})

	// A file merely named netdoc is not a netdoc. Preferring it would shadow a
	// working binary on $PATH and turn a clear "not found" into an exec failure
	// deep inside a namespace.
	t.Run("an unexecutable sibling is skipped", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows takes executability from the PATHEXT suffix, not a mode bit")
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "netdoc"), []byte("not a binary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := findNetdoc("", filepath.Join(dir, "netdoc-sim"))
		if err != nil || got != onPath {
			t.Fatalf("findNetdoc(\"\") = %q, %v, want the one on $PATH %q", got, err, onPath)
		}
	})
}

// The version has to come out of the binary that was selected, not out of the
// checkout or the simulator's own build.
func TestResolveNetdocAsksTheBinaryItSelected(t *testing.T) {
	pathDir := t.TempDir()
	onPath := writeFakeNetdoc(t, pathDir, "netdoc v0.0.0-on-path")
	t.Setenv("PATH", pathDir)
	chosen := writeFakeNetdoc(t, t.TempDir(), "netdoc v9.9.9-chosen")

	got, err := resolveNetdoc(context.Background(), chosen, filepath.Join(t.TempDir(), "netdoc-sim"))
	if err != nil {
		t.Fatal(err)
	}
	if got.path != chosen || got.version != "netdoc v9.9.9-chosen" {
		t.Fatalf("resolveNetdoc = %+v, want %q at %q", got, "netdoc v9.9.9-chosen", chosen)
	}
	if runs := fakeNetdocInvocations(t, chosen); len(runs) != 1 || runs[0] != "-version" {
		t.Errorf("the chosen binary was invoked as %v, want one -version", runs)
	}
	if runs := fakeNetdocInvocations(t, onPath); runs != nil {
		t.Errorf("the binary on $PATH was run %v, and it was never selected", runs)
	}
}

// A binary that answers nothing has no identity, and a challenge recorded
// against it could not be reproduced. Say so instead of recording a blank.
func TestNetdocVersionRejectsASilentBinary(t *testing.T) {
	silent := writeFakeNetdoc(t, t.TempDir(), "")
	if got, err := netdocVersion(context.Background(), silent); err == nil {
		t.Fatalf("netdocVersion = %q, want an error", got)
	} else if !strings.Contains(err.Error(), "printed no version") {
		t.Errorf("error = %q, want it to say the binary printed no version", err)
	}
	missing := filepath.Join(t.TempDir(), "not-a-binary")
	if got, err := netdocVersion(context.Background(), missing); err == nil {
		t.Fatalf("netdocVersion(%q) = %q, want an error", missing, got)
	}
}

func TestHuntDirectorReceivesExactGenerationInputs(t *testing.T) {
	abs := fakeNetdoc(t)
	f := newHuntFlags(io.Discard)
	base, err := f.parse([]string{"dual-stack-healthy", "--seed", "-44", "--cases", "6", "--case", "17",
		"--max-faults", "3", "--generator-version", "v3", "--fail-fast", "--json", "--netdoc", "./netdoc", "--timeout", "7s"})
	if err != nil {
		t.Fatal(err)
	}
	path, err := findNetdoc(*f.netdoc, filepath.Join(t.TempDir(), "netdoc-sim"))
	if err != nil {
		t.Fatal(err)
	}
	argv := huntDirectorArgv(f, base, path)
	got := newHuntFlags(io.Discard)
	gotBase, err := got.parse(argv[1:])
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != huntDirectorCommand || gotBase != base || !got.seed.set || got.seed.v != -44 ||
		*got.cases != 6 || *got.caseNum != 17 || *got.maxFaults != 3 || *got.generator != "v3" || *got.lane != string(simulation.HuntLaneAllOperators) || !*got.failFast || !*got.json ||
		*got.netdoc != abs || *got.timeout != 7*time.Second {
		t.Fatalf("forwarded hunt = argv %v base %q seed %+v", argv, gotBase, got.seed)
	}
}

func TestHuntDirectorReceivesShardSelector(t *testing.T) {
	abs := fakeNetdoc(t)
	f := newHuntFlags(io.Discard)
	base, err := f.parse([]string{"healthy", "--seed", "7", "--cases", "60", "--shard", "2/4",
		"--generator-version", "v3", "--netdoc", "./netdoc"})
	if err != nil {
		t.Fatal(err)
	}
	path, err := findNetdoc(*f.netdoc, filepath.Join(t.TempDir(), "netdoc-sim"))
	if err != nil {
		t.Fatal(err)
	}
	got, gotBase := receivedHunt(t, huntDirectorArgv(f, base, path))
	if gotBase != base || !got.shard.set || got.shard.value != (simulation.HuntShard{Index: 2, Count: 4}) ||
		*got.cases != 60 || got.seed.v != 7 || *got.generator != "v3" || *got.lane != string(simulation.HuntLaneAllOperators) || *got.netdoc != abs {
		t.Fatalf("forwarded shard hunt = base %q flags %+v", gotBase, got)
	}
}

func TestHuntDryRunNeedsNoNetdocOrNamespaces(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"hunt", "healthy-routed-network", "--dry-run", "--json", "--seed", "12345", "--cases", "6"}, &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 {
		t.Fatalf("code = %d stderr = %q", code, stderr.String())
	}
	var result simulation.HuntResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.GeneratedCases != 6 || result.ExecutedCases != 0 || len(result.Cases) != 6 {
		t.Fatalf("result = %+v", result)
	}
	if result.GeneratorVersion != simulation.HuntGeneratorVersion || result.Lane != simulation.HuntLaneBugOracle {
		t.Fatalf("default generator/lane = %q/%q, want %q/%q", result.GeneratorVersion, result.Lane,
			simulation.HuntGeneratorVersion, simulation.HuntLaneBugOracle)
	}
	selected := result.Cases[3].Manifest
	stdout.Reset()
	code = run([]string{"hunt", "healthy-routed-network", "--dry-run", "--json", "--seed", "12345",
		"--case", stringInt(selected.Case)}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("direct code = %d stderr = %q", code, stderr.String())
	}
	var direct simulation.HuntResult
	if err := json.Unmarshal(stdout.Bytes(), &direct); err != nil {
		t.Fatal(err)
	}
	if len(direct.Cases) != 1 || direct.Cases[0].Manifest.CaseFingerprint != selected.CaseFingerprint ||
		direct.Cases[0].Manifest.CaseSeed != selected.CaseSeed {
		t.Fatalf("direct = %+v, selected = %+v", direct.Cases, selected)
	}
}

func TestHuntDryRunReplaysAHistoricalGenerator(t *testing.T) {
	args := []string{"hunt", "healthy-routed-network", "--dry-run", "--json", "--seed", "12345",
		"--case", "76", "--max-faults", "2", "--generator-version", "v3"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	var result simulation.HuntResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.GeneratorVersion != "v3" || result.Lane != simulation.HuntLaneAllOperators || len(result.Cases) != 1 ||
		result.Cases[0].Manifest.GeneratorVersion != "v3" ||
		result.Cases[0].Manifest.CaseFingerprint != "3b23592ff5c01fd9" {
		t.Fatalf("historical result = %+v", result)
	}
}

func TestHuntDryRunRecordsTheRequestedStressLane(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hunt", "healthy-routed-network", "--lane", "stress", "--dry-run", "--json",
		"--seed", "12345", "--cases", "8"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	var result simulation.HuntResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Lane != simulation.HuntLaneStress || len(result.Cases) != 8 {
		t.Fatalf("stress result = %+v", result)
	}
	for _, item := range result.Cases {
		if item.Manifest.Lane != simulation.HuntLaneStress {
			t.Errorf("case %d lane = %q", item.Manifest.Case, item.Manifest.Lane)
		}
	}
}

func stringInt(value int) string { return strconv.Itoa(value) }

func TestHuntUsageBoundsAndBases(t *testing.T) {
	for _, args := range [][]string{
		{"hunt", "broken-dns", "--dry-run", "--seed", "1"},
		{"hunt", "--dry-run", "--seed", "1", "--cases", "501"},
		{"hunt", "--dry-run", "--seed", "1", "--case", "-2"},
		{"hunt", "--dry-run", "--seed", "1", "--max-faults", "4"},
		{"hunt", "--dry-run", "--seed", "1", "--generator-version", "v999"},
		{"hunt", "--dry-run", "--seed", "1", "--lane", "all"},
		{"hunt", "--dry-run", "--seed", "1", "--lane", "invalid"},
		{"hunt", "--dry-run", "--seed", "1", "--generator-version", "v3", "--lane", "stress"},
		{"hunt", "--dry-run", "--seed", "1", "--case", "2", "--shard", "0/2"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != exitUsage {
			t.Errorf("run(%v) = %d, stderr %q", args, code, stderr.String())
		}
	}
}

func TestHuntShardSyntaxIsStrict(t *testing.T) {
	for _, raw := range []string{"1", "a/2", "1/b", "0/0", "-1/2", "2/2", "1/-2", "1/2/3", "1/501", "1/999999999999999999999"} {
		t.Run(strings.ReplaceAll(raw, "/", "_"), func(t *testing.T) {
			f := newHuntFlags(io.Discard)
			if _, err := f.parse([]string{"healthy", "-shard", raw}); err == nil {
				t.Fatalf("-shard %q was accepted", raw)
			}
		})
	}
	f := newHuntFlags(io.Discard)
	if _, err := f.parse([]string{"healthy", "-shard", "0/1"}); err != nil {
		t.Fatalf("valid shard rejected: %v", err)
	}
}

func TestHuntMergeCommandReadsArbitraryFileOrder(t *testing.T) {
	base, err := simulation.LibraryScenario("healthy-routed-network")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var paths []string
	for index := 0; index < 3; index++ {
		shard := simulation.HuntShard{Index: index, Count: 3}
		result := simulation.RunHunt(context.Background(), "healthy-routed-network", base, nil,
			simulation.HuntOptions{Cases: 7, Seed: 12345, MaxFaults: 2, DryRun: true, Shard: &shard})
		path := filepath.Join(dir, fmt.Sprintf("anything-%d.json", index))
		// #nosec G304 -- path is inside t.TempDir.
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := result.WriteJSON(file); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	slices.Reverse(paths)
	args := append([]string{"hunt", "merge"}, paths...)
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	var merged simulation.HuntResult
	if err := json.Unmarshal(stdout.Bytes(), &merged); err != nil {
		t.Fatal(err)
	}
	if err := simulation.ValidateMergedHuntResult(&merged); err != nil {
		t.Fatal(err)
	}
	if merged.Shard != nil || len(merged.Cases) != 7 {
		t.Fatalf("merged result = %+v", merged)
	}
}

func TestHuntMergeCommandRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"result":`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hunt", "merge", path}, &stdout, &stderr); code != exitUsage ||
		!strings.Contains(stderr.String(), "read hunt result") || stdout.Len() != 0 {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

// forward runs the launcher's half: parse the user's argv, resolve the binary,
// build the director's command line.
func forward(t *testing.T, userArgs ...string) []string {
	t.Helper()
	f := newRunFlags(io.Discard)
	ref, err := f.parse(userArgs)
	if err != nil {
		t.Fatalf("parse %v: %v", userArgs, err)
	}
	path, err := findNetdoc(*f.netdoc, filepath.Join(t.TempDir(), "netdoc-sim"))
	if err != nil {
		t.Fatalf("findNetdoc %q: %v", *f.netdoc, err)
	}
	return directorArgv(f, ref, path)
}

// received runs the director's half on what it was handed.
func received(t *testing.T, argv []string) (*runFlags, string) {
	t.Helper()
	if argv[0] != directorCommand {
		t.Fatalf("argv[0] = %q, want %q", argv[0], directorCommand)
	}
	f := newRunFlags(io.Discard)
	ref, err := f.parse(argv[1:])
	if err != nil {
		t.Fatalf("director could not parse %v: %v", argv, err)
	}
	return f, ref
}

// The same for the other two directors: the command line a launcher built is
// only correct if the flag set on the far side reads back what was meant.
func receivedCampaign(t *testing.T, argv []string) (*campaignFlags, string) {
	t.Helper()
	if argv[0] != campaignDirectorCommand {
		t.Fatalf("argv[0] = %q, want %q", argv[0], campaignDirectorCommand)
	}
	f := newCampaignFlags(io.Discard)
	ref, err := f.parse(argv[1:])
	if err != nil {
		t.Fatalf("the campaign director could not parse %v: %v", argv, err)
	}
	return f, ref
}

func receivedHunt(t *testing.T, argv []string) (*huntFlags, string) {
	t.Helper()
	if argv[0] != huntDirectorCommand {
		t.Fatalf("argv[0] = %q, want %q", argv[0], huntDirectorCommand)
	}
	f := newHuntFlags(io.Discard)
	base, err := f.parse(argv[1:])
	if err != nil {
		t.Fatalf("the hunt director could not parse %v: %v", argv, err)
	}
	return f, base
}

func TestRelativeNetdocReachesDirectorResolved(t *testing.T) {
	abs := fakeNetdoc(t)
	f, ref := received(t, forward(t, "healthy", "-netdoc", "./netdoc"))
	if *f.netdoc != abs {
		t.Errorf("director got -netdoc %q, want the resolved %q", *f.netdoc, abs)
	}
	if ref != "healthy" {
		t.Errorf("scenario = %q, want healthy", ref)
	}
}

func TestNetdocEqualsFormReachesDirectorResolved(t *testing.T) {
	abs := fakeNetdoc(t)
	f, _ := received(t, forward(t, "healthy", "-netdoc=./netdoc"))
	if *f.netdoc != abs {
		t.Errorf("director got -netdoc %q, want the resolved %q", *f.netdoc, abs)
	}
	// The double-dash spelling of the same flag, which the flag package accepts.
	f2, _ := received(t, forward(t, "healthy", "--netdoc=./netdoc"))
	if *f2.netdoc != abs {
		t.Errorf("director got --netdoc %q, want the resolved %q", *f2.netdoc, abs)
	}
}

// TestDirectorCannotBeGivenTwoNetdocs is the regression: forwarding the user's
// argv verbatim left a second -netdoc on the line, and the flag package takes
// the last one, so the unresolved spelling won and the launcher's resolution
// was dead code.
func TestDirectorCannotBeGivenTwoNetdocs(t *testing.T) {
	abs := fakeNetdoc(t)
	argv := forward(t, "healthy", "-netdoc", "./netdoc")
	if n := slices.IndexFunc(argv[1:], func(s string) bool { return s == "-netdoc" }); n < 0 {
		t.Fatalf("no -netdoc in %v", argv)
	}
	occurrences := 0
	for _, a := range argv {
		if a == "-netdoc" || a == "--netdoc" || a == "-netdoc="+abs || a == "--netdoc="+abs {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Errorf("-netdoc appears %d times in %v, want exactly 1", occurrences, argv)
	}
	f, _ := received(t, argv)
	if *f.netdoc != abs {
		t.Errorf("director got %q, want %q", *f.netdoc, abs)
	}
}

func TestOtherFlagsAndScenarioSurviveForwarding(t *testing.T) {
	abs := fakeNetdoc(t)
	f, ref := received(t, forward(t,
		"-json", "-keep", "-v", "-timeout", "9s", "-repeat", "3", "./my-scenario.yaml", "-netdoc", "./netdoc"))

	if ref != "./my-scenario.yaml" {
		t.Errorf("scenario = %q, want ./my-scenario.yaml", ref)
	}
	if *f.netdoc != abs {
		t.Errorf("netdoc = %q, want %q", *f.netdoc, abs)
	}
	if !*f.json || !*f.keep || !*f.verbose {
		t.Errorf("json=%t keep=%t v=%t, want all true", *f.json, *f.keep, *f.verbose)
	}
	if *f.dry {
		t.Error("dry-run was not asked for and must not arrive set")
	}
	if *f.timeout != 9*time.Second || *f.repeat != 3 {
		t.Errorf("timeout=%s repeat=%d, want 9s/3", *f.timeout, *f.repeat)
	}
}

// TestDoubleDashIsHandled covers the terminator the flag package honours. A
// scenario after "--" is still a scenario, and the director's own line puts the
// reference behind one so a path beginning with a dash cannot be read as a flag.
func TestDoubleDashIsHandled(t *testing.T) {
	abs := fakeNetdoc(t)
	f, ref := received(t, forward(t, "-netdoc", "./netdoc", "-json", "--", "healthy"))
	if ref != "healthy" || *f.netdoc != abs || !*f.json {
		t.Errorf("ref=%q netdoc=%q json=%t", ref, *f.netdoc, *f.json)
	}

	argv := forward(t, "-netdoc", "./netdoc", "--", "-dash-leading.yaml")
	if argv[len(argv)-2] != "--" {
		t.Errorf("the scenario must be forwarded behind a terminator: %v", argv)
	}
	f2, ref2 := received(t, argv)
	if ref2 != "-dash-leading.yaml" {
		t.Errorf("scenario = %q, want -dash-leading.yaml", ref2)
	}
	if *f2.netdoc != abs {
		t.Errorf("netdoc = %q, want %q", *f2.netdoc, abs)
	}
}

func TestCampaignDirectorReceivesExactSeedAndIteration(t *testing.T) {
	abs := fakeNetdoc(t)
	f := newCampaignFlags(io.Discard)
	ref, err := f.parse([]string{"unstable-connectivity", "--seed", "0", "--runs", "5", "--iteration", "37", "--fail-fast", "--json", "--netdoc", "./netdoc"})
	if err != nil {
		t.Fatal(err)
	}
	path, err := findNetdoc(*f.netdoc, filepath.Join(t.TempDir(), "netdoc-sim"))
	if err != nil {
		t.Fatal(err)
	}
	argv := campaignDirectorArgv(f, ref, path)
	got := newCampaignFlags(io.Discard)
	gotRef, err := got.parse(argv[1:])
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != campaignDirectorCommand || gotRef != ref || !got.seed.set || got.seed.v != 0 ||
		*got.runs != 5 || *got.iteration != 37 || !*got.failFast || !*got.json || *got.netdoc != abs {
		t.Fatalf("forwarded campaign = argv %v ref %q seed %+v runs %d iteration %d", argv, gotRef, got.seed, *got.runs, *got.iteration)
	}
}

// --- run, from inside the namespaces -----------------------------------

// The director is the half that runs inside the namespaces the launcher
// created, so it must never create more of them, and the scenario it runs is
// the one already on its command line.
func TestDirectRunsInsideTheNamespacesItWasGiven(t *testing.T) {
	backends := stubBackends(t, false)
	directors := stubDirectors(t, &fakeDirectors{code: exitOK})
	var stdout, stderr bytes.Buffer
	code := run([]string{directorCommand, "-netdoc", "/bin/true", "-timeout", "9s", "-repeat", "2",
		"-json=false", "-keep=false", "-dry-run=false", "-v=true", "--", "healthy"}, &stdout, &stderr)

	if len(directors.calls) != 0 {
		t.Fatalf("the director launched another director: %+v", directors.calls)
	}
	if len(backends.calls) != 1 {
		t.Fatalf("backends = %+v, want exactly one", backends.calls)
	}
	// The backend refused, so the report is an error report and the exit code
	// comes from it, not from the parse.
	if code != exitError {
		t.Errorf("code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stdout.String(), "healthy-network") {
		t.Errorf("stdout = %q, want the report for the scenario it was handed", stdout.String())
	}
}

// -json swaps the whole report for the machine-readable one, on stdout.
func TestDirectWritesTheJSONReportWhenAsked(t *testing.T) {
	stubBackends(t, false)
	stubDirectors(t, &fakeDirectors{})
	var stdout, stderr bytes.Buffer
	if code := run([]string{directorCommand, "-json", "--", "healthy"}, &stdout, &stderr); code != exitError {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	var report simulation.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not a report: %v (%q)", err, stdout.String())
	}
	if report.Scenario != "healthy-network" || report.Result != simulation.ResultError ||
		!strings.Contains(report.Error, "stub backend") {
		t.Fatalf("report = %+v", report)
	}
}

// Which backend a run asks for is decided entirely by two flags, and a run
// that logs nothing must be given nowhere to log to.
func TestDirectAsksForTheBackendItsFlagsDescribe(t *testing.T) {
	for _, tt := range []struct {
		name    string
		args    []string
		dry     bool
		logging bool
	}{
		{name: "plain", args: []string{directorCommand, "--", "healthy"}},
		{name: "verbose", args: []string{directorCommand, "-v", "--", "healthy"}, logging: true},
		{name: "dry run", args: []string{directorCommand, "-dry-run", "--", "healthy"}, dry: true, logging: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			backends := stubBackends(t, true)
			var stdout, stderr bytes.Buffer
			run(tt.args, &stdout, &stderr)
			if len(backends.calls) != 1 {
				t.Fatalf("backends = %+v, want exactly one", backends.calls)
			}
			if backends.calls[0].dry != tt.dry {
				t.Errorf("dry = %t, want %t", backends.calls[0].dry, tt.dry)
			}
			want := io.Writer(nil)
			if tt.logging {
				want = &stderr
			}
			if backends.calls[0].log != want {
				t.Errorf("command log = %#v, want %#v", backends.calls[0].log, want)
			}
		})
	}
}

// -dry-run announces what a run would do and stops: no report on stdout, and
// even with -keep, nothing held open afterwards. Which commands the
// announcement lists is the backend's business, and the backend's own tests.
func TestDirectDryRunAnnouncesTheRunAndHoldsNothing(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	stubBackends(t, true)
	var stdout, stderr bytes.Buffer
	code := run([]string{directorCommand, "-dry-run", "-keep", "--", "healthy"}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("code = %d, want %d: a dry run cannot fail a diagnosis", code, exitOK)
	}
	if stdout.Len() != 0 {
		t.Errorf("a dry run wrote a report: %q", stdout.String())
	}
	if !strings.HasPrefix(stderr.String(), "would run, inside a user namespace owning nothing on this host:\n") {
		t.Errorf("stderr = %q, want the dry-run preamble first", stderr.String())
	}
	// -keep is neutralised by -dry-run: hold never ran, so there is no record.
	if entries, err := os.ReadDir(simulation.StateDir()); err == nil && len(entries) != 0 {
		t.Errorf("a dry run left %d kept-simulation record(s)", len(entries))
	}
	if strings.Contains(stdout.String()+stderr.String(), "is still up") {
		t.Error("a dry run held the simulation open")
	}
}

// -keep is what turns a finished run into a simulation the user can walk
// around inside, and the record it leaves has to describe the run that just
// happened. direct is called here rather than run so the hold has a context
// the test owns; nothing else about the path changes.
func TestDirectHoldsTheRunItJustReportedWhenKeepIsSet(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	stubBackends(t, false)
	ctx, cancel := holdContext(t)
	defer cancel()

	var held *simulation.State
	var stderr bytes.Buffer
	w := &holdWriter{marker: "Release it with", at: func() {
		states, err := simulation.ListStates()
		if err != nil {
			t.Errorf("ListStates: %v", err)
		}
		if len(states) != 1 {
			t.Errorf("%d simulations are being kept alive, want 1", len(states))
		} else {
			held = states[0]
		}
		cancel()
	}}
	if code := direct(ctx, []string{"--", "healthy"}, w, &stderr); code != exitError {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitError, stderr.String())
	}
	if strings.Contains(w.out.String(), "is still up") {
		t.Fatal("a run without -keep held the simulation open")
	}

	w = &holdWriter{marker: "Release it with", at: w.at}
	if code := direct(ctx, []string{"-keep", "--", "healthy"}, w, &stderr); code != exitError {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitError, stderr.String())
	}
	if held == nil {
		t.Fatal("-keep recorded nothing")
	}
	if held.Scenario != "healthy-network" {
		t.Errorf("record = %+v, want the scenario the report described", held)
	}
	// The report and the invitation to enter the simulation go to the same
	// place, in that order.
	if !strings.Contains(w.out.String(), "healthy-network") ||
		!strings.Contains(w.out.String(), "Simulation "+held.ID+" is still up.") {
		t.Errorf("output = %q", w.out.String())
	}
}

// The dispatcher hands direct the arguments after the subcommand, and direct
// parses all of them. A slice that shifted by one would turn the first flag
// into the scenario, or the command name into one.
func TestDirectDispatchRejects(t *testing.T) {
	runDirectorRejections(t, []dispatchCase{
		{name: "no scenario", args: []string{directorCommand}, code: exitUsage,
			stderr: "netdoc-sim: a scenario is required\n"},
		{name: "bad flag value", args: []string{directorCommand, "-repeat", "0", "--", "healthy"},
			code: exitUsage, stderr: "netdoc-sim: -repeat must be at least 1\n"},
		{name: "non-positive timeout", args: []string{directorCommand, "-timeout", "0s", "--", "healthy"},
			code: exitUsage, stderr: "netdoc-sim: -timeout must be positive\n"},
		// -timeout is spelled onto the spawned netdoc's command line, so the
		// precision netdoc accepts is the precision this accepts. Refusing here
		// is the difference between one usage error and a run of child processes
		// that all exit 2 for a reason nothing up here reported.
		{name: "sub-millisecond timeout", args: []string{directorCommand, "-timeout", "500us", "--", "healthy"},
			code: exitUsage, stderr: "netdoc-sim: -timeout must be a whole number of milliseconds, not 500\u00b5s\n"},
		{name: "fractional millisecond timeout", args: []string{directorCommand, "-timeout", "1.9ms", "--", "healthy"},
			code: exitUsage, stderrHas: "whole number of milliseconds"},
		{name: "two scenarios", args: []string{directorCommand, "healthy", "healthy"}, code: exitUsage,
			stderr: "netdoc-sim: unexpected argument \"healthy\"\n"},
		{name: "unknown scenario", args: []string{directorCommand, "--", "no-such-scenario"},
			code: exitUsage, stderrHas: "no-such-scenario"},
	})
}

// --- hold ---------------------------------------------------------------

// holdWriter cancels the hold the instant hold has finished announcing the
// simulation, and runs a check at exactly that point. Nothing here waits on a
// clock: the write happens on hold's own goroutine, so the state the check
// sees is the state hold is holding.
type holdWriter struct {
	out    bytes.Buffer
	marker string
	at     func()
}

func (w *holdWriter) Write(p []byte) (int, error) {
	n, err := w.out.Write(p)
	if w.at != nil && strings.Contains(string(p), w.marker) {
		at := w.at
		w.at = nil
		at()
	}
	return n, err
}

// holdContext is what releases the hold, plus a deadline that exists only so
// that a marker which stops matching fails the test instead of hanging it
// until the whole package times out. A working hold never reaches it: the
// cancel fires on hold's own goroutine, before the deadline can matter.
func holdContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func heldReport(workspace string) *simulation.Report {
	return &simulation.Report{
		ID: "abcdef0123456789", Scenario: "healthy-network",
		StartedAt: time.Date(2026, 8, 8, 19, 15, 45, 0, time.UTC),
		Topology: []simulation.NodeInfo{
			{Name: "client", Address: "10.77.0.10/24", PID: 4242},
			{Name: "server", Address: "10.77.0.20/24", PID: 4343},
		},
		Cleanup: simulation.CleanupInfo{Workspace: workspace},
	}
}

// The record hold leaves is the one `list`, `inspect` and `cleanup` read, and
// it must not outlive the namespaces: it exists for exactly as long as the
// hold does, and the workspace goes with it.
func TestHoldPublishesTheRecordThenSweepsIt(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "topology.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := heldReport(work)
	ctx, cancel := holdContext(t)
	defer cancel()

	var held *simulation.State
	w := &holdWriter{marker: "Release it with", at: func() {
		var err error
		if held, err = simulation.LoadState(report.ID); err != nil {
			t.Errorf("nothing to list or inspect while the simulation is held: %v", err)
		}
		if _, err := os.Stat(work); err != nil {
			t.Errorf("the workspace went before the hold ended: %v", err)
		}
		cancel()
	}}
	hold(ctx, report, w)

	want := "\nSimulation abcdef0123456789 is still up. Enter a node with:\n" +
		"  nsenter -t 4242 -n -m -- sh   # client (10.77.0.10/24)\n" +
		"  nsenter -t 4343 -n -m -- sh   # server (10.77.0.20/24)\n" +
		"Release it with `netdoc-sim cleanup abcdef0123456789`, or press Ctrl-C here.\n"
	if w.out.String() != want {
		t.Errorf("output = %q, want %q", w.out.String(), want)
	}
	if held == nil {
		t.Fatal("no record was published")
	}
	if held.Scenario != report.Scenario || held.Workspace != work || held.PID != os.Getpid() ||
		!held.Started.Equal(report.StartedAt) {
		t.Errorf("record = %+v", held)
	}
	if len(held.Nodes) != 2 || held.Nodes[0].PID != 4242 || held.Nodes[1].Name != "server" {
		t.Errorf("record nodes = %+v, want the topology the report described", held.Nodes)
	}
	// The hold is over: the namespaces are gone, so the record and the
	// workspace must be too.
	if _, err := os.Stat(filepath.Join(simulation.StateDir(), report.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record outlived the hold: %v", err)
	}
	if _, err := os.Stat(work); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the workspace outlived the hold: %v", err)
	}
}

// A record that cannot be written is said out loud rather than swallowed,
// and the simulation is still held, because that is what the user asked for.
func TestHoldSaysSoWhenItCannotRecordTheSimulation(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", blocked)
	work := t.TempDir()
	ctx, cancel := holdContext(t)
	defer cancel()
	w := &holdWriter{marker: "Release it with", at: cancel}
	hold(ctx, heldReport(work), w)

	if !strings.HasPrefix(w.out.String(), "netdoc-sim: cannot record this simulation:") {
		t.Errorf("output = %q, want the failure reported first", w.out.String())
	}
	if !strings.Contains(w.out.String(), "nsenter -t 4242 -n -m -- sh   # client (10.77.0.10/24)") {
		t.Errorf("output = %q, want the simulation held anyway", w.out.String())
	}
	// Whether the sweep of an unwritable state directory then reports a
	// failure of its own is the OS's call, so it is not asserted here, but
	// the workspace is this process's to remove either way.
	if _, err := os.Stat(work); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the workspace outlived the hold: %v", err)
	}
}

func TestHoldDoesNotSweepARecordItFailedToPublish(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	report := heldReport(t.TempDir())
	original := simulation.NewState(report.ID, "pre-existing", t.TempDir(), report.StartedAt.Add(-time.Hour), nil)
	if err := original.Save(); err != nil {
		t.Fatal(err)
	}
	before, err := simulation.LoadState(report.ID)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := holdContext(t)
	defer cancel()
	w := &holdWriter{marker: "Release it with", at: cancel}
	hold(ctx, report, w)

	if !strings.Contains(w.out.String(), "netdoc-sim: cannot record this simulation:") {
		t.Errorf("output = %q, want publication failure", w.out.String())
	}
	after, err := simulation.LoadState(report.ID)
	if err != nil {
		t.Fatalf("pre-existing record was removed: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Errorf("pre-existing record changed:\n got %+v\nwant %+v", after, before)
	}
	if _, err := os.Stat(report.Cleanup.Workspace); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the run-owned workspace outlived the hold: %v", err)
	}
}

// --- run, the launcher --------------------------------------------------

// self is what the launcher must re-execute: this very binary.
func self(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// The launcher's whole job is to hand one director one command line and pass
// its exit code straight back.
func TestLaunchHandsTheDirectorTheCommandLineAndItsExitCode(t *testing.T) {
	abs := fakeNetdoc(t)
	stubBackends(t, true)
	directors := stubDirectors(t, &fakeDirectors{code: exitMismatch})
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "healthy", "-netdoc", "./netdoc", "-json", "-repeat", "3", "-timeout", "9s"},
		&stdout, &stderr)

	if code != exitMismatch {
		t.Fatalf("code = %d, want the director's %d, stderr %q", code, exitMismatch, stderr.String())
	}
	if len(directors.calls) != 1 {
		t.Fatalf("directors = %+v, want exactly one", directors.calls)
	}
	if directors.calls[0].self != self(t) {
		t.Errorf("re-executed %q, want this binary %q", directors.calls[0].self, self(t))
	}
	f, ref := received(t, directors.calls[0].argv)
	if ref != "healthy" || *f.netdoc != abs || !*f.json || *f.repeat != 3 || *f.timeout != 9*time.Second {
		t.Errorf("director got ref %q netdoc %q json %t repeat %d timeout %s",
			ref, *f.netdoc, *f.json, *f.repeat, *f.timeout)
	}
}

// A director that could not be started at all is a simulator failure, not a
// diagnosis: whichever launcher asked for it, the exit code says so and the
// reason reaches the user rather than being reported as a clean run.
func TestLaunchersReportADirectorTheyCannotStart(t *testing.T) {
	for _, args := range [][]string{
		{"run", "healthy", "-netdoc", "./netdoc"},
		{"campaign", "unstable-connectivity", "-netdoc", "./netdoc"},
		{"hunt", "-netdoc", "./netdoc", "-seed", "1"},
	} {
		t.Run(args[0], func(t *testing.T) {
			fakeNetdoc(t)
			stubBackends(t, true)
			stubDirectors(t, &fakeDirectors{code: 1, err: errors.New("namespaces unavailable")})
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != exitError || !strings.Contains(stderr.String(), "namespaces unavailable") {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
		})
	}
}

// Everything the launcher can check cheaply, it checks before it creates a
// namespace. None of these may reach a director.
func TestLaunchStopsBeforeTheDirector(t *testing.T) {
	runRejections(t, []dispatchCase{
		{name: "no scenario", supported: true, args: []string{"run"}, code: exitUsage,
			stderrHas: "netdoc-sim: a scenario is required"},
		{name: "help", supported: true, args: []string{"run", "-h"}, code: exitOK,
			stdoutHas: "Usage: netdoc-sim <command> [arguments]"},
		{name: "unknown scenario", supported: true, args: []string{"run", "no-such-scenario"},
			code: exitUsage, stderrHas: "no-such-scenario"},
		{name: "host cannot simulate", supported: false, args: []string{"run", "healthy", "-netdoc", "./netdoc"},
			code: exitError, stderrHas: "stub backend: this host cannot simulate"},
		{name: "no netdoc anywhere", supported: true, args: []string{"run", "healthy"}, code: exitUsage,
			stderrHas: "cannot find the netdoc binary"},
		{name: "netdoc path is wrong", supported: true, args: []string{"run", "healthy", "-netdoc", "./absent"},
			code: exitUsage, stderrHas: "-netdoc ./absent"},
	})
}

// --- campaign -----------------------------------------------------------

// The seed is chosen out here, once, so the report can print one number that
// reproduces the whole campaign. The director is handed that number, never the
// job of picking its own.
func TestCampaignLaunchChoosesTheSeedTheDirectorRunsWith(t *testing.T) {
	abs := fakeNetdoc(t)
	stubBackends(t, true)
	directors := stubDirectors(t, &fakeDirectors{code: exitOK})
	var stdout, stderr bytes.Buffer
	args := []string{"campaign", "unstable-connectivity", "-netdoc", "./netdoc", "-runs", "4", "-fail-fast"}
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if len(directors.calls) != 2 {
		t.Fatalf("directors = %+v, want two", directors.calls)
	}
	seeds := make([]int64, 2)
	for i, call := range directors.calls {
		if call.self != self(t) {
			t.Errorf("re-executed %q, want %q", call.self, self(t))
		}
		f, ref := receivedCampaign(t, call.argv)
		if ref != "unstable-connectivity" || *f.netdoc != abs || *f.runs != 4 || !*f.failFast {
			t.Errorf("director got ref %q netdoc %q runs %d fail-fast %t", ref, *f.netdoc, *f.runs, *f.failFast)
		}
		if !f.seed.set {
			t.Fatal("the director was left to choose its own seed")
		}
		seeds[i] = f.seed.v
	}
	// A dropped RandomSeed leaves the zero value behind on every run. Two
	// drawn seeds collide with probability 2^-64.
	if seeds[0] == seeds[1] {
		t.Errorf("both campaigns were seeded %d; the seed is not being drawn", seeds[0])
	}
}

// An explicit seed is forwarded untouched, and the director's exit is the
// launcher's exit.
func TestCampaignLaunchForwardsAnExplicitSeed(t *testing.T) {
	fakeNetdoc(t)
	stubBackends(t, true)
	directors := stubDirectors(t, &fakeDirectors{code: exitMismatch})
	var stdout, stderr bytes.Buffer
	code := run([]string{"campaign", "unstable-connectivity", "-netdoc", "./netdoc", "-seed", "-99",
		"-iteration", "12", "-json"}, &stdout, &stderr)
	if code != exitMismatch {
		t.Fatalf("code = %d, want the director's %d, stderr %q", code, exitMismatch, stderr.String())
	}
	f, _ := receivedCampaign(t, directors.calls[0].argv)
	if !f.seed.set || f.seed.v != -99 || *f.iteration != 12 || !*f.json {
		t.Fatalf("director got seed %+v iteration %d json %t", f.seed, *f.iteration, *f.json)
	}
}

func TestCampaignLaunchStopsBeforeTheDirector(t *testing.T) {
	runRejections(t, []dispatchCase{
		{name: "no scenario", supported: true, args: []string{"campaign"}, code: exitUsage,
			stderrHas: "netdoc-sim: a campaign scenario is required"},
		{name: "help", supported: true, args: []string{"campaign", "-h"}, code: exitOK,
			stdoutHas: "Usage: netdoc-sim <command> [arguments]"},
		{name: "unknown scenario", supported: true, args: []string{"campaign", "no-such-scenario"},
			code: exitUsage, stderrHas: "no-such-scenario"},
		{name: "scenario has no campaign", supported: true, args: []string{"campaign", "healthy"},
			code: exitUsage, stderrHas: "netdoc-sim: scenario has no campaign definition"},
		{name: "bad run count", supported: true, args: []string{"campaign", "unstable-connectivity", "-runs", "1001"},
			code: exitUsage, stderrHas: "-runs must be between 1 and 1000"},
		{name: "host cannot simulate", supported: false,
			args: []string{"campaign", "unstable-connectivity", "-netdoc", "./netdoc"},
			code: exitError, stderrHas: "stub backend: this host cannot simulate"},
		{name: "no netdoc anywhere", supported: true, args: []string{"campaign", "unstable-connectivity"},
			code: exitUsage, stderrHas: "cannot find the netdoc binary"},
	})
}

// The campaign director runs the iterations it was told to, at the seed it was
// told to. -iteration is a pointer on the far side: dropping the conversion
// would silently run iterations 0..n-1 instead of the one asked for.
func TestCampaignDirectorRunsTheSeededIterationItWasGiven(t *testing.T) {
	backends := stubBackends(t, false)
	directors := stubDirectors(t, &fakeDirectors{})
	var stdout, stderr bytes.Buffer
	code := run([]string{campaignDirectorCommand, "-json", "-v", "-seed", "1234", "-runs", "2", "-iteration", "7",
		"--", "unstable-connectivity"}, &stdout, &stderr)

	if len(directors.calls) != 0 {
		t.Fatalf("the campaign director launched another director: %+v", directors.calls)
	}
	// Every iteration gets its own backend, and -v points all of them at
	// stderr so the log cannot land in the middle of the report.
	if len(backends.calls) != 2 {
		t.Fatalf("backends = %+v, want one per run", backends.calls)
	}
	for _, call := range backends.calls {
		if call.dry || call.log != io.Writer(&stderr) {
			t.Errorf("backend = %+v, want a live one logging to stderr", call)
		}
	}
	if code != exitError {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitError, stderr.String())
	}
	var result simulation.CampaignResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not a campaign result: %v (%q)", err, stdout.String())
	}
	if result.Seed != 1234 {
		t.Errorf("seed = %d, want the 1234 it was handed", result.Seed)
	}
	if len(result.Outcomes) != 2 {
		t.Fatalf("outcomes = %+v, want -runs 2 of them", result.Outcomes)
	}
	for _, outcome := range result.Outcomes {
		if outcome.Iteration != 7 {
			t.Errorf("ran iteration %d, want the 7 it was handed", outcome.Iteration)
		}
	}
}

// Without -iteration every run is its own iteration, and the text report is
// what a human gets.
func TestCampaignDirectorWritesTheTextReportByDefault(t *testing.T) {
	stubBackends(t, false)
	var stdout, stderr bytes.Buffer
	code := run([]string{campaignDirectorCommand, "-seed", "5", "-runs", "2", "--", "unstable-connectivity"},
		&stdout, &stderr)
	if code != exitError {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitError, stderr.String())
	}
	if json.Valid(bytes.TrimSpace(stdout.Bytes())) {
		t.Errorf("stdout = %q, want the text report", stdout.String())
	}
	if !strings.Contains(stdout.String(), "unstable-connectivity") {
		t.Errorf("stdout = %q, want the scenario named", stdout.String())
	}
}

// The seed is the launcher's to choose. A director that reached the far side
// without one cannot reproduce anything, and says so instead of guessing.
func TestCampaignDirectorRefusesWithoutASeed(t *testing.T) {
	backends := stubBackends(t, false)
	var stdout, stderr bytes.Buffer
	code := run([]string{campaignDirectorCommand, "--", "unstable-connectivity"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("code = %d, want %d", code, exitError)
	}
	if stderr.String() != "netdoc-sim: internal campaign director did not receive a seed\n" {
		t.Errorf("stderr = %q", stderr.String())
	}
	if stdout.Len() != 0 || len(backends.calls) != 0 {
		t.Errorf("stdout = %q, backends = %+v", stdout.String(), backends.calls)
	}
}

func TestCampaignDirectorRejects(t *testing.T) {
	runDirectorRejections(t, []dispatchCase{
		{name: "no scenario", args: []string{campaignDirectorCommand, "-seed", "1"}, code: exitUsage,
			stderrHas: "netdoc-sim: a campaign scenario is required"},
		{name: "unknown scenario", args: []string{campaignDirectorCommand, "-seed", "1", "--", "no-such-scenario"},
			code: exitUsage, stderrHas: "no-such-scenario"},
	})
}

// --- hunt, the launcher -------------------------------------------------

// Like the campaign, a hunt's seed is drawn once out here so one number
// reproduces the whole run, and the director is handed it.
func TestHuntLaunchChoosesTheSeedTheDirectorRunsWith(t *testing.T) {
	abs := fakeNetdoc(t)
	stubBackends(t, true)
	directors := stubDirectors(t, &fakeDirectors{code: exitMismatch})
	var stdout, stderr bytes.Buffer
	args := []string{"hunt", "dual-stack-healthy", "-netdoc", "./netdoc", "-cases", "6", "-max-faults", "3"}
	for range 2 {
		if code := run(args, &stdout, &stderr); code != exitMismatch {
			t.Fatalf("code = %d, want the director's %d, stderr %q", code, exitMismatch, stderr.String())
		}
	}
	if len(directors.calls) != 2 {
		t.Fatalf("directors = %+v, want two", directors.calls)
	}
	seeds := make([]int64, 2)
	for i, call := range directors.calls {
		if call.self != self(t) {
			t.Fatalf("re-executed %q, want %q", call.self, self(t))
		}
		f, base := receivedHunt(t, call.argv)
		if base != "dual-stack-healthy" || *f.netdoc != abs || *f.cases != 6 || *f.maxFaults != 3 ||
			*f.generator != simulation.HuntGeneratorVersion || *f.lane != string(simulation.HuntLaneBugOracle) {
			t.Errorf("hunt got base %q netdoc %q cases %d max-faults %d", base, *f.netdoc, *f.cases, *f.maxFaults)
		}
		if !f.seed.set {
			t.Fatal("the director was left to choose its own seed")
		}
		seeds[i] = f.seed.v
	}
	if seeds[0] == seeds[1] {
		t.Errorf("both hunts were seeded %d; the seed is not being drawn", seeds[0])
	}
}

// A dry run needs neither a netdoc binary nor a director: it generates the
// manifests here and prints them.
func TestHuntLaunchDryRunNeedsNoDirector(t *testing.T) {
	t.Setenv("PATH", "")
	stubBackends(t, false)
	directors := stubDirectors(t, &fakeDirectors{})
	var stdout, stderr bytes.Buffer
	code := run([]string{"hunt", "-dry-run", "-cases", "2"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitOK, stderr.String())
	}
	if len(directors.calls) != 0 {
		t.Errorf("a dry hunt created namespaces: %+v", directors.calls)
	}
	// No -json, so this is the text report, and it has to name the seed it
	// drew or the run cannot be reproduced.
	if json.Valid(bytes.TrimSpace(stdout.Bytes())) || !strings.Contains(stdout.String(), "Seed:") ||
		!strings.Contains(stdout.String(), "Generated: 2 unique case(s)") {
		t.Errorf("stdout = %q, want the text report naming its seed", stdout.String())
	}
}

func TestHuntLaunchStopsBeforeTheDirector(t *testing.T) {
	runRejections(t, []dispatchCase{
		{name: "help", supported: true, args: []string{"hunt", "-h"}, code: exitOK,
			stdoutHas: "Usage: netdoc-sim <command> [arguments]"},
		{name: "unsupported base", supported: true, args: []string{"hunt", "broken-dns"}, code: exitUsage,
			stderrHas: "unsupported hunt base"},
		{name: "unsupported generator", supported: true, args: []string{"hunt", "--generator-version", "v999"}, code: exitUsage,
			stderrHas: "-generator-version must be one of"},
		{name: "host cannot simulate", supported: false, args: []string{"hunt", "-netdoc", "./netdoc"},
			code: exitError, stderrHas: "stub backend: this host cannot simulate"},
		{name: "no netdoc anywhere", supported: true, args: []string{"hunt"}, code: exitUsage,
			stderrHas: "cannot find the netdoc binary"},
	})
}

// --- hunt, from inside the namespaces -----------------------------------

func TestHuntDirectorRunsTheCasesItWasGiven(t *testing.T) {
	backends := stubBackends(t, false)
	directors := stubDirectors(t, &fakeDirectors{})
	var stdout, stderr bytes.Buffer
	code := run([]string{huntDirectorCommand, "-json", "-v", "-seed", "99", "-cases", "2", "-max-faults", "1", "-generator-version", "v3",
		"--", "healthy-routed-network"}, &stdout, &stderr)

	if len(directors.calls) != 0 {
		t.Fatalf("the hunt director launched another director: %+v", directors.calls)
	}
	if len(backends.calls) == 0 {
		t.Fatal("the hunt asked for no backend at all")
	}
	for _, call := range backends.calls {
		if call.dry || call.log != io.Writer(&stderr) {
			t.Errorf("backend = %+v, want a live one logging to stderr under -v", call)
		}
	}
	if code != exitError {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitError, stderr.String())
	}
	var result simulation.HuntResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not a hunt result: %v (%q)", err, stdout.String())
	}
	if result.HuntSeed != 99 || result.BaseScenario != "healthy-routed-network" || result.RequestedCases != 2 ||
		result.GeneratorVersion != "v3" || result.Lane != simulation.HuntLaneAllOperators {
		t.Fatalf("result = %+v", result)
	}
	// The director is the executing half: unlike the launcher's -dry-run, it
	// really tries to build every case.
	if result.ExecutedCases == 0 {
		t.Errorf("executed %d cases, want the hunt to have tried", result.ExecutedCases)
	}
}

// Without -json the hunt writes the text report, and an unrunnable hunt is a
// simulator failure rather than a finding.
func TestHuntDirectorWritesTheTextReportByDefault(t *testing.T) {
	stubBackends(t, false)
	var stdout, stderr bytes.Buffer
	code := run([]string{huntDirectorCommand, "-seed", "1", "-cases", "1", "--", "healthy-routed-network"},
		&stdout, &stderr)
	if code != exitError {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitError, stderr.String())
	}
	if json.Valid(bytes.TrimSpace(stdout.Bytes())) || stdout.Len() == 0 {
		t.Errorf("stdout = %q, want the text report", stdout.String())
	}
}

func TestHuntDirectorRefusesWithoutASeed(t *testing.T) {
	backends := stubBackends(t, false)
	var stdout, stderr bytes.Buffer
	code := run([]string{huntDirectorCommand, "--", "healthy-routed-network"}, &stdout, &stderr)
	if code != exitError || stderr.String() != "netdoc-sim: internal hunt director did not receive a seed\n" {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 || len(backends.calls) != 0 {
		t.Errorf("stdout = %q, backends = %+v", stdout.String(), backends.calls)
	}
}

func TestHuntDirectorRejectsBadArguments(t *testing.T) {
	runDirectorRejections(t, []dispatchCase{
		{name: "cases out of range",
			args: []string{huntDirectorCommand, "-seed", "1", "-cases", "0", "--", "healthy-routed-network"},
			code: exitUsage, stderrHas: "-cases must be between 1 and"},
		{name: "unknown generator",
			args: []string{huntDirectorCommand, "-seed", "1", "-generator-version", "v999", "--", "healthy-routed-network"},
			code: exitUsage, stderrHas: "-generator-version must be one of"},
	})
}
