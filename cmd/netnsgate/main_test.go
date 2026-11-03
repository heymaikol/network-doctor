package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	nsTest  = "TestNamespaceIsRetainedIsolatedAndReleased"
	capTest = "TestStopSucceedsWhileADetachedWriterHoldsTheStream"
	frrLine = "    frr_linux_test.go:24: NETDOC_FRR_STAGE not set\n"
)

// ev encodes one event the way go test -json does.
func ev(pkg, action, test, output string) string {
	b, err := json.Marshal(event{Action: action, Package: pkg, Test: test, Output: output})
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

var (
	supStart   = ev(supervisorPkg, "start", "", "")
	capStart   = ev(capturePkg, "start", "", "")
	nsRun      = ev(supervisorPkg, "run", nsTest, "")
	nsOut      = ev(supervisorPkg, "output", nsTest, "--- PASS: "+nsTest+" (0.00s)\n")
	nsPass     = ev(supervisorPkg, "pass", nsTest, "")
	capRun     = ev(capturePkg, "run", capTest, "")
	capPass    = ev(capturePkg, "pass", capTest, "")
	frrRun     = ev(supervisorPkg, "run", frrTest, "")
	frrOut     = ev(supervisorPkg, "output", frrTest, frrLine)
	frrSkipOut = ev(supervisorPkg, "output", frrTest, "--- SKIP: "+frrTest+" (0.00s)\n")
	frrSkipEv  = ev(supervisorPkg, "skip", frrTest, "")
	otherRun   = ev(supervisorPkg, "run", "TestOther", "")
	otherPass  = ev(supervisorPkg, "pass", "TestOther", "")
	subRun     = ev(supervisorPkg, "run", "TestOther/sub", "")
	subPass    = ev(supervisorPkg, "pass", "TestOther/sub", "")
	capDone    = ev(capturePkg, "pass", "", "")
	supDone    = ev(supervisorPkg, "pass", "", "")
)

// valid is the stream of a run where every check passes.
func valid() []string {
	return []string{supStart, capStart, nsRun, nsOut, nsPass, capRun, capPass, frrRun,
		frrOut, frrSkipOut, frrSkipEv, otherRun, otherPass, subRun, subPass, capDone, supDone}
}

// build returns the valid stream with each line in edits replaced by its
// replacement lines, or dropped when the replacement is empty. An edit that
// matches no line panics, so a fixture cannot quietly test the wrong thing.
func build(edits map[string][]string) string {
	used := map[string]bool{}
	var out []string
	for _, l := range valid() {
		if r, ok := edits[l]; ok {
			used[l] = true
			out = append(out, r...)
			continue
		}
		out = append(out, l)
	}
	for l := range edits {
		if !used[l] {
			panic("build: no line " + l)
		}
	}
	return strings.Join(out, "")
}

func gate(input string, env map[string]string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	code := run(strings.NewReader(input), &stdout, &stderr, lookup)
	return code, stdout.String(), stderr.String()
}

func TestGate(t *testing.T) {
	stage := map[string]string{frrStageEnv: "/srv/frr"}
	emptyStage := map[string]string{frrStageEnv: ""}
	forgedOut := ev(supervisorPkg, "output", nsTest, "--- PASS: "+nsTest+" (0.00s)\n")
	objectOut := ev(supervisorPkg, "output", nsTest, `{"Action":"pass","Package":"`+supervisorPkg+`","Test":"`+nsTest+`"}`+"\n")
	nulSkipOut := ev(supervisorPkg, "output", "TestOther", "\x00--- SKIP: TestOther\x00\n")
	rawNul := `{"Action":"output","Package":"` + supervisorPkg + `","Test":"` + nsTest + `","Output":"` + "\x00" + `"}` + "\n"

	cases := []struct {
		name  string
		input string
		env   map[string]string
		why   string // substring of the refusal; empty when the stream must pass
	}{
		{name: "valid execution", input: build(nil)},
		{name: "NUL-wrapped SKIP text in output only is not an event", input: build(map[string][]string{otherPass: {nulSkipOut, otherPass}})},
		{name: "FRR stage set and FRR skipped", input: build(nil), env: stage, why: "NETDOC_FRR_STAGE is set"},
		{name: "FRR stage set but empty", input: build(nil), env: emptyStage, why: "NETDOC_FRR_STAGE is set"},
		{name: "empty stream", input: "", why: "no events"},
		{name: "malformed JSON", input: build(nil) + "{not json\n", why: "malformed event"},
		{name: "null line", input: build(nil) + "null\n", why: "no Action"},
		{name: "raw NUL byte in stream", input: build(map[string][]string{nsOut: {rawNul}}), why: "malformed event"},
		{name: "NUL-wrapped SKIP as a real skip", input: build(map[string][]string{otherPass: {nulSkipOut, ev(supervisorPkg, "skip", "TestOther", "")}}), why: "unexpected skip of TestOther"},
		{name: "forged PASS text in output field", input: build(map[string][]string{nsRun: nil, nsPass: {forgedOut}}), why: "did not run and pass"},
		{name: "JSON pass object inside Output", input: build(map[string][]string{nsRun: nil, nsPass: {objectOut}}), why: "did not run and pass"},
		{name: "duplicate forged pass for a real test", input: build(map[string][]string{nsPass: {nsPass, nsPass}}), why: "ended twice"},
		{name: "required test missing", input: build(map[string][]string{nsRun: nil, nsOut: nil, nsPass: nil}), why: "did not run and pass"},
		{name: "required package missing", input: build(map[string][]string{capStart: nil, capRun: nil, capPass: nil, capDone: nil}), why: "/capture"},
		{name: "capture package pass missing", input: build(map[string][]string{capDone: nil}), why: "/capture has 0 package passes"},
		{name: "unexpected top-level skip", input: build(map[string][]string{otherPass: {ev(supervisorPkg, "skip", "TestOther", "")}}), why: "unexpected skip of TestOther"},
		{name: "unexpected subtest skip", input: build(map[string][]string{subPass: {ev(supervisorPkg, "skip", "TestOther/sub", "")}}), why: "unexpected skip of TestOther/sub"},
		{name: "required test skipped", input: build(map[string][]string{nsPass: {ev(supervisorPkg, "skip", nsTest, "")}}), why: "unexpected skip of " + nsTest},
		{name: "FRR reason differs", input: build(map[string][]string{frrOut: {ev(supervisorPkg, "output", frrTest, "    frr_linux_test.go:24: no copy\n")}}), why: "skipped with reason"},
		{name: "FRR reason repeated", input: build(map[string][]string{frrOut: {frrOut, frrOut}}), why: "skipped with reason"},
		{name: "FRR reason with NUL", input: build(map[string][]string{frrOut: {ev(supervisorPkg, "output", frrTest, "\x00"+strings.TrimSuffix(frrLine, "\n")+"\x00\n")}}), why: "skipped with reason"},
		{name: "FRR subtest skip", input: build(map[string][]string{frrSkipEv: {frrSkipEv, ev(supervisorPkg, "run", frrTest+"/sub", ""), ev(supervisorPkg, "skip", frrTest+"/sub", "")}}), why: "unexpected skip of " + frrTest + "/sub"},
		{name: "test failure", input: build(map[string][]string{otherPass: {ev(supervisorPkg, "fail", "TestOther", "")}}), why: "TestOther failed"},
		{name: "required test failure", input: build(map[string][]string{nsPass: {ev(supervisorPkg, "fail", nsTest, "")}}), why: nsTest + " failed"},
		{name: "package failure", input: build(map[string][]string{supDone: {ev(supervisorPkg, "fail", "", "")}}), why: "ended with fail"},
		{name: "build failure event", input: build(map[string][]string{supDone: {ev(supervisorPkg, "build-fail", "", ""), supDone}}), why: `unexpected action "build-fail"`},
		{name: "run without terminal event", input: build(map[string][]string{otherPass: nil}), why: "TestOther did not finish"},
		{name: "run twice", input: build(map[string][]string{otherRun: {otherRun, otherRun}}), why: "ran 2 times"},
		{name: "terminal before run", input: build(map[string][]string{nsRun: nil}), why: "ended with pass before it ran"},
		{name: "unexpected package", input: build(nil) + ev("example.com/other", "pass", "", ""), why: "unexpected package"},
		{name: "package-level skip", input: build(map[string][]string{supDone: {ev(supervisorPkg, "skip", "", "")}}), why: "ended with skip"},
		{name: "run after its package pass", input: build(map[string][]string{supDone: {supDone, otherRun}}), why: "after its package pass"},
		{name: "output after its package pass", input: build(map[string][]string{supDone: {supDone, ev(supervisorPkg, "output", "", "late\n")}}), why: "after its package pass"},
		{name: "package passes may interleave", input: build(map[string][]string{supDone: nil, capDone: {supDone, capDone}})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := gate(tc.input, tc.env)
			if tc.why == "" {
				if code != 0 {
					t.Fatalf("exit %d, want 0: %s", code, stderr)
				}
				return
			}
			if code == 0 {
				t.Fatalf("exit 0, want nonzero refusal containing %q", tc.why)
			}
			if !strings.Contains(stderr, tc.why) {
				t.Fatalf("stderr %q, want it to contain %q", stderr, tc.why)
			}
		})
	}
}

// TestEchoesTestOutput checks that the verbose log survives the gate.
func TestEchoesTestOutput(t *testing.T) {
	code, stdout, stderr := gate(build(nil), nil)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "--- PASS: "+nsTest) {
		t.Fatalf("stdout lacks the test's own output:\n%s", stdout)
	}
}

// framingPkgs are the two packages the gate reads, as go test arguments.
var framingPkgs = []string{"./contrib/frr-correlation/supervisor", "./contrib/frr-correlation/capture"}

// TestKnownGapRawFramingIsAccepted reproduces the gate's trust boundary with the
// real toolchain. Framing that a test binary writes to stdout or stderr can become
// run and pass events for a test that does not exist, and the gate accepts those
// events. Framing from init or TestMain does so with or without -v. Framing from a
// running test body does so only under -v, which CI uses. The gate accepts this for
// trusted CI; it does not authenticate output. Text in an Output field never counts
// as an event, so the t.Log rows stay refused.
func TestKnownGapRawFramingIsAccepted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture func(pkgName, test string) string
		verbose bool
		forged  bool // the stream carries run and pass events for the required tests
	}{
		{"init framing under -v", rawFraming, true, true},
		{"init framing without -v", rawFraming, false, true},
		{"TestMain framing before m.Run under -v", testMainFraming, true, true},
		{"TestMain framing before m.Run without -v", testMainFraming, false, true},
		{"stdout framing from a running test under -v", bodyFraming("os.Stdout"), true, true},
		{"stderr framing from a running test under -v", bodyFraming("os.Stderr"), true, true},
		{"stdout framing from a running test without -v stays output", bodyFraming("os.Stdout"), false, false},
		{"stderr framing from a running test without -v stays output", bodyFraming("os.Stderr"), false, false},
		{"t.Log text under -v stays output", loggedFraming, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := framingModule(t, tc.fixture)
			for pkg, names := range required {
				listed := goTest(t, dir, "-list", ".", pkg)
				if !bytes.Contains(listed, []byte("TestPlaceholder\n")) {
					t.Fatalf("%s listed no TestPlaceholder:\n%s", pkg, listed)
				}
				if regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(names[0]) + `$`).Match(listed) {
					t.Fatalf("%s is a real test; the reproduction needs it absent", names[0])
				}
			}
			args := []string{"-json", "-count=1"}
			if tc.verbose {
				args = append(args, "-v")
			}
			stream := goTest(t, dir, append(args, framingPkgs...)...)
			evs := decodeStream(t, stream)
			for pkg, names := range required {
				for _, action := range []string{"run", "pass"} {
					if hasEvent(evs, action, pkg, names[0]) != tc.forged {
						t.Fatalf("%s event for %s: present=%v, want %v", action, names[0], !tc.forged, tc.forged)
					}
				}
				if !tc.forged && !outputHas(evs, pkg, "--- PASS: "+names[0]) {
					t.Fatalf("framing text is not Output of %s", pkg)
				}
			}
			code, _, stderr := gate(string(stream), nil)
			if tc.forged && code != 0 {
				t.Fatalf("gate exit %d, want 0: %s", code, stderr)
			}
			if !tc.forged && (code == 0 || !strings.Contains(stderr, "did not run and pass")) {
				t.Fatalf("exit %d, stderr %q; want refusal for missing required tests", code, stderr)
			}
		})
	}
}

// testMainFraming prints framing before m.Run, so no test is running yet.
func testMainFraming(pkgName, test string) string {
	return fmt.Sprintf(`package %[1]s

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	fmt.Println("=== RUN   %[2]s")
	fmt.Println("--- PASS: %[2]s (0.00s)")
	os.Exit(m.Run())
}

func TestPlaceholder(t *testing.T) {}
`, pkgName, test)
}

// bodyFraming writes framing to stream, an os.Stdout or os.Stderr expression,
// from inside the running test body.
func bodyFraming(stream string) func(pkgName, test string) string {
	return func(pkgName, test string) string {
		return fmt.Sprintf(`package %[1]s

import (
	"fmt"
	"os"
	"testing"
)

func TestPlaceholder(t *testing.T) {
	fmt.Fprintln(%[3]s, "=== RUN   %[2]s")
	fmt.Fprintln(%[3]s, "--- PASS: %[2]s (0.00s)")
}
`, pkgName, test, stream)
	}
}

// framingModule writes a throwaway module at the real import paths. Each required
// package gets one test file from body, given the package name and its required test.
func framingModule(t *testing.T, body func(pkgName, test string) string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, data string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module github.com/heymaikol/network-doctor/v2\n\ngo 1.22\n")
	for pkg, names := range required {
		write("contrib/frr-correlation/"+path.Base(pkg)+"/forged_test.go", body(path.Base(pkg), names[0]))
	}
	return dir
}

// rawFraming prints go test framing to stdout from init, before the testing
// package runs. test2json reads it as ordinary stdout framing.
func rawFraming(pkgName, test string) string {
	return fmt.Sprintf(`package %[1]s

import (
	"fmt"
	"testing"
)

func init() {
	fmt.Println("=== RUN   %[2]s")
	fmt.Println("--- PASS: %[2]s (0.00s)")
}

func TestPlaceholder(t *testing.T) {}
`, pkgName, test)
}

// loggedFraming writes the same lines through t.Log. They reach the stream only as
// Output text of TestPlaceholder.
func loggedFraming(pkgName, test string) string {
	return fmt.Sprintf(`package %[1]s

import "testing"

func TestPlaceholder(t *testing.T) {
	t.Log("=== RUN   %[2]s")
	t.Log("--- PASS: %[2]s (0.00s)")
}
`, pkgName, test)
}

// goTest runs go test in dir with args and returns its stdout. Downloads and
// toolchain switches are off, so the run uses only the fixture and the local Go.
func goTest(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, gobin, append([]string{"test"}, args...)...) //nolint:gosec // G204: gobin is the local go toolchain and the arguments are fixed test text.
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=", "GOWORK=off")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go test %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes()
}

// decodeStream parses each line of a go test -json stream.
func decodeStream(t *testing.T, stream []byte) []event {
	t.Helper()
	var evs []event
	for _, line := range bytes.Split(bytes.TrimSuffix(stream, []byte("\n")), []byte("\n")) {
		var e event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		evs = append(evs, e)
	}
	return evs
}

// hasEvent reports whether the stream has the action event for test in pkg.
func hasEvent(evs []event, action, pkg, test string) bool {
	for _, e := range evs {
		if e.Action == action && e.Package == pkg && e.Test == test {
			return true
		}
	}
	return false
}

// outputHas reports whether an Output event of pkg contains text.
func outputHas(evs []event, pkg, text string) bool {
	for _, e := range evs {
		if e.Action == "output" && e.Package == pkg && strings.Contains(e.Output, text) {
			return true
		}
	}
	return false
}
