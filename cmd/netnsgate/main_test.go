package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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

// TestKnownGapRawFramingIsAccepted pins the boundary of the gate. A test body
// that writes go test framing to raw stdout makes test2json emit run and pass
// events indistinguishable from real ones, so the gate must accept them. Text
// in an output field cannot satisfy the check; raw stdout framing can. Closing
// this gap needs a record the test binary cannot write itself.
func TestKnownGapRawFramingIsAccepted(t *testing.T) {
	code, _, stderr := gate(build(nil), nil)
	if code != 0 {
		t.Fatalf("exit %d, want 0 for test2json-shaped framing: %s", code, stderr)
	}
}
