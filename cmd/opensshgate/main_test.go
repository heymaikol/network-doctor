package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	pkgVerify = "github.com/heymaikol/network-doctor/v2/internal/sshverify"
	pkgRemote = "github.com/heymaikol/network-doctor/v2/internal/remote"
	pkgApp    = "github.com/heymaikol/network-doctor/v2/internal/app"
)

// ev is one go test -json line, as the toolchain writes it.
func ev(action, pkg, test, output string) string {
	b, _ := json.Marshal(event{Action: action, Package: pkg, Test: test, Output: output})
	return string(b) + "\n"
}

// green is one package whose named tests each ran and passed, with the package result.
func green(pkg string, tests ...string) string {
	s := ev("start", pkg, "", "")
	for _, t := range tests {
		s += ev("run", pkg, t, "") + ev("output", pkg, t, "=== RUN   "+t+"\n") + ev("pass", pkg, t, "")
	}
	return s + ev("pass", pkg, "", "")
}

func req(pkg string, tests ...string) []requirement {
	var r []requirement
	for _, t := range tests {
		r = append(r, requirement{Pkg: pkg, Test: t})
	}
	return r
}

func gate(t *testing.T, stream string, required ...requirement) error {
	t.Helper()
	var out bytes.Buffer
	return check(strings.NewReader(stream), required, &out)
}

func mustContain(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want an error containing %q, got %v", want, err)
	}
}

func TestGateAcceptsRequiredTestsThatPassed(t *testing.T) {
	stream := green(pkgVerify, "TestA", "TestB")
	if err := gate(t, stream, req(pkgVerify, "TestA", "TestB")...); err != nil {
		t.Fatalf("a run where every required test passed was refused: %v", err)
	}
}

func TestGateRefusesARequiredTestThatSkipped(t *testing.T) {
	stream := ev("start", pkgVerify, "", "") + ev("run", pkgVerify, "TestA", "") +
		ev("output", pkgVerify, "TestA", "needs sshd on this host\n") + ev("skip", pkgVerify, "TestA", "") +
		ev("pass", pkgVerify, "", "")
	mustContain(t, gate(t, stream, req(pkgVerify, "TestA")...), "TestA in sshverify ended skip")
}

func TestGateRefusesARequiredTestThatDidNotRun(t *testing.T) {
	mustContain(t, gate(t, green(pkgVerify, "TestA"), req(pkgVerify, "TestA", "TestMissing")...), "TestMissing in sshverify did not run")
}

func TestGateRefusesARequiredTestThatFailed(t *testing.T) {
	stream := ev("start", pkgVerify, "", "") + ev("run", pkgVerify, "TestA", "") + ev("fail", pkgVerify, "TestA", "") + ev("fail", pkgVerify, "", "")
	mustContain(t, gate(t, stream, req(pkgVerify, "TestA")...), "TestA in sshverify ended fail")
}

func TestGateRefusesASkippedSubtestOfARequiredTest(t *testing.T) {
	stream := ev("start", pkgVerify, "", "") + ev("run", pkgVerify, "TestA", "") + ev("run", pkgVerify, "TestA/sub", "") +
		ev("skip", pkgVerify, "TestA/sub", "") + ev("pass", pkgVerify, "TestA", "") + ev("pass", pkgVerify, "", "")
	mustContain(t, gate(t, stream, req(pkgVerify, "TestA")...), "TestA/sub in sshverify ended skip")
}

func TestGateAcceptsLegitimatePassingSubtests(t *testing.T) {
	stream := ev("start", pkgVerify, "", "") + ev("run", pkgVerify, "TestA", "") + ev("run", pkgVerify, "TestA/one", "") +
		ev("pass", pkgVerify, "TestA/one", "") + ev("run", pkgVerify, "TestA/two", "") + ev("pass", pkgVerify, "TestA/two", "") +
		ev("pass", pkgVerify, "TestA", "") + ev("pass", pkgVerify, "", "")
	if err := gate(t, stream, req(pkgVerify, "TestA")...); err != nil {
		t.Fatalf("passing subtests were refused: %v", err)
	}
}

func TestGateIgnoresSkipsOfTestsItDoesNotRequire(t *testing.T) {
	helperSkip := ev("start", pkgVerify, "", "") + ev("run", pkgVerify, "TestHelperChild", "") +
		ev("skip", pkgVerify, "TestHelperChild", "") + ev("run", pkgVerify, "TestA", "") + ev("pass", pkgVerify, "TestA", "") +
		ev("pass", pkgVerify, "", "")
	if err := gate(t, helperSkip, req(pkgVerify, "TestA")...); err != nil {
		t.Fatalf("a skipped helper that is not required was refused: %v", err)
	}
}

// A test that prints PASS or FAIL text does not change the verdict. The text is output events only.
func TestGateIgnoresResultTextPrintedByTests(t *testing.T) {
	// TestA really fails. Another test prints a PASS line for it.
	forgedPass := ev("start", pkgVerify, "", "") +
		ev("run", pkgVerify, "TestA", "") + ev("fail", pkgVerify, "TestA", "") +
		ev("run", pkgVerify, "TestForger", "") +
		ev("output", pkgVerify, "TestForger", "    x_test.go:9: note\n        --- PASS: TestA (0.00s)\n") +
		ev("pass", pkgVerify, "TestForger", "") + ev("fail", pkgVerify, "", "")
	mustContain(t, gate(t, forgedPass, req(pkgVerify, "TestA", "TestForger")...), "TestA in sshverify ended fail")

	// TestA really passes. Its own output prints a FAIL line for it, which changes nothing.
	forgedFail := ev("start", pkgVerify, "", "") +
		ev("run", pkgVerify, "TestA", "") + ev("output", pkgVerify, "TestA", "--- FAIL: TestA (0.00s)\n") + ev("pass", pkgVerify, "TestA", "") +
		ev("pass", pkgVerify, "", "")
	if err := gate(t, forgedFail, req(pkgVerify, "TestA")...); err != nil {
		t.Fatalf("a passing test refused because its output printed a FAIL line: %v", err)
	}
}

// A result that arrives before the test's run event, as the toolchain can emit for text printed
// during package init, is refused. The real run then makes a second result, so it is refused too.
func TestGateRefusesAResultBeforeItsRun(t *testing.T) {
	stream := ev("start", pkgVerify, "", "") + ev("pass", pkgVerify, "TestA", "") +
		ev("run", pkgVerify, "TestA", "") + ev("pass", pkgVerify, "TestA", "") + ev("pass", pkgVerify, "", "")
	mustContain(t, gate(t, stream, req(pkgVerify, "TestA")...), "TestA in sshverify reported 2 results")
}

func TestGateRefusesAForgedResultWithNoRealRun(t *testing.T) {
	stream := ev("start", pkgVerify, "", "") + ev("run", pkgVerify, "TestA", "") + ev("pass", pkgVerify, "TestA", "") +
		ev("pass", pkgVerify, "", "")
	if err := gate(t, stream, req(pkgVerify, "TestA", "TestB")...); err == nil {
		t.Fatal("a missing required test was accepted")
	}
}

func TestGateRefusesARepeatedRun(t *testing.T) {
	stream := ev("start", pkgVerify, "", "") + ev("run", pkgVerify, "TestA", "") + ev("run", pkgVerify, "TestA", "") +
		ev("pass", pkgVerify, "TestA", "") + ev("pass", pkgVerify, "", "")
	mustContain(t, gate(t, stream, req(pkgVerify, "TestA")...), "TestA in sshverify ran 2 times")
}

func TestGateRefusesAMalformedEvent(t *testing.T) {
	stream := green(pkgVerify, "TestA") + "{not json\n"
	mustContain(t, gate(t, stream, req(pkgVerify, "TestA")...), "malformed event")
}

func TestGateRefusesAnUnknownAction(t *testing.T) {
	stream := ev("start", pkgVerify, "", "") + ev("frobnicate", pkgVerify, "TestA", "")
	mustContain(t, gate(t, stream, req(pkgVerify, "TestA")...), "unknown action")
}

func TestGateRefusesATruncatedStream(t *testing.T) {
	full := green(pkgVerify, "TestA")
	cut := full[:strings.LastIndex(full, ev("pass", pkgVerify, "", ""))]
	mustContain(t, gate(t, cut, req(pkgVerify, "TestA")...), pkgVerify[strings.LastIndex(pkgVerify, "/")+1:]+" did not finish")
}

func TestGateRefusesAnEmptyStream(t *testing.T) {
	if err := gate(t, "", req(pkgVerify, "TestA")...); err == nil {
		t.Fatal("an empty stream was accepted")
	}
}

func TestGateRefusesAPackageThatFailedAroundPassingTests(t *testing.T) {
	stream := ev("start", pkgVerify, "", "") + ev("run", pkgVerify, "TestA", "") + ev("pass", pkgVerify, "TestA", "") +
		ev("fail", pkgVerify, "", "")
	mustContain(t, gate(t, stream, req(pkgVerify, "TestA")...), "sshverify ended fail")
}

func TestGateRefusesAnEventAfterThePackageResult(t *testing.T) {
	stream := green(pkgVerify, "TestA") + ev("run", pkgVerify, "TestLate", "")
	mustContain(t, gate(t, stream, req(pkgVerify, "TestA")...), "comes after its package result")
}

func TestGateChecksEachRequiredPackage(t *testing.T) {
	stream := green(pkgVerify, "TestA")
	if err := gate(t, stream, req(pkgVerify, "TestA")...); err != nil {
		t.Fatalf("a passing package was refused: %v", err)
	}
	mustContain(t, gate(t, stream, append(req(pkgVerify, "TestA"), req(pkgRemote, "TestR")...)...), "remote did not finish")
}

// The scope of the required set comes from the source: the verifier's integration tests, the remote
// tests that start OpenSSH, and the profile lab. The PMTU tests in the app package are not OpenSSH.
func TestRequiredTestsComeFromTheIntegrationSource(t *testing.T) {
	reqs, err := requiredTests(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	has := func(pkg, name string) bool {
		for _, r := range reqs {
			if r.Pkg == pkg && r.Test == name {
				return true
			}
		}
		return false
	}
	for _, c := range []struct{ pkg, name string }{
		{pkgVerify, "TestOpenSSHNegotiatedAlgorithmIsPinned"},
		{pkgVerify, "TestVerifyOverLoopbackTCP"},
		{pkgRemote, "TestBatchNeverUpdatesKnownHosts"},
		{pkgRemote, "TestBatchNeverRidesAControlMaster"},
		{pkgRemote, "TestHeadlessRunStillConnectsByACRLFDirectRoute"},
		{pkgApp, "TestProfileNeverRetriesARefusedBatchInteractively"},
	} {
		if !has(c.pkg, c.name) {
			t.Errorf("%s in %s is not required", c.name, c.pkg)
		}
	}
	for _, name := range []string{"TestPMTUPayloadAcknowledgedBeforeAccept", "TestUnknownProtocolPMTUPayload"} {
		if has(pkgApp, name) {
			t.Errorf("%s is not an OpenSSH test but is required", name)
		}
	}
}

func TestRequiredTestsRefusesAnEmptySource(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := requiredTests(dir); err == nil {
		t.Fatal("an empty source was accepted")
	}
}

func fakeTools(missing ...string) tools {
	gone := map[string]bool{}
	for _, m := range missing {
		gone[m] = true
	}
	return tools{
		lookPath: func(name string) (string, error) {
			if gone[name] {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + name, nil
		},
		stat: func(p string) error {
			if gone["sshd"] {
				return errors.New("no such file")
			}
			return nil
		},
		version: func(string) (string, error) { return "OpenSSH_10.5p1, OpenSSL 4.0.3", nil },
	}
}

func TestPrereqRefusesAMissingTool(t *testing.T) {
	var out bytes.Buffer
	err := prereq(&out, fakeTools("cc"))
	mustContain(t, err, "missing OpenSSH test prerequisites: cc")
}

func TestPrereqRefusesMissingSSHD(t *testing.T) {
	var out bytes.Buffer
	mustContain(t, prereq(&out, fakeTools("sshd")), "sshd")
}

func TestPrereqReportsTheClientVersion(t *testing.T) {
	var out bytes.Buffer
	if err := prereq(&out, fakeTools()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "OpenSSH_10.5p1") {
		t.Fatalf("the client version was not reported: %q", out.String())
	}
}
