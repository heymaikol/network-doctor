package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const greenRun = `=== RUN   TestOpenSSHTrusted
--- PASS: TestOpenSSHTrusted (1.20s)
=== RUN   TestProfileLab
=== RUN   TestProfileLab/unknown_host_key
    --- PASS: TestProfileLab/unknown_host_key (0.10s)
--- PASS: TestProfileLab (0.30s)
`

func gate(t *testing.T, stream string, required ...string) error {
	t.Helper()
	var out bytes.Buffer
	return check(strings.NewReader(stream), required, &out)
}

func TestGateAcceptsRequiredTestsThatPassed(t *testing.T) {
	if err := gate(t, greenRun, "TestOpenSSHTrusted", "TestProfileLab"); err != nil {
		t.Fatalf("a run where every required test passed was refused: %v", err)
	}
}

func TestGateRefusesARequiredTestThatSkipped(t *testing.T) {
	stream := strings.Replace(greenRun, "--- PASS: TestOpenSSHTrusted", "--- SKIP: TestOpenSSHTrusted", 1)
	if err := gate(t, stream, "TestOpenSSHTrusted"); err == nil || !strings.Contains(err.Error(), "TestOpenSSHTrusted ended SKIP") {
		t.Fatalf("a skipped required test was not refused: %v", err)
	}
}

func TestGateRefusesARequiredTestThatDidNotRun(t *testing.T) {
	if err := gate(t, greenRun, "TestOpenSSHTrusted", "TestMissing"); err == nil || !strings.Contains(err.Error(), "TestMissing did not run") {
		t.Fatalf("a missing required test was not refused: %v", err)
	}
}

func TestGateRefusesARequiredTestThatFailed(t *testing.T) {
	stream := strings.Replace(greenRun, "--- PASS: TestOpenSSHTrusted", "--- FAIL: TestOpenSSHTrusted", 1)
	if err := gate(t, stream, "TestOpenSSHTrusted"); err == nil || !strings.Contains(err.Error(), "TestOpenSSHTrusted ended FAIL") {
		t.Fatalf("a failed required test was not refused: %v", err)
	}
}

// A subtest skipped under a required test is a skip of the required test's own check, so it is refused too.
func TestGateRefusesASkippedSubtestOfARequiredTest(t *testing.T) {
	stream := strings.Replace(greenRun, "--- PASS: TestProfileLab/unknown_host_key", "--- SKIP: TestProfileLab/unknown_host_key", 1)
	if err := gate(t, stream, "TestProfileLab"); err == nil || !strings.Contains(err.Error(), "TestProfileLab/unknown_host_key ended SKIP") {
		t.Fatalf("a skipped subtest of a required test was not refused: %v", err)
	}
}

func TestGateIgnoresSkipsOfTestsItDoesNotRequire(t *testing.T) {
	stream := greenRun + "--- SKIP: TestUnrelatedNetns (0.00s)\n"
	if err := gate(t, stream, "TestOpenSSHTrusted"); err != nil {
		t.Fatalf("a skip of a test outside the required set was refused: %v", err)
	}
}

// The required set is read from the source: integration-tagged files of the verifier, and the profile
// lab, and nothing else. A test in an ordinary file is not required.
func TestRequiredTestsComeFromTheIntegrationSource(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/sshverify/loop_integration_test.go", "//go:build integration && unix\n\npackage sshverify\n\nfunc TestOpenSSHLoop(t *testing.T) {}\n")
	write("internal/sshverify/plain_test.go", "package sshverify\n\nfunc TestPlainOnly(t *testing.T) {}\n")
	write("internal/app/profile_batch_integration_test.go", "//go:build integration\n\npackage app\n\nfunc TestProfileNeverRetriesARefusedBatchInteractively(t *testing.T) {}\n")

	got, err := requiredTests(root)
	if err != nil {
		t.Fatal(err)
	}
	want := "TestOpenSSHLoop TestProfileNeverRetriesARefusedBatchInteractively"
	if strings.Join(got, " ") != want {
		t.Fatalf("required = %v, want %s", got, want)
	}
}

func TestRequiredTestsRefusesAnEmptySource(t *testing.T) {
	if _, err := requiredTests(t.TempDir()); err == nil {
		t.Fatal("an empty source gave a required set, so a run could pass with nothing to check")
	}
}
