// Command opensshgate reads the verbose output of the integration tests that need a real OpenSSH
// and exits nonzero unless every one of them ran and passed. CI runs it after go test with
// NETDOC_REQUIRE_OPENSSH=1, so a test that skips, or is missing from the run, fails the job.
//
// The required tests are read from the source: every test in an integration-tagged file of
// internal/sshverify, and every test in the profile lab that starts a real sshd. A new test in
// those files is required without any change here.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// labFile is the profile lab, which starts a real sshd and runs the ssh client.
const labFile = "internal/app/profile_batch_integration_test.go"

// sshverifyDir holds the verifier, whose integration-tagged files run the real client.
const sshverifyDir = "internal/sshverify"

var (
	testFunc   = regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\)`)
	buildTag   = regexp.MustCompile(`(?m)^//go:build .*\bintegration\b`)
	terminal   = regexp.MustCompile(`^\s*--- (PASS|FAIL|SKIP): (\S+) \(`)
	reqEnvName = "NETDOC_REQUIRE_OPENSSH"
)

func main() {
	if os.Getenv(reqEnvName) != "1" {
		fmt.Fprintf(os.Stderr, "opensshgate: %s=1 must be set; the gate refuses to pass without it\n", reqEnvName)
		os.Exit(2)
	}
	required, err := requiredTests(".")
	if err == nil {
		err = check(os.Stdin, required, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "opensshgate:", err)
		os.Exit(1)
	}
}

// requiredTests lists the top-level tests the gate requires, from the source under root.
func requiredTests(root string) ([]string, error) {
	var names []string
	files, err := filepath.Glob(filepath.Join(root, sshverifyDir, "*_test.go"))
	if err != nil {
		return nil, err
	}
	files = append(files, filepath.Join(root, labFile))
	for _, f := range files {
		src, err := os.ReadFile(f) // #nosec G304 -- a source file under the repository root named by the gate's own list
		if err != nil {
			return nil, err
		}
		if f != filepath.Join(root, labFile) && !buildTag.Match(src) {
			continue
		}
		for _, m := range testFunc.FindAllSubmatch(src, -1) {
			names = append(names, string(m[1]))
		}
	}
	if len(names) == 0 {
		return nil, errors.New("no required tests were found in the source; the gate would prove nothing")
	}
	sort.Strings(names)
	return names, nil
}

// check reads a go test -v stream from in. It returns an error naming each required test that did
// not run, or did not pass, or had a skipped or failed subtest. It writes a one-line summary to out.
func check(in io.Reader, required []string, out io.Writer) error {
	ended := map[string]string{} // the last terminal line of each test, by its full name
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if m := terminal.FindStringSubmatch(sc.Text()); m != nil {
			ended[m[2]] = m[1]
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	var problems []string
	need := map[string]bool{}
	for _, r := range required {
		need[r] = true
		switch action, ok := ended[r]; {
		case !ok:
			problems = append(problems, r+" did not run")
		case action != "PASS":
			problems = append(problems, r+" ended "+action)
		}
	}
	for name, action := range ended {
		top, _, _ := strings.Cut(name, "/")
		if need[top] && name != top && action != "PASS" {
			problems = append(problems, name+" ended "+action)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%d required OpenSSH test problem(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	fmt.Fprintf(out, "opensshgate: all %d required OpenSSH tests ran and passed\n", len(required))
	return nil
}
