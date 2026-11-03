// Command netnsgate reads the go test -json stream of the supervisor and capture
// namespace tests and exits nonzero unless the stream proves they ran. CI runs
// it after go test with NETDOC_SIM_REQUIRE_NETNS=1.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	supervisorPkg = "github.com/heymaikol/network-doctor/v2/contrib/frr-correlation/supervisor"
	capturePkg    = "github.com/heymaikol/network-doctor/v2/contrib/frr-correlation/capture"
	frrTest       = "TestFRRRunsUnderTheSupervisor"
	frrStageEnv   = "NETDOC_FRR_STAGE"
)

// required lists the tests that must run and pass, by package.
var required = map[string][]string{
	supervisorPkg: {"TestNamespaceIsRetainedIsolatedAndReleased"},
	capturePkg:    {"TestStopSucceedsWhileADetachedWriterHoldsTheStream"},
}

// actions are the go test -json actions the gate knows. fail is known so the
// event checks can name the test, and it is always refused. Any other action,
// build-fail and build-output included, refuses the stream as unexpected.
var actions = map[string]bool{"start": true, "run": true, "output": true, "pass": true, "skip": true, "fail": true, "pause": true, "cont": true}

// frrReason is the one output line the FRR test may leave when it skips.
var frrReason = regexp.MustCompile(`^\s*frr_linux_test\.go:\d+: NETDOC_FRR_STAGE not set$`)

// event is one go test -json line. Time and Elapsed are not read.
type event struct {
	Action, Package, Test, Output string
}

type key struct{ pkg, test string }

type testState struct {
	runs     int
	terminal string   // "pass" or "skip" once the test ends
	output   []string // output lines without go test's own === and --- framing
}

type checker struct {
	lookupEnv func(string) (string, bool)
	events    int
	passes    map[string]int // package-level pass events, by package
	tests     map[key]*testState
	frrSkip   bool
}

// run checks the stream on in and echoes test output to stdout, so the CI log
// stays verbose. It returns 0 only when the stream proves the required tests
// ran and passed in both packages.
func run(in io.Reader, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	c := &checker{lookupEnv: lookupEnv, passes: map[string]int{}, tests: map[key]*testState{}}
	var first error
	r := bufio.NewReader(in)
	for n := 1; ; n++ {
		raw, err := r.ReadBytes('\n')
		if len(raw) > 0 {
			if cerr := c.line(raw, stdout); cerr != nil && first == nil {
				first = fmt.Errorf("line %d: %w", n, cerr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(stderr, "netnsgate: read: %v\n", err)
			return 1
		}
	}
	if first == nil {
		first = c.finish()
	}
	if first != nil {
		fmt.Fprintf(stderr, "netnsgate: refused: %v\n", first)
		return 1
	}
	fmt.Fprintf(stdout, "netnsgate: ok: %d events; required tests ran and passed in both packages; FRR skipped: %t\n", c.events, c.frrSkip)
	return 0
}

// line decodes one raw line. bufio.Reader has no token limit, so long race
// output cannot fail the gate by length.
func (c *checker) line(raw []byte, stdout io.Writer) error {
	var e event
	if err := json.Unmarshal(raw, &e); err != nil {
		return fmt.Errorf("malformed event: %w", err)
	}
	if e.Action == "" {
		return errors.New("malformed event: no Action")
	}
	// Compile errors arrive as build-output. Echo them so the log shows why go test
	// failed; the action check below still refuses them.
	if e.Action == "output" || e.Action == "build-output" {
		fmt.Fprint(stdout, e.Output)
	}
	c.events++
	return c.event(e)
}

func (c *checker) event(e event) error {
	if _, ok := required[e.Package]; !ok {
		return fmt.Errorf("unexpected package %q", e.Package)
	}
	if !actions[e.Action] {
		return fmt.Errorf("unexpected action %q in %s", e.Action, e.Package)
	}
	k := key{e.Package, e.Test}
	switch e.Action {
	case "output":
		// Output text is never an event. Only action fields count toward the
		// checks, so a line that looks like a PASS in this field proves nothing.
		if e.Test != "" && !strings.HasPrefix(e.Output, "=== ") && !strings.HasPrefix(e.Output, "--- ") {
			s := c.state(k)
			s.output = append(s.output, e.Output)
		}
	case "run":
		if e.Test == "" {
			return fmt.Errorf("run event in %s without a test name", e.Package)
		}
		s := c.state(k)
		s.runs++
		if s.runs > 1 {
			return fmt.Errorf("%s ran %d times; the gate expects -count=1", e.Test, s.runs)
		}
	case "pass", "skip", "fail":
		if e.Test == "" {
			if e.Action != "pass" {
				return fmt.Errorf("package %s ended with %s", e.Package, e.Action)
			}
			c.passes[e.Package]++
			return nil
		}
		s := c.tests[k]
		switch {
		case s == nil || s.runs == 0:
			return fmt.Errorf("%s ended with %s before it ran", e.Test, e.Action)
		case s.terminal != "":
			return fmt.Errorf("%s ended twice", e.Test)
		}
		s.terminal = e.Action
		switch e.Action {
		case "fail":
			return fmt.Errorf("%s failed", e.Test)
		case "skip":
			return c.allowSkip(k, s)
		}
	}
	return nil
}

func (c *checker) state(k key) *testState {
	s := c.tests[k]
	if s == nil {
		s = &testState{}
		c.tests[k] = s
	}
	return s
}

// allowSkip accepts one skip: the FRR test, with no FRR copy staged, leaving
// exactly the reason line it prints in that case.
func (c *checker) allowSkip(k key, s *testState) error {
	if k.pkg != supervisorPkg || k.test != frrTest {
		return fmt.Errorf("unexpected skip of %s", k.test)
	}
	if _, set := c.lookupEnv(frrStageEnv); set {
		return fmt.Errorf("%s skipped while %s is set", k.test, frrStageEnv)
	}
	reason := strings.TrimSuffix(strings.Join(s.output, ""), "\n")
	if strings.Contains(reason, "\n") || !frrReason.MatchString(reason) {
		return fmt.Errorf("%s skipped with reason %q, want only the %s not set reason", k.test, reason, frrStageEnv)
	}
	c.frrSkip = true
	return nil
}

// finish checks what the whole stream must contain: each package passed once,
// each required test ran once and passed, and no test was left mid-run.
func (c *checker) finish() error {
	if c.events == 0 {
		return errors.New("no events: empty stream")
	}
	for pkg, names := range required {
		if n := c.passes[pkg]; n != 1 {
			return fmt.Errorf("%s has %d package passes, want 1", pkg, n)
		}
		for _, name := range names {
			if s := c.tests[key{pkg, name}]; s == nil || s.runs != 1 || s.terminal != "pass" {
				return fmt.Errorf("required test %s did not run and pass in %s", name, pkg)
			}
		}
	}
	for k, s := range c.tests {
		if s.runs == 1 && s.terminal == "" {
			return fmt.Errorf("%s did not finish", k.test)
		}
	}
	return nil
}

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr, os.LookupEnv))
}
