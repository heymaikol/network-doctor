// Command opensshgate reads the go test -json stream of the integration lanes and exits nonzero
// unless every OpenSSH-dependent test it requires ran once and passed, and every package that holds
// one finished with a passing result. The verdict comes only from the framework's events. Text that
// a test prints is output, and the gate never reads it as a result.
//
// CI runs it with NETDOC_REQUIRE_OPENSSH=1 after go test -json. With -prereq it checks that the
// OpenSSH client, its key tool, sshd and a C compiler are present, before any test runs.
//
// The required tests are read from the source: every test in an integration-tagged file of an
// OpenSSH package that starts the real client or sshd. A new such test is required without any
// change here.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// sshDirs holds the packages whose integration tests run the real OpenSSH client or sshd.
var sshDirs = []string{"internal/sshverify", "internal/remote", "internal/app"}

// verifierDir is the verifier. Every integration-tagged file there runs the real client.
const verifierDir = "internal/sshverify"

const reqEnvName = "NETDOC_REQUIRE_OPENSSH"

var (
	integrationTag = regexp.MustCompile(`(?m)^//go:build integration(\s|$)`)
	// sshMarker finds the helpers and binary names that start the real client or sshd. Files outside
	// the verifier that match none of them are not OpenSSH tests.
	sshMarker  = regexp.MustCompile(`"ssh"|"sshd"|"ssh-keygen"|newOSHLab\(|newBatchLab\(|newProfileLab\(|lookTool\(|oshTool\(`)
	topTest    = regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\)`)
	modulePath = regexp.MustCompile(`(?m)^module (\S+)`)
)

// knownActions is the vocabulary of go test -json (cmd/test2json, cmd/go). Any other action is refused.
var knownActions = map[string]bool{
	"start": true, "run": true, "pause": true, "cont": true, "pass": true, "bench": true,
	"fail": true, "output": true, "skip": true, "attr": true, "artifacts": true,
	"build-output": true, "build-fail": true,
}

// requirement names one test in one package by its import path and its full name.
type requirement struct {
	Pkg  string
	Test string
}

// event is one line of go test -json.
type event struct {
	Action  string
	Package string
	Test    string
	Output  string
}

func main() {
	if os.Getenv(reqEnvName) != "1" {
		fmt.Fprintf(os.Stderr, "opensshgate: %s=1 must be set; the gate refuses to pass without it\n", reqEnvName)
		os.Exit(2)
	}
	if len(os.Args) == 2 && os.Args[1] == "-prereq" {
		if err := prereq(os.Stdout, defaultTools()); err != nil {
			fmt.Fprintln(os.Stderr, "opensshgate:", err)
			os.Exit(1)
		}
		return
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

// requiredTests lists the tests the gate requires, from the source under root.
func requiredTests(root string) ([]requirement, error) {
	mod, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- the module file under the repository root
	if err != nil {
		return nil, err
	}
	m := modulePath.FindSubmatch(mod)
	if m == nil {
		return nil, errors.New("go.mod has no module line")
	}
	var reqs []requirement
	for _, dir := range sshDirs {
		files, err := filepath.Glob(filepath.Join(root, dir, "*_test.go"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			src, err := os.ReadFile(f) // #nosec G304 -- a source file under the repository root, named by the gate's own list
			if err != nil {
				return nil, err
			}
			if !integrationTag.Match(src) {
				continue
			}
			if dir != verifierDir && !sshMarker.Match(src) {
				continue
			}
			for _, t := range topTest.FindAllSubmatch(src, -1) {
				reqs = append(reqs, requirement{Pkg: string(m[1]) + "/" + dir, Test: string(t[1])})
			}
		}
	}
	if len(reqs) == 0 {
		return nil, errors.New("no required tests were found in the source; the gate would prove nothing")
	}
	sort.Slice(reqs, func(i, j int) bool {
		if reqs[i].Pkg != reqs[j].Pkg {
			return reqs[i].Pkg < reqs[j].Pkg
		}
		return reqs[i].Test < reqs[j].Test
	})
	return reqs, nil
}

// check reads a go test -json stream from in. It returns an error naming each required test that did
// not run, did not finish, ran or reported more than once, or did not pass, each required package that
// did not finish or did not pass, and each malformed or out-of-order event. It writes a one-line
// summary to out.
func check(in io.Reader, required []requirement, out io.Writer) error {
	needPkg := map[string]bool{}
	for _, r := range required {
		needPkg[r.Pkg] = true
	}
	life := map[requirement][]string{} // lifecycle actions of each test, in stream order
	lastOut := map[requirement]string{}
	pkgResults := map[string][]string{} // package-level results
	closed := map[string]bool{}         // a package that has reported its result
	dec := json.NewDecoder(in)
	for n := 1; ; n++ {
		var e event
		if err := dec.Decode(&e); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("malformed event %d in the stream: %w", n, err)
		}
		if !knownActions[e.Action] {
			return fmt.Errorf("event %d has an unknown action %q", n, e.Action)
		}
		if e.Package == "" {
			if strings.HasPrefix(e.Action, "build-") {
				continue
			}
			return fmt.Errorf("event %d (%s) names no package", n, e.Action)
		}
		if !needPkg[e.Package] {
			continue
		}
		if closed[e.Package] && e.Action != "output" {
			return fmt.Errorf("event %d (%s) for %s comes after its package result", n, e.Action, e.Package)
		}
		r := requirement{Pkg: e.Package, Test: e.Test}
		switch {
		case e.Test == "" && (e.Action == "pass" || e.Action == "fail" || e.Action == "skip"):
			pkgResults[e.Package] = append(pkgResults[e.Package], e.Action)
			closed[e.Package] = true
		case e.Test == "":
			// start, output and build events of the package carry no verdict.
		case e.Action == "output":
			if s := strings.TrimSpace(e.Output); s != "" {
				lastOut[r] = s
			}
		case e.Action == "run" || e.Action == "pass" || e.Action == "fail" || e.Action == "skip" || e.Action == "pause" || e.Action == "cont":
			life[r] = append(life[r], e.Action)
		}
	}

	var problems []string
	for _, r := range required {
		seq := lifecycle(life[r])
		problems = append(problems, sequenceProblems(label(r), seq, lastOut[r])...)
	}
	// Subtests of a required test are checked too: every one that ran must have passed.
	need := map[requirement]bool{}
	for _, r := range required {
		need[r] = true
	}
	for r, acts := range life {
		parent, _, nested := strings.Cut(r.Test, "/")
		if !nested || !need[requirement{Pkg: r.Pkg, Test: parent}] {
			continue
		}
		problems = append(problems, sequenceProblems(label(r), lifecycle(acts), lastOut[r])...)
	}
	for pkg := range needPkg {
		switch res := pkgResults[pkg]; {
		case len(res) == 0:
			problems = append(problems, shortPkg(pkg)+" did not finish")
		case len(res) > 1:
			problems = append(problems, fmt.Sprintf("%s reported %d package results", shortPkg(pkg), len(res)))
		case res[0] != "pass":
			problems = append(problems, shortPkg(pkg)+" ended "+res[0])
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%d required OpenSSH test problem(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	fmt.Fprintf(out, "opensshgate: all %d required OpenSSH tests ran and passed\n", len(required))
	return nil
}

// lifecycle keeps the actions that decide a test's result. Pauses and continues do not decide it.
func lifecycle(acts []string) []string {
	var seq []string
	for _, a := range acts {
		if a != "pause" && a != "cont" {
			seq = append(seq, a)
		}
	}
	return seq
}

// sequenceProblems checks one test's lifecycle. A result must be exactly one run followed by exactly
// one pass. Anything else, including a result before the run, is refused.
func sequenceProblems(name string, seq []string, last string) []string {
	runs, results := 0, 0
	for _, a := range seq {
		if a == "run" {
			runs++
		} else {
			results++
		}
	}
	detail := ""
	if last != "" {
		detail = fmt.Sprintf(" (last output: %q)", last)
	}
	switch {
	case len(seq) == 0:
		return []string{name + " did not run"}
	case runs == 0:
		return []string{name + " reported a result without running"}
	case runs > 1:
		return []string{fmt.Sprintf("%s ran %d times", name, runs)}
	case results > 1:
		return []string{fmt.Sprintf("%s reported %d results", name, results)}
	case seq[0] != "run":
		return []string{name + " reported a result before it ran"}
	case results == 0:
		return []string{name + " did not finish"}
	case seq[len(seq)-1] != "pass":
		return []string{name + " ended " + seq[len(seq)-1] + detail}
	}
	return nil
}

func label(r requirement) string {
	return r.Test + " in " + shortPkg(r.Pkg)
}

// shortPkg names a package by its last path element, which is unique among the OpenSSH packages.
func shortPkg(pkg string) string {
	return pkg[strings.LastIndex(pkg, "/")+1:]
}

// tools are the host programs the OpenSSH tests start. prereq takes them as functions so a test can
// remove one.
type tools struct {
	lookPath func(string) (string, error)
	stat     func(string) error
	version  func(string) (string, error)
}

func defaultTools() tools {
	return tools{
		lookPath: exec.LookPath,
		stat:     func(p string) error { _, err := os.Stat(p); return err },
		version: func(p string) (string, error) {
			var buf bytes.Buffer
			cmd := exec.Command(p, "-V")
			cmd.Stdout, cmd.Stderr = &buf, &buf
			err := cmd.Run()
			return strings.TrimSpace(buf.String()), err
		},
	}
}

// prereq reports each host program the OpenSSH tests need. A missing one is an error. sshd is found
// as the tests find it, on PATH or in /usr/sbin.
func prereq(out io.Writer, t tools) error {
	var missing []string
	for _, name := range []string{"ssh", "ssh-keygen", "cc"} {
		if _, err := t.lookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	if _, err := t.lookPath("sshd"); err != nil && t.stat("/usr/sbin/sshd") != nil {
		missing = append(missing, "sshd")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing OpenSSH test prerequisites: %s", strings.Join(missing, ", "))
	}
	v, err := t.version("ssh")
	if err != nil {
		return fmt.Errorf("ssh -V failed: %w", err)
	}
	fmt.Fprintf(out, "opensshgate: prerequisites present; %s\n", v)
	return nil
}
