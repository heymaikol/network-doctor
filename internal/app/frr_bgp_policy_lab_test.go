package app

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// policyLabScript is the BGP policy lab. Its capture path needs unshare, FRR, and namespaces, so these
// tests run its preflight, which exits before anything is written, and its cap and captxt functions.
// The functions are cut out of the script and run over committed captures, with the vty replaced by a
// copy, so the lab's own checker call and file handling are what the tests exercise.
const policyLabScript = "../../testdata/frr/10.7.0/lab/bgp-policy.sh"

// utcStamp is the form of a .collected_at stamp: date -u with nanoseconds, then a newline.
var utcStamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z\n$`)

// policyStub replaces the lab's two vty calls with a copy of $FIXTURE and the exit status $STUB_RC.
const policyStub = `query() { cp -- "$FIXTURE" "$2" && : >"$2.err" && return "$STUB_RC"; return 1; }
vtyrun() { cp -- "$FIXTURE" "$1" && : >"$1.err" && return "$STUB_RC"; return 1; }
`

// policyDispatch runs the function named by its first argument, with the rest as its arguments.
const policyDispatch = `fn=$1
shift
"$fn" "$@"
`

// runPolicyLab runs the lab script under bash with exactly env, and returns its exit status and stderr.
// The script checks its port and user namespace before it writes anything, so a run that the check
// refuses leaves no files.
func runPolicyLab(t *testing.T, env ...string) (int, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not on PATH, so the lab preflight cannot run")
	}
	cmd := exec.Command(bash, policyLabScript) //nolint:gosec // G204: bash and the committed lab script are fixed; env is test data.
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	if exit != nil {
		return exit.ExitCode(), stderr.String()
	}
	return 0, stderr.String()
}

// requirePortRefusal runs the lab with env and requires the port refusal: exit 2, the port rule named,
// and scratch not created.
func requirePortRefusal(t *testing.T, scratch string, env ...string) {
	t.Helper()
	code, stderr := runPolicyLab(t, env...)
	if code != 2 || !strings.Contains(stderr, "BGPD_VTY_PORT must be 1 to 65535") {
		t.Errorf("exit %d, want 2 naming the port rule; stderr %q", code, stderr)
	}
	if _, err := os.Stat(scratch); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused port left %s behind: %v", scratch, err)
	}
}

// TestPolicyLabRefusesBadPortBeforeAnyWrite runs the lab's preflight with no port, and with ports it
// must not use. Each run exits 2, names the port rule, and leaves no scratch directory, since the port
// is checked before anything is written. A missing SCRATCH must also fail.
func TestPolicyLabRefusesBadPortBeforeAnyWrite(t *testing.T) {
	scratch := filepath.Join(t.TempDir(), "scratch")
	t.Run("unset port", func(t *testing.T) {
		requirePortRefusal(t, scratch, "SCRATCH="+scratch)
	})
	for _, port := range []string{"", "0", "01", "1x", "123456", "65536", "2604", "2601", "179"} {
		t.Run(fmt.Sprintf("port %q", port), func(t *testing.T) {
			requirePortRefusal(t, scratch, "SCRATCH="+scratch, "BGPD_VTY_PORT="+port)
		})
	}
	t.Run("unset SCRATCH", func(t *testing.T) {
		code, stderr := runPolicyLab(t, "BGPD_VTY_PORT=2605")
		if code == 0 || !strings.Contains(stderr, "set SCRATCH") {
			t.Errorf("exit %d, want nonzero naming SCRATCH; stderr %q", code, stderr)
		}
	})
}

// TestPolicyLabRefusesInitialUserNamespace runs the lab with a valid port in the initial user namespace,
// where its check refuses to run. It must exit 1 and create nothing. The test runs only where the test
// process is in the initial user namespace, since the lab's check admits every other one.
func TestPolicyLabRefusesInitialUserNamespace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the lab's namespace check reads /proc/self/uid_map")
	}
	raw, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		t.Skip("cannot read /proc/self/uid_map")
	}
	if !slices.Equal(strings.Fields(string(raw)), []string{"0", "0", "4294967295"}) {
		t.Skip("the test process is in a user namespace, which the lab's check admits")
	}
	scratch := filepath.Join(t.TempDir(), "scratch")
	code, stderr := runPolicyLab(t, "SCRATCH="+scratch, "BGPD_VTY_PORT=2605")
	if code != 1 || !strings.Contains(stderr, "initial user namespace") {
		t.Errorf("exit %d, want 1 naming the initial user namespace; stderr %q", code, stderr)
	}
	if _, err := os.Stat(scratch); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the refused lab left %s behind: %v", scratch, err)
	}
}

// labFunc returns the definition of the lab's shell function name: the line "name() {" through the
// next line that is exactly "}". The lab's functions close at column 0 with no such line inside.
func labFunc(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, "\n"+name+"() {\n")
	if start < 0 {
		t.Fatalf("the lab script has no function %s", name)
	}
	start++
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("function %s has no closing brace at column 0", name)
	}
	return script[start : start+end+len("\n}\n")]
}

// runCaptureFunc runs the lab's function fn, cap or captxt, with args over a copy of fixture, and returns
// its exit status and the output directory it wrote into. The checker is the real bgp-policy-check.py.
// The harness is a file this test writes under t.TempDir, not a file in the repository.
func runCaptureFunc(t *testing.T, fn, fixture, stubRC string, args ...string) (int, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the lab stamps captures with GNU date %N, which only linux has")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not on PATH, so the lab functions cannot run")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not on PATH, so the policy checker cannot run")
	}
	script, err := os.ReadFile(policyLabScript) //nolint:gosec // G304: a fixed path to a committed lab script.
	if err != nil {
		t.Fatal(err)
	}
	check, err := filepath.Abs(policyCheck)
	if err != nil {
		t.Fatal(err)
	}
	fix, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o750); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(dir, "harness.sh")
	body := policyStub + labFunc(t, string(script), "cap") + labFunc(t, string(script), "captxt") + policyDispatch
	if err := os.WriteFile(harness, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, append([]string{harness, fn}, args...)...) //nolint:gosec // G204: bash runs a harness this test wrote; its arguments are test data.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "OUT=" + out, "CHECK=" + check, "FIXTURE=" + fix, "STUB_RC=" + stubRC}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	t.Logf("%s stderr: %s", fn, stderr.String())
	return code, out
}

// checkCaptureFiles checks one capture base in out. A passing capture keeps its .raw and a UTC stamp,
// and leaves no .raw.failed and no .raw.err. A failing one keeps .raw.failed and .raw.err, and has
// neither a .raw nor a stamp.
func checkCaptureFiles(t *testing.T, base string, passed bool) {
	t.Helper()
	has := func(suffix string) bool {
		_, err := os.Stat(base + suffix)
		return err == nil
	}
	if passed {
		if !has(".raw") || !has(".collected_at") || has(".raw.failed") || has(".raw.err") {
			t.Errorf("%s: want .raw and .collected_at, and no .raw.failed or .raw.err", base)
		}
		stamp, err := os.ReadFile(base + ".collected_at") //nolint:gosec // G304: a stamp in the test's own output directory.
		if err != nil || !utcStamp.Match(stamp) {
			t.Errorf("%s.collected_at = %q, want one UTC stamp line", base, stamp)
		}
		return
	}
	if has(".raw") || has(".collected_at") || !has(".raw.failed") || !has(".raw.err") {
		t.Errorf("%s: want .raw.failed and .raw.err, and no .raw or .collected_at", base)
	}
}

// TestPolicyLabCapturesGradeThroughChecker runs the lab's cap and captxt over committed captures, with
// the real checker. A capture that passes keeps its .raw and stamp. A capture the terms refuse, or whose
// vty call failed, keeps .raw.failed and its .raw.err and no stamp, and the function exits 1.
func TestPolicyLabCapturesGradeThroughChecker(t *testing.T) {
	const table = "show ip bgp json"
	before := filepath.Join(withdrawLab, "r1-before-show_ip_bgp_json.raw")
	shutdown := filepath.Join(sessionLab+"admin", "r1-shutdown.raw")
	passing := append([]string{"before", table}, policyBeforeTable...)
	refused := append([]string{"before", table}, policyAfterTable...)
	bound := []string{"admin", "shutdown", "show running-config", "has:neighbor 10.0.1.2 shutdown"}
	missing := []string{"admin", "shutdown", "show running-config", "has:neighbor 10.0.3.3 route-map R3-IN in"}
	for _, c := range []struct {
		name    string
		fn      string
		fixture string
		stubRC  string
		args    []string
		base    string
		passed  bool
	}{
		{"cap passes the committed before table", "cap", before, "0", passing, "r1-before-show_ip_bgp_json", true},
		{"cap refuses the after terms on the before table", "cap", before, "0", refused, "r1-before-show_ip_bgp_json", false},
		{"cap keeps a capture whose vty call failed", "cap", before, "124", passing, "r1-before-show_ip_bgp_json", false},
		{"captxt passes the committed shutdown transcript", "captxt", shutdown, "0", bound, "r1-admin-shutdown", true},
		{"captxt refuses a binding the transcript lacks", "captxt", shutdown, "0", missing, "r1-admin-shutdown", false},
		{"captxt keeps a capture whose vty call failed", "captxt", shutdown, "1", bound, "r1-admin-shutdown", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out := runCaptureFunc(t, c.fn, c.fixture, c.stubRC, c.args...)
			want := 1
			if c.passed {
				want = 0
			}
			if code != want {
				t.Errorf("exit %d, want %d", code, want)
			}
			checkCaptureFiles(t, filepath.Join(out, c.base), c.passed)
		})
	}
}
