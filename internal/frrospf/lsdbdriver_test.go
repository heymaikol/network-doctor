//go:build linux

package frrospf

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// lsdbShims are labShims with a python3 for lsdb.sh. It logs the port of each vty query
// and answers the neighbor poll with a Full neighbor, which lsdb.sh waits for. A -c call
// runs the real python3 at REAL_PYTHON3, so the RIB check reads its real input.
// MOCK_VTY_BODY replaces the answer body, and MOCK_VTY_FAIL makes a matching query fail.
// The answer prints the prompt of the node it runs on: r1, or r2 when nsenter -t reaches
// it, since lsdb.sh reaches r2 only that way. MOCK_RIB_FRAME replaces the whole answer to
// the zebra RIB query. Mock answers copy the committed ospfd shape, so they test the RIB
// framing check and are not zebra evidence.
func lsdbShims() map[string]string {
	shims := maps.Clone(labShims)
	shims["nsenter"] = `echo "nsenter $*" >>"$MOCK_LOG"
if [ "$1" = -t ]; then shift 2; MOCK_NODE=r2; export MOCK_NODE; fi
if [ "$1" = -n ]; then shift; fi
exec "$@"
`
	shims["python3"] = `if [ "$2" = -c ]; then exec "$REAL_PYTHON3" "$@"; fi
cmd=$4
echo "vty $3 [$cmd]" >>"$MOCK_LOG"
if [ -n "$MOCK_VTY_FAIL" ]; then
	case "$cmd" in *"$MOCK_VTY_FAIL"*) echo refused >&2; exit 1 ;; esac
fi
if [ "$cmd" = "show ip route json" ] && [ -n "${MOCK_RIB_FRAME+x}" ]; then
	printf '%s' "$MOCK_RIB_FRAME"
	exit 0
fi
body='{"nbrState":"Full/DR"}'
if [ -n "${MOCK_VTY_BODY+x}" ]; then body=$MOCK_VTY_BODY; fi
printf '%s\r\n%s\r\n%s> ' "$cmd" "$body" "${MOCK_NODE:-r1}"
`
	return shims
}

// ribEcho is the echoed command that starts a zebra RIB answer, with its CRLF.
const ribEcho = "show ip route json\r\n"

// runLSDB runs lab/lsdb.sh for mode in scratch under lsdbShims. The faults are set as for
// runLab.
func runLSDB(t *testing.T, scratch, mode string, faults ...string) labRun {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("..", "..", "testdata", "frr", "10.7.0", "lab", "lsdb.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return runWithShims(t, lsdbShims(), script, scratch, mode, faults...)
}

// realPython returns the host's python3. The RIB check runs it, so a test that reaches the
// check is skipped where there is none.
func realPython(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not on PATH, so the RIB check cannot run")
	}
	return p
}

// bracketCalls returns the vty queries in the shim log, in order, without the neighbor poll.
func bracketCalls(calls []string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, "vty ") && !strings.Contains(c, "neighbor json") {
			out = append(out, c)
		}
	}
	return out
}

// lsdbFile is the path of one file in the steady run's output directory.
func lsdbFile(scratch, name string) string {
	return filepath.Join(scratch, "run", "lsdb-steady", name)
}

// exists reports whether path is present.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// stampOf reads the collected_at stamp at path, which must hold an RFC 3339 time.
func stampOf(t *testing.T, path string) time.Time {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: a capture path this test built under its scratch dir.
	if err != nil {
		t.Fatal(err)
	}
	ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return ts
}

// TestLSDBRejectsBadZebraPortBeforeTouchingFiles gives ZEBRA_VTY_PORT values that are not
// a zebra vty port. Each must exit 2 before any mount, copy, or removal, and before any
// shim runs.
func TestLSDBRejectsBadZebraPortBeforeTouchingFiles(t *testing.T) {
	for _, port := range []string{"", "x", "0", "02601", "65536", "2604"} {
		t.Run(fmt.Sprintf("%q", port), func(t *testing.T) {
			s := newLabScratch(t, "scratch")
			r := runLSDB(t, s, "steady", "ZEBRA_VTY_PORT="+port)
			if r.code != 2 {
				t.Errorf("exit %d, want 2; stderr %q", r.code, r.stderr)
			}
			if len(r.mock) != 1 || r.mock[0] != "" {
				t.Errorf("shims ran for a rejected port: %q", r.mock)
			}
			if _, err := os.Stat(filepath.Join(s, "run")); err == nil {
				t.Errorf("run directory was created for a rejected port")
			}
		})
	}
}

// TestLSDBWithoutZebraPortKeepsTheBracket runs steady with no ZEBRA_VTY_PORT. Each node's
// bracket must be A, B, E, D on the ospfd port, and no zebra version or RIB capture may be
// written.
func TestLSDBWithoutZebraPortKeepsTheBracket(t *testing.T) {
	s := newLabScratch(t, "scratch")
	r := runLSDB(t, s, "steady")
	if r.code != 0 || !strings.Contains(r.stdout, "DONE") {
		t.Fatalf("exit %d, want a finished run; stderr %q", r.code, r.stderr)
	}
	node := []string{
		"vty 2604 [show ip ospf json]",
		"vty 2604 [show ip ospf database detail json]",
		"vty 2604 [show ip ospf route json]",
		"vty 2604 [show ip ospf json]",
	}
	if got := bracketCalls(r.mock); !slices.Equal(got, slices.Concat(node, node)) {
		t.Errorf("vty queries\n got %q\nwant %q", got, slices.Concat(node, node))
	}
	if hasCall(r.mock, "zebra [--version]") {
		t.Errorf("zebra was asked for its version without ZEBRA_VTY_PORT")
	}
	for _, name := range []string{"zebra-version.txt", "r1-R-show_ip_route_json.raw", "r2-R-show_ip_route_json.raw"} {
		if exists(lsdbFile(s, name)) {
			t.Errorf("%s was written without ZEBRA_VTY_PORT", name)
		}
	}
}

// TestLSDBZebraRIBCaptureOrderAndProvenance sets a zebra port and runs steady. Each node's
// bracket must be A, B, E, R, D, with R on the zebra port and the others on the ospfd
// port. zebra's version must sit beside the captures, and R must be stamped between E and D.
func TestLSDBZebraRIBCaptureOrderAndProvenance(t *testing.T) {
	py := realPython(t)
	s := newLabScratch(t, "scratch")
	r := runLSDB(t, s, "steady", "ZEBRA_VTY_PORT=2650", "REAL_PYTHON3="+py)
	if r.code != 0 || !strings.Contains(r.stdout, "DONE") {
		t.Fatalf("exit %d, want a finished run; stderr %q", r.code, r.stderr)
	}
	node := []string{
		"vty 2604 [show ip ospf json]",
		"vty 2604 [show ip ospf database detail json]",
		"vty 2604 [show ip ospf route json]",
		"vty 2650 [show ip route json]",
		"vty 2604 [show ip ospf json]",
	}
	if got := bracketCalls(r.mock); !slices.Equal(got, slices.Concat(node, node)) {
		t.Errorf("vty queries\n got %q\nwant %q", got, slices.Concat(node, node))
	}
	zv, err := os.ReadFile(lsdbFile(s, "zebra-version.txt")) //nolint:gosec // G304: a path this test built under its scratch dir.
	if err != nil || !strings.Contains(string(zv), "zebra") {
		t.Errorf("zebra-version.txt = %q, %v; want the zebra version", zv, err)
	}
	for _, tag := range []string{"r1", "r2"} {
		for _, suffix := range []string{".raw", ".collected_at"} {
			if !exists(lsdbFile(s, tag+"-R-show_ip_route_json"+suffix)) {
				t.Errorf("%s has no R capture %s", tag, suffix)
			}
		}
		// The default answer is a valid frame for this node, and it must be kept byte for byte.
		want := ribEcho + `{"nbrState":"Full/DR"}` + "\r\n" + tag + "> "
		got, err := os.ReadFile(lsdbFile(s, tag+"-R-show_ip_route_json.raw")) //nolint:gosec // G304: a path this test built under its scratch dir.
		if err != nil || string(got) != want {
			t.Errorf("%s R capture = %q, %v; want the valid frame %q", tag, got, err, want)
		}
	}
	e := stampOf(t, lsdbFile(s, "r1-E-show_ip_ospf_route_json.collected_at"))
	rib := stampOf(t, lsdbFile(s, "r1-R-show_ip_route_json.collected_at"))
	d := stampOf(t, lsdbFile(s, "r1-D-show_ip_ospf_json.collected_at"))
	if rib.Before(e) || d.Before(rib) {
		t.Errorf("r1 stamps E %s, R %s, D %s are out of order", e, rib, d)
	}
}

// TestLSDBFailedRIBCaptureIsKeptAndStopsTheBracket makes the zebra query fail. Its output
// must stay as .raw.failed with no marker, the bracket must stop before D, and the run must
// exit nonzero without DONE.
func TestLSDBFailedRIBCaptureIsKeptAndStopsTheBracket(t *testing.T) {
	s := newLabScratch(t, "scratch")
	r := runLSDB(t, s, "steady", "ZEBRA_VTY_PORT=2650", "MOCK_VTY_FAIL=show ip route json")
	mustNotFinish(t, r, "failed RIB capture")
	if !exists(lsdbFile(s, "r1-R-show_ip_route_json.raw.failed")) {
		t.Errorf("failed RIB capture kept no .raw.failed")
	}
	if exists(lsdbFile(s, "r1-R-show_ip_route_json.collected_at")) {
		t.Errorf("failed RIB capture left a .collected_at marker")
	}
	if !exists(lsdbFile(s, "r1-E-show_ip_ospf_route_json.collected_at")) {
		t.Errorf("an earlier good capture lost its marker")
	}
	want := []string{
		"vty 2604 [show ip ospf json]",
		"vty 2604 [show ip ospf database detail json]",
		"vty 2604 [show ip ospf route json]",
		"vty 2650 [show ip route json]",
	}
	if got := bracketCalls(r.mock); !slices.Equal(got, want) {
		t.Errorf("vty queries after a failed RIB capture\n got %q\nwant %q", got, want)
	}
	if !strings.Contains(r.stderr, "r1 bracket failed") {
		t.Errorf("stderr %q does not name the failed bracket", r.stderr)
	}
}

// TestLSDBMalformedRIBCaptureFailsTheBracket answers the zebra query with text that is not
// one JSON object after its echo. The RIB check must reject it like a failed query.
func TestLSDBMalformedRIBCaptureFailsTheBracket(t *testing.T) {
	py := realPython(t)
	s := newLabScratch(t, "scratch")
	r := runLSDB(t, s, "steady", "ZEBRA_VTY_PORT=2650", "REAL_PYTHON3="+py, `MOCK_VTY_BODY="Full/DR"`)
	mustNotFinish(t, r, "malformed RIB capture")
	if !exists(lsdbFile(s, "r1-R-show_ip_route_json.raw.failed")) {
		t.Errorf("malformed RIB capture kept no .raw.failed")
	}
	if exists(lsdbFile(s, "r1-R-show_ip_route_json.raw")) || exists(lsdbFile(s, "r1-R-show_ip_route_json.collected_at")) {
		t.Errorf("malformed RIB capture left a .raw or .collected_at beside its .raw.failed")
	}
	want := []string{
		"vty 2604 [show ip ospf json]",
		"vty 2604 [show ip ospf database detail json]",
		"vty 2604 [show ip ospf route json]",
		"vty 2650 [show ip route json]",
	}
	if got := bracketCalls(r.mock); !slices.Equal(got, want) {
		t.Errorf("vty queries after a malformed RIB capture\n got %q\nwant %q", got, want)
	}
}

// TestLSDBRIBFrameRejectsAnythingButOneFrame gives r1 zebra RIB answers that are not exactly
// the echoed command, CRLF, one JSON object, CRLF, and r1's ">" prompt with nothing after it.
// Each must fail R: the answer stays in .raw.failed unchanged, no marker is written, and the
// bracket stops before D. The cases that the old check accepted come first, and the rest
// were already rejected and stay as guards.
func TestLSDBRIBFrameRejectsAnythingButOneFrame(t *testing.T) {
	py := realPython(t)
	const obj = `{"a":1}`
	for _, c := range []struct{ name, frame string }{
		{"junk after the prompt", ribEcho + obj + "\r\nr1> junk"},
		{"a junk line before the prompt", ribEcho + obj + "\r\njunk\r\nr1> "},
		{"text after the object on its line", ribEcho + obj + "junk\r\nr1> "},
		{"text with no prompt", ribEcho + obj + "\r\ntrailing text"},
		{"junk between the echo and the object", ribEcho + "noise " + obj + "\r\nr1> "},
		{"a blank line before the prompt", ribEcho + obj + "\r\n\r\nr1> "},
		{"no prompt", ribEcho + obj + "\r\n"},
		{"prompt without a space", ribEcho + obj + "\r\nr1>"},
		{"newline after the prompt", ribEcho + obj + "\r\nr1> \r\n"},
		{"enable prompt", ribEcho + obj + "\r\nr1# "},
		{"another node's prompt", ribEcho + obj + "\r\nr2> "},
		{"LF line endings", "show ip route json\n" + obj + "\nr1> "},
		{"junk before the echo", "junk\r\n" + ribEcho + obj + "\r\nr1> "},
		{"truncated object", ribEcho + `{"a":` + "\r\nr1> "},
		{"object cut off with no prompt", ribEcho + `{"a":1`},
		{"two objects on separate lines", ribEcho + obj + "\r\n" + `{"b":2}` + "\r\nr1> "},
		{"two objects on one line", ribEcho + obj + `{"b":2}` + "\r\nr1> "},
		{"a JSON array, not an object", ribEcho + "[1]\r\nr1> "},
		{"another command's echo", "show ip ospf route json\r\n" + obj + "\r\nr1> "},
		{"echo only", ribEcho},
		{"empty answer", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newLabScratch(t, "scratch")
			r := runLSDB(t, s, "steady", "ZEBRA_VTY_PORT=2650", "REAL_PYTHON3="+py, "MOCK_RIB_FRAME="+c.frame)
			mustNotFinish(t, r, c.name)
			got, err := os.ReadFile(lsdbFile(s, "r1-R-show_ip_route_json.raw.failed")) //nolint:gosec // G304: a path this test built under its scratch dir.
			if err != nil {
				t.Fatalf("kept no .raw.failed: %v", err)
			}
			if string(got) != c.frame {
				t.Errorf(".raw.failed = %q, want the answer kept unchanged %q", got, c.frame)
			}
			if exists(lsdbFile(s, "r1-R-show_ip_route_json.raw")) || exists(lsdbFile(s, "r1-R-show_ip_route_json.collected_at")) {
				t.Errorf("failed RIB capture left a .raw or .collected_at beside its .raw.failed")
			}
			if !exists(lsdbFile(s, "r1-E-show_ip_ospf_route_json.collected_at")) {
				t.Errorf("an earlier good capture lost its marker")
			}
			want := []string{
				"vty 2604 [show ip ospf json]",
				"vty 2604 [show ip ospf database detail json]",
				"vty 2604 [show ip ospf route json]",
				"vty 2650 [show ip route json]",
			}
			if calls := bracketCalls(r.mock); !slices.Equal(calls, want) {
				t.Errorf("vty queries after a rejected RIB answer\n got %q\nwant %q", calls, want)
			}
			if !strings.Contains(r.stderr, "capture r1 R failed") {
				t.Errorf("stderr %q does not name the failed R capture", r.stderr)
			}
		})
	}
}

// TestLSDBRIBFramePromptBindsToTheNode gives r1 and r2 the same answer, whose prompt is r1's.
// r1 must keep and stamp its R capture. r2 must fail R, since its prompt is not r2's, and the
// run must stop with r2's bracket named.
func TestLSDBRIBFramePromptBindsToTheNode(t *testing.T) {
	py := realPython(t)
	s := newLabScratch(t, "scratch")
	frame := ribEcho + `{"10.10.2.0/24":[]}` + "\r\nr1> "
	r := runLSDB(t, s, "steady", "ZEBRA_VTY_PORT=2650", "REAL_PYTHON3="+py, "MOCK_RIB_FRAME="+frame)
	mustNotFinish(t, r, "r1's prompt on r2's RIB answer")
	got, err := os.ReadFile(lsdbFile(s, "r1-R-show_ip_route_json.raw")) //nolint:gosec // G304: a path this test built under its scratch dir.
	if err != nil || string(got) != frame {
		t.Errorf("r1 R capture = %q, %v; want the valid frame %q", got, err, frame)
	}
	if !exists(lsdbFile(s, "r1-R-show_ip_route_json.collected_at")) {
		t.Errorf("r1 R capture has no .collected_at")
	}
	got, err = os.ReadFile(lsdbFile(s, "r2-R-show_ip_route_json.raw.failed")) //nolint:gosec // G304: a path this test built under its scratch dir.
	if err != nil || string(got) != frame {
		t.Errorf("r2 R .raw.failed = %q, %v; want the answer kept unchanged %q", got, err, frame)
	}
	if exists(lsdbFile(s, "r2-R-show_ip_route_json.raw")) || exists(lsdbFile(s, "r2-R-show_ip_route_json.collected_at")) {
		t.Errorf("failed r2 RIB capture left a .raw or .collected_at beside its .raw.failed")
	}
	if !strings.Contains(r.stderr, "r2 bracket failed") {
		t.Errorf("stderr %q does not name the failed r2 bracket", r.stderr)
	}
	want := []string{
		"vty 2604 [show ip ospf json]",
		"vty 2604 [show ip ospf database detail json]",
		"vty 2604 [show ip ospf route json]",
		"vty 2650 [show ip route json]",
		"vty 2604 [show ip ospf json]",
		"vty 2604 [show ip ospf json]",
		"vty 2604 [show ip ospf database detail json]",
		"vty 2604 [show ip ospf route json]",
		"vty 2650 [show ip route json]",
	}
	if calls := bracketCalls(r.mock); !slices.Equal(calls, want) {
		t.Errorf("vty queries\n got %q\nwant %q", calls, want)
	}
}

// TestLSDBRIBFrameAcceptsGenuineOSPFDFrames runs the RIB check from lsdb.sh on the committed
// ospfd captures under lsdb and ecmp, which are real daemon output. Each must pass for its own
// node and fail for the other node's name. These frames show only the framing shape. They are
// ospfd output, not zebra's, so they say nothing about zebra's prompt.
func TestLSDBRIBFrameAcceptsGenuineOSPFDFrames(t *testing.T) {
	py := realPython(t)
	lab := filepath.Join("..", "..", "testdata", "frr", "10.7.0")
	script, err := os.ReadFile(filepath.Join(lab, "lab", "lsdb.sh")) //nolint:gosec // G304: the lab script this test locates under the repo.
	if err != nil {
		t.Fatal(err)
	}
	const marker = "RIBOK='"
	start := strings.Index(string(script), marker)
	if start < 0 {
		t.Fatal("lsdb.sh has no RIBOK")
	}
	code, _, ok := strings.Cut(string(script)[start+len(marker):], "'")
	if !ok {
		t.Fatal("RIBOK has no closing quote")
	}
	frames, err := filepath.Glob(filepath.Join(lab, "lsdb", "*", "*.raw"))
	if err != nil {
		t.Fatal(err)
	}
	ecmp, err := filepath.Glob(filepath.Join(lab, "ecmp", "*.raw"))
	if err != nil {
		t.Fatal(err)
	}
	frames = append(frames, ecmp...)
	if len(frames) == 0 {
		t.Fatal("no committed ospfd captures found")
	}
	for _, path := range frames {
		// The name is rN-X-command.raw, with the command's spaces written as underscores.
		node, rest, _ := strings.Cut(strings.TrimSuffix(filepath.Base(path), ".raw"), "-")
		_, name, ok := strings.Cut(rest, "-")
		if !ok || (node != "r1" && node != "r2") {
			t.Fatalf("%s is not rN-X-command.raw", path)
		}
		command := strings.ReplaceAll(name, "_", " ")
		other := "r2"
		if node == "r2" {
			other = "r1"
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			if err := ribCheck(py, code, path, command, node); err != nil {
				t.Errorf("genuine frame rejected for %s: %v", node, err)
			}
			if err := ribCheck(py, code, path, command, other); err == nil {
				t.Errorf("genuine frame accepted for %s, want rejected", other)
			}
		})
	}
}

// ribCheck runs the RIB check code on the bytes at path, with command and node as its
// arguments, as lsdb.sh runs it. It returns nil when the check accepts the bytes.
func ribCheck(py, code, path, command, node string) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: a capture this test found under testdata.
	if err != nil {
		return err
	}
	cmd := exec.Command(py, "-I", "-c", code, command, node) //nolint:gosec // G204: py is the host python3 that realPython found, and the other arguments are test data.
	cmd.Stdin = bytes.NewReader(b)
	return cmd.Run()
}
