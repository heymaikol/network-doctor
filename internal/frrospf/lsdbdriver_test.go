//go:build linux

package frrospf

import (
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
func lsdbShims() map[string]string {
	shims := maps.Clone(labShims)
	shims["python3"] = `if [ "$2" = -c ]; then exec "$REAL_PYTHON3" "$@"; fi
cmd=$4
echo "vty $3 [$cmd]" >>"$MOCK_LOG"
if [ -n "$MOCK_VTY_FAIL" ]; then
	case "$cmd" in *"$MOCK_VTY_FAIL"*) echo refused >&2; exit 1 ;; esac
fi
body='{"nbrState":"Full/DR"}'
if [ -n "${MOCK_VTY_BODY+x}" ]; then body=$MOCK_VTY_BODY; fi
printf '%s\r\n%s\r\nr1# ' "$cmd" "$body"
`
	return shims
}

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
