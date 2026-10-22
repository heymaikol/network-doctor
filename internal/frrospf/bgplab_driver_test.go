//go:build linux

package frrospf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The BGP lab scripts lab/bgp-session.sh and lab/bgp-withdraw.sh need FRR, root-less namespaces,
// and a live vty, so these tests do not run them through a daemon. Each test either runs a script
// that stops before any daemon starts, or runs one function copied out of a script with its vty
// and clock stubbed. The frames are committed captures and edits of them. The checks are offline.
// They show framing, failure paths, and the order of the finish. They do not show zebra's output.

// labBGPScripts are the two scripts that take ZEBRA_VTY_PORT.
var labBGPScripts = []string{"bgp-session.sh", "bgp-withdraw.sh"}

// labBGPPath returns the path of one lab script.
func labBGPPath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "frr", "10.7.0", "lab", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// labBGPText returns the text of one lab script.
func labBGPText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(labBGPPath(t, name)) //nolint:gosec // G304: a lab script this test locates under the repo.
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// labBGPFunc returns the definition of the shell function name in script, from its "name() {"
// line through the "}" that closes it at column 0.
func labBGPFunc(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, "\n"+name+"() {")
	if start < 0 {
		t.Fatalf("no function %s", name)
	}
	start++
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("function %s has no closing brace", name)
	}
	return script[start : start+end+len("\n}")]
}

// labBGPCheck returns the Python of the BGPOK checker in script. It takes a capture file, the
// command the capture must echo, and the node whose prompt must end it.
func labBGPCheck(t *testing.T, script string) string {
	t.Helper()
	const marker = "BGPOK='"
	start := strings.Index(script, marker)
	if start < 0 {
		t.Fatal("script has no BGPOK")
	}
	code, _, ok := strings.Cut(script[start+len(marker):], "'")
	if !ok {
		t.Fatal("BGPOK has no closing quote")
	}
	return code
}

// labBGPOK runs the checker code on the capture at path, as the script runs it. It returns nil
// when the checker accepts the file.
func labBGPOK(py, code, path, command, node string) error {
	return exec.Command(py, "-I", "-c", code, path, command, node).Run() //nolint:gosec // G204: py is the host python3 that realPython found, and the other arguments are test data.
}

// labBGPHarness runs bash with set -u, the setup text, the named functions of script, and the
// body. The environment is PATH plus env, so nothing else from the test process reaches it.
func labBGPHarness(t *testing.T, script string, names []string, setup, body string, env ...string) labRun {
	t.Helper()
	var text strings.Builder
	text.WriteString("set -u\n" + setup + "\n")
	for _, n := range names {
		text.WriteString(labBGPFunc(t, script, n) + "\n")
	}
	text.WriteString(body + "\n")
	cmd := exec.Command("bash", "-c", text.String()) //nolint:gosec // G204: bash runs fixed harness text and functions copied from a lab script the test locates.
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run harness: %v", err)
		}
		code = ee.ExitCode()
	}
	return labRun{stdout: out.String(), stderr: errb.String(), code: code}
}

// labBGPOutDir makes a run directory holding files, as the lab leaves it before sums runs.
func labBGPOutDir(t *testing.T, files map[string]string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(out, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(out, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestLabBGPRefusesBadPortsBeforeTouchingFiles gives each script a port, or for the session
// script an ARM, that it must refuse. Each must exit 2 before any shim runs or any run directory
// is made. A valid port pair with ZEBRA_VTY_PORT unset must not be refused, so the refusals are
// not vacuous.
func TestLabBGPRefusesBadPortsBeforeTouchingFiles(t *testing.T) {
	refused := [][]string{
		{"BGPD_VTY_PORT="}, {"BGPD_VTY_PORT=x"}, {"BGPD_VTY_PORT=0"}, {"BGPD_VTY_PORT=02650"},
		{"BGPD_VTY_PORT=65536"}, {"BGPD_VTY_PORT=179"}, {"BGPD_VTY_PORT=2604"}, {"BGPD_VTY_PORT=2601"},
		{"ZEBRA_VTY_PORT="}, {"ZEBRA_VTY_PORT=x"}, {"ZEBRA_VTY_PORT=0"}, {"ZEBRA_VTY_PORT=02650"},
		{"ZEBRA_VTY_PORT=65536"}, {"ZEBRA_VTY_PORT=179"}, {"ZEBRA_VTY_PORT=2604"}, {"ZEBRA_VTY_PORT=2650"},
	}
	for _, name := range labBGPScripts {
		path := labBGPPath(t, name)
		cases := slices.Clone(refused)
		if name == "bgp-session.sh" {
			cases = append(cases, []string{"ARM="}, []string{"ARM=PLAIN"})
		}
		for _, c := range cases {
			t.Run(name+" "+strings.Join(c, " "), func(t *testing.T) {
				s := newLabScratch(t, "scratch")
				faults := append([]string{"BGPD_VTY_PORT=2650", "ARM=plain"}, c...)
				r := runWithShims(t, labShims, path, s, "", faults...)
				if r.code != 2 {
					t.Errorf("exit %d, want 2; stderr %q", r.code, r.stderr)
				}
				if len(r.mock) != 1 || r.mock[0] != "" {
					t.Errorf("shims ran for a refused run: %q", r.mock)
				}
				if exists(filepath.Join(s, "run")) {
					t.Errorf("run directory was created for a refused run")
				}
			})
		}
		t.Run(name+" valid ports", func(t *testing.T) {
			s := newLabScratch(t, "scratch")
			r := runWithShims(t, labShims, path, s, "", "BGPD_VTY_PORT=2650", "ARM=plain")
			if r.code == 2 || strings.Contains(r.stderr, "must be") {
				t.Errorf("valid ports refused: exit %d, stderr %q", r.code, r.stderr)
			}
		})
	}
}

// TestLabBGPFramingAcceptsGenuineFramesAndRejectsEdits runs each script's BGPOK checker on the
// committed r1 captures and on edits of one frame. Each committed capture must pass for r1 and
// fail for r2. Each edit must fail, and the unedited frame must pass. These frames are bgpd
// output, so the test shows framing only, not zebra's.
func TestLabBGPFramingAcceptsGenuineFramesAndRejectsEdits(t *testing.T) {
	py := realPython(t)
	lab := filepath.Join("..", "..", "testdata", "frr", "10.7.0", "bgp")
	frames, err := filepath.Glob(filepath.Join(lab, "session", "*", "r1-*-show_ip_bgp*.raw"))
	if err != nil {
		t.Fatal(err)
	}
	more, err := filepath.Glob(filepath.Join(lab, "withdraw", "r1-*-show_ip_bgp*.raw"))
	if err != nil {
		t.Fatal(err)
	}
	frames = append(frames, more...)
	if len(frames) < 4 {
		t.Fatalf("found %d committed r1 captures, want the session and withdrawal ones", len(frames))
	}
	const echo = "show ip bgp json"
	const obj = `{"a":1}`
	edits := []struct {
		name, frame string
		want        bool
	}{
		{"one object", echo + "\r\n" + obj + "\r\nr1> ", true},
		{"LF line ends", echo + "\n" + obj + "\nr1> ", false},
		{"junk after the prompt", echo + "\r\n" + obj + "\r\nr1> junk", false},
		{"no prompt", echo + "\r\n" + obj + "\r\n", false},
		{"another node's prompt", echo + "\r\n" + obj + "\r\nr2> ", false},
		{"two objects", echo + "\r\n" + obj + obj + "\r\nr1> ", false},
		{"duplicate key", echo + "\r\n" + `{"a":1,"a":2}` + "\r\nr1> ", false},
		{"NaN", echo + "\r\n" + `{"a":NaN}` + "\r\nr1> ", false},
		{"a JSON array", echo + "\r\n[1]\r\nr1> ", false},
		{"another command's echo", "show ip ospf json\r\n" + obj + "\r\nr1> ", false},
		{"empty answer", "", false},
	}
	for _, name := range labBGPScripts {
		code := labBGPCheck(t, labBGPText(t, name))
		for _, path := range frames {
			// The name is rN-PHASE-command.raw, with the command's spaces written as underscores.
			base := strings.TrimSuffix(filepath.Base(path), ".raw")
			_, rest, _ := strings.Cut(base, "-")
			_, cmdName, ok := strings.Cut(rest, "-")
			if !ok {
				t.Fatalf("%s is not rN-PHASE-command.raw", path)
			}
			command := strings.ReplaceAll(cmdName, "_", " ")
			t.Run(name+" "+base, func(t *testing.T) {
				if err := labBGPOK(py, code, path, command, "r1"); err != nil {
					t.Errorf("committed capture rejected for r1: %v", err)
				}
				if err := labBGPOK(py, code, path, command, "r2"); err == nil {
					t.Errorf("committed capture accepted for r2")
				}
			})
		}
		for _, e := range edits {
			t.Run(name+" "+e.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "frame.raw")
				if err := os.WriteFile(path, []byte(e.frame), 0o600); err != nil {
					t.Fatal(err)
				}
				if got := labBGPOK(py, code, path, echo, "r1") == nil; got != e.want {
					t.Errorf("accepted = %v, want %v for %q", got, e.want, e.frame)
				}
			})
		}
	}
}

// TestLabBGPCaptureKeepsFailedFramesAsRaw runs capture from each script with a query that copies
// a frame and exits with a given status. An accepted frame must leave its .raw and .collected_at.
// An edited frame, or a query that exits 124, must leave .raw.failed holding the bytes unchanged,
// with no .raw or .collected_at beside it.
func TestLabBGPCaptureKeepsFailedFramesAsRaw(t *testing.T) {
	realPython(t)
	genuine, err := os.ReadFile(filepath.Join("..", "..", "testdata", "frr", "10.7.0", "bgp", "session", "plain", "r1-before-show_ip_bgp_json.raw")) //nolint:gosec // G304: a committed fixture path under the repo.
	if err != nil {
		t.Fatal(err)
	}
	edited := []byte("show ip bgp json\n{}\nr1> ")
	for _, c := range []struct {
		name  string
		frame []byte
		rc    string
		want  bool
	}{
		{"genuine frame", genuine, "0", true},
		{"edited frame", edited, "0", false},
		{"query exits 124", genuine, "124", false},
	} {
		for _, name := range labBGPScripts {
			t.Run(name+" "+c.name, func(t *testing.T) {
				script := labBGPText(t, name)
				out := labBGPOutDir(t, nil)
				frame := filepath.Join(t.TempDir(), "frame.raw")
				if err := os.WriteFile(frame, c.frame, 0o600); err != nil {
					t.Fatal(err)
				}
				r := labBGPHarness(t, script, []string{"capture"},
					`query() { cp "$FRAME_SRC" "$2"; return "${QUERY_RC:-0}"; }`,
					`capture 2650 before "show ip bgp json"`,
					"OUT="+out, "FRAME_SRC="+frame, "QUERY_RC="+c.rc, "BGPOK="+labBGPCheck(t, script))
				base := filepath.Join(out, "r1-before-show_ip_bgp_json")
				if got := r.code == 0; got != c.want {
					t.Errorf("capture accepted = %v, want %v; stderr %q", got, c.want, r.stderr)
				}
				if c.want {
					if !exists(base+".raw") || !exists(base+".collected_at") || exists(base+".raw.failed") {
						t.Errorf("accepted capture lacks its .raw or .collected_at, or has a .raw.failed")
					}
					return
				}
				if exists(base+".raw") || exists(base+".collected_at") {
					t.Errorf("failed capture left a .raw or .collected_at beside its .raw.failed")
				}
				got, err := os.ReadFile(base + ".raw.failed") //nolint:gosec // G304: a path this test built under its temp dir.
				if err != nil || !bytes.Equal(got, c.frame) {
					t.Errorf(".raw.failed = %q, %v; want the bytes kept unchanged %q", got, err, c.frame)
				}
			})
		}
	}
}

// TestLabBGPKernelFailureLeavesNoStamp fails the stamp write of a kernel capture after the stamp
// file has been created. The capture must fail, keep its output as .json.failed, and leave no
// .collected_at beside it. With a working stamp the same capture must pass.
func TestLabBGPKernelFailureLeavesNoStamp(t *testing.T) {
	realPython(t)
	for _, name := range labBGPScripts {
		for _, c := range []struct {
			name, setup string
			want        bool
		}{
			{"stamp written", "ip() { echo '[]'; }", true},
			{"stamp write fails", "ip() { echo '[]'; }\nprintf() { echo partial; return 1; }", false},
		} {
			t.Run(name+" "+c.name, func(t *testing.T) {
				out := labBGPOutDir(t, nil)
				r := labBGPHarness(t, labBGPText(t, name), []string{"kernel"}, c.setup, "kernel before", "OUT="+out)
				base := filepath.Join(out, "r1-before-ip_route")
				if got := r.code == 0; got != c.want {
					t.Errorf("kernel accepted = %v, want %v; stderr %q", got, c.want, r.stderr)
				}
				if c.want {
					if !exists(base+".json") || !exists(base+".collected_at") {
						t.Errorf("accepted kernel capture lacks its .json or .collected_at")
					}
					return
				}
				if exists(base + ".collected_at") {
					t.Errorf("failed stamp left a .collected_at beside the failed capture")
				}
				if exists(base+".json") || !exists(base+".json.failed") {
					t.Errorf("failed kernel capture was not kept as .json.failed")
				}
			})
		}
	}
}

// TestLabBGPSumsWaitsForStoppedPIDs runs sums with the pids that stop would have signaled. A live
// pid must make it fail and write no SHA256SUMS. Once the pids are gone it must write the manifest
// of the run's files, leaving out the poll and error files.
func TestLabBGPSumsWaitsForStoppedPIDs(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum is not installed")
	}
	const setup = "sleep() { :; }\nfail() { echo \"lab: $*\" >&2; exit 1; }"
	files := map[string]string{"b.txt": "b\n", "a.txt": "a\n", "poll-r1-table.last": "p\n", "x.raw.err": "e\n"}
	for _, name := range labBGPScripts {
		script := labBGPText(t, name)
		t.Run(name+" live pid", func(t *testing.T) {
			out := labBGPOutDir(t, files)
			pid, _ := startSacrificial(t)
			r := labBGPHarness(t, script, []string{"sums"}, fmt.Sprintf("%s\nSTOPPED=%d", setup, pid), "sums", "OUT="+out)
			if r.code == 0 || !strings.Contains(r.stderr, "outlived SIGTERM") {
				t.Errorf("exit %d, want a refusal naming the live pid; stderr %q", r.code, r.stderr)
			}
			if exists(filepath.Join(out, "SHA256SUMS")) {
				t.Errorf("SHA256SUMS written while a stopped pid was alive")
			}
		})
		t.Run(name+" stopped pids", func(t *testing.T) {
			out := labBGPOutDir(t, files)
			dead := exec.Command("true")
			if err := dead.Run(); err != nil {
				t.Fatal(err)
			}
			r := labBGPHarness(t, script, []string{"sums"}, fmt.Sprintf("%s\nSTOPPED=%d", setup, dead.Process.Pid), "sums", "OUT="+out)
			if r.code != 0 {
				t.Fatalf("exit %d, want the manifest written; stderr %q", r.code, r.stderr)
			}
			manifest, err := os.ReadFile(filepath.Join(out, "SHA256SUMS")) //nolint:gosec // G304: a path this test built under its temp dir.
			if err != nil {
				t.Fatal(err)
			}
			var listed []string
			for _, l := range nonBlankLines(manifest) {
				f := strings.Fields(l)
				listed = append(listed, f[len(f)-1])
			}
			if want := []string{"a.txt", "b.txt"}; !slices.Equal(listed, want) {
				t.Errorf("SHA256SUMS lists %q, want %q", listed, want)
			}
		})
	}
}

// TestLabBGPSumsRunsAfterTheLastStop is a static check. Each script must call sums after its last
// stop, and sums must not read pid files under /run/frr, which the lab does not rely on a daemon to
// keep.
func TestLabBGPSumsRunsAfterTheLastStop(t *testing.T) {
	for _, name := range labBGPScripts {
		script := labBGPText(t, name)
		if strings.Contains(labBGPFunc(t, script, "sums"), "/run/frr") {
			t.Errorf("%s: sums reads pid files under /run/frr", name)
		}
		stopAt := strings.LastIndex(script, "\nstop\n")
		sumsAt := strings.Index(script, "then sums; fi")
		if stopAt < 0 || sumsAt < stopAt {
			t.Errorf("%s: sums is not called after the last stop", name)
		}
	}
}
