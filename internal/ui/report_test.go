// Report rendering and export: sanitization, IPv6 bracketing, the OSC 52
// copy path, and save fallbacks.

package ui

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// captureStderr swaps os.Stderr for a pipe and returns a func that restores
// it and yields everything written, which is how the tests see OSC 52 output.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	return func() string {
		os.Stderr = old
		_ = w.Close()
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

func TestCopyReportWritesOSC52(t *testing.T) {
	t.Setenv("TMUX", "")
	done := captureStderr(t)

	notice, ok := exportReport("hello", false)
	if got, want := done(), "\x1b]52;c;aGVsbG8=\a"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
	if !ok || notice != "report sent to clipboard (OSC 52); w saves a file" {
		t.Fatalf("exportReport() = %q, %v", notice, ok)
	}
}

func TestWriteFileExclRefusesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.txt")
	if err := writeFileExcl(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeFileExcl(path, []byte("second"), 0o600); err == nil {
		t.Fatal("second write succeeded, want O_EXCL collision error")
	}
}

func TestExportReportSavePath(t *testing.T) {
	oldWriteFile, oldUserHomeDir := reportWriteFile, reportUserHomeDir
	t.Cleanup(func() { reportWriteFile, reportUserHomeDir = oldWriteFile, oldUserHomeDir })

	home := t.TempDir()
	var paths []string
	reportWriteFile = func(path string, data []byte, perm os.FileMode) error {
		paths = append(paths, path)
		if len(paths) == 1 {
			return os.ErrPermission
		}
		if string(data) != "hello" || perm != 0o600 {
			t.Errorf("write data = %q, mode = %o", data, perm)
		}
		return nil
	}
	reportUserHomeDir = func() (string, error) { return home, nil }

	notice, ok := exportReport("hello", true)
	if !ok || len(paths) != 2 {
		t.Fatalf("exportReport() = %q, %v; writes = %v", notice, ok, paths)
	}
	saved := strings.TrimPrefix(notice, "report saved to ")
	if !filepath.IsAbs(paths[0]) || !filepath.IsAbs(saved) || filepath.Dir(saved) != home || saved != paths[1] {
		t.Errorf("saved path = %q, writes = %v, want absolute home path", saved, paths)
	}
}

func TestOSC52Sequence(t *testing.T) {
	tests := []struct {
		name string
		tmux string
		want string
	}{
		{name: "terminal", want: "\x1b]52;c;aGVsbG8=\a"},
		{name: "tmux", tmux: "tmux", want: "\x1bPtmux;\x1b\x1b]52;c;aGVsbG8=\a\x1b\\"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TMUX", tt.tmux)
			if got := osc52Sequence("hello"); got != tt.want {
				t.Errorf("osc52Sequence() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReportSanitized(t *testing.T) {
	tgt, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(tgt, false)
	for _, p := range m.probes {
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Detail: "ok"}
	}
	m.results[m.probes[0].ID] = diagnostic.ProbeResult{
		ID:     m.probes[0].ID,
		Status: diagnostic.StatusFail,
		// No escapes here: probe results arrive sanitized from BuildProbesFromSources
		// (see TestCleanResultScrubsEveryTextField). Tool output is the one
		// thing report() still cleans itself.
		Detail: "boom red",
		Fix:    "restart it",
		Attempts: []diagnostic.Attempt{
			{IP: net.ParseIP("93.184.216.34"), Dur: 12 * time.Millisecond, Err: errors.New("refused")},
		},
	}
	for i := 0; i < 16; i++ {
		m.cur.lines = append(m.cur.lines, fmt.Sprintf("line %02d", i))
	}
	m.cur.lines = append(m.cur.lines,
		"ssh banner on stderr",
		"result 200\x1b[31m",
	)
	m.cur.status = JobDone
	m.cur.display = "curl https://example.com"

	rep := m.report()
	for _, want := range []string{
		"version: test",
		"os: ",
		"review before sharing",
		"target: example.com:443",
		"verdict: FAIL",
		"boom red",
		"fix: restart it",
		"attempt: 93.184.216.34 12ms refused",
		"tool output ($ curl https://example.com)",
		"status: done",
		"output tail: 15 of 18 retained lines",
		"line 03",
		"ssh banner on stderr",
		"result 200",
		"curl https://example.com",
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("report missing %q\n%s", want, rep)
		}
	}
	for _, unwanted := range []string{"line 00", "line 01", "line 02"} {
		if strings.Contains(rep, unwanted) {
			t.Errorf("report unexpectedly contains %q\n%s", unwanted, rep)
		}
	}
	if strings.ContainsRune(rep, 0x1b) {
		t.Errorf("escape byte leaked into report:\n%q", rep)
	}
}

func TestReportBracketsIPv6(t *testing.T) {
	tgt, err := diagnostic.ParseTarget("[2001:db8::1]:443")
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(tgt, false)
	for _, p := range m.probes {
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
	}
	if rep := m.report(); !strings.Contains(rep, "target: [2001:db8::1]:443") {
		t.Errorf("IPv6 target not bracketed:\n%s", rep)
	}
}

func TestReportVerdictPass(t *testing.T) {
	m := newModel(nil, false)
	for _, p := range m.probes {
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
	}
	rep := m.report()
	if !strings.Contains(rep, "verdict: PASS") || !strings.Contains(rep, "target: none") {
		t.Errorf("bad generic pass report:\n%s", rep)
	}
}

func TestReportIncludesTimedOutToolOutput(t *testing.T) {
	m := newModel(nil, false)
	m.cur.status = JobTimedOut
	m.cur.display = "ping example.com"
	m.cur.dur = 12 * time.Second
	m.cur.lines = []string{"reply before timeout"}

	if rep := m.report(); !strings.Contains(rep, "tool output ($ ping example.com):\n  status: timed out\n  duration: 12s") ||
		!strings.Contains(rep, "    reply before timeout") {
		t.Errorf("timed-out tool output missing from report:\n%s", rep)
	}
}

func TestReportIncludesEveryToolTail(t *testing.T) {
	m := newModel(nil, false)
	m.cur = jobState{
		status: JobDone, display: "ping selected.example", dur: 1500 * time.Millisecond,
		lines: []string{"selected output"},
	}
	m.otherJobs = []jobState{
		{status: JobFailed, display: "curl other.example", dur: 2 * time.Second},
		{status: JobCanceled, display: "mtr final.example", dur: 3 * time.Second, lines: []string{"final output"}},
	}
	m.otherJobs[0].lines = make([]string, 16)
	for i := range m.otherJobs[0].lines {
		m.otherJobs[0].lines[i] = fmt.Sprintf("tail line %02d", i)
	}
	m.otherJobs[0].evicted, m.otherJobs[0].dropped = 4, 2

	rep := m.report()
	for _, want := range []string{
		"tool output ($ ping selected.example):",
		"duration: 1.5s",
		"tool output ($ curl other.example):",
		"status: failed",
		"output tail: 15 of 16 retained lines (4 evicted, 2 dropped)",
		"tail line 01",
		"tool output ($ mtr final.example):",
		"status: canceled",
		"final output",
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("report missing %q\n%s", want, rep)
		}
	}
	if strings.Contains(rep, "tail line 00") {
		t.Errorf("report contains output before per-job tail:\n%s", rep)
	}
}

func TestRestartClearsToolOutputFromReport(t *testing.T) {
	m := newModel(mustTarget(t, "example.com"), false)
	m.cur.display = "ping old.example"
	m.cur.lines = []string{"reply from old.example"}
	m.doRestart()

	if rep := m.report(); strings.Contains(rep, "old.example") {
		t.Errorf("restarted report contains previous tool output:\n%s", rep)
	}
}

// The shareable report and the Details pane both hide a passing row's fix, and
// a working http:// proxy is a passing row. Pin that the cleartext observation
// is the one exception, so the advice the probe wrote is actually read.
func TestCleartextProxyAdviceIsVisibleOnAPassingRow(t *testing.T) {
	tgt, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(tgt, false)
	doneResults(&m, "")
	const advice = "an http:// proxy sends the CONNECT destination hostname in cleartext"
	if _, ok := m.results[diagnostic.ProbeProxy]; !ok {
		t.Fatalf("the proxy row is not in this run's probe set")
	}
	m.results[diagnostic.ProbeProxy] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeProxy, Status: diagnostic.StatusPass,
		Detail: "proxy tunnels; the CONNECT destination hostname is sent to the proxy without TLS",
		Fix:    advice, ConnectCleartext: true,
	}
	// An ordinary passing row keeps its fix hidden, which is what makes the
	// proxy row's visibility a decision rather than a blanket change.
	other := m.probes[0].ID
	if other == diagnostic.ProbeProxy {
		other = m.probes[1].ID
	}
	m.results[other] = diagnostic.ProbeResult{
		ID: other, Status: diagnostic.StatusPass, Detail: "ok", Fix: "not shown for a pass",
	}

	rep := m.report()
	if !strings.Contains(rep, "fix: "+advice) {
		t.Errorf("the shareable report hid the cleartext advice:\n%s", rep)
	}
	if strings.Contains(rep, "not shown for a pass") {
		t.Errorf("an ordinary passing row started printing its fix:\n%s", rep)
	}

	for i, p := range m.probes {
		if p.ID == diagnostic.ProbeProxy {
			m.selected = i
		}
	}
	details := ansi.Strip(strings.Join(m.detailRows(false), "\n"))
	if !strings.Contains(details, "Fix: "+advice) {
		t.Errorf("the Details pane hid the cleartext advice:\n%s", details)
	}
}
