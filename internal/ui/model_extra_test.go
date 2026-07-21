// Update-loop odds and ends: the output ring buffer, tool builders, actions
// deferred behind a live job, stale-message drops, and view rendering.

package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func TestAppendJobLine(t *testing.T) {
	var m model
	for i := 0; i < maxJobLines+50; i++ {
		m.appendJobLine("x")
	}
	if len(m.jobLines) != maxJobLines {
		t.Errorf("len = %d, want cap %d", len(m.jobLines), maxJobLines)
	}
	// Ring evictions are counted separately from channel-overflow drops.
	if m.jobEvicted != 50 {
		t.Errorf("jobEvicted = %d, want 50", m.jobEvicted)
	}
	if m.jobDropped != 0 {
		t.Errorf("jobDropped = %d, want 0 — evictions must not touch it", m.jobDropped)
	}
	m.appendJobLine("newest")
	if last := m.jobLines[len(m.jobLines)-1]; last != "newest" {
		t.Errorf("last = %q, want newest line kept", last)
	}
	if len(m.jobLines) != maxJobLines || m.jobEvicted != 51 {
		t.Errorf("len=%d evicted=%d, want %d and 51", len(m.jobLines), m.jobEvicted, maxJobLines)
	}
}

func TestToolBuildCurlScheme(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"http://example.com", "http"},
		{"https://example.com", "https"},
		{"example.com:9999", "https"}, // ProtoNone defaults to https (ssh/smtp targets get their own tool)
	}
	for _, c := range cases {
		target := mustTarget(t, c.target)
		var curl Tool
		for _, tool := range toolsFor(target, "linux") {
			if tool.Key == "c" {
				curl = tool
				break
			}
		}
		args, _, _ := curl.Build(target)
		if got := args[len(args)-1]; !strings.HasPrefix(got, c.want+"://") {
			t.Errorf("curl URL for %q = %q, want %q scheme", c.target, got, c.want)
		}
	}
}

func TestNetworkLine(t *testing.T) {
	m := newModel(nil, false)
	if got := m.networkLine(); got != "" {
		t.Errorf("no iface result → %q, want empty", got)
	}
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Network: "HomeWiFi"}
	if got := m.networkLine(); got != "Wi-Fi: HomeWiFi" {
		t.Errorf("wifi line = %q", got)
	}
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Iface: "eth0"}
	if got := m.networkLine(); got != "Wired: eth0" {
		t.Errorf("wired line = %q", got)
	}
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusFail, Iface: "eth0"}
	if got := m.networkLine(); got != "" {
		t.Errorf("failed iface → %q, want empty", got)
	}
}

func TestGlyph(t *testing.T) {
	m := newModel(nil, false)
	if got := m.glyph(diagnostic.ProbeIface); !strings.ContainsRune(got, '·') {
		t.Errorf("queued glyph = %q, want faint dot", got)
	}
	m.started[diagnostic.ProbeIface] = true
	if got := m.glyph(diagnostic.ProbeIface); got != m.spinner.View() {
		t.Errorf("running glyph = %q, want spinner %q", got, m.spinner.View())
	}
	cases := []struct {
		status diagnostic.Status
		want   rune
	}{
		{diagnostic.StatusPass, '✓'},
		{diagnostic.StatusWarn, '!'},
		{diagnostic.StatusFail, '✗'},
		{diagnostic.StatusSkip, '⊘'},
		{diagnostic.StatusNA, '–'},
		{diagnostic.Status(255), '?'},
	}
	for _, c := range cases {
		m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: c.status}
		if got := m.glyph(diagnostic.ProbeIface); !strings.ContainsRune(got, c.want) {
			t.Errorf("glyph(%d) = %q, want to contain %q", c.status, got, c.want)
		}
	}
}

func TestJobStatusString(t *testing.T) {
	cases := []struct {
		s    JobStatus
		want string
	}{
		{JobQueued, "queued"},
		{JobRunning, "running"},
		{JobDone, "done"},
		{JobFailed, "failed"},
		{JobCanceled, "canceled"},
		{JobTimedOut, "timed out"},
		{JobStatus(99), "?"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("JobStatus(%d) = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestJobStatusLineShowsMilliseconds(t *testing.T) {
	m := newModel(nil, false)
	m.jobStatus, m.jobDur = JobDone, 40*time.Millisecond
	if got := m.jobStatusLine(); !strings.Contains(got, "40ms") {
		t.Errorf("jobStatusLine() = %q, want 40ms", got)
	}
}

// classifyJob is success-wins, then consults the context cause only on error.
func TestClassifyJob(t *testing.T) {
	if got := classifyJob(context.Background(), nil); got != JobDone {
		t.Errorf("nil err = %v, want JobDone", got)
	}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := classifyJob(cctx, errors.New("x")); got != JobCanceled {
		t.Errorf("canceled ctx = %v, want JobCanceled", got)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer dcancel()
	<-dctx.Done()
	if got := classifyJob(dctx, errors.New("x")); got != JobTimedOut {
		t.Errorf("deadline ctx = %v, want JobTimedOut", got)
	}
	if got := classifyJob(context.Background(), errors.New("boom")); got != JobFailed {
		t.Errorf("plain err = %v, want JobFailed", got)
	}
}

// ---- tool construction ----

// toolsFor builds the curl argv with the right URL (scheme + explicit port) and
// sets LC_ALL=C via env, never as an argv token.
func TestToolBuildCurl(t *testing.T) {
	tg := mustTarget(t, "https://example.com:8443")
	var curl Tool
	for _, tl := range toolsFor(tg, "linux") {
		if tl.Key == "c" {
			curl = tl
		}
	}
	if curl.Key == "" {
		t.Fatal("curl tool not offered for an https target")
	}
	args, env, display := curl.Build(tg)
	if !strings.Contains(display, "https://example.com:8443") {
		t.Errorf("display = %q, want the explicit-port https URL", display)
	}
	if args[len(args)-1] != "https://example.com:8443" {
		t.Errorf("last arg = %q, want the URL", args[len(args)-1])
	}
	if !containsEnv(env, "LC_ALL=C") {
		t.Error("curl must set LC_ALL=C in env, not argv")
	}
}

func TestToolBuildPingHost(t *testing.T) {
	tg := mustTarget(t, "example.com")
	var ping Tool
	for _, tl := range toolsFor(tg, "linux") {
		if tl.Key == "p" {
			ping = tl
		}
	}
	args, _, _ := ping.Build(tg)
	if args[len(args)-1] != "example.com" {
		t.Errorf("ping last arg = %q, want host", args[len(args)-1])
	}
}

func containsEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

// ---- message routing & deferred actions ----

// 'q' while a job runs cancels it and defers the quit; the terminal event then
// performs it.
func TestDeferredQuit(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), true)
	m.generation = 3
	canceled := false
	m.activeJob = &job{id: "j", cancel: func() { canceled = true }}

	u, cmd := m.Update(keyMsg("q"))
	nm := asModel(t, u)
	if nm.pending == nil || nm.pending.kind != pendQuit {
		t.Fatal("q during a job must defer a quit")
	}
	if !canceled {
		t.Error("the active job must be canceled")
	}
	if cmd != nil {
		t.Error("deferred quit must not quit immediately")
	}

	u2, cmd2 := nm.Update(ToolDoneMsg{JobID: "j", Generation: 3, Status: JobCanceled})
	nm2 := asModel(t, u2)
	if nm2.activeJob != nil {
		t.Error("active job must clear on the terminal event")
	}
	if cmd2 == nil {
		t.Fatal("terminal event must run the deferred quit")
	}
	if _, ok := cmd2().(tea.QuitMsg); !ok {
		t.Errorf("deferred quit cmd = %T, want tea.QuitMsg", cmd2())
	}
	if ExitCode(u2) != 0 {
		t.Error("deferred quit from toolbox mode must exit 0")
	}
}

// Committing the restart prompt while a job runs cancels it and defers the
// restart; the terminal event bumps the generation.
func TestDeferredRestart(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), false)
	m.generation = 3
	canceled := false
	m.activeJob = &job{id: "j", cancel: func() { canceled = true }}

	u, _ := m.Update(keyMsg("r"))
	nm := asModel(t, u)
	if !nm.entering {
		t.Fatal("r must open the restart prompt")
	}
	if canceled {
		t.Error("opening the prompt must not cancel the job")
	}
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm = asModel(t, u)
	if nm.pending == nil || nm.pending.kind != pendRestart {
		t.Fatal("committing during a job must defer a restart")
	}
	if !canceled {
		t.Error("committing must cancel the active job")
	}

	u2, cmd2 := nm.Update(ToolDoneMsg{JobID: "j", Generation: 3, Status: JobCanceled})
	nm2 := asModel(t, u2)
	if nm2.generation != 4 {
		t.Errorf("generation = %d, want 4 after deferred restart", nm2.generation)
	}
	if cmd2 == nil {
		t.Error("deferred restart must issue a reschedule cmd")
	}
}

// A target entered during an active job must not be applied until the job's
// terminal event runs the deferred restart; otherwise old results can render
// under the new target's header and produce a false healthy verdict.
func TestDeferredRestartDefersTargetSwap(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), false)
	for _, probe := range m.probes {
		m.results[probe.ID] = diagnostic.ProbeResult{ID: probe.ID, Status: diagnostic.StatusPass}
	}
	m.generation = 3
	canceled := false
	m.activeJob = &job{id: "j", cancel: func() { canceled = true }}

	u, _ := m.Update(keyMsg("r"))
	nm := asModel(t, u)
	nm.input.SetValue("example.com")
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm = asModel(t, u)

	if !canceled {
		t.Fatal("committing must cancel the active job")
	}
	if nm.target == nil || nm.target.Host != "github.com" {
		t.Fatalf("target changed before terminal event: %+v", nm.target)
	}
	if nm.pending == nil || nm.pending.kind != pendRestart || nm.pending.target == nil || nm.pending.target.Host != "example.com" {
		t.Fatalf("pending restart target = %+v", nm.pending)
	}
	if got := nm.banner(); strings.Contains(got, "example.com") {
		t.Fatalf("banner used pending target before restart: %q", got)
	}

	u, cmd := nm.Update(ToolDoneMsg{JobID: "j", Generation: 3, Status: JobCanceled})
	nm2 := asModel(t, u)
	if cmd == nil {
		t.Fatal("deferred restart must issue a reschedule cmd")
	}
	if nm2.target == nil || nm2.target.Host != "example.com" {
		t.Fatalf("target after terminal event = %+v, want example.com", nm2.target)
	}
	if len(nm2.results) != 0 {
		t.Fatalf("results after deferred restart = %d, want cleared", len(nm2.results))
	}
}

// Starting another tool keeps the first one running, routes its output in the
// background, and lets Tab select it again.
func TestConcurrentToolsCanSwitch(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), false)
	m.generation = 1
	canceled := false
	m.activeJob = &job{id: "first", ch: make(chan tea.Msg, 1), cancel: func() { canceled = true }}
	m.jobStatus, m.jobName, m.jobDisplay = JobRunning, "first tool", "first"
	m.tools = []Tool{{
		Key: "z", Name: "second tool", Bin: os.Args[0], available: true,
		Build: func(*diagnostic.Target) ([]string, []string, string) {
			return []string{"-test.run=TestHelperProcess"},
				append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE=lines", "GO_HELPER_N=1"),
				"second"
		},
	}}

	u, cmd := m.Update(keyMsg("z"))
	nm := asModel(t, u)
	if cmd == nil || nm.activeJob == nil || nm.activeJob.id == "first" {
		t.Fatal("second tool must start immediately")
	}
	second := nm.activeJob
	if canceled || nm.pending != nil || len(nm.otherJobs) != 1 || nm.otherJobs[0].active.id != "first" {
		t.Fatalf("first tool was not preserved (canceled=%v pending=%v other=%+v)", canceled, nm.pending, nm.otherJobs)
	}
	if !strings.Contains(nm.View(), "tab") {
		t.Fatal("multiple jobs must show the switch key")
	}

	u, cmd = nm.Update(ToolOutputMsg{JobID: "first", Generation: 1, Line: "still running"})
	nm = asModel(t, u)
	if cmd == nil || len(nm.otherJobs[0].lines) != 1 {
		t.Fatal("background output must keep streaming")
	}

	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm = asModel(t, u)
	if nm.activeJob == nil || nm.activeJob.id != "first" || nm.jobLines[0] != "still running" {
		t.Fatalf("Tab selected job %q with lines %v, want first job", nm.activeJob.id, nm.jobLines)
	}

	second.cancel()
	_, _ = drain(t, second.ch)
}

func TestTabPreservesArmedQuit(t *testing.T) {
	m := newModel(nil, false)
	m.jobName, m.jobStatus = "current tool", JobDone
	m.otherJobs = []jobState{{name: "next tool", status: JobDone}}

	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	nm := asModel(t, u)
	deadline := nm.noticeDeadline
	u, cmd := nm.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm = asModel(t, u)
	if cmd != nil || nm.jobName != "next tool" || nm.notice != ctrlCNotice || !nm.noticeDeadline.Equal(deadline) {
		t.Fatalf("Tab changed armed quit: job=%q notice=%q deadline=%v cmd nil=%v", nm.jobName, nm.notice, nm.noticeDeadline, cmd == nil)
	}

	_, cmd = nm.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("Ctrl+C after Tab must quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("second Ctrl+C command = %T, want tea.QuitMsg", cmd())
	}
}

func TestTabWithoutOtherJobsDoesNothing(t *testing.T) {
	m := newModel(nil, false)
	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm := asModel(t, u)
	if cmd != nil || nm.notice != "" {
		t.Fatalf("Tab without another job: notice=%q cmd nil=%v", nm.notice, cmd == nil)
	}
}

// Output lines interleave in arrival order; stale messages are dropped.
func TestToolOutputRouting(t *testing.T) {
	m := newModel(nil, false)
	m.generation = 1
	m.activeJob = &job{id: "j", ch: make(chan tea.Msg, 1)}

	u, cmd := m.Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: "hello"})
	nm := asModel(t, u)
	if len(nm.jobLines) != 1 || nm.jobLines[0] != "hello" {
		t.Errorf("jobLines = %v, want [hello]", nm.jobLines)
	}
	if cmd == nil {
		t.Error("an accepted output line must reissue waitForMsg")
	}

	u, _ = nm.Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: "oops"})
	u, _ = asModel(t, u).Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: "world"})
	nm = asModel(t, u)
	want := []string{"hello", "oops", "world"}
	if len(nm.jobLines) != 3 || nm.jobLines[1] != want[1] || nm.jobLines[2] != want[2] {
		t.Errorf("jobLines = %v, want interleaved %v", nm.jobLines, want)
	}

	// Stale generation → ignored.
	u, cmd = nm.Update(ToolOutputMsg{JobID: "j", Generation: 99, Line: "nope"})
	nm = asModel(t, u)
	if len(nm.jobLines) != 3 {
		t.Errorf("stale output must be dropped, jobLines = %v", nm.jobLines)
	}
	if cmd != nil {
		t.Error("stale output must issue no cmd")
	}
}

// A terminal event for a stale job (wrong id/gen) is ignored.
func TestStaleToolDoneDropped(t *testing.T) {
	m := newModel(nil, false)
	m.generation = 2
	m.activeJob = &job{id: "j", cancel: func() {}}
	u, cmd := m.Update(ToolDoneMsg{JobID: "other", Generation: 2, Status: JobDone})
	nm := asModel(t, u)
	if nm.activeJob == nil {
		t.Error("a mismatched-id terminal event must not clear the active job")
	}
	if cmd != nil {
		t.Error("stale terminal event must issue no cmd")
	}
}

func TestWindowSize(t *testing.T) {
	m := newModel(nil, false)
	u, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	nm := asModel(t, u)
	if nm.width != 120 || nm.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", nm.width, nm.height)
	}
}

// Launching a tool in toolbox mode before the first 'r' must lazily create the
// generation context instead of panicking on a nil parent (pre-existing bug,
// Codex round 2).
func TestToolboxLaunchBeforeRun(t *testing.T) {
	m := newModel(nil, true)
	if m.ctx != nil {
		t.Fatal("precondition: toolbox model must start with a nil ctx")
	}
	tool := Tool{Key: "z", Name: "helper", Bin: os.Args[0], available: true,
		Build: func(*diagnostic.Target) ([]string, []string, string) {
			return []string{"-test.run=TestHelperProcess"},
				append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE=lines", "GO_HELPER_N=1"),
				"helper"
		}}
	cmd := (&m).launchTool(tool) // must not panic
	if cmd == nil {
		t.Fatalf("launchTool returned no cmd (jobLines=%v)", m.jobLines)
	}
	if m.ctx == nil {
		t.Fatal("launchTool must lazily initialize the context")
	}
	_, done := drain(t, m.activeJob.ch)
	if done.Status != JobDone {
		t.Errorf("status = %v, want JobDone", done.Status)
	}
	m.clearCancel()
}

// launchTool on a missing binary fails gracefully with an install hint and no cmd.
func TestLaunchToolUnavailable(t *testing.T) {
	m := newModel(nil, false)
	m.jobDropped = 7
	m.jobEvicted = 9
	tool := Tool{
		Key: "z", Name: "nope", Bin: "network-doctor-no-such-binary-xyz",
		Build: func(*diagnostic.Target) ([]string, []string, string) { return nil, nil, "nope" },
	}
	cmd := (&m).launchTool(tool)
	if cmd != nil {
		t.Error("a missing binary must not spawn anything")
	}
	if m.jobStatus != JobFailed {
		t.Errorf("status = %v, want JobFailed", m.jobStatus)
	}
	if len(m.jobLines) == 0 || !strings.Contains(m.jobLines[0], "not found") {
		t.Errorf("jobLines = %v, want a 'not found' hint", m.jobLines)
	}
	if m.jobDropped != 0 || m.jobEvicted != 0 {
		t.Errorf("jobDropped/jobEvicted = %d/%d, want 0/0", m.jobDropped, m.jobEvicted)
	}
}

func TestLaunchToolStartErrorClearsPreviousJobState(t *testing.T) {
	m := newModel(nil, false)
	m.jobDropped = 7
	m.jobEvicted = 9
	name := "bad-tool"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(bin, []byte("not an executable format"), 0755); err != nil {
		t.Fatal(err)
	}
	tool := Tool{
		Key: "z", Name: "bad tool", Bin: bin, available: true,
		Build: func(*diagnostic.Target) ([]string, []string, string) { return nil, nil, "bad-tool --display" },
	}
	cmd := (&m).launchTool(tool)
	if cmd != nil {
		t.Error("a start error must not return a running job command")
	}
	if m.jobStatus != JobFailed {
		t.Errorf("status = %v, want JobFailed", m.jobStatus)
	}
	if m.jobDisplay != "bad-tool --display" {
		t.Errorf("jobDisplay = %q, want built display string", m.jobDisplay)
	}
	if len(m.jobLines) == 0 {
		t.Errorf("jobLines = %v, want an error line", m.jobLines)
	}
	if m.jobDropped != 0 || m.jobEvicted != 0 {
		t.Errorf("jobDropped/jobEvicted = %d/%d, want 0/0", m.jobDropped, m.jobEvicted)
	}
}

// ---- render smoke tests (must not panic; show key labels) ----

func TestViewRenders(t *testing.T) {
	m := newModel(nil, false)
	out := m.View()
	for _, want := range []string{"Network Doctor", "Checks", "Details"} {
		if !strings.Contains(out, want) {
			t.Errorf("View missing %q", want)
		}
	}

	tb := newModel(nil, true)
	if !strings.Contains(tb.View(), "check your connection") {
		t.Error("deferred toolbox view must explain itself")
	}

	job := newModel(mustTarget(t, "github.com"), false)
	job.jobStatus, job.jobName, job.jobDisplay = JobDone, "ping", "ping github.com"
	job.jobLines = []string{"64 bytes from ..."}
	if !strings.Contains(job.View(), "$ ping github.com") {
		t.Error("job view must show the command line")
	}

	net := newModel(nil, false)
	net.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Network: "HomeWiFi"}
	if !strings.Contains(net.View(), "Wi-Fi: HomeWiFi") {
		t.Error("view must show the connected network")
	}
}

// Enter opens the output viewport in follow mode; scrolling up pauses follow
// and new output must not yank the view back down; esc closes it.
func TestViewportFollow(t *testing.T) {
	m := newModel(nil, false)
	m.width, m.height = 60, 10 // wrapped footer leaves 5 viewport rows
	m.generation = 1
	m.activeJob = &job{id: "j", ch: make(chan tea.Msg, 1)}
	var u tea.Model = m
	for i := 0; i < 20; i++ {
		u, _ = asModel(t, u).Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: fmt.Sprintf("line %d", i)})
	}

	u, _ = asModel(t, u).Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm := asModel(t, u)
	if !nm.viewing || !nm.follow || !nm.vp.AtBottom() {
		t.Fatalf("enter must open the viewport following the tail (viewing=%v follow=%v atBottom=%v)",
			nm.viewing, nm.follow, nm.vp.AtBottom())
	}
	out := nm.View()
	if !strings.Contains(out, "line 19") || !strings.Contains(out, "of 20") {
		t.Errorf("viewport must show the newest line and a position context, got:\n%s", out)
	}
	if rows := strings.Count(out, "\n") + 1; rows > m.height {
		t.Errorf("viewer is %d rows, terminal is %d", rows, m.height)
	}

	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyHome})
	nm = asModel(t, u)
	if nm.vp.YOffset != 0 || nm.follow {
		t.Errorf("home must jump to the top and pause follow (offset=%d follow=%v)", nm.vp.YOffset, nm.follow)
	}
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEnd})
	nm = asModel(t, u)
	if !nm.vp.AtBottom() || !nm.follow {
		t.Errorf("end must jump to the bottom and resume follow (follow=%v)", nm.follow)
	}

	u, _ = nm.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp})
	nm = asModel(t, u)
	if nm.follow {
		t.Error("wheel up must pause follow mode")
	}

	u, _ = nm.Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: "boom"})
	nm = asModel(t, u)
	if nm.vp.AtBottom() {
		t.Error("paused viewport must hold its position on new output")
	}

	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if nm = asModel(t, u); nm.viewing {
		t.Error("esc must close the viewport")
	}
}

func TestViewportEvictionKeepsPausedReader(t *testing.T) {
	m := newModel(nil, false)
	m.width, m.height = 20, 10
	m.generation = 1
	m.activeJob = &job{id: "j", ch: make(chan tea.Msg, 1)}
	m.jobLines = make([]string, maxJobLines)
	m.jobLines[0] = strings.Repeat("x", m.width+1) // two display rows
	for i := 1; i < maxJobLines; i++ {
		m.jobLines[i] = fmt.Sprintf("line %d", i)
	}
	m.viewing, m.follow = true, false
	m.refreshViewport()
	m.vp.SetYOffset(10)
	want := m.vp.View()

	u, _ := m.Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: "newest"})
	nm := asModel(t, u)
	if nm.vp.YOffset != 8 {
		t.Fatalf("offset = %d, want 8 after evicting two wrapped rows", nm.vp.YOffset)
	}
	if got := nm.vp.View(); got != want {
		t.Errorf("paused viewport moved after eviction\nbefore:\n%s\nafter:\n%s", want, got)
	}
}
