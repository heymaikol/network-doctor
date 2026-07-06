package ui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mplaczek99/network-doctor/internal/diagnostic"
)

// doneResults fills every probe with a result: failID fails, the rest pass.
// An empty failID means an all-pass run.
func doneResults(m *model, failID diagnostic.ProbeID) {
	for _, p := range m.probes {
		st := diagnostic.StatusPass
		if p.ID == failID {
			st = diagnostic.StatusFail
		}
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: st}
	}
}

func TestFixFor(t *testing.T) {
	cases := []struct {
		id   diagnostic.ProbeID
		goos string
		bin  string // "" = no fix expected
	}{
		{diagnostic.ProbeIface, "linux", "nmcli"},
		{diagnostic.ProbeIface, "darwin", ""},
		{diagnostic.ProbeIface, "windows", ""},
		{diagnostic.ProbeDNS, "linux", "resolvectl"},
		{diagnostic.ProbeDNS, "darwin", "dscacheutil"},
		{diagnostic.ProbeDNS, "windows", "ipconfig"},
		{diagnostic.ProbeInternet, "linux", ""},
		{diagnostic.ProbeTargetTCP, "linux", ""},
		{diagnostic.ProbeTLS, "windows", ""},
	}
	for _, c := range cases {
		fix := fixFor(c.id, c.goos)
		if c.bin == "" {
			if fix != nil {
				t.Errorf("fixFor(%s, %s) = %q, want no fix", c.id, c.goos, fix.Bin)
			}
			continue
		}
		if fix == nil {
			t.Errorf("fixFor(%s, %s) = nil, want %q", c.id, c.goos, c.bin)
			continue
		}
		if fix.Bin != c.bin || fix.Key != "f" {
			t.Errorf("fixFor(%s, %s) = bin %q key %q, want bin %q key f", c.id, c.goos, fix.Bin, fix.Key, c.bin)
		}
		if args, _, display := fix.Build(nil); len(args) == 0 || display == "" {
			t.Errorf("fixFor(%s, %s).Build → args %v display %q, want both non-empty", c.id, c.goos, args, display)
		}
	}
}

func TestFixToolGating(t *testing.T) {
	m := newModel(nil)
	if m.fixTool() != nil {
		t.Error("an unfinished run must offer no fix")
	}
	doneResults(&m, "")
	if m.fixTool() != nil {
		t.Error("an all-pass run must offer no fix")
	}
	doneResults(&m, diagnostic.ProbeDNS)
	if m.fixTool() == nil {
		t.Error("a DNS failure must offer a fix on every OS")
	}
}

// The fix job's terminal event reruns the chain (bumped generation, cleared
// results) — that rerun is the verification — and labels it via verifying.
func TestFixVerifyRerun(t *testing.T) {
	m := newModel(nil)
	m.generation = 2
	doneResults(&m, diagnostic.ProbeDNS)
	m.fixing = true
	m.activeJob = &job{id: "fx", cancel: func() {}}

	u, cmd := m.Update(ToolDoneMsg{JobID: "fx", Generation: 2, Status: JobDone})
	nm := asModelP(t, u)
	if nm.generation != 3 {
		t.Errorf("generation = %d, want 3 — fix completion must rerun to verify", nm.generation)
	}
	if len(nm.results) != 0 {
		t.Errorf("results = %v, want cleared for the verification rerun", nm.results)
	}
	if nm.fixing || !nm.verifying {
		t.Errorf("fixing=%v verifying=%v, want false/true after the fix job ends", nm.fixing, nm.verifying)
	}
	if cmd == nil {
		t.Fatal("fix completion must issue the reschedule cmd")
	}
}

// 'f' while a job streams defers the fix like any tool launch.
func TestDeferredFix(t *testing.T) {
	m := newModel(nil)
	m.generation = 1
	doneResults(&m, diagnostic.ProbeDNS)
	canceled := false
	m.activeJob = &job{id: "j", cancel: func() { canceled = true }}

	u, _ := m.Update(keyMsg("f"))
	nm := asModel(t, u)
	if nm.pending == nil || nm.pending.kind != pendFix {
		t.Fatal("f during a job must defer the fix")
	}
	if nm.pending.tool.Key != "f" {
		t.Errorf("deferred tool key = %q, want f", nm.pending.tool.Key)
	}
	if !canceled {
		t.Error("the running job must be canceled first")
	}
}

// A deferred fix launch marks the new job as a fix so its completion verifies.
func TestRunPendingFixLaunches(t *testing.T) {
	m := newModel(nil)
	tool := Tool{Key: "f", Name: "fix", Bin: os.Args[0],
		Build: func(*diagnostic.Target) ([]string, []string, string) {
			return []string{"-test.run=TestHelperProcess"},
				append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE=lines", "GO_HELPER_N=1"),
				"fix"
		}}
	u, cmd := (&m).runPending(&pendingAction{kind: pendFix, tool: tool})
	nm := asModelP(t, u)
	if cmd == nil || nm.activeJob == nil {
		t.Fatalf("deferred fix must launch (jobLines=%v)", nm.jobLines)
	}
	if !nm.fixing {
		t.Error("a launched fix job must set fixing")
	}
	if _, done := drain(t, nm.activeJob.ch); done.Status != JobDone {
		t.Errorf("helper status = %v, want JobDone", done.Status)
	}
	nm.clearCancel()
}

// A user-deferred action (quit/rerun/tool) during a fix job wins over the
// fix's auto-verify — no surprise rerun afterwards.
func TestPendingOverridesFix(t *testing.T) {
	m := newModel(nil)
	m.generation = 1
	m.fixing = true
	m.activeJob = &job{id: "fx", cancel: func() {}}
	m.pending = &pendingAction{kind: pendQuit}

	u, cmd := m.Update(ToolDoneMsg{JobID: "fx", Generation: 1, Status: JobCanceled})
	nm := asModelP(t, u)
	if nm.fixing {
		t.Error("a deferred action must clear the fix flag")
	}
	if nm.generation != 1 {
		t.Errorf("generation = %d, want 1 — no verify rerun on override", nm.generation)
	}
	if cmd == nil {
		t.Fatal("the deferred quit must still run")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Errorf("cmd = %T, want tea.QuitMsg", cmd())
	}
}

// The banner labels the verification rerun's verdict and offers 'f' on a
// fixable failure.
func TestBannerFixVerdicts(t *testing.T) {
	pass := newModel(nil)
	doneResults(&pass, "")
	pass.verifying = true
	if got := pass.banner(); !strings.Contains(got, "Fix verified") {
		t.Errorf("all-pass verify banner = %q, want 'Fix verified'", got)
	}

	fail := newModel(nil)
	doneResults(&fail, diagnostic.ProbeDNS)
	fail.verifying = true
	got := fail.banner()
	if !strings.Contains(got, "Fix didn't help") {
		t.Errorf("failed verify banner = %q, want \"Fix didn't help\"", got)
	}
	if !strings.Contains(got, "to try a fix") {
		t.Errorf("banner = %q, want the 'f' fix offer", got)
	}

	// A manual rerun clears the label.
	(&fail).doRerun()
	if fail.verifying {
		t.Error("doRerun must clear verifying")
	}
}
