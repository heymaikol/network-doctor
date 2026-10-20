// Update-loop odds and ends: the output ring buffer, actions deferred behind
// a live job, stale-message drops, and view rendering.

package ui

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

func TestAppendJobLine(t *testing.T) {
	var m model
	for i := 0; i < maxJobLines+50; i++ {
		m.appendJobLine("x")
	}
	if len(m.cur.lines) != maxJobLines {
		t.Errorf("len = %d, want cap %d", len(m.cur.lines), maxJobLines)
	}
	// Ring evictions are counted separately from channel-overflow drops.
	if m.cur.evicted != 50 {
		t.Errorf("jobEvicted = %d, want 50", m.cur.evicted)
	}
	if m.cur.dropped != 0 {
		t.Errorf("jobDropped = %d, want 0: evictions must not touch it", m.cur.dropped)
	}
	m.appendJobLine("newest")
	if last := m.cur.lines[len(m.cur.lines)-1]; last != "newest" {
		t.Errorf("last = %q, want newest line kept", last)
	}
	if len(m.cur.lines) != maxJobLines || m.cur.evicted != 51 {
		t.Errorf("len=%d evicted=%d, want %d and 51", len(m.cur.lines), m.cur.evicted, maxJobLines)
	}
}

func TestNetworkLine(t *testing.T) {
	m := newModel(nil, false)
	if got := m.networkLine(); got != "" {
		t.Errorf("no iface result → %q, want empty", got)
	}
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Iface: "en0"}
	if got := m.networkLine(); got != "" {
		t.Errorf("pending ssid result → %q, want empty", got)
	}
	m.results[diagnostic.ProbeSSID] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Network: "HomeWiFi"}
	if got := m.networkLine(); got != "Wi-Fi: HomeWiFi" {
		t.Errorf("wifi line = %q", got)
	}
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Iface: "eth0"}
	m.results[diagnostic.ProbeSSID] = diagnostic.ProbeResult{Status: diagnostic.StatusNA}
	if got := m.networkLine(); got != "Wired: eth0" {
		t.Errorf("wired line = %q", got)
	}
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusFail, Iface: "eth0"}
	if got := m.networkLine(); got != "" {
		t.Errorf("failed iface → %q, want empty", got)
	}
}

func TestPortalURLDisplayed(t *testing.T) {
	const portalURL = "https://portal.example/signin"
	m := newModel(nil, false)
	for i, p := range m.probes {
		if p.ID == diagnostic.ProbeInternet {
			m.selected = i
			m.results[p.ID] = diagnostic.ProbeResult{
				Status: diagnostic.StatusFail,
				Detail: "HTTP is intercepted",
				Portal: &diagnostic.Portal{RedirectURL: portalURL},
			}
			break
		}
	}
	for name, got := range map[string]string{"details": m.bodyView(false, 0), "report": m.report()} {
		if !strings.Contains(got, portalURL) {
			t.Errorf("%s missing portal URL:\n%s", name, got)
		}
	}
	if help := m.helpView(false); strings.Contains(help, "copy portal URL") {
		t.Errorf("footer advertises portal copy action:\n%s", help)
	}

	t.Setenv("TMUX", "")
	done := captureStderr(t)
	u, cmd := m.Update(keyMsg("y"))
	nm := asModel(t, u)
	if got, want := done(), osc52Sequence(portalURL); got != want {
		t.Errorf("clipboard output = %q, want %q", got, want)
	}
	if cmd == nil || nm.notice != "portal URL sent to clipboard (OSC 52)" {
		t.Fatalf("copy notice = %q, cmd nil = %v", nm.notice, cmd == nil)
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
		{JobStatus(-1), "?"},
		{JobStatus(99), "?"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("JobStatus(%d) = %q, want %q", c.s, got, c.want)
		}
	}

	f, err := parser.ParseFile(token.NewFileSet(), "jobs.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := 0
	ast.Inspect(f, func(node ast.Node) bool {
		group, ok := node.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST || len(group.Specs) == 0 {
			return true
		}
		first := group.Specs[0].(*ast.ValueSpec)
		typeName, ok := first.Type.(*ast.Ident)
		if !ok || typeName.Name != "JobStatus" {
			return false
		}
		for i, spec := range group.Specs {
			value := spec.(*ast.ValueSpec)
			if len(value.Names) != 1 || i == 0 && len(value.Values) != 1 || i > 0 && len(value.Values) != 0 {
				t.Fatal("JobStatus must remain a contiguous iota enum")
			}
			if i == 0 {
				iotaExpr, ok := value.Values[0].(*ast.Ident)
				if !ok || iotaExpr.Name != "iota" {
					t.Fatal("first JobStatus constant is not iota")
				}
			}
			declared += len(value.Names)
		}
		return false
	})
	if declared != len(jobStatusNames) {
		t.Errorf("%d JobStatus constants, but %d names", declared, len(jobStatusNames))
	}
	if declared != len(jobGlyphs) {
		t.Errorf("%d JobStatus constants, but %d strip glyphs", declared, len(jobGlyphs))
	}
}

func TestJobStatusLineShowsMilliseconds(t *testing.T) {
	m := newModel(nil, false)
	m.cur.status, m.cur.dur = JobDone, 40*time.Millisecond
	if got := m.jobStatusLine(); !strings.Contains(got, "40ms") {
		t.Errorf("jobStatusLine() = %q, want 40ms", got)
	}
}

// jobStripModel is a model whose ring is these runs, the first selected, on a
// terminal w columns wide.
func jobStripModel(w int, runs ...jobState) model {
	m := newModel(nil, false)
	m.width = w
	runs = append([]jobState(nil), runs...)
	for i := range runs {
		if runs[i].active != nil && runs[i].start.IsZero() {
			runs[i].start = time.Now() // launching a run stamps this; the timer reads it
		}
	}
	m.cur, m.otherJobs = runs[0], runs[1:]
	return m
}

// ringNames is the ring in the order tab walks it: the selected run, then the
// parked ones. It comes from the joblist iterator, so a test comparing the
// strip against it is comparing the strip against switchJob's own order.
func ringNames(m model) []string {
	var names []string
	for j := range m.jobs {
		names = append(names, j.name)
	}
	return names
}

func TestJobStripRunsInRingOrder(t *testing.T) {
	lone := jobStripModel(80, jobState{name: "ping the host", status: JobDone, dur: time.Second})
	got := ansi.Strip(lone.jobStrip())
	if strings.Contains(got, "›") {
		t.Errorf("a lone run has nowhere to switch to, so it takes no marker: %q", got)
	}
	if !strings.Contains(got, "ping the host: done") {
		t.Errorf("jobStrip() = %q, want the run and its status", got)
	}

	m := jobStripModel(120,
		jobState{name: "ping the host", status: JobRunning, active: &job{}},
		jobState{name: "DNS lookup", status: JobDone},
		jobState{name: "trace the path", status: JobFailed},
	)
	got = ansi.Strip(m.jobStrip())
	if !strings.HasPrefix(got, "› ping the host: running") {
		t.Errorf("the selected run leads the strip, marked and spelled out: %q", got)
	}
	if strings.Count(got, "›") != 1 {
		t.Errorf("exactly one tab is the selected one: %q", got)
	}
	at := -1
	for _, name := range ringNames(m) {
		i := strings.Index(got, name)
		if i <= at {
			t.Fatalf("strip %q does not follow the ring %v", got, ringNames(m))
		}
		at = i
	}
	// Only the selected run spells its status out; the parked ones carry a
	// glyph, so no run's state is written twice on the row.
	if strings.Count(got, "failed") != 0 || !strings.Contains(got, "trace the path ✗") {
		t.Errorf("a parked run is name + glyph, not a second status word: %q", got)
	}
}

func TestTabMovesTheSelectedTab(t *testing.T) {
	m := jobStripModel(120,
		jobState{name: "ping the host", status: JobDone},
		jobState{name: "DNS lookup", status: JobDone},
		jobState{name: "trace the path", status: JobDone},
	)
	if got := ansi.Strip(m.jobStrip()); !strings.HasPrefix(got, "› ping the host") {
		t.Fatalf("strip starts marked on the selected run: %q", got)
	}
	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm := asModel(t, u)
	got := ansi.Strip(nm.jobStrip())
	if !strings.HasPrefix(got, "› DNS lookup") {
		t.Errorf("tab must move the marker to the tab on its right: %q", got)
	}
	// The row rotates with the ring rather than holding a layout of its own.
	if want := []string{"DNS lookup", "trace the path", "ping the host"}; !slices.Equal(ringNames(nm), want) {
		t.Fatalf("ring is %v, want %v", ringNames(nm), want)
	}
	at := -1
	for _, name := range ringNames(nm) {
		i := strings.Index(got, name)
		if i <= at {
			t.Fatalf("strip %q does not follow the rotated ring %v", got, ringNames(nm))
		}
		at = i
	}
}

// A reader without colour still has to tell a run that is working from one
// that finished, and a clean finish from a failure, a timeout or a cancel.
func TestJobStripTellsStatusesApartWithoutColour(t *testing.T) {
	seen := map[string]JobStatus{}
	for _, status := range []JobStatus{JobDone, JobFailed, JobCanceled, JobTimedOut} {
		m := jobStripModel(120,
			jobState{name: "selected run", status: JobDone},
			jobState{name: "parked run", status: status},
		)
		glyph := ansi.Strip(m.jobGlyph(&m.otherJobs[0]))
		if glyph == "" {
			t.Fatalf("%s has no glyph", status)
		}
		if other, dup := seen[glyph]; dup {
			t.Errorf("%s and %s share glyph %q, so colour is the only difference", status, other, glyph)
		}
		seen[glyph] = status
		if got := ansi.Strip(m.jobStrip()); !strings.Contains(got, "parked run "+glyph) {
			t.Errorf("%s: strip %q must carry glyph %q", status, got, glyph)
		}
	}
	live := jobStripModel(120,
		jobState{name: "selected run", status: JobDone},
		jobState{name: "parked run", status: JobRunning, active: &job{}},
	)
	glyph := ansi.Strip(live.jobGlyph(&live.otherJobs[0]))
	if other, terminal := seen[glyph]; terminal {
		t.Errorf("a running run reuses %s's glyph %q", other, glyph)
	}
	if got := ansi.Strip(live.jobStrip()); !strings.Contains(got, "parked run "+glyph) {
		t.Errorf("a parked run still streaming must say so: %q", got)
	}
}

// The strip is one row at every width: it drops tabs from the tail of the ring
// and counts them instead of wrapping into a wall.
func TestJobStripStaysOneBoundedRow(t *testing.T) {
	runs := []jobState{{name: "ping the host", status: JobRunning, active: &job{}}}
	for i := 0; i < maxParkedJobs; i++ {
		runs = append(runs, jobState{name: fmt.Sprintf("parked-%02d", i), status: JobDone})
	}
	for _, w := range []int{300, 200, 120, 100, 80, 60, 40, 30, 20, 10, 1} {
		m := jobStripModel(w, runs...)
		row := m.jobStrip()
		plain := ansi.Strip(row)
		if strings.Contains(plain, "\n") {
			t.Errorf("width %d: strip wrapped into %q", w, plain)
		}
		if !strings.Contains(plain, "› ping the host: running") {
			t.Errorf("width %d: the selected run must never be elided: %q", w, plain)
		}
		// The row fits the terminal, unless the selected run alone does not,
		// which is the one case the pane wraps exactly as it did before.
		sel := lipgloss.Width(m.jobStatusLine()) + lipgloss.Width("› ")
		if got := lipgloss.Width(row); got > w && got > sel {
			t.Errorf("width %d: strip is %d cells wide: %q", w, got, plain)
		}
		shown := 0
		for i := 0; i < maxParkedJobs; i++ {
			if strings.Contains(plain, fmt.Sprintf("parked-%02d", i)) {
				shown++
			}
		}
		// Tabs go from the tail, so what survives is what tab reaches first.
		for i := 0; i < shown; i++ {
			if !strings.Contains(plain, fmt.Sprintf("parked-%02d", i)) {
				t.Errorf("width %d: elision must drop the far end of the ring: %q", w, plain)
			}
		}
		hidden := 0
		if at := strings.LastIndex(plain, "+"); at >= 0 {
			_, _ = fmt.Sscanf(plain[at:], "+%d", &hidden)
		}
		// Every parked run is either a tab or in the count, as soon as the
		// row has room for the count at all. Below that the marker is the
		// only thing left saying there is somewhere to switch to.
		room := sel + lipgloss.Width("  ·  ") + lipgloss.Width(fmt.Sprintf("+%d", maxParkedJobs))
		if shown+hidden != maxParkedJobs && w >= room {
			t.Errorf("width %d: strip accounts for %d shown and %d hidden of %d parked runs: %q",
				w, shown, hidden, maxParkedJobs, plain)
		}
		if w >= 300 && shown != maxParkedJobs {
			t.Errorf("width %d: a wide terminal shows the whole ring, got %d tabs: %q", w, shown, plain)
		}
		if shown == maxParkedJobs && hidden != 0 {
			t.Errorf("width %d: nothing is hidden, so nothing should be counted: %q", w, plain)
		}
	}
}

// One long name must cost its own tab, never the row.
func TestJobStripCapsLongNames(t *testing.T) {
	long := "an extremely long tool name that would eat the whole row"
	m := jobStripModel(120,
		jobState{name: "ping the host", status: JobRunning, active: &job{}},
		jobState{name: long, status: JobDone},
		jobState{name: "DNS lookup", status: JobDone},
	)
	plain := ansi.Strip(m.jobStrip())
	if strings.Contains(plain, long) {
		t.Errorf("a long parked name must be capped: %q", plain)
	}
	if !strings.Contains(plain, "…") {
		t.Errorf("a capped name must show it was cut: %q", plain)
	}
	if !strings.Contains(plain, "DNS lookup ✓") {
		t.Errorf("one long name must not crowd the rest of the ring out: %q", plain)
	}
	if got := lipgloss.Width(m.jobStrip()); got > 120 {
		t.Errorf("strip is %d cells wide, want at most 120: %q", got, plain)
	}

	// Capping counts display cells, not runes: twenty wide runes are forty
	// columns, and a rune-counted cap would push this tab off the row.
	wide := jobStripModel(46,
		jobState{name: "ping", status: JobDone},
		jobState{name: strings.Repeat("界", 20), status: JobDone},
	)
	plain = ansi.Strip(wide.jobStrip())
	if !strings.Contains(plain, "界") {
		t.Errorf("a wide-rune name must be capped by display width, not dropped: %q", plain)
	}
	if got := lipgloss.Width(wide.jobStrip()); got > 46 {
		t.Errorf("wide-rune strip is %d cells wide, want at most 46: %q", got, plain)
	}
}

// The viewer is a place tab still switches runs, so it carries the same strip.
func TestOutputViewerShowsTheJobStrip(t *testing.T) {
	m := jobStripModel(80,
		jobState{name: "ping the host", status: JobRunning, active: &job{}, display: "ping -c 4 host"},
		jobState{name: "DNS lookup", status: JobDone},
	)
	m.height, m.viewing = 24, true
	m.cur.lines = []string{"64 bytes from host"}
	m.refreshViewport()
	head := ansi.Strip(m.viewerHeader())
	if !strings.Contains(head, "› ping the host: running") || !strings.Contains(head, "DNS lookup ✓") {
		t.Errorf("viewer header must carry the job strip: %q", head)
	}
	v := m.View()
	if got := lipgloss.Height(v); got > m.height {
		t.Errorf("viewer is %d rows tall, want at most %d:\n%s", got, m.height, v)
	}
	if !strings.Contains(ansi.Strip(v), "DNS lookup ✓") {
		t.Errorf("the viewer must not hide the rest of the ring:\n%s", v)
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

// ---- message routing & deferred actions ----

// 'q' while a job runs cancels it and defers the quit; the terminal event then
// performs it.
func TestDeferredQuit(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), true)
	m.generation = 3
	canceled := false
	m.cur.active = &job{id: "j", cancel: func() { canceled = true }}

	u, cmd := m.Update(keyMsg("q"))
	nm := asModel(t, u)
	if nm.pending == nil || nm.pending.kind != pendQuit {
		t.Fatal("q during a job must defer a quit")
	}
	if !canceled {
		t.Error("the active job must be canceled")
	}
	if nm.notice == "" {
		t.Error("deferred quit must show feedback")
	}
	_ = cmd // notice-expiry tick, not a quit; the quit only runs on the terminal event below

	u2, cmd2 := nm.Update(ToolDoneMsg{JobID: "j", Generation: 3, Status: JobCanceled})
	nm2 := asModel(t, u2)
	if nm2.cur.active != nil {
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
	m.cur.active = &job{id: "j", cancel: func() { canceled = true }}

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
	m.cur.active = &job{id: "j", cancel: func() { canceled = true }}

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

// A restart forgets its jobs, but each producer still owes one blocking
// terminal send. With a full buffer and nothing left re-issuing waitForMsg,
// that send parks the goroutine forever.
func TestRestartDrainsAbandonedJob(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), false)
	ch := make(chan tea.Msg, 2)
	ch <- ToolOutputMsg{JobID: "j"}
	ch <- ToolOutputMsg{JobID: "j"} // buffer full: the terminal send will block
	m.cur.active, m.cur.status = &job{id: "j", ch: ch, cancel: func() {}}, JobRunning

	m.doRestart()

	sent := make(chan struct{})
	go func() {
		ch <- ToolDoneMsg{JobID: "j", Status: JobCanceled}
		close(sent)
	}()
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("terminal send parked: an abandoned job's channel is never drained")
	}
}

// Starting another tool keeps the first one running, routes its output in the
// background, and lets Tab select it again.
func TestConcurrentToolsCanSwitch(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), false)
	m.generation = 1
	canceled := false
	m.cur.active = &job{id: "first", ch: make(chan tea.Msg, 1), cancel: func() { canceled = true }}
	m.cur.status, m.cur.name, m.cur.display = JobRunning, "first tool", "first"
	m.tools = []Tool{{
		Key: "z", Name: "second tool", Bin: os.Args[0], Available: true,
		Build: func(*diagnostic.Target, net.IP) ([]string, []string, string) {
			return []string{"-test.run=TestHelperProcess"},
				append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE=lines", "GO_HELPER_N=1"),
				"second"
		},
	}}

	u, cmd := m.Update(keyMsg("z"))
	nm := asModel(t, u)
	if cmd == nil || nm.cur.active == nil || nm.cur.active.id == "first" {
		t.Fatal("second tool must start immediately")
	}
	second := nm.cur.active
	if canceled || nm.pending != nil || len(nm.otherJobs) != 1 || nm.otherJobs[0].active.id != "first" {
		t.Fatalf("first tool was not preserved (canceled=%v pending=%v other=%+v)", canceled, nm.pending, nm.otherJobs)
	}
	if strings.Contains(nm.helpView(false), "switch job") {
		t.Fatal("multiple jobs advertise switching in the compact footer")
	}
	if !slices.Contains(menuNames(nm), "Switch job") {
		t.Fatal("multiple jobs must expose switching in the Actions menu")
	}

	u, cmd = nm.Update(ToolOutputMsg{JobID: "first", Generation: 1, Line: "still running"})
	nm = asModel(t, u)
	if cmd == nil || len(nm.otherJobs[0].lines) != 1 {
		t.Fatal("background output must keep streaming")
	}

	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm = asModel(t, u)
	if nm.cur.active == nil || nm.cur.active.id != "first" || nm.cur.lines[0] != "still running" {
		t.Fatalf("Tab selected job %q with lines %v, want first job", nm.cur.active.id, nm.cur.lines)
	}

	second.cancel()
	_, _ = drain(t, second.ch)
}

// TestJobLimits covers both caps: the ring evicts finished runs oldest-first
// and keeps live ones, and a launch at maxActiveJobs is refused instead of
// forking yet another subprocess.
func TestJobLimits(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), false)
	m.generation = 1

	// One live run plus a full ring of finished ones.
	m.cur.active = &job{id: "live", ch: make(chan tea.Msg, 1)}
	m.cur.status, m.cur.name = JobRunning, "live tool"
	for i := range maxParkedJobs {
		m.otherJobs = append(m.otherJobs, jobState{status: JobDone, name: fmt.Sprintf("old-%d", i)})
	}
	m.stashJob()
	if len(m.otherJobs) != maxParkedJobs {
		t.Fatalf("ring holds %d runs, want %d", len(m.otherJobs), maxParkedJobs)
	}
	if m.otherJobs[0].name != "old-1" {
		t.Fatalf("evicted %q, want the oldest finished run old-0", m.otherJobs[0].name)
	}
	if m.otherJobs[len(m.otherJobs)-1].active == nil {
		t.Fatal("the live run must survive eviction")
	}

	// At the active cap, the hotkey reports back instead of launching.
	m.cur = jobState{}
	m.otherJobs = nil
	for i := range maxActiveJobs {
		m.otherJobs = append(m.otherJobs, jobState{
			active: &job{id: fmt.Sprintf("run-%d", i)}, status: JobRunning,
		})
	}
	tool := Tool{Key: "z", Name: "second tool", Bin: os.Args[0], Available: true,
		Build: func(*diagnostic.Target, net.IP) ([]string, []string, string) {
			t.Fatal("launch must be refused at the active cap")
			return nil, nil, ""
		}}
	m.tools = []Tool{tool}
	u, _ := m.Update(keyMsg("z"))
	nm := asModel(t, u)
	if nm.cur.active != nil || len(nm.otherJobs) != maxActiveJobs {
		t.Fatalf("refused launch still touched job state (cur=%+v other=%d)", nm.cur, len(nm.otherJobs))
	}
	if !strings.Contains(nm.notice, "already running") {
		t.Fatalf("notice = %q, want the at-capacity message", nm.notice)
	}
}

func TestTabPreservesArmedQuit(t *testing.T) {
	m := newModel(nil, false)
	m.cur.name, m.cur.status = "current tool", JobDone
	m.otherJobs = []jobState{{name: "next tool", status: JobDone}}

	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	nm := asModel(t, u)
	deadline := nm.noticeDeadline
	u, cmd := nm.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm = asModel(t, u)
	if cmd != nil || nm.cur.name != "next tool" || nm.notice != ctrlCNotice || !nm.noticeDeadline.Equal(deadline) {
		t.Fatalf("Tab changed armed quit: job=%q notice=%q deadline=%v cmd nil=%v", nm.cur.name, nm.notice, nm.noticeDeadline, cmd == nil)
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
	m.cur.active = &job{id: "j", ch: make(chan tea.Msg, 1)}

	u, cmd := m.Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: "hello"})
	nm := asModel(t, u)
	if len(nm.cur.lines) != 1 || nm.cur.lines[0] != "hello" {
		t.Errorf("jobLines = %v, want [hello]", nm.cur.lines)
	}
	if cmd == nil {
		t.Error("an accepted output line must reissue waitForMsg")
	}

	u, _ = nm.Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: "oops"})
	u, _ = asModel(t, u).Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: "world"})
	nm = asModel(t, u)
	want := []string{"hello", "oops", "world"}
	if len(nm.cur.lines) != 3 || nm.cur.lines[1] != want[1] || nm.cur.lines[2] != want[2] {
		t.Errorf("jobLines = %v, want interleaved %v", nm.cur.lines, want)
	}

	// Stale generation → ignored.
	u, cmd = nm.Update(ToolOutputMsg{JobID: "j", Generation: 99, Line: "nope"})
	nm = asModel(t, u)
	if len(nm.cur.lines) != 3 {
		t.Errorf("stale output must be dropped, jobLines = %v", nm.cur.lines)
	}
	if cmd != nil {
		t.Error("stale output must issue no cmd")
	}
}

// A terminal event for a stale job (wrong id/gen) is ignored.
func TestStaleToolDoneDropped(t *testing.T) {
	m := newModel(nil, false)
	m.generation = 2
	m.cur.active = &job{id: "j", cancel: func() {}}
	u, cmd := m.Update(ToolDoneMsg{JobID: "other", Generation: 2, Status: JobDone})
	nm := asModel(t, u)
	if nm.cur.active == nil {
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
	tool := Tool{Key: "z", Name: "helper", Bin: os.Args[0], Available: true,
		Build: func(*diagnostic.Target, net.IP) ([]string, []string, string) {
			return []string{"-test.run=TestHelperProcess"},
				append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE=lines", "GO_HELPER_N=1"),
				"helper"
		}}
	cmd := (&m).launchTool(tool) // must not panic
	if cmd == nil {
		t.Fatalf("launchTool returned no cmd (jobLines=%v)", m.cur.lines)
	}
	if m.ctx == nil {
		t.Fatal("launchTool must lazily initialize the context")
	}
	_, done := drain(t, m.cur.active.ch)
	if done.Status != JobDone {
		t.Errorf("status = %v, want JobDone", done.Status)
	}
	m.clearCancel()
}

// launchTool on a missing binary fails gracefully with an install hint and no cmd.
func TestLaunchToolUnavailable(t *testing.T) {
	m := newModel(nil, false)
	m.cur.dropped = 7
	m.cur.evicted = 9
	tool := Tool{
		Key: "z", Name: "nope", Bin: "network-doctor-no-such-binary-xyz",
		Build: func(*diagnostic.Target, net.IP) ([]string, []string, string) { return nil, nil, "nope" },
	}
	cmd := (&m).launchTool(tool)
	if cmd != nil {
		t.Error("a missing binary must not spawn anything")
	}
	if m.cur.status != JobFailed {
		t.Errorf("status = %v, want JobFailed", m.cur.status)
	}
	if len(m.cur.lines) == 0 || !strings.Contains(m.cur.lines[0], "not found") {
		t.Errorf("jobLines = %v, want a 'not found' hint", m.cur.lines)
	}
	if m.cur.dropped != 0 || m.cur.evicted != 0 {
		t.Errorf("jobDropped/jobEvicted = %d/%d, want 0/0", m.cur.dropped, m.cur.evicted)
	}
}

func TestLaunchToolStartErrorClearsPreviousJobState(t *testing.T) {
	m := newModel(nil, false)
	m.cur.dropped = 7
	m.cur.evicted = 9
	name := "bad-tool"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	// #nosec G306 -- the fixture must be executable to reach the exec-format failure path.
	if err := os.WriteFile(bin, []byte("not an executable format"), 0o755); err != nil {
		t.Fatal(err)
	}
	tool := Tool{
		Key: "z", Name: "bad tool", Bin: bin, Available: true,
		Build: func(*diagnostic.Target, net.IP) ([]string, []string, string) { return nil, nil, "bad-tool --display" },
	}
	cmd := (&m).launchTool(tool)
	if cmd != nil {
		t.Error("a start error must not return a running job command")
	}
	if m.cur.status != JobFailed {
		t.Errorf("status = %v, want JobFailed", m.cur.status)
	}
	if m.cur.display != "bad-tool --display" {
		t.Errorf("jobDisplay = %q, want built display string", m.cur.display)
	}
	if len(m.cur.lines) == 0 {
		t.Errorf("jobLines = %v, want an error line", m.cur.lines)
	}
	if m.cur.dropped != 0 || m.cur.evicted != 0 {
		t.Errorf("jobDropped/jobEvicted = %d/%d, want 0/0", m.cur.dropped, m.cur.evicted)
	}
}

// ---- render smoke tests (must not panic; show key labels) ----

func TestViewRenders(t *testing.T) {
	m := newModel(nil, false)
	out := m.View()
	for _, want := range []string{"Checking your connection", "Checks", "Details"} {
		if !strings.Contains(out, want) {
			t.Errorf("View missing %q", want)
		}
	}

	tb := newModel(nil, true)
	if !strings.Contains(tb.View(), "check your connection") {
		t.Error("deferred toolbox view must explain itself")
	}

	job := newModel(mustTarget(t, "github.com"), false)
	job.cur.status, job.cur.name, job.cur.display = JobDone, "ping", "ping github.com"
	job.cur.lines = []string{"64 bytes from ..."}
	if !strings.Contains(job.View(), "$ ping github.com") {
		t.Error("job view must show the command line")
	}

	net := newModel(nil, false)
	net.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Iface: "en0"}
	net.results[diagnostic.ProbeSSID] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Network: "HomeWiFi"}
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
	m.cur.active = &job{id: "j", ch: make(chan tea.Msg, 1)}
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

	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyUp})
	nm = asModel(t, u)
	if nm.follow {
		t.Error("scrolling up must pause follow mode")
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
	m.cur.active = &job{id: "j", ch: make(chan tea.Msg, 1)}
	m.cur.lines = make([]string, maxJobLines)
	m.cur.lines[0] = strings.Repeat("x", m.width+1) // two display rows
	for i := 1; i < maxJobLines; i++ {
		m.cur.lines[i] = fmt.Sprintf("line %d", i)
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

func TestViewportEvictionIgnoresFilteredOutLine(t *testing.T) {
	m := newModel(nil, false)
	m.width, m.height = 20, 10
	m.generation = 1
	m.cur.active = &job{id: "j", ch: make(chan tea.Msg, 1)}
	m.cur.lines = make([]string, maxJobLines)
	m.cur.lines[0] = "noise" // hidden by the filter
	for i := 1; i < maxJobLines; i++ {
		m.cur.lines[i] = fmt.Sprintf("line %d", i)
	}
	m.viewing, m.follow = true, false
	m.filter = "line"
	m.refreshViewport()
	m.vp.SetYOffset(10)

	u, _ := m.Update(ToolOutputMsg{JobID: "j", Generation: 1, Line: "line new"})
	nm := asModel(t, u)
	if nm.vp.YOffset != 10 {
		t.Fatalf("offset = %d, want 10: filtered view lost nothing at the top", nm.vp.YOffset)
	}
}

func TestEscClearsCommittedFilterBeforeClosing(t *testing.T) {
	m := newModel(nil, false)
	m.width, m.height = 40, 10
	m.viewing = true
	m.filter = "timeout"
	m.refreshViewport()

	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	nm := asModel(t, u)
	if !nm.viewing || nm.filter != "" {
		t.Fatalf("first esc must clear the filter and stay (viewing=%v filter=%q)", nm.viewing, nm.filter)
	}
	u, _ = nm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if nm = asModel(t, u); nm.viewing {
		t.Error("second esc must close the viewer")
	}
}

func TestFilterLines(t *testing.T) {
	lines := []string{"64 bytes from 1.1.1.1", "Request timeout", "64 bytes from 8.8.8.8"}
	if got := filterLines(lines, "TIMEOUT"); len(got) != 1 || got[0] != "Request timeout" {
		t.Fatalf("filterLines(TIMEOUT) = %v", got)
	}
	if got := filterLines(lines, ""); len(got) != 3 {
		t.Fatalf("empty filter dropped lines: %v", got)
	}
}

func TestPromptTargetHistory(t *testing.T) {
	up := tea.KeyMsg{Type: tea.KeyUp}
	down := tea.KeyMsg{Type: tea.KeyDown}
	enter := tea.KeyMsg{Type: tea.KeyEnter}

	m := newModel(mustTarget(t, "github.com:443"), false)
	step := func(msg tea.Msg) {
		u, _ := m.Update(msg)
		m = asModel(t, u)
	}
	step(keyMsg("r"))
	m.input.SetValue("one.test")
	step(enter) // restarts; history = [github.com:443, one.test]

	step(keyMsg("r")) // prefilled with the current target, one.test
	step(up)
	if got := m.input.Value(); got != "one.test" {
		t.Fatalf("first up = %q, want one.test", got)
	}
	step(up)
	if got := m.input.Value(); got != "github.com:443" {
		t.Fatalf("second up = %q, want github.com:443", got)
	}
	step(up) // at oldest; no-op
	if got := m.input.Value(); got != "github.com:443" {
		t.Fatalf("up past oldest = %q, want github.com:443", got)
	}
	step(down)
	step(down) // back to the prefilled draft
	if got := m.input.Value(); got != "one.test" {
		t.Fatalf("down to draft = %q, want one.test", got)
	}
}

func TestHistoryPersistsAcrossSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netdoc", "history")

	m := NewWithSelection(mustTarget(t, "github.com:443"), nil, false, false, path, "test", diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)
	u, _ := m.Update(keyMsg("r"))
	m = asModel(t, u)
	m.input.SetValue("one.test")
	u, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)

	// A fresh session relaunched with the same target loads both entries,
	// without duplicating the launch target it already knows.
	m2 := NewWithSelection(mustTarget(t, "one.test"), nil, false, false, path, "test", diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)
	if got := strings.Join(m2.history, ","); got != "github.com:443,one.test" {
		t.Fatalf("reloaded history = %q, want github.com:443,one.test", got)
	}
}

// The empty path is what --no-history hands the UI: nothing is loaded, a typed
// target is remembered for the session only, and the file already on disk is
// neither read nor rewritten.
func TestEmptyHistoryPathNeitherLoadsNorWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	const existing = "github.com:443\n"
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewWithSelection(mustTarget(t, "one.test"), nil, false, false, "", "test", diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)
	if got := strings.Join(m.history, ","); got != "one.test" {
		t.Fatalf("history = %q, want the launch target alone", got)
	}
	u, _ := m.Update(keyMsg("r"))
	m = asModel(t, u)
	m.input.SetValue("two.test")
	u, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	if got := strings.Join(m.history, ","); got != "one.test,two.test" {
		t.Fatalf("in-session history = %q, want both targets", got)
	}

	// #nosec G304 -- path is this test's temporary history fixture.
	if b, err := os.ReadFile(path); err != nil || string(b) != existing {
		t.Fatalf("history file = %q (err %v), want it untouched", b, err)
	}
}

func TestSaveHistoryDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "history")
	if err := os.Symlink(victim, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	saveHistory(path, []string{"one.test"})

	// #nosec G304 -- victim is this test's temporary symlink target.
	if b, err := os.ReadFile(victim); err != nil || string(b) != "precious\n" {
		t.Fatalf("symlink target = %q (err %v), want it untouched", b, err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("history path is still a symlink; write went through it")
	}
}

// Each row spins until its own name lands: the advertised batch clears the rows
// it named, a per-address reverse lookup clears the rest one at a time, and
// nmap's PTR placeholder is never shown in the meantime.
func TestNetworkMapSpinsPerRowUntilNamesArrive(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:22"), false)
	m.width = 100
	m.networkMap = true
	m.networkCIDR = "192.168.1.0/24"
	m.cur.name, m.cur.status = lanDiscoveryName, JobDone
	m.cur.lines = []string{
		"Host: 192.168.1.7 (unknownaabbcc.attlocal.net)\tStatus: Up",
		"Host: 192.168.1.8 (unknownddeeff.attlocal.net)\tStatus: Up",
	}
	ips := []string{"192.168.1.7", "192.168.1.8"}
	m.namesPending = map[string]bool{ips[0]: true, ips[1]: true}

	if view := m.View(); strings.Contains(view, "unknownaabbcc") || strings.Contains(view, "Domain:") {
		t.Fatalf("placeholder name or its domain shown while names are pending:\n%s", view)
	}
	if !m.spinnerActive() {
		t.Fatal("spinner tick chain must stay alive while names are pending")
	}

	// The advertised batch names one host and leaves the other to reverse DNS.
	u, _ := m.Update(lanNamesMsg{gen: 0, ips: ips, names: map[string]string{ips[0]: "printer"}})
	m = asModel(t, u)
	view := m.View()
	if !strings.Contains(view, "192.168.1.7 (printer)") || m.namesPending[ips[0]] {
		t.Fatalf("advertised name should have cleared its own row:\n%s", view)
	}
	if !m.namesPending[ips[1]] || strings.Contains(view, "unknownddeeff") {
		t.Fatalf("the unnamed row must keep spinning:\n%s", view)
	}

	// An empty reverse-DNS result still stops the spin, since there is nothing better
	// coming, so nmap's own name is finally the best on offer.
	u, _ = m.Update(lanNameMsg{gen: 0, ip: ips[1], name: ""})
	m = asModel(t, u)
	if view := m.View(); !strings.Contains(view, "192.168.1.8 (unknownddeeff)") || m.namesPending[ips[1]] {
		t.Fatalf("empty reverse lookup should end the spin and fall back to nmap:\n%s", view)
	}

	u, _ = m.Update(lanNameMsg{gen: 1, ip: ips[0], name: "stale"})
	if m = asModel(t, u); m.hostNames[ips[0]] != "printer" {
		t.Fatalf("stale-generation name must be ignored: %v", m.hostNames)
	}
}

// AdvertisedNames legitimately returns nil (non-Linux, or several Linux
// error paths); mergeLANNames must still hand back a usable map, and ssh
// aliases must keep winning collisions once one is allocated.
func TestMergeLANNames(t *testing.T) {
	if got := mergeLANNames(nil, map[string]string{"192.168.1.7": "printer"}); got["192.168.1.7"] != "printer" {
		t.Fatalf("nil advertised names must not drop aliases: %v", got)
	}

	got := mergeLANNames(
		map[string]string{"192.168.1.7": "attlocal-guess"},
		map[string]string{"192.168.1.7": "printer"},
	)
	if got["192.168.1.7"] != "printer" {
		t.Fatalf("ssh alias must win over an advertised name for the same IP: %v", got)
	}
}

// Tab with nothing in the selected slot must not park the zero jobState: a
// blank entry in the ring is a tab stop with no name, no command, no output.
func TestTabDoesNotParkAnEmptySlot(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.otherJobs = []jobState{{name: "ping", status: JobDone}}

	u, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm := asModel(t, u)
	if nm.cur.name != "ping" {
		t.Fatalf("tab must select the parked run, got %q", nm.cur.name)
	}
	if len(nm.otherJobs) != 0 {
		t.Fatalf("the empty slot must be dropped, not parked: %v", nm.otherJobs)
	}
}
