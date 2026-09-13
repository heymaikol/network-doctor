// TUI probe scheduling: sibling independence, skip propagation, and
// end-of-run bookkeeping.

package ui

import (
	"context"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func mustTarget(t *testing.T, s string) *diagnostic.Target {
	t.Helper()
	target, err := diagnostic.ParseTarget(s)
	if err != nil {
		t.Fatalf("parseTarget(%q): %v", s, err)
	}
	return target
}

// Generic mode: TCP/QUIC egress, proxy egress, and the DNS rows are siblings, so
// an egress failure must not skip DNS, so DNS-down-but-internet-up remains
// diagnosable.
func TestSiblingIndependence(t *testing.T) {
	m := newModel(nil, false)
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass}
	m.started[diagnostic.ProbeIface] = true
	cmds := m.scheduleStep()
	if len(cmds) != 7 {
		t.Fatalf("want 7 dispatched (TCP/QUIC internet, proxy, system/public/encrypted dns, ssid), got %d", len(cmds))
	}
	if !m.started[diagnostic.ProbeInternet] || !m.started[diagnostic.ProbeQUIC] || !m.started[diagnostic.ProbeProxy] || !m.started[diagnostic.ProbeDNS] || !m.started[diagnostic.ProbeDNSPublic] || !m.started[diagnostic.ProbeDNSEncrypted] || !m.started[diagnostic.ProbeSSID] {
		t.Fatal("TCP/QUIC internet+proxy+system/public/encrypted dns+ssid should all be dispatched")
	}
	if _, ok := m.results[diagnostic.ProbeDNS]; ok {
		t.Error("dns must be dispatched, not skipped by an egress failure")
	}
}

func TestSkipPropagation(t *testing.T) {
	m := newModel(mustTarget(t, "github.com"), false)
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeInternet] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{Status: diagnostic.StatusFail}
	m.started[diagnostic.ProbeIface], m.started[diagnostic.ProbeInternet], m.started[diagnostic.ProbeDNS] = true, true, true
	m.scheduleStep()
	if m.results[diagnostic.ProbeTargetTCP].Status != diagnostic.StatusSkip {
		t.Fatalf("target_tcp = %v, want Skip", m.results[diagnostic.ProbeTargetTCP].Status)
	}
	if m.results[diagnostic.ProbeTLS].Status != diagnostic.StatusSkip || m.results[diagnostic.ProbeHTTP].Status != diagnostic.StatusSkip || m.results[diagnostic.ProbeHTTPS].Status != diagnostic.StatusSkip {
		t.Error("skip must propagate through TLS, HTTP, and HTTPS")
	}
}

// When the last real probe result arrives and the run only completes via the
// skip cascade inside scheduleStep, Finalize must still run; otherwise
// a proxy-only network shows internet FAIL in the TUI but WARN in -json.
func TestDowngradeRunsWhenSkipsFinishRun(t *testing.T) {
	m := newModel(mustTarget(t, "github.com:443"), false)
	pass := func(id diagnostic.ProbeID) {
		m.results[id] = diagnostic.ProbeResult{ID: id, Status: diagnostic.StatusPass}
		m.started[id] = true
	}
	fail := func(id diagnostic.ProbeID) {
		m.results[id] = diagnostic.ProbeResult{ID: id, Status: diagnostic.StatusFail}
		m.started[id] = true
	}
	pass(diagnostic.ProbeIface)
	pass(diagnostic.ProbeSSID)
	fail(diagnostic.ProbeInternet)
	pass(diagnostic.ProbeQUIC)
	pass(diagnostic.ProbeProxy)
	pass(diagnostic.ProbeDNS)
	pass(diagnostic.ProbeDNSPublic)
	pass(diagnostic.ProbeDNSEncrypted)
	fail(diagnostic.ProbeHTTP)
	m.started[diagnostic.ProbeTargetTCP] = true // in flight; its done-msg arrives below

	u, _ := m.Update(probeDoneMsg{id: diagnostic.ProbeTargetTCP, gen: 0, res: diagnostic.ProbeResult{Status: diagnostic.StatusFail}})
	nm := asModel(t, u)
	if !nm.allDone() {
		t.Fatal("run should complete via the tls/https skip cascade")
	}
	if got := nm.results[diagnostic.ProbeInternet].Status; got != diagnostic.StatusWarn {
		t.Fatalf("internet = %v, want Warn (proxy works, egress downgraded)", got)
	}
}

func TestCompletedRunSelectsFirstFailure(t *testing.T) {
	m := newModel(mustTarget(t, "github.com:443"), false)
	for _, id := range []diagnostic.ProbeID{
		diagnostic.ProbeIface,
		diagnostic.ProbeSSID,
		diagnostic.ProbeInternet,
		diagnostic.ProbeQUIC,
		diagnostic.ProbeProxy,
		diagnostic.ProbeDNS,
		diagnostic.ProbeDNSPublic,
		diagnostic.ProbeDNSEncrypted,
		diagnostic.ProbeHTTP,
	} {
		m.results[id] = diagnostic.ProbeResult{ID: id, Status: diagnostic.StatusPass}
		m.started[id] = true
	}
	m.started[diagnostic.ProbeTargetTCP] = true

	u, _ := m.Update(probeDoneMsg{id: diagnostic.ProbeTargetTCP, res: diagnostic.ProbeResult{Status: diagnostic.StatusFail, Detail: "connection refused"}})
	nm := asModel(t, u)
	if nm.selected != 7 {
		t.Fatalf("selected = %d, want first failed probe 7", nm.selected)
	}
	// The row the run blames is the row the answer block quotes, so the
	// evidence for it is above the panels rather than inside one.
	if !strings.Contains(nm.banner(), "connection refused") {
		t.Error("the answer block must quote the selected failure")
	}
}

func TestWatchRecordsAndRestarts(t *testing.T) {
	m := newModel(mustTarget(t, "github.com:443"), false)
	m.watch = true
	for _, probe := range m.probes {
		m.started[probe.ID] = true
		m.results[probe.ID] = diagnostic.ProbeResult{ID: probe.ID, Status: diagnostic.StatusPass}
	}
	last := m.probes[len(m.probes)-1]
	m.results[last.ID] = diagnostic.ProbeResult{ID: last.ID, Status: diagnostic.StatusFail}

	u, cmd := m.Update(probeDoneMsg{id: last.ID, res: m.results[last.ID]})
	completed := asModel(t, u)
	if cmd == nil {
		t.Fatal("watched completion must schedule another pass")
	}
	for _, probe := range completed.probes {
		if got := len(completed.runHistory[probe.ID]); got != 1 {
			t.Fatalf("%s history length = %d, want 1", probe.ID, got)
		}
	}
	if got := completed.historyLine(last.ID); !strings.Contains(got, "failed 1 of 1 runs") {
		t.Fatalf("history summary = %q", got)
	}

	u, cmd = completed.Update(watchMsg{gen: completed.generation})
	restarted := asModel(t, u)
	if restarted.generation != completed.generation+1 || len(restarted.results) != 0 {
		t.Fatalf("watch restart generation/results = %d/%d", restarted.generation, len(restarted.results))
	}
	if len(restarted.runHistory[last.ID]) != 1 || cmd == nil {
		t.Fatal("watch restart must retain history and schedule the probe root")
	}
}

func TestWatchAndTargetRestartPreserveProbeSelection(t *testing.T) {
	selection := diagnostic.ProbeSelection{Check: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeTLS: {}}}
	m := NewWithSelection(mustTarget(t, "example.com"), nil, false, true, "", "test", diagnostic.DefaultPublicDNS, true, selection).(model)
	want := []diagnostic.ProbeID{diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeTLS}
	ids := func(probes []diagnostic.Probe) []diagnostic.ProbeID {
		got := make([]diagnostic.ProbeID, len(probes))
		for i, probe := range probes {
			got[i] = probe.ID
		}
		return got
	}
	if got := ids(m.probes); !reflect.DeepEqual(got, want) {
		t.Fatalf("initial probes = %v, want %v", got, want)
	}

	m.doRestart()
	if got := ids(m.probes); !reflect.DeepEqual(got, want) {
		t.Errorf("watch restart probes = %v, want %v", got, want)
	}
	m.applyTarget(mustTarget(t, "example.org"), true)
	if got := ids(m.probes); !reflect.DeepEqual(got, want) {
		t.Errorf("target restart probes = %v, want %v", got, want)
	}

	conditional := diagnostic.ProbeSelection{Check: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeSSH: {}}}
	m = NewWithSelection(nil, nil, false, false, "", "test", diagnostic.DefaultPublicDNS, true, conditional).(model)
	if len(m.probes) != 0 {
		t.Fatalf("generic SSH selection = %v, want empty", ids(m.probes))
	}
	m.applyTarget(mustTarget(t, "ssh://example.org"), true)
	want = []diagnostic.ProbeID{diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeSSH}
	if got := ids(m.probes); !reflect.DeepEqual(got, want) {
		t.Errorf("conditional selection after target change = %v, want %v", got, want)
	}
}

func TestEmptySelectionCompletesAndKeepsWatching(t *testing.T) {
	selection := diagnostic.ProbeSelection{Check: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeTLS: {}}}
	m := NewWithSelection(nil, nil, false, true, "", "test", diagnostic.DefaultPublicDNS, true, selection).(model)
	if !m.allDone() || ExitCode(m) != 0 || !strings.Contains(m.banner(), "No checks selected") {
		t.Fatalf("empty selection did not complete cleanly: done=%v exit=%d banner=%q", m.allDone(), ExitCode(m), m.banner())
	}
	u, cmd := m.Update(scheduleMsg{gen: m.generation})
	m = asModel(t, u)
	if cmd == nil {
		t.Fatal("empty watched selection did not schedule the next pass")
	}
}

// A watch tick refreshes results underneath the user: it must not close a
// modal they are typing into, dismiss a confirmation gate mid-decision, wipe
// the last notice, or yank a cursor they moved themselves.
func TestWatchPreservesOpenUIState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		open  func(m *model)
		check func(t *testing.T, m model)
	}{
		{"ssh form", func(m *model) {
			m.sshPrompt, m.ssh = true, newSSHForm(m.st, m.target)
			m.ssh.user.SetValue("operator")
		}, func(t *testing.T, m model) {
			if !m.sshPrompt {
				t.Error("watch tick closed the open SSH form")
			}
			if got := m.ssh.user.Value(); got != "operator" {
				t.Errorf("typed username = %q, want %q", got, "operator")
			}
		}},
		{"tool confirmation", func(m *model) {
			tool := m.tools[0]
			m.confirmTool = &tool
		}, func(t *testing.T, m model) {
			if m.confirmTool == nil {
				t.Error("watch tick dismissed the tool confirmation gate")
			}
		}},
		{"notice", func(m *model) { m.notice, m.noticeOK = "report saved to /tmp/report.txt", true },
			func(t *testing.T, m model) {
				if m.notice != "report saved to /tmp/report.txt" {
					t.Errorf("notice = %q, want it preserved", m.notice)
				}
			}},
		{"moved cursor", func(m *model) { m.selMoved = true }, func(t *testing.T, m model) {
			if !m.selMoved {
				t.Error("watch tick reset selMoved, re-yanking the cursor to the first failure")
			}
		}},
		{"network map", func(m *model) {
			m.width = 100
			m.networkMap, m.mapSelected, m.networkCIDR = true, 1, "192.168.12.0/24"
			m.hostNames = map[string]string{"192.168.12.1": "pihole"}
			m.cur.name, m.cur.status = lanDiscoveryName, JobDone
			m.cur.lines = []string{
				"Host: 192.168.12.1 (isp-cpe-4471.example)\tStatus: Up",
				"Host: 192.168.12.50 ()\tStatus: Up",
			}
		}, func(t *testing.T, m model) {
			if !m.networkMap || m.mapSelected != 1 || m.networkCIDR != "192.168.12.0/24" {
				t.Errorf("map state = open:%v sel:%d cidr:%q, want it preserved", m.networkMap, m.mapSelected, m.networkCIDR)
			}
			want := []string{"192.168.12.1 (pihole)", "192.168.12.50"}
			if got := m.networkHosts(); !reflect.DeepEqual(got, want) {
				t.Errorf("networkHosts = %v, want %v", got, want)
			}
			if view := m.View(); !strings.Contains(view, "192.168.12.0/24") || !strings.Contains(view, "pihole") {
				t.Errorf("watch tick stopped rendering the map:\n%s", view)
			}
		}},
		{"no network map", func(m *model) {}, func(t *testing.T, m model) {
			if m.networkMap || m.mapSelected != 0 || m.networkCIDR != "" || len(m.hostNames) != 0 {
				t.Errorf("map state = open:%v sel:%d cidr:%q names:%v, want all zero",
					m.networkMap, m.mapSelected, m.networkCIDR, m.hostNames)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newModel(mustTarget(t, "github.com:443"), false)
			m.watch = true
			for _, probe := range m.probes {
				m.started[probe.ID] = true
				m.results[probe.ID] = diagnostic.ProbeResult{ID: probe.ID, Status: diagnostic.StatusPass}
			}
			tc.open(&m)

			restarted := asModel(t, must(m.Update(watchMsg{gen: m.generation})))
			if restarted.generation != m.generation+1 {
				t.Fatalf("watch tick did not restart: generation = %d", restarted.generation)
			}
			tc.check(t, restarted)
		})
	}
}

func TestWatchHistoryKeepsLastTwentyRuns(t *testing.T) {
	m := newModel(nil, false)
	m.watch = true
	for run := 0; run < watchRuns+1; run++ {
		for _, probe := range m.probes {
			status := diagnostic.StatusPass
			if probe.ID == diagnostic.ProbeIface && run%2 == 0 {
				status = diagnostic.StatusFail
			}
			m.results[probe.ID] = diagnostic.ProbeResult{ID: probe.ID, Status: status}
		}
		m.recordRun()
	}
	history := m.runHistory[diagnostic.ProbeIface]
	if len(history) != watchRuns {
		t.Fatalf("history length = %d, want %d", len(history), watchRuns)
	}
	if history[0] != diagnostic.StatusPass {
		t.Fatalf("oldest retained status = %v, want second run's PASS", history[0])
	}
}

// blockUntilDone is the diagnostic-side helper's twin: a probe that only ends
// when its context does, so a runProbe that dropped the timeout wrapper hangs
// instead of passing.
func blockUntilDone(id diagnostic.ProbeID) diagnostic.Probe {
	return diagnostic.Probe{ID: id, Name: string(id), Run: func(ctx context.Context, _ map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
		if _, ok := ctx.Deadline(); !ok {
			return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Detail: "no deadline"}
		}
		<-ctx.Done()
		return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Detail: ctx.Err().Error()}
	}}
}

// The bounded-time guarantee, TUI half: runProbe wraps each probe in its own
// probeTimeout child of the model context, so a stuck probe still lands as a
// probeDoneMsg instead of freezing the run.
func TestRunProbeBoundsProbe(t *testing.T) {
	m := newModel(nil, false)
	m.probeTimeout = 20 * time.Millisecond
	m.ctx = context.Background()
	msg := m.runProbe(blockUntilDone("slow"))()
	done, ok := msg.(probeDoneMsg)
	if !ok {
		t.Fatalf("msg = %T, want probeDoneMsg", msg)
	}
	if done.id != "slow" || done.gen != m.generation {
		t.Errorf("msg id/gen = %q/%d, want slow/%d", done.id, done.gen, m.generation)
	}
	if done.res.Detail != context.DeadlineExceeded.Error() {
		t.Errorf("detail = %q, want %q", done.res.Detail, context.DeadlineExceeded)
	}
}

// Quitting cancels the model context; the per-probe timeout is a child of it,
// so in-flight probes must unwind rather than outlive the TUI.
func TestRunProbePropagatesCancellation(t *testing.T) {
	m := newModel(nil, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.ctx = ctx
	msg := m.runProbe(blockUntilDone("slow"))()
	if got := msg.(probeDoneMsg).res.Detail; got != context.Canceled.Error() {
		t.Errorf("detail = %q, want %q", got, context.Canceled)
	}
}

func TestNADoesNotBlock(t *testing.T) {
	m := newModel(mustTarget(t, "1.1.1.1"), false)
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeInternet] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{Status: diagnostic.StatusNA, Addrs: []net.IP{net.ParseIP("1.1.1.1")}}
	m.started[diagnostic.ProbeIface], m.started[diagnostic.ProbeInternet], m.started[diagnostic.ProbeDNS] = true, true, true
	m.scheduleStep()
	if _, ok := m.results[diagnostic.ProbeTargetTCP]; ok {
		t.Fatal("an NA dependency must not skip target_tcp")
	}
	if !m.started[diagnostic.ProbeTargetTCP] {
		t.Fatal("target_tcp should be dispatched after an NA dependency")
	}
}

// The TUI's probe budget belongs to the model, not to the package. The second
// model is constructed after the first one's command is built but before it
// runs, which is the exact window a package-level timeout would leak through:
// under a global, m1's probe would come back carrying m2's value.
func TestRunProbeTimeoutIsPerModel(t *testing.T) {
	const short, long = 2 * time.Second, time.Hour

	budget := make(chan time.Duration, 2)
	reportBudget := diagnostic.Probe{ID: "p", Name: "p", Run: func(ctx context.Context, _ map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
		dl, ok := ctx.Deadline()
		if !ok {
			budget <- 0 // no deadline at all fails both bounds below
			return diagnostic.ProbeResult{Status: diagnostic.StatusFail}
		}
		budget <- time.Until(dl)
		return diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	}}

	m1 := NewWithSelection(nil, nil, false, false, "", "test", "", false, diagnostic.ProbeSelection{}, WithProbeTimeout(short)).(model)
	m1.ctx = context.Background()
	cmd := m1.runProbe(reportBudget)

	m2 := NewWithSelection(nil, nil, false, false, "", "test", "", false, diagnostic.ProbeSelection{}, WithProbeTimeout(long)).(model)
	m2.ctx = context.Background()

	cmd()
	if got := <-budget; got <= 0 || got > short {
		t.Errorf("first model's probe budget = %v, want (0, %v]", got, short)
	}
	m2.runProbe(reportBudget)()
	if got := <-budget; got <= time.Minute {
		t.Errorf("second model's probe budget = %v, want well over a minute", got)
	}
}

// The TUI half of the concurrency invariant. Bubble Tea runs a batch's commands
// on their own goroutines, so what this scheduler owes the run is a command per
// ready probe, each of which does its work when it is called rather than when
// it is built. A dispatcher that ran probes while assembling the batch would
// turn the whole layer into one serial pass no matter what the runtime did.
//
// The gate is a barrier, not a stopwatch: every probe reports only once its
// whole layer is in flight, so a serialized dispatcher deadlocks into its own
// probe timeout instead of producing a wall-clock number a busy runner could
// also produce.
func TestScheduleStepDispatchesEveryReadyProbeConcurrently(t *testing.T) {
	m := newModel(nil, false)
	m.ctx = context.Background()
	m.probeTimeout = 2 * time.Second

	// Every probe below the interface row: the seven checks the generic DAG
	// makes ready at once.
	var siblings []diagnostic.Probe
	for _, p := range m.probes {
		if p.ID != diagnostic.ProbeIface {
			siblings = append(siblings, p)
		}
	}
	var arrived sync.WaitGroup
	arrived.Add(len(siblings))
	open := make(chan struct{})
	go func() {
		arrived.Wait()
		close(open)
	}()
	var built atomic.Int32
	for i, p := range m.probes {
		if p.ID == diagnostic.ProbeIface {
			m.probes[i].Run = func(context.Context, map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
				return diagnostic.ProbeResult{Status: diagnostic.StatusPass}
			}
			continue
		}
		m.probes[i].Run = func(ctx context.Context, _ map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
			built.Add(1)
			arrived.Done()
			select {
			case <-open:
				return diagnostic.ProbeResult{Status: diagnostic.StatusPass}
			case <-ctx.Done():
				return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Detail: "the layer never had every probe in flight at once: " + ctx.Err().Error()}
			}
		}
	}

	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass}
	m.started[diagnostic.ProbeIface] = true
	cmds := m.scheduleStep()
	if len(cmds) != len(siblings) {
		t.Fatalf("scheduleStep dispatched %d commands, want one per ready probe (%d)", len(cmds), len(siblings))
	}
	// Assembling the batch must not have run anything: the work belongs to the
	// command, which the runtime is free to place on its own goroutine.
	if got := built.Load(); got != 0 {
		t.Fatalf("%d probes ran while the batch was being built", got)
	}

	msgs := make(chan tea.Msg, len(cmds))
	for _, cmd := range cmds {
		go func() { msgs <- cmd() }()
	}
	for range cmds {
		done, ok := (<-msgs).(probeDoneMsg)
		if !ok {
			t.Fatal("a dispatched command produced something other than a probe result")
		}
		if done.res.Status != diagnostic.StatusPass {
			t.Errorf("%s: %s", done.id, done.res.Detail)
		}
	}
}
