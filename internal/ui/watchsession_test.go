package ui

import (
	"context"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	ndoc "github.com/heymaikol/network-doctor/internal/snapshot"
)

// tuiLink is the network under a TUI Watch test. While down, the target's TCP
// connect fails and the rows behind it are skipped. While tlsDown, the TLS row
// fails and nothing else does, which is a fault only a reused row can hide.
type tuiLink struct {
	down    atomic.Bool
	tlsDown atomic.Bool
	// targets counts the target connects that ran, so a test can tell how many
	// passes ran, not only how many were recorded.
	targets atomic.Int32
	// runs counts every probe that ran, for the rows a pass executed.
	runs atomic.Int64
}

// tuiFakeProbes is the production row shape with each row replaced by a fake
// that passes, except the target connect while the link is down. A fake that
// runs is timed the way the production probe bodies are, so its result reports
// a duration. A reused row is not run and keeps the zero duration it reports in
// production.
func tuiFakeProbes(target *diagnostic.Target, link *tuiLink) []diagnostic.Probe {
	probes := diagnostic.ProbePlan(target, diagnostic.DefaultPublicDNS, true)
	for i := range probes {
		id := probes[i].ID
		probes[i].Run = func(_ context.Context, _ map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
			link.runs.Add(1)
			if id == diagnostic.ProbeTargetTCP {
				link.targets.Add(1)
				if link.down.Load() {
					return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Cause: "timeout", Dur: time.Millisecond}
				}
			}
			if id == diagnostic.ProbeTLS && link.tlsDown.Load() {
				return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Cause: "tls-handshake", Dur: time.Millisecond}
			}
			return diagnostic.ProbeResult{Status: diagnostic.StatusPass, Dur: time.Millisecond}
		}
	}
	return probes
}

// settleWait caps one command. A fake probe finishes in microseconds, so a
// command that is still running after this is a timer: a notice expiry or a
// Watch tick. Timers are dropped rather than waited for.
const settleWait = 500 * time.Millisecond

func runCmd(c tea.Cmd) tea.Msg {
	done := make(chan tea.Msg, 1)
	go func() { done <- c() }()
	select {
	case msg := <-done:
		return msg
	case <-time.After(settleWait):
		return nil
	}
}

// settleWatch runs the commands an Update returned, as the program does, and
// feeds each probe and schedule message back through Update until no work is
// left. Watch ticks, notice timers, and spinner frames are dropped: each pass in
// these tests is started by the test, not by a tick.
func settleWatch(t *testing.T, m model, cmds ...tea.Cmd) model {
	t.Helper()
	queue := append([]tea.Cmd(nil), cmds...)
	for steps := 0; len(queue) > 0; steps++ {
		if steps > 1000 {
			t.Fatal("commands did not settle")
		}
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		switch msg := runCmd(c).(type) {
		case tea.BatchMsg:
			queue = append(queue, msg...)
		case scheduleMsg, probeDoneMsg:
			u, next := m.Update(msg)
			m = asModel(t, u)
			queue = append(queue, next)
		}
	}
	return m
}

// startWatchPass starts the next pass the way a Watch tick does, once the last
// pass is done. A discarded pass starts the one after it inside the same call.
func startWatchPass(t *testing.T, m model) model {
	t.Helper()
	if !m.allDone() {
		t.Fatal("previous pass is still running")
	}
	u, cmd := m.Update(watchMsg{gen: m.generation})
	return settleWatch(t, asModel(t, u), cmd)
}

// The TUI runs the real probe commands through the Watch session. A stable pass
// answers its passing rows from the last pass, so it runs fewer rows than the
// graph. A status change is confirmed before it is published, so the history
// holds one entry per published pass and nothing a discarded pass measured.
func TestWatchSessionRecordsOnlyPublishedPassesThroughTheTUI(t *testing.T) {
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	target := mustTarget(t, "example.com:443")
	link := &tuiLink{}
	m := watchModel(t)
	m.graph = func(*diagnostic.Target) []diagnostic.Probe { return tuiFakeProbes(target, link) }
	m.buildPass()

	m = settleWatch(t, m, m.Init())
	if !m.allDone() {
		t.Fatal("first pass did not finish")
	}
	if got := m.runHistory[diagnostic.ProbeTargetTCP]; !reflect.DeepEqual(got, []diagnostic.Status{diagnostic.StatusPass}) {
		t.Fatalf("after the first pass, target history = %v, want one pass", got)
	}

	before := link.runs.Load()
	m = startWatchPass(t, m)
	if ran := link.runs.Load() - before; ran >= int64(len(m.probes)) {
		t.Errorf("stable pass ran %d of %d rows, want fewer: passing rows are reused", ran, len(m.probes))
	}
	if !anyReused(m) {
		t.Error("stable pass reused no row")
	}
	if got := m.runHistory[diagnostic.ProbeTargetTCP]; len(got) != 2 {
		t.Fatalf("after a stable pass, target history = %v, want two entries", got)
	}

	link.down.Store(true)
	beforeTargets := link.targets.Load()
	m = startWatchPass(t, m)
	// The reused rows still pass, so the pass that sees the fault is discarded,
	// and the confirming pass runs every row before anything is published.
	if ran := link.targets.Load() - beforeTargets; ran != 2 {
		t.Errorf("fault took %d target connects, want 2: the first pass is discarded and the confirmation is fresh", ran)
	}
	wantFault := []diagnostic.Status{diagnostic.StatusPass, diagnostic.StatusPass, diagnostic.StatusFail}
	if got := m.runHistory[diagnostic.ProbeTargetTCP]; !reflect.DeepEqual(got, wantFault) {
		t.Errorf("after the fault, target history = %v, want %v", got, wantFault)
	}
	if got := m.results[diagnostic.ProbeTargetTCP].Status; got != diagnostic.StatusFail {
		t.Errorf("shown target status = %v, want fail from the confirmed pass", got)
	}

	link.down.Store(false)
	beforeTargets = link.targets.Load()
	m = startWatchPass(t, m)
	if ran := link.targets.Load() - beforeTargets; ran != 1 {
		t.Errorf("recovery took %d target connects, want 1", ran)
	}
	wantRecovered := []diagnostic.Status{diagnostic.StatusPass, diagnostic.StatusPass, diagnostic.StatusFail, diagnostic.StatusPass}
	if got := m.runHistory[diagnostic.ProbeTargetTCP]; !reflect.DeepEqual(got, wantRecovered) {
		t.Errorf("after recovery, target history = %v, want %v", got, wantRecovered)
	}
}

// exportedIncident runs the export the w key runs on the newest incident. The
// file write and the home lookup are captured, so nothing reaches disk. The
// bytes that would have been written are decoded, which validates them the way
// a reader does.
func exportedIncident(t *testing.T, m model) ndoc.Snapshot {
	t.Helper()
	items := m.incidents.Incidents()
	if len(items) == 0 {
		t.Fatal("no incident was recorded")
	}
	oldWriteFile, oldUserHomeDir := incidentWriteFile, reportUserHomeDir
	t.Cleanup(func() {
		incidentWriteFile, reportUserHomeDir = oldWriteFile, oldUserHomeDir
	})
	reportUserHomeDir = func() (string, error) { return t.TempDir(), nil }
	var data []byte
	incidentWriteFile = func(_ string, content []byte, _ os.FileMode) error {
		data = append([]byte(nil), content...)
		return nil
	}
	if notice, ok := exportIncident(items[len(items)-1], time.Now()); !ok {
		t.Fatalf("export failed: %s", notice)
	}
	s, err := ndoc.Decode(data)
	if err != nil {
		t.Fatalf("exported incident does not decode: %v", err)
	}
	return s
}

// The last healthy pass before an outage is the incident's Before state, and
// the incident keeps it. A healthy pass that reused a row is not kept, so the
// Before state is a pass that measured every row. The export must encode.
func TestWatchIncidentExportKeepsAStableHealthyBefore(t *testing.T) {
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	target := mustTarget(t, "example.com:443")
	link := &tuiLink{}
	m := watchModel(t)
	m.graph = func(*diagnostic.Target) []diagnostic.Probe { return tuiFakeProbes(target, link) }
	m.buildPass()
	m = settleWatch(t, m, m.Init())
	m = startWatchPass(t, m)
	link.down.Store(true)
	m = startWatchPass(t, m)

	s := exportedIncident(t, m)
	if s.Incident == nil || s.Incident.Before == nil {
		t.Fatal("incident has no Before state, want the healthy pass before the outage")
	}
	if !s.Incident.Before.OK || s.OK {
		t.Errorf("Before ok=%v, onset ok=%v, want a healthy Before and a failing onset", s.Incident.Before.OK, s.OK)
	}

	link.down.Store(false)
	m = startWatchPass(t, m)
	s = exportedIncident(t, m)
	if s.Incident == nil || s.Incident.Recovered == nil || !s.Incident.Recovered.OK {
		t.Errorf("recovered incident has no healthy Recovered state")
	}
}

// A session that opens during a failure has no earlier state. The export must
// say so rather than invent one, and the recovery must still encode.
func TestWatchIncidentExportBeginningInTheFirstPass(t *testing.T) {
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	target := mustTarget(t, "example.com:443")
	link := &tuiLink{}
	link.down.Store(true)
	m := watchModel(t)
	m.graph = func(*diagnostic.Target) []diagnostic.Probe { return tuiFakeProbes(target, link) }
	m.buildPass()
	m = settleWatch(t, m, m.Init())
	m = startWatchPass(t, m)
	// The stable failing pass must join the open incident as a plain repeat: one
	// more failing pass, no During state, and no step recorded. A reused row would
	// read as changed here, so this holds only while every row is measured.
	open := m.incidents.Incidents()
	if len(open) != 1 {
		t.Fatalf("incidents = %d, want the one open incident", len(open))
	}
	if got := open[0]; got.Passes != 2 || got.During != nil || len(got.Steps) != 0 {
		t.Errorf("open incident has %d failing passes, during=%v, %d steps; want 2, none, none", got.Passes, got.During != nil, len(got.Steps))
	}

	link.down.Store(false)
	m = startWatchPass(t, m)
	s := exportedIncident(t, m)
	if s.Incident == nil || s.Incident.Before != nil {
		t.Errorf("incident Before present = %v, want absent: the session began during the failure", s.Incident != nil && s.Incident.Before != nil)
	}
	if s.Incident == nil || s.Incident.Recovered == nil || !s.Incident.Recovered.OK {
		t.Errorf("recovered incident has no healthy Recovered state")
	}
}

// A new target starts a new session, and it reuses nothing from the last one.
// Its stable pass before the outage is the Before state of the incident it opens.
func TestWatchIncidentExportAfterATargetSwitch(t *testing.T) {
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	link := &tuiLink{}
	m := watchModel(t)
	m.graph = func(target *diagnostic.Target) []diagnostic.Probe { return tuiFakeProbes(target, link) }
	m.buildPass()
	m = settleWatch(t, m, m.Init())
	u, cmd := m.restartWithTarget(mustTarget(t, "other.test:443"), true)
	m = settleWatch(t, asModel(t, u), cmd)
	m = startWatchPass(t, m)
	link.down.Store(true)
	m = startWatchPass(t, m)

	s := exportedIncident(t, m)
	if s.Incident == nil || s.Incident.Before == nil || !s.Incident.Before.OK {
		t.Fatal("incident after a target switch has no healthy Before state")
	}
}

// A retest asks for fresh evidence. Every row runs, including the rows a stable
// pass would have reused.
func TestWatchRetestRunsEveryRowThroughTheTUI(t *testing.T) {
	prevEvery := WatchEvery
	WatchEvery = time.Millisecond
	t.Cleanup(func() { WatchEvery = prevEvery })

	target := mustTarget(t, "example.com:443")
	link := &tuiLink{}
	m := watchModel(t)
	m.graph = func(*diagnostic.Target) []diagnostic.Probe { return tuiFakeProbes(target, link) }
	m.buildPass()
	m = settleWatch(t, m, m.Init())
	m = startWatchPass(t, m)

	before := link.runs.Load()
	u, cmd := m.retest()
	m = settleWatch(t, asModel(t, u), cmd)
	if ran := link.runs.Load() - before; ran != int64(len(m.probes)) {
		t.Errorf("retest ran %d rows, want all %d", ran, len(m.probes))
	}
}

// anyReused reports whether the shown results include a row answered from an
// earlier pass.
func anyReused(m model) bool {
	for _, r := range m.results {
		if _, reused := r.ReusedFrom(); reused {
			return true
		}
	}
	return false
}
