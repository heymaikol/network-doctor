package ui

import (
	"context"
	"net"
	"reflect"
	"slices"
	"testing"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// Complete through Update without executing any probe commands.
func diagnosisReuseModel(t *testing.T) model {
	t.Helper()
	m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "test", "", false,
		diagnostic.ProbeSelection{}).(model)
	m.width, m.height = 100, 40
	last := m.probes[len(m.probes)-1]
	for _, p := range m.probes {
		m.started[p.ID] = true
		if p.ID != last.ID {
			m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
		}
	}
	u, _ := m.Update(probeDoneMsg{id: last.ID, gen: m.generation,
		res: diagnostic.ProbeResult{Status: diagnostic.StatusFail, Detail: "no response"}})
	return asModel(t, u)
}

func assertAnalysisFresh(t *testing.T, m model) {
	t.Helper()
	if !m.analysisReady {
		t.Fatal("Update returned without storing the current analysis")
	}
	order := diagnostic.ProbeOrder(m.probes)
	want := diagnostic.Interpret(m.target, order, m.results)
	if !reflect.DeepEqual(m.analysis.diagnosis, want) || !slices.Equal(m.analysis.order, order) {
		t.Fatalf("stale diagnosis or order: got %#v, want %#v", m.analysis.diagnosis, want)
	}
	if !reflect.DeepEqual(m.analysis.collateral, want.Collateral(order, m.results)) ||
		m.analysis.explanation != want.Explain(m.target, order, m.results) {
		t.Fatal("stale collateral or explanation")
	}
}

func TestDiagnosisReusePartialUpdates(t *testing.T) {
	m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "test", "", false,
		diagnostic.ProbeSelection{}).(model)
	assertAnalysisFresh(t, m)
	for _, p := range m.probes {
		m.started[p.ID] = true
	}
	for i, p := range m.probes {
		before := m
		m = asModel(t, must(m.Update(probeDoneMsg{id: p.ID, gen: m.generation,
			res: diagnostic.ProbeResult{Status: diagnostic.StatusPass}})))
		assertAnalysisFresh(t, m)
		assertAnalysisFresh(t, before)
		if len(before.results) != i {
			t.Fatal("a result write changed a saved model's inputs")
		}
		if i < len(m.probes)-1 && m.diagnosis().Verdict != diagnostic.VerdictIncomplete {
			t.Fatal("partial results produced a completed diagnosis")
		}
	}
	if !m.allDone() || m.diagnosis().Verdict == diagnostic.VerdictIncomplete {
		t.Fatal("completion retained the partial diagnosis")
	}
}

func TestDiagnosisReuseStatusAndEvidenceChanges(t *testing.T) {
	m := diagnosisReuseModel(t)
	for _, status := range []diagnostic.Status{diagnostic.StatusPass, diagnostic.StatusWarn, diagnostic.StatusFail, diagnostic.StatusSkip} {
		before := m
		m = asModel(t, must(m.Update(probeDoneMsg{id: diagnostic.ProbeTLS, gen: m.generation,
			res: diagnostic.ProbeResult{Status: status, Cause: diagnostic.TLSCauseCertificateExpired}})))
		assertAnalysisFresh(t, m)
		assertAnalysisFresh(t, before)
	}
	// Same status and map length, but a different cause must change the finding.
	for _, cause := range []string{diagnostic.TLSCauseCertificateExpired, diagnostic.TLSCauseHostnameMismatch} {
		before := m
		m = asModel(t, must(m.Update(probeDoneMsg{id: diagnostic.ProbeTLS, gen: m.generation,
			res: diagnostic.ProbeResult{Status: diagnostic.StatusFail, Cause: cause}})))
		assertAnalysisFresh(t, m)
		assertAnalysisFresh(t, before)
		if reflect.DeepEqual(m.diagnosis(), before.diagnosis()) {
			t.Fatal("changed TLS evidence retained the previous diagnosis")
		}
	}
}

func TestDiagnosisReuseAfterFinalization(t *testing.T) {
	m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "test", "", false,
		diagnostic.ProbeSelection{}).(model)
	last := m.probes[len(m.probes)-1]
	for _, p := range m.probes {
		m.started[p.ID] = true
		if p.ID != last.ID {
			m.results[p.ID] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
		}
	}
	m.results[diagnostic.ProbeInternet] = diagnostic.ProbeResult{Status: diagnostic.StatusFail}
	m.results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, SelectedIP: net.ParseIP("203.0.113.1")}
	m.refreshAnalysis()
	before := m
	m = asModel(t, must(m.Update(probeDoneMsg{id: last.ID, gen: m.generation,
		res: diagnostic.ProbeResult{Status: diagnostic.StatusPass}})))
	assertAnalysisFresh(t, m)
	assertAnalysisFresh(t, before)
	if m.results[diagnostic.ProbeInternet].Status != diagnostic.StatusWarn ||
		before.results[diagnostic.ProbeInternet].Status != diagnostic.StatusFail {
		t.Fatal("finalization did not preserve the previous result revision")
	}
}

func TestDiagnosisReuseSchedulerSkips(t *testing.T) {
	m := NewWithSelection(nil, nil, false, false, "", "test", "", false, diagnostic.ProbeSelection{}).(model)
	// Use a small deterministic DAG to exercise synchronous skip propagation.
	m.probes = []diagnostic.Probe{
		{ID: diagnostic.ProbeIface},
		{ID: diagnostic.ProbeDNS, Deps: []diagnostic.ProbeID{diagnostic.ProbeIface}},
		{ID: diagnostic.ProbeTargetTCP, Deps: []diagnostic.ProbeID{diagnostic.ProbeDNS}},
	}
	m.refreshAnalysis()
	m.started[diagnostic.ProbeIface] = true
	before := m
	m = asModel(t, must(m.Update(probeDoneMsg{id: diagnostic.ProbeIface, gen: m.generation,
		res: diagnostic.ProbeResult{Status: diagnostic.StatusFail}})))
	assertAnalysisFresh(t, m)
	assertAnalysisFresh(t, before)
	if !m.allDone() || m.results[diagnostic.ProbeTargetTCP].Status != diagnostic.StatusSkip {
		t.Fatal("synchronous skips did not complete the run")
	}
	// scheduleMsg can also record skips without a new probeDoneMsg.
	m = before
	m.results = map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface: {Status: diagnostic.StatusFail},
	}
	m.started = map[diagnostic.ProbeID]bool{diagnostic.ProbeIface: true}
	m.refreshAnalysis()
	before = m
	m = asModel(t, must(m.Update(scheduleMsg{gen: m.generation})))
	t.Cleanup(m.clearCancel)
	assertAnalysisFresh(t, m)
	assertAnalysisFresh(t, before)
	if !m.allDone() {
		t.Fatal("scheduleMsg retained partial results after skip propagation")
	}
}

func TestDiagnosisReuseRunBoundaries(t *testing.T) {
	for _, action := range []string{"watch", "restart", "target", "selection", "order", "deferred restart"} {
		t.Run(action, func(t *testing.T) {
			m := diagnosisReuseModel(t)
			before := m
			switch action {
			case "watch":
				m.watch = true
				m = asModel(t, must(m.Update(watchMsg{gen: m.generation})))
			case "restart":
				m = asModel(t, must(m.retest()))
			case "target":
				m = asModel(t, must(m.restartWithTarget(mustTarget(t, "other.example:22"), true)))
			case "selection":
				m.selection = diagnostic.ProbeSelection{Check: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeDNS: {}}}
				m = asModel(t, must(m.restartWithTarget(m.target, false)))
			case "order":
				m.probes = slices.Clone(m.probes)
				slices.Reverse(m.probes)
				_ = m.restartRun()
			case "deferred restart":
				m.cur = jobState{status: JobRunning, active: &job{cancel: func() {}}}
				m = asModel(t, must(m.restartWithTarget(mustTarget(t, "other.example:22"), true)))
				assertAnalysisFresh(t, m)
				m.cur.active, m.cur.status = nil, JobCanceled
				m = asModel(t, must(m.runPending(m.pending)))
			}
			assertAnalysisFresh(t, m)
			assertAnalysisFresh(t, before)
			if m.generation != before.generation+1 || len(m.results) != 0 || m.diagnosis().Verdict != diagnostic.VerdictIncomplete {
				t.Fatal("new generation retained the completed diagnosis")
			}
			m = asModel(t, must(m.Update(probeDoneMsg{id: before.probes[0].ID, gen: before.generation,
				res: diagnostic.ProbeResult{Status: diagnostic.StatusFail}})))
			assertAnalysisFresh(t, m)
			if len(m.results) != 0 {
				t.Fatal("stale completion changed the new generation")
			}
		})
	}
}

func TestDiagnosisReuseCosmeticUpdates(t *testing.T) {
	m := diagnosisReuseModel(t)
	order := &m.analysis.order[0]
	for _, msg := range []tea.Msg{spinner.TickMsg{}, keyMsg("j"), tea.WindowSizeMsg{Width: 80, Height: 20}} {
		m = asModel(t, must(m.Update(msg)))
		if !m.analysisReady || &m.analysis.order[0] != order {
			t.Fatal("cosmetic update recomputed the analysis")
		}
		_ = m.View()
	}
}

func TestDiagnosisReuseCancellation(t *testing.T) {
	m := diagnosisReuseModel(t)
	m.ctx, m.cancel = context.WithCancel(context.Background())
	order := &m.analysis.order[0]
	m = asModel(t, must(m.quit()))
	if m.ctx.Err() != context.Canceled || &m.analysis.order[0] != order {
		t.Fatal("cancellation changed immutable diagnostic inputs")
	}
	// A cancelled probe is still a new result if its generation is current.
	m = asModel(t, must(m.Update(probeDoneMsg{id: diagnostic.ProbeTLS, gen: m.generation,
		res: diagnostic.ProbeResult{Status: diagnostic.StatusFail, Cause: diagnostic.TLSCauseTimeout}})))
	assertAnalysisFresh(t, m)
}

func TestDiagnosisReuseStableResults(t *testing.T) {
	m := diagnosisReuseModel(t)
	if allocs := testing.AllocsPerRun(10, func() { _ = m.diagnosis() }); allocs != 0 {
		t.Fatalf("unchanged diagnosis allocated %.0f times per read; want 0", allocs)
	}
}

// Run separately with -covermode=count -coverpkg=./internal/diagnostic to
// count Interpret's entry block for one versus ten completed renders.
func TestDiagnosisReuseRenderOnce(t *testing.T) { diagnosisReuseRender(t, 1) }
func TestDiagnosisReuseRenderTen(t *testing.T)  { diagnosisReuseRender(t, 10) }

func diagnosisReuseRender(t *testing.T, renders int) {
	t.Helper()
	m := diagnosisReuseModel(t)
	var first string
	for i := range renders {
		view := m.View()
		if i == 0 {
			first = view
		} else if view != first {
			t.Fatal("unchanged completed results rendered differently")
		}
	}
}
