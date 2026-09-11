// The causal path strip: which rungs it draws, where they come from, and the
// one thing it is allowed to claim about a failure.

package ui

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// planFor is the probe DAG a run really gets for this target and selection:
// the same builder the model uses, filtered by the same dependency closure.
func planFor(t *testing.T, spec string, sel diagnostic.ProbeSelection) []diagnostic.Probe {
	t.Helper()
	var target *diagnostic.Target
	if spec != "" {
		target = mustTarget(t, spec)
	}
	return sel.BuildProbesFromSources(target, nil, diagnostic.DefaultPublicDNS, true)
}

// pathRun is a finished run over spec in which the named rows carry the named
// statuses, every rung whose dependency failed is skipped the way the scheduler
// skips it, and everything else passed. It leaves each case below naming only
// the result it is about.
func pathRun(t *testing.T, spec string, status map[diagnostic.ProbeID]diagnostic.Status) model {
	t.Helper()
	m := newModel(mustTarget(t, spec), false)
	settled := map[diagnostic.ProbeID]diagnostic.Status{}
	for id, s := range status {
		settled[id] = s
	}
	// m.probes is in dependency order, so one pass settles every skip. A row
	// with no entry passed, which is the zero Status, so an absent dependency
	// blocks nothing.
	for _, p := range m.probes {
		if _, given := settled[p.ID]; given {
			continue
		}
		for _, dep := range p.Deps {
			if s := settled[dep]; s == diagnostic.StatusFail || s == diagnostic.StatusSkip {
				settled[p.ID] = diagnostic.StatusSkip
				break
			}
		}
	}
	finishedRun(&m, settled)
	m.width = 100
	return m
}

// pathLine is the strip as plain text, which is what a reader without colour
// sees and all any of these tests are about.
func pathLine(m model) string { return ansi.Strip(m.pathView()) }

// TestServicePathIsTheTargetsOwnDependencyChain: the strip follows the probe
// DAG this run was built with, from the interface up to the rung the target's
// protocol ends on, and never sweeps in the branches that hang off the side of
// it.
func TestServicePathIsTheTargetsOwnDependencyChain(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec string
		want []diagnostic.ProbeID
	}{
		{"https", "example.com:443", []diagnostic.ProbeID{
			diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeTLS, diagnostic.ProbeHTTPS}},
		{"http", "http://example.com", []diagnostic.ProbeID{
			diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeHTTP}},
		{"ssh", "ssh://example.com", []diagnostic.ProbeID{
			diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeSSH}},
		{"smtp", "smtp://example.com", []diagnostic.ProbeID{
			diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeSMTP}},
		{"no protocol rung", "example.com:9999", []diagnostic.ProbeID{
			diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP}},
		{"ip literal keeps the row DNS still has", "192.0.2.1:443", []diagnostic.ProbeID{
			diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeTLS, diagnostic.ProbeHTTPS}},
		{"no target has no target path", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := servicePath(planFor(t, tc.spec, diagnostic.ProbeSelection{}))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("path = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestServicePathLeavesTheSiblingBranchesOut is the same rule stated as the
// thing that would break it: the DAG is not a line, and the branches beside
// the target chain are not rungs of it.
func TestServicePathLeavesTheSiblingBranchesOut(t *testing.T) {
	probes := planFor(t, "example.com:443", diagnostic.ProbeSelection{})
	path := servicePath(probes)
	if len(path) < 4 {
		t.Fatalf("path = %v, too short to be missing anything", path)
	}
	for _, id := range []diagnostic.ProbeID{
		diagnostic.ProbePMTU, diagnostic.ProbeInternet, diagnostic.ProbeQUIC, diagnostic.ProbeProxy,
		diagnostic.ProbeDNSPublic, diagnostic.ProbeDNSEncrypted, diagnostic.ProbeSSID, diagnostic.ProbeHTTP,
	} {
		if !inPlan(probes, id) {
			t.Fatalf("%s is not in the plan, so leaving it out of the path proves nothing", id)
		}
		if slices.Contains(path, id) {
			t.Errorf("%s is a branch beside the target path, not a rung of it: %v", id, path)
		}
	}
}

func inPlan(probes []diagnostic.Probe, id diagnostic.ProbeID) bool {
	return slices.ContainsFunc(probes, func(p diagnostic.Probe) bool { return p.ID == id })
}

// TestServicePathFollowsTheSelectedPlan: --check and --skip change which
// probes exist, so they change the path, and a rung this run does not have is
// never drawn.
func TestServicePathFollowsTheSelectedPlan(t *testing.T) {
	ids := func(v ...diagnostic.ProbeID) map[diagnostic.ProbeID]struct{} {
		out := map[diagnostic.ProbeID]struct{}{}
		for _, id := range v {
			out[id] = struct{}{}
		}
		return out
	}
	for _, tc := range []struct {
		name string
		sel  diagnostic.ProbeSelection
		want []diagnostic.ProbeID
	}{
		{"skip the top rung", diagnostic.ProbeSelection{Skip: ids(diagnostic.ProbeHTTPS)}, []diagnostic.ProbeID{
			diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeTLS}},
		{"skip a rung under it", diagnostic.ProbeSelection{Skip: ids(diagnostic.ProbeTLS)}, []diagnostic.ProbeID{
			diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP}},
		{"check one rung pulls its closure", diagnostic.ProbeSelection{Check: ids(diagnostic.ProbeHTTPS)}, []diagnostic.ProbeID{
			diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeTLS, diagnostic.ProbeHTTPS}},
		{"a plan with no target rung has no path", diagnostic.ProbeSelection{Check: ids(diagnostic.ProbeDNS)}, nil},
		{"skipping DNS takes the path with it", diagnostic.ProbeSelection{Skip: ids(diagnostic.ProbeDNS)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probes := planFor(t, "example.com:443", tc.sel)
			got := servicePath(probes)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("path = %v, want %v", got, tc.want)
			}
			for _, id := range got {
				if !inPlan(probes, id) {
					t.Errorf("path names %s, which this run does not check: %v", id, got)
				}
			}
		})
	}
}

// TestPathStripDrawsTheRun is the whole visualization in one table: the rungs,
// their status glyphs, and the root marker exactly where the diagnosis put its
// focus.
func TestPathStripDrawsTheRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		spec   string
		status map[diagnostic.ProbeID]diagnostic.Status
		want   string
		focus  diagnostic.ProbeID
	}{
		{
			name: "a path that worked end to end is left to the verdict",
			spec: "example.com:443",
			want: "",
		},
		{
			name:   "a degraded rung is drawn, and blamed on nobody",
			spec:   "example.com:443",
			status: map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeTLS: diagnostic.StatusWarn},
			want:   "Target path  ✓ Interface → ✓ DNS → ✓ TCP → ! TLS → ✓ HTTPS",
		},
		{
			name:   "dns failure skips everything above it",
			spec:   "example.com:443",
			status: map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeDNS: diagnostic.StatusFail},
			want:   "Target path  ✓ Interface → ✗ DNS [root] → ⊘ TCP → ⊘ TLS → ⊘ HTTPS",
			focus:  diagnostic.ProbeDNS,
		},
		{
			name:   "a refused connect is blamed on the connect",
			spec:   "example.com:443",
			status: map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeTargetTCP: diagnostic.StatusFail},
			want:   "Target path  ✓ Interface → ✓ DNS → ✗ TCP [root] → ⊘ TLS → ⊘ HTTPS",
			focus:  diagnostic.ProbeTargetTCP,
		},
		{
			name:   "a handshake failure is blamed on the handshake",
			spec:   "example.com:443",
			status: map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeTLS: diagnostic.StatusFail},
			want:   "Target path  ✓ Interface → ✓ DNS → ✓ TCP → ✗ TLS [root] → ⊘ HTTPS",
			focus:  diagnostic.ProbeTLS,
		},
		{
			name:   "http target",
			spec:   "http://example.com",
			status: map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeHTTP: diagnostic.StatusFail},
			want:   "Target path  ✓ Interface → ✓ DNS → ✓ TCP → ✗ HTTP [root]",
			focus:  diagnostic.ProbeHTTP,
		},
		{
			name:   "ssh target",
			spec:   "ssh://example.com",
			status: map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeSSH: diagnostic.StatusFail},
			want:   "Target path  ✓ Interface → ✓ DNS → ✓ TCP → ✗ SSH [root]",
			focus:  diagnostic.ProbeSSH,
		},
		{
			name:   "smtp target",
			spec:   "smtp://example.com",
			status: map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeSMTP: diagnostic.StatusFail},
			want:   "Target path  ✓ Interface → ✓ DNS → ✓ TCP → ✗ SMTP [root]",
			focus:  diagnostic.ProbeSMTP,
		},
		{
			name: "an ip literal needed no name",
			spec: "192.0.2.1:443",
			status: map[diagnostic.ProbeID]diagnostic.Status{
				diagnostic.ProbeDNS: diagnostic.StatusNA,
				diagnostic.ProbeTLS: diagnostic.StatusFail,
			},
			want:  "Target path  ✓ Interface → – DNS → ✓ TCP → ✗ TLS [root] → ⊘ HTTPS",
			focus: diagnostic.ProbeTLS,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := pathRun(t, tc.spec, tc.status)
			if got := m.diagnosis().Focus(); got != tc.focus {
				t.Fatalf("the diagnosis focuses %q, want %q: the case is not the one it describes", got, tc.focus)
			}
			if got := pathLine(m); got != tc.want {
				t.Errorf("strip =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

// TestPathStripMarksTheDiagnosisFocusNotTheFirstFailure: the marker is a
// causal claim, so it follows the row the diagnosis is about. Here the path
// itself carries a failed rung and the diagnosis blames a row on another
// branch, which is exactly the case a first-failed-rung rule gets wrong.
func TestPathStripMarksTheDiagnosisFocusNotTheFirstFailure(t *testing.T) {
	m := pathRun(t, "example.com:443", map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeInternet:  diagnostic.StatusFail,
		diagnostic.ProbeProxy:     diagnostic.StatusFail,
		diagnostic.ProbeTargetTCP: diagnostic.StatusFail,
	})
	d := m.diagnosis()
	if d.Focus() != diagnostic.ProbeInternet {
		t.Fatalf("the diagnosis focuses %q, want the egress row off the target path", d.Focus())
	}
	if m.results[diagnostic.ProbeTargetTCP].Status != diagnostic.StatusFail {
		t.Fatal("the target connect must be a failed rung on the path for this to test anything")
	}
	line := pathLine(m)
	if !strings.Contains(line, "✗ TCP") {
		t.Fatalf("the failed rung must still be drawn as failed:\n%s", line)
	}
	if strings.Contains(line, pathRootLabel) {
		t.Errorf("the diagnosis blames a row off the path, so no rung is the root:\n%s", line)
	}
}

// TestPathStripNeverMarksAFallbackCursorRow is the Focus/Blamed distinction.
// Blamed falls back to the first failed row so a caller has somewhere to put
// the cursor; that is a presentation answer, and the strip must not repeat it
// as a statement about cause.
func TestPathStripNeverMarksAFallbackCursorRow(t *testing.T) {
	// Mid-run, which is where a diagnosis names nothing while a row has
	// already failed: a finished run with a failure names the row that
	// carries it, so it is no longer the case this is about.
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.width = 100
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeQUIC] = diagnostic.ProbeResult{ID: diagnostic.ProbeQUIC, Status: diagnostic.StatusFail}
	d := m.diagnosis()
	if d.Verdict != diagnostic.VerdictIncomplete {
		t.Fatalf("verdict = %q, want an unfinished run", d.Verdict)
	}
	if d.Focus() != "" {
		t.Fatalf("the diagnosis focuses %q, so this is no longer the fallback case", d.Focus())
	}
	if d.Blamed == "" {
		t.Fatal("Blamed did not fall back, so the case cannot tell it apart from Focus")
	}
	if line := pathLine(m); strings.Contains(line, pathRootLabel) {
		t.Errorf("the diagnosis names no cause, so nothing may be marked as one:\n%s", line)
	}
}

// TestPathRootReadsTheDiagnosisFocusAndNeverBlamed pins the one claim the
// strip makes, on the rule itself rather than through a run: Blamed falls back
// to the first failed row so a caller has somewhere to put a cursor, and a
// cursor position must never be rendered as a cause.
func TestPathRootReadsTheDiagnosisFocusAndNeverBlamed(t *testing.T) {
	path := []diagnostic.ProbeID{diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP}
	res := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface:     {ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass},
		diagnostic.ProbeDNS:       {ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail},
		diagnostic.ProbeTargetTCP: {ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusSkip},
		diagnostic.ProbePMTU:      {ID: diagnostic.ProbePMTU, Status: diagnostic.StatusFail},
	}
	focused := func(id diagnostic.ProbeID) []diagnostic.DiagnosisFinding {
		return []diagnostic.DiagnosisFinding{{ID: diagnostic.DiagnosisDNSFailure, Verdict: diagnostic.VerdictDNS, Focus: id}}
	}
	for _, tc := range []struct {
		name string
		d    diagnostic.Diagnosis
		want diagnostic.ProbeID
	}{
		{
			name: "a fallback cursor row is not a cause",
			d:    diagnostic.Diagnosis{Verdict: diagnostic.VerdictDegraded, Blamed: diagnostic.ProbeDNS},
			want: "",
		},
		{
			name: "the row the diagnosis is about is",
			d:    diagnostic.Diagnosis{Verdict: diagnostic.VerdictDNS, Blamed: diagnostic.ProbeDNS, Findings: focused(diagnostic.ProbeDNS)},
			want: diagnostic.ProbeDNS,
		},
		{
			name: "a focus on another branch marks nothing on this path",
			d:    diagnostic.Diagnosis{Verdict: diagnostic.VerdictNetwork, Blamed: diagnostic.ProbePMTU, Findings: focused(diagnostic.ProbePMTU)},
			want: "",
		},
		{
			name: "a focused rung that did not fail is not a root cause",
			d:    diagnostic.Diagnosis{Verdict: diagnostic.VerdictNetwork, Blamed: diagnostic.ProbeIface, Findings: focused(diagnostic.ProbeIface)},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathRoot(tc.d, res, path); got != tc.want {
				t.Errorf("pathRoot = %q, want %q (Focus %q, Blamed %q)", got, tc.want, tc.d.Focus(), tc.d.Blamed)
			}
		})
	}
}

// TestPathStripStaysOutOfAHealthyRun: the strip explains a break in the path.
// A path that worked has none, the verdict already said so in one line, and a
// second line agreeing with it is the decoration this view does not do.
func TestPathStripStaysOutOfAHealthyRun(t *testing.T) {
	m := pathRun(t, "example.com:443", nil)
	if got, want := m.diagnosis().Verdict, diagnostic.VerdictOK; got != want {
		t.Fatalf("verdict = %q, want %q", got, want)
	}
	if line := pathLine(m); line != "" {
		t.Errorf("a healthy run drew a strip that only agrees with the verdict:\n%s", line)
	}
	if path := servicePath(m.probes); len(path) != 5 {
		t.Errorf("the path itself is still %v, so this is about drawing it, not deriving it", path)
	}
}

// TestPathStripWaitsForTheAnswer: it is part of the conclusion, so it appears
// with the conclusion rather than as a row of dots while the probes run.
func TestPathStripWaitsForTheAnswer(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.width = 100
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail}
	if line := pathLine(m); line != "" {
		t.Errorf("the strip drew itself before the run finished:\n%s", line)
	}
}

// TestPathStripHasNothingToSayWithoutATarget: a generic run has no target
// path, and the strip is left out rather than inventing one.
func TestPathStripHasNothingToSayWithoutATarget(t *testing.T) {
	m := newModel(nil, false)
	m.width = 100
	for _, p := range m.probes {
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
	}
	if line := pathLine(m); line != "" {
		t.Errorf("a targetless run drew a target path:\n%s", line)
	}
}

// TestPathStripDegradesOnANarrowTerminal: it wraps between rungs and never
// inside one, and a terminal too narrow for that gets no strip at all rather
// than a clipped or shredded one.
func TestPathStripDegradesOnANarrowTerminal(t *testing.T) {
	m := pathRun(t, "example.com:443", map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeDNS: diagnostic.StatusFail,
	})
	rungs := []string{"Interface", "DNS", "TCP", "TLS", "HTTPS"}
	for _, width := range []int{100, 80, 60, 46, 30, 20, 10} {
		m.width = width
		line := pathLine(m)
		if line == "" {
			continue // too narrow to draw one, which is an answer
		}
		for _, row := range strings.Split(line, "\n") {
			if len(row) > 0 && ansi.StringWidth(row) > width {
				t.Errorf("width %d: row %q is %d columns wide", width, row, ansi.StringWidth(row))
			}
		}
		if rows := strings.Count(line, "\n") + 1; rows > pathMaxRows {
			t.Errorf("width %d: the strip took %d rows:\n%s", width, rows, line)
		}
		for _, rung := range rungs {
			if !strings.Contains(line, rung) {
				t.Errorf("width %d: the %s rung was lost:\n%s", width, rung, line)
			}
		}
	}
	m.width = 10
	if line := pathLine(m); line != "" {
		t.Errorf("10 columns cannot hold a path, so none should be drawn:\n%s", line)
	}
}

// TestPathStripSitsUnderTheAnswer: the strip is context for the verdict, so it
// goes below the answer block and above the results block, and the verdict
// still owns the top of the screen.
func TestPathStripSitsUnderTheAnswer(t *testing.T) {
	m := pathRun(t, "example.com:443", map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeDNS: diagnostic.StatusFail,
	})
	m, v := renderAt(t, m)
	lines := viewLines(v)
	strip := lineWith(lines, "Target path")
	if strip < 0 {
		t.Fatalf("the strip never reached the screen:\n%s", v)
	}
	if !strings.HasPrefix(lines[0], probeGlyph(diagnostic.StatusFail)+" ") {
		t.Errorf("the verdict must still be the first row on screen:\n%s", v)
	}
	if panel := firstBodyLine(lines); strip > panel {
		t.Errorf("the strip is at row %d, below the results block at %d:\n%s", strip, panel, v)
	}
	for _, banner := range strings.Split(m.banner(), "\n") {
		if at := lineWith(lines, answerLead(banner)); at > strip {
			t.Errorf("the answer line %q is at row %d, below the strip at %d:\n%s", answerLead(banner), at, strip, v)
		}
	}
}

// TestPathStripYieldsBeforeTheConclusionDoes: on a terminal too short for
// everything, the strip goes and the verdict, its guidance, the context strip
// and the help bar stay.
func TestPathStripYieldsBeforeTheConclusionDoes(t *testing.T) {
	m := blackHoleModel(t)
	for _, h := range []int{40, 30, 24, 20, 16, 14, 12, 10} {
		u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: h})
		nm := asModel(t, u)
		v := nm.View()
		if rows := lipgloss.Height(v); rows > h {
			t.Errorf("100x%d: view is %d display rows tall", h, rows)
		}
		checkPersistent(t, nm, fmt.Sprintf("100x%d", h), v)
		if n := unclosedPanels(v); n != 0 {
			t.Errorf("100x%d: %d panel border(s) left unclosed:\n%s", h, n, v)
		}
	}
	// The shortest terminal must actually have shed it, or nothing above says
	// the strip yields rather than pushing the conclusion off the top.
	u, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 10})
	if v := asModel(t, u).View(); strings.Contains(v, "Target path") {
		t.Errorf("100x10 kept the strip instead of the conclusion:\n%s", v)
	}
}

func TestPMTUSelectionSurvivesTargetChanges(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		selection := diagnostic.ProbeSelection{}
		if explicit {
			selection.Check = map[diagnostic.ProbeID]struct{}{diagnostic.ProbePMTU: {}}
		}
		m := asModel(t, NewWithSelection(mustTarget(t, "host:9999"), nil, false, true, "", "test", "", false, selection))
		check := func(want bool) {
			t.Helper()
			if got := slices.ContainsFunc(m.probes, func(p diagnostic.Probe) bool { return p.ID == diagnostic.ProbePMTU }); got != want {
				t.Fatalf("target %v, explicit %t: PMTU = %t, want %t", m.target, explicit, got, want)
			}
		}
		check(explicit)
		for _, raw := range []string{"https://host:9999", "host:9999", ""} {
			var target *diagnostic.Target
			if raw != "" {
				target = mustTarget(t, raw)
			}
			m.applyTarget(target)
			check(target != nil && (target.Proto != diagnostic.ProtoNone || explicit))
		}
	}
}
