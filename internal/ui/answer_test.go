// The completed run's information hierarchy: the answer, then what to do
// about it, then the evidence for it, and only then the probe chain that
// produced it. These tests read the rendered view rather than the helpers that
// build it, because the claim under test is about what reaches the screen and
// in what order.

package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// answerScenario is one finished run: the probe results that differ from an
// all-pass baseline, and what the answer block must be saying about them.
type answerScenario struct {
	name   string
	target string // "" for generic mode
	over   map[diagnostic.ProbeID]diagnostic.ProbeResult
	// blamed is the row the diagnosis is about, "" when it is about no single
	// row (a healthy run). The answer block takes all three of its lines from
	// this row, so it is also what the cursor lands on.
	blamed diagnostic.ProbeID
	// verdict is the machine-readable classification, asserted so a scenario
	// cannot quietly stop being the case it was written for.
	verdict string
}

// answerScenarios covers the result shapes a completed run has to present:
// healthy, a root failure with the chain skipped behind it, a root failure with
// the chain failing behind it, degraded with nothing failed, several
// independent failures, a resolver failure over a working path, and a service
// failure with the whole path under it healthy.
func answerScenarios(t *testing.T) []answerScenario {
	t.Helper()
	fail := func(detail, fix string) diagnostic.ProbeResult {
		return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Detail: detail, Fix: fix}
	}
	skip := func() diagnostic.ProbeResult {
		return diagnostic.ProbeResult{Status: diagnostic.StatusSkip, Detail: "not run: a check it depends on failed"}
	}
	return []answerScenario{
		{
			name:    "healthy target",
			target:  "example.com:443",
			verdict: diagnostic.VerdictOK,
		},
		{
			name:   "root failure with the chain skipped behind it",
			target: "printer.local:443",
			over: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeDNS: fail("no A or AAAA record for printer.local",
					"check the device name, or use the address it was given"),
				diagnostic.ProbeDNSPublic: {Status: diagnostic.StatusNA, Detail: "nothing to compare"},
				diagnostic.ProbeTargetTCP: skip(),
				diagnostic.ProbePMTU:      skip(),
				diagnostic.ProbeTLS:       skip(),
				diagnostic.ProbeHTTP:      skip(),
				diagnostic.ProbeHTTPS:     skip(),
			},
			blamed:  diagnostic.ProbeDNS,
			verdict: diagnostic.VerdictDNS,
		},
		{
			// An offline machine with a target: eleven rows fail at once and
			// the diagnosis is about one of them. Which one is the diagnosis's
			// call and not the row order's: the egress row fails first, and the
			// sentence on screen is the resolver one.
			name:   "root failure with the chain failing behind it",
			target: "example.com:443",
			over: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeInternet: fail("no direct TCP egress to 1.1.1.1 (port 443)",
					"no default route: check DHCP, the VPN, or a static route"),
				diagnostic.ProbeQUIC:         fail("no UDP/443 handshake", ""),
				diagnostic.ProbeProxy:        fail("cannot reach proxy 10.0.0.9:3128", "check the proxy host"),
				diagnostic.ProbeDNS:          fail("resolver did not answer", "check the configured resolver"),
				diagnostic.ProbeDNSPublic:    fail("public resolver unreachable", ""),
				diagnostic.ProbeDNSEncrypted: fail("no verified exchange", ""),
				diagnostic.ProbeTargetTCP:    fail("port 443 unreachable on all addresses", "check the firewall"),
				diagnostic.ProbePMTU:         skip(),
				diagnostic.ProbeTLS:          fail("handshake timed out", ""),
				diagnostic.ProbeHTTP:         fail("no HTTP response", ""),
				diagnostic.ProbeHTTPS:        fail("no HTTPS response", ""),
			},
			blamed:  diagnostic.ProbeDNS,
			verdict: diagnostic.VerdictDNS,
		},
		{
			name:   "degraded with nothing failed",
			target: "example.com:443",
			over: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeInternet: {
					Status: diagnostic.StatusWarn,
					Detail: "IPv6 egress unavailable, IPv4 egress in 41ms",
					Fix:    "IPv6 is advertised but not carrying traffic; check the router advertisement",
				},
			},
			blamed:  diagnostic.ProbeInternet,
			verdict: diagnostic.VerdictDegraded,
		},
		{
			name:   "several independent failures",
			target: "example.com:443",
			over: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeProxy: fail("cannot reach proxy 10.0.0.9:3128", "check the proxy host"),
				diagnostic.ProbeQUIC:  fail("no UDP/443 handshake", "UDP/443 is blocked; applications fall back to TCP"),
			},
			// The target and the direct path both work, so the QUIC row is
			// what the sentence is about; the proxy row keeps its own red and
			// its own remedy in the panel beside it.
			blamed:  diagnostic.ProbeQUIC,
			verdict: diagnostic.VerdictDegraded,
		},
		{
			name:   "resolver down while the internet works",
			target: "example.com:443",
			over: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeQUIC:      fail("no UDP/443 handshake", "UDP/443 is blocked"),
				diagnostic.ProbeDNS:       fail("resolver did not answer", "check the configured resolver, VPN, or DNS filter"),
				diagnostic.ProbeDNSPublic: {Status: diagnostic.StatusNA, Detail: "nothing to compare"},
				diagnostic.ProbeTargetTCP: skip(),
				diagnostic.ProbePMTU:      skip(),
				diagnostic.ProbeTLS:       skip(),
				diagnostic.ProbeHTTP:      skip(),
				diagnostic.ProbeHTTPS:     skip(),
			},
			// QUIC fails first in probe order and the sentence is about the
			// resolver, which is exactly the pairing the answer block must not
			// take its guidance from.
			blamed:  diagnostic.ProbeDNS,
			verdict: diagnostic.VerdictDNS,
		},
		{
			name:   "service failure over a healthy path",
			target: "example.com:443",
			over: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeTargetTCP: {
					Status: diagnostic.StatusFail,
					Cause:  diagnostic.ConnectionCauseRefused,
					Detail: "connection to port 443 was refused on all 2 attempted address(es)",
					Fix:    "port 443 refused: the service may not be listening",
				},
				diagnostic.ProbePMTU:  skip(),
				diagnostic.ProbeTLS:   skip(),
				diagnostic.ProbeHTTP:  skip(),
				diagnostic.ProbeHTTPS: skip(),
			},
			blamed:  diagnostic.ProbeTargetTCP,
			verdict: diagnostic.VerdictService,
		},
	}
}

// build renders the scenario as a finished run, with the tool table pinned to
// one GOOS so the "Next:" chip reads the same wherever the suite runs.
func (s answerScenario) build(t *testing.T) model {
	t.Helper()
	oldLookPath := toolLookPath
	toolLookPath = func(bin string) (string, error) { return bin, nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	var target *diagnostic.Target
	if s.target != "" {
		target = mustTarget(t, s.target)
	}
	m := newModel(target, false)
	m.tools = toolsFor(target, "linux", toolBind{})
	for _, p := range m.probes {
		r, ok := s.over[p.ID]
		if !ok {
			r = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Detail: "ok"}
		}
		r.ID = p.ID
		m.started[p.ID], m.results[p.ID] = true, r
	}
	diagnostic.Finalize(m.results)
	// The real completion path parks the cursor, so the scenario goes through
	// it rather than setting m.selected by hand.
	last := m.probes[len(m.probes)-1]
	u, _ := m.Update(probeDoneMsg{id: last.ID, gen: m.generation, res: m.results[last.ID]})
	return asModel(t, u)
}

// viewLines is the rendered view with its styling stripped and its trailing
// padding trimmed, which is what a reader actually sees.
func viewLines(v string) []string {
	lines := strings.Split(ansi.Strip(v), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " ")
	}
	return lines
}

// lineWith is the index of the first rendered line carrying want, or -1.
func lineWith(lines []string, want string) int {
	for i, line := range lines {
		if strings.Contains(line, want) {
			return i
		}
	}
	return -1
}

// firstBodyLine is where the results block starts: the Checks heading, which
// is the first row of probe machinery on screen.
func firstBodyLine(lines []string) int { return lineWith(lines, "Checks") }

// answerLead is a fragment of a banner line long enough to identify it and
// short enough to survive the wrap the full-width block goes through.
func answerLead(line string) string {
	line = strings.TrimSpace(ansi.Strip(line))
	if len(line) > 24 {
		return line[:24]
	}
	return line
}

// TestAnswerLeadsTheCompletedView is the hierarchy itself: every line of the
// answer block reaches the screen, in order, above the first probe panel. A
// reader who stops at the first bordered box has already been told what
// happened, what to do about it, and what the diagnosis is resting on.
func TestAnswerLeadsTheCompletedView(t *testing.T) {
	for _, s := range answerScenarios(t) {
		t.Run(s.name, func(t *testing.T) {
			m := s.build(t)
			_, v := renderAt(t, m)
			lines := viewLines(v)
			panel := firstBodyLine(lines)
			if panel < 0 {
				t.Fatalf("no results block on screen:\n%s", v)
			}
			prev := -1
			for _, banner := range strings.Split(m.banner(), "\n") {
				lead := answerLead(banner)
				at := lineWith(lines, lead)
				switch {
				case at < 0:
					t.Fatalf("the answer line %q never reaches the screen:\n%s", lead, v)
				case at >= panel:
					t.Errorf("the answer line %q is at row %d, below the results block at %d:\n%s", lead, at, panel, v)
				case at <= prev:
					t.Errorf("the answer line %q is at row %d, out of order after row %d:\n%s", lead, at, prev, v)
				}
				prev = at
			}
			if got := lines[0]; !strings.HasPrefix(got, probeGlyph(verdictStatus(s.verdict))+" ") {
				t.Errorf("the first row on screen is %q, want the verdict:\n%s", got, v)
			}
		})
	}
}

// TestAnswerBlockCarriesTheDiagnosisGuidance: whatever the diagnosis has to
// offer about the row it blames reaches the answer block. A missing "Fix:" is
// how the old first-failure rule used to fail, silently, on exactly the runs
// where the reader needed it most.
func TestAnswerBlockCarriesTheDiagnosisGuidance(t *testing.T) {
	for _, s := range answerScenarios(t) {
		t.Run(s.name, func(t *testing.T) {
			m := s.build(t)
			summary, verdict := m.diagnose(m.probeOrder())
			if verdict != s.verdict {
				t.Fatalf("verdict = %q, want %q (%q)", verdict, s.verdict, summary)
			}
			banner := ansi.Strip(m.banner())
			if !strings.Contains(banner, summary) {
				t.Errorf("the answer block does not carry the diagnosis:\n%s", banner)
			}
			i := m.answerRow()
			if s.blamed == "" {
				if i >= 0 {
					t.Fatalf("a healthy run blames row %d (%s)", i, m.probes[i].ID)
				}
				if strings.Contains(banner, "Fix:") || strings.Contains(banner, "Evidence:") {
					t.Errorf("a healthy run offers guidance it has no failure for:\n%s", banner)
				}
				return
			}
			if i < 0 || m.probes[i].ID != s.blamed {
				t.Fatalf("the answer block quotes row %d, want %s", i, s.blamed)
			}
			// The cursor follows the same row, so the reader's next keypress
			// acts on what they were just told about.
			if m.selected != i {
				t.Errorf("cursor is on row %d, want the blamed row %d", m.selected, i)
			}
			// The remedy reaches the reader exactly once. Where the diagnosis
			// reached an action of its own that is the "Do:" line, and the
			// row's own wording waits in that row's Details; where it did not,
			// the row's hint is the only advice there is and stays up here.
			r := m.results[s.blamed]
			rem, advised := m.remediation()
			switch {
			case advised:
				if strings.Contains(banner, "Fix: ") {
					t.Errorf("the answer block states the remedy twice:\n%s", banner)
				}
				if !strings.Contains(ansi.Strip(strings.Join(m.answerRemediation(), "\n")), "Do: "+rem.Action) {
					t.Errorf("the answer block lost the diagnosis's action %q", rem.Action)
				}
				if r.Fix != "" && !strings.Contains(answerRowDetails(m), "Fix: "+r.Fix) {
					t.Errorf("the blamed row's details lost the remedy %q", r.Fix)
				}
			case r.Fix != "" && !strings.Contains(banner, "Fix: "+r.Fix):
				t.Errorf("the answer block lost the remedy %q:\n%s", r.Fix, banner)
			}
			if r.Detail != "" && !strings.Contains(banner, "Evidence: ") {
				t.Errorf("the answer block lost the evidence %q:\n%s", r.Detail, banner)
			}
			if next := m.nextStep(s.blamed); next != "" && !strings.Contains(banner, "Next: press") {
				t.Errorf("the answer block lost the drill-down hint:\n%s", banner)
			}
		})
	}
}

// TestBlamedRowGuidanceIsStatedOnce: the screen states the blamed row's remedy
// in one place, never two. It used to appear in the banner and again in the
// Details panel four rows apart, which reads as a second answer competing with
// the first; it must not come back the other way round either, now that the
// answer block prints the diagnosis's own action and hands the row's wording
// down to that row's Details. Every other row keeps its own remedy, because
// nothing else on screen is saying it.
func TestBlamedRowGuidanceIsStatedOnce(t *testing.T) {
	for _, s := range answerScenarios(t) {
		if s.blamed == "" {
			continue
		}
		t.Run(s.name, func(t *testing.T) {
			m := s.build(t)
			_, v := renderAt(t, m)
			fix := m.results[s.blamed].Fix
			if fix == "" {
				t.Skip("this row carries no remedy to duplicate")
			}
			// Both places wrap their text to their own column, so each is
			// compared with its whitespace collapsed rather than as it sits on
			// screen. The two are counted separately: collapsing the whole
			// screen would run the Checks column into the Details one.
			answer := strings.Count(reflowed(ansi.Strip(m.answerBlock())), reflowed(fix))
			details := strings.Count(reflowed(strings.Join(detailsRows(v), " ")), reflowed(fix))
			if answer+details != 1 {
				t.Errorf("the remedy for %s appears %d times in the answer and %d times in Details:\n%s",
					s.blamed, answer, details, v)
			}
		})
	}
}

// reflowed collapses the runs of whitespace a panel's own wrapping introduces,
// so a string can be looked for in rendered output without knowing which column
// it was broken in.
func reflowed(s string) string { return strings.Join(strings.Fields(s), " ") }

// TestOtherRowsKeepTheirOwnGuidance: the de-duplication is scoped to the one
// row the answer block quotes. Walking the cursor onto an independent failure
// must still show that row's own remedy, since nothing else on screen does.
func TestOtherRowsKeepTheirOwnGuidance(t *testing.T) {
	var s answerScenario
	for _, c := range answerScenarios(t) {
		if c.name == "several independent failures" {
			s = c
		}
	}
	m := s.build(t)
	proxy := probeIndex(t, m, diagnostic.ProbeProxy)
	if m.selected == proxy {
		t.Fatalf("the proxy row is already the blamed one, so the case is not under test")
	}
	m.selected, m.selMoved = proxy, true
	_, v := renderAt(t, m)
	want := m.results[diagnostic.ProbeProxy].Fix
	if !containsRow(detailsRows(v), "Fix: "+want) {
		t.Errorf("an independently failing row lost its own remedy:\n%s", v)
	}
}

// TestAnswerBlockStaysAFixedHeight: the evidence quote is clipped to one row,
// so however long a probe's detail runs the answer block is a fixed size and
// cannot crowd out the machinery below it on a short terminal.
func TestAnswerBlockStaysAFixedHeight(t *testing.T) {
	long := strings.Repeat("stalled after 64KiB without draining the send buffer; ", 8)
	m := answerScenario{
		target: "example.com:443",
		over: map[diagnostic.ProbeID]diagnostic.ProbeResult{
			diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusFail, Detail: long, Fix: "lower the interface MTU"},
			diagnostic.ProbePMTU:      {Status: diagnostic.StatusSkip, Detail: "not run"},
			diagnostic.ProbeTLS:       {Status: diagnostic.StatusSkip, Detail: "not run"},
			diagnostic.ProbeHTTP:      {Status: diagnostic.StatusSkip, Detail: "not run"},
			diagnostic.ProbeHTTPS:     {Status: diagnostic.StatusSkip, Detail: "not run"},
		},
	}.build(t)
	m.width = 100
	// The verdict, the drill-down hint and the one-row evidence quote. The
	// blamed row's own hint is not among them: this run reaches a diagnosis
	// with an action of its own, which is printed instead.
	if n := len(strings.Split(m.banner(), "\n")); n != 3 {
		t.Errorf("the answer block is %d lines, want the verdict plus Next and Evidence:\n%s", n, m.banner())
	}
	line, whole := m.evidenceLine(long)
	if whole {
		t.Fatalf("this detail fits in one row, so the clip is not under test")
	}
	if ansi.StringWidth(line) > m.width {
		t.Errorf("the evidence quote is %d columns wide on a %d column terminal", ansi.StringWidth(line), m.width)
	}
	// Nothing is lost to the clip: the panel still holds the whole finding,
	// reflowed across as many of its own rows as that takes.
	_, v := renderAt(t, m)
	if reflowed := strings.Join(strings.Fields(strings.Join(detailsRows(v), " ")), " "); !strings.Contains(reflowed, strings.TrimSpace(long)) {
		t.Errorf("the clipped detail is nowhere in full:\n%s", v)
	}
}

// TestFindingsOutrankRoutineSuccesses: every row the reader has something to
// act on or to understand keeps its place, and the passing rows that would
// bury them are one summary line. Skipped rows stay, because they are how a
// root failure shows what it stopped.
func TestFindingsOutrankRoutineSuccesses(t *testing.T) {
	for _, s := range answerScenarios(t) {
		t.Run(s.name, func(t *testing.T) {
			m := s.build(t)
			_, v := renderAt(t, m)
			passing := 0
			for _, probe := range rowProbes(m) {
				status := m.results[probe.ID].Status
				shown := hasRow(v, probe.Name)
				switch status {
				case diagnostic.StatusPass, diagnostic.StatusNA:
					if shown && m.probes[m.selected].ID != probe.ID {
						passing++
					}
				default:
					if !shown {
						t.Errorf("the %s row (%s) is hidden behind the passing checks:\n%s", probe.ID, status, v)
					}
				}
			}
			if passing > 0 {
				t.Errorf("%d routine passing rows are still taking space on a finished run:\n%s", passing, v)
			}
		})
	}
}

// TestHealthyCompletionIsConcise: a clean run has no guidance to give and no
// failure to explain, so the answer is one line and the machinery collapses to
// a single summary row under it.
func TestHealthyCompletionIsConcise(t *testing.T) {
	m := answerScenarios(t)[0].build(t)
	_, v := renderAt(t, m)
	lines := viewLines(v)
	if got := len(strings.Split(m.banner(), "\n")); got != 1 {
		t.Errorf("a healthy answer is %d lines, want one:\n%s", got, m.banner())
	}
	if collapsedRow(v) == "" {
		t.Errorf("a healthy run still lists its passing checks one by one:\n%s", v)
	}
	if panel := firstBodyLine(lines); panel < 0 || panel > 3 {
		t.Errorf("the results block starts at row %d, too far under a one-line answer:\n%s", panel, v)
	}
}

// TestExpandStillOffersTheWholeChain: the collapsing is presentation, and the
// expand action takes it all back. Every probe with a row is a row again.
func TestExpandStillOffersTheWholeChain(t *testing.T) {
	for _, s := range answerScenarios(t) {
		t.Run(s.name, func(t *testing.T) {
			m, _ := renderAt(t, s.build(t))
			_, v := renderAt(t, press(t, m, "a"))
			for _, probe := range rowProbes(m) {
				if !hasRow(v, probe.Name) {
					t.Errorf("expand did not bring back the %s row:\n%s", probe.ID, v)
				}
			}
			// The answer keeps its place at the top either way.
			if lines := viewLines(v); lineWith(lines, answerLead(strings.Split(m.banner(), "\n")[0])) != 0 {
				t.Errorf("expanding moved the answer off the first row:\n%s", v)
			}
		})
	}
}

// TestNarrowAndShortTerminalsKeepTheAnswer: the diagnosis is the last thing
// the layout gives up. Whatever else is shed for want of rows or columns, the
// verdict and the remedy under it stay on screen.
func TestNarrowAndShortTerminalsKeepTheAnswer(t *testing.T) {
	sizes := []struct{ w, h int }{
		{40, 40}, {52, 24}, {60, 10}, {80, 8}, {100, 6}, {120, 40},
	}
	for _, s := range answerScenarios(t) {
		if s.blamed == "" {
			continue
		}
		for _, size := range sizes {
			t.Run(s.name, func(t *testing.T) {
				m := s.build(t)
				u, _ := m.Update(tea.WindowSizeMsg{Width: size.w, Height: size.h})
				m = asModel(t, u)
				v := m.View()
				lines := viewLines(v)
				if n := len(lines); n > size.h {
					t.Fatalf("%dx%d: the view is %d rows, so the renderer eats the top:\n%s", size.w, size.h, n, v)
				}
				summary, _ := m.diagnose(m.probeOrder())
				if lineWith(lines, answerLead(summary)) != 0 {
					t.Errorf("%dx%d: the verdict is not the first row:\n%s", size.w, size.h, v)
				}
				// Whichever of the two the answer block is carrying: the
				// diagnosis's action where it reached one, and otherwise the
				// blamed row's own hint.
				remedy := m.results[s.blamed].Fix
				if rem, ok := m.remediation(); ok {
					remedy = rem.Action
				}
				if remedy != "" && lineWith(lines, answerLead(remedy)) < 0 {
					t.Errorf("%dx%d: the remedy was shed:\n%s", size.w, size.h, v)
				}
			})
		}
	}
}

// TestRunningStateKeepsProbeProgress: there is no answer yet, so the machinery
// is the useful thing and stays prominent. Nothing must claim a verdict, a
// remedy or evidence before every probe has reported.
func TestRunningStateKeepsProbeProgress(t *testing.T) {
	s := answerScenarios(t)[1]
	m := s.build(t)
	// Take the blamed row's result away again: a run one probe short.
	delete(m.results, s.blamed)
	m.selMoved = false
	_, v := renderAt(t, m)
	plain := ansi.Strip(v)
	if !strings.Contains(plain, "Checking your connection") {
		t.Errorf("an unfinished run does not say it is still working:\n%s", v)
	}
	for _, unfinished := range []string{"Fix:", "Next: press", "Evidence:"} {
		if strings.Contains(plain, unfinished) {
			t.Errorf("an unfinished run already offers %q:\n%s", unfinished, v)
		}
	}
	if m.answerRow() >= 0 {
		t.Errorf("an unfinished run blames row %d", m.answerRow())
	}
	// Every applicable row is on screen while the run is going: nothing is
	// collapsed until there is an answer to collapse it behind.
	for _, probe := range rowProbes(m) {
		if !hasRow(v, probe.Name) {
			t.Errorf("the %s row is hidden while the run is still going:\n%s", probe.ID, v)
		}
	}
}

// TestWatchPassReplacesTheAnswer: the answer block is derived from the results
// on screen, so a pass that repairs the network takes the previous pass's
// verdict, remedy and evidence with it rather than leaving them behind.
func TestWatchPassReplacesTheAnswer(t *testing.T) {
	s := answerScenarios(t)[1] // the resolver failure
	m := s.build(t)
	m.watch = true
	for _, p := range m.probes {
		m.runHistory[p.ID] = []diagnostic.Status{m.results[p.ID].Status}
	}
	nm, v := renderAt(t, m)
	broken := m.results[s.blamed]
	if !strings.Contains(ansi.Strip(v), broken.Fix) {
		t.Fatalf("the failing pass does not show its remedy:\n%s", v)
	}
	// The next pass: everything works.
	for _, p := range nm.probes {
		nm.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Detail: "ok"}
		nm.runHistory[p.ID] = append(nm.runHistory[p.ID], diagnostic.StatusPass)
	}
	_, healthy := renderAt(t, nm)
	plain := ansi.Strip(healthy)
	for _, stale := range []string{broken.Fix, broken.Detail, "Evidence:", "Next: press"} {
		if strings.Contains(plain, stale) {
			t.Errorf("a healthy pass still carries %q from the previous one:\n%s", stale, healthy)
		}
	}
}

// TestToolJobKeepsTheAnswerOnTop: a tool running under the diagnosis is more
// output, not a new answer. The verdict stays the first row and the job pane
// takes only the rows left over.
func TestToolJobKeepsTheAnswerOnTop(t *testing.T) {
	s := answerScenarios(t)[1]
	m := s.build(t)
	m.cur = jobState{name: "DNS lookup", display: "dig printer.local", status: JobRunning}
	for i := range 40 {
		m.appendJobLine(";; answer section line " + string(rune('a'+i%26)))
	}
	_, v := renderAt(t, m)
	lines := viewLines(v)
	summary, _ := m.diagnose(m.probeOrder())
	if lineWith(lines, answerLead(summary)) != 0 {
		t.Errorf("the job pane displaced the answer:\n%s", v)
	}
	if lineWith(lines, "dig printer.local") <= firstBodyLine(lines) {
		t.Errorf("the job pane is above the results block:\n%s", v)
	}
	if len(lines) > 40 {
		t.Errorf("the view is %d rows on a 40 row terminal:\n%s", len(lines), v)
	}
}

// TestToolboxModeHasNoAnswerYet: --toolbox holds the chain back until r, so
// there is nothing to be answer-first about and the block must not pretend
// otherwise.
func TestToolboxModeHasNoAnswerYet(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), true)
	_, v := renderAt(t, m)
	plain := ansi.Strip(v)
	if !strings.Contains(plain, "Press r to check your connection") {
		t.Errorf("--toolbox does not offer to run the checks:\n%s", v)
	}
	for _, claimed := range []string{"Fix:", "Evidence:", "Next: press"} {
		if strings.Contains(plain, claimed) {
			t.Errorf("--toolbox claims %q before anything has run:\n%s", claimed, v)
		}
	}
	if m.answerRow() >= 0 {
		t.Errorf("--toolbox blames row %d before the checks have run", m.answerRow())
	}
}
