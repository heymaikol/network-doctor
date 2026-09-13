package ui

import (
	"net"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func resolverExplanationModel(t *testing.T) model {
	t.Helper()
	skip := diagnostic.ProbeResult{Status: diagnostic.StatusSkip, Detail: "not run: a check it depends on failed"}
	return answerScenario{
		target: "example.com:443",
		over: map[diagnostic.ProbeID]diagnostic.ProbeResult{
			diagnostic.ProbeDNS: {
				Status: diagnostic.StatusFail, Detail: "the configured resolver returned SERVFAIL",
				Fix: "check the configured resolver",
			},
			diagnostic.ProbeDNSPublic: {
				Status: diagnostic.StatusPass, Detail: "independent DNS resolved example.com",
				Addrs: []net.IP{net.ParseIP("192.0.2.1")},
			},
			diagnostic.ProbeTargetTCP: skip,
			diagnostic.ProbePMTU:      skip,
			diagnostic.ProbeTLS:       skip,
			diagnostic.ProbeHTTP:      skip,
			diagnostic.ProbeHTTPS:     skip,
		},
	}.build(t)
}

func TestWhyActionUsesTheExistingDetailsPanel(t *testing.T) {
	m := resolverExplanationModel(t)
	d := m.diagnosis()
	if len(d.Findings) != 1 || d.Findings[0].ID != diagnostic.DiagnosisSystemDNSFailure {
		t.Fatalf("diagnosis = %+v", d)
	}
	if strings.Contains(ansi.Strip(strings.Join(m.detailRows(false), "\n")), "Ruled out") {
		t.Fatal("details panel showed the causal explanation before e was pressed")
	}
	if bar := ansi.Strip(m.helpView(false)); strings.Contains(bar, "e why") {
		t.Fatalf("footer advertises the explanation action: %q", bar)
	}

	m = pressed(t, m, keyPress("e"))
	if !m.explaining || m.selected != m.answerRow() {
		t.Fatalf("explanation state = %v, selected = %d, answer = %d", m.explaining, m.selected, m.answerRow())
	}
	view := ansi.Strip(strings.Join(m.detailRows(false), "\n"))
	for _, want := range []string{
		"Why: DNS example.com",
		// The system resolver failed where an independent one answered, which
		// is an observed comparison, but the branch also records that a general
		// DNS failure was only weakened and not excluded. That surviving
		// alternative is what keeps this off the strongest claim.
		"Confidence",
		"MEDIUM: the best explanation, with an ambiguity unresolved",
		"Evidence",
		"the configured resolver returned SERVFAIL",
		"DNS (public) returned an address",
		"Ruled out",
		"Missing DNS record",
		"General network outage",
		"Against alternatives",
		"General DNS failure",
		"Not evaluated",
		"TCP example.com:443: a prerequisite failed",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("Why view is missing %q:\n%s", want, view)
		}
	}
	if bar := ansi.Strip(m.helpView(false)); strings.Contains(bar, "e details") {
		t.Errorf("open Why footer advertises the toggle: %q", bar)
	}

	m = pressed(t, m, keyPress("e"))
	if m.explaining || !strings.Contains(ansi.Strip(strings.Join(m.detailRows(false), "\n")), "Details: DNS example.com") {
		t.Errorf("second e did not restore normal details: explaining=%v", m.explaining)
	}
}

func TestWhyActionIsUnavailableWithoutACompletedFinding(t *testing.T) {
	m := newModel(nil, false)
	if bar := ansi.Strip(m.helpView(false)); strings.Contains(bar, "e why") {
		t.Errorf("unfinished help bar advertises Why: %q", bar)
	}
	m = pressed(t, m, keyPress("e"))
	if m.explaining || !strings.Contains(m.notice, "no diagnosis explanation") {
		t.Errorf("unfinished e left explaining=%v notice=%q", m.explaining, m.notice)
	}
}

func TestCausalExplanationReachesTheTextReport(t *testing.T) {
	rep := resolverExplanationModel(t).report()
	for _, want := range []string{
		"why:\n  Confidence\n    MEDIUM: the best explanation, with an ambiguity unresolved\n  Evidence",
		"General network outage",
		"TCP example.com:443: a prerequisite failed",
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("report is missing %q:\n%s", want, rep)
		}
	}
}

// TestConfidenceLineCoversTheVocabulary pins the one presentation rule this
// panel adds: each level renders as a word plus what that word means here, and
// nothing else renders at all. A percentage or a meter would be inventing a
// precision the four categories do not have, and a level the app does not know
// is drawn as nothing rather than as a bare token.
func TestConfidenceLineCoversTheVocabulary(t *testing.T) {
	tests := []struct {
		in   diagnostic.Confidence
		want string
	}{
		{diagnostic.ConfidenceHigh, "HIGH: specific evidence, with no alternative left open"},
		{diagnostic.ConfidenceMedium, "MEDIUM: the best explanation, with an ambiguity unresolved"},
		{diagnostic.ConfidenceLow, "LOW: the failure is named, its cause barely narrowed"},
		{diagnostic.ConfidenceInsufficientEvidence, "INSUFFICIENT EVIDENCE: this run cannot say what caused it"},
		// A finding from an artifact written before confidence existed, and a
		// value from a build that knows more words than this one.
		{"", ""},
		{"certain", ""},
	}
	for _, test := range tests {
		if got := confidenceLine(test.in); got != test.want {
			t.Errorf("confidenceLine(%q) = %q, want %q", test.in, got, test.want)
		}
		if strings.ContainsAny(confidenceLine(test.in), "%") {
			t.Errorf("confidenceLine(%q) renders confidence as a quantity", test.in)
		}
	}
}

// The Why panel is the only place confidence appears. The probe table is a list
// of measurements, and a strength-of-evidence word on one of its rows would read
// as a claim about that measurement.
func TestConfidenceStaysOutOfTheChecksPanel(t *testing.T) {
	m := resolverExplanationModel(t)
	view := ansi.Strip(m.View())
	for _, word := range []string{"HIGH:", "MEDIUM:", "LOW:", "INSUFFICIENT EVIDENCE:"} {
		if strings.Contains(view, word) {
			t.Errorf("the ordinary view shows %q before e was pressed:\n%s", word, view)
		}
	}
}

// whyOnWatch is a watched run whose diagnosis carries evidence, with the
// explanation already open on the row it blames: the state the reproducer
// reaches by pressing e on a finished pass.
func whyOnWatch(t *testing.T) model {
	t.Helper()
	m := pressed(t, watchRun(t, watchModel(t), dnsOutage), keyPress("e"))
	if !m.explaining {
		t.Fatal("e did not open the explanation on a finished watch pass")
	}
	return m
}

// whyTitle is the Details panel's title row, which names which of the two
// panels is on screen: "Why: <probe>" for the explanation, "Details: <probe>"
// for the ordinary evidence.
func whyTitle(t *testing.T, m model) string {
	t.Helper()
	rows := m.detailRows(false)
	if len(rows) == 0 {
		t.Fatal("the details panel drew nothing")
	}
	return ansi.Strip(rows[0])
}

// TestWatchPassKeepsTheExplanationOpen is the bug this file's watch coverage
// exists for: a periodic pass replaces the run underneath the reader, and the
// panel they opened to read has to still be there afterwards. It closed on the
// first pass, which left the explanation readable for less than one watch
// interval.
//
// The cursor is asserted alongside it, because an explanation that survived
// onto a different row would be the same bug wearing the opposite result.
func TestWatchPassKeepsTheExplanationOpen(t *testing.T) {
	m := whyOnWatch(t)
	selected, title := m.selected, whyTitle(t, m)
	if want := "Why: DNS example.com"; title != want {
		t.Fatalf("panel title = %q, want %q", title, want)
	}

	m = watchRun(t, m, dnsOutage)
	if !m.explaining {
		t.Error("a watch pass closed the explanation")
	}
	if m.selected != selected {
		t.Errorf("selected = %d, want the row the explanation is about, %d", m.selected, selected)
	}
	if got := whyTitle(t, m); got != title {
		t.Errorf("panel title after one pass = %q, want %q", got, title)
	}
}

// TestRepeatedWatchPassesKeepTheExplanationOpen: one pass surviving could be an
// accident of ordering, and the panel is only useful if it stays put for as
// long as the reader takes to read it.
func TestRepeatedWatchPassesKeepTheExplanationOpen(t *testing.T) {
	m := whyOnWatch(t)
	selected, title := m.selected, whyTitle(t, m)
	for pass := 1; pass <= 4; pass++ {
		m = watchRun(t, m, dnsOutage)
		if !m.explaining {
			t.Fatalf("watch pass %d closed the explanation", pass)
		}
		if m.selected != selected {
			t.Fatalf("pass %d: selected = %d, want %d", pass, m.selected, selected)
		}
		if got := whyTitle(t, m); got != title {
			t.Fatalf("pass %d: panel title = %q, want %q", pass, got, title)
		}
	}
}

// TestExplanationStillClosesByHandAfterAWatchPass: the key that opened it is
// still the key that closes it, and what it goes back to is the ordinary
// Details panel for the same row. Surviving a pass must not leave the toggle
// stuck open.
func TestExplanationStillClosesByHandAfterAWatchPass(t *testing.T) {
	m := watchRun(t, whyOnWatch(t), dnsOutage)
	m = pressed(t, m, keyPress("e"))
	if m.explaining {
		t.Error("e did not close the explanation after a watch pass")
	}
	if got, want := whyTitle(t, m), "Details: DNS example.com"; got != want {
		t.Errorf("panel title = %q, want %q", got, want)
	}
}

// TestMovingTheCursorStillClosesTheExplanationAfterAWatchPass: the explanation
// is about one row, so walking off that row ends it. A pass in between changes
// nothing about that.
func TestMovingTheCursorStillClosesTheExplanationAfterAWatchPass(t *testing.T) {
	m := watchRun(t, whyOnWatch(t), dnsOutage)
	if m = pressed(t, m, keyPress("down")); m.explaining {
		t.Error("moving the cursor left the explanation open")
	}
}

// TestRestartClosesTheExplanation pins the other half of the split: a restart
// the user asked for is a different run than the one on screen, so the screen
// starts over with it. Retest and a new target both take that path, and
// neither may inherit an explanation of the run they replaced.
func TestRestartClosesTheExplanation(t *testing.T) {
	for _, tc := range []struct {
		name string
		act  func(t *testing.T, m model) model
	}{
		{"retest", func(t *testing.T, m model) model {
			t.Helper()
			next, _ := m.retest()
			return asModel(t, next)
		}},
		{"new target", func(t *testing.T, m model) model {
			t.Helper()
			next, _ := m.restartWithTarget(mustTarget(t, "example.net:443"), true)
			return asModel(t, next)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := pressed(t, resolverExplanationModel(t), keyPress("e"))
			if !m.explaining {
				t.Fatal("e did not open the explanation")
			}
			if m = tc.act(t, m); m.explaining {
				t.Error("the restart kept the previous run's explanation open")
			}
		})
	}
}

// TestWatchPassResetsOnlyRunState is the inventory the fix rests on: the two
// halves of a restart, asserted as sets rather than one field at a time. A
// watch pass takes restartRun and leaves resetPresentation alone, so a
// presentation field added later is carried by construction and cannot be
// forgotten the way explaining was.
func TestWatchPassResetsOnlyRunState(t *testing.T) {
	m := whyOnWatch(t)
	m.notice, m.selMoved, m.expanded = "kept", true, true
	m.networkMap, m.mapSelected, m.networkCIDR = true, 3, "192.0.2.0/24"
	m.hostNames = map[string]string{"192.0.2.9": "printer"}
	m.namesPending = map[string]bool{"192.0.2.9": true}
	m.svc = serviceChoice{host: "192.0.2.9"}
	m.cur.name = "nmap"
	gen, results := m.generation, len(m.results)
	if results == 0 {
		t.Fatal("the finished pass recorded no results to replace")
	}

	u, _ := m.Update(watchMsg{gen: m.generation})
	next := asModel(t, u)

	// Run state: replaced.
	if next.generation != gen+1 {
		t.Errorf("generation = %d, want %d", next.generation, gen+1)
	}
	if len(next.results) != 0 || len(next.started) != 0 {
		t.Errorf("the pass kept the previous run's results: %d results, %d started", len(next.results), len(next.started))
	}
	// namesPending is generation-scoped, so its replies are dropped with it.
	if len(next.namesPending) != 0 {
		t.Errorf("namesPending = %v, want the old generation's lookups dropped", next.namesPending)
	}
	// Presentation: untouched.
	for _, f := range []struct {
		name      string
		got, want any
	}{
		{"explaining", next.explaining, true},
		{"selected", next.selected, m.selected},
		{"selMoved", next.selMoved, true},
		{"expanded", next.expanded, true},
		{"notice", next.notice, "kept"},
		{"networkMap", next.networkMap, true},
		{"mapSelected", next.mapSelected, 3},
		{"networkCIDR", next.networkCIDR, "192.0.2.0/24"},
		{"hostNames", next.hostNames["192.0.2.9"], "printer"},
		{"svc host", next.svc.host, "192.0.2.9"},
		{"parked job", next.cur.name, "nmap"},
	} {
		if f.got != f.want {
			t.Errorf("%s = %v, want %v", f.name, f.got, f.want)
		}
	}
}
