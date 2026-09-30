// Explain is the diagnosis retold for a reader with no networking vocabulary.
// These tests hold it to the diagnosis it retells: it may say less, and say it
// in plainer words, but it never claims more than the finding established,
// never reads an unfinished run as a verdict, and never advises something the
// evidence does not point at. The rendering of it is pinned in
// internal/ui/plain_test.go.

package diagnostic

import (
	"go/ast"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	healthyHeadline = "No obvious problem found"
	lowSentence     = "Network Doctor could not pin down the exact cause."
	unknownSentence = "Network Doctor does not have enough evidence to say why."
)

// TestEveryDiagnosisIDHasAnExplanation keeps the table total, so a new
// identity cannot reach the screen as a blank headline.
func TestEveryDiagnosisIDHasAnExplanation(t *testing.T) {
	declared := map[DiagnosisID]bool{}
	for _, spec := range declaredConstants(t, "finding.go", "DiagnosisID") {
		for i, name := range spec.Names {
			value, err := strconv.Unquote(spec.Values[i].(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			id := DiagnosisID(value)
			declared[id] = true
			text, ok := plainTexts[id]
			if !ok {
				t.Errorf("%s (%q) has no entry in plainTexts", name.Name, value)
				continue
			}
			if text.headline == "" || text.meaning == "" {
				t.Errorf("%s has an empty headline or meaning: %+v", name.Name, text)
			}
		}
	}
	for id := range plainTexts {
		if !declared[id] {
			t.Errorf("plainTexts explains %q, which is not a declared diagnosis ID", id)
		}
	}
}

// TestExplanationFollowsTheDiagnosis runs every arm of the diagnosis matrix
// and holds the explanation to the invariants that make it safe to put above
// the technical answer.
func TestExplanationFollowsTheDiagnosis(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			d := Interpret(c.target, c.order, c.res)
			e := Explain(c.target, c.order, c.res)
			if again := Explain(c.target, c.order, maps.Clone(c.res)); again != e {
				t.Errorf("Explain is not deterministic:\n%+v\n%+v", e, again)
			}
			all := e.Headline + " " + e.Meaning + " " + e.TryFirst
			if e.Headline == "" {
				t.Fatal("empty headline")
			}
			// rune 0x2014 is the em dash, built at run time because a literal
			// one fails TestNoEmDashInTrackedTextFiles.
			for _, bad := range []string{"{host}", string(rune(0x2014)), "Oops", "Don't worry", "perfect"} {
				if strings.Contains(all, bad) {
					t.Errorf("explanation contains %q: %+v", bad, e)
				}
			}
			failed := slices.ContainsFunc(c.order, func(id ProbeID) bool { r, ok := c.res[id]; return ok && r.Status == StatusFail })
			healthy := e.Headline == healthyHeadline
			// A healthy headline is only ever the ok verdict, and never over a
			// failed row, a warning, or a run that has not finished.
			if healthy != (d.Verdict == VerdictOK && len(c.order) > 0) {
				t.Errorf("verdict %q with headline %q", d.Verdict, e.Headline)
			}
			if healthy && failed {
				t.Errorf("a run with a failed row is explained as healthy: %+v", e)
			}
			if d.Verdict == VerdictIncomplete && (e.Headline != "The checks have not finished" || e.Meaning != "" || e.TryFirst != "") {
				t.Errorf("an unfinished run is explained as %+v", e)
			}
			if (d.Verdict == VerdictOK || d.Verdict == VerdictIncomplete) && e.TryFirst != "" {
				t.Errorf("verdict %q offers a first step: %q", d.Verdict, e.TryFirst)
			}
			// The strength of the plain sentence is the finding's confidence,
			// said once and only where the finding carries it.
			var conf Confidence
			if len(d.Findings) > 0 {
				conf = d.Findings[0].Confidence
			}
			if got, want := strings.Contains(e.Meaning, lowSentence), conf == ConfidenceLow; got != want {
				t.Errorf("confidence %q, low-confidence sentence present = %v: %q", conf, got, e.Meaning)
			}
			if got, want := strings.Contains(e.Meaning, unknownSentence), conf == ConfidenceInsufficientEvidence; got != want {
				t.Errorf("confidence %q, insufficient-evidence sentence present = %v: %q", conf, got, e.Meaning)
			}
			// "Your internet connection works" is a claim about the egress
			// row, and only the diagnosis's own test for it may license it.
			if strings.Contains(e.Meaning, "internet connection itself works") && !directEgressOK(c.res) {
				t.Errorf("claims a working connection the egress row does not show: %q", e.Meaning)
			}
			// Restarting the router is advice about a dead connection or a
			// failing name lookup, and nothing else.
			if strings.Contains(e.TryFirst, "router") {
				switch d.Findings[0].ID {
				case DiagnosisOffline, DiagnosisReachabilityUnlocalized, DiagnosisDNSFailure, DiagnosisSystemDNSFailure, DiagnosisDNSNameNotFound:
				default:
					t.Errorf("%s advises the router: %q", d.Findings[0].ID, e.TryFirst)
				}
			}
			if d.Verdict == VerdictDegraded && strings.Contains(e.Headline, "cannot reach") {
				t.Errorf("a degraded run is headlined as unreachable: %q", e.Headline)
			}
		})
	}
}

// TestNameLookupFailureDependsOnThePathUnderIt: a failed lookup on a working
// connection is its own problem, and one beside a dead connection is not
// presented as the root cause the reader should fix first.
func TestNameLookupFailureDependsOnThePathUnderIt(t *testing.T) {
	working := matrixCaseNamed(t, "targeted DNS failure with working egress")
	e := Explain(working.target, working.order, working.res)
	if !strings.Contains(e.Meaning, "Your internet connection itself works.") {
		t.Errorf("a lookup failure over working egress does not say the connection works: %q", e.Meaning)
	}
	if !strings.HasPrefix(e.TryFirst, "Check that the name is spelled correctly.") {
		t.Errorf("a lookup failure that may be a misspelled name does not start with the spelling: %q", e.TryFirst)
	}

	dead := matrixCaseNamed(t, "targeted DNS failure")
	e = Explain(dead.target, dead.order, dead.res)
	if strings.Contains(e.Meaning, "itself works") {
		t.Errorf("a lookup failure beside failed egress claims the connection works: %q", e.Meaning)
	}
	if !strings.Contains(e.Meaning, "may be down") || e.TryFirst != plainTryOffline {
		t.Errorf("a lookup failure beside failed egress does not point at the connection first: %+v", e)
	}

	generic := matrixCaseNamed(t, "generic egress works, DNS broken")
	if e := Explain(generic.target, generic.order, generic.res); strings.Contains(e.TryFirst, "spelled") {
		t.Errorf("a run with no target asks the reader to respell a name they never typed: %q", e.TryFirst)
	}
}

// TestUnexplainedFailuresAreCounted: rows the diagnosis already explains, as
// its evidence or as consequences of the blamed row, are not counted again,
// and a failure it does not explain is.
func TestUnexplainedFailuresAreCounted(t *testing.T) {
	tls := &Target{Raw: "example.com", Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeTargetTCP, ProbeTLS, ProbeHTTPS}
	res := map[ProbeID]ProbeResult{
		ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusFail), ProbeProxy: ok(StatusPass),
		ProbeDNS: ok(StatusFail), ProbeTargetTCP: ok(StatusFail), ProbeTLS: ok(StatusFail), ProbeHTTPS: ok(StatusFail),
	}
	if n := Explain(tls, order, res).Unexplained; n != 0 {
		t.Errorf("an offline run's knock-on failures count as %d unexplained", n)
	}
	res[ProbeProxy] = ok(StatusFail)
	if n := Explain(tls, order, res).Unexplained; n != 1 {
		t.Errorf("an independently failing proxy counts as %d unexplained, want 1", n)
	}
}

// TestUncertainRunsAreNotConfident: the arms whose own meaning is that netdoc
// could not tell say so in plain words too, and offer no confident remedy.
func TestUncertainRunsAreNotConfident(t *testing.T) {
	for _, name := range []string{
		"target unreachable with egress unchecked",
		"target and reference endpoints both unreachable",
		"target silent only at uncorroborated addresses",
		"selected DNS check failed",
		"TLS handshake failure",
		"target unreachable while the internet works",
	} {
		c := matrixCaseNamed(t, name)
		e := Explain(c.target, c.order, c.res)
		if !strings.Contains(e.Meaning, lowSentence) && !strings.Contains(e.Meaning, unknownSentence) {
			t.Errorf("%s: the meaning does not admit the uncertainty: %q", name, e.Meaning)
		}
	}
}

// TestSpecificExplanations pins the arms whose plain reading is easy to get
// wrong: each names the right part of the connection and the right first step.
func TestSpecificExplanations(t *testing.T) {
	cases := []struct {
		name, headline, try string
	}{
		{"link down", "not connected to a network", "Wi-Fi"},
		{"generic offline", "cannot reach the internet", "other devices"},
		{"target unreachable and the routing table names the break", "cannot reach the internet", "reconnect"},
		{"generic captive portal", "sign in", "sign-in page"},
		{"generic proxy failed", "proxy", "ask"},
		{"generic proxy-only network with broken DNS", "names", "IT staff"},
		{"target reachable over IPv4 only", "one way but not the other", ""},
		{"target reachable over IPv6 only", "one way but not the other", ""},
		{"TLS expiry explained by a fast clock", "clock is wrong", "date and time"},
		{"TLS expiry with the clock ruled out", "expired", "Do not click past"},
		{"TLS untrusted issuer", "does not trust", "Do not click past"},
		{"path MTU black hole", "Larger transfers", "VPN"},
		{"no plain HTTP response beside working HTTPS", "unencrypted web address", "https://"},
		{"target refuses the connection", "turning connections away", "started"},
		{"targeted name has no records", "does not exist", "spelling"},
		{"generic QUIC blocked", "faster connection method", ""},
	}
	for _, tc := range cases {
		c := matrixCaseNamed(t, tc.name)
		e := Explain(c.target, c.order, c.res)
		if !strings.Contains(e.Headline, tc.headline) {
			t.Errorf("%s: headline %q, want it to mention %q", tc.name, e.Headline, tc.headline)
		}
		if tc.try == "" && e.TryFirst != "" || !strings.Contains(e.TryFirst, tc.try) {
			t.Errorf("%s: first step %q, want %q", tc.name, e.TryFirst, tc.try)
		}
	}
	// IPv6 and IPv4 are not interchangeable in the sentence that names them.
	v4 := matrixCaseNamed(t, "target reachable over IPv4 only")
	if e := Explain(v4.target, v4.order, v4.res); !strings.Contains(e.Meaning, "answered over IPv4 but not over IPv6") {
		t.Errorf("IPv4-only reachability explained as %q", e.Meaning)
	}
	v6 := matrixCaseNamed(t, "target reachable over IPv6 only")
	if e := Explain(v6.target, v6.order, v6.res); !strings.Contains(e.Meaning, "answered over IPv6 but not over IPv4") {
		t.Errorf("IPv6-only reachability explained as %q", e.Meaning)
	}
}
