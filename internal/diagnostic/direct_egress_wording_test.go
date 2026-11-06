package diagnostic

import (
	"net"
	"strings"
	"testing"
)

// Issue 438: the reference dials failed, the link recovered, and later checks
// passed. The run cannot see the recovery, so the summary must not call one
// failed sample a lasting block.
func TestDirectEgressFailureIsNotDescribedAsLasting(t *testing.T) {
	target := &Target{Raw: "routed-target.test", Host: "routed-target.test", Port: 80, Proto: ProtoHTTP}
	res := map[ProbeID]ProbeResult{
		ProbeIface:     ok(StatusPass),
		ProbeInternet:  {Status: StatusFail, Cause: RouteCauseSelectedPathFailed},
		ProbeDNS:       ok(StatusPass),
		ProbeTargetTCP: {Status: StatusPass, SelectedIP: net.ParseIP("10.77.2.20")},
		ProbeHTTP:      ok(StatusPass),
		ProbeQUIC:      ok(StatusPass),
	}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeHTTP, ProbeQUIC}

	d := Interpret(target, order, res)
	if len(d.Findings) != 1 || d.Findings[0].ID != DiagnosisDirectEgressBlocked {
		t.Fatalf("findings: got %+v, want one %s finding", d.Findings, DiagnosisDirectEgressBlocked)
	}
	if strings.Contains(d.Summary, "is blocked") {
		t.Errorf("summary claims a lasting block from one observed failure: %q", d.Summary)
	}
	if !strings.Contains(d.Summary, "during this run") {
		t.Errorf("summary does not say when the failure was observed: %q", d.Summary)
	}
	if !strings.Contains(d.Summary, "again") {
		t.Errorf("summary does not say the state may change: %q", d.Summary)
	}
}

// proxyOnlyRunFor builds what one run records when direct TCP egress fails and
// the environment proxy carries traffic, then applies the same Finalize pass a
// real run applies. dns is the resolver row; a non-nil target adds a failed
// target dial, which is the only way the target-mode proxy branch is reached.
func proxyOnlyRunFor(dns Status, target *Target) (map[ProbeID]ProbeResult, []ProbeID) {
	res := map[ProbeID]ProbeResult{
		ProbeIface:    ok(StatusPass),
		ProbeInternet: {Status: StatusFail, Cause: RouteCauseSelectedPathFailed},
		ProbeProxy:    ok(StatusPass),
		ProbeDNS:      ok(dns),
	}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS}
	if target != nil {
		res[ProbeTargetTCP] = ProbeResult{Status: StatusFail}
		order = append(order, ProbeTargetTCP)
	}
	Finalize(res)
	return res, order
}

// The three proxy-only shapes a single failed direct sample can produce: the
// generic no-target branch, the same branch with a broken resolver, and the
// target-mode branch. banned lists sentences that claim a lasting condition.
var proxyOnlyShapes = []struct {
	name   string
	target *Target
	dns    Status
	want   DiagnosisID
	banned []string
}{
	{"generic proxy-only", nil, StatusPass, DiagnosisProxyOnlyNetwork, []string{"is blocked"}},
	{"proxy-only with broken DNS", nil, StatusFail, DiagnosisDNSFailure, []string{"is blocked", "is failing"}},
	{"target behind proxy-only", &Target{Raw: "routed-target.test", Host: "routed-target.test", Port: 80, Proto: ProtoHTTP}, StatusPass, DiagnosisProxyOnlyNetwork, []string{"is unreachable directly, but", "this is a proxy-only network"}},
}

// Issue 438: a single failed direct sample must not be stated as a lasting
// proxy-only network. The summary keeps the observed scope and says the check
// can be run again to see whether the failure persists.
func TestProxyOnlySummariesDoNotCallOneFailureLasting(t *testing.T) {
	for _, c := range proxyOnlyShapes {
		t.Run(c.name, func(t *testing.T) {
			res, order := proxyOnlyRunFor(c.dns, c.target)
			d := Interpret(c.target, order, res)
			if len(d.Findings) == 0 || d.Findings[0].ID != c.want {
				t.Fatalf("lead finding: got %+v, want %s", d.Findings, c.want)
			}
			for _, s := range c.banned {
				if strings.Contains(d.Summary, s) {
					t.Errorf("summary %q states a lasting condition from one run: contains %q", d.Summary, s)
				}
			}
			for _, s := range []string{"during this run", "again"} {
				if !strings.Contains(d.Summary, s) {
					t.Errorf("summary %q does not say the failure was seen in this run and may be retried: missing %q", d.Summary, s)
				}
			}
		})
	}
}

// Issue 438: the plain headline and body must not state the block as a fact,
// and the next step must offer a rerun for the same reason.
func TestProxyOnlyPlainTextDoesNotStateALastingBlock(t *testing.T) {
	for _, c := range proxyOnlyShapes {
		t.Run(c.name, func(t *testing.T) {
			res, order := proxyOnlyRunFor(c.dns, c.target)
			d := Interpret(c.target, order, res)
			if len(d.Findings) == 0 || d.Findings[0].ID != c.want {
				t.Fatalf("lead finding: got %+v, want %s", d.Findings, c.want)
			}
			res2, _ := proxyOnlyRunFor(c.dns, c.target)
			e := Explain(c.target, order, res2)
			text := e.Headline + " " + e.Meaning
			for _, s := range []string{"are blocked", "is blocked", "allows internet access only"} {
				if strings.Contains(text, s) {
					t.Errorf("plain text %q states a lasting condition from one run: contains %q", text, s)
				}
			}
			if !strings.Contains(e.TryFirst, "again") {
				t.Errorf("plain next step %q does not offer a rerun", e.TryFirst)
			}
		})
	}
}

// Issue 438: remediation for the proxy path must offer a rerun, and must not
// describe direct connections as leaving the network in the present tense.
func TestProxyPathRemediationOffersARerun(t *testing.T) {
	for _, c := range proxyOnlyShapes {
		if c.want != DiagnosisProxyOnlyNetwork {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			res, order := proxyOnlyRunFor(c.dns, c.target)
			d := Interpret(c.target, order, res)
			res2, _ := proxyOnlyRunFor(c.dns, c.target)
			rem, ok := Remediate(d, res2, "linux")
			if !ok || rem.ID != RemedyUseProxyPath {
				t.Fatalf("remediation: got ok=%v %+v, want %s", ok, rem, RemedyUseProxyPath)
			}
			if strings.Contains(rem.Why, "do not leave this network") {
				t.Errorf("remediation why states a lasting condition: %q", rem.Why)
			}
			if !strings.Contains(strings.Join(rem.Steps, " "), "again") {
				t.Errorf("remediation steps %q do not offer a rerun", rem.Steps)
			}
		})
	}
}

// lastingPhrases are sentences that state a standing property, a requirement or
// a recovery from one run. None may appear in a text a user reads for a
// proxy-only run.
var lastingPhrases = []string{
	"only through a proxy",
	"allow internet access only",
	"has egress",
	"route traffic through the proxy",
	"Use the environment proxy",
	"is the path that worked",
	"should work",
	"recovered",
	"now works",
	"back online",
}

// Issue 438: every user-visible sentence for a proxy-only run is scoped to the
// run. The headline of a proxy-only finding must say what was observed in this
// run, and no sentence may state a standing property or a recovery.
func TestProxyOnlyWordingStaysWithinTheRun(t *testing.T) {
	for _, c := range proxyOnlyShapes {
		t.Run(c.name, func(t *testing.T) {
			res, order := proxyOnlyRunFor(c.dns, c.target)
			d := Interpret(c.target, order, res)
			e := Explain(c.target, order, res)
			rem, _ := Remediate(d, res, "linux")
			texts := map[string]string{
				"summary":       d.Summary,
				"headline":      e.Headline,
				"meaning":       e.Meaning,
				"next step":     e.TryFirst,
				"remedy action": rem.Action,
				"remedy why":    rem.Why,
				"remedy steps":  strings.Join(rem.Steps, " "),
			}
			for label, text := range texts {
				for _, s := range lastingPhrases {
					if strings.Contains(text, s) {
						t.Errorf("%s %q states a standing property or a recovery: contains %q", label, text, s)
					}
				}
			}
			if c.want == DiagnosisProxyOnlyNetwork && !strings.Contains(e.Headline, "during this run") {
				t.Errorf("headline %q does not say what was observed in this run", e.Headline)
			}
		})
	}
}

// The direct-egress finding already says the failure may be temporary, so its
// remediation, which shares the proxy path, must offer the same rerun.
func TestDirectEgressRemediationOffersARerun(t *testing.T) {
	res := map[ProbeID]ProbeResult{
		ProbeIface:    ok(StatusPass),
		ProbeInternet: {Status: StatusFail, Cause: RouteCauseSelectedPathFailed},
		ProbeProxy:    ok(StatusNA),
		ProbeDNS:      ok(StatusPass),
	}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS}
	Finalize(res)
	d := Interpret(nil, order, res)
	if len(d.Findings) == 0 || d.Findings[0].ID != DiagnosisDirectEgressBlocked {
		t.Fatalf("lead finding: got %+v, want %s", d.Findings, DiagnosisDirectEgressBlocked)
	}
	res2 := map[ProbeID]ProbeResult{
		ProbeIface:    ok(StatusPass),
		ProbeInternet: {Status: StatusFail, Cause: RouteCauseSelectedPathFailed},
		ProbeProxy:    ok(StatusNA),
		ProbeDNS:      ok(StatusPass),
	}
	Finalize(res2)
	rem, ok := Remediate(d, res2, "linux")
	if !ok {
		t.Fatalf("no remediation for %s", DiagnosisDirectEgressBlocked)
	}
	if !strings.Contains(strings.Join(rem.Steps, " "), "again") {
		t.Errorf("remediation steps %q do not offer a rerun", rem.Steps)
	}
}
