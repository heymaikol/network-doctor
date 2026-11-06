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
// target-mode branch.
var proxyOnlyShapes = []struct {
	name   string
	target *Target
	dns    Status
	want   DiagnosisID
}{
	{"generic proxy-only", nil, StatusPass, DiagnosisProxyOnlyNetwork},
	{"proxy-only with broken DNS", nil, StatusFail, DiagnosisDNSFailure},
	{"target behind proxy-only", &Target{Raw: "routed-target.test", Host: "routed-target.test", Port: 80, Proto: ProtoHTTP}, StatusPass, DiagnosisProxyOnlyNetwork},
}

// lastingPhrases are sentences that state a standing property, a requirement or
// a recovery from one run, or that present one failed sample as a block. None
// may appear in a text a user reads for a proxy-only run.
var lastingPhrases = []string{
	"are blocked",
	"is blocked",
	"only through a proxy",
	"allow internet access only",
	"has egress",
	"is unreachable directly, but",
	"this is a proxy-only network",
	"route traffic through the proxy",
	"Use the environment proxy",
	"is the path that worked",
	"do not leave this network",
	"should work",
	"recovered",
	"now works",
	"back online",
}

// Issue 438: every user-visible sentence for a proxy-only run is scoped to the
// run. A single failed direct sample is not stated as a lasting condition, the
// proxy is not presented as a requirement, and no recovery is claimed. The
// headline of a proxy-only finding names what was observed in this run, and the
// summary, next step and remedy all offer a rerun.
func TestProxyOnlyWordingIsRunScoped(t *testing.T) {
	for _, c := range proxyOnlyShapes {
		t.Run(c.name, func(t *testing.T) {
			res, order := proxyOnlyRunFor(c.dns, c.target)
			d := Interpret(c.target, order, res)
			if len(d.Findings) == 0 || d.Findings[0].ID != c.want {
				t.Fatalf("lead finding: got %+v, want %s", d.Findings, c.want)
			}
			e := Explain(c.target, order, res)
			rem, ok := Remediate(d, res, "linux")
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
			if !strings.Contains(d.Summary, "during this run") || !strings.Contains(d.Summary, "again") {
				t.Errorf("summary %q does not say the failure was seen in this run and may be retried", d.Summary)
			}
			if strings.Contains(d.Summary, "is failing") {
				t.Errorf("summary %q states a lasting failure from one run", d.Summary)
			}
			if !strings.Contains(e.TryFirst, "again") {
				t.Errorf("next step %q does not offer a rerun", e.TryFirst)
			}
			if c.want != DiagnosisProxyOnlyNetwork {
				return
			}
			if !strings.Contains(e.Headline, "during this run") {
				t.Errorf("headline %q does not say what was observed in this run", e.Headline)
			}
			if !ok || rem.ID != RemedyUseProxyPath {
				t.Fatalf("remediation: got ok=%v %+v, want %s", ok, rem, RemedyUseProxyPath)
			}
			if !strings.Contains(strings.Join(rem.Steps, " "), "again") {
				t.Errorf("remediation steps %q do not offer a rerun", rem.Steps)
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
	rem, ok := Remediate(d, res, "linux")
	if !ok {
		t.Fatalf("no remediation for %s", DiagnosisDirectEgressBlocked)
	}
	if !strings.Contains(strings.Join(rem.Steps, " "), "again") {
		t.Errorf("remediation steps %q do not offer a rerun", rem.Steps)
	}
}
