package diagnostic

import (
	"net"
	"regexp"
	"strings"
	"testing"
)

// Issue 438: the reference dials failed, the link recovered, and later checks
// passed. The run cannot see the recovery, so the summary must not call one
// failed sample a lasting block.
func TestDirectEgressFailureIsNotDescribedAsLasting(t *testing.T) {
	target := routedTarget
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

// directEgressRunFor is the same failed direct sample with no proxy configured.
func directEgressRunFor() (map[ProbeID]ProbeResult, []ProbeID) {
	res := map[ProbeID]ProbeResult{
		ProbeIface:    ok(StatusPass),
		ProbeInternet: {Status: StatusFail, Cause: RouteCauseSelectedPathFailed},
		ProbeProxy:    ok(StatusNA),
		ProbeDNS:      ok(StatusPass),
	}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS}
	Finalize(res)
	return res, order
}

var routedTarget = &Target{Raw: "routed-target.test", Host: "routed-target.test", Port: 80, Proto: ProtoHTTP}

// wordingRun is one shape a failed direct sample can produce, with the lead
// finding it must produce.
type wordingRun struct {
	name   string
	target *Target
	res    map[ProbeID]ProbeResult
	order  []ProbeID
	want   DiagnosisID
}

// The failed-direct-egress shapes whose user-visible text this file pins: the
// no-proxy finding and the three proxy-only shapes (the generic branch, the same
// branch with a broken resolver, and the target-mode branch).
func wordingRuns() []wordingRun {
	res, order := directEgressRunFor()
	gres, gorder := proxyOnlyRunFor(StatusPass, nil)
	bres, border := proxyOnlyRunFor(StatusFail, nil)
	tres, torder := proxyOnlyRunFor(StatusPass, routedTarget)
	return []wordingRun{
		{"direct egress blocked, no proxy", nil, res, order, DiagnosisDirectEgressBlocked},
		{"generic proxy-only", nil, gres, gorder, DiagnosisProxyOnlyNetwork},
		{"proxy-only with broken DNS", nil, bres, border, DiagnosisDNSFailure},
		{"target behind proxy-only", routedTarget, tres, torder, DiagnosisProxyOnlyNetwork},
	}
}

// lastingPhrases are sentences that state a standing property, a requirement or
// a recovery from one run, or that present one failed sample as a block. None
// may appear in a text a user reads for a failed direct run.
var lastingPhrases = []string{
	"only through a proxy",
	"internet access only",
	"has egress",
	"is unreachable directly, but",
	"(proxy-only network)",
	"is a proxy-only network",
	"is proxy-only",
	"only a proxy can",
	"a path that worked",
	"carried traffic to the egress check",
	"route traffic through the proxy",
	"Use the environment proxy",
	"is the path that worked",
	"do not leave this network",
	"should work",
	// The proxy check tunnels to a fixed reference host, never to the target.
	"proxy reaches",
	"proxy can reach",
	"recovered",
	"now works",
	"back online",
}

// standingWord catches "allow(s)", "require(s)", "must", "block(s)", "blocked"
// and "permanent(ly)" in any form. A sentence saying what this network permits,
// demands or blocks, or calling the failure permanent, is a standing claim the
// run cannot support, whatever its grammatical subject or tense. The hedge's
// "a lasting block" names a possibility the run leaves open, so the bare noun
// is not matched.
var standingWord = regexp.MustCompile(`(?i)\b(allows?|requires?|must|block(s|ed)|permanent(ly)?)\b`)

// Issue 438: every user-visible sentence for a failed direct run is scoped to
// the run. A single failed direct sample is not stated as a lasting condition,
// the proxy is not presented as a requirement, no recovery is claimed, and no
// sentence says what this network permits. The lead finding names what was
// observed, and the summary and the next step offer a rerun.
func TestFailedDirectEgressWordingIsRunScopedAndCategoryFree(t *testing.T) {
	for _, c := range wordingRuns() {
		t.Run(c.name, func(t *testing.T) {
			d := Interpret(c.target, c.order, c.res)
			if len(d.Findings) == 0 || d.Findings[0].ID != c.want {
				t.Fatalf("lead finding: got %+v, want %s", d.Findings, c.want)
			}
			e := Explain(c.target, c.order, c.res)
			rem, ok := Remediate(d, c.res, "linux")
			texts := map[string]string{
				"summary":       d.Summary,
				"headline":      e.Headline,
				"meaning":       e.Meaning,
				"next step":     e.TryFirst,
				"remedy action": rem.Action,
				"remedy why":    rem.Why,
				"remedy steps":  strings.Join(rem.Steps, " "),
				"remedy expect": rem.Expect,
			}
			for label, text := range texts {
				for _, s := range lastingPhrases {
					// Case-insensitive: "Only a proxy can" opens a sentence as often as not.
					if strings.Contains(strings.ToLower(text), strings.ToLower(s)) {
						t.Errorf("%s %q states a standing property or a recovery: contains %q", label, text, s)
					}
				}
				if m := standingWord.FindString(text); m != "" {
					t.Errorf("%s %q makes a standing claim about this network: contains %q", label, text, m)
				}
			}
			if !strings.Contains(d.Summary, "during this run") || !strings.Contains(d.Summary, "again") {
				t.Errorf("summary %q does not say the failure was seen in this run and may be retried", d.Summary)
			}
			if strings.Contains(d.Summary, "is failing") {
				t.Errorf("summary %q states a lasting failure from one run", d.Summary)
			}
			// The next step offers a rerun on the proxy-only shapes, as it always
			// has. The DNS-failure shape is remedied by the resolver row, which
			// this wording does not own, so its remedy steps are not checked here.
			if c.want != DiagnosisDirectEgressBlocked && !strings.Contains(e.TryFirst, "again") {
				t.Errorf("next step %q does not offer a rerun", e.TryFirst)
			}
			if !ok {
				t.Fatalf("no remediation for %s", c.want)
			}
			if c.want != DiagnosisDNSFailure && !strings.Contains(strings.Join(rem.Steps, " "), "again") {
				t.Errorf("remediation steps %q do not offer a rerun", rem.Steps)
			}
		})
	}
}

// Reviewer D (PR 467): the remedy's action and why describe what this run
// observed. The direct-egress action offers a path without asserting one exists,
// and the proxy remedy says only that the proxy carried a test connection.
func TestRemedyWordingDescribesTheRunNotThePolicy(t *testing.T) {
	cases := []struct {
		name string
		run  func() (map[ProbeID]ProbeResult, []ProbeID)
		want DiagnosisID
		text map[string]string
	}{
		{
			name: "direct egress blocked",
			run:  directEgressRunFor,
			want: DiagnosisDirectEgressBlocked,
			text: map[string]string{
				"action": "Send this traffic through the path this network intends, if it has one",
				"expect": "Traffic leaving through the path this network intends, if it has one, or a confirmed filter.",
			},
		},
		{
			name: "generic proxy-only",
			run:  func() (map[ProbeID]ProbeResult, []ProbeID) { return proxyOnlyRunFor(StatusPass, nil) },
			want: DiagnosisProxyOnlyNetwork,
			text: map[string]string{
				"action": "Try the environment proxy for this traffic",
				"why":    "Direct connections failed during this run, but the configured proxy carried a test connection at the same time.",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, order := c.run()
			d := Interpret(nil, order, res)
			if len(d.Findings) == 0 || d.Findings[0].ID != c.want {
				t.Fatalf("lead finding: got %+v, want %s", d.Findings, c.want)
			}
			rem, ok := Remediate(d, res, "linux")
			if !ok {
				t.Fatalf("no remediation for %s", c.want)
			}
			got := map[string]string{"action": rem.Action, "why": rem.Why, "expect": rem.Expect}
			for label, want := range c.text {
				if got[label] != want {
					t.Errorf("remedy %s:\n got %q\nwant %q", label, got[label], want)
				}
			}
		})
	}
}

// A target failure with working direct egress and a working proxy points at
// the target. It must not borrow the proxy wording, which describes a failed
// direct path, and the proxy row must not be read as the cause.
func TestTargetFailureWithWorkingEgressIsNotProxyWording(t *testing.T) {
	res := map[ProbeID]ProbeResult{
		ProbeIface:     ok(StatusPass),
		ProbeInternet:  ok(StatusPass),
		ProbeProxy:     ok(StatusPass),
		ProbeDNS:       ok(StatusPass),
		ProbeTargetTCP: {Status: StatusFail},
	}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeTargetTCP}
	Finalize(res)
	d := Interpret(routedTarget, order, res)
	if len(d.Findings) == 0 || d.Findings[0].ID != DiagnosisTargetUnreachable {
		t.Fatalf("lead finding: got %+v, want %s", d.Findings, DiagnosisTargetUnreachable)
	}
	for _, s := range []string{"proxy", "allow"} {
		if strings.Contains(strings.ToLower(d.Summary), s) {
			t.Errorf("target-unreachable summary %q borrows proxy or egress wording: contains %q", d.Summary, s)
		}
	}
}

// The proxy-only shapes keep the proxy-path remedy, and their headline states
// that the observation is run-scoped, as the original run-scope test required.
func TestProxyOnlyShapesKeepTheirRemedyAndRunScopedHeadline(t *testing.T) {
	for _, c := range wordingRuns() {
		if c.want != DiagnosisProxyOnlyNetwork {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			d := Interpret(c.target, c.order, c.res)
			e := Explain(c.target, c.order, c.res)
			rem, ok := Remediate(d, c.res, "linux")
			if !ok || rem.ID != RemedyUseProxyPath {
				t.Fatalf("remedy: got %+v (ok=%v), want %s", rem.ID, ok, RemedyUseProxyPath)
			}
			if !strings.Contains(e.Headline, "during this run") {
				t.Errorf("headline %q does not say the observation is run-scoped", e.Headline)
			}
		})
	}
}
