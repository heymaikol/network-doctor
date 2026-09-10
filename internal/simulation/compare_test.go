package simulation

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
)

func diag(verdict string, checks ...DiagnosisCheck) *Diagnosis {
	return &Diagnosis{Verdict: verdict, Summary: "summary", Checks: checks}
}

func check(id, status string) DiagnosisCheck {
	return DiagnosisCheck{ID: id, Name: id, Status: status, Detail: "detail", Fix: "fix", Ms: 1}
}

func TestCompareMatches(t *testing.T) {
	o := TestOutcome{Name: "t", Diagnosis: diag("dns",
		check("iface", "PASS"), check("dns", "FAIL"), check("internet_tcp", "PASS"))}
	o.compare(Expect{Verdict: "dns", Checks: []ExpectedCheck{
		{ID: "iface", Status: "PASS"}, {ID: "dns", Status: "FAIL"}, {ID: "internet_tcp", Status: "PASS"},
	}}, 4*time.Second)

	if !o.ok() {
		t.Fatalf("want ok, got %+v", o.Checks)
	}
	if o.Matched != 3 || o.FalseNegatives != 0 || o.FalsePositives != 0 {
		t.Errorf("matched=%d fn=%d fp=%d", o.Matched, o.FalseNegatives, o.FalsePositives)
	}
	if len(o.suggest()) != 0 {
		t.Errorf("a clean run should suggest nothing, got %v", o.suggest())
	}
}

func TestCompareFalseNegative(t *testing.T) {
	// The scenario broke DNS; netdoc called it fine. That is the miss this
	// whole package exists to name.
	o := TestOutcome{Name: "t", Diagnosis: diag("ok", check("dns", "PASS"))}
	o.compare(Expect{Verdict: "dns", Checks: []ExpectedCheck{{ID: "dns", Status: "FAIL"}}}, 4*time.Second)

	if o.ok() {
		t.Error("want not ok")
	}
	if o.FalseNegatives != 1 || o.FalsePositives != 0 {
		t.Errorf("fn=%d fp=%d, want 1/0", o.FalseNegatives, o.FalsePositives)
	}
	if o.Checks[0].Outcome != OutcomeWrongStatus {
		t.Errorf("outcome = %q", o.Checks[0].Outcome)
	}
	codes := suggestionCodes(&o)
	if !slices.Contains(codes, SuggestMissedFinding) || !slices.Contains(codes, SuggestWrongVerdict) {
		t.Errorf("codes = %v", codes)
	}
}

func TestCompareFalsePositive(t *testing.T) {
	o := TestOutcome{Name: "t", Diagnosis: diag("ok", check("iface", "PASS"), check("internet_tcp", "FAIL"))}
	o.compare(Expect{Verdict: "ok", Checks: []ExpectedCheck{{ID: "iface", Status: "PASS"}}}, 4*time.Second)

	if o.FalsePositives != 1 {
		t.Errorf("fp = %d, want 1", o.FalsePositives)
	}
	if !slices.Contains(suggestionCodes(&o), SuggestFalsePositive) {
		t.Errorf("codes = %v", suggestionCodes(&o))
	}
	// Naming the row must not downgrade the finding: a scenario that says this
	// probe passes and gets a FAIL is the same false positive as an unmentioned
	// one. The healthy scenario names every row it cares about, so this is the
	// shape a netdoc regression actually arrives in.
	o3 := TestOutcome{Name: "t", Diagnosis: diag("dns", check("dns", "FAIL"))}
	o3.compare(Expect{Verdict: "ok", Checks: []ExpectedCheck{{ID: "dns", Status: "PASS"}}}, 4*time.Second)
	if o3.FalsePositives != 1 || o3.FalseNegatives != 0 {
		t.Errorf("expected PASS, got FAIL: fp=%d fn=%d, want 1/0", o3.FalsePositives, o3.FalseNegatives)
	}
	if codes := suggestionCodes(&o3); !slices.Contains(codes, SuggestFalsePositive) || slices.Contains(codes, SuggestWrongSeverity) {
		t.Errorf("codes = %v: a flag on a working probe is a false positive, not a severity mistake", codes)
	}

	// A PASS nobody mentioned is not a false positive.
	o2 := TestOutcome{Name: "t", Diagnosis: diag("ok", check("iface", "PASS"), check("http", "PASS"))}
	o2.compare(Expect{Verdict: "ok", Checks: []ExpectedCheck{{ID: "iface", Status: "PASS"}}}, 4*time.Second)
	if o2.FalsePositives != 0 || !o2.ok() {
		t.Errorf("an unmentioned PASS should be ignored, got fp=%d ok=%t", o2.FalsePositives, o2.ok())
	}
}

func TestProxySuggestionPreservesStructuredCause(t *testing.T) {
	o := TestOutcome{Name: "proxy", Diagnosis: diag("degraded", DiagnosisCheck{
		ID: "proxy_connect", Status: "FAIL", Cause: "client_dns_failure", Detail: "local DNS failed", Fix: "fix DNS",
	})}
	o.compare(Expect{Verdict: "degraded", Checks: []ExpectedCheck{{ID: "proxy_connect", Status: "PASS"}}}, time.Second)
	suggestions := o.suggest()
	if len(suggestions) == 0 || suggestions[0].Cause != "client_dns_failure" {
		t.Errorf("suggestions = %+v", suggestions)
	}
}

func TestCompareExpectedCause(t *testing.T) {
	actual := DiagnosisCheck{ID: "tls", Name: "TLS", Status: "FAIL", Cause: "hostname_mismatch", Detail: "wrong name", Fix: "fix cert", Ms: 1}
	matching := TestOutcome{Name: "tls", Diagnosis: diag("service", actual)}
	matching.compare(Expect{Verdict: "service", Checks: []ExpectedCheck{{
		ID: "tls", Status: "FAIL", Cause: "hostname_mismatch",
	}}}, time.Second)
	if !matching.ok() || matching.FalseNegatives != 0 || matching.FalsePositives != 0 {
		t.Fatalf("matching cause = %+v", matching)
	}

	wrong := TestOutcome{Name: "tls", Diagnosis: diag("service", actual)}
	wrong.compare(Expect{Verdict: "service", Checks: []ExpectedCheck{{
		ID: "tls", Status: "FAIL", Cause: "certificate_expired",
	}}}, time.Second)
	if wrong.ok() || wrong.Checks[0].Outcome != OutcomeWrongCause || wrong.FalseNegatives != 0 || wrong.FalsePositives != 0 {
		t.Fatalf("wrong cause comparison = %+v", wrong)
	}
	if !slices.Contains(suggestionCodes(&wrong), SuggestWrongCause) {
		t.Errorf("suggestions = %+v", wrong.suggest())
	}
}

func TestCompareExpectedWording(t *testing.T) {
	actual := DiagnosisCheck{ID: "internet_tcp", Name: "Internet", Status: "WARN", Cause: "ipv6_unreachable",
		Fix: "check IPv6 route", Families: &DiagnosisFamilies{IPv4: "reachable", IPv6: "unreachable"}}
	for _, tc := range []struct {
		name        string
		expect      Expect
		wantOK      bool
		wantOutcome string
	}{
		{"matching fix", Expect{Checks: []ExpectedCheck{{ID: "internet_tcp", Status: "WARN", Cause: "ipv6_unreachable",
			IPv4: "reachable", IPv6: "unreachable", Fix: "check IPv6 route"}}}, true, OutcomeMatched},
		{"mismatching fix", Expect{Checks: []ExpectedCheck{{ID: "internet_tcp", Status: "WARN",
			Fix: "check the gateway"}}}, false, OutcomeWrongFix},
		{"omitted fix", Expect{Checks: []ExpectedCheck{{ID: "internet_tcp", Status: "WARN"}}}, true, OutcomeMatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := TestOutcome{Name: "wording", Diagnosis: diag("degraded", actual)}
			o.compare(tc.expect, time.Second)
			if o.ok() != tc.wantOK || len(o.Checks) != 1 || o.Checks[0].Outcome != tc.wantOutcome {
				t.Fatalf("comparison = %+v, ok = %t; want outcome %s, ok %t", o.Checks, o.ok(), tc.wantOutcome, tc.wantOK)
			}
		})
	}

	for _, tc := range []struct {
		name    string
		summary string
		wantOK  bool
	}{
		{"matching summary", "summary", true},
		{"mismatching summary", "different summary", false},
		{"omitted summary", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := TestOutcome{Name: "wording", Diagnosis: diag("ok")}
			o.compare(Expect{Summary: tc.summary}, time.Second)
			if o.ok() != tc.wantOK {
				t.Fatalf("ok = %t, want %t for expected %q and actual %q", o.ok(), tc.wantOK, tc.summary, o.Diagnosis.Summary)
			}
		})
	}
}

func TestWordingMismatchReportIsUsefulAndDeterministic(t *testing.T) {
	o := TestOutcome{Name: "wording", Node: "client", Diagnosis: &Diagnosis{Verdict: "dns", Summary: "actual summary",
		Checks: []DiagnosisCheck{{ID: "dns", Name: "DNS", Status: "FAIL", Detail: "lookup failed", Fix: "actual fix"}}}}
	o.compare(Expect{Summary: "expected summary", Checks: []ExpectedCheck{{
		ID: "dns", Status: "FAIL", Fix: "expected fix",
	}}}, time.Second)

	var first, second strings.Builder
	o.writeText(&first)
	o.writeText(&second)
	if first.String() != second.String() {
		t.Fatalf("failure report changed between writes:\nfirst: %q\nsecond: %q", first.String(), second.String())
	}
	for _, want := range []string{`expected: "expected summary"`, `actual:   "actual summary"`, "dns",
		`expected fix "expected fix", actual "actual fix"`} {
		if !strings.Contains(first.String(), want) {
			t.Errorf("failure report is missing %q:\n%s", want, first.String())
		}
	}
}

func TestCompareMissingRow(t *testing.T) {
	o := TestOutcome{Name: "t", Diagnosis: diag("ok", check("iface", "PASS"))}
	o.compare(Expect{Checks: []ExpectedCheck{{ID: "dns", Status: "FAIL"}}}, 4*time.Second)
	if o.Checks[0].Outcome != OutcomeMissing || o.FalseNegatives != 1 {
		t.Errorf("outcome=%q fn=%d", o.Checks[0].Outcome, o.FalseNegatives)
	}
}

func TestCompareWrongSeverity(t *testing.T) {
	// WARN where FAIL was expected is still a finding: the severity is what is
	// wrong, and the suggestion has to say so rather than cry "missed".
	o := TestOutcome{Name: "t", Diagnosis: diag("degraded", check("internet_tcp", "WARN"))}
	o.compare(Expect{Checks: []ExpectedCheck{{ID: "internet_tcp", Status: "FAIL"}}}, 4*time.Second)
	if o.FalseNegatives != 0 {
		t.Errorf("fn = %d, want 0: the finding was made, at the wrong level", o.FalseNegatives)
	}
	if !slices.Contains(suggestionCodes(&o), SuggestWrongSeverity) {
		t.Errorf("codes = %v", suggestionCodes(&o))
	}
}

func TestCompareTimeout(t *testing.T) {
	o := TestOutcome{Name: "t", Diagnosis: diag("dns", DiagnosisCheck{ID: "dns", Status: "FAIL", Ms: 4000, Fix: "f"})}
	o.compare(Expect{Verdict: "dns", Checks: []ExpectedCheck{{ID: "dns", Status: "FAIL"}}}, 4*time.Second)
	if len(o.TimedOut) != 1 {
		t.Fatalf("timed out = %v", o.TimedOut)
	}
	if !slices.Contains(suggestionCodes(&o), SuggestProbeTimedOut) {
		t.Errorf("codes = %v", suggestionCodes(&o))
	}
	// A timeout is evidence, not a mismatch: the expectation still held.
	if !o.ok() {
		t.Error("a timed-out probe that reported what was expected is still a match")
	}
}

func TestCompareMissingFixHint(t *testing.T) {
	o := TestOutcome{Name: "t", Diagnosis: diag("dns", DiagnosisCheck{ID: "dns", Status: "FAIL", Detail: "d"})}
	o.compare(Expect{Verdict: "dns", Checks: []ExpectedCheck{{ID: "dns", Status: "FAIL"}}}, 4*time.Second)
	if !slices.Contains(suggestionCodes(&o), SuggestNoFixHint) {
		t.Errorf("codes = %v", suggestionCodes(&o))
	}
}

func TestCompareUnstableVerdicts(t *testing.T) {
	o := TestOutcome{Name: "t", Diagnosis: diag("ok", check("dns", "PASS")),
		RepeatVerdicts: []string{"ok", "dns", "ok"}}
	o.compare(Expect{Verdict: "ok", Checks: []ExpectedCheck{{ID: "dns", Status: "PASS"}}}, 4*time.Second)
	if o.ok() {
		t.Error("a diagnosis that changed between identical runs is not a pass")
	}
	if !slices.Contains(suggestionCodes(&o), SuggestNondeterministic) {
		t.Errorf("codes = %v", suggestionCodes(&o))
	}
}

func TestCompareNoDiagnosis(t *testing.T) {
	o := TestOutcome{Name: "t", Error: "netdoc did not run"}
	o.compare(Expect{Verdict: "ok"}, 4*time.Second)
	if o.ok() {
		t.Error("want not ok")
	}
	if codes := suggestionCodes(&o); len(codes) != 1 || codes[0] != SuggestNoDiagnosis {
		t.Errorf("codes = %v", codes)
	}
}

func TestEmptyExpectedVerdictMatchesAnything(t *testing.T) {
	o := TestOutcome{Name: "t", Diagnosis: diag("service", check("tls", "FAIL"))}
	o.compare(Expect{Checks: []ExpectedCheck{{ID: "tls", Status: "FAIL"}}}, 4*time.Second)
	if !o.ok() {
		t.Error("a scenario that expects no particular verdict must not fail on the verdict")
	}
}

func suggestionCodes(o *TestOutcome) []string {
	var out []string
	for _, s := range o.suggest() {
		out = append(out, s.Code)
	}
	return out
}

func TestReportResult(t *testing.T) {
	pass := TestOutcome{Name: "a", Diagnosis: diag("ok", check("dns", "PASS"))}
	pass.compare(Expect{Verdict: "ok", Checks: []ExpectedCheck{{ID: "dns", Status: "PASS"}}}, time.Second)
	fail := TestOutcome{Name: "b", Diagnosis: diag("ok", check("dns", "PASS"))}
	fail.compare(Expect{Verdict: "dns", Checks: []ExpectedCheck{{ID: "dns", Status: "FAIL"}}}, time.Second)

	tests := []struct {
		name           string
		rep            Report
		want           string
		hasSuggestions bool
	}{
		{"all held", Report{Tests: []TestOutcome{pass}}, ResultPass, false},
		{"none held", Report{Tests: []TestOutcome{fail}}, ResultFail, true},
		{"some held", Report{Tests: []TestOutcome{pass, fail}}, ResultPartial, true},
		{"setup broke", Report{Error: "boom", Tests: []TestOutcome{pass}}, ResultError, false},
		{"nothing ran", Report{}, ResultError, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := tc.rep
			rep.finish()
			if rep.Result != tc.want {
				t.Errorf("result = %q, want %q", rep.Result, tc.want)
			}
			if got := len(rep.Suggestions) > 0; got != tc.hasSuggestions {
				t.Errorf("suggestions = %v", rep.Suggestions)
			}
		})
	}
}

func TestWriteTextSanitizesSubprocessText(t *testing.T) {
	// netdoc's detail lines carry text from the far end of the network, and
	// this report lands on a terminal.
	o := TestOutcome{Name: "t", Node: "client",
		Diagnosis: diag("ok", DiagnosisCheck{ID: "dns", Status: "PASS", Detail: "hi\x1b]52;c;cGF5bG9hZA==\x07there"})}
	o.compare(Expect{Verdict: "ok", Checks: []ExpectedCheck{{ID: "dns", Status: "PASS"}}}, time.Second)
	rep := Report{Scenario: "s", Tests: []TestOutcome{o}}
	rep.finish()
	var sb strings.Builder
	rep.WriteText(&sb)
	if strings.Contains(sb.String(), "\x1b") {
		t.Errorf("escape sequence survived into the report: %q", sb.String())
	}
}

// Every evidence family prints on its own, not only when some unrelated family
// happens to be non-empty: the scenarios that produce netem, per-query DNS and
// reset evidence have no routes, SOCKS requests or TLS handshakes at all.
func TestWriteTextPrintsEachEvidenceFamilyExactlyOnce(t *testing.T) {
	rep := Report{Scenario: "s", Evidence: Evidence{
		PacketConditions: []PacketConditionEvidence{{Node: "client", Segment: "lan", Active: true}},
		DNSQueries:       []DNSQueryEvidence{{Node: "resolver", QueryType: "A", Sequence: 1, Name: "a.test"}},
		TCPResets:        []TCPResetEvidence{{Node: "target", Event: "reset", Result: "connection_reset", Count: 1}},
	}}
	rep.finish()
	var sb strings.Builder
	rep.WriteText(&sb)
	for _, want := range []string{"NETEM", "DNSQ", "RESET"} {
		if n := strings.Count(sb.String(), "  "+want+" "); n != 1 {
			t.Errorf("%s printed %d times, want 1:\n%s", want, n, sb.String())
		}
	}
}

func TestWriteJSONIsValid(t *testing.T) {
	rep := Report{Scenario: "s", ID: "abc123", Backend: "linux-netns"}
	rep.finish()
	var sb strings.Builder
	if err := rep.WriteJSON(&sb); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"scenario": "s"`, `"result": "ERROR"`, `"id": "abc123"`,
		`"dns": []`, `"socks_requests": []`, `"tls": []`, `"links": []`, `"routes": []`, `"routers": []`,
		`"controlled_targets": []`, `"family_reachability": []`} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("json is missing %s:\n%s", want, sb.String())
		}
	}
}

func TestReportRendersStructuredRouteEvidence(t *testing.T) {
	reachable := true
	rep := Report{Scenario: "routed", ID: "abc123", Backend: "fake", Evidence: Evidence{
		Links:             []LinkEvidence{{Node: "client", Segment: "client-lan", Address: "10.77.1.10/24", Up: true}},
		Routes:            []RouteEvidence{{Node: "client", Destination: "10.77.2.20", Via: "10.77.1.1", Segment: "client-lan", Metric: 50, Selected: true, GatewayReachable: &reachable}},
		Routers:           []RouterEvidence{{Node: "gateway", IPv4Forwarding: true}},
		ControlledTargets: []ControlledTargetEvidence{{From: "client", To: "10.77.0.1:80", Via: []string{"client-lan", "gateway", "upstream"}, Reachable: true}},
	}}
	rep.finish()
	var text strings.Builder
	rep.WriteText(&text)
	for _, want := range []string{"LINK", "ROUTE", "ROUTER", "PATH", "client-lan", "IPv4 forwarding=true"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text missing %q:\n%s", want, text.String())
		}
	}
	var jsonText strings.Builder
	if err := rep.WriteJSON(&jsonText); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"segment": "client-lan"`, `"selected": true`, `"gateway_reachable": true`, `"ipv4_forwarding": true`} {
		if !strings.Contains(jsonText.String(), want) {
			t.Errorf("JSON missing %s:\n%s", want, jsonText.String())
		}
	}
}

func TestReportRendersStructuredTLSEvidence(t *testing.T) {
	now := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	rep := Report{
		Scenario: "tls", ID: "abc123", Backend: "fake",
		Evidence: Evidence{TLS: []TLSEvidence{{
			Node: "target", Service: "tls-target", CertificateMode: TLSCertificateExpired,
			RequestedServer: "secure-target.test", CertificateDNS: []string{"secure-target.test"},
			NotBefore: now.AddDate(-2, 0, 0), NotAfter: now.Add(-24 * time.Hour),
			CertificatePresented: true, Result: "client_rejected_certificate", Count: 1,
		}}},
	}
	rep.finish()
	var text strings.Builder
	rep.WriteText(&text)
	for _, want := range []string{"Structured evidence", "expired", "secure-target.test", "presented", "client_rejected_certificate"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text missing %q:\n%s", want, text.String())
		}
	}
	var jsonText strings.Builder
	if err := rep.WriteJSON(&jsonText); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"certificate_mode": "expired"`, `"certificate_presented": true`, `"certificate_dns": [`} {
		if !strings.Contains(jsonText.String(), want) {
			t.Errorf("JSON missing %s:\n%s", want, jsonText.String())
		}
	}
	if strings.Contains(jsonText.String(), "PRIVATE KEY") {
		t.Fatal("private key material appeared in the report")
	}
}

func TestReportRendersStructuredProxyEvidence(t *testing.T) {
	rep := Report{
		Scenario: "proxy", ID: "abc123", Backend: "fake",
		Evidence: Evidence{
			DNS:           []DNSEvidence{{Node: "proxy", Service: "private-dns", Source: "10.77.0.30", Name: "private.test", QueryType: "A", Result: "ANSWER", Count: 1}},
			SOCKSRequests: []SOCKSEvidence{{Node: "proxy", Service: "socks-proxy", Event: "connect", AddressType: "domain", Destination: "private.test", Port: 443, Result: "connected", Count: 1}},
		},
	}
	rep.finish()
	var text strings.Builder
	rep.WriteText(&text)
	for _, want := range []string{"Structured evidence", "10.77.0.30", "private.test", "domain", "connected"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text missing %q:\n%s", want, text.String())
		}
	}
	var jsonText strings.Builder
	if err := rep.WriteJSON(&jsonText); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"source": "10.77.0.30"`, `"address_type": "domain"`, `"result": "connected"`} {
		if !strings.Contains(jsonText.String(), want) {
			t.Errorf("JSON missing %s:\n%s", want, jsonText.String())
		}
	}
}

// A family netdoc never dialed carries no verdict. The simulator decodes that
// absence, so it has to re-encode it as absence too: writing "ipv6": "" into
// the run report would hand every downstream reader an empty verdict where
// netdoc deliberately published none, and "" is one careless comparison away
// from reading as a failed family.
func TestUntestedAddressFamilyStaysAbsentThroughTheSimulatorReport(t *testing.T) {
	netdocJSON, err := json.Marshal(report.Report{Verdict: "ok", Checks: []report.Check{{
		ID: "internet_tcp", Status: "PASS", Families: &report.Families{IPv4: "reachable"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := decodeDiagnosis(ExecResult{Stdout: netdocJSON})
	if err != nil {
		t.Fatal(err)
	}
	families := d.Checks[0].Families
	if families == nil || families.IPv4 != "reachable" || families.IPv6 != "" {
		t.Fatalf("decoded families = %+v, want IPv4 reachable and IPv6 untested", families)
	}
	blob, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(blob, []byte(`"address_families":{"ipv4":"reachable"}`)) || bytes.Contains(blob, []byte(`"ipv6"`)) {
		t.Errorf("re-encoded %s, want the untested family omitted the way netdoc omits it", blob)
	}
}

// The other half: absence must not become a free pass. A scenario that names a
// family is asserting netdoc produced that verdict, so a missing one is a
// mismatch, and the simulator only stays quiet about families it never claimed.
func TestCompareTreatsAddressFamiliesAsPresentOnlyWhenClaimed(t *testing.T) {
	families := func(v4, v6 string) DiagnosisCheck {
		c := check("internet_tcp", "PASS")
		c.Families = &DiagnosisFamilies{IPv4: v4, IPv6: v6}
		return c
	}
	for _, tc := range []struct {
		name        string
		actual      DiagnosisCheck
		expect      ExpectedCheck
		wantOutcome string
	}{
		{"dual stack matches both claims", families("reachable", "reachable"),
			ExpectedCheck{ID: "internet_tcp", Status: "PASS", IPv4: "reachable", IPv6: "reachable"}, OutcomeMatched},
		{"unclaimed families are not compared", families("reachable", ""),
			ExpectedCheck{ID: "internet_tcp", Status: "PASS"}, OutcomeMatched},
		{"an untested family still satisfies the claim it was not asked to make", families("reachable", ""),
			ExpectedCheck{ID: "internet_tcp", Status: "PASS", IPv4: "reachable"}, OutcomeMatched},
		{"a claimed family that never arrived is a mismatch", families("reachable", ""),
			ExpectedCheck{ID: "internet_tcp", Status: "PASS", IPv6: "reachable"}, OutcomeWrongFamily},
		// The bug this whole item exists to prevent: an untested family must
		// never satisfy an expectation of unreachable.
		{"an untested family is not an unreachable one", families("reachable", ""),
			ExpectedCheck{ID: "internet_tcp", Status: "PASS", IPv6: "unreachable"}, OutcomeWrongFamily},
		{"a genuinely dead family is still unreachable", families("reachable", "unreachable"),
			ExpectedCheck{ID: "internet_tcp", Status: "PASS", IPv6: "unreachable"}, OutcomeMatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := TestOutcome{Name: "t", Diagnosis: diag("ok", tc.actual)}
			o.compare(Expect{Verdict: "ok", Checks: []ExpectedCheck{tc.expect}}, 4*time.Second)
			if len(o.Checks) != 1 || o.Checks[0].Outcome != tc.wantOutcome {
				t.Fatalf("outcome = %+v, want %s", o.Checks, tc.wantOutcome)
			}
		})
	}
}

// TestCompareTimeoutClassification pins what puts a row in TimedOut. The
// probe's own elapsed clock starts inside the deadline it races and Ms
// truncates, so a genuine expiry routinely records just under the budget;
// classification has to rest on the cause netdoc recorded, not on that
// comparison.
func TestCompareTimeoutClassification(t *testing.T) {
	timeout := time.Second
	cases := []struct {
		name  string
		check DiagnosisCheck
		want  bool
	}{
		{"genuine timeout just under the budget", DiagnosisCheck{ID: "target_tcp", Status: "FAIL", Ms: 999,
			Attempts: []DiagnosisAttempt{{IP: "10.77.0.20", Ms: 998, Error: "dial tcp4 10.77.0.20:2222: i/o timeout",
				Cause: diagnostic.ConnectionCauseTimeout, Aborted: true}}}, true},
		{"probe row classified as a timeout", DiagnosisCheck{ID: "quic_udp_443", Status: "FAIL", Ms: 900,
			Cause: diagnostic.QUICCauseTimeout}, true},
		{"resolver timeout", DiagnosisCheck{ID: "dns", Status: "FAIL", Ms: 900,
			Cause: diagnostic.DNSCauseTimeout}, true},
		{"fast definite refusal", DiagnosisCheck{ID: "target_tcp", Status: "FAIL", Ms: 20,
			Cause: diagnostic.ConnectionCauseRefused,
			Attempts: []DiagnosisAttempt{{IP: "10.77.0.20", Ms: 20, Error: "connect: connection refused",
				Cause: diagnostic.ConnectionCauseRefused}}}, false},
		{"unreachable address", DiagnosisCheck{ID: "internet_tcp", Status: "FAIL", Ms: 12,
			Attempts: []DiagnosisAttempt{{IP: "10.77.0.20", Ms: 12, Error: "connect: network is unreachable",
				Cause: diagnostic.ConnectionCauseUnreachable}}}, false},
		{"cancellation is not a timeout", DiagnosisCheck{ID: "target_tcp", Status: "FAIL", Ms: 999,
			Attempts: []DiagnosisAttempt{{IP: "10.77.0.20", Ms: 998, Error: "operation was canceled",
				Cause: diagnostic.ConnectionCauseCanceled, Aborted: true}}}, false},
		{"a temporary resolver failure is an answer", DiagnosisCheck{ID: "dns", Status: "FAIL", Ms: 30,
			Cause: diagnostic.DNSCauseTemporaryFailure}, false},
		{"a TLS certificate rejection is an answer", DiagnosisCheck{ID: "tls", Status: "FAIL", Ms: 40,
			Cause: diagnostic.TLSCauseCertificateExpired}, false},
		{"a proxy protocol failure is an answer", DiagnosisCheck{ID: "proxy_connect", Status: "FAIL", Ms: 15,
			Cause: diagnostic.ProxyCauseProtocol}, false},
		// Reports captured before netdoc recorded causes carry nothing but the
		// elapsed time, so the original comparison stays as the fallback.
		{"legacy row with no cause at all", DiagnosisCheck{ID: "dns", Status: "FAIL", Ms: 1000}, true},
		{"legacy row that answered quickly", DiagnosisCheck{ID: "dns", Status: "FAIL", Ms: 30}, false},
		// Only a failure can be a timeout: a slow row that still answered spent
		// the budget getting somewhere.
		{"a passing row that waited", DiagnosisCheck{ID: "internet_tcp", Status: "PASS", Ms: 1200,
			Attempts: []DiagnosisAttempt{{IP: "10.77.0.20", Ms: 999, Cause: diagnostic.ConnectionCauseTimeout}}}, false},
		// One address answered and the other never did: the row was still paced
		// by the deadline the silent address ran out.
		{"one refused address and one silent one", DiagnosisCheck{ID: "target_tcp", Status: "FAIL", Ms: 999,
			Attempts: []DiagnosisAttempt{
				{IP: "10.77.0.20", Ms: 3, Cause: diagnostic.ConnectionCauseRefused},
				{IP: "fd00::20", Ms: 998, Cause: diagnostic.ConnectionCauseTimeout, Aborted: true}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := TestOutcome{Name: "t", Diagnosis: diag("v", tc.check)}
			o.compare(Expect{Checks: []ExpectedCheck{{ID: tc.check.ID, Status: tc.check.Status}}}, timeout)
			if got := slices.Contains(o.TimedOut, tc.check.ID); got != tc.want {
				t.Errorf("timed out = %v, want %v (TimedOut=%v)", got, tc.want, o.TimedOut)
			}
		})
	}
}
