package diagnostic

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// TestReplaySnapshotRoundTripSemantics is the replay-completeness proof: every
// arm of the diagnosis truth table, written to an artifact and read back,
// still reaches the same machine-readable conclusion. Running the whole matrix
// rather than a chosen sample is what makes a new diagnosis input that nobody
// remembered to persist fail here instead of in the field.
func TestReplaySnapshotRoundTripSemantics(t *testing.T) {
	cases := append(diagnosisMatrix(), []matrixCase{
		{
			name:  "family-neutral route cause on both stacks",
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: {Status: StatusPass},
				// failedRouteCause reports no family when the same fact held
				// for both, so an absent cause_family is a state to replay and
				// never a missing one to reject.
				ProbeInternet: {Status: StatusFail, Cause: RouteCauseNoDefaultRoute},
				ProbeDNS:      {Status: StatusFail},
			},
		},
		{
			name:  "offline with cause family and route evidence",
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: {Status: StatusPass, Routes: []RouteDecision{{
					Destination: net.ParseIP("1.1.1.1"), Family: counterfactualIPv4, Unreachable: true,
				}}},
				ProbeInternet: {Status: StatusFail, Cause: RouteCauseNoDefaultRoute, causeFamily: counterfactualIPv4},
				ProbeDNS:      {Status: StatusFail},
			},
		},
		{
			name:   "target failure routed through another routing domain",
			target: &Target{Raw: "example.invalid:443", Host: "example.invalid", Port: 443, Proto: ProtoNone, PortExplicit: true},
			order:  []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				// Same interface for both flows, so the difference the replay
				// has to reproduce is only in the fields an interface name
				// cannot carry: the next hop and the routing table.
				ProbeIface: {Status: StatusPass, Routes: []RouteDecision{{
					Destination: net.ParseIP("1.1.1.1"), Family: counterfactualIPv4, Iface: "eth0",
					Gateway: net.ParseIP("192.168.1.1"), Tunnel: TunnelDirect, TableKnown: true,
				}}},
				ProbeInternet: {Status: StatusPass},
				ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{net.ParseIP("198.51.100.7")}},
				ProbeTargetTCP: {Status: StatusFail, Routes: []RouteDecision{{
					Destination: net.ParseIP("198.51.100.7"), Family: counterfactualIPv4, Iface: "eth0",
					Gateway: net.ParseIP("10.0.0.1"), Tunnel: TunnelDirect,
					Table: "table 51820", TableKnown: true,
				}}},
			},
		},
		{
			name:   "target failure with split tunnel evidence",
			target: &Target{Raw: "example.invalid:443", Host: "example.invalid", Port: 443, Proto: ProtoNone, PortExplicit: true},
			order:  []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: {Status: StatusPass, Routes: []RouteDecision{{
					Destination: net.ParseIP("1.1.1.1"), Family: counterfactualIPv4, Iface: "eth0", Tunnel: TunnelDirect,
				}}},
				ProbeInternet: {Status: StatusPass},
				ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{net.ParseIP("198.51.100.7")}},
				ProbeTargetTCP: {Status: StatusFail, Routes: []RouteDecision{{
					Destination: net.ParseIP("198.51.100.7"), Family: counterfactualIPv4, Iface: "wg0", Tunnel: TunnelKnown,
				}}},
			},
		},
	}...)

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			probes := make([]Probe, len(test.order))
			for i, id := range test.order {
				probes[i] = Probe{ID: id, Name: string(id)}
			}
			want := Interpret(test.target, test.order, test.res)
			data, err := snapshot.Encode(BuildSnapshot(test.target, probes, test.res))
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := snapshot.Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReplaySnapshot(artifact)
			if err != nil {
				t.Fatal(err)
			}
			assertDiagnosisSemantics(t, got, want)
		})
	}
}

func TestResolverTargetsSurviveSnapshotReplay(t *testing.T) {
	targets := []string{"192.0.2.53:53", "[2001:db8::53]:53"}
	probes := []Probe{{ID: ProbeDNS, Name: "DNS"}}
	artifact := BuildSnapshot(nil, probes, map[ProbeID]ProbeResult{
		ProbeDNS: {Status: StatusPass, ResolverTargets: targets},
	})
	data, err := snapshot.Encode(artifact)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err = snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	result, err := replayResult(ProbeDNS, StatusPass, artifact.Checks[0])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.ResolverTargets, targets) {
		t.Errorf("resolver targets = %v, want %v", result.ResolverTargets, targets)
	}
}

func TestReplaySnapshotIgnoresHistoricalDiagnosisAndProse(t *testing.T) {
	artifact := snapshot.Snapshot{
		Schema: snapshot.Schema,
		Checks: []snapshot.Check{
			{ID: string(ProbeIface), Status: snapshot.StatusPass, Detail: "offline", Fix: "declare a DNS failure"},
			{ID: string(ProbeInternet), Status: snapshot.StatusPass},
			{ID: string(ProbeDNS), Status: snapshot.StatusPass},
		},
		Diagnosis: snapshot.Diagnosis{
			Verdict: VerdictService,
			Summary: "Historical output that must not be replayed.",
			Findings: []snapshot.Finding{{
				ID: string(DiagnosisOffline), Verdict: VerdictNetwork, Confidence: snapshot.ConfidenceHigh,
			}},
		},
	}
	got, err := ReplaySnapshot(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != VerdictOK || len(got.Findings) != 0 {
		t.Fatalf("replay used stored diagnosis or prose: %+v", got)
	}
}

// The stored confidence is the producing version's assessment, so replay has to
// recompute it from the observations like every other diagnostic field. That is
// the property future calibration work depends on: an artifact captured under
// one policy has to be re-judged under the policy being measured, not read back
// as its own answer.
func TestReplayRecomputesConfidenceRatherThanReadingIt(t *testing.T) {
	artifact := snapshot.Snapshot{
		Schema: snapshot.Schema,
		Checks: []snapshot.Check{
			{ID: string(ProbeIface), Status: snapshot.StatusPass},
			{ID: string(ProbeInternet), Status: snapshot.StatusFail},
			{ID: string(ProbeDNS), Status: snapshot.StatusFail},
		},
		Diagnosis: snapshot.Diagnosis{
			Verdict: VerdictNetwork,
			Summary: "Offline: neither direct egress nor DNS is working.",
			Findings: []snapshot.Finding{{
				ID: string(DiagnosisOffline), Verdict: VerdictNetwork, Focus: string(ProbeInternet),
				Confidence: snapshot.ConfidenceHigh,
			}},
		},
	}
	got, err := ReplaySnapshot(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || got.Findings[0].ID != DiagnosisOffline {
		t.Fatalf("replayed diagnosis = %+v", got)
	}
	if got.Findings[0].Confidence != ConfidenceMedium {
		t.Errorf("confidence = %q, want the recomputed %q rather than the stored high",
			got.Findings[0].Confidence, ConfidenceMedium)
	}
}

func TestReplaySnapshotRejectsUnfaithfulArtifacts(t *testing.T) {
	base := func() snapshot.Snapshot {
		return snapshot.Snapshot{Schema: snapshot.Schema, Checks: []snapshot.Check{{ID: string(ProbeIface), Status: snapshot.StatusPass}}}
	}
	tests := []struct {
		name string
		edit func(*snapshot.Snapshot)
		want string
	}{
		{"unsupported schema", func(s *snapshot.Snapshot) { s.Schema = "netdoc.snapshot.v2" }, "schema"},
		{"watch incident", func(s *snapshot.Snapshot) { s.Incident = &snapshot.Incident{} }, "ordinary snapshot"},
		{"unknown check", func(s *snapshot.Snapshot) { s.Checks[0].ID = "future_probe" }, "unsupported check"},
		{"duplicate incomplete check", func(s *snapshot.Snapshot) {
			s.Checks = []snapshot.Check{{ID: string(ProbeIface), Status: snapshot.StatusIncomplete}, {ID: string(ProbeIface), Status: snapshot.StatusIncomplete}}
		}, "repeats check"},
		{"unknown status", func(s *snapshot.Snapshot) { s.Checks[0].Status = "BROKEN" }, "unsupported status"},
		{"unknown protocol", func(s *snapshot.Snapshot) {
			s.Target = &snapshot.Target{Host: "example.invalid", Port: 443, Protocol: "gopher"}
		}, "protocol"},
		{"unknown cause family", func(s *snapshot.Snapshot) {
			s.Checks = []snapshot.Check{{
				ID: string(ProbeInternet), Status: snapshot.StatusFail,
				Cause: RouteCauseNoDefaultRoute, CauseFamily: "ipx",
			}}
		}, "unsupported cause family"},
		{"cause family with no cause", func(s *snapshot.Snapshot) {
			s.Checks[0].CauseFamily = counterfactualIPv4
		}, "without a cause"},
		{"unknown route tunnel state", func(s *snapshot.Snapshot) {
			s.Checks[0].Observed = &snapshot.Observed{Routes: []snapshot.Route{{Destination: "192.0.2.1", Tunnel: "maybe"}}}
		}, "unsupported route tunnel state"},
		{"downgrade on a non-WARN row", func(s *snapshot.Snapshot) {
			s.Checks[0].Derived = &snapshot.Derived{StatusDowngraded: true}
		}, "status downgrade"},
		{"human-only target attempt", func(s *snapshot.Snapshot) {
			s.Checks = []snapshot.Check{{ID: string(ProbeTargetTCP), Status: snapshot.StatusWarn, Observed: &snapshot.Observed{
				Attempts: []snapshot.Attempt{{IP: "192.0.2.1", Error: "connection refused"}},
			}}}
		}, "human error text"},
		{"clock offset overflow", func(s *snapshot.Snapshot) {
			ms := int64(^uint64(0) >> 1)
			s.Checks[0].Observed = &snapshot.Observed{ClockOffsetMs: &ms}
		}, "out of range"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact := base()
			test.edit(&artifact)
			if _, err := ReplaySnapshot(artifact); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ReplaySnapshot error = %v, want %q", err, test.want)
			}
		})
	}
}

func assertDiagnosisSemantics(t *testing.T, got, want Diagnosis) {
	t.Helper()
	if got.Verdict != want.Verdict || got.Blamed != want.Blamed || len(got.Findings) != len(want.Findings) {
		t.Fatalf("diagnosis verdict/blame/findings = %q/%q/%d, want %q/%q/%d",
			got.Verdict, got.Blamed, len(got.Findings), want.Verdict, want.Blamed, len(want.Findings))
	}
	for i := range want.Findings {
		gotFinding, wantFinding := got.Findings[i], want.Findings[i]
		if gotFinding.ID != wantFinding.ID || gotFinding.Verdict != wantFinding.Verdict || gotFinding.Focus != wantFinding.Focus ||
			gotFinding.Confidence != wantFinding.Confidence ||
			!reflect.DeepEqual(gotFinding.Evidence, wantFinding.Evidence) ||
			!reflect.DeepEqual(gotFinding.Counterfactual, wantFinding.Counterfactual) {
			t.Errorf("finding %d machine semantics =\n%+v\nwant\n%+v", i, gotFinding, wantFinding)
		}
	}
}

func TestReplayedAttemptErrorIsOnlyATypedFailureMarker(t *testing.T) {
	result, err := replayResult(ProbeTargetTCP, StatusWarn, snapshot.Check{Observed: &snapshot.Observed{
		Attempts: []snapshot.Attempt{{IP: "192.0.2.1", Error: "private prose", Cause: ConnectionCauseUnreachable}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attempts) != 1 || !errors.Is(result.Attempts[0].Err, errReplayedAttempt) || result.Attempts[0].Err.Error() == "private prose" {
		t.Fatalf("replayed attempt = %+v", result.Attempts)
	}
}

func TestReplayClockOffsetKeepsThresholdSemantics(t *testing.T) {
	ms := clockSkewThreshold.Milliseconds()
	result, err := replayResult(ProbeInternet, StatusPass, snapshot.Check{Observed: &snapshot.Observed{ClockOffsetMs: &ms}})
	if err != nil {
		t.Fatal(err)
	}
	if result.clockOffset != clockSkewThreshold {
		t.Fatalf("clock offset = %v, want %v", result.clockOffset, clockSkewThreshold)
	}
}

// A real field fixture is a --support artifact, so replay has to survive
// redaction as well as encoding. Pseudonymization preserves the class of every
// address (loopback, private, link-local, public) and the shape of every
// structured field, which is all the truth table reads, so the conclusion must
// come out the same. Only the address strings inside evidence change, and they
// change to exactly the addresses the sanitized artifact records.
//
// Counterfactual alternatives are compared by what they concluded rather than
// by value, because an address-valued alternative names the sanitized address
// on the replayed side, which is the artifact reporting what it actually
// holds. Whether a counterfactual exists at all, and what each alternative
// concluded, has to match. For the resolver comparison it does only because
// the run recorded that comparison's outcome: answersAgree reads the /16 an
// answer sits in, and pseudonymization does not preserve it in either
// direction, so recomputing it from a sanitized artifact is not the same
// question the run asked.
func TestReplayAfterSupportSanitizationKeepsTheConclusion(t *testing.T) {
	for _, test := range diagnosisMatrix() {
		t.Run(test.name, func(t *testing.T) {
			probes := make([]Probe, len(test.order))
			for i, id := range test.order {
				probes[i] = Probe{ID: id, Name: string(id)}
			}
			want := Interpret(test.target, test.order, test.res)
			data, err := snapshot.Encode(snapshot.SanitizeForSupport(BuildSnapshot(test.target, probes, test.res)))
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := snapshot.Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReplaySnapshot(artifact)
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != want.Verdict || got.Blamed != want.Blamed {
				t.Fatalf("sanitized replay = %q/%q, want %q/%q", got.Verdict, got.Blamed, want.Verdict, want.Blamed)
			}
			if len(got.Findings) != len(want.Findings) {
				t.Fatalf("sanitized replay has %d findings, want %d", len(got.Findings), len(want.Findings))
			}
			for i := range want.Findings {
				if got.Findings[i].ID != want.Findings[i].ID || got.Findings[i].Focus != want.Findings[i].Focus {
					t.Errorf("finding %d = %s@%s, want %s@%s", i,
						got.Findings[i].ID, got.Findings[i].Focus, want.Findings[i].ID, want.Findings[i].Focus)
				}
				if gotShape, wantShape := counterfactualShape(got.Findings[i]), counterfactualShape(want.Findings[i]); gotShape != wantShape {
					t.Errorf("finding %d counterfactual = %q, want %q", i, gotShape, wantShape)
				}
			}
		})
	}
}

// counterfactualShape reduces a finding's counterfactual to the parts a
// sanitized artifact has to reproduce exactly: whether there is one at all,
// the variable it compared, and what each alternative concluded. The
// alternative values are deliberately left out, since an address-valued one
// names the sanitized address after a round trip.
func counterfactualShape(f DiagnosisFinding) string {
	if f.Counterfactual == nil {
		return "none"
	}
	shape := string(f.Counterfactual.Variable)
	for _, alternative := range f.Counterfactual.Alternatives {
		shape += " " + string(alternative.Outcome)
	}
	return shape
}

// Replay reads an allowlist of probe IDs so an artifact from a future version
// is rejected rather than silently reinterpreted. That only stays honest while
// the list covers the graph this checkout builds.
func TestEveryProbeTheGraphBuildsIsReplayable(t *testing.T) {
	targets := []*Target{
		nil,
		{Host: "example.invalid", Port: 443, Proto: ProtoTLSHTTP},
		{Host: "example.invalid", Port: 80, Proto: ProtoHTTP},
		{Host: "example.invalid", Port: 22, Proto: ProtoSSH},
		{Host: "example.invalid", Port: 25, Proto: ProtoSMTP},
		{Host: "example.invalid", Port: 9100, Proto: ProtoNone},
	}
	for _, target := range targets {
		for _, p := range BuildProbesFromSources(target, nil, DefaultPublicDNS, true) {
			if !replayProbeID(p.ID) {
				t.Errorf("probe %q is in the graph but not replayable", p.ID)
			}
		}
	}
}

// The two tests below are the reason Derived carries an answer comparison at
// all. Support redaction pseudonymizes addresses without preserving the /16
// answersAgree compares, in both directions: it keeps a public resolver's own
// address verbatim while pseudonymizing its neighbours, and it collapses every
// other public address in one artifact into a single block. So recomputing the
// comparison from a sanitized artifact can invent a disagreement that never
// happened and erase one that did. The original run made the comparison from
// the addresses the resolvers actually returned, and that outcome is what the
// artifact has to carry.
//
// Neither test asserts anything about how the redactor maps a particular
// address. They assert only that the conclusion survives, which is what has to
// stay true when the redactor changes.

func TestReplayKeepsAnAgreementSanitizationWouldSplit(t *testing.T) {
	target := &Target{Raw: "dns.google:443", Host: "dns.google", Port: 443, Proto: ProtoTLSHTTP, PortExplicit: true}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic, ProbeTargetTCP, ProbeTLS, ProbeHTTPS}
	res := map[ProbeID]ProbeResult{
		ProbeIface:    {Status: StatusPass},
		ProbeInternet: {Status: StatusPass},
		// Both answers are records of the name being diagnosed and both sit in
		// 8.8.0.0/16, so the two resolvers agree and the run is healthy. One of
		// them is also the public resolver's own address, which is the field
		// support redaction keeps verbatim.
		ProbeDNS: {Status: StatusPass, Addrs: []net.IP{net.ParseIP("8.8.4.4")}},
		ProbeDNSPublic: {
			Status: StatusPass, Addrs: []net.IP{net.ParseIP("8.8.8.8")},
			resolver: "8.8.8.8", ResolverTargets: []string{"8.8.8.8:53"},
		},
		ProbeTargetTCP: {Status: StatusPass},
		ProbeTLS:       {Status: StatusPass},
		ProbeHTTPS:     {Status: StatusPass},
	}

	want, artifact := sanitizedReplayInput(t, target, order, res)
	if want.Verdict != VerdictOK || len(want.Findings) != 0 {
		t.Fatalf("live diagnosis = %q with %d findings, want a healthy run", want.Verdict, len(want.Findings))
	}
	if !sanitizedAnswersLookDifferent(t, artifact) {
		t.Fatal("the sanitized artifact still shares a comparison prefix, so it no longer proves anything")
	}
	got, err := ReplaySnapshot(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range got.Findings {
		if finding.ID == DiagnosisDNSDisagreement {
			t.Error("replay invented a DNS disagreement the run never found")
		}
	}
	assertDiagnosisSemantics(t, got, want)
}

func TestReplayKeepsADisagreementSanitizationWouldCollapse(t *testing.T) {
	target := &Target{Raw: "example.com:443", Host: "example.com", Port: 443, Proto: ProtoTLSHTTP, PortExplicit: true}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic, ProbeTargetTCP, ProbePMTU, ProbeTLS, ProbeHTTP, ProbeHTTPS}
	res := map[ProbeID]ProbeResult{
		ProbeIface:    {Status: StatusPass},
		ProbeInternet: {Status: StatusPass},
		// Two public answers in different allocations: a real disagreement.
		// Sanitization pseudonymizes both into one block, so an artifact-only
		// comparison reads them as agreeing.
		ProbeDNS: {Status: StatusPass, Addrs: []net.IP{net.ParseIP("203.0.113.9")}},
		ProbeDNSPublic: {
			Status: StatusPass, Addrs: []net.IP{net.ParseIP("198.51.100.20")},
			resolver: "9.9.9.9", ResolverTargets: []string{"9.9.9.9:53"},
		},
		// The target fails, so the headline is the target failure and the
		// disagreement survives only as the appended DNS counterfactual: the
		// finding this artifact could otherwise lose without changing verdict.
		ProbeTargetTCP: {Status: StatusFail},
		ProbePMTU:      {Status: StatusPass},
		ProbeTLS:       {Status: StatusSkip},
		ProbeHTTP:      {Status: StatusSkip},
		ProbeHTTPS:     {Status: StatusSkip},
	}

	want, artifact := sanitizedReplayInput(t, target, order, res)
	live, ok := findingByID(want, DiagnosisDNSDisagreement)
	if !ok || live.Counterfactual == nil {
		t.Fatalf("live diagnosis = %q with findings %v, want a DNS disagreement carrying a counterfactual",
			want.Verdict, findingIDs(want))
	}
	if sanitizedAnswersLookDifferent(t, artifact) {
		t.Fatal("the sanitized artifact still shows two comparison prefixes, so it no longer proves anything")
	}
	got, err := ReplaySnapshot(artifact)
	if err != nil {
		t.Fatal(err)
	}
	replayed, ok := findingByID(got, DiagnosisDNSDisagreement)
	if !ok {
		t.Fatalf("replay lost the DNS disagreement; findings = %v", findingIDs(got))
	}
	if !reflect.DeepEqual(replayed.Counterfactual, live.Counterfactual) {
		t.Errorf("replayed counterfactual =\n%+v\nwant\n%+v", replayed.Counterfactual, live.Counterfactual)
	}
	assertDiagnosisSemantics(t, got, want)
}

// sanitizedReplayInput runs one set of live results through the whole path a
// support artifact takes: reconciliation, interpretation, the snapshot, the
// sanitizer, and a real encode and decode. It returns the live diagnosis and
// the artifact replay has to reproduce it from.
func sanitizedReplayInput(t *testing.T, target *Target, order []ProbeID, res map[ProbeID]ProbeResult) (Diagnosis, snapshot.Snapshot) {
	t.Helper()
	probes := make([]Probe, len(order))
	for i, id := range order {
		probes[i] = Probe{ID: id, Name: string(id)}
	}
	Finalize(res)
	want := Interpret(target, order, res)
	data, err := snapshot.Encode(snapshot.SanitizeForSupport(BuildSnapshot(target, probes, res)))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return want, artifact
}

// sanitizedAnswersLookDifferent reports what answersAgree would conclude from
// the artifact's own addresses, which is the wrong answer both tests above are
// built to produce. It is a guard on the fixtures rather than an assertion
// about the redactor: if a change to pseudonymization stops rewriting these
// addresses the way each test needs, the test says so instead of passing for
// the wrong reason.
func sanitizedAnswersLookDifferent(t *testing.T, artifact snapshot.Snapshot) bool {
	t.Helper()
	answers := map[ProbeID][]net.IP{}
	for _, check := range artifact.Checks {
		if check.Observed == nil {
			continue
		}
		ips, err := replayIPs("address", check.Observed.Addresses)
		if err != nil {
			t.Fatal(err)
		}
		answers[ProbeID(check.ID)] = ips
	}
	system, public := answers[ProbeDNS], answers[ProbeDNSPublic]
	if len(system) == 0 || len(public) == 0 {
		t.Fatalf("the sanitized artifact kept no answers to compare: system %v, public %v", system, public)
	}
	return !answersAgree(system, public)
}

func findingIDs(d Diagnosis) []DiagnosisID {
	ids := make([]DiagnosisID, 0, len(d.Findings))
	for _, finding := range d.Findings {
		ids = append(ids, finding.ID)
	}
	return ids
}

// The recorded outcome is the authoritative one wherever it exists, so a
// refactor that quietly went back to reading the addresses fails here rather
// than only on a sanitized artifact, where the two disagree.
func TestRecordedAnswerComparisonOutranksTheAddresses(t *testing.T) {
	system := ProbeResult{Addrs: []net.IP{net.ParseIP("203.0.113.9")}}
	elsewhere := []net.IP{net.ParseIP("198.51.100.20")}
	sameBlock := []net.IP{net.ParseIP("203.0.113.10")}
	tests := []struct {
		name       string
		comparison answerComparison
		addrs      []net.IP
		want       bool
	}{
		{"agreement outranks addresses in different blocks", comparisonAgree, elsewhere, false},
		{"disagreement outranks addresses in one block", comparisonDisagree, sameBlock, true},
		{"nothing recorded falls back to the addresses", comparisonUnrecorded, elsewhere, true},
		{"nothing recorded agrees on one block", comparisonUnrecorded, sameBlock, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			independent := ProbeResult{Addrs: test.addrs, answerComparison: test.comparison}
			if got := dnsAnswersDisagree(system, independent); got != test.want {
				t.Fatalf("dnsAnswersDisagree = %v, want %v", got, test.want)
			}
		})
	}
}

// Replay refuses an artifact whose derived state no reasoning pass could have
// produced, rather than restoring it and reasoning from it anyway.
func TestReplayRejectsImpossibleAnswerComparisons(t *testing.T) {
	tests := []struct {
		name    string
		id      ProbeID
		status  Status
		value   snapshot.AnswerComparison
		answers []string
	}{
		// Answers are what a comparison is made of, so neither outcome can
		// have been reached on a row that recorded none.
		{"agreement without answers to compare", ProbeDNSPublic, StatusPass, snapshot.AnswerComparisonAgree, nil},
		{"disagreement without answers to compare", ProbeDNSPublic, StatusWarn, snapshot.AnswerComparisonDisagree, nil},
		// The comparison is defined for the independent DNS row alone, which
		// these rows are not, however well formed the rest of the row is.
		{"agreement on a row nothing compares", ProbeDNS, StatusPass, snapshot.AnswerComparisonAgree, []string{"198.51.100.20"}},
		{"disagreement on a row nothing compares", ProbeTargetTCP, StatusWarn, snapshot.AnswerComparisonDisagree, []string{"198.51.100.20"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			check := snapshot.Check{ID: string(test.id), Derived: &snapshot.Derived{AnswerComparison: test.value}}
			if len(test.answers) > 0 {
				check.Observed = &snapshot.Observed{Addresses: test.answers}
			}
			if _, err := replayResult(test.id, test.status, check); err == nil {
				t.Fatal("replayResult accepted an artifact no run could have written")
			}
		})
	}
}

// The one status pairing deliberately left open: agreement is what the current
// producer records on the PASS row it leaves alone, and a later reconciliation
// rule could warn that row for an unrelated reason without making a recorded
// agreement false.
func TestReplayAcceptsAgreementOnEitherStatus(t *testing.T) {
	for _, status := range []Status{StatusPass, StatusWarn} {
		check := snapshot.Check{
			ID:       string(ProbeDNSPublic),
			Derived:  &snapshot.Derived{AnswerComparison: snapshot.AnswerComparisonAgree},
			Observed: &snapshot.Observed{Addresses: []string{"198.51.100.20"}},
		}
		result, err := replayResult(ProbeDNSPublic, status, check)
		if err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if result.answerComparison != comparisonAgree {
			t.Fatalf("%s: comparison = %v, want agree", status, result.answerComparison)
		}
	}
}

// TestEveryReconciledDNSStateReplays is the producer/replay symmetry guard.
// reconcileDNS records the answer comparison before the switch under it picks
// which arm rewrites the row, so the two can drift: reordering an arm could
// leave a comparison serialized on a row replay then refuses, and the artifact
// this tool wrote would be one this tool cannot read. Sweeping the
// reconciliation inputs rather than sampling them is what makes that drift fail
// here instead of on a support capture nobody can open. It asserts only that
// the round trip is accepted and preserves the comparison, never what the
// diagnosis concluded from it.
func TestEveryReconciledDNSStateReplays(t *testing.T) {
	answers := []struct {
		name string
		ips  []net.IP
	}{
		{"no answers", nil},
		{"one allocation", []net.IP{net.ParseIP("203.0.113.9")}},
		{"another allocation", []net.IP{net.ParseIP("198.51.100.20")}},
	}
	var states []struct {
		name   string
		result ProbeResult
	}
	for _, status := range []Status{StatusPass, StatusWarn, StatusFail, StatusNA, StatusSkip} {
		for _, answer := range answers {
			for _, notFound := range []bool{false, true} {
				states = append(states, struct {
					name   string
					result ProbeResult
				}{
					fmt.Sprintf("%s/%s/notfound=%t", status, answer.name, notFound),
					ProbeResult{Status: status, Addrs: answer.ips, DNSNotFound: notFound, resolver: "9.9.9.9"},
				})
			}
		}
	}

	probes := []Probe{{ID: ProbeDNS, Name: "DNS"}, {ID: ProbeDNSPublic, Name: "Public DNS"}}
	for _, system := range states {
		for _, public := range states {
			res := map[ProbeID]ProbeResult{ProbeDNS: system.result, ProbeDNSPublic: public.result}
			Finalize(res)
			want := res[ProbeDNSPublic].answerComparison
			data, err := snapshot.Encode(BuildSnapshot(nil, probes, res))
			if err != nil {
				t.Fatalf("system %s, public %s: encode: %v", system.name, public.name, err)
			}
			artifact, err := snapshot.Decode(data)
			if err != nil {
				t.Fatalf("system %s, public %s: decode: %v", system.name, public.name, err)
			}
			if _, err := ReplaySnapshot(artifact); err != nil {
				t.Errorf("system %s, public %s: replay refused an artifact this producer wrote: %v",
					system.name, public.name, err)
				continue
			}
			stored := artifact.Checks[1]
			if stored.ID != string(ProbeDNSPublic) {
				t.Fatalf("snapshot check 1 = %q, want the independent DNS row", stored.ID)
			}
			status, err := replayStatus(stored.Status)
			if err != nil {
				t.Fatalf("system %s, public %s: %v", system.name, public.name, err)
			}
			got, err := replayResult(ProbeDNSPublic, status, stored)
			if err != nil {
				t.Fatalf("system %s, public %s: %v", system.name, public.name, err)
			}
			if got.answerComparison != want {
				t.Errorf("system %s, public %s: replayed comparison = %v, want the recorded %v",
					system.name, public.name, got.answerComparison, want)
			}
		}
	}
}
