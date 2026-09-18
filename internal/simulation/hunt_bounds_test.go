package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// netdocReportWithSummary is netdoc's own report JSON with a summary of the
// requested length: the shortest route to a simulation report whose size the
// model does not control, since nothing between a subprocess's stdout and a
// stored hunt case shortens what netdoc wrote there.
func netdocReportWithSummary(n int) string {
	return `{"checks":[{"id":"internet_tcp","status":"WARN","cause":"gateway_unreachable",` +
		`"detail":"d","address_families":{"IPv4":"unreachable","IPv6":"unavailable"}}],` +
		`"verdict":"network","summary":"` + strings.Repeat("x", n) + `"}`
}

// huntCaseWithPadding is one stored case carrying the given captured stderr,
// put there after the case was canonicalized. Stderr is one of the fields the
// canonical report drops, so what this builds is a case as a hand-written
// document may carry one rather than as a hunt produces one: derived fields
// that recompute exactly, and stored bytes the padding decides. That is the
// shape the ingestion ceilings exist to weigh.
func huntCaseWithPadding(t *testing.T, stderr string) HuntCaseResult {
	t.Helper()
	base := loadHuntBase(t, "healthy")
	generated, err := generateHuntCase(HuntGeneratorVersion, "healthy", base, 20260917, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	report := &Report{Scenario: "healthy", ID: "case-3", Backend: "fake", Result: ResultPass,
		Cleanup: CleanupInfo{Done: true},
		Tests:   []TestOutcome{{Name: "client", Node: "client", ProcessOutcome: ProcessExited}}}
	report.finish()
	item := canonicalHuntCaseResult(generated.Manifest, report)
	item.Report.Tests[0].Stderr = stderr
	return item
}

// huntCaseFillToCeiling is the stderr length that lands a stored case exactly
// on HuntMaxCaseResultBytes. It is measured rather than assumed, and measured
// against a case that already carries one byte of fill, because the field is
// omitempty and an absent key is not the same baseline as a present one. The
// fill encodes one byte per byte, so the remaining distance is the answer.
func huntCaseFillToCeiling(t *testing.T) int {
	t.Helper()
	one := huntEncodedElementSize(huntCaseWithPadding(t, "x"))
	if one > HuntMaxCaseResultBytes {
		t.Fatalf("a case with one byte of fill already measures %d bytes, over the %d byte ceiling",
			one, HuntMaxCaseResultBytes)
	}
	return HuntMaxCaseResultBytes - one + 1
}

// The three fills are text the corresponding clip has to cut, made of the character that costs six encoded bytes each, so what
// comes back sits on its ceiling exactly. A case built out of them is the
// largest one the ceilings allow rather than merely a large one.
func huntCanonicalFill() string {
	return huntCanonicalText(strings.Repeat("<", huntCanonicalTextBytes))
}

func huntCanonicalNameFill() string {
	return huntCanonicalName(strings.Repeat("<", huntCanonicalNameBytes))
}

func huntCanonicalHostFill() string {
	return huntCanonicalHost(strings.Repeat("<", huntCanonicalHostBytes))
}

// huntDistinctHostFill is the host fill with an index in its tail, at the same
// encoded ceiling. It exists for the one list canonicalization reduces: two DNS
// queries that agree on node, service, name, query type and outcome are one
// fact, so a saturated list of them has to differ somewhere, and the queried
// name is where.
func huntDistinctHostFill(i int) string {
	tail := fmt.Sprintf("%06d", i)
	return huntCanonicalHost(strings.Repeat("<", (huntCanonicalHostBytes-len(tail))/6)) + tail
}

// saturatedCanonicalHuntCase is the largest case result the hunt model allows:
// every list at the cardinality hunt_bounds.go declares for it, and every
// string at the ceiling its clip enforces. It is built rather than measured,
// which is the whole point. HuntMaxCaseResultBytes is what this weighs, so the
// ceiling follows from the model instead of from what runs have been seen to
// produce.
//
// Two assertions make it a maximum rather than a guess. Canonicalizing it
// returns it unchanged, so it is a case the projection could have produced;
// and checkHuntCaseCardinality accepts it while every list in it is exactly at
// its declared maximum, so no legal case can hold more rows of anything.
func saturatedCanonicalHuntCase(t *testing.T) HuntCaseResult {
	t.Helper()
	text, name, host := huntCanonicalFill(), huntCanonicalNameFill(), huntCanonicalHostFill()
	checks := make([]DiagnosisCheck, huntMaxDiagnosisChecks)
	for i := range checks {
		checks[i] = DiagnosisCheck{ID: name, Status: name, Cause: name, Detail: text,
			Families: &DiagnosisFamilies{IPv4: name, IPv6: name}}
	}
	diagnosisFindings := make([]DiagnosisFinding, huntMaxDiagnosisFindings)
	for i := range diagnosisFindings {
		diagnosisFindings[i] = DiagnosisFinding{ID: name}
	}
	report := &Report{Scenario: name, ID: name, Backend: name, Result: name, TimelineID: name,
		Error: text, Cleanup: CleanupInfo{Done: true}}
	report.Cleanup.Errors = saturateEncodedList(t, huntReportCleanupBytes, func(int) string { return text })
	for i := 0; i < huntMaxTopologyNodes; i++ {
		node := NodeInfo{Name: name, Role: name}
		for j := 0; j < huntMaxNodeInterfaces; j++ {
			node.Interfaces = append(node.Interfaces, InterfaceInfo{Segment: name, Address: name, IPv4: name, IPv6: name})
		}
		for j := 0; j < huntMaxNodeRoutes; j++ {
			node.Routes = append(node.Routes, RouteInfo{Destination: name, Via: name, Segment: name,
				Metric: math.MaxInt32, Family: name})
		}
		report.Topology = append(report.Topology, node)
	}
	for i := 0; i < huntMaxReportFaults; i++ {
		report.Faults = append(report.Faults, FaultInfo{Type: name})
	}
	for i := 0; i < huntMaxTimelineEvents; i++ {
		report.Timeline = append(report.Timeline, FaultEventEvidence{
			Event: TimedEvent{Offset: math.MaxInt64, Type: name, Node: name, Segment: name, Service: name,
				Latency: math.MaxInt64, Jitter: math.MaxInt64, LossPercent: 99.999, NetemSeed: math.MaxUint32,
				Outcome: name, Delay: math.MaxInt64, State: name},
			ScheduledOffset: math.MaxInt64, AppliedOffset: math.MaxInt64,
			Result: name, State: text, Error: text})
	}
	for i := 0; i < huntMaxCanonicalTests; i++ {
		report.Tests = append(report.Tests, TestOutcome{Name: text, Node: name, Target: host, SourceSegment: name,
			StartOffset: math.MaxInt64, EndOffset: math.MaxInt64, ProcessOutcome: name, Signal: name, Error: text,
			Diagnosis: &Diagnosis{Verdict: name, Checks: checks, Findings: diagnosisFindings}})
	}
	for i := 0; i < huntMaxReportSuggestions; i++ {
		report.Suggestions = append(report.Suggestions, Suggestion{Code: widestHuntSuggestionCode(t),
			Test: text, Probe: name, Cause: name, Message: text, Evidence: text})
	}
	report.Evidence = saturatedCanonicalHuntEvidence(text, name, host)

	item := HuntCaseResult{Manifest: saturatedHuntManifest(text, name), Status: "findings", Report: report,
		Truth: ObservedTruth{DNS: name, IPv4: name, IPv6: name, Gateway: name, Proxy: name, TLS: name,
			TCP: name, Link: name, Packet: name, Route: name},
		TruthFingerprint: strings.Repeat("f", 16)}
	for i := 0; i < huntMaxObservedFaults; i++ {
		item.Truth.ObservedFaults = append(item.Truth.ObservedFaults, name)
	}
	item.DiagnosisFingerprint = DiagnosisFingerprint{ID: strings.Repeat("f", 16)}
	for i := 0; i < huntMaxCanonicalTests; i++ {
		item.DiagnosisFingerprint.Verdicts = append(item.DiagnosisFingerprint.Verdicts, text)
	}
	for i := 0; i < huntMaxCanonicalTests*huntMaxDiagnosisChecks; i++ {
		item.DiagnosisFingerprint.Probes = append(item.DiagnosisFingerprint.Probes,
			ProbeFingerprint{Test: text, ID: name, Status: name, Cause: name, IPv4: name, IPv6: name})
	}
	for i := 0; i < huntMaxCaseFindings; i++ {
		item.Findings = append(item.Findings, HuntCaseFinding{Fingerprint: strings.Repeat("f", 16),
			Category: name, Severity: SeverityCritical, Code: name, SuggestionCode: name, Probe: name,
			Expected: name, Actual: name, Cause: name, Family: name, Summary: text, Evidence: text,
			Reproduce: reproductionFor(item.Manifest)})
	}

	if canonical := canonicalHuntReport(report); !reflect.DeepEqual(canonical, report) {
		t.Fatal("the saturated report is not one canonicalization could have produced")
	}
	if err := checkHuntCaseCardinality(&item); err != nil {
		t.Fatalf("the saturated case is over a model cardinality: %v", err)
	}
	return item
}

// widestHuntSuggestionCode is the longest code canonicalization keeps, so the
// saturated case pays the most a stored suggestion can cost.
func widestHuntSuggestionCode(t *testing.T) string {
	t.Helper()
	widest := ""
	for _, code := range []string{SuggestTransientNotResampled, SuggestTransientReportedPermanent,
		SuggestTransientMissed, SuggestTimelineInconsistent, SuggestNondeterministic,
		"jitter_sampling_gap", "alternate_route_available", "wrong_default_route_evidence",
		"gateway_unreachable"} {
		if _, _, ok := huntSuggestionClass(code); !ok {
			t.Fatalf("%q is no longer a code hunt analysis reads", code)
		}
		if len(code) > len(widest) {
			widest = code
		}
	}
	return widest
}

func saturatedCanonicalHuntEvidence(text, name, host string) Evidence {
	addresses := make([]string, huntMaxLookupAddresses)
	for i := range addresses {
		addresses[i] = name
	}
	certificateNames := make([]string, huntMaxCertificateNames)
	for i := range certificateNames {
		certificateNames[i] = host
	}
	via := make([]string, huntMaxViaHops)
	for i := range via {
		via[i] = name
	}
	reachable := true
	e := Evidence{}
	for i := 0; i < huntMaxResolverLookups; i++ {
		e.ResolverLookups = append(e.ResolverLookups, ResolverLookupEvidence{Node: name, Name: host,
			Resolver: name, State: name, Addresses: addresses, Stable: true})
	}
	for i := 0; i < huntMaxCanonicalDNSQueries; i++ {
		e.DNSQueries = append(e.DNSQueries, DNSQueryEvidence{Node: name, Service: name, Name: huntDistinctHostFill(i),
			QueryType: name, ActualOutcome: name, Offset: math.MaxInt64, OffsetKnown: true})
	}
	for i := 0; i < huntMaxSOCKSRequests; i++ {
		e.SOCKSRequests = append(e.SOCKSRequests, SOCKSEvidence{Node: name, Service: name, Event: name,
			Destination: host, Port: math.MaxInt32, Result: name, Count: math.MaxInt32})
	}
	for i := 0; i < huntMaxTLSHandshakes; i++ {
		e.TLS = append(e.TLS, TLSEvidence{Node: name, Service: name, CertificateMode: name,
			RequestedServer: host, CertificateDNS: certificateNames, CertificatePresented: true,
			Result: name, Count: math.MaxInt32})
	}
	for i := 0; i < huntMaxServiceReplies; i++ {
		e.ServiceReplies = append(e.ServiceReplies, ServiceReplyEvidence{Node: name, Service: name, Type: name,
			Port: math.MaxInt32, Status: math.MaxInt32, Result: name, Count: math.MaxInt32})
	}
	for i := 0; i < huntMaxTCPResets; i++ {
		e.TCPResets = append(e.TCPResets, TCPResetEvidence{Node: name, Service: name, Event: name,
			Result: name, Count: math.MaxInt32})
	}
	for i := 0; i < huntMaxPacketConditions; i++ {
		e.PacketConditions = append(e.PacketConditions, PacketConditionEvidence{Node: name, Segment: name,
			Latency: math.MaxInt64, Jitter: math.MaxInt64, LossPercent: 99.999, Seed: math.MaxUint32,
			Active: true, DroppedPackets: math.MaxUint32})
	}
	for i := 0; i < huntMaxPacketDrops; i++ {
		e.PacketDrops = append(e.PacketDrops, PacketDropEvidence{Node: name, Protocol: name,
			Port: math.MaxInt32, Direction: name, Packets: math.MaxUint32})
	}
	for i := 0; i < huntMaxLinks; i++ {
		e.Links = append(e.Links, LinkEvidence{Node: name, Segment: name, IPv4: name, IPv6: name,
			Up: true, MTU: math.MaxInt32})
	}
	for i := 0; i < huntMaxRouteEvidence; i++ {
		e.Routes = append(e.Routes, RouteEvidence{Node: name, Destination: name, Via: name, Segment: name,
			Metric: math.MaxInt32, Family: name, Selected: true, GatewayReachable: &reachable})
	}
	for i := 0; i < huntMaxRouteTables; i++ {
		table := RouteTableEvidence{Node: name, Family: name}
		for j := 0; j < huntMaxKernelRoutes; j++ {
			table.Routes = append(table.Routes, KernelRoute{Destination: name, Via: name, Segment: name,
				Metric: math.MaxInt32})
		}
		e.RouteTables = append(e.RouteTables, table)
	}
	for i := 0; i < huntMaxRouters; i++ {
		e.Routers = append(e.Routers, RouterEvidence{Node: name, IPv4Forwarding: true, IPv6Forwarding: true})
	}
	for i := 0; i < huntMaxControlledTargets; i++ {
		e.ControlledTargets = append(e.ControlledTargets, ControlledTargetEvidence{From: name, To: name,
			Family: name, Via: via, Reachable: true, Outcome: name})
	}
	for i := 0; i < huntMaxFamilyReachability; i++ {
		e.FamilyReachability = append(e.FamilyReachability, FamilyReachabilityEvidence{Node: name,
			Family: name, Via: via, State: name})
	}
	return e
}

// saturatedHuntManifest is the largest manifest the generator's own vocabulary
// allows: HuntMaxFaults mutations whose every string is a scenario name or an
// operator description. It is not clipped by canonicalization, because it is
// this package's own artifact rather than a subprocess's output, so
// TestTheGeneratorCannotOutgrowTheSaturatedManifest holds it against every
// manifest every base and lane actually produces.
func saturatedHuntManifest(text, name string) GeneratedCaseManifest {
	manifest := GeneratedCaseManifest{GeneratorVersion: name, Lane: HuntLane(name), BaseScenario: name,
		HuntSeed: math.MaxInt64, Case: HuntMaxCaseNumber, CaseSeed: math.MaxInt64, MaxFaults: HuntMaxFaults,
		CaseFingerprint: strings.Repeat("f", 16)}
	for i := 0; i < huntMaxCaseMutations; i++ {
		manifest.Mutations = append(manifest.Mutations, GeneratedMutation{ID: name, Description: text,
			Node: name, TargetNode: name, Segment: name, Service: name, Family: name,
			PreferredVia: name, PreferredSegment: name, PreferredMetric: math.MaxInt32,
			AlternateVia: name, AlternateSegment: name, AlternateMetric: math.MaxInt32,
			ControlTarget: name, TargetEndpoint: name, RouteDestination: name, RouteVia: name,
			LossPercent: 99.999, LatencyMS: math.MaxInt32, JitterMS: math.MaxInt32, StartMS: math.MaxInt32,
			DurationMS: math.MaxInt32, NetemSeed: math.MaxUint32, TargetPort: math.MaxInt32,
			Status: math.MaxInt32, MTU: math.MaxInt32})
	}
	return manifest
}

// TestHuntCaseCeilingIsTheSaturatedCanonicalCase is what HuntMaxCaseResultBytes
// means. It is not a round number with headroom and it is not a measurement of
// real cases: it is the encoded size of the case the model's own cardinality
// and text ceilings describe, so equality is the assertion. A change to any
// ceiling, any projected field or any row type moves this number, and the test
// says what to move it to.
func TestHuntCaseCeilingIsTheSaturatedCanonicalCase(t *testing.T) {
	size := huntEncodedElementSize(saturatedCanonicalHuntCase(t))
	if size != HuntMaxCaseResultBytes {
		t.Fatalf("the saturated canonical case measures %d bytes; set HuntMaxCaseResultBytes to that, not %d",
			size, HuntMaxCaseResultBytes)
	}
	t.Logf("HuntMaxCaseResultBytes = %d, campaign %d, result %d",
		HuntMaxCaseResultBytes, huntMaxCasesBytes, HuntMaxResultBytes)
}

// TestHuntModelCardinalityCoversTheHuntBases is the derivation behind the
// topology cardinalities. A hunt scenario is a library base with mutations
// applied, and no operator adds a node, an interface or a route, so the largest
// base is the largest hunt topology. This recomputes that from the library
// rather than trusting the numbers in the comment beside the constants.
func TestHuntModelCardinalityCoversTheHuntBases(t *testing.T) {
	nodes, interfaces, routes, tests, faults := 0, 0, 0, 0, 0
	for _, base := range HuntBaseNames() {
		scenario := loadHuntBase(t, base)
		validated := cloneScenario(scenario)
		canonicalScenarioInput(validated)
		if err := validated.Validate(); err != nil {
			t.Fatalf("%s: %v", base, err)
		}
		nodes = max(nodes, len(validated.Topology.Nodes))
		tests = max(tests, len(validated.Tests))
		faults = max(faults, len(validated.Faults))
		perNode := map[string]int{}
		for _, route := range validated.Topology.Routes {
			perNode[route.Node]++
		}
		for _, count := range perNode {
			routes = max(routes, count)
		}
		for _, node := range validated.Topology.Nodes {
			interfaces = max(interfaces, len(node.Interfaces))
		}
	}
	// timeline.dns_outage is the one operator that rewrites the test list, and
	// it replaces it with exactly three entries.
	tests = max(tests, 3)
	// Each of at most HuntMaxFaults mutations appends at most two faults.
	faults += 2 * HuntMaxFaults
	for _, c := range []struct {
		what     string
		model    int
		declared int
	}{
		{"topology nodes", nodes, huntMaxTopologyNodes},
		{"interfaces on one node", interfaces, huntMaxNodeInterfaces},
		{"routes on one node", routes, huntMaxNodeRoutes},
		{"tests", tests, huntMaxCanonicalTests},
		{"faults", faults, huntMaxReportFaults},
	} {
		if c.model > c.declared {
			t.Errorf("the hunt bases reach %d %s, over the declared maximum of %d", c.model, c.what, c.declared)
		}
	}
	t.Logf("hunt model: nodes=%d/%d interfaces=%d/%d routes=%d/%d tests=%d/%d faults=%d/%d",
		nodes, huntMaxTopologyNodes, interfaces, huntMaxNodeInterfaces, routes, huntMaxNodeRoutes,
		tests, huntMaxCanonicalTests, faults, huntMaxReportFaults)
}

// TestHuntDiagnosisCardinalityCoversTheProbeRegistry is the derivation behind
// the two diagnosis ceilings. netdoc emits one check row per probe it ran, so
// its stable probe graph is what bounds them; a finding is raised over those
// same rows. Growing the probe registry past these is a real event, and this is
// where it surfaces.
func TestHuntDiagnosisCardinalityCoversTheProbeRegistry(t *testing.T) {
	probes := len(diagnostic.StableProbes())
	if probes == 0 {
		t.Fatal("the probe registry is empty")
	}
	if probes > huntMaxDiagnosisChecks {
		t.Errorf("netdoc has %d stable probes, over huntMaxDiagnosisChecks %d", probes, huntMaxDiagnosisChecks)
	}
	if probes > huntMaxDiagnosisFindings {
		t.Errorf("netdoc has %d stable probes, over huntMaxDiagnosisFindings %d", probes, huntMaxDiagnosisFindings)
	}
	// Every producer analyzeHuntCase has, summed. A case that could carry more
	// findings than huntMaxCaseFindings would be one this program can write and
	// its own reader refuses.
	oracle := 2*len(conditionOracle) + 2
	if oracle > huntMaxOracleFindings {
		t.Errorf("the oracle can raise %d findings, over huntMaxOracleFindings %d", oracle, huntMaxOracleFindings)
	}
	producible := huntMaxTimelineEvents + 4*huntMaxCanonicalTests + huntMaxOracleFindings + 1 + huntMaxReportSuggestions
	if producible > huntMaxCaseFindings {
		t.Errorf("analyzeHuntCase can produce %d findings, over huntMaxCaseFindings %d",
			producible, huntMaxCaseFindings)
	}
	t.Logf("probes=%d/%d oracle findings=%d/%d case findings=%d/%d",
		probes, huntMaxDiagnosisChecks, oracle, huntMaxOracleFindings, producible, huntMaxCaseFindings)
}

// TestTheGeneratorCannotOutgrowTheSaturatedManifest holds the manifest half of
// the ceiling. A manifest is stored verbatim, so the saturated case has to
// cover the largest one the generator produces over every base and lane at the
// fault ceiling, and the observed truth derived alongside it.
func TestTheGeneratorCannotOutgrowTheSaturatedManifest(t *testing.T) {
	text, name := huntCanonicalFill(), huntCanonicalNameFill()
	saturated := len(mustMarshalIndent(t, saturatedHuntManifest(text, name)))
	worstManifest, worstTruth := 0, 0
	for _, base := range HuntBaseNames() {
		scenario := loadHuntBase(t, base)
		for _, lane := range []HuntLane{HuntLaneBugOracle, HuntLaneStress} {
			result := RunHunt(context.Background(), base, scenario, nil, HuntOptions{Cases: HuntMaxCases,
				Seed: 4242, MaxFaults: HuntMaxFaults, Lane: lane, DryRun: true})
			if result.Result == HuntResultError {
				t.Fatalf("generating %s on lane %s: %s", base, lane, result.Error)
			}
			for _, item := range result.Cases {
				worstManifest = max(worstManifest, len(mustMarshalIndent(t, item.Manifest)))
				truth := item.Truth
				// A dry run observes nothing, so fill the one list that grows.
				for _, mutation := range item.Manifest.Mutations {
					truth.ObservedFaults = append(truth.ObservedFaults, mutation.ID)
				}
				worstTruth = max(worstTruth, len(mustMarshalIndent(t, truth)))
			}
		}
	}
	if worstManifest > saturated {
		t.Errorf("the largest generated manifest is %d bytes, over the saturated %d", worstManifest, saturated)
	}
	saturatedTruth := ObservedTruth{DNS: name, IPv4: name, IPv6: name, Gateway: name, Proxy: name,
		TLS: name, TCP: name, Link: name, Packet: name, Route: name}
	for i := 0; i < huntMaxObservedFaults; i++ {
		saturatedTruth.ObservedFaults = append(saturatedTruth.ObservedFaults, name)
	}
	if size := len(mustMarshalIndent(t, saturatedTruth)); worstTruth > size {
		t.Errorf("the largest observed truth is %d bytes, over the saturated %d", worstTruth, size)
	}
	t.Logf("largest generated manifest %d/%d bytes, largest truth %d bytes", worstManifest, saturated, worstTruth)
}

// TestHuntCanonicalTextCountsJSONEscaping is why free text is bounded by what
// it costs encoded rather than by how many bytes it holds. Text made of
// characters the encoder expands sixfold is well inside any ceiling as a Go
// string and well outside it as JSON, and it is the JSON a merge has to
// allocate. Cutting on a rune boundary and cutting to a fixed point are both
// required: a merge canonicalizes text that is already canonical.
func TestHuntCanonicalTextCountsJSONEscaping(t *testing.T) {
	for _, text := range []string{
		strings.Repeat("<", 1<<10),
		strings.Repeat("é", 1<<10),
		strings.Repeat("\u0000", 1<<10),
		strings.Repeat("plain ", 1<<10),
	} {
		bounded := huntCanonicalText(text)
		blob, err := json.Marshal(bounded)
		if err != nil {
			t.Fatal(err)
		}
		if len(blob) > huntCanonicalTextBytes {
			t.Errorf("text encodes to %d bytes, over the %d byte ceiling", len(blob), huntCanonicalTextBytes)
		}
		if !utf8.ValidString(bounded) {
			t.Errorf("bounding cut a rune in half")
		}
		if again := huntCanonicalText(bounded); again != bounded {
			t.Errorf("bounding canonical text changed it again")
		}
	}
}

// TestReportSizeCannotChangeACaseSemantically is the property the old per-case
// ceiling did not have, and the regression it caused. Two runs differing only
// in material no hunt derivation reads, one of them past every size the old
// ceiling allowed, have to store the same semantics: the same status, the same
// truth and fingerprints, the same findings. Under the old design the larger
// one became a runtime_error whose only finding was simulation_run_failed, and
// the gap the case had rediscovered disappeared with it.
func TestReportSizeCannotChangeACaseSemantically(t *testing.T) {
	recorded := recordedHuntCase(t)
	small := canonicalHuntCaseResult(recorded.Manifest, recorded.Report)

	bloated := *recorded.Report
	bloated.Description = strings.Repeat("d", 1<<20)
	bloated.Tests = append([]TestOutcome(nil), recorded.Report.Tests...)
	bloated.Tests[0].Stderr = strings.Repeat("x", 4*HuntMaxCaseResultBytes)
	if size := huntEncodedElementSize(huntCaseResultFrom(recorded.Manifest, &bloated)); size <= HuntMaxCaseResultBytes {
		t.Fatalf("the bloated case measures %d bytes, which is not over the %d byte ceiling it has to cross",
			size, HuntMaxCaseResultBytes)
	}
	large := canonicalHuntCaseResult(recorded.Manifest, &bloated)

	if large.Status != small.Status {
		t.Fatalf("the bloated case stored status %q against %q", large.Status, small.Status)
	}
	if !hasFindingCode(large.Findings, SuggestTransientNotResampled) {
		t.Fatalf("the bloated case lost %s: %+v", SuggestTransientNotResampled, large.Findings)
	}
	if !reflect.DeepEqual(large.Findings, small.Findings) {
		t.Errorf("irrelevant report material changed the case findings")
	}
	if !reflect.DeepEqual(large.Truth, small.Truth) || large.TruthFingerprint != small.TruthFingerprint ||
		!reflect.DeepEqual(large.DiagnosisFingerprint, small.DiagnosisFingerprint) {
		t.Errorf("irrelevant report material changed the derived truth or fingerprints")
	}
	if size := huntEncodedElementSize(large); size > HuntMaxCaseResultBytes {
		t.Errorf("the bloated case stores %d bytes, over the %d byte ceiling", size, HuntMaxCaseResultBytes)
	}
}

// TestRunHuntCannotProduceAResultItCannotWrite is the write-side invariant. A
// hunt whose every case came back with a report far past every ceiling still
// writes, still keeps each case's findings, and still merges back to the same
// canonical cases. A budget failure here would be an internal contradiction
// rather than an outcome a legitimate hunt can reach, which is what
// canonicalization on every case buys.
func TestRunHuntCannotProduceAResultItCannotWrite(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	shard := HuntShard{Index: 0, Count: 1}
	result := RunHunt(context.Background(), "healthy", base, func() Backend {
		return &clientRoleBackend{env: &fakeEnv{
			stdout:   netdocReportWithSummary(4 * HuntMaxCaseResultBytes),
			evidence: deadRouteEvidence()}}
	}, HuntOptions{Cases: 3, Seed: 20260917, MaxFaults: 2, Shard: &shard})
	if len(result.Cases) != 3 {
		t.Fatalf("generated %d cases, want 3", len(result.Cases))
	}
	for _, item := range result.Cases {
		if item.Status == "runtime_error" {
			t.Fatalf("case %d became a runtime error because its report was large", item.Manifest.Case)
		}
		if size := huntEncodedElementSize(item); size > HuntMaxCaseResultBytes {
			t.Fatalf("case %d stores %d bytes, over the %d byte ceiling", item.Manifest.Case, size, HuntMaxCaseResultBytes)
		}
	}

	var buf bytes.Buffer
	if err := result.WriteJSON(&buf); err != nil {
		t.Fatalf("a hunt of oversized reports could not be written: %v", err)
	}
	if buf.Len() > HuntMaxResultBytes {
		t.Fatalf("the shard writes %d bytes, over HuntMaxResultBytes %d", buf.Len(), HuntMaxResultBytes)
	}
	decoded, err := DecodeHuntResult(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("decoding the shard it wrote: %v", err)
	}
	merged, err := MergeHuntResults(decoded)
	if err != nil {
		t.Fatalf("merging a shard of oversized reports: %v", err)
	}
	if err := ValidateMergedHuntResult(merged); err != nil {
		t.Fatalf("validating the merge of oversized reports: %v", err)
	}
}

// TestMergeRefusesACaseResultOverTheCeiling closes the one gap a hand-written
// shard could still walk through. canonicalHuntCaseResult bounds what it
// derives, so a shard can carry an oversized report next to derived fields that
// match the stand-in and satisfy every semantic check. The stored case is
// therefore weighed as well, and this builds exactly that shard: a case whose
// derived fields are the stand-in's and whose report is not.
func TestMergeRefusesACaseResultOverTheCeiling(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	shard := HuntShard{Index: 0, Count: 1}
	result := RunHunt(context.Background(), "healthy", base, func() Backend {
		return &clientRoleBackend{env: &fakeEnv{
			stdout:   netdocReportWithSummary(1 << 10),
			evidence: deadRouteEvidence()}}
	}, HuntOptions{Cases: 2, Seed: 20260917, MaxFaults: 2, Shard: &shard})
	if _, err := MergeHuntResults(result); err != nil {
		t.Fatalf("the unmodified shard does not merge: %v", err)
	}

	// Captured stderr is a field the canonical report drops, so growing it
	// leaves every derived field, and every recomputation of them, unchanged
	// while the stored case grows without limit.
	result.Cases[0].Report.Tests[0].Stderr = strings.Repeat("x", 2*HuntMaxCaseResultBytes)
	if size := huntEncodedElementSize(result.Cases[0]); size <= HuntMaxCaseResultBytes {
		t.Fatalf("the tampered case measures %d bytes, which is not over the %d byte ceiling",
			size, HuntMaxCaseResultBytes)
	}
	_, err := MergeHuntResults(result)
	if err == nil {
		t.Fatal("a shard carrying an oversized case result merged")
	}
	if !strings.Contains(err.Error(), "over the maximum of "+strconv.Itoa(HuntMaxCaseResultBytes)) {
		t.Fatalf("error = %q, want it to name the per-case maximum", err)
	}
}

// TestHuntAggregateSectionsAreBounded covers the two sections whose row count
// is a function of the cases rather than of a fixed vocabulary. Both are
// deterministically ordered projections of case findings, so bounding them
// costs a summary its tail and costs the artifact nothing, and the bounded list
// is what the deterministic merge validation recomputes.
func TestHuntAggregateSectionsAreBounded(t *testing.T) {
	summary := strings.Repeat("y", 8<<10)
	codes := []string{SuggestMissedFinding, SuggestWrongSeverity, SuggestWrongCause, SuggestFalsePositive,
		SuggestWrongVerdict, SuggestProbeTimedOut, SuggestNoFixHint, SuggestNondeterministic, SuggestNoDiagnosis}
	cases := make([]HuntCaseResult, 0, 512)
	for i := 0; i < 512; i++ {
		finding := HuntCaseFinding{Fingerprint: "fp" + strconv.Itoa(i), Category: FindingFalseNegative,
			Severity: SeverityHigh, Code: "code" + strconv.Itoa(i), SuggestionCode: codes[i%len(codes)],
			Summary: summary, Evidence: summary}
		cases = append(cases, HuntCaseResult{Manifest: GeneratedCaseManifest{Case: i}, Status: "findings",
			Findings: []HuntCaseFinding{finding}})
	}

	findings := aggregateHuntFindings(cases)
	if len(findings) == 0 || len(findings) >= len(cases) {
		t.Fatalf("kept %d of %d distinct findings, want a bounded prefix", len(findings), len(cases))
	}
	if size := len(mustMarshalIndent(t, findings)); size > huntMaxAggregateFindingsBytes {
		t.Errorf("the findings section measures %d bytes, over %d", size, huntMaxAggregateFindingsBytes)
	}
	suggestions := aggregateHuntSuggestions(findings)
	if size := len(mustMarshalIndent(t, suggestions)); size > huntMaxAggregateSuggestionsBytes {
		t.Errorf("the suggestions section measures %d bytes, over %d", size, huntMaxAggregateSuggestionsBytes)
	}

	// The same comparison validateHuntCases makes: a bounded section has to be
	// exactly what recomputing it from the cases produces, or a merge rejects
	// every hunt large enough to reach the ceiling.
	result := &HuntResult{GeneratorVersion: HuntGeneratorVersion, BaseScenario: "healthy",
		RequestedCases: len(cases), MaxFaults: 2, Cases: cases}
	result.finish()
	if !reflect.DeepEqual(result.Findings, aggregateHuntFindings(result.Cases)) {
		t.Error("the stored findings section is not what recomputing it produces")
	}
	if !reflect.DeepEqual(result.Suggestions, aggregateHuntSuggestions(result.Findings)) {
		t.Error("the stored suggestions section is not what recomputing it produces")
	}
}

// TestHuntRunSummaryFitsItsBudget holds huntMaxRunSummaryBytes against the
// largest run metadata and coverage model the vocabularies allow: every
// registry operator and every oracle condition for the base and lane, the fault
// cardinality filled to HuntMaxFaults, and an error string clipped from text
// that encodes six bytes to the character.
func TestHuntRunSummaryFitsItsBudget(t *testing.T) {
	worst := 0
	for _, name := range HuntBaseNames() {
		base := loadHuntBase(t, name)
		for _, lane := range []HuntLane{HuntLaneBugOracle, HuntLaneStress} {
			result := RunHunt(context.Background(), name, base, func() Backend {
				return &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport, evidence: deadRouteEvidence()}}
			}, HuntOptions{Cases: 24, Seed: 777, MaxFaults: HuntMaxFaults, Lane: lane})
			// The three weighed sections are budgeted separately, so what is
			// left is what this ceiling has to cover.
			result.Cases, result.Findings, result.Suggestions = []HuntCaseResult{}, []HuntFinding{}, []HuntSuggestion{}
			result.Error, result.ErrorKind = clip(strings.Repeat("<", 4<<10)), "runtime"
			for len(result.Coverage.Cardinality) < HuntMaxFaults {
				result.Coverage.Cardinality = append(result.Coverage.Cardinality, HuntMaxCases)
			}
			var buf bytes.Buffer
			if err := result.WriteJSON(&buf); err != nil {
				t.Fatal(err)
			}
			if buf.Len() > worst {
				worst = buf.Len()
			}
			if buf.Len() > huntMaxRunSummaryBytes {
				t.Errorf("%s %s writes a %d byte run summary, over huntMaxRunSummaryBytes %d",
					name, lane, buf.Len(), huntMaxRunSummaryBytes)
			}
		}
	}
	t.Logf("largest run summary: %d/%d bytes", worst, huntMaxRunSummaryBytes)
}

// TestMaximumBudgetedHuntResultFitsTheDeclaredMaximum is the byte accounting
// theorem the reader depends on: HuntMaxResultBytes is the sum of four enforced
// ceilings, so a result built with every one of them saturated still fits, and
// the four ceilings add up to the document the writer emits.
//
// What it builds is a budget object, not a hunt. Every section is filled to the
// limit its own producer enforces: HuntMaxCases copies of one synthetic case
// measuring exactly HuntMaxCaseResultBytes, and aggregate sections saturated on
// their own rather than derived from those cases. The whole legal count of
// maximum cases is what it builds because huntMaxCasesBytes is priced at that
// product, so the combination the writer has to accept is the one nothing else
// bounds. Duplicate case manifests alone make it something no hunt produces and
// no merge would accept.
// Semantic validity is proved elsewhere, by
// TestHuntMergeAcceptsTheLargestGeneratedShard on a real generated shard. What
// this proves is the arithmetic.
func TestMaximumBudgetedHuntResultFitsTheDeclaredMaximum(t *testing.T) {
	saturated := huntCaseWithPadding(t, strings.Repeat("x", huntCaseFillToCeiling(t)))
	if size := huntEncodedElementSize(saturated); size != HuntMaxCaseResultBytes {
		t.Fatalf("the saturated case measures %d bytes, want exactly %d", size, HuntMaxCaseResultBytes)
	}

	base := loadHuntBase(t, "healthy")
	result := RunHunt(context.Background(), "healthy", base, func() Backend {
		return &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport, evidence: deadRouteEvidence()}}
	}, HuntOptions{Cases: 8, Seed: 555, MaxFaults: HuntMaxFaults})
	result.Error, result.ErrorKind = clip(strings.Repeat("<", 4<<10)), "runtime"
	result.Cases = make([]HuntCaseResult, HuntMaxCases)
	for i := range result.Cases {
		result.Cases[i] = saturated
	}
	result.Findings = saturateEncodedList(t, huntMaxAggregateFindingsBytes, func(i int) HuntFinding {
		return HuntFinding{Fingerprint: "fp" + strconv.Itoa(i), Category: FindingFalseNegative,
			Severity: SeverityHigh, Code: "c", Summary: strings.Repeat("y", 4<<10), Evidence: strings.Repeat("z", 4<<10)}
	})
	result.Suggestions = saturateEncodedList(t, huntMaxAggregateSuggestionsBytes, func(i int) HuntSuggestion {
		return HuntSuggestion{Code: "s" + strconv.Itoa(i), Description: strings.Repeat("y", 8<<10),
			HighestSeverity: SeverityHigh, ExampleCases: []int{1, 2, 3}}
	})

	var buf bytes.Buffer
	if err := result.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > HuntMaxResultBytes {
		t.Fatalf("the maximum budgeted hunt result writes %d bytes, over HuntMaxResultBytes %d",
			buf.Len(), HuntMaxResultBytes)
	}
	// The formula and the writer have to agree, or the ceilings bound something
	// other than the document. Sections are weighed at the indentation writeJSON
	// gives them, and the summary is measured with every list present and empty,
	// so summing them reproduces the encoded length byte for byte: property
	// names, punctuation, indentation and the trailing newline included.
	summary, err := huntRunSummarySize(result)
	if err != nil {
		t.Fatal(err)
	}
	accounted := summary + huntEncodedListSize(result.Findings) +
		huntEncodedListSize(result.Suggestions) + huntEncodedListSize(result.Cases)
	if accounted != buf.Len() {
		t.Errorf("the budget accounts for %d bytes and writeJSON wrote %d", accounted, buf.Len())
	}
	// And the reader takes the largest document the writer can produce, which
	// is the other half of the same claim: the two ends of the budget agree on
	// what a legal maximum is.
	if _, err := DecodeHuntResult(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("the maximum budgeted hunt result was refused by its own reader: %v", err)
	}
	t.Logf("maximum budgeted hunt result: %d/%d bytes", buf.Len(), HuntMaxResultBytes)
}

// saturateEncodedList fills a section right up to the ceiling boundEncodedList
// enforces on it, so the whole-result accounting is tested against sections at
// their maximum rather than at their typical size.
func saturateEncodedList[T any](t *testing.T, max int, build func(int) T) []T {
	t.Helper()
	var out []T
	for i := 0; ; i++ {
		next := append(out, build(i))
		if len(boundEncodedList(next, max)) != len(next) {
			break
		}
		out = next
	}
	if len(out) == 0 {
		t.Fatalf("no element of this section fits its %d byte budget", max)
	}
	return out
}

func mustMarshalIndent(t *testing.T, v any) []byte {
	t.Helper()
	blob, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// huntSummaryAtSize builds a hunt result with no cases, findings or
// suggestions, whose run summary encodes to exactly total bytes. The padding
// goes into base_scenario, a field with no omitempty and no escaping in it, so
// one character of padding is one byte of document.
func huntSummaryAtSize(t *testing.T, total int) *HuntResult {
	t.Helper()
	result := &HuntResult{GeneratorVersion: HuntGeneratorVersion, RequestedCases: 1, MaxFaults: 1,
		Findings: []HuntFinding{}, Suggestions: []HuntSuggestion{}, Cases: []HuntCaseResult{}}
	empty, err := huntRunSummarySize(result)
	if err != nil {
		t.Fatal(err)
	}
	if empty > total {
		t.Fatalf("an empty run summary already measures %d bytes, over the %d asked for", empty, total)
	}
	result.BaseScenario = strings.Repeat("x", total-empty)
	if size, err := huntRunSummarySize(result); err != nil || size != total {
		t.Fatalf("the padded run summary measures %d bytes (err %v), want exactly %d", size, err, total)
	}
	return result
}

// TestHuntRunSummaryBudgetIsEnforcedAtWrite pins huntMaxRunSummaryBytes as a
// production limit rather than a measurement. At the ceiling the result writes,
// and what it writes is the size the accounting predicted; one byte over, the
// write is refused and nothing reaches the writer.
func TestHuntRunSummaryBudgetIsEnforcedAtWrite(t *testing.T) {
	var buf bytes.Buffer
	if err := huntSummaryAtSize(t, huntMaxRunSummaryBytes).WriteJSON(&buf); err != nil {
		t.Fatalf("a run summary at its exact ceiling was refused: %v", err)
	}
	if buf.Len() != huntMaxRunSummaryBytes {
		t.Errorf("the run summary wrote %d bytes, want the %d the accounting measured",
			buf.Len(), huntMaxRunSummaryBytes)
	}

	buf.Reset()
	err := huntSummaryAtSize(t, huntMaxRunSummaryBytes+1).WriteJSON(&buf)
	if err == nil {
		t.Fatal("a run summary one byte over its ceiling was written")
	}
	want := fmt.Sprintf("hunt run summary is %d bytes, over the maximum of %d",
		huntMaxRunSummaryBytes+1, huntMaxRunSummaryBytes)
	if err.Error() != want {
		t.Errorf("refusal says %q, want %q", err.Error(), want)
	}
	if buf.Len() != 0 {
		t.Errorf("the refused result still wrote %d bytes", buf.Len())
	}
}

// TestAnOutgrownCoverageModelCannotBeWritten is the mistake the ceiling exists
// to catch: a future registry with far more operators than today's grows the
// coverage model past the run summary budget. Production refuses the artifact
// instead of writing one its own merge command would reject for its size, so
// the failure lands on the developer who grew the registry and does not depend
// on anyone rerunning the budget test.
func TestAnOutgrownCoverageModelCannotBeWritten(t *testing.T) {
	result := &HuntResult{GeneratorVersion: HuntGeneratorVersion, BaseScenario: "healthy",
		RequestedCases: 1, MaxFaults: 1,
		Findings: []HuntFinding{}, Suggestions: []HuntSuggestion{}, Cases: []HuntCaseResult{}}
	for i := 0; ; i++ {
		result.Coverage.Operators = append(result.Coverage.Operators, HuntOperatorCoverage{
			ID: fmt.Sprintf("operator-%04d", i), Contract: "oracle", Applicable: true})
		size, err := huntRunSummarySize(result)
		if err != nil {
			t.Fatal(err)
		}
		if size > huntMaxRunSummaryBytes {
			break
		}
	}
	var buf bytes.Buffer
	if err := result.WriteJSON(&buf); err == nil {
		t.Fatalf("a %d operator coverage model wrote %d bytes instead of being refused",
			len(result.Coverage.Operators), buf.Len())
	} else if !strings.Contains(err.Error(), "hunt run summary is") {
		t.Errorf("refusal says %q, want the run summary budget", err.Error())
	}
	t.Logf("refused at %d coverage operators", len(result.Coverage.Operators))
}

// ceilingThatDiscardedARealCase is the per-case ceiling under which a real
// namespace-backed hunt case stopped fitting, so its report was replaced by the
// stand-in and every finding derived from it was lost. The recorded case below
// is only evidence while it is still larger than this.
const ceilingThatDiscardedARealCase = 64 << 10

// recordedHuntCase loads a hunt case result captured from a namespace-backed
// run. A recording rather than a constructed report because the size that
// matters here is the size real evidence reaches: the case that exposed this
// crossed the ceiling on its DNS query evidence and its three per-test
// diagnoses together, not on any one field a test could pad, and a synthetic
// case padded through one string proves nothing about either.
func recordedHuntCase(t *testing.T) HuntCaseResult {
	t.Helper()
	// recordedHuntCasePath is a constant so reading it needs no gosec
	// exemption.
	const recordedHuntCasePath = "testdata/hunt/case-116-transient-dns-outage.json"
	blob, err := os.ReadFile(recordedHuntCasePath)
	if err != nil {
		t.Fatal(err)
	}
	var item HuntCaseResult
	if err := json.Unmarshal(blob, &item); err != nil {
		t.Fatalf("decoding %s: %v", recordedHuntCasePath, err)
	}
	return item
}

// TestALargeRealHuntCaseKeepsTheFindingItRediscovered is the property the
// per-case ceiling exists alongside rather than above. Bounding what a hunt
// stores is worth doing, and it is not worth a finding: a legitimate case big
// enough to reach the size boundary has to arrive at the same findings and the
// same aggregate suggestion it would have reached unbounded, has to agree with
// what a merge recomputes from what was stored, and has to stay inside the
// budget the reader enforces.
//
// The recorded case is generated case 116 of the healthy-routed-network
// bug-oracle hunt, whose resolver recovers mid-run. Rediscovering
// SuggestTransientNotResampled there is what
// TestGeneratedHuntCasesAreReproducible asks a real namespace backend for, and
// this asks the same question of the stored form alone, with no backend.
func TestALargeRealHuntCaseKeepsTheFindingItRediscovered(t *testing.T) {
	recorded := recordedHuntCase(t)
	if recorded.Report == nil {
		t.Fatal("the recorded case carries no simulation report")
	}
	if size := huntEncodedElementSize(recorded); size <= ceilingThatDiscardedARealCase {
		t.Fatalf("the recorded case measures %d bytes and no longer reaches the %d byte ceiling that discarded it",
			size, ceilingThatDiscardedARealCase)
	}

	// What the case is worth before anything bounds it.
	unbounded := huntCaseResultFrom(recorded.Manifest, recorded.Report)
	if !hasFindingCode(unbounded.Findings, SuggestTransientNotResampled) {
		t.Fatalf("the recorded case does not carry %s unbounded: %+v",
			SuggestTransientNotResampled, unbounded.Findings)
	}

	// What canonical storage keeps of it.
	stored := canonicalHuntCaseResult(recorded.Manifest, recorded.Report)
	if size := huntEncodedElementSize(stored); size > HuntMaxCaseResultBytes {
		t.Fatalf("the stored case measures %d bytes, over the %d byte ceiling", size, HuntMaxCaseResultBytes)
	}
	if stored.Status != unbounded.Status {
		t.Errorf("the stored case status is %q, want %q", stored.Status, unbounded.Status)
	}
	if !reflect.DeepEqual(stored.Findings, unbounded.Findings) {
		t.Fatalf("bounded storage changed the case findings:\nstored:   %+v\nunbounded: %+v",
			stored.Findings, unbounded.Findings)
	}
	if !reflect.DeepEqual(stored.Truth, unbounded.Truth) || stored.TruthFingerprint != unbounded.TruthFingerprint ||
		!reflect.DeepEqual(stored.DiagnosisFingerprint, unbounded.DiagnosisFingerprint) {
		t.Errorf("bounded storage changed the derived truth or fingerprints")
	}

	// What the run summary says about it, which is what the namespace test
	// reads and what this regression took away.
	suggestions := aggregateHuntSuggestions(aggregateHuntFindings([]HuntCaseResult{stored}))
	if !slices.ContainsFunc(suggestions, func(s HuntSuggestion) bool { return s.Code == SuggestTransientNotResampled }) {
		t.Fatalf("aggregate suggestions lost %s: %+v", SuggestTransientNotResampled, suggestions)
	}

	// What a merge recomputes from what was stored, which is the equality
	// MergeHuntResults validates every case against.
	if recomputed := canonicalHuntCaseResult(stored.Manifest, stored.Report); !reflect.DeepEqual(recomputed, stored) {
		t.Errorf("a merge recomputes a different case from the stored manifest and report")
	}
}

func hasFindingCode(findings []HuntCaseFinding, code string) bool {
	return slices.ContainsFunc(findings, func(f HuntCaseFinding) bool { return f.Code == code })
}
