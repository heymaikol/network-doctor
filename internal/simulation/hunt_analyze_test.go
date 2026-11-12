package simulation

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

func huntManifest(mutations ...GeneratedMutation) GeneratedCaseManifest {
	manifest := GeneratedCaseManifest{GeneratorVersion: HuntGeneratorVersion, Lane: HuntLaneBugOracle, BaseScenario: "healthy-routed-network",
		HuntSeed: 12345, Case: 17, CaseSeed: -99, Mutations: mutations}
	manifest.CaseFingerprint = huntCaseFingerprint(manifest)
	return manifest
}

func TestObservedTruthUsesServiceAndKernelEvidence(t *testing.T) {
	manifest := huntManifest(
		GeneratedMutation{ID: "dns.drop", Service: "r"},
		GeneratedMutation{ID: "netem.loss", Node: "gateway", Segment: "upstream", LossPercent: 20},
	)
	report := &Report{
		Faults:   []FaultInfo{{Type: FaultNetem, Node: "gateway", LossPercent: 20}},
		Timeline: []FaultEventEvidence{{Event: TimedEvent{Type: FaultScheduledDNS, Service: "r", Outcome: DNSOutcomeDrop}, Result: EventApplied}},
		Evidence: Evidence{
			DNSQueries: []DNSQueryEvidence{{Node: "resolver", Service: "r", ActualOutcome: dnsServedDropped},
				{Node: "resolver", Service: "r", ActualOutcome: "ANSWER"}},
			PacketConditions: []PacketConditionEvidence{{Node: "gateway", Segment: "upstream", Active: true,
				LossPercent: 20, DroppedPackets: 7}},
			Routes: []RouteEvidence{{Selected: true, GatewayReachable: boolPointer(true)}},
			Links:  []LinkEvidence{{Up: true}},
		},
	}
	truth := collectObservedTruth(manifest, report)
	if truth.DNS != "mixed" || truth.Packet != "drops_observed" || truth.Gateway != "reachable" || truth.Link != "up" {
		t.Fatalf("truth = %+v", truth)
	}
	if !reflect.DeepEqual(truth.ObservedFaults, []string{"dns.drop", "netem.loss"}) {
		t.Errorf("observed faults = %v", truth.ObservedFaults)
	}
}

func boolPointer(value bool) *bool { return &value }

// familyTruthReport builds the measured record the holder would have written.
// An empty state means the measurement was never taken, which is a different
// report from one that recorded the family as unavailable.
func familyTruthReport(ipv4, ipv6 string) *Report {
	return withObservedFamilies(&Report{}, ipv4, ipv6)
}

// withObservedFamilies attaches the holder-side measurements to a report that
// already describes a finished run, so two otherwise identical cases can differ
// by nothing except what the simulator observed.
func withObservedFamilies(report *Report, ipv4, ipv6 string) *Report {
	report.Topology = append(report.Topology, NodeInfo{Name: "client", Role: "client"})
	for _, item := range []FamilyReachabilityEvidence{
		{Node: "client", Family: "ipv4", State: ipv4},
		{Node: "client", Family: "ipv6", State: ipv6},
	} {
		if item.State != "" {
			report.Evidence.FamilyReachability = append(report.Evidence.FamilyReachability, item)
		}
	}
	return report
}

func TestObservedTruthUsesIndependentFamilyReachability(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ipv4, ipv6 string
		want4      string
		want6      string
	}{
		{"dual stack reachable", FamilyStateReachable, FamilyStateReachable, "reachable", "reachable"},
		{"IPv4 broken", FamilyStateUnreachable, FamilyStateReachable, "unreachable", "reachable"},
		{"IPv6 broken", FamilyStateReachable, FamilyStateUnreachable, "reachable", "unreachable"},
		{"IPv4 only", FamilyStateReachable, FamilyStateUnavailable, "reachable", "unavailable"},
		{"IPv6 only", FamilyStateUnavailable, FamilyStateReachable, "unavailable", "reachable"},
		// An absent record is an absent measurement. Reading it as "unavailable"
		// would let a probe that silently never ran look like a family the
		// topology never had.
		{"IPv6 never measured", FamilyStateReachable, "", "reachable", "unknown"},
		{"nothing measured", "", "", "unknown", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			truth := collectObservedTruth(huntManifest(), familyTruthReport(tc.ipv4, tc.ipv6))
			if truth.IPv4 != tc.want4 || truth.IPv6 != tc.want6 {
				t.Fatalf("family truth = IPv4 %q, IPv6 %q; want %q, %q", truth.IPv4, truth.IPv6, tc.want4, tc.want6)
			}
		})
	}
	report := familyTruthReport(FamilyStateReachable, FamilyStateUnavailable)
	report.Topology = append(report.Topology, NodeInfo{Name: "router", Role: "router"})
	report.Evidence.FamilyReachability = append(report.Evidence.FamilyReachability,
		FamilyReachabilityEvidence{Node: "router", Family: "ipv4", State: FamilyStateUnreachable})
	report.Evidence.ControlledTargets = append(report.Evidence.ControlledTargets,
		ControlledTargetEvidence{From: "client", To: "10.77.0.1:443", Reachable: false})
	if got := collectObservedTruth(huntManifest(), report).IPv4; got != "reachable" {
		t.Fatalf("non-family observation changed client IPv4 truth to %q", got)
	}
}

func TestObservedTruthRejectsAmbiguousFamilyEvidence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		observation FamilyReachabilityEvidence
	}{
		{"duplicate", FamilyReachabilityEvidence{Node: "client", Family: "ipv4", State: FamilyStateReachable}},
		{"conflicting duplicate", FamilyReachabilityEvidence{Node: "client", Family: "ipv4", State: FamilyStateUnreachable}},
		{"unknown state", FamilyReachabilityEvidence{Node: "client", Family: "ipv4", State: "probably"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := familyTruthReport(FamilyStateReachable, FamilyStateUnavailable)
			report.Evidence.FamilyReachability = append(report.Evidence.FamilyReachability, tc.observation)
			if got := collectObservedTruth(huntManifest(), report).IPv4; got != "unknown" {
				t.Fatalf("ambiguous IPv4 truth = %q, want unknown", got)
			}
		})
	}
}

func TestObservedTruthFamilyReachabilityIgnoresDiagnosis(t *testing.T) {
	a := familyTruthReport(FamilyStateUnreachable, FamilyStateReachable)
	b := familyTruthReport(FamilyStateUnreachable, FamilyStateReachable)
	a.Tests = []TestOutcome{{Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "internet_tcp", Families: &DiagnosisFamilies{IPv4: "reachable", IPv6: "unreachable"}}}}}}
	b.Tests = []TestOutcome{{Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "internet_tcp", Families: &DiagnosisFamilies{IPv4: "unreachable", IPv6: "reachable"}}}}}}
	if gotA, gotB := collectObservedTruth(huntManifest(), a), collectObservedTruth(huntManifest(), b); !reflect.DeepEqual(gotA, gotB) {
		t.Fatalf("diagnosis changed family truth:\n%+v\n%+v", gotA, gotB)
	}
}

func TestMutationObservedUsesIndependentFamilyTruth(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutation string
		ipv4     string
		ipv6     string
		want     bool
	}{
		{"IPv4 drop observed", "family.ipv4_drop", "unreachable", "reachable", true},
		{"IPv4 remains reachable", "family.ipv4_drop", "reachable", "reachable", false},
		{"IPv4 unavailable", "family.ipv4_drop", "unavailable", "reachable", false},
		{"IPv4 unknown", "family.ipv4_drop", "unknown", "reachable", false},
		{"IPv4 wrong family", "family.ipv4_drop", "reachable", "unreachable", false},
		{"IPv6 drop observed", "family.ipv6_drop", "reachable", "unreachable", true},
		{"IPv6 remains reachable", "family.ipv6_drop", "reachable", "reachable", false},
		{"IPv6 unavailable", "family.ipv6_drop", "reachable", "unavailable", false},
		{"IPv6 unknown", "family.ipv6_drop", "reachable", "unknown", false},
		{"IPv6 wrong family", "family.ipv6_drop", "unreachable", "reachable", false},
		{"unrelated mutation", "quic.udp_443_block", "reachable", "unreachable", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			truth := ObservedTruth{IPv4: tc.ipv4, IPv6: tc.ipv6}
			if got := mutationObserved(GeneratedMutation{ID: tc.mutation}, &Report{}, truth); got != tc.want {
				t.Fatalf("mutationObserved(%q, IPv4=%q, IPv6=%q) = %t, want %t", tc.mutation, tc.ipv4, tc.ipv6, got, tc.want)
			}
		})
	}
}

func TestMutationObservedUsesIndependentProtocolServiceEvidence(t *testing.T) {
	socksRequest := func(item SOCKSEvidence) Report {
		return Report{Evidence: Evidence{SOCKSRequests: []SOCKSEvidence{item}}}
	}
	handshake := func(item TLSEvidence) Report {
		return Report{Evidence: Evidence{TLS: []TLSEvidence{item}}}
	}
	reply := func(item ServiceReplyEvidence) Report {
		return Report{Evidence: Evidence{ServiceReplies: []ServiceReplyEvidence{item}}}
	}
	drop := func(item PacketDropEvidence) Report {
		return Report{Evidence: Evidence{PacketDrops: []PacketDropEvidence{item}}}
	}
	// unconsumed is the fault standing there with nothing having happened to
	// anyone; configuredOnly is the record that says only that the simulator
	// asked for it. Neither is an observation.
	tests := []struct {
		name           string
		mutation       GeneratedMutation
		positive       Report
		wrongObject    Report
		wrongState     Report
		unconsumed     Report
		configuredOnly Report
	}{
		{
			name:     "TCP reset",
			mutation: GeneratedMutation{ID: "service.tcp_reset", Node: "target", TargetPort: 80},
			positive: Report{Evidence: Evidence{TCPResets: []TCPResetEvidence{{Node: "target", Service: "http-target",
				Event: "reset", Result: "connection_reset", Count: 1}}}},
			wrongObject: Report{Evidence: Evidence{TCPResets: []TCPResetEvidence{{Node: "other", Service: "http-target",
				Event: "reset", Result: "connection_reset", Count: 1}}}},
			wrongState: Report{Evidence: Evidence{TCPResets: []TCPResetEvidence{{Node: "target", Service: "http-target",
				Event: "accepted", Result: "connected", Count: 1}}}},
		},
		{
			name:     "expired TLS certificate",
			mutation: GeneratedMutation{ID: "service.tls_expired", Node: "target", Service: "tls-target"},
			positive: handshake(TLSEvidence{Node: "target", Service: "tls-target", CertificateMode: TLSCertificateExpired,
				CertificatePresented: true, Result: "client_rejected_certificate", Count: 1}),
			wrongObject: handshake(TLSEvidence{Node: "other", Service: "tls-target", CertificateMode: TLSCertificateExpired,
				CertificatePresented: true, Result: "client_rejected_certificate", Count: 1}),
			wrongState: handshake(TLSEvidence{Node: "target", Service: "tls-target", CertificateMode: TLSCertificateValid,
				CertificatePresented: true, Result: "passed", Count: 1}),
			// The service held the expired certificate out and nobody took it.
			unconsumed: handshake(TLSEvidence{Node: "target", Service: "tls-target", CertificateMode: TLSCertificateExpired,
				CertificatePresented: false, Result: "client_closed", Count: 1}),
			configuredOnly: Report{Evidence: Evidence{ServiceStates: []ServiceStateEvidence{{Node: "target",
				Service: "tls-target", Type: ServiceTLS, Port: 443, Mode: TLSCertificateExpired}}}},
		},
		{
			name: "proxy CONNECT refused",
			mutation: GeneratedMutation{ID: "proxy.connect_refused", Node: "proxy", TargetNode: "internet",
				Service: "socks-proxy", TargetPort: 443},
			positive: socksRequest(SOCKSEvidence{Node: "proxy", Service: "socks-proxy", Event: "connect",
				AddressType: "domain", Destination: proxyCONNECTTarget, Port: 443, Result: "connection_refused", Count: 1}),
			wrongObject: socksRequest(SOCKSEvidence{Node: "proxy", Service: "other-proxy", Event: "connect",
				AddressType: "domain", Destination: proxyCONNECTTarget, Port: 443, Result: "connection_refused", Count: 1}),
			wrongState: socksRequest(SOCKSEvidence{Node: "proxy", Service: "socks-proxy", Event: "connect",
				AddressType: "domain", Destination: proxyCONNECTTarget, Port: 443, Result: "connected", Count: 1}),
			// The proxy was reached and never asked to CONNECT anywhere.
			unconsumed: socksRequest(SOCKSEvidence{Node: "proxy", Service: "socks-proxy", Event: "greeting",
				Result: "accepted", Count: 1}),
		},
		{
			name: "QUIC UDP 443 blocked",
			mutation: GeneratedMutation{ID: "quic.udp_443_block", Node: "internet",
				Service: quicProbeService, TargetPort: 443},
			positive:    drop(PacketDropEvidence{Node: "internet", Protocol: "udp", Port: 443, Direction: DirectionInbound, Packets: 3}),
			wrongObject: drop(PacketDropEvidence{Node: "other", Protocol: "udp", Port: 443, Direction: DirectionInbound, Packets: 3}),
			wrongState:  drop(PacketDropEvidence{Node: "internet", Protocol: "tcp", Port: 443, Direction: DirectionInbound, Packets: 3}),
			// The rule was installed and matched nothing.
			unconsumed: drop(PacketDropEvidence{Node: "internet", Protocol: "udp", Port: 443, Direction: DirectionInbound}),
			configuredOnly: Report{Faults: []FaultInfo{{Type: FaultDrop, Node: "internet", Protocol: "udp",
				Port: 443, Direction: DirectionInbound}}},
		},
		{
			name:     "invalid DoH response",
			mutation: GeneratedMutation{ID: "encrypted_dns.doh_invalid", Node: "internet", Service: encryptedDNSProbeService},
			positive: reply(ServiceReplyEvidence{Node: "internet", Service: encryptedDNSProbeService,
				Type: ServiceEncryptedDNS, Port: 443, Status: 200, Result: DoHResponseInvalid, Count: 1}),
			wrongObject: reply(ServiceReplyEvidence{Node: "internet", Service: "other-doh",
				Type: ServiceEncryptedDNS, Port: 443, Status: 200, Result: DoHResponseInvalid, Count: 1}),
			wrongState: reply(ServiceReplyEvidence{Node: "internet", Service: encryptedDNSProbeService,
				Type: ServiceEncryptedDNS, Port: 443, Status: 200, Result: replyResponded, Count: 1}),
			configuredOnly: Report{Evidence: Evidence{ServiceStates: []ServiceStateEvidence{{Node: "internet",
				Service: encryptedDNSProbeService, Type: ServiceEncryptedDNS, Port: 443, Mode: DoHResponseInvalid}}}},
		},
		{
			name:     "HTTP status 503",
			mutation: GeneratedMutation{ID: "http.status_503", Node: "target", TargetPort: 80, Status: 503},
			positive: reply(ServiceReplyEvidence{Node: "target", Type: ServiceHTTP, Port: 80, Status: 503,
				Result: replyResponded, Count: 1}),
			wrongObject: reply(ServiceReplyEvidence{Node: "target", Type: ServiceHTTP, Port: 81, Status: 503,
				Result: replyResponded, Count: 1}),
			wrongState: reply(ServiceReplyEvidence{Node: "target", Type: ServiceHTTP, Port: 80, Status: 200,
				Result: replyResponded, Count: 1}),
			configuredOnly: Report{Evidence: Evidence{ServiceStates: []ServiceStateEvidence{{Node: "target",
				Type: ServiceHTTP, Port: 80, Status: 503}}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if mutationObserved(tc.mutation, &Report{}, ObservedTruth{}) {
				t.Fatal("manifest-only mutation counted as observed")
			}
			if !mutationObserved(tc.mutation, &tc.positive, ObservedTruth{}) {
				t.Fatal("matching independent evidence did not observe mutation")
			}
			if mutationObserved(tc.mutation, &tc.wrongObject, ObservedTruth{}) {
				t.Fatal("evidence for the wrong object counted as observed")
			}
			if mutationObserved(tc.mutation, &tc.wrongState, ObservedTruth{}) {
				t.Fatal("healthy or different state counted as observed")
			}
			if mutationObserved(tc.mutation, &tc.unconsumed, ObservedTruth{}) {
				t.Fatal("fault that reached nobody counted as observed")
			}
			if mutationObserved(tc.mutation, &tc.configuredOnly, ObservedTruth{}) {
				t.Fatal("scheduling the mutation counted as observing it")
			}

			truth := collectObservedTruth(huntManifest(tc.mutation), &tc.positive)
			if !reflect.DeepEqual(truth.ObservedFaults, []string{tc.mutation.ID}) {
				t.Fatalf("observed faults = %v, want %q", truth.ObservedFaults, tc.mutation.ID)
			}
			withoutObservation := truth
			withoutObservation.ObservedFaults = []string{}
			if truthFingerprint(truth) == truthFingerprint(withoutObservation) {
				t.Fatal("observed mutation did not change truth fingerprint")
			}
		})
	}
}

func TestProtocolServiceMutationObservationIgnoresDiagnosis(t *testing.T) {
	mutations := []struct {
		mutation GeneratedMutation
		report   Report
	}{
		{
			GeneratedMutation{ID: "service.tls_expired", Node: "target", Service: "tls-target"},
			Report{Evidence: Evidence{TLS: []TLSEvidence{{
				Node: "target", Service: "tls-target", CertificateMode: TLSCertificateExpired,
				CertificatePresented: true, Result: "client_rejected_certificate", Count: 1,
			}}}},
		},
		{
			GeneratedMutation{ID: "http.status_503", Node: "target", TargetPort: 80, Status: 503},
			Report{Evidence: Evidence{ServiceReplies: []ServiceReplyEvidence{{
				Node: "target", Type: ServiceHTTP, Port: 80, Status: 503, Result: replyResponded, Count: 1,
			}}}},
		},
	}
	for _, tc := range mutations {
		a, b := tc.report, tc.report
		a.Tests = []TestOutcome{{Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{Status: "PASS"}}}}}
		b.Tests = []TestOutcome{{Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{Status: "FAIL"}}}}}
		if !mutationObserved(tc.mutation, &a, ObservedTruth{}) || !mutationObserved(tc.mutation, &b, ObservedTruth{}) {
			t.Fatalf("diagnosis changed observation for %s", tc.mutation.ID)
		}
	}
}

func TestMutationObservedMatchesExactNetemDNSTimelineAndLinkEvidence(t *testing.T) {
	packet := func(item PacketConditionEvidence) Report {
		return Report{Evidence: Evidence{PacketConditions: []PacketConditionEvidence{item}}}
	}
	event := func(item TimedEvent) Report {
		return Report{Timeline: []FaultEventEvidence{{Event: item, Result: EventApplied}}}
	}
	// served attaches the resolver's own record of what one real client query
	// was answered with. The DNS families need it beside the scheduler's applied
	// event, because a resolver moved into a faulty state that nobody queried
	// refused nobody.
	served := func(report Report, service, outcome string) Report {
		report.Evidence.DNSQueries = []DNSQueryEvidence{{Node: "resolver-host", Service: service,
			Name: "example.com.", QueryType: "A", Sequence: 1, ActualOutcome: outcome}}
		return report
	}
	servfailScheduled := event(TimedEvent{Type: FaultScheduledDNS, Service: "resolver", Outcome: DNSOutcomeSERVFAIL})
	dropScheduled := event(TimedEvent{Type: FaultScheduledDNS, Service: "resolver", Outcome: DNSOutcomeDrop})
	outageScheduled := event(TimedEvent{Offset: 150 * time.Millisecond, Type: FaultScheduledDNS,
		Service: "resolver", Outcome: DNSOutcomeDrop})
	tests := []struct {
		name       string
		mutation   GeneratedMutation
		positive   Report
		nearMisses []Report
	}{
		{
			name: "persistent loss",
			mutation: GeneratedMutation{ID: "netem.loss", Node: "gateway", Segment: "upstream",
				LossPercent: 17, NetemSeed: 11},
			positive: packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true,
				LossPercent: 17, Seed: 11}),
			nearMisses: []Report{
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", LossPercent: 17, Seed: 11}),
				packet(PacketConditionEvidence{Node: "other", Segment: "upstream", Active: true, LossPercent: 17, Seed: 11}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "other", Active: true, LossPercent: 17, Seed: 11}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true, LossPercent: 18, Seed: 11}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true, LossPercent: 17, Seed: 12}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true, Latency: 17 * time.Millisecond}),
			},
		},
		{
			name:     "persistent latency",
			mutation: GeneratedMutation{ID: "netem.latency", Node: "gateway", Segment: "upstream", LatencyMS: 250},
			positive: packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true,
				Latency: 250 * time.Millisecond}),
			nearMisses: []Report{
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Latency: 250 * time.Millisecond}),
				packet(PacketConditionEvidence{Node: "other", Segment: "upstream", Active: true, Latency: 250 * time.Millisecond}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "other", Active: true, Latency: 250 * time.Millisecond}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true, Latency: 300 * time.Millisecond}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true, LossPercent: 25}),
			},
		},
		{
			name: "persistent jitter",
			mutation: GeneratedMutation{ID: "netem.jitter", Node: "gateway", Segment: "upstream",
				LatencyMS: 250, JitterMS: 40, NetemSeed: 12},
			positive: packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true,
				Latency: 250 * time.Millisecond, Jitter: 40 * time.Millisecond, Seed: 12}),
			nearMisses: []Report{
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream",
					Latency: 250 * time.Millisecond, Jitter: 40 * time.Millisecond, Seed: 12}),
				packet(PacketConditionEvidence{Node: "other", Segment: "upstream", Active: true,
					Latency: 250 * time.Millisecond, Jitter: 40 * time.Millisecond, Seed: 12}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "other", Active: true,
					Latency: 250 * time.Millisecond, Jitter: 40 * time.Millisecond, Seed: 12}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true,
					Latency: 250 * time.Millisecond, Jitter: 60 * time.Millisecond, Seed: 12}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true,
					Latency: 250 * time.Millisecond, Jitter: 40 * time.Millisecond, Seed: 13}),
				packet(PacketConditionEvidence{Node: "gateway", Segment: "upstream", Active: true,
					Latency: 250 * time.Millisecond}),
			},
		},
		{
			name: "timeline netem impairment",
			mutation: GeneratedMutation{ID: "timeline.netem_spike", Node: "gateway", Segment: "upstream",
				StartMS: 200, DurationMS: 800, LatencyMS: 400, LossPercent: 17, NetemSeed: 13},
			positive: event(TimedEvent{Offset: 200 * time.Millisecond, Type: FaultScheduledNetem,
				Node: "gateway", Segment: "upstream", Latency: 400 * time.Millisecond, LossPercent: 17, NetemSeed: 13}),
			nearMisses: []Report{
				event(TimedEvent{Type: FaultScheduledNetem, Node: "gateway", Segment: "upstream", NetemSeed: 13}),
				event(TimedEvent{Offset: time.Second, Type: FaultScheduledNetem, Node: "gateway", Segment: "upstream", NetemSeed: 13}),
				event(TimedEvent{Offset: 200 * time.Millisecond, Type: FaultScheduledNetem,
					Node: "gateway", Segment: "upstream", Latency: 450 * time.Millisecond, LossPercent: 17, NetemSeed: 13}),
				event(TimedEvent{Offset: 200 * time.Millisecond, Type: FaultScheduledNetem,
					Node: "gateway", Segment: "upstream", Latency: 400 * time.Millisecond, LossPercent: 17, NetemSeed: 14}),
				event(TimedEvent{Offset: 200 * time.Millisecond, Type: FaultScheduledNetem,
					Node: "gateway", Segment: "other", Latency: 400 * time.Millisecond, LossPercent: 17, NetemSeed: 13}),
			},
		},
		{
			name:     "DNS SERVFAIL",
			mutation: GeneratedMutation{ID: "dns.servfail", Service: "resolver"},
			positive: served(servfailScheduled, "resolver", dnsServedSERVFAIL),
			nearMisses: []Report{
				served(event(TimedEvent{Type: FaultScheduledDNS, Service: "other", Outcome: DNSOutcomeSERVFAIL}), "resolver", dnsServedSERVFAIL),
				served(dropScheduled, "resolver", dnsServedSERVFAIL),
				served(event(TimedEvent{Type: FaultScheduledDNS, Service: "resolver", Outcome: DNSOutcomeAnswer}), "resolver", dnsServedSERVFAIL),
				// Applied at the resolver, and nobody was ever refused by it.
				servfailScheduled,
				served(servfailScheduled, "resolver", "ANSWER"),
				served(servfailScheduled, "resolver", dnsServedDropped),
				served(servfailScheduled, "other", dnsServedSERVFAIL),
				served(servfailScheduled, "", dnsServedSERVFAIL),
			},
		},
		{
			name:     "DNS drop",
			mutation: GeneratedMutation{ID: "dns.drop", Service: "resolver"},
			positive: served(dropScheduled, "resolver", dnsServedDropped),
			nearMisses: []Report{
				served(event(TimedEvent{Type: FaultScheduledDNS, Service: "other", Outcome: DNSOutcomeDrop}), "resolver", dnsServedDropped),
				served(servfailScheduled, "resolver", dnsServedDropped),
				served(event(TimedEvent{Type: FaultScheduledDNS, Service: "resolver", Outcome: DNSOutcomeAnswer}), "resolver", dnsServedDropped),
				dropScheduled,
				served(dropScheduled, "resolver", "ANSWER"),
				served(dropScheduled, "resolver", dnsServedSERVFAIL),
				served(dropScheduled, "other", dnsServedDropped),
			},
		},
		{
			name: "timeline DNS outage",
			mutation: GeneratedMutation{ID: "timeline.dns_outage", Service: "resolver",
				StartMS: 150, DurationMS: 700},
			positive: served(outageScheduled, "resolver", dnsServedDropped),
			nearMisses: []Report{
				served(event(TimedEvent{Type: FaultScheduledDNS, Service: "resolver", Outcome: DNSOutcomeDelay,
					Delay: 200 * time.Millisecond}), "resolver", dnsServedDropped),
				served(event(TimedEvent{Offset: 850 * time.Millisecond, Type: FaultScheduledDNS, Service: "resolver",
					Outcome: DNSOutcomeAnswer}), "resolver", dnsServedDropped),
				served(event(TimedEvent{Offset: 150 * time.Millisecond, Type: FaultScheduledDNS, Service: "other",
					Outcome: DNSOutcomeDrop}), "resolver", dnsServedDropped),
				served(event(TimedEvent{Offset: 150 * time.Millisecond, Type: FaultScheduledDNS, Service: "resolver",
					Outcome: DNSOutcomeSERVFAIL}), "resolver", dnsServedDropped),
				// The outage window opened and closed with no query inside it.
				outageScheduled,
				served(outageScheduled, "resolver", "ANSWER"),
			},
		},
		{
			name:     "transient link down",
			mutation: GeneratedMutation{ID: "link.transient_down", Node: "gateway", Segment: "upstream", DurationMS: 700},
			positive: event(TimedEvent{Type: FaultScheduledLink, Node: "gateway", Segment: "upstream", State: LinkStateDown}),
			nearMisses: []Report{
				event(TimedEvent{Offset: 700 * time.Millisecond, Type: FaultScheduledLink,
					Node: "gateway", Segment: "upstream", State: LinkStateUp}),
				event(TimedEvent{Type: FaultScheduledLink, Node: "other", Segment: "upstream", State: LinkStateDown}),
				event(TimedEvent{Type: FaultScheduledLink, Node: "gateway", Segment: "other", State: LinkStateDown}),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if mutationObserved(tc.mutation, &Report{}, ObservedTruth{}) {
				t.Fatal("manifest-only mutation counted as observed")
			}
			if !mutationObserved(tc.mutation, &tc.positive, ObservedTruth{}) {
				t.Fatal("matching independent evidence did not observe mutation")
			}
			for i := range tc.nearMisses {
				if mutationObserved(tc.mutation, &tc.nearMisses[i], ObservedTruth{}) {
					t.Errorf("near miss %d counted as observed: %+v", i, tc.nearMisses[i])
				}
			}
			failed := tc.positive
			if len(failed.Timeline) > 0 {
				failed.Timeline = append([]FaultEventEvidence(nil), failed.Timeline...)
				failed.Timeline[0].Result = EventFailed
				if mutationObserved(tc.mutation, &failed, ObservedTruth{}) {
					t.Error("failed event counted as observed")
				}
			}
			truth := collectObservedTruth(huntManifest(tc.mutation), &tc.positive)
			if !reflect.DeepEqual(truth.ObservedFaults, []string{tc.mutation.ID}) {
				t.Fatalf("observed faults = %v, want %q", truth.ObservedFaults, tc.mutation.ID)
			}
			withoutObservation := truth
			withoutObservation.ObservedFaults = []string{}
			if truthFingerprint(truth) == truthFingerprint(withoutObservation) {
				t.Fatal("observed mutation did not change truth fingerprint")
			}
		})
	}
}

func preferredPathReport() Report {
	reachable := true
	return Report{
		Topology: []NodeInfo{
			{Name: "client", Role: "client", Routes: []RouteInfo{
				{Destination: "default", Via: "10.79.1.1", Segment: "preferred-lan", Metric: 50, Family: "ipv4"},
				{Destination: "default", Via: "10.79.3.1", Segment: "alternate-lan", Metric: 100, Family: "ipv4"},
			}},
			{Name: "preferred-gateway", Role: "router", Interfaces: []InterfaceInfo{
				{Segment: "preferred-lan", IPv4: "10.79.1.1/24"},
				{Segment: "preferred-upstream", IPv4: "10.79.2.1/24"},
			}},
			{Name: "alternate-gateway", Role: "router", Interfaces: []InterfaceInfo{
				{Segment: "alternate-lan", IPv4: "10.79.3.1/24"},
				{Segment: "alternate-upstream", IPv4: "10.79.4.1/24"},
			}},
		},
		Evidence: Evidence{
			Routes: []RouteEvidence{
				{Node: "client", Destination: "1.1.1.1", Via: "10.79.1.1", Segment: "preferred-lan",
					Metric: 50, Family: "ipv4", Selected: true, GatewayReachable: &reachable},
				{Node: "client", Destination: "default", Via: "10.79.3.1", Segment: "alternate-lan",
					Metric: 100, Family: "ipv4", GatewayReachable: &reachable},
				{Node: "client", Destination: "9.9.9.9", Via: "10.79.3.1", Segment: "alternate-lan",
					Family: "ipv4", Selected: true, GatewayReachable: &reachable},
			},
			Links: []LinkEvidence{
				{Node: "preferred-gateway", Segment: "preferred-lan", IPv4: "10.79.1.1/24", Up: true},
				{Node: "preferred-gateway", Segment: "preferred-upstream", IPv4: "10.79.2.1/24", Up: false},
				{Node: "alternate-gateway", Segment: "alternate-lan", IPv4: "10.79.3.1/24", Up: true},
				{Node: "alternate-gateway", Segment: "alternate-upstream", IPv4: "10.79.4.1/24", Up: true},
			},
			Routers: []RouterEvidence{
				{Node: "preferred-gateway", IPv4Forwarding: true},
				{Node: "alternate-gateway", IPv4Forwarding: true},
			},
			ControlledTargets: []ControlledTargetEvidence{
				{From: "client", To: "9.9.9.9:80", Family: "ipv4", Via: []string{"alternate-lan", "10.79.3.1"}, Reachable: reachable},
			},
			FamilyReachability: []FamilyReachabilityEvidence{
				{Node: "client", Family: "ipv4", Target: "IPv4 internet endpoints",
					Via: []string{"preferred-lan", "10.79.1.1"}, State: FamilyStateUnreachable},
			},
		},
	}
}

// pmtuLinks is one kernel reading of a three-link path: the client's own link,
// the hop's client-facing link, and the hop's forwarding link.
func pmtuLinks(hop, endpoint int) Report {
	return Report{Evidence: Evidence{Links: []LinkEvidence{
		{Node: "client", Segment: "client-lan", Address: "10.77.1.10/24", Up: true, MTU: endpoint},
		{Node: "gateway", Segment: "client-lan", Address: "10.77.1.1/24", Up: true, MTU: endpoint},
		{Node: "gateway", Segment: "upstream", Address: "10.77.2.1/24", Up: true, MTU: hop},
	}}}
}

// A black hole is a size asymmetry, and the observation is that asymmetry read
// back off two kernels. Either half alone is a different network: a path that
// narrowed everywhere carries small packets by agreement, and a hop that was
// never narrowed carries everything.
func TestPMTUBlackholeObservationNeedsBothLinkMTUs(t *testing.T) {
	mutation := GeneratedMutation{ID: "pmtu.blackhole", Node: "gateway", Segment: "upstream",
		TargetNode: "client", MTU: minBlackholeMTU}
	blackhole := pmtuLinks(minBlackholeMTU, 1500)
	if !mutationObserved(mutation, &blackhole, ObservedTruth{}) {
		t.Fatal("a narrowed hop under wider endpoints was not observed")
	}
	if truth := collectObservedTruth(huntManifest(mutation), &blackhole); !slices.Contains(truth.ObservedFaults, "pmtu.blackhole") {
		t.Fatalf("observed faults = %v, want the black hole", truth.ObservedFaults)
	}
	for name, links := range map[string][2]int{
		"the hop was never narrowed":       {1500, 1500},
		"the endpoints narrowed with it":   {minBlackholeMTU, minBlackholeMTU},
		"the hop narrowed to another size": {minIPv6MTU, 1500},
		"no link was read at all":          {0, 0},
	} {
		report := pmtuLinks(links[0], links[1])
		if mutationObserved(mutation, &report, ObservedTruth{}) {
			t.Errorf("%s was counted as a black hole", name)
		}
	}
}

func TestPreferredPathMutationObservedFromIndependentPathConsequence(t *testing.T) {
	mutation := GeneratedMutation{ID: "routing.preferred_path_failure", Node: "preferred-gateway",
		TargetNode: "client", Segment: "preferred-upstream", Family: "ipv4",
		PreferredVia: "10.79.1.1", PreferredSegment: "preferred-lan", PreferredMetric: 50,
		AlternateVia: "10.79.3.1", AlternateSegment: "alternate-lan", AlternateMetric: 100, ControlTarget: "9.9.9.9:80"}
	positive := preferredPathReport()
	if !mutationObserved(mutation, &positive, ObservedTruth{IPv4: "unreachable"}) {
		t.Fatal("matching selected-route, failed-path, and alternate-path evidence did not observe mutation")
	}
	if mutationObserved(mutation, &Report{}, ObservedTruth{}) {
		t.Fatal("manifest-only mutation counted as observed")
	}
	appliedOnly := Report{Faults: []FaultInfo{{Type: FaultLinkDown, Node: mutation.Node}}}
	if mutationObserved(mutation, &appliedOnly, ObservedTruth{IPv4: "unreachable"}) {
		t.Fatal("applied link-down bookkeeping counted as the routing consequence")
	}
	wrongMutation := mutation
	wrongMutation.Node = "other-gateway"
	if mutationObserved(wrongMutation, &positive, ObservedTruth{IPv4: "unreachable"}) {
		t.Fatal("path evidence for another router counted as observed")
	}
	wrongMutation = mutation
	wrongMutation.Segment = "other-upstream"
	if mutationObserved(wrongMutation, &positive, ObservedTruth{IPv4: "unreachable"}) {
		t.Fatal("path evidence for another upstream segment counted as observed")
	}

	nearMisses := map[string]func(*Report){
		"alternate selected": func(report *Report) {
			report.Evidence.Routes[0].Via, report.Evidence.Routes[0].Segment = "10.79.3.1", "alternate-lan"
			report.Evidence.FamilyReachability[0].Via = []string{"alternate-lan", "10.79.3.1"}
		},
		"wrong gateway": func(report *Report) {
			report.Evidence.Routes[0].Via = "10.79.1.254"
			report.Evidence.FamilyReachability[0].Via[1] = "10.79.1.254"
		},
		"wrong selected segment": func(report *Report) {
			report.Evidence.Routes[0].Segment = "other-lan"
			report.Evidence.FamilyReachability[0].Via[0] = "other-lan"
		},
		"targeted link remains up": func(report *Report) { report.Evidence.Links[1].Up = true },
		"preferred path remains reachable": func(report *Report) {
			report.Evidence.FamilyReachability[0].State = FamilyStateReachable
		},
		// A family the client never had is not a family whose preferred path
		// just failed, so "unavailable" must not stand in for the consequence.
		"preferred family unavailable": func(report *Report) {
			report.Evidence.FamilyReachability[0].State = FamilyStateUnavailable
		},
		"alternate route absent": func(report *Report) {
			report.Topology[0].Routes = report.Topology[0].Routes[:1]
			report.Evidence.Routes = report.Evidence.Routes[:1]
			report.Evidence.FamilyReachability = nil
		},
		"alternate transport unavailable": func(report *Report) { report.Evidence.ControlledTargets[0].Reachable = false },
		"wrong family": func(report *Report) {
			report.Evidence.Routes[0].Family = "ipv6"
			report.Evidence.FamilyReachability[0].Family = "ipv6"
		},
	}
	for name, change := range nearMisses {
		t.Run(name, func(t *testing.T) {
			report := preferredPathReport()
			change(&report)
			if mutationObserved(mutation, &report, ObservedTruth{IPv4: "unreachable"}) {
				t.Fatal("near-miss route evidence counted as observed")
			}
		})
	}

	truth := collectObservedTruth(huntManifest(mutation), &positive)
	if !reflect.DeepEqual(truth.ObservedFaults, []string{mutation.ID}) {
		t.Fatalf("observed faults = %v, want %q", truth.ObservedFaults, mutation.ID)
	}
}

func preferredPathIPv6Report() Report {
	reachable := true
	return Report{
		Topology: []NodeInfo{
			{Name: "client", Role: "client", Routes: []RouteInfo{
				{Destination: "default", Via: "2001:db8:79:1::1", Segment: "preferred-lan", Metric: 50, Family: "ipv6"},
				{Destination: "default", Via: "2001:db8:79:3::1", Segment: "alternate-lan", Metric: 100, Family: "ipv6"},
			}},
			{Name: "preferred-gateway", Role: "router", Interfaces: []InterfaceInfo{
				{Segment: "preferred-lan", IPv6: "2001:db8:79:1::1/64"},
				{Segment: "preferred-upstream", IPv6: "2001:db8:79:2::1/64"},
			}},
			{Name: "alternate-gateway", Role: "router", Interfaces: []InterfaceInfo{
				{Segment: "alternate-lan", IPv6: "2001:db8:79:3::1/64"},
				{Segment: "alternate-upstream", IPv6: "2001:db8:79:4::1/64"},
			}},
		},
		Evidence: Evidence{
			Routes: []RouteEvidence{
				{Node: "client", Destination: "2606:4700:4700::1111", Via: "2001:db8:79:1::1", Segment: "preferred-lan",
					Metric: 50, Family: "ipv6", Selected: true, GatewayReachable: &reachable},
				{Node: "client", Destination: "default", Via: "2001:db8:79:3::1", Segment: "alternate-lan",
					Metric: 100, Family: "ipv6", GatewayReachable: &reachable},
				{Node: "client", Destination: "2001:db8:79::99", Via: "2001:db8:79:3::1", Segment: "alternate-lan",
					Family: "ipv6", Selected: true, GatewayReachable: &reachable},
			},
			Links: []LinkEvidence{
				{Node: "preferred-gateway", Segment: "preferred-lan", IPv6: "2001:db8:79:1::1/64", Up: true},
				{Node: "preferred-gateway", Segment: "preferred-upstream", IPv6: "2001:db8:79:2::1/64", Up: false},
				{Node: "alternate-gateway", Segment: "alternate-lan", IPv6: "2001:db8:79:3::1/64", Up: true},
				{Node: "alternate-gateway", Segment: "alternate-upstream", IPv6: "2001:db8:79:4::1/64", Up: true},
			},
			Routers: []RouterEvidence{
				{Node: "preferred-gateway", IPv6Forwarding: true},
				{Node: "alternate-gateway", IPv6Forwarding: true},
			},
			ControlledTargets: []ControlledTargetEvidence{
				{From: "client", To: "[2001:db8:79::99]:80", Family: "ipv6", Via: []string{"alternate-lan", "2001:db8:79:3::1"}, Reachable: true},
			},
			FamilyReachability: []FamilyReachabilityEvidence{
				{Node: "client", Family: "ipv6", Target: "IPv6 internet endpoints",
					Via: []string{"preferred-lan", "2001:db8:79:1::1"}, State: FamilyStateUnreachable},
			},
		},
	}
}

func TestIPv6PreferredPathMutationObservationAndHuntGrading(t *testing.T) {
	mutation := GeneratedMutation{ID: "routing.preferred_path_failure", Node: "preferred-gateway",
		TargetNode: "client", Segment: "preferred-upstream", Family: "ipv6",
		PreferredVia: "2001:db8:79:1::1", PreferredSegment: "preferred-lan", PreferredMetric: 50,
		AlternateVia: "2001:db8:79:3::1", AlternateSegment: "alternate-lan", AlternateMetric: 100,
		ControlTarget: "[2001:db8:79::99]:80"}
	report := preferredPathIPv6Report()
	truth := collectObservedTruth(huntManifest(mutation), &report)
	if truth.IPv6 != FamilyStateUnreachable || !reflect.DeepEqual(truth.ObservedFaults, []string{mutation.ID}) ||
		!mutationObserved(mutation, &report, truth) {
		t.Fatalf("IPv6 preferred path was not independently observed: truth=%+v", truth)
	}
	if got := observedConditions(observation{Evidence: report.Evidence, Truth: truth}); !slices.Contains(got, ConditionIPv6InternetUnreachable) {
		t.Fatalf("observed conditions = %v, want IPv6 unreachable", got)
	}

	report.Cleanup.Done = true
	report.Tests = []TestOutcome{{Node: "client", ProcessOutcome: ProcessExited,
		Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "internet_tcp", Status: "FAIL",
			Families: &DiagnosisFamilies{IPv6: FamilyStateUnreachable}}}}}}
	if findings := unrecognizedConditionFindings(&report, truth); len(findings) != 0 {
		t.Fatalf("recognized IPv6 condition produced findings: %+v", findings)
	}
	report.Tests[0].Diagnosis.Checks[0].Families.IPv6 = FamilyStateReachable
	findings := unrecognizedConditionFindings(&report, truth)
	if len(findings) != 1 || findings[0].Family != "ipv6" || findings[0].Expected != string(ConditionIPv6InternetUnreachable) {
		t.Fatalf("unrecognized IPv6 condition findings = %+v", findings)
	}

	nearMisses := map[string]func(*Report){
		"scheduled only": func(report *Report) {
			*report = Report{Faults: []FaultInfo{{Type: FaultLinkDown, Node: mutation.Node}}}
		},
		"alternate broken":        func(report *Report) { report.Evidence.ControlledTargets[0].Reachable = false },
		"IPv4 alternate evidence": func(report *Report) { report.Evidence.ControlledTargets[0].Family = "ipv4" },
		"wrong node":              func(report *Report) { report.Evidence.ControlledTargets[0].From = "other-client" },
		"wrong path":              func(report *Report) { report.Evidence.ControlledTargets[0].Via[0] = "other-lan" },
		"IPv6 unavailable":        func(report *Report) { report.Evidence.FamilyReachability[0].State = FamilyStateUnavailable },
	}
	for name, change := range nearMisses {
		t.Run(name, func(t *testing.T) {
			nearMiss := preferredPathIPv6Report()
			change(&nearMiss)
			if mutationObserved(mutation, &nearMiss, ObservedTruth{IPv6: FamilyStateUnreachable}) {
				t.Fatal("inconclusive IPv6 evidence counted as observed")
			}
		})
	}
}

func TestTruthFingerprintIncludesFamilyReachability(t *testing.T) {
	base := ObservedTruth{DNS: "available", IPv4: "reachable", IPv6: "reachable", Gateway: "reachable",
		Proxy: "unknown", TLS: "unknown", TCP: "unknown", Link: "up", Packet: "unknown", Route: "selected", ObservedFaults: []string{}}
	equivalent := base
	if truthFingerprint(base) != truthFingerprint(equivalent) {
		t.Fatal("identical truth did not produce a stable fingerprint")
	}
	for _, tc := range []struct {
		name   string
		change func(*ObservedTruth)
	}{
		{"IPv4 unreachable", func(truth *ObservedTruth) { truth.IPv4 = "unreachable" }},
		{"IPv6 unreachable", func(truth *ObservedTruth) { truth.IPv6 = "unreachable" }},
		{"IPv4 unavailable", func(truth *ObservedTruth) { truth.IPv4 = "unavailable" }},
		{"non-family truth", func(truth *ObservedTruth) { truth.DNS = "unavailable" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.change(&changed)
			if truthFingerprint(base) == truthFingerprint(changed) {
				t.Fatalf("truth change did not alter fingerprint: %+v", changed)
			}
		})
	}
	unavailable, unreachable := base, base
	unavailable.IPv6, unreachable.IPv6 = "unavailable", "unreachable"
	if truthFingerprint(unavailable) == truthFingerprint(unreachable) {
		t.Fatal("unavailable and unreachable IPv6 produced the same fingerprint")
	}

	// Truth identity follows what was observed, not the order the holder wrote
	// its two records in. Without this, one run's fingerprint would depend on
	// probe completion order and every equivalence class would split at random.
	forward := familyTruthReport(FamilyStateUnreachable, FamilyStateReachable)
	reversed := familyTruthReport(FamilyStateUnreachable, FamilyStateReachable)
	slices.Reverse(reversed.Evidence.FamilyReachability)
	if a, b := collectObservedTruth(huntManifest(), forward), collectObservedTruth(huntManifest(), reversed); truthFingerprint(a) != truthFingerprint(b) {
		t.Fatalf("family record order changed the truth fingerprint:\n%+v\n%+v", a, b)
	}
}

func TestObservedTruthProxyIgnoresGreetingResult(t *testing.T) {
	healthy := []SOCKSEvidence{
		{Event: "greeting", Result: "accepted"},
		{Event: "connect", Result: "connected"},
	}
	if truth := collectObservedTruth(huntManifest(), &Report{Evidence: Evidence{SOCKSRequests: healthy}}); truth.Proxy != "reached" {
		t.Fatalf("healthy proxy session = %q, want reached", truth.Proxy)
	}
	broken := append(healthy[:1:1], SOCKSEvidence{Event: "connect", Result: "dns_failure"})
	if truth := collectObservedTruth(huntManifest(), &Report{Evidence: Evidence{SOCKSRequests: broken}}); truth.Proxy != "failed" {
		t.Fatalf("failed proxy session = %q, want failed", truth.Proxy)
	}
}

func TestObservedTruthRequiresAnActualTCPReset(t *testing.T) {
	accepted := &Report{Evidence: Evidence{TCPResets: []TCPResetEvidence{{Node: "target", Event: "accepted",
		Result: "connected", Count: 1}}}}
	if truth := collectObservedTruth(huntManifest(), accepted); truth.TCP != "unknown" {
		t.Fatalf("accepted connection counted as a reset: %+v", truth)
	}
	// A holder stamps its own name on every record it writes, so a reset from
	// nowhere is not an observation anybody made.
	unstamped := &Report{Evidence: Evidence{TCPResets: []TCPResetEvidence{{Event: "reset",
		Result: "connection_reset", Count: 1}}}}
	if truth := collectObservedTruth(huntManifest(), unstamped); truth.TCP != "unknown" {
		t.Fatalf("unattributable reset became truth: %+v", truth)
	}
	reset := &Report{Evidence: Evidence{TCPResets: []TCPResetEvidence{{Node: "target", Event: "reset",
		Result: "connection_reset", Count: 1}}}}
	if truth := collectObservedTruth(huntManifest(), reset); truth.TCP != "reset" {
		t.Fatalf("recorded connection reset was not observed: %+v", truth)
	}
}

// TestHuntAnalysisDoesNotExpectAResetNoProbeObserved replays the Oct 28
// two-path-healthy case 1 from #436 (case e622e73f7af5fd94). Three tests ran
// generic checks only; no protocol or target_tcp row executed. The reset stays
// in truth and ObservedFaults, but it is not a diagnostic miss.
func TestHuntAnalysisDoesNotExpectAResetNoProbeObserved(t *testing.T) {
	check := func(id, status string) DiagnosisCheck { return DiagnosisCheck{ID: id, Status: status} }
	checks := func(dnsPublic string) []DiagnosisCheck {
		return []DiagnosisCheck{
			check("iface", "PASS"), check("internet_tcp", "PASS"), check("quic_udp_443", "PASS"),
			check("proxy_connect", "N/A"), check("dns", "PASS"), check("dns_public", dnsPublic),
			check("dns_encrypted", "PASS"), check("ssid", "N/A"),
		}
	}
	tests := []TestOutcome{
		{ProcessOutcome: ProcessExited, Diagnosis: &Diagnosis{Checks: checks("PASS")}},
		{ProcessOutcome: ProcessExited, Diagnosis: &Diagnosis{Checks: checks("N/A")}},
		{ProcessOutcome: ProcessExited, Diagnosis: &Diagnosis{Checks: checks("PASS")}},
	}
	report := &Report{Cleanup: CleanupInfo{Done: true}, Tests: tests, Evidence: Evidence{TCPResets: []TCPResetEvidence{
		{Node: "target", Service: "routed-http", Event: "accepted", Result: "connected", Count: 2},
		{Node: "target", Service: "routed-http", Event: "reset", Result: "connection_reset", Count: 2},
	}}}
	manifest := huntManifest(
		GeneratedMutation{ID: "service.tcp_reset", Node: "target", TargetPort: 80},
		GeneratedMutation{ID: "timeline.dns_outage"},
	)
	truth := collectObservedTruth(manifest, report)
	if truth.TCP != "reset" || !slices.Contains(truth.ObservedFaults, "service.tcp_reset") {
		t.Fatalf("injected reset lost from truth: %+v", truth)
	}
	if findings := analyzeHuntCase(manifest, report, truth); len(findings) != 0 {
		t.Fatalf("unprobed reset reported as a diagnostic miss: %+v", findings)
	}
}

// TestHuntAnalysisAttributesAResetToTheRowsThatReadIt pins which rows can
// claim a missed reset. The reset sits on target port 80. target owns
// 10.78.2.20 and 2001:db8:78::20 and declares the aliases 9.9.9.9 and
// 2001:db8:79::99, as the two-path bases do; internet owns 10.80.2.20. A row
// reads the reset only when it is an http, https or tls row of a netdoc that
// exited, failed with connection_closed on port 80, against an address target
// owns. The first such row in report order names the probe. The canonical
// projection of each report must give the same answer as the raw one.
func TestHuntAnalysisAttributesAResetToTheRowsThatReadIt(t *testing.T) {
	closed := diagnostic.ConnectionCauseClosed
	row := func(id, status, cause, dialed string) DiagnosisCheck {
		return DiagnosisCheck{ID: id, Status: status, Cause: cause, SelectedIP: dialed}
	}
	exited := func(target string, checks ...DiagnosisCheck) TestOutcome {
		return TestOutcome{Node: "client", Target: target, ProcessOutcome: ProcessExited, Diagnosis: &Diagnosis{Checks: checks}}
	}
	general := exited("", row("iface", "PASS", "", ""), row("internet_tcp", "PASS", "", "10.78.2.20"), row("dns", "PASS", "", ""))
	readHTTP := exited("10.78.2.20:80", row("target_tcp", "PASS", "", "10.78.2.20"), row("http", "FAIL", closed, "10.78.2.20"))
	for _, tc := range []struct {
		name  string
		tests []TestOutcome
		want  string // the probe the miss names, or empty for no miss
	}{
		{"#436: only general checks ran, the portal host is the reset node", []TestOutcome{general, general, general}, ""},
		{"reset node on 8080: http closed", []TestOutcome{exited("10.78.2.20:8080", row("http", "FAIL", closed, "10.78.2.20"))}, ""},
		{"reset node on 8080: http passed", []TestOutcome{exited("10.78.2.20:8080", row("http", "PASS", "", "10.78.2.20"))}, ""},
		{"reset node on 8080: target_tcp refused", []TestOutcome{exited("10.78.2.20:8080",
			row("target_tcp", "FAIL", diagnostic.ConnectionCauseRefused, "10.78.2.20"), row("http", "SKIP", "", ""))}, ""},
		{"reset node on 8080 over IPv6: http closed", []TestOutcome{exited("[2001:db8:78::20]:8080", row("http", "FAIL", closed, "2001:db8:78::20"))}, ""},
		{"another node on 80: http passed", []TestOutcome{exited("10.80.2.20:80", row("http", "PASS", "", "10.80.2.20"))}, ""},
		{"another node on 80: http timed out", []TestOutcome{exited("10.80.2.20:80", row("http", "FAIL", diagnostic.ConnectionCauseTimeout, "10.80.2.20"))}, ""},
		{"another node on 80: http closed", []TestOutcome{exited("10.80.2.20:80", row("http", "FAIL", closed, "10.80.2.20"))}, ""},
		{"an address no node owns", []TestOutcome{exited("192.0.2.7:80", row("http", "FAIL", closed, "192.0.2.7"))}, ""},
		{"reset endpoint: target_tcp connected and read nothing", []TestOutcome{exited("10.78.2.20:80", row("target_tcp", "PASS", "", "10.78.2.20"))}, ""},
		{"reset endpoint: http timed out", []TestOutcome{exited("10.78.2.20:80", row("http", "FAIL", diagnostic.ConnectionCauseTimeout, "10.78.2.20"))}, ""},
		{"reset endpoint: http failed with no cause", []TestOutcome{exited("10.78.2.20:80", row("http", "FAIL", "", "10.78.2.20"))}, ""},
		{"reset endpoint: response bytes", []TestOutcome{exited("10.78.2.20:80", row("http", "FAIL", diagnostic.HTTPCauseInvalidResponse, "10.78.2.20"))}, ""},
		{"reset endpoint: http passed", []TestOutcome{exited("10.78.2.20:80", row("http", "PASS", "", "10.78.2.20"))}, ""},
		{"reset endpoint: tls failed the generic handshake", []TestOutcome{exited("https://10.78.2.20:80", row("tls", "FAIL", diagnostic.TLSCauseHandshake, "10.78.2.20"))}, ""},
		{"reset endpoint: rows skipped", []TestOutcome{exited("10.78.2.20:80", row("target_tcp", "SKIP", "", ""), row("http", "SKIP", "", ""))}, ""},
		{"reset endpoint: rows not applicable", []TestOutcome{exited("10.78.2.20:80", row("http", "N/A", "", ""))}, ""},
		{"reset endpoint: unknown status", []TestOutcome{exited("10.78.2.20:80", row("http", "UNKNOWN", closed, "10.78.2.20"))}, ""},
		{"reset endpoint: no diagnosis", []TestOutcome{{Node: "client", Target: "10.78.2.20:80", ProcessOutcome: ProcessExited}}, ""},
		{"reset endpoint: netdoc hit the process deadline", []TestOutcome{{Node: "client", Target: "10.78.2.20:80",
			ProcessOutcome: ProcessTimedOut, Diagnosis: readHTTP.Diagnosis}}, ""},
		{"reset endpoint: netdoc was signaled", []TestOutcome{{Node: "client", Target: "10.78.2.20:80",
			ProcessOutcome: ProcessSignaled, Diagnosis: readHTTP.Diagnosis}}, ""},
		{"reset endpoint: no recorded address", []TestOutcome{exited("10.78.2.20:80", row("http", "FAIL", closed, ""))}, ""},
		{"reset endpoint: recorded address does not parse", []TestOutcome{exited("10.78.2.20:80", row("http", "FAIL", closed, "not-an-address"))}, ""},
		{"target does not parse", []TestOutcome{exited("http://[::1", row("http", "FAIL", closed, "10.78.2.20"))}, ""},
		{"TLS-and-HTTP target on 443: tls closed on 443", []TestOutcome{exited("https://10.78.2.20", row("tls", "FAIL", closed, "10.78.2.20"))}, ""},
		{"reset endpoint: classified as connection_reset", []TestOutcome{exited("10.78.2.20:80",
			row("http", "FAIL", diagnostic.ConnectionCauseReset, "10.78.2.20"))}, ""},

		{"reset endpoint: http closed", []TestOutcome{readHTTP}, "http"},
		{"reset endpoint over IPv6: http closed", []TestOutcome{exited("[2001:db8:78::20]:80", row("http", "FAIL", closed, "2001:db8:78::20"))}, "http"},
		{"reset endpoint in v4-mapped spelling", []TestOutcome{exited("[::ffff:10.78.2.20]:80", row("http", "FAIL", closed, "::ffff:10.78.2.20"))}, "http"},
		{"a name that dialed the reset node", []TestOutcome{exited("routed-target.test:80", row("dns", "PASS", "", ""),
			row("http", "FAIL", closed, "10.78.2.20"))}, "http"},
		{"the IPv4 alias", []TestOutcome{exited("http://9.9.9.9:80", row("http", "FAIL", closed, "9.9.9.9"))}, "http"},
		{"the IPv6 alias", []TestOutcome{exited("http://[2001:db8:79::99]:80", row("http", "FAIL", closed, "2001:db8:79::99"))}, "http"},
		{"tls closed on the reset port", []TestOutcome{exited("https://10.78.2.20:80", row("tls", "FAIL", closed, "10.78.2.20"))}, "tls"},
		{"TLS-and-HTTP target on 443: its http row dials 80", []TestOutcome{exited("https://10.78.2.20",
			row("tls", "FAIL", closed, "10.78.2.20"), row("http", "FAIL", closed, "10.78.2.20"))}, "http"},
		{"skipped http, then tls closed: the row that ran names it", []TestOutcome{exited("https://10.78.2.20:80",
			row("http", "SKIP", "", ""), row("tls", "FAIL", closed, "10.78.2.20"))}, "tls"},
		{"tls then http closed: the first in report order names it", []TestOutcome{exited("https://10.78.2.20:80",
			row("target_tcp", "PASS", "", "10.78.2.20"), row("tls", "FAIL", closed, "10.78.2.20"), row("https", "FAIL", closed, "10.78.2.20"))}, "tls"},
		{"8080 read first, then the reset endpoint", []TestOutcome{
			exited("10.78.2.20:8080", row("http", "FAIL", closed, "10.78.2.20")), readHTTP}, "http"},
		{"another node passed first, then the reset endpoint", []TestOutcome{
			exited("10.80.2.20:80", row("http", "PASS", "", "10.80.2.20")), general, readHTTP}, "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := huntManifest(GeneratedMutation{ID: "service.tcp_reset", Node: "target", TargetPort: 80})
			raw := &Report{Cleanup: CleanupInfo{Done: true}, Tests: tc.tests, Topology: []NodeInfo{
				{Name: "target", Aliases: []string{"9.9.9.9", "2001:db8:79::99"}, Interfaces: []InterfaceInfo{
					{Segment: "preferred-upstream", IPv4: "10.78.2.20/24"}, {Segment: "alternate-upstream", IPv6: "2001:db8:78::20/64"}}},
				{Name: "internet", Interfaces: []InterfaceInfo{{Segment: "internet-lan", IPv4: "10.80.2.20/24"}}},
			}}
			for name, report := range map[string]*Report{"raw": raw, "canonical": canonicalHuntReport(raw)} {
				var got []string
				for _, f := range analyzeHuntCase(manifest, report, ObservedTruth{TCP: "reset"}) {
					if f.Code == "tcp_reset_not_distinguished" {
						got = append(got, f.Probe)
					}
				}
				var want []string
				if tc.want != "" {
					want = []string{tc.want}
				}
				if !slices.Equal(got, want) {
					t.Errorf("%s report: misses named %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestObservedTruthTLSUsesHandshakeResultVocabulary(t *testing.T) {
	passed := []TLSEvidence{{Result: tlsHandshakeResult(nil, true)}}
	if truth := collectObservedTruth(huntManifest(), &Report{Evidence: Evidence{TLS: passed}}); truth.TLS != "observed" {
		t.Fatalf("successful handshake = %q, want observed", truth.TLS)
	}
	broken := []TLSEvidence{{Result: "handshake_failure"}}
	if truth := collectObservedTruth(huntManifest(), &Report{Evidence: Evidence{TLS: broken}}); truth.TLS != "failed" {
		t.Fatalf("failed handshake = %q, want failed", truth.TLS)
	}
}

func TestHuntAnalysisRequiresObservedFailureForFalseNegative(t *testing.T) {
	manifest := huntManifest(GeneratedMutation{ID: "netem.loss", Node: "gateway", Segment: "upstream", LossPercent: 20})
	diagnosis := &Diagnosis{Verdict: "ok", Checks: []DiagnosisCheck{{ID: "internet_tcp", Status: "PASS"}}}
	report := &Report{Cleanup: CleanupInfo{Done: true}, Faults: []FaultInfo{{Type: FaultNetem, Node: "gateway", LossPercent: 20}},
		Tests:    []TestOutcome{{Name: "t", Diagnosis: diagnosis, ProcessOutcome: ProcessExited}},
		Evidence: Evidence{PacketConditions: []PacketConditionEvidence{{Active: true, DroppedPackets: 7}}}, Suggestions: []Suggestion{}}
	truth := collectObservedTruth(manifest, report)
	if findings := analyzeHuntCase(manifest, report, truth); len(findings) != 0 {
		t.Fatalf("packet loss alone was overclaimed as a bug: %+v", findings)
	}
}

func TestHuntAnalysisFindsObservedDNSFalseNegative(t *testing.T) {
	manifest := huntManifest(GeneratedMutation{ID: "dns.drop", Service: "r"})
	report := &Report{Cleanup: CleanupInfo{Done: true},
		Timeline: []FaultEventEvidence{{Event: TimedEvent{Type: FaultScheduledDNS, Service: "r", Outcome: DNSOutcomeDrop}, Result: EventApplied}},
		Tests: []TestOutcome{{Name: "t", StartOffset: 0, EndOffset: time.Second, ProcessOutcome: ProcessExited,
			Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "dns", Status: "PASS", Detail: "resolved"}}}}},
		Evidence:    Evidence{DNSQueries: []DNSQueryEvidence{{Service: "r", ActualOutcome: "DROPPED", Offset: 100 * time.Millisecond, OffsetKnown: true}}},
		Suggestions: []Suggestion{}}
	truth := collectObservedTruth(manifest, report)
	findings := analyzeHuntCase(manifest, report, truth)
	if len(findings) != 1 || findings[0].Category != FindingFalseNegative || findings[0].Severity != SeverityHigh {
		t.Fatalf("findings = %+v", findings)
	}
}

func familyDiagnosisReport(ipv4, ipv6 string) *Report {
	return &Report{Cleanup: CleanupInfo{Done: true}, Topology: []NodeInfo{{Name: "client", Role: "client"}},
		Tests: []TestOutcome{{Name: "netdoc", Node: "client", ProcessOutcome: ProcessExited,
			Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "internet_tcp",
				Families: &DiagnosisFamilies{IPv4: ipv4, IPv6: ipv6}}}}}}, Suggestions: []Suggestion{}}
}

// familyMismatchFindings collects both directions of the family comparison: the
// generic false-negative oracle's semantic condition and the contradiction
// finding that stayed behind. Selecting on Family rather than on one code keeps
// the test honest about which direction fired.
func familyMismatchFindings(findings []HuntCaseFinding) []HuntCaseFinding {
	var out []HuntCaseFinding
	for _, finding := range findings {
		if finding.Family != "" && (finding.Code == "family_reachability_mismatch" ||
			finding.Code == "unrecognized_network_condition") {
			out = append(out, finding)
		}
	}
	return out
}

func TestHuntAnalysisComparesFamilyTruthWithDiagnosis(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		truth4, truth6           string
		diagnosis4, diagnosis6   string
		wantCategory, wantFamily string
	}{
		{"IPv4 false negative", "unreachable", "reachable", "reachable", "reachable", FindingFalseNegative, "ipv4"},
		{"IPv6 false negative", "reachable", "unreachable", "reachable", "reachable", FindingFalseNegative, "ipv6"},
		{"IPv4 contradiction", "reachable", "reachable", "unreachable", "reachable", FindingDiagnosticContradiction, "ipv4"},
		{"IPv6 contradiction", "reachable", "reachable", "reachable", "unreachable", FindingDiagnosticContradiction, "ipv6"},
		{"reachable agreement", "reachable", "reachable", "reachable", "reachable", "", ""},
		{"unreachable agreement", "unreachable", "reachable", "unreachable", "reachable", "", ""},
		{"unreachable unreported", "unreachable", "reachable", "", "reachable", FindingFalseNegative, "ipv4"},
		{"unavailable unreported", "unavailable", "reachable", "", "reachable", "", ""},
		{"unavailable reported reachable is outside reachability comparison", "unavailable", "reachable", "reachable", "reachable", "", ""},
		{"unavailable reported unreachable is outside reachability comparison", "unavailable", "reachable", "unreachable", "reachable", "", ""},
		{"unknown is not an oracle", "unknown", "reachable", "unreachable", "reachable", "", ""},
		{"dual-stack mixed isolates IPv6", "reachable", "unreachable", "reachable", "reachable", FindingFalseNegative, "ipv6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			truth := ObservedTruth{IPv4: tc.truth4, IPv6: tc.truth6}
			findings := familyMismatchFindings(analyzeHuntCase(huntManifest(), familyDiagnosisReport(tc.diagnosis4, tc.diagnosis6), truth))
			if tc.wantCategory == "" {
				if len(findings) != 0 {
					t.Fatalf("family findings = %+v, want none", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("family findings = %+v, want one", findings)
			}
			finding := findings[0]
			if finding.Category != tc.wantCategory || finding.Family != tc.wantFamily {
				t.Fatalf("family finding = %+v", finding)
			}
			// A false negative names the semantic condition and no probe; the
			// contradiction is still a claim about the row that made it.
			if tc.wantCategory == FindingFalseNegative {
				want := string(ConditionIPv4InternetUnreachable)
				if tc.wantFamily == "ipv6" {
					want = string(ConditionIPv6InternetUnreachable)
				}
				if finding.Expected != want || finding.Actual != "unrecognized" || finding.Probe != "" {
					t.Fatalf("false negative finding = %+v", finding)
				}
			} else if finding.Expected != "reachable" || finding.Actual != "unreachable" || finding.Probe != "internet_tcp" {
				t.Fatalf("contradiction finding = %+v", finding)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*Report)
	}{
		{"families object absent", func(report *Report) {
			report.Tests[0].Diagnosis.Checks[0].Families = nil
		}},
		{"internet check absent", func(report *Report) {
			report.Tests[0].Diagnosis.Checks = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := familyDiagnosisReport("reachable", "reachable")
			tc.change(report)
			findings := familyMismatchFindings(analyzeHuntCase(huntManifest(), report,
				ObservedTruth{IPv4: "unreachable", IPv6: "reachable"}))
			if len(findings) != 1 || findings[0].Family != "ipv4" ||
				findings[0].Expected != string(ConditionIPv4InternetUnreachable) {
				t.Fatalf("absent family diagnosis findings = %+v", findings)
			}
		})
	}
}

func TestHuntFamilyMismatchIsGenericAndExpectationIndependent(t *testing.T) {
	truth := ObservedTruth{IPv4: "reachable", IPv6: "unreachable"}
	report := familyDiagnosisReport("reachable", "reachable")
	first := familyMismatchFindings(analyzeHuntCase(huntManifest(), report, truth))
	if len(first) != 1 || first[0].Family != "ipv6" {
		t.Fatalf("mutation-free family findings = %+v", first)
	}
	report.Tests[0].ExpectedVerdict = "deliberately-wrong"
	report.Tests[0].Checks = []CheckComparison{{ID: "internet_tcp", ExpectedIPv6: "reachable", ActualIPv6: "reachable", Outcome: OutcomeMatched}}
	second := familyMismatchFindings(analyzeHuntCase(huntManifest(), report, truth))
	if len(second) != 1 || second[0].Fingerprint != first[0].Fingerprint {
		t.Fatalf("scenario expectation changed generic finding:\n%+v\n%+v", first, second)
	}
}

func TestHuntFamilyMismatchKeepsMutationObservationSeparate(t *testing.T) {
	mutation := GeneratedMutation{ID: "family.ipv6_drop"}
	manifest := huntManifest(mutation)
	truth := ObservedTruth{IPv4: "reachable", IPv6: "unreachable"}
	report := familyDiagnosisReport("reachable", "reachable")
	if !mutationObserved(mutation, report, truth) {
		t.Fatal("independent IPv6 consequence did not observe the mutation")
	}
	findings := familyMismatchFindings(analyzeHuntCase(manifest, report, truth))
	if len(findings) != 1 || findings[0].Category != FindingFalseNegative || findings[0].Family != "ipv6" {
		t.Fatalf("observed mutation with missed consequence = %+v", findings)
	}
}

func TestHuntFamilyMismatchExcludesSampledAndTransientPaths(t *testing.T) {
	truth := ObservedTruth{IPv4: "reachable", IPv6: "reachable"}
	for _, tc := range []struct {
		name   string
		change func(*Report)
	}{
		{"netem", func(report *Report) { report.Faults = []FaultInfo{{Type: FaultNetem, LossPercent: 20}} }},
		{"timed netem", func(report *Report) {
			report.Timeline = []FaultEventEvidence{{Event: TimedEvent{Type: FaultScheduledNetem, LossPercent: 100}, Result: EventApplied}}
		}},
		{"transient link", func(report *Report) {
			report.Timeline = []FaultEventEvidence{{Event: TimedEvent{Type: FaultScheduledLink, State: LinkStateDown}, Result: EventApplied}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := familyDiagnosisReport("unreachable", "reachable")
			tc.change(report)
			if findings := familyMismatchFindings(analyzeHuntCase(huntManifest(), report, truth)); len(findings) != 0 {
				t.Fatalf("final-state comparison overclaimed a changing/sampled path: %+v", findings)
			}
		})
	}
	for _, event := range []TimedEvent{
		{Type: FaultScheduledNetem},
		{Type: FaultScheduledLink, State: LinkStateUp},
	} {
		report := familyDiagnosisReport("unreachable", "reachable")
		report.Timeline = []FaultEventEvidence{{Event: event, Result: EventApplied}}
		if findings := familyMismatchFindings(analyzeHuntCase(huntManifest(), report, truth)); len(findings) != 1 {
			t.Fatalf("non-impairing timeline event suppressed final-state comparison: %+v", findings)
		}
	}
}

func TestHuntSeverityVocabulary(t *testing.T) {
	if len(HuntSeverities) == 0 {
		t.Fatal("hunt severity vocabulary is empty")
	}
	seen := make(map[HuntSeverity]bool, len(HuntSeverities))
	for i, severity := range HuntSeverities {
		if seen[severity] {
			t.Errorf("duplicate hunt severity %q", severity)
		}
		seen[severity] = true
		if parsed, ok := ParseSeverity(string(severity)); !ok || parsed != severity {
			t.Errorf("ParseSeverity(%q) = %q, %t", severity, parsed, ok)
		}
		if rank := severityRank(severity); rank != len(HuntSeverities)-i {
			t.Errorf("severityRank(%q) = %d, want %d", severity, rank, len(HuntSeverities)-i)
		}
	}
	if rank := severityRank("unknown"); rank != 0 {
		t.Errorf("severityRank(unknown) = %d, want 0", rank)
	}
	if severity, ok := ParseSeverity("unknown"); ok || severity != "" {
		t.Errorf("ParseSeverity(unknown) = %q, %t", severity, ok)
	}
}

func TestHuntSuggestionTaxonomy(t *testing.T) {
	for code, want := range map[string]struct {
		category string
		severity HuntSeverity
	}{
		SuggestTransientNotResampled: {FindingCoverageGap, SeverityMedium},
		SuggestTimelineInconsistent:  {FindingDiagnosticContradiction, SeverityHigh},
		"jitter_sampling_gap":        {FindingCoverageGap, SeverityLow},
		"gateway_unreachable":        {FindingCoverageGap, SeverityInfo},
	} {
		category, severity, ok := huntSuggestionClass(code)
		if !ok || category != want.category || severity != want.severity {
			t.Errorf("%s = %s/%s/%t", code, category, severity, ok)
		}
	}
}

func TestHuntFindingFingerprintExcludesCaseSpecificText(t *testing.T) {
	a := HuntCaseFinding{Category: FindingCoverageGap, Code: SuggestTransientNotResampled, Probe: "dns", Cause: "dns_timeout",
		Summary: "one", Evidence: "case 3 at 500ms"}
	b := a
	b.Summary, b.Evidence = "two", "case 99 at 700ms"
	if huntFindingFingerprint(a) != huntFindingFingerprint(b) {
		t.Error("case-specific prose changed finding fingerprint")
	}
	b.Cause = "temporary_failure"
	if huntFindingFingerprint(a) == huntFindingFingerprint(b) {
		t.Error("semantic cause change did not alter finding fingerprint")
	}
	b = a
	b.Family = "ipv6"
	if huntFindingFingerprint(a) == huntFindingFingerprint(b) {
		t.Error("family change did not alter finding fingerprint")
	}
	b = a
	b.Expected, b.Actual = "reachable", "unreachable"
	if huntFindingFingerprint(a) == huntFindingFingerprint(b) {
		t.Error("mismatch direction did not alter finding fingerprint")
	}
}

func TestHuntFamilyMismatchAggregatesByFamilyAndDirection(t *testing.T) {
	manifestA, manifestB := huntManifest(), huntManifest()
	manifestA.Case, manifestB.Case = 3, 8
	ipv4 := familyMismatchFindings(analyzeHuntCase(manifestA, familyDiagnosisReport("reachable", "reachable"),
		ObservedTruth{IPv4: "unreachable", IPv6: "reachable"}))
	ipv6 := familyMismatchFindings(analyzeHuntCase(manifestA, familyDiagnosisReport("reachable", "reachable"),
		ObservedTruth{IPv4: "reachable", IPv6: "unreachable"}))
	contradiction := familyMismatchFindings(analyzeHuntCase(manifestA, familyDiagnosisReport("unreachable", "reachable"),
		ObservedTruth{IPv4: "reachable", IPv6: "reachable"}))
	if len(ipv4) != 1 || len(ipv6) != 1 || len(contradiction) != 1 ||
		ipv4[0].Fingerprint == ipv6[0].Fingerprint || ipv4[0].Fingerprint == contradiction[0].Fingerprint {
		t.Fatalf("family/direction fingerprints collapsed: IPv4=%+v IPv6=%+v contradiction=%+v", ipv4, ipv6, contradiction)
	}
	repeated := ipv6[0]
	repeated.Reproduce = reproductionFor(manifestB)
	findings := aggregateHuntFindings([]HuntCaseResult{
		{Manifest: manifestA, Findings: ipv6},
		{Manifest: manifestB, Findings: []HuntCaseFinding{repeated}},
	})
	if len(findings) != 1 || findings[0].Occurrences != 2 || !reflect.DeepEqual(findings[0].ExampleCases, []int{3, 8}) {
		t.Fatalf("repeated family mismatch did not aggregate: %+v", findings)
	}
}

func TestHuntAggregatesFindingsAndSuggestions(t *testing.T) {
	manifestA, manifestB := huntManifest(), huntManifest()
	manifestA.Case, manifestB.Case = 3, 8
	makeFinding := func(manifest GeneratedCaseManifest) HuntCaseFinding {
		finding := HuntCaseFinding{Category: FindingCoverageGap, Severity: SeverityMedium, Code: SuggestTransientNotResampled,
			SuggestionCode: SuggestTransientNotResampled, Probe: "dns", Summary: "resample temporary DNS", Reproduce: reproductionFor(manifest)}
		finding.Fingerprint = huntFindingFingerprint(finding)
		return finding
	}
	cases := []HuntCaseResult{{Manifest: manifestA, Findings: []HuntCaseFinding{makeFinding(manifestA)}},
		{Manifest: manifestB, Findings: []HuntCaseFinding{makeFinding(manifestB)}}}
	findings := aggregateHuntFindings(cases)
	if len(findings) != 1 || findings[0].Occurrences != 2 || !reflect.DeepEqual(findings[0].ExampleCases, []int{3, 8}) {
		t.Fatalf("findings = %+v", findings)
	}
	suggestions := aggregateHuntSuggestions(findings)
	if len(suggestions) != 1 || suggestions[0].Code != SuggestTransientNotResampled || suggestions[0].Evidence != 2 {
		t.Fatalf("suggestions = %+v", suggestions)
	}
}

func TestRunHuntDryRunReproducesDirectCaseAndSkipsDuplicates(t *testing.T) {
	base := loadHuntBase(t, "healthy-routed-network")
	batch := RunHunt(context.Background(), "healthy-routed-network", base, nil, HuntOptions{
		Cases: 50, Seed: 12345, MaxFaults: 2, GeneratorVersion: "v5", Lane: HuntLaneAllOperators, DryRun: true})
	if batch.Result != HuntResultClean || batch.ExecutedCases != 0 || batch.GeneratedCases != 50 {
		t.Fatalf("batch = %+v", batch)
	}
	if batch.DuplicateCandidates == 0 {
		t.Fatal("test seed did not exercise duplicate-case suppression")
	}
	selected := batch.Cases[17]
	caseNumber := selected.Manifest.Case
	direct := RunHunt(context.Background(), "healthy-routed-network", base, nil,
		HuntOptions{Seed: 12345, Case: &caseNumber, MaxFaults: 2, GeneratorVersion: "v5", Lane: HuntLaneAllOperators, DryRun: true})
	if len(direct.Cases) != 1 || !reflect.DeepEqual(direct.Cases[0].Manifest, selected.Manifest) {
		t.Fatalf("direct manifest differs:\n%+v\n%+v", direct.Cases, selected.Manifest)
	}
	var text bytes.Buffer
	direct.WriteText(&text)
	if !strings.Contains(text.String(), selected.Manifest.CaseFingerprint) || strings.Contains(text.String(), "tc qdisc") {
		t.Errorf("dry report = %s", text.String())
	}
}

func TestRunHuntUsesTheSelectedGeneratorVersion(t *testing.T) {
	base := loadHuntBase(t, "healthy-routed-network")
	caseNumber := 76
	opts := HuntOptions{Seed: 12345, Case: &caseNumber, MaxFaults: 2, GeneratorVersion: "v3", DryRun: true}
	first := RunHunt(context.Background(), "healthy-routed-network", base, nil, opts)
	second := RunHunt(context.Background(), "healthy-routed-network", base, nil, opts)
	if first.Result != HuntResultClean || first.GeneratorVersion != "v3" || len(first.Cases) != 1 {
		t.Fatalf("historical hunt = %+v", first)
	}
	if got := first.Cases[0].Manifest; got.GeneratorVersion != "v3" || got.CaseFingerprint != "3b23592ff5c01fd9" {
		t.Fatalf("historical manifest = %+v", got)
	}
	if !reflect.DeepEqual(first.Cases[0].Manifest, second.Cases[0].Manifest) {
		t.Fatal("the historical generator did not reproduce the same case")
	}

	defaults := RunHunt(context.Background(), "healthy-routed-network", base, nil,
		HuntOptions{Seed: 12345, Case: &caseNumber, MaxFaults: 2, DryRun: true})
	if defaults.GeneratorVersion != HuntGeneratorVersion ||
		defaults.Cases[0].Manifest.GeneratorVersion != HuntGeneratorVersion {
		t.Fatalf("default generator = result %q manifest %q, want %q", defaults.GeneratorVersion,
			defaults.Cases[0].Manifest.GeneratorVersion, HuntGeneratorVersion)
	}
	if HuntGeneratorVersion != "v3" &&
		defaults.Cases[0].Manifest.CaseFingerprint == first.Cases[0].Manifest.CaseFingerprint {
		t.Fatal("different generator versions produced the same case identity")
	}
}

func TestRunHuntRejectsUnknownGeneratorVersion(t *testing.T) {
	result := RunHunt(context.Background(), "healthy", loadHuntBase(t, "healthy"), nil,
		HuntOptions{Cases: 1, GeneratorVersion: "v999", DryRun: true})
	if result.Result != HuntResultError || result.ErrorKind != "configuration" ||
		!strings.Contains(result.Error, "unknown hunt generator version") {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunHuntFailFastStopsAfterFirstFinding(t *testing.T) {
	base := loadHuntBase(t, "healthy-routed-network")
	seed := int64(0)
	// Keep this lifecycle unit test fast by choosing a first candidate without a
	// delayed timeline. Cleanup failure itself supplies the finding.
	for ; seed < 10000; seed++ {
		generated, err := generateHuntCase(HuntGeneratorVersion, "healthy-routed-network", base, seed, 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(generated.Manifest.Mutations[0].ID, "timeline.") && generated.Manifest.Mutations[0].ID != "link.transient_down" {
			break
		}
	}
	result := RunHunt(context.Background(), "healthy-routed-network", base, func() Backend {
		return &fakeBackend{caps: supported(), env: &fakeEnv{stdout: okReport, cleanupErrors: []string{"left bridge"}}}
	}, HuntOptions{Cases: 10, Seed: seed, MaxFaults: 1, FailFast: true, Run: Options{Netdoc: "netdoc"}})
	if !result.FailFastStopped || result.ExecutedCases != 1 || len(result.Findings) == 0 || !result.RuntimeFailure {
		t.Fatalf("result = %+v", result)
	}
	if item := result.Cases[0]; item.TruthFingerprint != "" || item.DiagnosisFingerprint.ID != "" {
		t.Errorf("runtime failure analyzed incomplete evidence: %+v", item)
	}
}

func TestHuntAnalysisStopsAfterRuntimeFailure(t *testing.T) {
	manifest := huntManifest(GeneratedMutation{ID: "dns.drop", Service: "r"})
	report := &Report{Cleanup: CleanupInfo{Errors: []string{"evidence recorder failed"}},
		Tests: []TestOutcome{{StartOffset: 0, EndOffset: time.Second,
			Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "dns", Status: "PASS"}}}}},
		Evidence: Evidence{DNSQueries: []DNSQueryEvidence{{Service: "r", ActualOutcome: "DROPPED", Offset: time.Millisecond, OffsetKnown: true}}}}
	findings := analyzeHuntCase(manifest, report, collectObservedTruth(manifest, report))
	if len(findings) != 1 || findings[0].Code != "simulation_cleanup_failed" {
		t.Fatalf("findings from incomplete evidence = %+v", findings)
	}
}

// A hunt that could not run says so in one sentence, and the sentence names
// the reason. The per-case report is where the runner records it, and a caller
// that prints only the summary, the nightly triage, used to get "runtime" and
// nothing else, which is a failure nobody can act on from a CI log.
func TestRunHuntReportsWhyACaseFailed(t *testing.T) {
	base := loadHuntBase(t, "healthy-routed-network")
	result := RunHunt(context.Background(), "healthy-routed-network", base, func() Backend {
		return &fakeBackend{caps: supported(), env: &fakeEnv{stdout: okReport,
			faultErr: errors.New("this tc has no `netem seed`")}}
	}, HuntOptions{Cases: 1, Seed: 7, MaxFaults: 1, Run: Options{Netdoc: "netdoc"}})
	if result.Result != HuntResultError || result.ErrorKind != "runtime" {
		t.Fatalf("result = %s, kind = %s", result.Result, result.ErrorKind)
	}
	if !strings.Contains(result.Error, "netem seed") || !strings.Contains(result.Error, "case 0") {
		t.Errorf("error = %q, want the failing case and its reason", result.Error)
	}
	var text bytes.Buffer
	result.WriteText(&text)
	if !strings.Contains(text.String(), "netem seed") {
		t.Errorf("report = %s", text.String())
	}
}

// A hunt runs each case exactly once and makes no reproducibility claim, so a
// repeat suggestion must never reach a finding through it. The mechanism that
// used to produce one compared a cold netdoc run against a warm one inside the
// same live topology, which reported the cost of a first packet as netdoc
// drifting. This pins the decision rather than the absence: if repeats are ever
// wired back in, they have to answer the cold-versus-warm question first.
func TestHuntRunsEachCaseOnceAndMakesNoReproducibilityClaim(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	env := &fakeEnv{stdout: okReport}
	result := RunHunt(context.Background(), "healthy", base, func() Backend {
		return &fakeBackend{caps: supported(), env: env}
	}, HuntOptions{Cases: 3, Seed: 20260101, MaxFaults: 2, Run: Options{Netdoc: "netdoc"}})
	if result.ExecutedCases != 3 {
		t.Fatalf("executed %d cases, want 3", result.ExecutedCases)
	}
	for _, item := range result.Cases {
		for _, test := range item.Report.Tests {
			if len(test.RepeatVerdicts) != 0 {
				t.Errorf("case %d ran netdoc more than once: %v", item.Manifest.Case, test.RepeatVerdicts)
			}
		}
	}
	// And the suggestion has no route into a finding even if a report arrives
	// carrying one, since nothing in a hunt is entitled to raise it.
	report := &Report{Cleanup: CleanupInfo{Done: true},
		Topology: []NodeInfo{{Name: "client", Role: "client"}},
		Tests: []TestOutcome{{Name: "netdoc", Node: "client", ProcessOutcome: ProcessExited,
			Diagnosis: &Diagnosis{Verdict: "ok", Checks: []DiagnosisCheck{{ID: "dns", Status: "PASS"}}}}}}
	if len(report.Tests[0].suggest()) != 0 {
		t.Fatalf("a single run produced repeat suggestions: %+v", report.Tests[0].suggest())
	}
}

func TestRunRecordsWholeProcessOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  *fakeEnv
		want string
	}{
		{"timeout", &fakeEnv{timedOut: true}, ProcessTimedOut},
		{"cancel", &fakeEnv{cancelled: true}, ProcessCancelled},
		{"signal", &fakeEnv{signal: "segmentation fault"}, ProcessSignaled},
		{"exec", &fakeEnv{execCtxErr: context.Canceled}, ProcessExecError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := Run(context.Background(), testScenario(t), &fakeBackend{caps: supported(), env: tc.env}, Options{Netdoc: "netdoc"})
			if got := rep.Tests[0].ProcessOutcome; got != tc.want {
				t.Errorf("outcome = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAnalyzeEmitsExecutionFindingCategories pins the categories that describe
// how a run failed rather than what the network was. The oracle tests cover the
// evidence-backed categories; together they leave no category that analysis
// cannot actually emit.
func TestAnalyzeEmitsExecutionFindingCategories(t *testing.T) {
	manifest := huntManifest(GeneratedMutation{ID: "dns.drop", Service: "r"})
	done := CleanupInfo{Done: true}
	for _, tc := range []struct {
		name   string
		report *Report
		want   string
	}{
		{"run failed", &Report{Error: "netns setup failed", Cleanup: done}, FindingSimulatorFailure},
		{"cleanup failed", &Report{Cleanup: CleanupInfo{Errors: []string{"left bridge"}}}, FindingCleanupFailure},
		{"scheduled fault failed", &Report{Cleanup: done,
			Timeline: []FaultEventEvidence{{Result: EventFailed, Error: "tc busy"}}}, FindingSimulatorFailure},
		{"process deadline", &Report{Cleanup: done,
			Tests: []TestOutcome{{ProcessOutcome: ProcessTimedOut}}}, FindingNetdocHang},
		{"process signaled", &Report{Cleanup: done,
			Tests: []TestOutcome{{ProcessOutcome: ProcessSignaled, Signal: "segmentation fault"}}}, FindingNetdocCrash},
		{"process cancelled", &Report{Cleanup: done,
			Tests: []TestOutcome{{ProcessOutcome: ProcessCancelled}}}, FindingSimulatorFailure},
		{"exec error", &Report{Cleanup: done,
			Tests: []TestOutcome{{ProcessOutcome: ProcessExecError, Error: "netdoc not found"}}}, FindingUnexpectedRuntimeError},
		{"invalid report", &Report{Cleanup: done,
			Tests: []TestOutcome{{ProcessOutcome: ProcessExited, Error: "bad json"}}}, FindingUnexpectedRuntimeError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := analyzeHuntCase(manifest, tc.report, collectObservedTruth(manifest, tc.report))
			if len(findings) != 1 || findings[0].Category != tc.want {
				t.Fatalf("findings = %+v, want one %s", findings, tc.want)
			}
		})
	}
}

// TestHuntReportsGeneratorDefect covers the one category analysis never emits:
// the hunt loop reports it when case generation itself fails.
func TestHuntReportsGeneratorDefect(t *testing.T) {
	result := RunHunt(context.Background(), "no-such-base", nil, nil, HuntOptions{Cases: 1, DryRun: true})
	if result.Result != HuntResultError || result.ErrorKind != FindingGeneratorDefect {
		t.Fatalf("result = %s, kind = %s, err = %s", result.Result, result.ErrorKind, result.Error)
	}
}

// clientRoleEnv is fakeEnv with the one thing the condition oracle needs that
// the shared fake does not say: which node is the client. Conditions about a
// node's own kernel cannot be read without it.
type clientRoleEnv struct{ *fakeEnv }

func (e clientRoleEnv) Nodes() []NodeInfo {
	return []NodeInfo{{Name: "client", Role: "client", Address: "10.77.0.10"}}
}

type clientRoleBackend struct{ env *fakeEnv }

func (b *clientRoleBackend) Capabilities(context.Context) Capabilities { return supported() }

func (b *clientRoleBackend) Prepare(context.Context, *Scenario, string) (Env, error) {
	return clientRoleEnv{b.env}, nil
}

// deadRouteEvidence is what a node holder writes down for a client whose only
// default route was deleted: the table read back holding one on-link route and
// no default, and the client's own dial of the controlled IPv4 endpoints not
// completing. Nothing here is derived from a diagnosis.
func deadRouteEvidence() Evidence {
	return Evidence{
		RouteTables: []RouteTableEvidence{{Node: "client", Family: "ipv4",
			Routes: []KernelRoute{{Destination: "10.77.0.0/24", Segment: "lan"}}}},
		FamilyReachability: []FamilyReachabilityEvidence{{Node: "client", Family: "ipv4",
			State: FamilyStateUnreachable}},
		ControlledTargets: []ControlledTargetEvidence{},
	}
}

// A netdoc that blames the gateway for a route the user deleted: stable across
// runs, structurally valid, and materially wrong, since it sends the reader to
// look at hardware instead of at one missing line in their own routing table.
const blamesTheGatewayReport = `{"checks":[{"id":"internet_tcp","status":"WARN","cause":"gateway_unreachable",` +
	`"detail":"d","address_families":{"IPv4":"unreachable","IPv6":"unavailable"}}],"verdict":"network","summary":"s"}`

// The same run with the one thing that makes it right: netdoc's own cause for
// the route being gone.
const namesTheMissingRouteReport = `{"checks":[{"id":"internet_tcp","status":"WARN","cause":"no_default_route",` +
	`"detail":"d","address_families":{"IPv4":"unreachable","IPv6":"unavailable"}}],"verdict":"network","summary":"s"}`

// This is the whole point of the hunt, exercised through the pipeline a nightly
// run actually uses rather than against the oracle alone: a wrong diagnosis of
// a condition the simulator established on its own becomes a finding, the same
// run with the right diagnosis becomes nothing, and the finding is reproducible
// from the coordinates it publishes. The last part is the one that matters
// most in practice, because a finding a single-case replay cannot produce can
// never be filed however real the defect behind it is.
func TestWrongDiagnosisOfAnObservedConditionBecomesAReproducibleFinding(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	// A case that deletes the client's only default route and leaves the
	// network otherwise still, so the final state is comparable.
	const caseNumber = 18
	generated, err := generateHuntCase(HuntGeneratorVersion, "healthy", base, 20260101, caseNumber, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Manifest.Mutations) != 1 || generated.Manifest.Mutations[0].ID != "routing.no_default_route" {
		t.Fatalf("case %d is %+v, want the sole no_default_route case this test is written against",
			caseNumber, generated.Manifest.Mutations)
	}

	hunt := func(report string, cases int, only *int) *HuntResult {
		return RunHunt(context.Background(), "healthy", base, func() Backend {
			return &clientRoleBackend{env: &fakeEnv{stdout: report, evidence: deadRouteEvidence()}}
		}, HuntOptions{Cases: cases, Seed: 20260101, Case: only, MaxFaults: 2, Run: Options{Netdoc: "netdoc"}})
	}
	missed := func(result *HuntResult) *HuntFinding {
		for i, finding := range result.Findings {
			if finding.Code == "unrecognized_network_condition" && finding.Expected == string(ConditionNoDefaultRoute) {
				return &result.Findings[i]
			}
		}
		return nil
	}

	only := caseNumber
	wrong := hunt(blamesTheGatewayReport, 1, &only)
	finding := missed(wrong)
	if finding == nil {
		t.Fatalf("a wrong diagnosis of an observed condition produced no finding: %+v", wrong.Findings)
	}
	if finding.Severity != SeverityHigh || finding.Category != FindingFalseNegative {
		t.Errorf("finding = %s/%s, want %s/%s", finding.Category, finding.Severity,
			FindingFalseNegative, SeverityHigh)
	}
	// The coordinates a filed issue would print have to name this experiment
	// completely, ceiling included.
	repro := finding.Reproduce
	if repro.BaseScenario != "healthy" || repro.Seed != 20260101 || repro.Case != caseNumber ||
		repro.MaxFaults != 2 || repro.CaseFingerprint != generated.Manifest.CaseFingerprint {
		t.Errorf("reproduction = %+v, want the coordinates of case %d", repro, caseNumber)
	}

	// The right diagnosis of the same network, from the same evidence.
	if right := hunt(namesTheMissingRouteReport, 1, &only); missed(right) != nil {
		t.Errorf("the correct diagnosis was accused anyway: %+v", right.Findings)
	}

	// Replay: the finding has to survive being regenerated from its own
	// published coordinates as a single case, which is what triage requires
	// before it files anything. A finding that only exists when siblings are
	// present is unfilable by construction.
	replay := hunt(blamesTheGatewayReport, 1, &repro.Case)
	again := missed(replay)
	if again == nil || again.Fingerprint != finding.Fingerprint {
		t.Fatalf("replay of case %d did not reproduce fingerprint %s: %+v",
			repro.Case, finding.Fingerprint, replay.Findings)
	}
	if replay.Cases[0].Manifest.CaseFingerprint != generated.Manifest.CaseFingerprint {
		t.Errorf("replay regenerated case fingerprint %s, want %s",
			replay.Cases[0].Manifest.CaseFingerprint, generated.Manifest.CaseFingerprint)
	}
}

// Every finding a batch hunt can raise has to be raisable by a single case,
// because a single case is all the reproduction step ever re-runs. A finding
// that needs its siblings is reported and then permanently unfilable, which is
// worse than not raising it: it consumes a whole simulated run per night to
// conclude nothing.
func TestEveryBatchFindingIsReachableFromItsOwnCase(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	env := func() Backend {
		return &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport, evidence: deadRouteEvidence()}}
	}
	batch := RunHunt(context.Background(), "healthy", base, env,
		HuntOptions{Cases: 8, Seed: 20260101, MaxFaults: 2, Run: Options{Netdoc: "netdoc"}})
	if len(batch.Findings) == 0 {
		t.Fatal("the batch hunt raised nothing, so this test proves nothing")
	}
	for _, finding := range batch.Findings {
		caseNumber := finding.Reproduce.Case
		single := RunHunt(context.Background(), "healthy", base, env,
			HuntOptions{Cases: 1, Seed: 20260101, Case: &caseNumber, MaxFaults: 2, Run: Options{Netdoc: "netdoc"}})
		if !slices.ContainsFunc(single.Findings, func(f HuntFinding) bool { return f.Fingerprint == finding.Fingerprint }) {
			t.Errorf("%s (%s) was raised by the batch on case %d but not by that case on its own;"+
				" it can never be filed", finding.Code, finding.Fingerprint, caseNumber)
		}
	}
}
