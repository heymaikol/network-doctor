package simulation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

type HuntSeverity string

const (
	SeverityCritical HuntSeverity = "critical"
	SeverityHigh     HuntSeverity = "high"
	SeverityMedium   HuntSeverity = "medium"
	SeverityLow      HuntSeverity = "low"
	SeverityInfo     HuntSeverity = "info"
)

// HuntSeverities is the hunt severity vocabulary, most severe first.
var HuntSeverities = []HuntSeverity{
	SeverityCritical,
	SeverityHigh,
	SeverityMedium,
	SeverityLow,
	SeverityInfo,
}

// Finding categories name what kind of disagreement a case produced. A category
// the oracle cannot establish from independent evidence is not a category, and
// there is deliberately no catch-all. "Network Doctor claimed a fault the
// network did not have" belongs to FindingDiagnosticContradiction, where the
// finding still names which dimension disagreed, and a probe that spent its
// deadline is either the correct diagnosis of an injected fault, a whole-process
// hang (FindingNetdocHang), or harness failure (FindingSimulatorFailure), never
// a kind of its own.
//
// FindingDiagnosticInstability is the one a hunt never reaches on its own. It
// classifies a repeat suggestion, and a hunt runs each case once because two
// runs inside one live topology are not the same experiment. It stays defined
// so a caller who does ask for repeats, or a campaign report read through this
// taxonomy, lands somewhere honest.
const (
	FindingFalseNegative           = "comparison_false_negative"
	FindingDiagnosticInstability   = "diagnostic_instability"
	FindingDiagnosticContradiction = "diagnostic_contradiction"
	FindingCoverageGap             = "coverage_gap"
	FindingUnexpectedRuntimeError  = "unexpected_runtime_error"
	FindingNetdocCrash             = "netdoc_crash"
	FindingNetdocHang              = "netdoc_hang"
	FindingCleanupFailure          = "cleanup_failure"
	FindingSimulatorFailure        = "simulator_failure"
	FindingGeneratorDefect         = "generator_defect"
)

// dnsServedSERVFAIL and dnsServedDropped are the resolver's own words for what
// it put on the wire, which is a different vocabulary from the scheduler's
// outcome names: one describes an answer a client received, the other a state
// the service was asked to enter.
const (
	dnsServedSERVFAIL = "SERVFAIL"
	dnsServedDropped  = "DROPPED"
)

// ObservedTruth is deliberately coarse. It records only simulator evidence,
// not conclusions inferred from the mutation request or copied from netdoc.
// IPv4 and IPv6 describe point-in-time reachability when final evidence was
// collected, after the diagnostic run and fault scheduler had stopped.
type ObservedTruth struct {
	DNS            string   `json:"dns"`
	IPv4           string   `json:"ipv4"`
	IPv6           string   `json:"ipv6"`
	Gateway        string   `json:"gateway"`
	Proxy          string   `json:"proxy"`
	TLS            string   `json:"tls"`
	TCP            string   `json:"tcp"`
	Link           string   `json:"link"`
	Packet         string   `json:"packet"`
	Route          string   `json:"route"`
	ObservedFaults []string `json:"observed_faults"`
}

type HuntReproduction struct {
	BaseScenario string   `json:"base_scenario"`
	Lane         HuntLane `json:"lane,omitempty"`
	Seed         int64    `json:"seed"`
	Case         int      `json:"case"`
	CaseSeed     int64    `json:"case_seed"`
	// MaxFaults is the ceiling the case was drawn under. Without it the visible
	// coordinates below name a different experiment under a different ceiling,
	// so it is part of the reproduction rather than a run preference.
	MaxFaults        int    `json:"max_faults"`
	GeneratorVersion string `json:"generator_version"`
	CaseFingerprint  string `json:"case_fingerprint"`
}

type HuntCaseFinding struct {
	Fingerprint    string           `json:"fingerprint"`
	Category       string           `json:"category"`
	Severity       HuntSeverity     `json:"severity"`
	Code           string           `json:"code"`
	SuggestionCode string           `json:"suggestion_code,omitempty"`
	Probe          string           `json:"probe,omitempty"`
	Expected       string           `json:"expected,omitempty"`
	Actual         string           `json:"actual,omitempty"`
	Cause          string           `json:"cause,omitempty"`
	Family         string           `json:"family,omitempty"`
	Summary        string           `json:"summary"`
	Evidence       string           `json:"evidence,omitempty"`
	Reproduce      HuntReproduction `json:"reproduce"`
}

type HuntFinding struct {
	Fingerprint    string           `json:"fingerprint"`
	Category       string           `json:"category"`
	Severity       HuntSeverity     `json:"severity"`
	Code           string           `json:"code"`
	SuggestionCode string           `json:"suggestion_code,omitempty"`
	Probe          string           `json:"probe,omitempty"`
	Expected       string           `json:"expected,omitempty"`
	Actual         string           `json:"actual,omitempty"`
	Cause          string           `json:"cause,omitempty"`
	Family         string           `json:"family,omitempty"`
	Summary        string           `json:"summary"`
	Evidence       string           `json:"evidence,omitempty"`
	Occurrences    int              `json:"occurrences"`
	FirstCase      int              `json:"first_case"`
	ExampleCases   []int            `json:"example_cases"`
	Reproduce      HuntReproduction `json:"reproduce"`
}

func severityRank(severity HuntSeverity) int {
	index := slices.Index(HuntSeverities, severity)
	if index < 0 {
		return 0
	}
	return len(HuntSeverities) - index
}

func collectObservedTruth(manifest GeneratedCaseManifest, report *Report) ObservedTruth {
	truth := ObservedTruth{DNS: "unknown", IPv4: "unknown", IPv6: "unknown", Gateway: "unknown",
		Proxy: "unknown", TLS: "unknown", TCP: "unknown", Link: "unknown", Packet: "unknown", Route: "unknown"}
	if report == nil {
		truth.ObservedFaults = []string{}
		return truth
	}
	truth.IPv4 = observedFamilyTruth(report, "ipv4")
	truth.IPv6 = observedFamilyTruth(report, "ipv6")
	answered, dnsFailed := false, false
	for _, query := range report.Evidence.DNSQueries {
		switch query.ActualOutcome {
		case "ANSWER", "NODATA":
			answered = true
		case dnsServedDropped, dnsServedSERVFAIL:
			dnsFailed = true
		}
	}
	switch {
	case answered && dnsFailed:
		truth.DNS = "mixed"
	case dnsFailed:
		truth.DNS = "unavailable"
	case answered:
		truth.DNS = "available"
	}
	selectedRoute := false
	for _, route := range report.Evidence.Routes {
		if !route.Selected {
			continue
		}
		selectedRoute = true
		truth.Route = "selected"
		if route.GatewayReachable != nil {
			if *route.GatewayReachable {
				truth.Gateway = "reachable"
			} else {
				truth.Gateway = "unreachable"
			}
		}
	}
	if !selectedRoute && len(report.Evidence.Routes) > 0 {
		truth.Route = "not_selected"
	}
	if len(report.Evidence.SOCKSRequests) > 0 {
		truth.Proxy = "reached"
		for _, item := range report.Evidence.SOCKSRequests {
			if item.Event == "connect" && item.Result != "connected" {
				truth.Proxy = "failed"
			}
		}
	}
	if len(report.Evidence.TLS) > 0 {
		truth.TLS = "observed"
		for _, item := range report.Evidence.TLS {
			if item.Result != "passed" {
				truth.TLS = "failed"
			}
		}
	}
	if anyConnectionReset(report.Evidence) {
		truth.TCP = "reset"
	}
	linkDown, linkRecovered := false, false
	for _, event := range report.Timeline {
		if event.Result != EventApplied || event.Event.Type != FaultScheduledLink {
			continue
		}
		if event.Event.State == LinkStateDown {
			linkDown = true
		}
		if linkDown && event.Event.State == LinkStateUp {
			linkRecovered = true
		}
	}
	switch {
	case linkRecovered:
		truth.Link = "transient_loss"
	case linkDown:
		truth.Link = "down"
	default:
		for _, link := range report.Evidence.Links {
			if !link.Up {
				truth.Link = "down"
				break
			}
		}
		if truth.Link == "unknown" && len(report.Evidence.Links) > 0 {
			truth.Link = "up"
		}
	}
	packetActive, packetDropped := false, false
	for _, condition := range report.Evidence.PacketConditions {
		packetActive = packetActive || condition.Active
		packetDropped = packetDropped || condition.DroppedPackets > 0
	}
	switch {
	case packetDropped:
		truth.Packet = "drops_observed"
	case packetActive:
		truth.Packet = "impairment_active"
	}
	for _, mutation := range manifest.Mutations {
		if mutationObserved(mutation, report, truth) {
			truth.ObservedFaults = append(truth.ObservedFaults, mutation.ID)
		}
	}
	sort.Strings(truth.ObservedFaults)
	if truth.ObservedFaults == nil {
		truth.ObservedFaults = []string{}
	}
	return truth
}

// observedFamilyTruth reads the one measured record for this family and repeats
// its state. It invents nothing: no record means no observation was taken, and
// an unobserved family is unknown, not unavailable: only the holder-side probe
// gets to say a family was absent. Two records leave no single answer.
func observedFamilyTruth(report *Report, family string) string {
	client := observedClient(report)
	if client == "" {
		return "unknown"
	}
	state := "unknown"
	for _, observation := range report.Evidence.FamilyReachability {
		if observation.Node != client || observation.Family != family {
			continue
		}
		if state != "unknown" {
			return "unknown"
		}
		switch observation.State {
		case FamilyStateReachable, FamilyStateUnreachable, FamilyStateUnavailable:
			state = observation.State
		default:
			return "unknown"
		}
	}
	return state
}

func observedClient(report *Report) string {
	client := ""
	for _, node := range report.Topology {
		if node.Role != "client" {
			continue
		}
		if client != "" {
			return ""
		}
		client = node.Name
	}
	return client
}

func mutationObserved(mutation GeneratedMutation, report *Report, truth ObservedTruth) bool {
	switch mutation.ID {
	case "netem.loss", "netem.latency", "netem.jitter":
		for _, condition := range report.Evidence.PacketConditions {
			if !sameName(mutation.Node, condition.Node) || !sameName(mutation.Segment, condition.Segment) || !condition.Active {
				continue
			}
			latency := time.Duration(mutation.LatencyMS) * time.Millisecond
			jitter := time.Duration(mutation.JitterMS) * time.Millisecond
			if condition.Latency == latency && condition.Jitter == jitter &&
				condition.LossPercent == mutation.LossPercent && condition.Seed == mutation.NetemSeed {
				return true
			}
		}
	case "timeline.netem_spike":
		return timelineApplied(report, func(event TimedEvent) bool {
			return event.Type == FaultScheduledNetem && sameName(mutation.Node, event.Node) && sameName(mutation.Segment, event.Segment) &&
				event.Offset == time.Duration(mutation.StartMS)*time.Millisecond &&
				event.Latency == time.Duration(mutation.LatencyMS)*time.Millisecond &&
				event.Jitter == time.Duration(mutation.JitterMS)*time.Millisecond &&
				event.LossPercent == mutation.LossPercent && event.NetemSeed == mutation.NetemSeed
		})
	// The DNS families want both halves. The timeline says this exact scheduled
	// fault reached the resolver, and the resolver's per-query record says a
	// client was actually served the faulty outcome, since a resolver moved into
	// SERVFAIL that nobody queried refused nobody.
	case "dns.servfail", "dns.drop":
		outcome, served := DNSOutcomeSERVFAIL, dnsServedSERVFAIL
		if mutation.ID == "dns.drop" {
			outcome, served = DNSOutcomeDrop, dnsServedDropped
		}
		return timelineApplied(report, func(event TimedEvent) bool {
			return event.Type == FaultScheduledDNS && sameName(mutation.Service, event.Service) &&
				event.Offset == 0 && event.Outcome == outcome
		}) && dnsOutcomeServedAt(report.Evidence, mutation.Service, served)
	case "timeline.dns_outage":
		return timelineApplied(report, func(event TimedEvent) bool {
			return event.Type == FaultScheduledDNS && sameName(mutation.Service, event.Service) &&
				event.Offset == time.Duration(mutation.StartMS)*time.Millisecond && event.Outcome == DNSOutcomeDrop
		}) && dnsOutcomeServedAt(report.Evidence, mutation.Service, dnsServedDropped)
	case "service.tcp_reset":
		return connectionResetAt(report.Evidence, mutation.Node)
	case "service.tls_expired":
		return expiredCertificateRejectedAt(report.Evidence, mutation.Node, mutation.Service)
	case "proxy.connect_refused":
		return proxyCONNECTRefusedAt(report.Evidence, mutation.Node, mutation.Service, proxyCONNECTTarget, mutation.TargetPort)
	case "quic.udp_443_block":
		return udpPortDroppedAt(report.Evidence, mutation.Node, mutation.TargetPort)
	case "encrypted_dns.doh_invalid":
		return invalidDoHServedAt(report.Evidence, mutation.Node, mutation.Service)
	case "http.status_503":
		return httpStatusServedAt(report.Evidence, mutation.Node, mutation.TargetPort, mutation.Status)
	// The family drops are measured at the client rather than at the node the
	// rule was installed on, because losing a family is a fact about what the
	// client can still reach. observedFamilyTruth already required the record to
	// name that client, so there is no scope left for the mutation to add.
	case "family.ipv4_drop":
		return truth.IPv4 == FamilyStateUnreachable
	case "family.ipv6_drop":
		return truth.IPv6 == FamilyStateUnreachable
	case "link.transient_down":
		return timelineApplied(report, func(event TimedEvent) bool {
			return event.Type == FaultScheduledLink && sameName(mutation.Node, event.Node) &&
				sameName(mutation.Segment, event.Segment) && event.Offset == 0 && event.State == LinkStateDown
		})
	case "routing.preferred_path_failure":
		return preferredPathFailureObserved(mutation, report)
	// The refusal and the filter are one another's negative. Each demands the
	// evidence that rules the other out, so no run can satisfy both and neither
	// can be established by a dial that merely failed.
	case "service.connection_refused":
		outcome, observed := controlledTargetOutcome(report.Evidence, observedClient(report), mutation.TargetEndpoint)
		return observed && outcome == TargetStateRefused && !tcpPortDroppedAt(report.Evidence, mutation.Node, mutation.TargetPort)
	case "service.tcp_port_blocked":
		outcome, observed := controlledTargetOutcome(report.Evidence, observedClient(report), mutation.TargetEndpoint)
		return observed && outcome == FamilyStateUnreachable && tcpPortDroppedAt(report.Evidence, mutation.Node, mutation.TargetPort)
	case "service.tls_hostname_mismatch":
		return mismatchedCertificateRejectedAt(report.Evidence, mutation.Node, mutation.Service)
	case "routing.no_default_route":
		return noDefaultRouteObserved(mutation, report)
	case "routing.wrong_default_route":
		return wrongDefaultRouteObserved(mutation, report)
	case "routing.missing_subnet_route":
		return missingSubnetRouteObserved(mutation, report)
	// A black hole is a size asymmetry, so both halves are read back off the
	// kernel: the hop really carries the narrowed MTU, and the client's own link
	// is still wider than it, which is what leaves the client offering packets
	// that hop cannot forward. A narrowed hop on its own is a small link, and a
	// small link is discovered and worked around rather than black-holed. The
	// suppressed fragmentation-needed replies are deliberately not claimed here:
	// that rule keeps no counter, so nothing independent says it matched.
	case "pmtu.blackhole":
		return sameNumber(mutation.MTU, linkMTUAt(report.Evidence, mutation.Node, mutation.Segment)) &&
			wideLinkAt(report.Evidence, mutation.TargetNode, mutation.MTU)
	}
	return false
}

// linkMTUAt is the MTU one node's kernel reported for one segment. Zero when no
// such link was read, which no scoped question can match.
func linkMTUAt(evidence Evidence, node, segment string) int {
	for _, link := range evidence.Links {
		if sameName(node, link.Node) && sameName(segment, link.Segment) {
			return link.MTU
		}
	}
	return 0
}

// wideLinkAt reports whether this node still holds a link wider than the
// narrowed hop. It is the other half of the asymmetry, read at the endpoint
// rather than at the hop.
func wideLinkAt(evidence Evidence, node string, mtu int) bool {
	return mtu > 0 && slices.ContainsFunc(evidence.Links, func(link LinkEvidence) bool {
		return sameName(node, link.Node) && link.MTU > mtu
	})
}

// noDefaultRouteObserved wants the table to be empty of defaults and the family
// those defaults served to be dead. The table alone is a configuration reading;
// the reachability alongside it is what says the missing route mattered.
func noDefaultRouteObserved(mutation GeneratedMutation, report *Report) bool {
	routes, read := kernelRouteTable(report.Evidence, mutation.Node, mutation.Family)
	return read && len(defaultRoutesIn(routes)) == 0 &&
		familyStateAt(report, mutation.Node, mutation.Family) == FamilyStateUnreachable
}

// wrongDefaultRouteObserved is the one family where "the family is unreachable"
// is nowhere near enough: a downstream outage looks identical from the client.
// What makes it a wrong turn rather than a broken path is the control endpoint,
// reached over its own specific route through the next hop the default used
// to name, still answering. That proves the original gateway forwards, the
// network beyond it works, and the only thing that changed is where the default
// points.
func wrongDefaultRouteObserved(mutation GeneratedMutation, report *Report) bool {
	if mutation.RouteVia == "" || mutation.PreferredVia == "" || mutation.RouteVia == mutation.PreferredVia ||
		mutation.ControlTarget == "" {
		return false
	}
	routes, read := kernelRouteTable(report.Evidence, mutation.Node, mutation.Family)
	if !read {
		return false
	}
	defaults := defaultRoutesIn(routes)
	if len(defaults) != 1 || defaults[0].Via != mutation.RouteVia || !sameName(mutation.PreferredSegment, defaults[0].Segment) {
		return false
	}
	// A next hop that does not answer is an unreachable gateway, which is a
	// different fault with a different fix.
	if !selectedGatewayReachable(report, mutation.Node, mutation.Family, mutation.RouteVia) {
		return false
	}
	outcome, observed := controlledTargetOutcome(report.Evidence, mutation.Node, mutation.ControlTarget)
	return observed && outcome == FamilyStateReachable &&
		controlReachedVia(report, mutation.Node, mutation.ControlTarget, mutation.PreferredVia) &&
		familyStateAt(report, mutation.Node, mutation.Family) == FamilyStateUnreachable
}

// missingSubnetRouteObserved proves the route-specific defect rather than the
// target simply being unreachable: no route but the default covers the briefed
// address, that address does not answer, and the internet the default carries
// is still fine. The last clause is what stops a dead default from wearing this
// name.
func missingSubnetRouteObserved(mutation GeneratedMutation, report *Report) bool {
	if mutation.TargetEndpoint == "" || mutation.RouteDestination == "" || defaultDestination(mutation.RouteDestination) {
		return false
	}
	routes, read := kernelRouteTable(report.Evidence, mutation.Node, mutation.Family)
	if !read || len(defaultRoutesIn(routes)) == 0 {
		return false
	}
	address, _, found := strings.Cut(mutation.TargetEndpoint, ":")
	if !found || specificRouteCovering(routes, address) {
		return false
	}
	outcome, observed := controlledTargetOutcome(report.Evidence, mutation.Node, mutation.TargetEndpoint)
	if !observed || outcome == FamilyStateReachable {
		return false
	}
	control, controlObserved := controlledTargetOutcome(report.Evidence, mutation.Node, mutation.ControlTarget)
	return controlObserved && control == FamilyStateReachable &&
		familyStateAt(report, mutation.Node, mutation.Family) == FamilyStateReachable
}

// familyStateAt repeats the one measured record for this node and family, and
// invents nothing: no record, or two that disagree, is unknown.
func familyStateAt(report *Report, node, family string) string {
	state := ""
	for _, item := range report.Evidence.FamilyReachability {
		if !sameName(node, item.Node) || !sameName(family, item.Family) {
			continue
		}
		if state != "" {
			return ""
		}
		state = item.State
	}
	return state
}

func selectedGatewayReachable(report *Report, node, family, via string) bool {
	return slices.ContainsFunc(report.Evidence.Routes, func(route RouteEvidence) bool {
		return sameName(node, route.Node) && sameName(family, route.Family) && route.Selected &&
			sameName(via, route.Via) && route.GatewayReachable != nil && *route.GatewayReachable
	})
}

func controlReachedVia(report *Report, node, endpoint, via string) bool {
	return slices.ContainsFunc(report.Evidence.ControlledTargets, func(item ControlledTargetEvidence) bool {
		return sameName(node, item.From) && sameName(endpoint, item.To) && slices.Contains(item.Via, via)
	})
}

func preferredPathFailureObserved(mutation GeneratedMutation, report *Report) bool {
	if mutation.TargetNode == "" || mutation.PreferredVia == "" || mutation.PreferredSegment == "" ||
		mutation.AlternateVia == "" || mutation.AlternateSegment == "" || mutation.ControlTarget == "" ||
		(mutation.Family != string(familyIPv4) && mutation.Family != string(familyIPv6)) {
		return false
	}
	var selected *RouteEvidence
	for i := range report.Evidence.Routes {
		route := &report.Evidence.Routes[i]
		if route.Node == mutation.TargetNode && route.Selected && route.Family == mutation.Family &&
			slices.Contains(internetEndpointsForFamily(mutation.Family), route.Destination) &&
			route.Via == mutation.PreferredVia && route.Segment == mutation.PreferredSegment &&
			route.Metric == mutation.PreferredMetric {
			selected = route
			break
		}
	}
	if selected == nil || !defaultRouteMatches(report, mutation.TargetNode, mutation.Family,
		mutation.PreferredVia, mutation.PreferredSegment, mutation.PreferredMetric) ||
		!nodeInterfaceOwns(report, mutation.Node, mutation.Family, selected.Segment, selected.Via) ||
		!linkState(report, mutation.Node, mutation.Segment, false) ||
		!linkState(report, mutation.Node, selected.Segment, true) ||
		!routerForwardsFamily(report, mutation.Node, mutation.Family) ||
		!familyReachabilityMatches(report, mutation.TargetNode, mutation.Family,
			[]string{selected.Segment, selected.Via}, FamilyStateUnreachable) {
		return false
	}

	for _, node := range report.Topology {
		if node.Name != mutation.TargetNode {
			continue
		}
		for _, alternate := range node.Routes {
			if !defaultDestination(alternate.Destination) || alternate.Family != mutation.Family || alternate.Via != mutation.AlternateVia ||
				alternate.Segment != mutation.AlternateSegment || alternate.Metric != mutation.AlternateMetric ||
				alternate.Via == selected.Via || alternate.Segment == selected.Segment || alternate.Metric <= selected.Metric ||
				!gatewayReachable(report, mutation.TargetNode, alternate) ||
				!controlledTargetMatches(report, mutation.TargetNode, mutation.Family, mutation.ControlTarget,
					[]string{alternate.Segment, alternate.Via}, true) {
				continue
			}
			for _, gateway := range report.Topology {
				if gateway.Role == "router" && nodeInterfaceOwns(report, gateway.Name, mutation.Family, alternate.Segment, alternate.Via) &&
					routerForwardsFamily(report, gateway.Name, mutation.Family) &&
					routerHasOtherLiveLink(report, gateway.Name, mutation.Family, alternate.Segment) {
					return true
				}
			}
		}
	}
	return false
}

func defaultRouteMatches(report *Report, node, family, via, segment string, metric int) bool {
	for _, item := range report.Topology {
		if item.Name != node {
			continue
		}
		for _, route := range item.Routes {
			if defaultDestination(route.Destination) && route.Family == family && route.Via == via &&
				route.Segment == segment && route.Metric == metric {
				return true
			}
		}
	}
	return false
}

func nodeInterfaceOwns(report *Report, node, family, segment, address string) bool {
	for _, item := range report.Topology {
		if item.Name != node {
			continue
		}
		for _, iface := range item.Interfaces {
			if iface.Segment != segment {
				continue
			}
			raw := iface.IPv6
			if family == string(familyIPv4) {
				raw = iface.IPv4
			}
			for _, raw := range []string{raw, iface.Address} {
				if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Addr().String() == address {
					return true
				}
			}
		}
	}
	return false
}

func linkState(report *Report, node, segment string, up bool) bool {
	for _, link := range report.Evidence.Links {
		if link.Node == node && link.Segment == segment && link.Up == up {
			return true
		}
	}
	return false
}

func routerForwardsFamily(report *Report, node, family string) bool {
	for _, router := range report.Evidence.Routers {
		if router.Node == node {
			if family == string(familyIPv4) {
				return router.IPv4Forwarding
			}
			return router.IPv6Forwarding
		}
	}
	return false
}

func controlledTargetMatches(report *Report, from, family, target string, via []string, reachable bool) bool {
	for _, item := range report.Evidence.ControlledTargets {
		if item.From == from && item.Family == family && item.To == target &&
			item.Reachable == reachable && slices.Equal(item.Via, via) {
			return true
		}
	}
	return false
}

func familyReachabilityMatches(report *Report, node, family string, via []string, state string) bool {
	for _, item := range report.Evidence.FamilyReachability {
		if item.Node == node && item.Family == family && item.State == state && slices.Equal(item.Via, via) {
			return true
		}
	}
	return false
}

func gatewayReachable(report *Report, node string, route RouteInfo) bool {
	for _, item := range report.Evidence.Routes {
		if item.Node == node && defaultDestination(item.Destination) && item.Family == route.Family &&
			item.Via == route.Via && item.Segment == route.Segment && item.Metric == route.Metric &&
			item.GatewayReachable != nil && *item.GatewayReachable {
			return true
		}
	}
	return false
}

func defaultDestination(destination string) bool {
	if destination == "default" {
		return true
	}
	prefix, err := netip.ParsePrefix(destination)
	return err == nil && prefix.Bits() == 0
}

func routerHasOtherLiveLink(report *Report, node, family, clientSegment string) bool {
	for _, link := range report.Evidence.Links {
		address := link.IPv6
		if family == string(familyIPv4) {
			address = link.IPv4
		}
		if link.Node == node && link.Segment != clientSegment && link.Up && address != "" {
			return true
		}
	}
	return false
}

func timelineApplied(report *Report, match func(TimedEvent) bool) bool {
	for _, event := range report.Timeline {
		if event.Result == EventApplied && match(event.Event) {
			return true
		}
	}
	return false
}

func truthFingerprint(truth ObservedTruth) string {
	blob, _ := json.Marshal(truth)
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:8])
}

// Command is the single-case reproduction, and the only place its shape is
// decided. Every coordinate the generator draws from is named rather than left
// to a flag default, the fault ceiling included, so pasting this reproduces
// this experiment and not whichever one the defaults of the day would pick.
// The scenario is a validated base name by the time a hunt runs, but this
// string is pasted into a shell, so it is sanitized here rather than trusted.
func (r HuntReproduction) Command() string {
	lane, err := resolveRecordedHuntLane(r.GeneratorVersion, r.Lane)
	if err != nil {
		lane = "missing"
	}
	return fmt.Sprintf("netdoc-sim hunt %s --lane %s --seed %d --case %d --max-faults %d --generator-version %s --json",
		textsafe.Clean(r.BaseScenario), textsafe.Clean(string(lane)), r.Seed, r.Case, r.MaxFaults,
		textsafe.Clean(r.GeneratorVersion))
}

func reproductionFor(manifest GeneratedCaseManifest) HuntReproduction {
	return HuntReproduction{BaseScenario: manifest.BaseScenario, Lane: manifest.Lane, Seed: manifest.HuntSeed, Case: manifest.Case,
		CaseSeed: manifest.CaseSeed, MaxFaults: manifest.MaxFaults, GeneratorVersion: manifest.GeneratorVersion,
		CaseFingerprint: manifest.CaseFingerprint}
}

func analyzeHuntCase(manifest GeneratedCaseManifest, report *Report, truth ObservedTruth) []HuntCaseFinding {
	findings := []HuntCaseFinding{}
	add := func(f HuntCaseFinding) {
		f.Reproduce = reproductionFor(manifest)
		f.Fingerprint = huntFindingFingerprint(f)
		findings = append(findings, f)
	}
	if report == nil {
		return findings
	}
	if report.Error != "" {
		add(HuntCaseFinding{Category: FindingSimulatorFailure, Severity: SeverityCritical, Code: "simulation_run_failed",
			Summary: "The simulator could not complete the generated case.", Evidence: report.Error})
	}
	if !report.Cleanup.Done {
		add(HuntCaseFinding{Category: FindingCleanupFailure, Severity: SeverityCritical, Code: "simulation_cleanup_failed",
			Summary: "Simulation resources did not clean up completely.", Evidence: strings.Join(report.Cleanup.Errors, "; ")})
	}
	if report.Error != "" || !report.Cleanup.Done {
		return findings
	}
	for _, event := range report.Timeline {
		if event.Result == EventFailed {
			add(HuntCaseFinding{Category: FindingSimulatorFailure, Severity: SeverityHigh, Code: "scheduled_fault_failed",
				Summary: "A generated timed fault failed to reach the simulated network.", Evidence: event.State + ": " + event.Error})
		}
	}
	for _, test := range report.Tests {
		switch test.ProcessOutcome {
		case ProcessTimedOut:
			add(HuntCaseFinding{Category: FindingNetdocHang, Severity: SeverityCritical, Code: "netdoc_process_deadline",
				Summary: "The whole netdoc process exceeded the simulator deadline.", Evidence: test.Name})
		case ProcessSignaled:
			add(HuntCaseFinding{Category: FindingNetdocCrash, Severity: SeverityCritical, Code: "netdoc_signal_termination",
				Summary: "The netdoc process terminated from a signal.", Actual: test.Signal, Evidence: test.Name})
		case ProcessCancelled:
			add(HuntCaseFinding{Category: FindingSimulatorFailure, Severity: SeverityHigh, Code: "netdoc_cancelled",
				Summary: "The generated run was cancelled before netdoc completed.", Evidence: test.Name})
		case ProcessExecError:
			add(HuntCaseFinding{Category: FindingUnexpectedRuntimeError, Severity: SeverityHigh, Code: "netdoc_exec_error",
				Summary: "The simulator could not execute netdoc.", Evidence: test.Error})
		}
		if test.Diagnosis == nil && test.Error != "" && test.ProcessOutcome == ProcessExited {
			add(HuntCaseFinding{Category: FindingUnexpectedRuntimeError, Severity: SeverityHigh, Code: "netdoc_invalid_report",
				Summary: "Netdoc exited without a valid structured diagnosis.", Evidence: test.Error})
		}
		if test.Diagnosis != nil && dnsFailureDuring(test, report.Evidence.DNSQueries) {
			if check := checkByID(test.Diagnosis, "dns"); check != nil && check.Status == "PASS" {
				add(HuntCaseFinding{Category: FindingFalseNegative, Severity: SeverityHigh, Code: "observed_dns_failure_reported_healthy",
					Probe: "dns", Expected: "FAIL or WARN", Actual: check.Status,
					Summary: "The resolver service observed failed queries while netdoc reported DNS healthy.", Evidence: check.Detail})
			}
		}
	}
	for _, finding := range unrecognizedConditionFindings(report, truth) {
		add(finding)
	}
	for _, finding := range familyContradictionFindings(report, truth) {
		add(finding)
	}
	for _, finding := range unsupportedConditionFindings(report, truth) {
		add(finding)
	}
	if truth.TCP == "reset" && !diagnosisClassifiedReset(report) {
		add(HuntCaseFinding{Category: FindingCoverageGap, Severity: SeverityLow, Code: "tcp_reset_not_distinguished",
			Probe: protocolProbe(report), Expected: "connection_reset",
			Summary:  "The simulator observed a TCP reset, but no protocol diagnosis classified it as a reset.",
			Evidence: "TCP reset service recorded connection_reset"})
	}
	for _, suggestion := range report.Suggestions {
		category, severity, ok := huntSuggestionClass(suggestion.Code)
		if !ok {
			continue
		}
		add(HuntCaseFinding{Category: category, Severity: severity, Code: suggestion.Code, SuggestionCode: suggestion.Code,
			Probe: suggestion.Probe, Cause: suggestion.Cause, Summary: suggestion.Message, Evidence: suggestion.Evidence})
	}
	sort.Slice(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	return findings
}

// familyContradictionFindings is the opposite direction from the false-negative
// oracle: the simulator reached a family that the diagnosis calls unreachable.
// That is netdoc claiming something the network disagrees with, not a missed
// condition, so it stays a contradiction and is reported separately.
func familyContradictionFindings(report *Report, truth ObservedTruth) []HuntCaseFinding {
	if !finalStateComparable(report) {
		return nil
	}
	diagnosis := finalClientDiagnosis(report)
	if diagnosis == nil {
		return nil
	}
	var findings []HuntCaseFinding
	for _, family := range []struct {
		name, truth string
	}{{"ipv4", truth.IPv4}, {"ipv6", truth.IPv6}} {
		actual := diagnosedFamily(diagnosis, family.name)
		if family.truth != FamilyStateReachable || actual != FamilyStateUnreachable {
			continue
		}
		findings = append(findings, HuntCaseFinding{Category: FindingDiagnosticContradiction, Severity: SeverityHigh,
			Code: "family_reachability_mismatch", Probe: "internet_tcp", Family: family.name,
			Expected: family.truth, Actual: actual,
			Summary:  fmt.Sprintf("Final simulator truth says %s is %s, but Network Doctor reported %s.", family.name, family.truth, actual),
			Evidence: fmt.Sprintf("simulator final %s=%s; internet_tcp address_families.%s=%s", family.name, family.truth, family.name, actual)})
	}
	return findings
}

// finalStateComparable reports whether the run ended on a path stable enough
// for final-state evidence and the final diagnosis to describe the same
// network. Separate samples can disagree under packet impairment or after a
// timed path transition without either observer being wrong.
func finalStateComparable(report *Report) bool {
	// Final-state truth is not a temporal oracle, so leave those cases to the
	// timeline analysis rather than accusing either side of being wrong.
	for _, fault := range report.Faults {
		if fault.Type == FaultNetem {
			return false
		}
	}
	for _, event := range report.Timeline {
		if event.Result != EventApplied {
			continue
		}
		switch event.Event.Type {
		case FaultScheduledNetem:
			if event.Event.Latency > 0 || event.Event.Jitter > 0 || event.Event.LossPercent > 0 {
				return false
			}
		case FaultScheduledLink:
			if event.Event.State == LinkStateDown {
				return false
			}
		}
	}
	return true
}

// dnsFailureDuring reports whether a resolver was still refusing netdoc's
// queries by the end of this run. Judging it on the last query per service, not
// on any query, is what separates a missed failure from a resolver that dropped
// one query, recovered, and answered the resample: reporting PASS after that is
// the truth about the run, not a false negative.
func dnsFailureDuring(test TestOutcome, queries []DNSQueryEvidence) bool {
	last := map[string]DNSQueryEvidence{}
	for _, query := range queries {
		if !query.placedWithin(test.StartOffset, test.EndOffset) {
			continue
		}
		if prev, seen := last[query.Service]; !seen || query.Offset > prev.Offset {
			last[query.Service] = query
		}
	}
	for _, query := range last {
		if query.ActualOutcome == dnsServedDropped || query.ActualOutcome == dnsServedSERVFAIL {
			return true
		}
	}
	return false
}

func diagnosisClassifiedReset(report *Report) bool {
	for _, test := range report.Tests {
		if test.Diagnosis == nil {
			continue
		}
		for _, check := range test.Diagnosis.Checks {
			if check.Cause == "connection_reset" {
				return true
			}
		}
	}
	return false
}

func protocolProbe(report *Report) string {
	for _, test := range report.Tests {
		if test.Diagnosis == nil {
			continue
		}
		for _, check := range test.Diagnosis.Checks {
			switch check.ID {
			case "http", "https", "ssh_banner", "smtp_banner", "tls":
				return check.ID
			}
		}
	}
	return "target_tcp"
}

func huntSuggestionClass(code string) (string, HuntSeverity, bool) {
	switch code {
	case SuggestTransientNotResampled:
		return FindingCoverageGap, SeverityMedium, true
	case SuggestTransientReportedPermanent:
		return FindingCoverageGap, SeverityLow, true
	case SuggestTransientMissed:
		return FindingCoverageGap, SeverityLow, true
	case SuggestTimelineInconsistent:
		return FindingDiagnosticContradiction, SeverityHigh, true
	case "jitter_sampling_gap":
		return FindingCoverageGap, SeverityLow, true
	case "alternate_route_available", "wrong_default_route_evidence":
		return FindingCoverageGap, SeverityMedium, true
	case "gateway_unreachable":
		return FindingCoverageGap, SeverityInfo, true
	case SuggestNondeterministic:
		return FindingDiagnosticInstability, SeverityMedium, true
	default:
		return "", "", false
	}
}

func huntFindingFingerprint(f HuntCaseFinding) string {
	semantic := struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Probe    string `json:"probe,omitempty"`
		Expected string `json:"expected,omitempty"`
		Actual   string `json:"actual,omitempty"`
		Cause    string `json:"cause,omitempty"`
		Family   string `json:"family,omitempty"`
	}{f.Category, f.Code, f.Probe, f.Expected, f.Actual, f.Cause, f.Family}
	blob, _ := json.Marshal(semantic)
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:8])
}

func aggregateHuntFindings(cases []HuntCaseResult) []HuntFinding {
	byFingerprint := make(map[string]*HuntFinding)
	for _, item := range cases {
		for _, finding := range item.Findings {
			aggregate := byFingerprint[finding.Fingerprint]
			if aggregate == nil {
				aggregate = &HuntFinding{Fingerprint: finding.Fingerprint, Category: finding.Category,
					Severity: finding.Severity, Code: finding.Code, SuggestionCode: finding.SuggestionCode,
					Probe: finding.Probe, Expected: finding.Expected, Actual: finding.Actual, Cause: finding.Cause,
					Family: finding.Family, Summary: finding.Summary, Evidence: finding.Evidence,
					FirstCase: item.Manifest.Case, Reproduce: finding.Reproduce}
				byFingerprint[finding.Fingerprint] = aggregate
			}
			aggregate.Occurrences++
			if len(aggregate.ExampleCases) < 3 {
				aggregate.ExampleCases = append(aggregate.ExampleCases, item.Manifest.Case)
			}
		}
	}
	out := make([]HuntFinding, 0, len(byFingerprint))
	for _, finding := range byFingerprint {
		out = append(out, *finding)
	}
	sort.Slice(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		if out[i].Occurrences != out[j].Occurrences {
			return out[i].Occurrences > out[j].Occurrences
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}
