package simulation

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// A hunt false negative means exactly one thing: the simulator independently
// established a network condition whose diagnostic meaning Network Doctor
// failed to recognize. It deliberately does not mean "a mutation expected probe
// X to fail and probe X did not fail": a mutation is intent rather than truth,
// and a probe id is an implementation detail of how the diagnosis is assembled
// rather than the thing a user is told.
//
// NetworkCondition is the vocabulary in between: one domain-level fact about
// the network. Every condition is established from simulator-side observation
// alone and recognized from one diagnosis alone. Nothing in this file reads the
// mutation manifest, and no diagnosis ever feeds back into truth.
type NetworkCondition string

const (
	ConditionIPv4InternetUnreachable NetworkCondition = "ipv4_internet_unreachable"
	ConditionIPv6InternetUnreachable NetworkCondition = "ipv6_internet_unreachable"
	ConditionTLSCertificateExpired   NetworkCondition = "tls_certificate_expired"
	ConditionTLSHostnameMismatch     NetworkCondition = "tls_hostname_mismatch"
	ConditionProxyDestinationRefused NetworkCondition = "proxy_destination_refused"
	ConditionQUICUDP443Blocked       NetworkCondition = "quic_udp_443_blocked"
	ConditionNoDefaultRoute          NetworkCondition = "no_default_route"
	ConditionPreferredRouteFailed    NetworkCondition = "preferred_route_failed"
)

// observation is everything a condition rule is allowed to look at: the
// simulator's own independent evidence, the coarse truth derived from it, and
// which node the client is. Deliberately not the report, so a rule cannot
// reach netdoc's diagnosis even by accident. The client is here because some
// conditions are facts about one node's kernel rather than about the network at
// large, and a rule cannot pick the right node without being told which it is.
type observation struct {
	Evidence Evidence
	Truth    ObservedTruth
	Client   string
}

// conditionRule holds the two halves of one oracle entry side by side, because
// the pair is what has to be reviewable: what simulator truth establishes this
// condition, and what diagnosis output counts as recognizing it. The two
// functions never see each other's input.
type conditionRule struct {
	condition NetworkCondition
	// family scopes a condition to one address family so per-family findings
	// stay distinguishable. Empty for conditions that have no family.
	family string
	// summary is the domain sentence a finding is built from: a network fact,
	// not a probe row.
	summary string
	// evidence names the independent observation that established the
	// condition. It describes the simulator side only; a finding must be
	// readable without trusting anything netdoc said.
	evidence string
	// observed takes the simulator's own observation rather than the whole
	// report, so a rule cannot reach netdoc's diagnosis even by accident.
	observed func(observation) bool
	// recognized reads one diagnosis. It must never read simulator evidence.
	recognized func(*Diagnosis) bool
}

// conditionOracle is ordered API. A slice rather than a map so repeated runs
// emit findings in one order regardless of Go's map iteration.
//
// Recognition is expressed over netdoc's cause vocabulary and its structured
// per-family verdicts, not over probe ids, because those are the parts of the
// report that say what is wrong with the network rather than which row noticed.
// Splitting or merging probe rows therefore leaves this table correct.
var conditionOracle = []conditionRule{
	{
		condition: ConditionIPv4InternetUnreachable,
		family:    "ipv4",
		summary:   "IPv4 internet reachability lost",
		evidence:  "the client node's own TCP dial of the controlled IPv4 endpoints did not complete",
		observed: func(o observation) bool {
			return o.Truth.IPv4 == FamilyStateUnreachable
		},
		recognized: func(d *Diagnosis) bool {
			return diagnosedFamily(d, "ipv4") == FamilyStateUnreachable ||
				flaggedCause(d, nil, diagnostic.FamilyCauseIPv4Unreachable)
		},
	},
	{
		condition: ConditionIPv6InternetUnreachable,
		family:    "ipv6",
		summary:   "IPv6 internet reachability lost",
		evidence:  "the client node's own TCP dial of the controlled IPv6 endpoints did not complete",
		observed: func(o observation) bool {
			return o.Truth.IPv6 == FamilyStateUnreachable
		},
		recognized: func(d *Diagnosis) bool {
			return diagnosedFamily(d, "ipv6") == FamilyStateUnreachable ||
				flaggedCause(d, nil, diagnostic.FamilyCauseIPv6Unreachable)
		},
	},
	{
		condition: ConditionTLSCertificateExpired,
		summary:   "a target serving an expired TLS certificate",
		evidence:  "a controlled TLS service presented an expired certificate and watched a client refuse it",
		observed: func(o observation) bool {
			return anyExpiredCertificateRejected(o.Evidence)
		},
		// An expired certificate has its own cause in netdoc's vocabulary and
		// its own fix, so a bare handshake failure is deliberately not
		// equivalent: it tells the user to suspect a MITM proxy or clock skew
		// for a certificate whose dates are readable on the wire.
		recognized: func(d *Diagnosis) bool {
			return flaggedCause(d, nil, diagnostic.TLSCauseCertificateExpired)
		},
	},
	{
		condition: ConditionTLSHostnameMismatch,
		summary:   "a target serving a certificate issued for a different name",
		evidence:  "a controlled TLS service was asked for a name its certificate does not carry and watched the client refuse it",
		observed: func(o observation) bool {
			return anyMismatchedCertificateRejected(o.Evidence)
		},
		// Deliberately not interchangeable with the expired rule next door. The
		// dates on this certificate are fine and the issuer is trusted; what is
		// wrong is the name, and netdoc has its own cause and its own fix for
		// that. Naming the wrong one sends the user to check a clock.
		recognized: func(d *Diagnosis) bool {
			return flaggedCause(d, nil, diagnostic.TLSCauseHostnameMismatch)
		},
	},
	{
		condition: ConditionProxyDestinationRefused,
		summary:   "a proxy refusing its CONNECT destination",
		evidence:  "a controlled SOCKS5 proxy answered a CONNECT request with a refusal",
		observed: func(o observation) bool {
			return anyProxyCONNECTRefused(o.Evidence)
		},
		// Reaching the proxy and being refused by it is a different fault from
		// not reaching the proxy at all, and netdoc separates the two. Only the
		// destination cause says the proxy answered and declined; proxy
		// unreachable or a protocol failure would be a wrong answer, not a
		// second way of giving the right one.
		recognized: func(d *Diagnosis) bool {
			return flaggedCause(d, nil, diagnostic.ProxyCauseDestinationUnreachable)
		},
	},
	{
		condition: ConditionQUICUDP443Blocked,
		summary:   "QUIC datagrams to UDP/443 being dropped on the path",
		evidence:  "the kernel drop counter on the controlled path counted inbound UDP/443 packets",
		// The counter is also the control for "while relevant connectivity
		// remains healthy": packets can only be counted once a client resolved
		// the endpoint and put datagrams on the wire, which a dead path would
		// have prevented.
		observed: func(o observation) bool {
			return anyUDPPortDropped(o.Evidence, 443)
		},
		// Scoped to the QUIC row because "timeout" is not unique in netdoc's
		// cause vocabulary, since TLS and encrypted DNS spend it too, and an
		// unrelated TLS timeout must not read as QUIC being recognized. This is
		// the only entry that needs a row scope, and it names the probe through
		// the diagnostic constant so a renamed id stays in step.
		recognized: func(d *Diagnosis) bool {
			return flaggedCause(d, []string{string(diagnostic.ProbeQUIC)},
				diagnostic.QUICCauseHandshake, diagnostic.QUICCauseTimeout)
		},
	},
	{
		condition: ConditionNoDefaultRoute,
		summary:   "a client with no default route left for a family it can no longer reach",
		evidence:  "the client's own routing table was read back from its kernel and held no default route for that family, while the client's own dial of that family's controlled endpoints did not complete",
		// Not family-scoped, because netdoc's answer is not: one cause on one
		// row covers whichever family lost its route, so a per-family accusation
		// would be asking for a distinction the vocabulary cannot make.
		observed: func(o observation) bool {
			return noDefaultRouteFor(o, string(familyIPv4)) || noDefaultRouteFor(o, string(familyIPv6))
		},
		// "The internet is unreachable" is true and useless here; the route is
		// gone, and netdoc has its own cause saying so, with its own fix. A
		// diagnosis that reports only the lost reachability sends the user to
		// look at the network instead of at one missing line in their own
		// routing table, which is why an unreachable family is deliberately not
		// accepted as a second way of recognizing this.
		recognized: func(d *Diagnosis) bool {
			return flaggedCause(d, nil, diagnostic.RouteCauseNoDefaultRoute)
		},
	},
	{
		condition: ConditionPreferredRouteFailed,
		summary:   "a client whose preferred default route goes nowhere while a lower-preference one still works",
		evidence:  "the client's own routing table was read back from its kernel and held two defaults with a strict preference between them, the client's own dial of the preferred family's controlled endpoints did not complete, and the client's own dial of a controlled target over one of the other defaults did",
		// Not family-scoped: the simulator can establish this condition
		// independently in either family.
		observed: func(o observation) bool {
			return preferredDefaultRouteFailedFor(o, string(familyIPv4)) ||
				preferredDefaultRouteFailedFor(o, string(familyIPv6))
		},
		// The report has selection metadata, not a measured comparison proving
		// a failed preferred route and working alternate. Independent simulator
		// evidence establishes the fault but cannot count as report recognition.
		recognized: func(*Diagnosis) bool { return false },
	},
}

// preferredDefaultRouteFailedFor reads the whole condition off the client's own
// kernel and the client's own dials, and needs all three halves of the sentence
// its name makes. Two defaults with a strict preference between them is what
// lets "preferred" mean anything at all, and is the same shape netdoc's own
// route classifier keys on, arrived at independently. The family being
// unreachable is what says the preferred one goes nowhere. A controlled target
// answering over one of the others is what says an alternate remains, and it is
// the clause that separates this condition from a network that is simply down:
// without it, two dead paths would wear the name of one.
func preferredDefaultRouteFailedFor(o observation, family string) bool {
	routes, read := kernelRouteTable(o.Evidence, o.Client, family)
	if !read {
		return false
	}
	defaults := defaultRoutesIn(routes)
	if len(defaults) < 2 {
		return false
	}
	slices.SortStableFunc(defaults, func(a, b KernelRoute) int { return cmp.Compare(a.Metric, b.Metric) })
	preferred := defaults[0]
	if preferred.Metric >= defaults[1].Metric {
		return false
	}
	state := o.Truth.IPv6
	if family == string(familyIPv4) {
		state = o.Truth.IPv4
	}
	if state != FamilyStateUnreachable {
		return false
	}
	for _, alternate := range defaults[1:] {
		if alternate.Via != "" && alternate.Via != preferred.Via &&
			controlledTargetReachedVia(o.Evidence, o.Client, family, alternate.Via) {
			return true
		}
	}
	return false
}

// controlledTargetReachedVia reports whether this node's own dial of a
// simulator-owned endpoint completed over a particular next hop. The via list
// is the path the dialing node recorded for itself, so this is the alternate
// route being exercised rather than merely being present in a table.
func controlledTargetReachedVia(evidence Evidence, from, family, via string) bool {
	return slices.ContainsFunc(evidence.ControlledTargets, func(item ControlledTargetEvidence) bool {
		return sameName(from, item.From) && sameName(family, item.Family) && item.Reachable &&
			slices.Contains(item.Via, via)
	})
}

// noDefaultRouteFor reads the condition entirely off the client's own kernel
// and the client's own dials. RouteTableEvidence is what makes an absence
// statable at all: a record exists for every family the node holds an address
// in, so an empty default set is the positive claim "this table was read and
// held none" rather than "nobody looked". The unreachable family alongside it
// is what says the missing route mattered, since a family reaching the internet
// over a specific route has lost nothing worth reporting.
func noDefaultRouteFor(o observation, family string) bool {
	routes, read := kernelRouteTable(o.Evidence, o.Client, family)
	if !read || len(defaultRoutesIn(routes)) > 0 {
		return false
	}
	state := o.Truth.IPv6
	if family == string(familyIPv4) {
		state = o.Truth.IPv4
	}
	return state == FamilyStateUnreachable
}

// observedConditions returns the semantic conditions this run's independent
// simulator observations establish, in registry order.
func observedConditions(o observation) []NetworkCondition {
	var out []NetworkCondition
	for _, rule := range conditionOracle {
		if rule.observed(o) {
			out = append(out, rule.condition)
		}
	}
	return out
}

// recognizedConditions returns the semantic conditions one diagnosis
// communicates, in registry order.
func recognizedConditions(d *Diagnosis) []NetworkCondition {
	var out []NetworkCondition
	if d == nil {
		return out
	}
	for _, rule := range conditionOracle {
		if rule.recognized(d) {
			out = append(out, rule.condition)
		}
	}
	return out
}

// caseConditions is the whole of what the oracle can say about one case: the
// conditions the simulator's own evidence established, the ones the final
// diagnosis named, and whether the case was a final-state comparison at all.
//
// The third return is load-bearing and is not the same as "established
// nothing". A case under persistent shaping or a timed path transition is one
// the oracle never got to ask about, which is a fact about coverage; a
// comparable case that established nothing is a fact about the network.
func caseConditions(report *Report, truth ObservedTruth) (established, recognized []NetworkCondition, comparable bool) {
	if report == nil || !finalStateComparable(report) {
		return nil, nil, false
	}
	test := finalClientTest(report)
	if test == nil || test.Diagnosis == nil {
		return nil, nil, false
	}
	return observedConditions(observation{Evidence: report.Evidence, Truth: truth, Client: observedClient(report)}),
		recognizedConditions(test.Diagnosis), true
}

// unrecognizedConditionFindings reconciles the two halves. A condition the
// simulator never established produces nothing, however loudly the manifest
// says a mutation was scheduled or applied: an unobserved effect is a coverage
// question, not an accusation about the diagnosis.
func unrecognizedConditionFindings(report *Report, truth ObservedTruth) []HuntCaseFinding {
	observed, recognized, comparable := caseConditions(report, truth)
	if !comparable {
		return nil
	}
	var findings []HuntCaseFinding
	for _, rule := range conditionOracle {
		if !slices.Contains(observed, rule.condition) || slices.Contains(recognized, rule.condition) {
			continue
		}
		findings = append(findings, HuntCaseFinding{Category: FindingFalseNegative, Severity: SeverityHigh,
			Code: "unrecognized_network_condition", Family: rule.family,
			Expected: string(rule.condition), Actual: "unrecognized",
			Summary:  "The simulator independently observed " + rule.summary + ", but the diagnosis did not recognize it.",
			Evidence: rule.evidence})
	}
	return findings
}

// finalClientTest returns the last run from the observed client. It is closest
// in time to final evidence collection; earlier runs can describe older state.
func finalClientTest(report *Report) *TestOutcome {
	if report == nil {
		return nil
	}
	client := observedClient(report)
	if client == "" {
		return nil
	}
	for i := len(report.Tests) - 1; i >= 0; i-- {
		if report.Tests[i].Node == client {
			return &report.Tests[i]
		}
	}
	return nil
}

func finalClientDiagnosis(report *Report) *Diagnosis {
	test := finalClientTest(report)
	if test == nil {
		return nil
	}
	return test.Diagnosis
}

// flaggedCause reports whether the diagnosis raised its hand on a row carrying
// one of these causes. Only FAIL and WARN count: a cause on a passing row is
// context, not a finding. rows scopes the search to particular report rows and
// is set only where netdoc reuses one cause string across subjects; nil means
// any row, which is what keeps recognition independent of which probe noticed.
func flaggedCause(d *Diagnosis, rows []string, causes ...string) bool {
	for _, check := range d.Checks {
		if !flagged(check.Status) || (rows != nil && !slices.Contains(rows, check.ID)) {
			continue
		}
		if slices.Contains(causes, check.Cause) {
			return true
		}
	}
	return false
}

// diagnosedFamily reads netdoc's structured per-family egress verdict from
// whichever row published one. Status is not required here: a row that states
// "ipv4: unreachable" has communicated the fact even while the run as a whole
// passes on the other family, which is exactly the dual-stack case.
func diagnosedFamily(d *Diagnosis, family string) string {
	for _, check := range d.Checks {
		if check.Families == nil {
			continue
		}
		state := check.Families.IPv6
		if family == "ipv4" {
			state = check.Families.IPv4
		}
		if state != "" {
			return state
		}
	}
	return ""
}

// The predicates below define what it takes for one fault to have reached the
// wire, judged from a single evidence record. They are shared so the unscoped
// question the oracle asks and the scoped question per-mutation observation
// asks cannot drift apart, and each requires the record to name the node that
// produced it: a holder always stamps its own name, so a record without one is
// not an observation anybody made.
//
// rejectedExpiredCertificate wants the handshake rather than the service's
// configured mode, because a certificate nobody was ever shown expired in
// private.
func rejectedExpiredCertificate(handshake TLSEvidence) bool {
	return handshake.Node != "" && handshake.CertificateMode == TLSCertificateExpired &&
		handshake.CertificatePresented && handshake.Result == "client_rejected_certificate" &&
		handshake.Count > 0
}

func refusedCONNECT(request SOCKSEvidence) bool {
	return request.Node != "" && request.Event == "connect" &&
		request.Result == "connection_refused" && request.Count > 0
}

// droppedInbound reports the rule's own kernel counter, not the fault record
// that installed it: an installed rule that never matched a packet blocked
// nothing.
func droppedInbound(drop PacketDropEvidence, protocol string, port int) bool {
	return drop.Node != "" && drop.Protocol == protocol && drop.Direction == DirectionInbound &&
		drop.Packets > 0 && sameNumber(port, drop.Port)
}

// rejectedMismatchedCertificate is the mismatch condition read off the
// handshake rather than off the service's configured mode, and it wants the two
// halves that make it that fault and not another: the client asked for a name,
// and the certificate it was shown does not carry it. A certificate that does
// cover the requested name and was still refused failed for some other reason.
func rejectedMismatchedCertificate(handshake TLSEvidence) bool {
	if handshake.Node == "" || handshake.CertificateMode != TLSCertificateHostnameMismatch ||
		!handshake.CertificatePresented || handshake.Result != "client_rejected_certificate" ||
		handshake.Count == 0 || handshake.RequestedServer == "" {
		return false
	}
	return !slices.ContainsFunc(handshake.CertificateDNS, func(name string) bool {
		return dnsKey(name) == dnsKey(handshake.RequestedServer)
	})
}

// resetConnection is the reset service's own record of having torn a connection
// down after accepting it. A service that came up in reset mode and was never
// dialed reset nobody.
func resetConnection(event TCPResetEvidence) bool {
	return event.Node != "" && event.Event == "reset" && event.Result == "connection_reset" && event.Count > 0
}

// droppedShapedPackets reports the netem qdisc's own drop counter, read back
// off the kernel after the run, rather than the shaper having been installed
// with the parameters that were asked for. A qdisc that matched no traffic
// impaired nobody, and the counter is the only reading that separates a shaper
// that was configured from one that was met.
func droppedShapedPackets(condition PacketConditionEvidence) bool {
	return condition.Node != "" && condition.Active && condition.DroppedPackets > 0
}

// The two reply readers below want a reply the service actually sent, which is
// why neither looks at ServiceStateEvidence: a service that started in a faulty
// mode has a state, and until it answered somebody nothing was done to anyone.
func servedInvalidDoH(reply ServiceReplyEvidence) bool {
	return reply.Node != "" && reply.Type == ServiceEncryptedDNS &&
		reply.Result == DoHResponseInvalid && reply.Count > 0
}

func servedHTTPStatus(reply ServiceReplyEvidence, status int) bool {
	return reply.Node != "" && reply.Type == ServiceHTTP && reply.Count > 0 &&
		sameNumber(status, reply.Status)
}

// servedDNSOutcome reads the outcome the resolver put on the wire for one real
// query. The fault scheduler's own "applied" record is a different claim: it
// says the resolver was moved into a faulty state, not that a client was ever
// made to live with it.
func servedDNSOutcome(query DNSQueryEvidence, outcome string) bool {
	return query.Node != "" && outcome != "" && query.ActualOutcome == outcome
}

// The any* readers answer the oracle's question, which is unscoped on purpose:
// a network condition is a fact about the run, and the oracle must not know
// which node a mutation aimed at. That wildcard is spelled out in the name
// rather than inferred from an empty argument, so the scoped readers below are
// free to treat a missing scope as insufficient evidence.
func anyExpiredCertificateRejected(evidence Evidence) bool {
	return slices.ContainsFunc(evidence.TLS, rejectedExpiredCertificate)
}

func anyProxyCONNECTRefused(evidence Evidence) bool {
	return slices.ContainsFunc(evidence.SOCKSRequests, refusedCONNECT)
}

func anyUDPPortDropped(evidence Evidence, port int) bool {
	return slices.ContainsFunc(evidence.PacketDrops, func(drop PacketDropEvidence) bool {
		return droppedInbound(drop, "udp", port)
	})
}

func anyMismatchedCertificateRejected(evidence Evidence) bool {
	return slices.ContainsFunc(evidence.TLS, rejectedMismatchedCertificate)
}

func anyConnectionReset(evidence Evidence) bool {
	return slices.ContainsFunc(evidence.TCPResets, resetConnection)
}

// sameName and sameNumber are the whole of the scope rule, in one place so no
// family can forget half of it. A scope key the manifest left blank is a
// question nobody asked: it matches nothing, not even a record that happens to
// be blank in the same place. Without that, a partially filled manifest would
// confirm itself from a fault some other node produced, and blank would quietly
// meet blank.
func sameName(named, recorded string) bool { return named != "" && named == recorded }

func sameNumber(named, recorded int) bool { return named != 0 && named == recorded }

// The *At readers answer the different question of whether one mutation took
// effect where it said it would. Each one is a thin pairing of the scope rule
// above with the shared wire predicate for its family, so the two questions
// stay in step and neither can be loosened alone.
func expiredCertificateRejectedAt(evidence Evidence, node, service string) bool {
	return slices.ContainsFunc(evidence.TLS, func(handshake TLSEvidence) bool {
		return sameName(node, handshake.Node) && sameName(service, handshake.Service) &&
			rejectedExpiredCertificate(handshake)
	})
}

func proxyCONNECTRefusedAt(evidence Evidence, node, service, destination string, port int) bool {
	return slices.ContainsFunc(evidence.SOCKSRequests, func(request SOCKSEvidence) bool {
		return sameName(node, request.Node) && sameName(service, request.Service) &&
			sameName(destination, request.Destination) && sameNumber(port, request.Port) &&
			refusedCONNECT(request)
	})
}

func udpPortDroppedAt(evidence Evidence, node string, port int) bool {
	return slices.ContainsFunc(evidence.PacketDrops, func(drop PacketDropEvidence) bool {
		return sameName(node, drop.Node) && droppedInbound(drop, "udp", port)
	})
}

func tcpPortDroppedAt(evidence Evidence, node string, port int) bool {
	return slices.ContainsFunc(evidence.PacketDrops, func(drop PacketDropEvidence) bool {
		return sameName(node, drop.Node) && droppedInbound(drop, "tcp", port)
	})
}

func mismatchedCertificateRejectedAt(evidence Evidence, node, service string) bool {
	return slices.ContainsFunc(evidence.TLS, func(handshake TLSEvidence) bool {
		return sameName(node, handshake.Node) && sameName(service, handshake.Service) &&
			rejectedMismatchedCertificate(handshake)
	})
}

// controlledTargetOutcome is what the simulator's own dial of one endpoint did.
// It is the only reading that separates a port that answered with a reset from
// one that swallowed the packet, so it returns the outcome rather than a bool,
// and reports whether the observation was taken at all: no dial is not the same
// as a dial that failed.
func controlledTargetOutcome(evidence Evidence, from, endpoint string) (string, bool) {
	for _, item := range evidence.ControlledTargets {
		if sameName(from, item.From) && sameName(endpoint, item.To) && item.Outcome != "" {
			return item.Outcome, true
		}
	}
	return "", false
}

// kernelRouteTable is the table one node's kernel held for one family. The bool
// is load-bearing: an absent record means nobody read that table, and a route
// family cannot be called empty on the strength of never having been looked at.
func kernelRouteTable(evidence Evidence, node, family string) ([]KernelRoute, bool) {
	for _, table := range evidence.RouteTables {
		if sameName(node, table.Node) && sameName(family, table.Family) {
			return table.Routes, true
		}
	}
	return nil, false
}

func defaultRoutesIn(routes []KernelRoute) []KernelRoute {
	var out []KernelRoute
	for _, route := range routes {
		if defaultDestination(route.Destination) {
			out = append(out, route)
		}
	}
	return out
}

// specificRouteCovering reports whether the table carries a non-default route
// that would carry traffic to this address. Non-default because a default route
// covers everything and would answer every question with yes, which is exactly
// the distinction a missing subnet route is made of.
func specificRouteCovering(routes []KernelRoute, address string) bool {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	for _, route := range routes {
		if defaultDestination(route.Destination) {
			continue
		}
		if prefix, err := netip.ParsePrefix(route.Destination); err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func shapedPacketsDroppedAt(evidence Evidence, node, segment string) bool {
	return slices.ContainsFunc(evidence.PacketConditions, func(condition PacketConditionEvidence) bool {
		return sameName(node, condition.Node) && sameName(segment, condition.Segment) &&
			droppedShapedPackets(condition)
	})
}

func connectionResetAt(evidence Evidence, node string) bool {
	return slices.ContainsFunc(evidence.TCPResets, func(event TCPResetEvidence) bool {
		return sameName(node, event.Node) && resetConnection(event)
	})
}

func invalidDoHServedAt(evidence Evidence, node, service string) bool {
	return slices.ContainsFunc(evidence.ServiceReplies, func(reply ServiceReplyEvidence) bool {
		return sameName(node, reply.Node) && sameName(service, reply.Service) && servedInvalidDoH(reply)
	})
}

func httpStatusServedAt(evidence Evidence, node string, port, status int) bool {
	return slices.ContainsFunc(evidence.ServiceReplies, func(reply ServiceReplyEvidence) bool {
		return sameName(node, reply.Node) && sameNumber(port, reply.Port) && servedHTTPStatus(reply, status)
	})
}

func dnsOutcomeServedAt(evidence Evidence, service, outcome string) bool {
	return slices.ContainsFunc(evidence.DNSQueries, func(query DNSQueryEvidence) bool {
		return sameName(service, query.Service) && servedDNSOutcome(query, outcome)
	})
}
