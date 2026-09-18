package simulation

import "encoding/json"

// The canonical hunt report.
//
// A hunt stores a simulation report so that a merge can recompute the case's
// truth, fingerprints, findings and status from it and check they match what
// the shard claimed. That makes the stored report part of the hunt artifact's
// schema rather than a copy of the run's own output, and it is the only part of
// a hunt result whose size nothing in this package decides: the report carries
// netdoc's prose and one evidence row per thing a subprocess did.
//
// canonicalHuntReport is what makes it decidable. It runs over every case,
// large or small, and keeps exactly what the derive path reads. Three rules
// cover the whole projection, and between them they are what makes a stored
// case's meaning independent of how large the run's report was.
//
// It keeps every field a hunt semantic function reads and drops the rest. The
// sections below name their readers. What is dropped is netdoc's explanation of
// itself, the comparison against the scenario's expectations, and the fields no
// hunt function opens, including the one field in a report with no ceiling of
// any kind, a subprocess's stderr.
//
// It clips free text and never drops a row. Text is human evidence: it reaches
// a finding's Summary or Evidence, which no fingerprint covers, so a clip costs
// a reader the tail of a sentence and costs the hunt nothing. A row is a fact,
// so a list is never shortened to fit a byte count. Every semantic list is held
// to a cardinality the hunt model fixes instead, checked by
// checkHuntCaseCardinality where a case is written and again where one is read,
// and a list past its declared maximum is refused loudly rather than quietly
// losing its tail.
//
// It reduces the one list a run's length decides. Every other evidence list
// carries one row per node, interface, route or controlled service, which the
// eight hunt base scenarios bound; DNSQueries carries one row per query a
// resolver answered, which nothing bounds. canonicalHuntDNSQueries selects the
// subset its four readers can distinguish, which is a fact-preserving
// reduction rather than a prefix. See its own comment for the argument.
//
// The whole projection is idempotent. Clipping bounded text and selecting an
// already selected subset are both fixed points, and every projection drops
// fields rather than rewriting them, so canonical(canonical(r)) is
// canonical(r). Merge validation depends on that: it recomputes from a report
// that is already canonical and compares against fields derived from the same
// projection.
func canonicalHuntReport(r *Report) *Report {
	if r == nil {
		return nil
	}
	tests := canonicalTests(r.Tests)
	return &Report{
		// Identity. None of it is read by the derive path; it is what lets a
		// reader of a merged artifact say which run a case came from.
		Scenario: huntCanonicalName(r.Scenario), ID: huntCanonicalName(r.ID), Backend: huntCanonicalName(r.Backend),
		StartedAt: r.StartedAt, Duration: r.Duration, Result: huntCanonicalName(r.Result),
		// Error decides the case status, and its text becomes the evidence of a
		// runtime finding. Clipping cannot empty a non-empty string, so the
		// status it decides is not a function of its length.
		Error: huntCanonicalText(r.Error),
		// Cleanup.Done decides the case status the same way. The error list is
		// joined into one finding's evidence text and read nowhere else, which
		// is what lets it be the one list here still bounded by bytes.
		Cleanup: CleanupInfo{Done: r.Cleanup.Done,
			Errors: boundEncodedList(canonicalTexts(r.Cleanup.Errors), huntReportCleanupBytes)},
		// Topology names the client the oracle measures from, and carries the
		// configured routes and interfaces the routing operators check
		// themselves against.
		Topology: canonicalTopology(r.Topology),
		// Faults are read for whether the run was under packet shaping at all,
		// which is what decides a final-state comparison is meaningful. The
		// type is the whole of that question.
		Faults: canonicalFaults(r.Faults),
		// The timeline is what says a scheduled fault reached the network, and
		// which recovery happened when.
		TimelineID: huntCanonicalName(r.TimelineID),
		Timeline:   canonicalTimeline(r.Timeline),
		// One entry per netdoc process, projected to what the analyzer, the
		// oracle and the diagnosis fingerprint read.
		Tests: tests,
		// Simulator-owned evidence, projected per list to the fields its
		// readers open.
		Evidence: canonicalHuntEvidence(r.Evidence, tests),
		// The suggestions netdoc's own run produced. analyzeHuntCase turns the
		// recognized ones into case findings, so this is the section that
		// carries findings like SuggestTransientNotResampled. Two identical
		// suggestions are two findings and two occurrences in the hunt summary,
		// so this list is never deduplicated.
		Suggestions: canonicalSuggestions(r.Suggestions),
	}
}

func canonicalTexts(items []string) []string {
	if items == nil {
		return nil
	}
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = huntCanonicalText(item)
	}
	return out
}

func canonicalHosts(items []string) []string {
	if items == nil {
		return nil
	}
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = huntCanonicalHost(item)
	}
	return out
}

func canonicalNames(items []string) []string {
	if items == nil {
		return nil
	}
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = huntCanonicalName(item)
	}
	return out
}

// canonicalTopology keeps the node identity the oracle measures from and the
// configured interfaces and routes the routing operators check themselves
// against. Addresses, aliases, service names and the run's process ids are a
// description of the namespace rather than anything a hunt function reads.
func canonicalTopology(nodes []NodeInfo) []NodeInfo {
	if nodes == nil {
		return nil
	}
	out := make([]NodeInfo, len(nodes))
	for i, node := range nodes {
		out[i] = NodeInfo{Name: huntCanonicalName(node.Name), Role: huntCanonicalName(node.Role)}
		if node.Interfaces != nil {
			out[i].Interfaces = make([]InterfaceInfo, len(node.Interfaces))
			for j, iface := range node.Interfaces {
				out[i].Interfaces[j] = InterfaceInfo{Segment: huntCanonicalName(iface.Segment),
					Address: huntCanonicalName(iface.Address), IPv4: huntCanonicalName(iface.IPv4),
					IPv6: huntCanonicalName(iface.IPv6)}
			}
		}
		if node.Routes != nil {
			out[i].Routes = make([]RouteInfo, len(node.Routes))
			for j, route := range node.Routes {
				out[i].Routes[j] = RouteInfo{Destination: huntCanonicalName(route.Destination),
					Via: huntCanonicalName(route.Via), Segment: huntCanonicalName(route.Segment),
					Metric: route.Metric, Family: huntCanonicalName(route.Family)}
			}
		}
	}
	return out
}

// canonicalFaults keeps the one field finalStateComparable reads. The command
// that injected the fault, its summary and its parameters are what the run's
// own report is for.
func canonicalFaults(faults []FaultInfo) []FaultInfo {
	if faults == nil {
		return nil
	}
	out := make([]FaultInfo, len(faults))
	for i, fault := range faults {
		out[i] = FaultInfo{Type: huntCanonicalName(fault.Type)}
	}
	return out
}

// canonicalTimeline keeps what happened to each scheduled event and the event
// itself. timelineApplied matches on every field of TimedEvent that some
// operator's observation question names, so the event is kept whole; State and
// Error are the prose of a failed event, which reaches one finding's evidence.
func canonicalTimeline(events []FaultEventEvidence) []FaultEventEvidence {
	if events == nil {
		return nil
	}
	out := make([]FaultEventEvidence, len(events))
	for i, event := range events {
		out[i] = FaultEventEvidence{Event: event.Event, ScheduledOffset: event.ScheduledOffset,
			AppliedOffset: event.AppliedOffset, Result: huntCanonicalName(event.Result),
			State: huntCanonicalText(event.State), Error: huntCanonicalText(event.Error)}
		out[i].Event.Type = huntCanonicalName(event.Event.Type)
		out[i].Event.Node = huntCanonicalName(event.Event.Node)
		out[i].Event.Segment = huntCanonicalName(event.Event.Segment)
		out[i].Event.Service = huntCanonicalName(event.Event.Service)
		out[i].Event.Outcome = huntCanonicalName(event.Event.Outcome)
		out[i].Event.State = huntCanonicalName(event.Event.State)
	}
	return out
}

// canonicalSuggestions keeps the suggestions hunt analysis can read. Only a
// code huntSuggestionClass names becomes a hunt finding; every other code is
// advice for the person reading a single simulation report, and the hunt
// artifact restates nothing about it. Within that set a suggestion is kept
// whole and never deduplicated: Probe and Cause are covered by the finding's
// fingerprint, Message and Evidence are the finding's prose, and two
// suggestions that differ only by which netdoc run raised them are two
// occurrences of the finding, not one.
func canonicalSuggestions(items []Suggestion) []Suggestion {
	if items == nil {
		return nil
	}
	out := make([]Suggestion, 0, len(items))
	for _, item := range items {
		if _, _, ok := huntSuggestionClass(item.Code); !ok {
			continue
		}
		out = append(out, Suggestion{Code: huntCanonicalName(item.Code), Test: huntCanonicalText(item.Test),
			Probe: huntCanonicalName(item.Probe), Cause: huntCanonicalName(item.Cause),
			Message: huntCanonicalText(item.Message), Evidence: huntCanonicalText(item.Evidence)})
	}
	return out
}

// canonicalTests keeps the fields of one netdoc run that the hunt reads: the
// coordinates that place the process on the fault timeline, how the process
// ended, and the diagnosis it produced. What it drops is the comparison against
// the scenario's expectations, which is a fact about the scenario rather than
// about netdoc, and the process's stderr, which is the one field in a report
// with no ceiling of any kind.
func canonicalTests(tests []TestOutcome) []TestOutcome {
	if tests == nil {
		return nil
	}
	out := make([]TestOutcome, len(tests))
	for i, test := range tests {
		out[i] = TestOutcome{Name: huntCanonicalText(test.Name), Node: huntCanonicalName(test.Node),
			Target: huntCanonicalHost(test.Target), SourceSegment: huntCanonicalName(test.SourceSegment),
			StartOffset: test.StartOffset, EndOffset: test.EndOffset,
			ProcessOutcome: huntCanonicalName(test.ProcessOutcome), Signal: huntCanonicalName(test.Signal),
			Error: huntCanonicalText(test.Error), Diagnosis: canonicalDiagnosis(test.Diagnosis)}
	}
	return out
}

// canonicalDiagnosis keeps the identity of what netdoc concluded and drops the
// prose it explained itself with. The fingerprint reads the verdict and each
// row's id, status, cause and address families; the oracle reads each finding's
// id and the same per-row fields; one finding quotes a row's detail. Nothing
// reads the row's name, its timing, its fix hint, its per-address attempts or
// its route dump, and those are most of what a diagnosis weighs.
func canonicalDiagnosis(d *Diagnosis) *Diagnosis {
	if d == nil {
		return nil
	}
	out := &Diagnosis{Verdict: huntCanonicalName(d.Verdict)}
	if d.Findings != nil {
		out.Findings = make([]DiagnosisFinding, len(d.Findings))
		for i, finding := range d.Findings {
			out.Findings[i] = DiagnosisFinding{ID: huntCanonicalName(finding.ID)}
		}
	}
	if d.Checks != nil {
		out.Checks = make([]DiagnosisCheck, len(d.Checks))
		for i, check := range d.Checks {
			out.Checks[i] = DiagnosisCheck{ID: huntCanonicalName(check.ID), Status: huntCanonicalName(check.Status),
				Cause: huntCanonicalName(check.Cause), Detail: huntCanonicalText(check.Detail)}
			if check.Families != nil {
				out.Checks[i].Families = &DiagnosisFamilies{
					IPv4: huntCanonicalName(check.Families.IPv4),
					IPv6: huntCanonicalName(check.Families.IPv6)}
			}
		}
	}
	return out
}

// canonicalHuntEvidence projects each evidence list to the fields its readers
// open. No list is shortened here. Fifteen of the sixteen carry one row per
// node, interface, route, resolver lookup or controlled service, so the hunt
// base library bounds them and checkHuntCaseCardinality states that bound;
// DNSQueries is the exception and has its own reduction.
//
// Two lists are gone rather than projected. Nothing in the hunt reads
// Evidence.DNS, whose rows are keyed by the client socket that asked and are
// therefore as many as the queries themselves, and nothing reads
// Evidence.ServiceStates, which says how a service was configured where
// ServiceReplies says what it actually sent.
func canonicalHuntEvidence(e Evidence, tests []TestOutcome) Evidence {
	out := Evidence{DNSQueries: canonicalHuntDNSQueries(e.DNSQueries, tests)}
	if e.ResolverLookups != nil {
		out.ResolverLookups = make([]ResolverLookupEvidence, len(e.ResolverLookups))
		for i, item := range e.ResolverLookups {
			out.ResolverLookups[i] = ResolverLookupEvidence{Node: huntCanonicalName(item.Node),
				Resolver: huntCanonicalName(item.Resolver), Name: huntCanonicalHost(item.Name),
				State: huntCanonicalName(item.State), Stable: item.Stable,
				Addresses: canonicalNames(item.Addresses)}
		}
	}
	if e.SOCKSRequests != nil {
		out.SOCKSRequests = make([]SOCKSEvidence, len(e.SOCKSRequests))
		for i, item := range e.SOCKSRequests {
			out.SOCKSRequests[i] = SOCKSEvidence{Node: huntCanonicalName(item.Node), Service: huntCanonicalName(item.Service),
				Event: huntCanonicalName(item.Event), Destination: huntCanonicalHost(item.Destination),
				Port: item.Port, Result: huntCanonicalName(item.Result), Count: item.Count}
		}
	}
	if e.TLS != nil {
		out.TLS = make([]TLSEvidence, len(e.TLS))
		for i, item := range e.TLS {
			out.TLS[i] = TLSEvidence{Node: huntCanonicalName(item.Node), Service: huntCanonicalName(item.Service),
				CertificateMode: huntCanonicalName(item.CertificateMode), RequestedServer: huntCanonicalHost(item.RequestedServer),
				CertificateDNS: canonicalHosts(item.CertificateDNS), CertificatePresented: item.CertificatePresented,
				Result: huntCanonicalName(item.Result), Count: item.Count}
		}
	}
	if e.ServiceReplies != nil {
		out.ServiceReplies = make([]ServiceReplyEvidence, len(e.ServiceReplies))
		for i, item := range e.ServiceReplies {
			out.ServiceReplies[i] = ServiceReplyEvidence{Node: huntCanonicalName(item.Node), Service: huntCanonicalName(item.Service),
				Type: huntCanonicalName(item.Type), Port: item.Port, Status: item.Status,
				Result: huntCanonicalName(item.Result), Count: item.Count}
		}
	}
	if e.TCPResets != nil {
		out.TCPResets = make([]TCPResetEvidence, len(e.TCPResets))
		for i, item := range e.TCPResets {
			out.TCPResets[i] = TCPResetEvidence{Node: huntCanonicalName(item.Node), Service: huntCanonicalName(item.Service),
				Event: huntCanonicalName(item.Event), Result: huntCanonicalName(item.Result), Count: item.Count}
		}
	}
	if e.PacketConditions != nil {
		out.PacketConditions = make([]PacketConditionEvidence, len(e.PacketConditions))
		for i, item := range e.PacketConditions {
			out.PacketConditions[i] = PacketConditionEvidence{Node: huntCanonicalName(item.Node), Segment: huntCanonicalName(item.Segment),
				Latency: item.Latency, Jitter: item.Jitter, LossPercent: item.LossPercent, Seed: item.Seed,
				Active: item.Active, DroppedPackets: item.DroppedPackets}
		}
	}
	if e.PacketDrops != nil {
		out.PacketDrops = make([]PacketDropEvidence, len(e.PacketDrops))
		for i, item := range e.PacketDrops {
			out.PacketDrops[i] = PacketDropEvidence{Node: huntCanonicalName(item.Node), Protocol: huntCanonicalName(item.Protocol),
				Port: item.Port, Direction: huntCanonicalName(item.Direction), Packets: item.Packets}
		}
	}
	if e.Links != nil {
		out.Links = make([]LinkEvidence, len(e.Links))
		for i, item := range e.Links {
			out.Links[i] = LinkEvidence{Node: huntCanonicalName(item.Node), Segment: huntCanonicalName(item.Segment),
				IPv4: huntCanonicalName(item.IPv4), IPv6: huntCanonicalName(item.IPv6), Up: item.Up, MTU: item.MTU}
		}
	}
	if e.Routes != nil {
		out.Routes = make([]RouteEvidence, len(e.Routes))
		for i, item := range e.Routes {
			out.Routes[i] = RouteEvidence{Node: huntCanonicalName(item.Node), Destination: huntCanonicalName(item.Destination),
				Via: huntCanonicalName(item.Via), Segment: huntCanonicalName(item.Segment), Metric: item.Metric,
				Family: huntCanonicalName(item.Family), Selected: item.Selected, GatewayReachable: item.GatewayReachable}
		}
	}
	if e.RouteTables != nil {
		out.RouteTables = make([]RouteTableEvidence, len(e.RouteTables))
		for i, table := range e.RouteTables {
			out.RouteTables[i] = RouteTableEvidence{Node: huntCanonicalName(table.Node), Family: huntCanonicalName(table.Family)}
			if table.Routes != nil {
				out.RouteTables[i].Routes = make([]KernelRoute, len(table.Routes))
				for j, route := range table.Routes {
					out.RouteTables[i].Routes[j] = KernelRoute{Destination: huntCanonicalName(route.Destination),
						Via: huntCanonicalName(route.Via), Segment: huntCanonicalName(route.Segment), Metric: route.Metric}
				}
			}
		}
	}
	if e.Routers != nil {
		out.Routers = make([]RouterEvidence, len(e.Routers))
		for i, item := range e.Routers {
			out.Routers[i] = RouterEvidence{Node: huntCanonicalName(item.Node),
				IPv4Forwarding: item.IPv4Forwarding, IPv6Forwarding: item.IPv6Forwarding}
		}
	}
	if e.ControlledTargets != nil {
		out.ControlledTargets = make([]ControlledTargetEvidence, len(e.ControlledTargets))
		for i, item := range e.ControlledTargets {
			out.ControlledTargets[i] = ControlledTargetEvidence{From: huntCanonicalName(item.From), To: huntCanonicalName(item.To),
				Family: huntCanonicalName(item.Family), Via: canonicalNames(item.Via),
				Reachable: item.Reachable, Outcome: huntCanonicalName(item.Outcome)}
		}
	}
	if e.FamilyReachability != nil {
		out.FamilyReachability = make([]FamilyReachabilityEvidence, len(e.FamilyReachability))
		for i, item := range e.FamilyReachability {
			out.FamilyReachability[i] = FamilyReachabilityEvidence{Node: huntCanonicalName(item.Node),
				Family: huntCanonicalName(item.Family), Via: canonicalNames(item.Via), State: huntCanonicalName(item.State)}
		}
	}
	return out
}

// canonicalHuntDNSQueries is the only evidence reduction in the hunt, and it is
// here because DNSQueries is the only evidence list a run's length decides: one
// row per query a resolver answered, so a slow host or a netdoc that retried
// stores more rows for the same network.
//
// Four readers open the list, and between them they can distinguish exactly two
// things. collectObservedTruth reads the set of outcomes served;
// dnsOutcomeServedAt asks whether some query of one service was served one
// outcome; caseObservation calls the run's DNS unstable when one queried
// name was served two different outcomes. Those three see a set: one row per
// distinct node, service, name, query type and outcome answers all of them.
// dnsFailureDuring is the fourth, and it is temporal: for one netdoc run's
// window it takes the last query each service answered and asks whether that
// one failed.
//
// So the reduction keeps the first row of each distinct set key, and the row
// each service answered last inside each netdoc run's window. Both are original
// rows rather than summaries, which is what makes the argument short: the
// result is a subsequence, so no reader can see a fact that was not there, and
// every row a reader selects is one of the two kinds kept. A set reader selects
// by key and finds the representative. dnsFailureDuring selects the earliest
// row holding the greatest offset in the window, which is exactly the row this
// keeps, and every other retained row in that window has an offset no greater,
// so the selection is unchanged. Running it again selects the same rows, so it
// is a fixed point.
func canonicalHuntDNSQueries(queries []DNSQueryEvidence, tests []TestOutcome) []DNSQueryEvidence {
	if queries == nil {
		return nil
	}
	keep := make([]bool, len(queries))
	seen := make(map[string]bool, len(queries))
	for i, query := range queries {
		key := query.Node + "\x00" + query.Service + "\x00" + query.Name + "\x00" +
			query.QueryType + "\x00" + query.ActualOutcome
		if !seen[key] {
			seen[key], keep[i] = true, true
		}
	}
	for _, test := range tests {
		last := map[string]int{}
		for i, query := range queries {
			if !query.placedWithin(test.StartOffset, test.EndOffset) {
				continue
			}
			if previous, ok := last[query.Service]; !ok || query.Offset > queries[previous].Offset {
				last[query.Service] = i
			}
		}
		for _, i := range last {
			keep[i] = true
		}
	}
	out := make([]DNSQueryEvidence, 0, len(queries))
	for i, query := range queries {
		if !keep[i] {
			continue
		}
		out = append(out, DNSQueryEvidence{Node: huntCanonicalName(query.Node), Service: huntCanonicalName(query.Service),
			Name: huntCanonicalHost(query.Name), QueryType: huntCanonicalName(query.QueryType),
			ActualOutcome: huntCanonicalName(query.ActualOutcome), Offset: query.Offset, OffsetKnown: query.OffsetKnown})
	}
	return out
}

// huntCanonicalText bounds one free string by what it costs encoded rather than
// by how many bytes it holds. A rune can encode to six bytes, so a ceiling on
// the raw string is a ceiling six times looser on the document, and the case
// ceiling is only as good as the strings inside it. Truncation is at a rune
// boundary and is a fixed point, so canonicalizing an already canonical string
// returns it unchanged. It never empties a non-empty string, because no single
// rune encodes to more than six bytes and every ceiling here is larger.
func huntCanonicalText(s string) string { return huntClip(s, huntCanonicalTextBytes) }

// huntCanonicalHost is the same clip at the ceiling a DNS name lives under. It
// is a class of its own because these are the only strings in a canonical
// report that a hunt function compares rather than displays: a resolver
// lookup's name against a target's host, a certificate's names against the
// server that was asked for. Clipping two of those to a shared prefix would be
// the one way text could change what a case means, and the ceiling is above the
// 253 bytes the protocol allows so that it cannot happen.
func huntCanonicalHost(s string) string { return huntClip(s, huntCanonicalHostBytes) }

// huntCanonicalName is the same clip at the tighter ceiling the model's own
// identifiers live under. See huntCanonicalNameBytes.
func huntCanonicalName(s string) string { return huntClip(s, huntCanonicalNameBytes) }

func huntClip(s string, max int) string {
	// Below this length no string can encode past the ceiling, which keeps the
	// per-rune walk off every short field in the graph.
	if len(s) <= max/6 {
		return s
	}
	cost := len(`""`)
	for i, r := range s {
		blob, err := json.Marshal(string(r))
		if err != nil || cost+len(blob)-len(`""`) > max {
			return s[:i]
		}
		cost += len(blob) - len(`""`)
	}
	return s
}
