package diagnostic

import "slices"

// Route intelligence enters the diagnosis as evidence and never as a verdict.
//
// Nothing in this file can select a diagnosis, add one, or change one. It runs
// after the interpretation pass has already decided what the run proved, and
// it attaches what the operating system's own route decisions say about that
// conclusion. That ordering is the whole design: "there is a VPN on this
// machine" explains a failure at most, and on a working machine it explains
// nothing at all, so a pass that could conclude from a tunnel's presence would
// be diagnosing the configuration rather than the network.
//
// Every item is a fact about one row's own path, checkable against the row
// that recorded it. Where the interesting fact is that two paths differ, it is
// stated as two items, one on each row, rather than as one item that neither
// row can support by itself.

// routeEvidence is the route observations that bear on one conclusion. It
// returns nothing when the platform recorded no decisions, which is the normal
// state on a platform netdoc cannot ask.
func routeEvidence(id DiagnosisID, order []ProbeID, res map[ProbeID]ProbeResult) []CausalEvidence {
	reported := func(check ProbeID) bool {
		_, ok := res[check]
		return ok && slices.Contains(order, check)
	}
	add := func(items []CausalEvidence, check ProbeID, observation ObservationID, value string) []CausalEvidence {
		if !reported(check) {
			return items
		}
		e := CausalEvidence{Kind: EvidenceSupport, Check: check, Observation: observation, Value: value}
		if slices.Contains(items, e) {
			return items
		}
		return append(items, e)
	}

	reference := res[ProbeIface].Routes
	var out []CausalEvidence
	switch id {
	case DiagnosisTargetUnreachable, DiagnosisLocalDeviceUnreachable, DiagnosisTLSTCPUnreachable,
		DiagnosisIPv4TargetUnreachable, DiagnosisIPv6TargetUnreachable, DiagnosisPartialReachability,
		DiagnosisProbablePathMTU:
		target, ok := selectedTargetRoute(res)
		if !ok {
			return nil
		}
		if target.Unreachable {
			out = add(out, ProbeTargetTCP, ObservationRouteUnreachable, target.Destination.String())
		}
		// A tunnel is only worth reporting when it is a difference: the target
		// leaves by something general traffic does not use, or bypasses
		// something general traffic does. A machine where everything goes
		// through the same tunnel has no split to explain.
		familyReference := routeByFamily(reference, target.Family)
		switch splitTunnelState(target, familyReference) {
		case SplitTargetTunneled:
			out = add(out, ProbeTargetTCP, ObservationRouteTunneled, target.Iface)
			out = add(out, ProbeIface, ObservationRouteDirect, familyReference.Iface)
		case SplitTargetBypassesTunnel:
			out = add(out, ProbeTargetTCP, ObservationRouteDirect, target.Iface)
			out = add(out, ProbeIface, ObservationRouteTunneled, familyReference.Iface)
		}
		if split, known := familyPathsDiffer(res[ProbeTargetTCP].Routes); known && split {
			out = add(out, ProbeTargetTCP, ObservationRouteFamilySplit, "")
		}
		out = routePolicyEvidence(add, out, ProbeTargetTCP, target, familyReference)
		// Interface MTU, and only interface MTU. A narrower link on the
		// selected path is consistent with an encapsulated one and is worth
		// putting beside a measured stall; it is never itself the path MTU,
		// which only the path_mtu probe measures.
		if id == DiagnosisProbablePathMTU {
			if _, narrower := narrowerPathMTU(target, familyReference); narrower {
				out = add(out, ProbeTargetTCP, ObservationRouteInterfaceMTU, target.Iface)
			}
		}
	case DiagnosisOffline, DiagnosisLocalEgressFailure, DiagnosisDirectEgressBlocked, DiagnosisDirectEgressDegraded, DiagnosisReachabilityUnlocalized:
		for _, r := range reference {
			if r.Unreachable {
				out = add(out, ProbeIface, ObservationRouteUnreachable, r.Destination.String())
				continue
			}
			if r.Tunneled() {
				out = add(out, ProbeIface, ObservationRouteTunneled, r.Iface)
			}
		}
	case DiagnosisSystemDNSFailure, DiagnosisDNSFailure, DiagnosisDNSDisagreement:
		resolvers := res[ProbeDNS].Routes
		if len(resolvers) == 0 {
			return nil
		}
		target, targetKnown := selectedTargetRoute(res)
		for _, resolver := range resolvers {
			if resolver.Unreachable {
				out = add(out, ProbeDNS, ObservationRouteUnreachable, resolver.Destination.String())
				continue
			}
			// A resolver target tried over a different path from the one the
			// application traffic takes is split DNS, which is a design as often
			// as it is a fault. It is recorded as what it is: a difference.
			if !targetKnown {
				continue
			}
			if comparePaths(resolver, target).Iface == pathDiffers {
				out = add(out, ProbeDNS, ObservationRoutePathDiffers, target.Iface)
			}
			out = routePolicyEvidence(add, out, ProbeDNS, resolver, target)
		}
	}
	return out
}

// routePolicyEvidence records the path differences an interface name cannot
// express: the same link carrying two flows to different routers, and a
// destination the kernel resolved in another routing domain. Both are
// observations about how this row's path was selected, and neither is a fault:
// a machine on a split tunnel, a VRF, or a policy rule is working as designed
// far more often than it is broken.
//
// A next hop is reported only where both sides have one. "On-link here, via
// the router there" is the ordinary shape of a destination on the local
// network rather than a routing policy, and reporting it would fire on every
// home network whose resolver is its own gateway.
//
// A routing table is reported only where this row's own is known and is not
// one the kernel consults by itself. Those are where traffic goes when no rule
// intervened, so they are the reference and not the finding, and an unknown
// table is neither.
//
// It appends through add, so a resolver whose policy difference another
// resolver target already reported is recorded once.
func routePolicyEvidence(add func([]CausalEvidence, ProbeID, ObservationID, string) []CausalEvidence,
	out []CausalEvidence, check ProbeID, path, reference RouteDecision) []CausalEvidence {
	diff := comparePaths(path, reference)
	if diff.NextHop == pathDiffers && diff.Iface == pathSame &&
		path.Gateway != nil && reference.Gateway != nil {
		out = add(out, check, ObservationRouteNextHopDiffers, reference.Gateway.String())
	}
	if domain, _ := routingDomain(path); diff.Table == pathDiffers && domain != "" {
		out = add(out, check, ObservationRouteTableDiffers, "")
	}
	return out
}

// attachRouteEvidence appends route observations to the findings a run already
// produced. It adds no finding and changes no verdict.
func attachRouteEvidence(d *Diagnosis, order []ProbeID, res map[ProbeID]ProbeResult) {
	for i := range d.Findings {
		for _, e := range routeEvidence(d.Findings[i].ID, order, res) {
			if !slices.Contains(d.Findings[i].Evidence, e) {
				d.Findings[i].Evidence = append(d.Findings[i].Evidence, e)
			}
		}
	}
}
