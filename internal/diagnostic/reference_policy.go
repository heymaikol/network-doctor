package diagnostic

// An ordinary run contacts a handful of destinations nobody asked it to
// contact: fixed anycast addresses that stand in for "the internet", two
// captive-portal observation points, a public resolver, a fixed QUIC endpoint,
// a fixed encrypted-DNS provider, and one compiled-in hostname a targetless
// run resolves so there is a DNS question to ask at all. None of it is
// telemetry, and all of it is visible in a firewall log, a proxy log, an IDS
// alert, and a packet capture, which is enough to make it the wrong traffic on
// a restricted host.
//
// This file is the one place that says which probes that describes. It is read
// twice and nowhere else: buildProbes marks the graph it just built, and the
// CLI asks for the same answer by name so it can refuse a --check that
// contradicts the flag, and hand the resolved decision to a --via worker as
// ordinary skips rather than as a protocol field the worker might not know.
//
// TestNoReferenceEgressAttemptsNoBuiltInDestination is what keeps this honest.
// It denies every built-in destination at the netops seam and runs the whole
// DAG, so a new fixed reference probe that never confronted this policy fails
// there instead of shipping.

// referenceEgress reports whether one probe's traffic is aimed at Network
// Doctor's own reference infrastructure in a run of this shape.
//
// Provenance decides it, not who happens to own an address. hasTarget says the
// user named an endpoint, which is what turns the DNS row from "resolve a
// compiled-in name so there is connectivity evidence" into "resolve the name
// that was asked about". publicDNSNamed says --public-dns chose the
// second-opinion resolver, which makes that row's destination one the user
// picked rather than one netdoc picked for them.
func referenceEgress(id ProbeID, hasTarget, publicDNSNamed bool) bool {
	switch id {
	// The fixed anycast endpoints and the two captive-portal endpoints, the
	// fixed QUIC host, and the fixed DoH/DoT provider. All three rows dial
	// netdoc's own choices in every run, whatever the user asked about.
	case ProbeInternet, ProbeQUIC, ProbeDNSEncrypted:
		return true
	// The proxy itself comes from this machine's environment and stays usable.
	// What this row asks it to tunnel to does not: the CONNECT names the
	// compiled-in connectivity host, and on a socks5:// proxy the row also
	// resolves that host first, so the traffic still leaves for a destination
	// netdoc chose.
	case ProbeProxy:
		return true
	// With a target this row resolves the name the user typed. Without one it
	// resolves ConnectivityProbeHost, which is a question netdoc invented.
	case ProbeDNS:
		return !hasTarget
	// The public resolver queries a canonical absolute name; system resolution
	// may apply configured search suffixes. Reference when netdoc chose the
	// resolver, and reference in a targetless run whoever chose it, since the
	// only name left to ask about is the compiled-in one.
	case ProbeDNSPublic:
		return !hasTarget || !publicDNSNamed
	}
	return false
}

// ReferenceEgressProbes lists the probes referenceEgress excludes for a run of
// this shape, in the stable inventory order --check and --skip already use.
//
// The CLI resolves the policy through this once per run, so what a snapshot
// records and what crosses the wire to a --via worker are ordinary probe IDs
// in the existing selection fields. A netdoc old enough to predate the flag
// still honors them, which a new request field would not have achieved.
func ReferenceEgressProbes(hasTarget, publicDNSNamed bool) []ProbeID {
	var ids []ProbeID
	for _, id := range selectableProbeIDs() {
		if referenceEgress(id, hasTarget, publicDNSNamed) {
			ids = append(ids, id)
		}
	}
	return ids
}
