package diagnostic

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Diagnose computes the plain-English summary and its machine-readable
// classification from current-generation native probe state only (tool output
// never feeds in). First-fail ordering + combination rules. Returns
// "Running diagnostics…" until every probe in order has a result. A completed
// run always returns a verdict.
//
// It is a view onto Interpret, which is the one place any of this is decided.
func Diagnose(t *Target, order []ProbeID, res map[ProbeID]ProbeResult) (string, string) {
	d := Interpret(t, order, res)
	return d.Summary, d.Verdict
}

// FocusProbe names the probe row a finished diagnosis is about: the row a
// caller should put the cursor on, take remediation from, and quote evidence
// from. It reads the same interpretation Diagnose reads, so the row and the
// prose cannot disagree, which is the whole reason it exists rather than being
// guessed at from the first failed row. Those two are not the same row nearly
// as often as they look: an outage fails the sibling probes (QUIC, the proxy,
// encrypted DNS) early in probe order while the prose blames a rung further
// down.
//
// Empty when the verdict is about no single row: a healthy run, a run that is
// merely degraded in several places at once, or one still in progress.
func FocusProbe(t *Target, order []ProbeID, res map[ProbeID]ProbeResult) ProbeID {
	return Interpret(t, order, res).Focus()
}

// Interpret is the diagnostic interpretation pass, and the only one there is.
// Everything a caller can ask about what a run means comes from the Diagnosis
// it returns: the summary, the verdict, the stable diagnosis ID, the blamed
// row, and the rows that support the conclusion. They are produced together by
// one walk of the truth table below, which is what makes it impossible for two
// callers to reconstruct the diagnosis differently and end up contradicting
// each other.
func Interpret(t *Target, order []ProbeID, res map[ProbeID]ProbeResult) Diagnosis {
	d := interpret(t, order, res)
	var counterfactuals []DiagnosisFinding
	if d.Verdict != VerdictIncomplete {
		counterfactuals = counterfactualFindings(t, res)
	}
	for _, finding := range counterfactuals {
		matched := false
		for i := range d.Findings {
			if d.Findings[i].ID != finding.ID {
				continue
			}
			d.Findings[i].Counterfactual = finding.Counterfactual
			for _, evidence := range finding.Evidence {
				if !slices.Contains(d.Findings[i].Evidence, evidence) {
					d.Findings[i].Evidence = append(d.Findings[i].Evidence, evidence)
				}
			}
			matched = true
			break
		}
		if matched {
			continue
		}
		if len(d.Findings) == 0 {
			d.Summary, d.Verdict = finding.Summary, finding.Verdict
		}
		d.Findings = append(d.Findings, finding)
	}
	// Route intelligence lands last, and only ever as evidence on a
	// conclusion the branches above already reached.
	attachRouteEvidence(&d, order, res)
	// Confidence after all of it, because it is a claim about the strength of
	// the evidence a finding carries and both stages above are still allowed to
	// change what that is. It reads the finished finding and writes one field;
	// nothing below it reads that field back.
	for i := range d.Findings {
		d.Findings[i].Confidence = confidenceFor(d.Findings[i])
	}
	// The row a caller should point at, which is the row the diagnosis names
	// when it names one and otherwise the first failure. A verdict about no
	// single row still leaves a reader wanting somewhere to look.
	d.Blamed = d.Focus()
	if d.Blamed == "" {
		for _, id := range order {
			if r, ok := res[id]; ok && r.Status == StatusFail {
				d.Blamed = id
				break
			}
		}
	}
	return d
}

// interpret walks the truth table. Every case whose sentence is about one rung
// returns a finding naming that rung (see blame below); the handful whose
// sentence is about the run as a whole return a verdict with no finding under
// it.
func interpret(t *Target, order []ProbeID, res map[ProbeID]ProbeResult) Diagnosis {
	// plain is a run-level answer with nothing specific to name: nothing was
	// selected, nothing has finished, everything works, or several unrelated
	// rungs are impaired at once. Deliberately not a finding, because there is
	// no single thing here that was proven wrong.
	plain := func(summary, verdict string) Diagnosis {
		return Diagnosis{Summary: summary, Verdict: verdict}
	}
	if len(order) == 0 {
		return plain("No checks selected.", VerdictOK)
	}
	degraded := false
	for _, id := range order {
		r, ok := res[id]
		if !ok {
			return plain("Running diagnostics…", VerdictIncomplete)
		}
		degraded = degraded || r.Status == StatusWarn
	}
	// Everything the caller asked for works; a Warn anywhere still counts.
	healthy := VerdictOK
	if degraded {
		healthy = VerdictDegraded
	}
	has := func(id ProbeID) bool { _, ok := res[id]; return ok }
	pass := func(id ProbeID) bool { r, ok := res[id]; return ok && r.Status == StatusPass }
	fail := func(id ProbeID) bool { r, ok := res[id]; return ok && r.Status == StatusFail }
	warn := func(id ProbeID) bool { r, ok := res[id]; return ok && r.Status == StatusWarn }
	// Each protocol probe reports a timeout in the vocabulary it has: TLS
	// classifies every handshake failure into a Cause, HTTP and HTTPS have no
	// such taxonomy and carry a plain flag.
	timedOut := func(id ProbeID) bool {
		r, ok := res[id]
		return ok && (r.timedOut || r.Cause == TLSCauseTimeout)
	}
	directOK := func() bool { return directEgressOK(res) }
	// observed turns one probe result into the most specific typed fact it
	// carries. The result remains the observation store; this only identifies
	// which field the diagnosis used.
	observed := func(id ProbeID) (CausalEvidence, bool) {
		r, ok := res[id]
		if !ok {
			return CausalEvidence{}, false
		}
		e := CausalEvidence{Kind: EvidenceSupport, Check: id}
		switch {
		case r.Portal != nil:
			e.Observation = ObservationCaptivePortal
		case r.DNSNotFound:
			e.Observation = ObservationDNSNotFound
		case r.Cause != "":
			e.Observation = ObservationCause
			e.Value = r.causeFamily
		case r.timedOut:
			e.Observation = ObservationTimeout
		case r.downgraded:
			e.Observation = ObservationStatusDowngraded
		case len(r.Addrs) > 0:
			e.Observation = ObservationDNSAnswers
		case r.Status == StatusPass:
			e.Observation = ObservationStatusPass
		case r.Status == StatusWarn:
			e.Observation = ObservationStatusWarn
		case r.Status == StatusFail:
			e.Observation = ObservationStatusFail
		case r.Status == StatusSkip:
			e.Kind, e.Observation, e.Reason = EvidenceNotEvaluated, ObservationStatusSkip, NotEvaluatedPrerequisite
		case r.Status == StatusNA:
			e.Kind, e.Observation, e.Reason = EvidenceNotEvaluated, ObservationStatusNA, NotEvaluatedNotApplicable
		default:
			return CausalEvidence{}, false
		}
		return e, true
	}
	observationExists := func(id ProbeID, observation ObservationID) bool {
		r, ok := res[id]
		if !ok {
			return false
		}
		switch observation {
		case ObservationStatusPass:
			return r.Status == StatusPass
		case ObservationStatusWarn:
			return r.Status == StatusWarn && !r.downgraded
		case ObservationStatusFail:
			return r.Status == StatusFail
		case ObservationStatusSkip:
			return r.Status == StatusSkip
		case ObservationStatusNA:
			return r.Status == StatusNA
		case ObservationCause:
			return r.Cause != ""
		case ObservationDNSAnswers:
			return len(r.Addrs) > 0
		case ObservationDNSNotFound:
			return r.DNSNotFound
		case ObservationCaptivePortal:
			return r.Portal != nil
		case ObservationTimeout:
			return r.timedOut || r.Cause == TLSCauseTimeout
		case ObservationClockOffset:
			return r.clockOffset.Abs() >= clockSkewThreshold
		case ObservationStatusDowngraded:
			return r.downgraded
		}
		return false
	}
	supportRows := func(rows ...ProbeID) []CausalEvidence {
		out := make([]CausalEvidence, 0, len(rows))
		for _, id := range rows {
			if e, ok := observed(id); ok {
				out = append(out, e)
			}
		}
		return out
	}
	supportObservation := func(id ProbeID, observation ObservationID) CausalEvidence {
		if !observationExists(id, observation) {
			return CausalEvidence{}
		}
		return CausalEvidence{Kind: EvidenceSupport, Check: id, Observation: observation}
	}
	relation := func(kind EvidenceKind, candidate DiagnosisID, id ProbeID, observation ObservationID) CausalEvidence {
		if (kind != EvidenceContradiction && kind != EvidenceRuledOut) || candidate == "" ||
			observation == ObservationStatusSkip || observation == ObservationStatusNA ||
			!observationExists(id, observation) {
			return CausalEvidence{}
		}
		return CausalEvidence{Kind: kind, Check: id, Observation: observation, Candidate: candidate}
	}
	contradicts := func(candidate DiagnosisID, id ProbeID, observation ObservationID) CausalEvidence {
		return relation(EvidenceContradiction, candidate, id, observation)
	}
	rulesOut := func(candidate DiagnosisID, id ProbeID, observation ObservationID) CausalEvidence {
		return relation(EvidenceRuledOut, candidate, id, observation)
	}
	notEvaluated := func(id ProbeID, reason NotEvaluatedReason) CausalEvidence {
		e := CausalEvidence{Kind: EvidenceNotEvaluated, Check: id, Reason: reason}
		switch reason {
		case NotEvaluatedPrerequisite:
			if observationExists(id, ObservationStatusSkip) {
				e.Observation = ObservationStatusSkip
				return e
			}
		case NotEvaluatedNotApplicable:
			if observationExists(id, ObservationStatusNA) {
				e.Observation = ObservationStatusNA
				return e
			}
		case NotEvaluatedNotSelected:
			if _, exists := res[id]; !exists && !slices.Contains(order, id) {
				return e
			}
		case NotEvaluatedIncomplete:
			if _, exists := res[id]; !exists && slices.Contains(order, id) {
				return e
			}
		}
		return CausalEvidence{}
	}
	addEvidence := func(base []CausalEvidence, extra ...CausalEvidence) []CausalEvidence {
		for _, e := range extra {
			if e.Check != "" {
				base = append(base, e)
			}
		}
		return base
	}
	// blame records the finding the sentence being returned carries: its
	// stable identity, the row it is about, and the other rows it was drawn
	// from. The caller uses the row to put the cursor, the remediation and the
	// evidence where the prose points, instead of guessing at the first failed
	// row: those two are the same row far less often than they look, because
	// the sibling probes (QUIC, the proxy, encrypted DNS) fail early in probe
	// order in exactly the outages the prose blames on something else.
	//
	// A sentence with no single subject deliberately blames nothing and
	// carries no identity: a caller with no row to point at is honest, and one
	// pointed at an arbitrary row is not. Those cases return plain instead.
	withEvidence := func(id DiagnosisID, focus ProbeID, summary, verdict string, evidence []CausalEvidence) Diagnosis {
		seen := make(map[CausalEvidence]bool, len(evidence))
		clean := make([]CausalEvidence, 0, len(evidence))
		for _, e := range evidence {
			if e.Check == "" || seen[e] {
				continue
			}
			seen[e] = true
			clean = append(clean, e)
		}
		finding := DiagnosisFinding{
			ID:       id,
			Verdict:  verdict,
			Summary:  summary,
			Focus:    focus,
			Evidence: clean,
		}
		return Diagnosis{Summary: summary, Verdict: verdict, Findings: []DiagnosisFinding{finding}}
	}
	blame := func(id DiagnosisID, focus ProbeID, summary, verdict string, from ...ProbeID) Diagnosis {
		return withEvidence(id, focus, summary, verdict, supportRows(append([]ProbeID{focus}, from...)...))
	}
	fallback := func() Diagnosis {
		for _, id := range order {
			switch {
			case !fail(id):
				continue
			case id == ProbeDNS:
				return blame(DiagnosisSelectedDNSCheckFailed, id, "A selected DNS check failed.", VerdictDNS)
			case id == ProbeTLS || id == ProbeHTTP || id == ProbeHTTPS || id == ProbeSSH || id == ProbeSMTP:
				return blame(DiagnosisSelectedServiceCheckFailed, id, "A selected service check failed.", VerdictService)
			default:
				return blame(DiagnosisSelectedNetworkCheckFailed, id, "A selected network check failed.", VerdictNetwork)
			}
		}
		if degraded {
			return plain("Selected checks completed with warnings.", VerdictDegraded)
		}
		return plain("Selected checks passed.", VerdictOK)
	}

	if fail(ProbeIface) {
		evidence := addEvidence(supportRows(ProbeIface),
			notEvaluated(ProbeInternet, NotEvaluatedPrerequisite),
			notEvaluated(ProbeDNS, NotEvaluatedPrerequisite))
		return withEvidence(DiagnosisNoUsableInterface, ProbeIface, "No usable network interface: the link is down.", VerdictNetwork, evidence)
	}

	prx := proxyCarries(res)
	prxDown := has(ProbeProxy) && fail(ProbeProxy)
	publicResolves := has(ProbeDNSPublic) && len(res[ProbeDNSPublic].Addrs) > 0
	bothNotFound := has(ProbeDNS) && res[ProbeDNS].DNSNotFound && has(ProbeDNSPublic) && res[ProbeDNSPublic].DNSNotFound

	// Generic mode (no target): the verdict is a truth table over egress, DNS,
	// and proxy state. Cases are ordered most-specific first because several
	// overlap, and reordering them changes answers, so don't.
	if t == nil {
		ip, dn := pass(ProbeInternet), pass(ProbeDNS)
		hasInternet := has(ProbeInternet)
		// Generic mode has only two rungs to lose, and which one broke doesn't
		// partition the prose cases cleanly, so classify it once up front.
		// Without egress a DNS failure is a symptom of the outage, not a
		// separate one; a working proxy makes a dead direct route a degradation.
		gv := healthy
		switch {
		case hasInternet && !directOK() && fail(ProbeDNS):
			gv = VerdictNetwork
		case fail(ProbeDNS):
			gv = VerdictDNS
		case hasInternet && !directOK() && !prx:
			gv = VerdictNetwork
		case hasInternet && !directOK():
			gv = VerdictDegraded
		}
		switch {
		case hasInternet && res[ProbeInternet].Portal != nil:
			return blame(DiagnosisCaptivePortal, ProbeInternet, "Behind a captive portal: traffic is intercepted until you sign in to the network.", VerdictNetwork)
		case directOK() && fail(ProbeDNS) && publicResolves:
			evidence := addEvidence(supportRows(ProbeDNS, ProbeDNSPublic, ProbeInternet),
				contradicts(DiagnosisDNSFailure, ProbeDNSPublic, ObservationDNSAnswers),
				rulesOut(DiagnosisDNSNameNotFound, ProbeDNSPublic, ObservationDNSAnswers),
				rulesOut(DiagnosisOffline, ProbeInternet, ObservationStatusPass))
			return withEvidence(DiagnosisSystemDNSFailure, ProbeDNS, "System DNS is failing, but public DNS resolves the name. Check the configured resolver, VPN, or DNS filter.", gv, evidence)
		case directOK() && fail(ProbeDNS) && bothNotFound:
			evidence := addEvidence(supportRows(ProbeDNS, ProbeDNSPublic, ProbeInternet),
				rulesOut(DiagnosisSystemDNSFailure, ProbeDNSPublic, ObservationDNSNotFound),
				rulesOut(DiagnosisOffline, ProbeInternet, ObservationStatusPass))
			return withEvidence(DiagnosisDNSNameNotFound, ProbeDNS, "Internet egress works, but the DNS test name has no A/AAAA records according to either resolver.", gv, evidence)
		case directOK() && has(ProbeQUIC) && fail(ProbeQUIC):
			return blame(DiagnosisQUICUnavailable, ProbeQUIC, "Direct TCP/443 works, but the QUIC handshake over UDP/443 failed. Applications can fall back to TCP, which may feel slower.", VerdictDegraded, ProbeInternet)
		case encryptedDNSBlocked(res):
			return blame(DiagnosisEncryptedDNSUnavailable, ProbeDNSEncrypted, encryptedDNSSummary, VerdictDegraded, ProbeDNS, ProbeDNSPublic, ProbeInternet)
		case warn(ProbeDNSPublic) && has(ProbeDNS) && functional(res[ProbeDNS].Status):
			return blame(DiagnosisDNSDisagreement, ProbeDNSPublic, "Online, but system DNS and public DNS disagree; split DNS or filtering may be intentional (see the DNS rows).", gv, ProbeDNS)
		case ip && dn && prxDown:
			return blame(DiagnosisProxyFailure, ProbeProxy, "Online directly, but the configured environment proxy check failed, so apps that use the proxy will fail (see the proxy row).", VerdictDegraded, ProbeInternet, ProbeDNS)
		case ip && dn:
			return plain("Online: direct TCP egress and DNS both work.", gv)
		case warn(ProbeInternet) && res[ProbeInternet].downgraded && dn && prx:
			return blame(DiagnosisProxyOnlyNetwork, ProbeInternet, "Online via the environment proxy: direct egress is blocked (proxy-only network).", gv, ProbeProxy, ProbeDNS)
		case warn(ProbeInternet) && res[ProbeInternet].downgraded && fail(ProbeDNS) && prx:
			// The same proxy-only network as the case above, with its resolver
			// gone too. The Warn here is downgradeEgress's, not the probe's, so
			// the direct route is dead rather than impaired and the prose must
			// not promise egress the machine does not have.
			//
			// The resolver is the row blamed rather than the dead direct one:
			// a proxy-only network with no default route is working as
			// designed, which is why downgradeEgress already took the routing
			// repair off the egress row. The resolver is the half of this
			// sentence there is still something to do about.
			return blame(DiagnosisDNSFailure, ProbeDNS, "Direct egress is blocked and DNS resolution is failing; only the environment proxy is carrying traffic.", gv, ProbeInternet, ProbeProxy)
		case directOK() && warn(ProbeInternet) && dn:
			return blame(DiagnosisDirectEgressDegraded, ProbeInternet, "Online but degraded: direct egress is impaired (see the ! row for details).", gv, ProbeDNS)
		case directOK() && warn(ProbeInternet) && fail(ProbeDNS):
			// directOK, so this is a Warn the egress probe raised itself: one
			// family down, packet loss, and so on. Direct egress really does
			// carry traffic here, which is what separates it from the case
			// above.
			evidence := addEvidence(supportRows(ProbeDNS, ProbeInternet),
				rulesOut(DiagnosisOffline, ProbeInternet, ObservationStatusWarn))
			return withEvidence(DiagnosisDNSFailure, ProbeDNS, "Internet egress works (degraded) but DNS resolution is failing.", gv, evidence)
		case ip && fail(ProbeDNS):
			evidence := addEvidence(supportRows(ProbeDNS, ProbeInternet),
				rulesOut(DiagnosisOffline, ProbeInternet, ObservationStatusPass))
			return withEvidence(DiagnosisDNSFailure, ProbeDNS, "Internet egress works but DNS resolution is failing.", gv, evidence)
		case hasInternet && !directOK() && dn:
			return blame(DiagnosisDirectEgressBlocked, ProbeInternet, "DNS resolves but there's no direct TCP egress to the egress check's reference endpoints (proxy-only or filtered network?).", gv, ProbeDNS)
		case fail(ProbeInternet) && fail(ProbeDNS):
			// Egress, not the resolver: nothing this machine sends is
			// arriving, so the resolver has not been given a fair test yet.
			return blame(DiagnosisOffline, ProbeInternet, "Offline: neither DNS nor direct TCP to the egress check's reference endpoints is working.", gv, ProbeDNS)
		default:
			return fallback()
		}
	}

	host := t.Host
	hp := net.JoinHostPort(host, strconv.Itoa(t.Port)) // brackets IPv6 literals

	// Targeted mode: walk up the protocol stack (DNS → TCP → TLS → HTTP →
	// banner) and report the first rung that broke. Everything above it
	// failing is implied, everything below it passing is context.
	//
	// The rows that decide whether the target works are also the rows a
	// verdict about the target rests on, so they are named once and used for
	// both.
	endpoint := targetRows(t)
	targetOK := true
	for _, id := range endpoint {
		targetOK = targetOK && has(id) && functional(res[id].Status)
	}
	// Protocol rungs that spent their whole budget rather than answering,
	// which is half of the path-MTU correlation below and the evidence a
	// path-MTU verdict cites. Immediate failures such as a bad certificate are
	// deliberately absent: they must continue down to their service-specific
	// verdict.
	var stalled []ProbeID
	for _, id := range []ProbeID{ProbeTLS, ProbeHTTP, ProbeHTTPS} {
		if fail(id) && timedOut(id) {
			stalled = append(stalled, id)
		}
	}

	switch {
	case has(ProbeInternet) && res[ProbeInternet].Portal != nil:
		// Ahead of the DNS rung: behind a portal every rung below is answering
		// for the portal, so nothing further down the stack means what it says.
		return blame(DiagnosisCaptivePortal, ProbeInternet, "Behind a captive portal: sign in to the network before trusting anything about "+host+".", VerdictNetwork)
	case fail(ProbeDNS):
		id := DiagnosisDNSFailure
		v := "Cannot resolve " + host + ": DNS failure."
		if publicResolves {
			id = DiagnosisSystemDNSFailure
			v = "System DNS cannot resolve " + host + ", but public DNS can, so the configured resolver is failing or filtering the name."
		} else if bothNotFound {
			id = DiagnosisDNSNameNotFound
			v = host + " has no A/AAAA records according to either system or public DNS."
		}
		if directOK() {
			v += " (The general internet is reachable.)"
		}
		evidence := supportRows(ProbeDNS, ProbeDNSPublic, ProbeInternet)
		switch id {
		case DiagnosisSystemDNSFailure:
			evidence = addEvidence(evidence,
				contradicts(DiagnosisDNSFailure, ProbeDNSPublic, ObservationDNSAnswers),
				rulesOut(DiagnosisDNSNameNotFound, ProbeDNSPublic, ObservationDNSAnswers))
		case DiagnosisDNSNameNotFound:
			evidence = addEvidence(evidence,
				rulesOut(DiagnosisSystemDNSFailure, ProbeDNSPublic, ObservationDNSNotFound))
		}
		if directOK() {
			observation := ObservationStatusPass
			if warn(ProbeInternet) {
				observation = ObservationStatusWarn
			}
			evidence = addEvidence(evidence, rulesOut(DiagnosisOffline, ProbeInternet, observation))
		}
		evidence = addEvidence(evidence, notEvaluated(ProbeTargetTCP, NotEvaluatedPrerequisite))
		return withEvidence(id, ProbeDNS, v, VerdictDNS, evidence)
	case fail(ProbeTargetTCP):
		// A device on the same network is not reached through the internet, so
		// the egress rung is not evidence about it either way and none of the
		// sentences below fit: they explain a failure by a route this target
		// never takes. What is left is what the connect itself said.
		if localTarget(t, res) {
			switch {
			case res[ProbeTargetTCP].Cause == ConnectionCauseRefused:
				// Something answered for that address, so the device is on the
				// network and the port is the whole of the problem.
				evidence := addEvidence(supportRows(ProbeTargetTCP),
					rulesOut(DiagnosisLocalDeviceUnreachable, ProbeTargetTCP, ObservationCause))
				return withEvidence(DiagnosisTCPConnectionRefused, ProbeTargetTCP, "Every TCP connection attempt to "+hp+" was explicitly refused: the device is on the network, but nothing is listening on that port.", VerdictService, evidence)
			case directOK():
				// This machine's own networking demonstrably works, so the
				// silence is the device's. Which of the reasons it is cannot be
				// told from here, and the sentence must not pick one.
				return blame(DiagnosisLocalDeviceUnreachable, ProbeTargetTCP, hp+" did not answer, though this machine's network is working: the device may be powered off or asleep, may have a different address now, or may be dropping the connection.", VerdictService, ProbeInternet)
			case !has(ProbeInternet):
				evidence := addEvidence(supportRows(ProbeTargetTCP),
					notEvaluated(ProbeInternet, NotEvaluatedNotSelected))
				return withEvidence(DiagnosisReachabilityUntested, ProbeTargetTCP, hp+" did not answer, and this machine's own network was not checked, so a problem here cannot be told apart from one on the device.", VerdictNetwork, evidence)
			case localPathObserved(res[ProbeInternet].Cause):
				// The routing tables observed the break, so nothing this
				// machine sends is arriving anywhere and the device has not
				// been given a fair test yet.
				return blame(DiagnosisLocalEgressFailure, ProbeInternet, hp+" did not answer, and neither did the egress check's reference endpoints; this machine's own routing state says why: fix this machine's own connection first.", VerdictNetwork, ProbeTargetTCP)
			default:
				// Everything tried was silent and nothing looked at where. A
				// device that is switched off and a machine whose traffic
				// never leaves are the same picture from here.
				return blame(DiagnosisReachabilityUnlocalized, ProbeInternet, hp+" did not answer, and neither did the egress check's reference endpoints; nothing this run observed says whether the break is on this machine, on the device, or between them.", VerdictNetwork, ProbeTargetTCP)
			}
		}
		// Without working direct egress we can't tell a closed port from a dead
		// path, so we don't guess: that's a network answer, not a service one.
		// A working proxy proves the box is online but says nothing about the
		// direct route this target needs.
		if directOK() {
			if res[ProbeTargetTCP].Cause == ConnectionCauseRefused {
				evidence := addEvidence(supportRows(ProbeTargetTCP, ProbeInternet),
					rulesOut(DiagnosisTargetUnreachable, ProbeTargetTCP, ObservationCause),
					rulesOut(DiagnosisLocalEgressFailure, ProbeInternet, ObservationStatusPass))
				return withEvidence(DiagnosisTCPConnectionRefused, ProbeTargetTCP, "Every TCP connection attempt to "+hp+" was explicitly refused: the service may not be listening, or a firewall may be actively rejecting it.", VerdictService, evidence)
			}
			evidence := addEvidence(supportRows(ProbeTargetTCP, ProbeInternet, ProbeDNS),
				rulesOut(DiagnosisLocalEgressFailure, ProbeInternet, ObservationStatusPass),
				rulesOut(DiagnosisDNSFailure, ProbeDNS, ObservationDNSAnswers))
			return withEvidence(DiagnosisTargetUnreachable, ProbeTargetTCP, hp+" is unreachable though DNS and the general internet work: remote port closed, firewall, or VPN routing.", VerdictService, evidence)
		}
		if prx {
			return blame(DiagnosisProxyOnlyNetwork, ProbeTargetTCP, hp+" is unreachable directly, but the environment proxy has egress: this is a proxy-only network, so route traffic through the proxy.", VerdictNetwork, ProbeProxy, ProbeInternet)
		}
		if !has(ProbeInternet) {
			evidence := addEvidence(supportRows(ProbeTargetTCP),
				notEvaluated(ProbeInternet, NotEvaluatedNotSelected))
			return withEvidence(DiagnosisReachabilityUntested, ProbeTargetTCP, hp+" is unreachable, but general internet reachability was not checked, so a local path problem cannot be told apart from a remote service failure.", VerdictNetwork, evidence)
		}
		// The egress row, not the target row: both sentences below are about
		// this machine's path off the network, and the target connect is what
		// that path looks like from one rung further up. Which of the two the
		// run has earned is decided by whether anything observed where the
		// break is; two destinations going silent together does not.
		if localPathObserved(res[ProbeInternet].Cause) {
			return blame(DiagnosisLocalEgressFailure, ProbeInternet, host+" resolves but neither it nor the egress check's reference endpoints are reachable, and this machine's own routing state says why: local egress problem.", VerdictNetwork, ProbeTargetTCP, ProbeDNS)
		}
		return blame(DiagnosisReachabilityUnlocalized, ProbeInternet, host+" resolves but neither it nor the egress check's reference endpoints answered, and nothing this run observed says where the path breaks.", VerdictNetwork, ProbeTargetTCP, ProbeDNS)
	case warn(ProbePMTU) && len(stalled) > 0:
		// A protocol timeout and a separate bulk-write stall are correlated
		// evidence for a path problem. Immediate failures such as a bad
		// certificate must continue down to their service-specific verdict.
		return blame(DiagnosisProbablePathMTU, ProbePMTU, "TCP reaches "+hp+" but the protocol and bulk-transfer checks both stall, which is evidence of a path MTU black hole rather than a broken service (see the Path MTU row).", VerdictNetwork, append([]ProbeID{ProbeTargetTCP}, stalled...)...)
	case has(ProbeTLS) && fail(ProbeTLS):
		// With a measured offset that points the same way as the certificate
		// error there is nothing left to hedge about, so name it instead.
		// An offset pointing the other way settles the hedge just as well, in
		// the opposite direction: it cannot have caused this, so it comes off
		// the list of maybes instead of onto it.
		if d, ok := clockSkew(res); ok {
			switch {
			case skewExplainsTLS(res[ProbeTLS].Cause, d):
				evidence := addEvidence(supportRows(ProbeTLS, ProbeInternet, ProbeTargetTCP),
					supportObservation(ProbeInternet, ObservationClockOffset),
					rulesOut(DiagnosisTLSTCPUnreachable, ProbeTargetTCP, ObservationStatusPass))
				return withEvidence(DiagnosisTLSClockSkew, ProbeTLS, "TCP reaches "+hp+" but the TLS handshake fails because "+clockSkewPhrase(d)+", so "+clockSkewEffect(d)+".", VerdictService, evidence)
			case skewDisprovesTLS(res[ProbeTLS].Cause, d):
				id := tlsDiagnosisID(res[ProbeTLS].Cause)
				evidence := addEvidence(supportRows(ProbeTLS, ProbeInternet, ProbeTargetTCP),
					rulesOut(DiagnosisTLSClockSkew, ProbeInternet, ObservationClockOffset),
					rulesOut(DiagnosisTLSTCPUnreachable, ProbeTargetTCP, ObservationStatusPass))
				return withEvidence(id, ProbeTLS, "TCP reaches "+hp+" but the TLS handshake fails: bad/expired cert or MITM proxy.", VerdictService, evidence)
			}
		}
		id := tlsDiagnosisID(res[ProbeTLS].Cause)
		evidence := supportRows(ProbeTLS, ProbeTargetTCP)
		if id != DiagnosisTLSTCPUnreachable {
			evidence = addEvidence(evidence,
				rulesOut(DiagnosisTLSTCPUnreachable, ProbeTargetTCP, ObservationStatusPass))
		}
		return withEvidence(id, ProbeTLS, "TCP reaches "+hp+" but the TLS handshake fails: bad/expired cert, clock skew, or MITM proxy.", VerdictService, evidence)
	case has(ProbeHTTPS) && fail(ProbeHTTPS):
		evidence := addEvidence(supportRows(ProbeHTTPS, ProbeTLS),
			rulesOut(DiagnosisTLSHandshakeFailure, ProbeTLS, ObservationStatusPass))
		return withEvidence(DiagnosisHTTPSNoResponse, ProbeHTTPS, "TLS is fine but no HTTPS response from "+hp+": application-layer or proxy block.", VerdictService, evidence)
	case has(ProbeHTTP) && fail(ProbeHTTP):
		if t.Proto == ProtoTLSHTTP {
			return blame(DiagnosisHTTPNoResponse, ProbeHTTP, "HTTPS works but no HTTP response from "+net.JoinHostPort(host, "80")+": the redirect/plain-HTTP endpoint may be blocked.", VerdictService, ProbeHTTPS)
		}
		return blame(DiagnosisHTTPNoResponse, ProbeHTTP, "No HTTP response from "+hp+": application-layer or proxy block.", VerdictService, ProbeTargetTCP)
	case (has(ProbeSSH) && fail(ProbeSSH)) || (has(ProbeSMTP) && fail(ProbeSMTP)):
		return blame(DiagnosisServiceBannerFailure, bannerRow(res, fail), hp+" accepts TCP but the service banner check failed.", VerdictService, ProbeTargetTCP)
	case (has(ProbeSSH) && warn(ProbeSSH)) || (has(ProbeSMTP) && warn(ProbeSMTP)):
		return blame(DiagnosisServiceBannerMissing, bannerRow(res, warn), hp+" accepts TCP but sent no service banner.", VerdictDegraded, ProbeTargetTCP)
	case targetOK && has(ProbeQUIC) && fail(ProbeQUIC) && directOK():
		return blame(DiagnosisQUICUnavailable, ProbeQUIC, "The target and direct TCP/443 work, but the QUIC handshake over UDP/443 failed. Applications can fall back to TCP, which may feel slower.", VerdictDegraded, ProbeInternet)
	case encryptedDNSBlocked(res):
		return blame(DiagnosisEncryptedDNSUnavailable, ProbeDNSEncrypted, encryptedDNSSummary, VerdictDegraded, ProbeDNS, ProbeDNSPublic, ProbeInternet)
	case targetOK && (fail(ProbeInternet) || (warn(ProbeInternet) && res[ProbeInternet].downgraded)):
		if publicTargetReachedDirectly(t, res) {
			// A public destination answered a direct connection on this run,
			// which refutes "direct egress is blocked" rather than softening
			// it: traffic did leave this machine without a proxy. What the run
			// observed is narrower and still worth saying, so it says that.
			// The row that observed the connection, in whichever state it
			// reported it: a target that answered slowly still answered, and
			// citing only a clean Pass would drop the refutation on exactly
			// the runs where the path is impaired.
			reached := ObservationStatusPass
			if warn(ProbeTargetTCP) {
				reached = ObservationStatusWarn
			}
			evidence := addEvidence(supportRows(append([]ProbeID{ProbeInternet, ProbeTargetTCP}, endpoint...)...),
				rulesOut(DiagnosisDirectEgressBlocked, ProbeTargetTCP, reached))
			return withEvidence(DiagnosisReferenceEgressUnreachable, ProbeInternet,
				"The target answered a direct connection, so direct egress works; the egress check's own fixed reference endpoints are what did not answer.",
				VerdictDegraded, evidence)
		}
		return blame(DiagnosisDirectEgressBlocked, ProbeInternet, "The target works but direct TCP egress to the egress check's reference endpoints is blocked (proxy-only or filtered network?).", VerdictDegraded, endpoint...)
	case targetOK && prxDown && directOK():
		return blame(DiagnosisProxyFailure, ProbeProxy, "The target and direct egress work, but the configured environment proxy check failed, so apps that use the proxy will fail (see the proxy row).", VerdictDegraded, ProbeInternet)
	case targetOK && warn(ProbeInternet):
		return blame(DiagnosisDirectEgressDegraded, ProbeInternet, "The target works but direct egress to the egress check's reference endpoints is degraded (see the ! row for details).", VerdictDegraded, endpoint...)
	case targetOK && warn(ProbeDNSPublic) && has(ProbeDNS) && functional(res[ProbeDNS].Status):
		return blame(DiagnosisDNSDisagreement, ProbeDNSPublic, "The target works, but system DNS and public DNS disagree; split DNS or filtering may be intentional (see the DNS rows).", VerdictDegraded, ProbeDNS)
	case targetOK && degraded:
		return plain("The target works, but some checks are degraded (see the ! rows for details).", VerdictDegraded)
	case targetOK:
		return plain("All checks passed. "+hp+" looks healthy.", VerdictOK)
	default:
		return fallback()
	}
}

// targetRows names the probe rows that decide whether the endpoint under test
// works, which the target's protocol chooses. Every row named has to be
// functional for the target to count as working, so the same list is both the
// test and the evidence a verdict about the target rests on.
func targetRows(t *Target) []ProbeID {
	switch t.Proto {
	case ProtoTLSHTTP:
		return []ProbeID{ProbeHTTP, ProbeHTTPS}
	case ProtoHTTP:
		return []ProbeID{ProbeHTTP}
	case ProtoSSH:
		return []ProbeID{ProbeSSH}
	case ProtoSMTP:
		return []ProbeID{ProbeSMTP}
	}
	return []ProbeID{ProbeTargetTCP}
}

// Verdict classifications: the second half of Diagnose's return, for scripts
// that need the shape of the failure without parsing English. It answers the
// question the prose answers, in one word: is this a broken path or a broken
// service? Stable vocabulary.
const (
	VerdictOK         = "ok"         // nothing failed, nothing degraded
	VerdictDegraded   = "degraded"   // everything asked for works, some rung is impaired
	VerdictDNS        = "dns"        // the name did not resolve
	VerdictNetwork    = "network"    // the path is unavailable, so we never got to ask the service
	VerdictService    = "service"    // the path works, the service on the far end does not
	VerdictIncomplete = "incomplete" // a probe has no result yet
)

func functional(s Status) bool {
	return s == StatusPass || s == StatusWarn
}

// bannerRow picks which of the two service-banner rungs a banner verdict is
// about. A run carries at most one of them (the target's protocol chooses it),
// so match is asked which one is in the state the verdict describes, and SMTP
// is the answer when SSH is not.
func bannerRow(res map[ProbeID]ProbeResult, match func(ProbeID) bool) ProbeID {
	if _, ok := res[ProbeSSH]; ok && match(ProbeSSH) {
		return ProbeSSH
	}
	return ProbeSMTP
}

// encryptedDNSSummary is what the probes can actually support: plaintext
// resolution demonstrably works and encrypted resolution demonstrably does not.
// It stops there. Nothing here proves the network *forced* anything: an
// operator's intent is not observable from a client, and neither is whatever a
// browser did next about it.
const encryptedDNSSummary = "Plain DNS works, but encrypted DNS could not complete a verified exchange. The resolver may be unavailable, or the network may be blocking or interfering with DoH/DoT."

// localTarget reports whether the endpoint under test sits on a local network
// rather than out on the internet. That distinction is what decides whether
// the direct-egress rung is evidence about reaching it at all: a printer down
// the hall is reached over the same link whether or not anything past the
// router is answering.
//
// A literal settles it on its own. A name settles it only when every address
// it resolved to is local, so a name that also has a public address keeps the
// ordinary internet-facing reading.
func localTarget(t *Target, res map[ProbeID]ProbeResult) bool {
	if t == nil {
		return false
	}
	if t.IP != nil {
		return localIP(t.IP)
	}
	addrs := res[ProbeDNS].Addrs
	if len(addrs) == 0 {
		return false
	}
	for _, ip := range addrs {
		if !localIP(ip) {
			return false
		}
	}
	return true
}

// localIP is the address ranges that are reachable without leaving the local
// network: RFC1918 and its IPv6 equivalent, link-local, and this machine.
func localIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback()
}

// directEgressOK means direct egress genuinely worked: a Pass, or a Warn the
// probe produced itself. A Warn planted by downgradeEgress doesn't count:
// that's a Fail wearing a nicer hat.
func directEgressOK(res map[ProbeID]ProbeResult) bool {
	r, ok := res[ProbeInternet]
	return ok && functional(r.Status) && !r.downgraded
}

// The egress row is a sample, not an oracle. It dials a fixed pair of anycast
// reference addresses, so what a failure there observes is that those
// addresses did not answer. Two other things in a run bear on how far that
// observation may be carried, and these are the only two questions the
// interpretation pass asks about it.

// publicTargetReachedDirectly reports whether some destination other than the
// reference addresses answered a direct connection on this run. The endpoint
// check dials the target itself, with no proxy in the path, so a public target
// answering is a direct counterexample to "direct egress is blocked": one
// destination refusing a run's traffic while another accepts it is a fact
// about those destinations. A device on the local network proves nothing here,
// because it is reached without leaving the network at all.
func publicTargetReachedDirectly(t *Target, res map[ProbeID]ProbeResult) bool {
	r, ok := res[ProbeTargetTCP]
	return ok && functional(r.Status) && t != nil && !localTarget(t, res)
}

// localPathObserved reports whether the operating system's own routing and
// neighbor tables classified the dead direct path. Those causes are read from
// local state rather than inferred from what failed to answer, which is what
// separates a located break from a set of destinations that happened to be
// silent together. Without one, reference endpoints and a target failing at the
// same moment is a correlation, and naming the local path would be a guess.
func localPathObserved(cause string) bool {
	switch cause {
	case RouteCauseNoDefaultRoute, RouteCauseGatewayUnreachable,
		RouteCauseSelectedPathFailed, RouteCausePreferredPathFailed:
		return true
	}
	return false
}

// proxyCarries reports whether the configured environment proxy is carrying
// traffic, which is the other way this machine can be online.
func proxyCarries(res map[ProbeID]ProbeResult) bool {
	r, ok := res[ProbeProxy]
	return ok && functional(r.Status)
}

// encryptedDNSBlocked reports the one state that is specific to encrypted DNS:
// the encrypted row failed while the network is otherwise carrying traffic and
// plaintext resolution still works. When DNS is failing outright, or when there
// is no working egress to reach any resolver, the encrypted row is a symptom
// and not a diagnosis, so this deliberately says no.
func encryptedDNSBlocked(res map[ProbeID]ProbeResult) bool {
	encrypted, ok := res[ProbeDNSEncrypted]
	if !ok || encrypted.Status != StatusFail {
		return false
	}
	// Without working direct egress the encrypted resolver is simply one more
	// address this machine cannot reach, and the path is the story. Naming
	// encrypted DNS there would blame the transport for a broken route.
	if !directEgressOK(res) {
		return false
	}
	// Presence is checked per row rather than read off the map: an absent probe
	// yields the zero ProbeResult, whose Status is StatusPass.
	for _, id := range []ProbeID{ProbeDNS, ProbeDNSPublic} {
		if plain, ok := res[id]; ok && functional(plain.Status) {
			return true
		}
	}
	return false
}

// Collateral names the failed probes a finished diagnosis already explains as
// downstream evidence of the failure it blames, rather than as something to go
// and act on. An offline machine fails egress, QUIC, plain DNS and encrypted
// DNS at once, and only the first of those is a thing to fix: the other three
// are what one dead path looks like from three more probes.
//
// It is a presentation answer and nothing else. Raw statuses, the report and
// the JSON output all keep saying Fail, because a failed probe really did
// fail; this only says which of those failures the diagnosis has already
// accounted for elsewhere.
//
// nil while a run is unfinished, and nil in the ordinary case where every
// failed probe had a working rung under it: a failure with its prerequisite
// met is evidence about that probe alone.
func Collateral(t *Target, order []ProbeID, res map[ProbeID]ProbeResult) map[ProbeID]bool {
	d := Interpret(t, order, res)
	if d.Verdict == VerdictIncomplete {
		return nil
	}
	// The blamed row the interpretation already worked out, which is what the
	// banner reads too. It is never collateral to itself.
	blamed, verdict := d.Blamed, d.Verdict
	var out map[ProbeID]bool
	for _, id := range order {
		r, ok := res[id]
		if !ok || r.Status != StatusFail || id == blamed || causeSatisfied(id, res) {
			continue
		}
		// A DNS verdict is the summary sentence naming the resolver, so the
		// plaintext rows that sentence is about stay prominent even when the
		// path under them is down: dimming the row the prose blames would
		// contradict the prose. The encrypted row is deliberately not here,
		// because encryptedDNSBlocked has already said that a plaintext
		// failure makes the encrypted one a symptom.
		if verdict == VerdictDNS && (id == ProbeDNS || id == ProbeDNSPublic) {
			continue
		}
		if out == nil {
			out = make(map[ProbeID]bool, len(order))
		}
		out[id] = true
	}
	return out
}

// causeSatisfied reports whether the rung a probe sits on was demonstrably
// carrying traffic when that probe ran. A failure with its rung up is evidence
// about the probe itself; a failure without one is evidence about the rung
// below it, which another row is already reporting.
//
// The probe DAG deliberately keeps these rows as siblings so that one failure
// never stops another from collecting evidence. This is the causal reading of
// the same network, kept apart from the graph the scheduler walks and read
// only to decide how loudly a failed row speaks.
//
// A rung that was not part of the run counts as up. It measured nothing, so it
// is no evidence that anything above it was doomed, and calling a failure a
// consequence of a check nobody made would be a guess.
func causeSatisfied(id ProbeID, res map[ProbeID]ProbeResult) bool {
	ran := func(dep ProbeID) bool { _, ok := res[dep]; return ok }
	switch id {
	case ProbeInternet, ProbeProxy:
		return !ran(ProbeIface) || functional(res[ProbeIface].Status)
	case ProbeQUIC, ProbeDNSPublic, ProbeTargetTCP:
		return !ran(ProbeInternet) || directEgressOK(res)
	case ProbeDNS:
		// The system resolver is the one row here the environment proxy can
		// stand in for: a proxy-only network is carrying traffic, so a
		// resolver failing on one is its own problem rather than the outage
		// restated. The rows above go direct by construction, so a working
		// proxy says nothing about them.
		return !ran(ProbeInternet) || directEgressOK(res) || proxyCarries(res)
	case ProbeDNSEncrypted:
		// encryptedDNSBlocked is this package's existing answer to exactly
		// this question: it says yes only when the path carries traffic and
		// plaintext resolution works at the same time, and no when the
		// encrypted row is a symptom of one of those two instead.
		return !ran(ProbeInternet) || encryptedDNSBlocked(res)
	case ProbeTLS, ProbeHTTP, ProbeHTTPS, ProbeSSH, ProbeSMTP, ProbePMTU:
		return !ran(ProbeTargetTCP) || functional(res[ProbeTargetTCP].Status)
	}
	return true
}

// Finalize applies the cross-probe passes that only make sense once every probe
// has a result: results that read each other, rather than the network. Both
// runners call it (RunAll on its way out, the ui scheduler when the last
// result lands), so a new pass added here reaches --json and the TUI at once,
// in the same order. Idempotent, but there's no reason to call it twice.
func Finalize(res map[ProbeID]ProbeResult) {
	reconcileDNS(res)
	downgradeEgress(res)
	// After the downgrade, so "direct egress worked" means what the finished
	// report says it means rather than what it said mid-pass.
	reconcileEncryptedDNS(res)
	reconcileClockSkew(res)
	reconcileCounterfactuals(res)
}

// clockSkewThreshold is how far this machine's clock has to be off the
// network's before netdoc will name it rather than list it as a maybe. HTTP
// Date has one-second granularity and the reading carries a round trip of
// latency and scheduler jitter, so the floor sits far above all three; it is
// also roughly where a wrong clock stops being cosmetic and starts rejecting
// certificates that everyone else accepts.
const clockSkewThreshold = 5 * time.Minute

// clockSkew returns the signed local-minus-remote offset the egress probe
// measured, and whether it is large enough to act on. The reading only exists
// when a fixed connectivity endpoint answered exactly what it documents, so an
// interception those checks can see never supplies it. That is a
// heuristic over plain HTTP, not authentication, which is why this is usable
// evidence rather than proof: the causal claim is only made when a
// certificate-date rejection independently points the same way. An offset
// exactly at the threshold counts.
func clockSkew(res map[ProbeID]ProbeResult) (time.Duration, bool) {
	d := res[ProbeInternet].clockOffset
	return d, d.Abs() >= clockSkewThreshold
}

// skewExplainsTLS reports whether the offset points the same way as the
// certificate error. A slow clock is what makes a valid certificate look not
// yet valid, and a fast one is what makes it look expired. The other two
// pairings are a genuinely bad certificate standing next to an unrelated bad
// clock, and saying otherwise would send the user to fix the wrong thing.
func skewExplainsTLS(cause string, d time.Duration) bool {
	switch cause {
	case TLSCauseCertificateNotYet:
		return d < 0
	case TLSCauseCertificateExpired:
		return d > 0
	}
	return false
}

// skewDisprovesTLS reports whether the offset rules the clock out. A
// certificate-date rejection can only be explained by an offset pointing the
// same way, so a material offset pointing the other way is evidence against
// the clock rather than an absence of evidence for it, and the hint should
// stop offering it.
func skewDisprovesTLS(cause string, d time.Duration) bool {
	switch cause {
	case TLSCauseCertificateNotYet, TLSCauseCertificateExpired:
		return !skewExplainsTLS(cause, d)
	}
	return false
}

// reconcileClockSkew replaces the TLS row's guess about the clock with the
// reading the egress probe already took, which settles the guess either way:
// an offset pointing at the certificate-date rejection becomes the answer, one
// pointing away from it takes the clock off the list, and the unclassified
// handshake failure gets the measurement alongside its maybes. Anything else
// has a specific cause of its own, and a bad clock beside it is a coincidence.
func reconcileClockSkew(res map[ProbeID]ProbeResult) {
	d, ok := clockSkew(res)
	if !ok {
		return
	}
	r, has := res[ProbeTLS]
	if !has || r.Status != StatusFail {
		return
	}
	switch {
	case skewExplainsTLS(r.Cause, d):
		r.Fix = clockSkewPhrase(d) + ", so " + clockSkewEffect(d) + ": set the clock (enable network time) and retry"
	case skewDisprovesTLS(r.Cause, d):
		// The certificate remedy stands; only the clock maybe goes, since the
		// offset runs the wrong way to have produced this rejection.
		r.Fix = strings.TrimSuffix(r.Fix, clockHedgeSuffix)
	case r.Cause == TLSCauseHandshake:
		r.Fix = "TLS broken: bad/expired cert or MITM proxy, and separately " + clockSkewPhrase(d) + ", which can break certificate validation on its own"
	default:
		return
	}
	res[ProbeTLS] = r
}

// clockSkewPhrase states the measurement. Direction is the half that decides
// what the user changes, so it is never dropped.
func clockSkewPhrase(d time.Duration) string {
	direction := " fast"
	if d < 0 {
		direction = " slow"
	}
	return "this machine's clock is about " + humanSkew(d) + direction
}

// clockSkewEffect names what that offset does to certificate validation.
func clockSkewEffect(d time.Duration) string {
	if d < 0 {
		return "certificates that are already valid look not yet valid"
	}
	return "certificates that are still valid look expired"
}

// humanSkew renders the magnitude of an offset at one sensible unit. Nothing
// below clockSkewThreshold reaches here, and the cutoffs are placed so the
// rounded count is never 1, which keeps the plural honest without a special
// case for it.
func humanSkew(d time.Duration) string {
	d = d.Abs()
	switch {
	case d >= 48*time.Hour:
		return strconv.Itoa(int(d.Round(24*time.Hour)/(24*time.Hour))) + " days"
	case d >= 90*time.Minute:
		return strconv.Itoa(int(d.Round(time.Hour)/time.Hour)) + " hours"
	default:
		return strconv.Itoa(int(d.Round(time.Minute)/time.Minute)) + " minutes"
	}
}

// reconcileEncryptedDNS adds the one thing the encrypted row cannot know on its
// own: whether plaintext resolution was working at the same time. That
// comparison is the difference between "encrypted DNS specifically is not
// getting through" and "DNS is broken", and it is as far as the evidence goes:
// the row states what both probes observed and never what the network intended.
func reconcileEncryptedDNS(res map[ProbeID]ProbeResult) {
	if !encryptedDNSBlocked(res) {
		return
	}
	encrypted := res[ProbeDNSEncrypted]
	encrypted.Detail += "; plain DNS resolves at the same time, so this is specific to encrypted DNS"
	encrypted.Fix = "encrypted DNS cannot complete a verified exchange while ordinary DNS works; the resolver may be unavailable, or a filter or middlebox may block or intercept DoH/DoT"
	res[ProbeDNSEncrypted] = encrypted
}

// reconcileDNS compares the independently collected system and public answers.
// Public DNS can add context or a warning, but never fails a run on its own.
func reconcileDNS(res map[ProbeID]ProbeResult) {
	system, systemOK := res[ProbeDNS]
	public, publicOK := res[ProbeDNSPublic]
	if !systemOK || !publicOK || public.Status != StatusPass {
		return
	}
	switch {
	case system.DNSNotFound && public.DNSNotFound:
		system.Detail += "; public DNS agrees there are no A/AAAA records"
		system.Fix = "check the hostname or publish the missing DNS record"
	case system.Status == StatusPass && public.DNSNotFound:
		public.Status = StatusWarn
		public.Detail = "system DNS resolves the name, but " + public.resolver + " reports no records; split DNS or filtering may be intentional"
	case system.DNSNotFound && len(public.Addrs) > 0:
		public.Status = StatusWarn
		public.Detail += " (system DNS reports no records, so split DNS or filtering may be intentional)"
		system.Detail += ", but public DNS resolves it"
		system.Fix = "check the configured resolver, VPN, or DNS filter"
	case system.Status == StatusPass && len(public.Addrs) > 0 && !answersAgree(system.Addrs, public.Addrs):
		public.Status = StatusWarn
		public.Detail = "answers point elsewhere; system: " + joinIPs(system.Addrs) + " (" + comparisonPrefixes(system.Addrs) + "); public " + public.resolver + ": " + joinIPs(public.Addrs) + " (" + comparisonPrefixes(public.Addrs) + ") (split DNS may be intentional)"
	case system.Status == StatusFail && len(public.Addrs) > 0:
		system.Detail += ", but public DNS resolves it"
		system.Fix = "check the configured resolver, VPN, or DNS filter"
	}
	res[ProbeDNS], res[ProbeDNSPublic] = system, public
}

// answersAgree reports whether two answer sets point at the same place.
// Round-robin and GeoDNS make byte-identical sets the exception rather than
// the rule (anycast hosts answer differently per resolver by design), so
// agreement means one shared routing prefix, not set equality. Disjoint
// prefixes are the case worth a warning: a different operator, or one side
// private and the other public.
func answersAgree(a, b []net.IP) bool {
	seen := make(map[netip.Prefix]struct{}, len(a))
	for _, ip := range a {
		if p, ok := routePrefix(ip); ok {
			seen[p] = struct{}{}
		}
	}
	for _, ip := range b {
		p, ok := routePrefix(ip)
		if !ok {
			continue
		}
		if _, dup := seen[p]; dup {
			return true
		}
	}
	return false
}

// routePrefix reduces an address to the block its operator was allocated:
// /16 for v4, /32 for v6: the RIR allocation size, deliberately coarser than
// the announced route. One anycast host answers from many /24s within a single
// allocation (142.250.9.94 and 142.250.189.99 are both Google), and treating
// those as different networks is exactly the false positive worth avoiding.
// Erring coarse costs us a warning when two operators share a block; erring
// fine costs a wrong headline verdict on every healthy run.
// Prefix length stands in for an ASN lookup: only an RIR/BGP source gets this
// exactly right, and it would cost either a network call or a bundled dataset
// in a probe that must stay time-bounded and offline.
func routePrefix(ip net.IP) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is4() {
		bits = 16
	}
	p, err := addr.Prefix(bits)
	return p, err == nil
}

// comparisonPrefixes reports the distinct prefixes an answer set masks down
// to under routePrefix, sorted: e.g. "142.250.0.0/16, 2607:f8b0::/32". These
// are the values answersAgree compares, nothing more: they name no RIR
// allocation, ASN, or operator, and say nothing about public routability. The
// function exists only to show the reader what the comparison saw, never to
// decide it. The verdict still rests on answersAgree, and because the text is
// derived from the same deterministic masking, a support artifact replays with
// identical text.
func comparisonPrefixes(ips []net.IP) string {
	seen := map[netip.Prefix]struct{}{}
	for _, ip := range ips {
		if p, ok := routePrefix(ip); ok {
			seen[p] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return "no comparison prefix"
	}
	prefixes := make([]string, 0, len(seen))
	for p := range seen {
		prefixes = append(prefixes, p.String())
	}
	slices.Sort(prefixes)
	return strings.Join(prefixes, ", ")
}

// downgradeEgress rewrites a direct-egress failure to Warn once another path
// has proven the network usable: the target TCP connect succeeded, the
// environment proxy tunnels traffic, or, in generic mode where DNS is the
// only other network path, DNS answered. Call it once, after every probe has
// a result; degraded-but-functional must not read as an outage.
func downgradeEgress(res map[ProbeID]ProbeResult) {
	r, ok := res[ProbeInternet]
	// An intercepted path is exempt: behind a portal DNS and the target
	// connect both "work" because the portal answers them, so the usual
	// evidence that the network is usable is exactly the thing being faked.
	if !ok || r.Status != StatusFail || r.Portal != nil {
		return
	}
	other, hasOther := res[ProbeTargetTCP]
	if !hasOther {
		other, hasOther = res[ProbeDNS]
	}
	prx, hasProxy := res[ProbeProxy]
	otherOK := hasOther && functional(other.Status)
	proxyOK := hasProxy && functional(prx.Status)
	if !otherOK && !proxyOK {
		return
	}
	r.Status = StatusWarn
	r.downgraded = true
	// Another path carries traffic, so whatever the routing table said about
	// the dead direct path is no longer a repair to hand the user: a proxy-only
	// network with no default route is working as designed. The cause stays in
	// the JSON as evidence; only the advice reverts.
	r.Fix = egressFix
	if otherOK {
		r.Detail += ", but another path works"
	} else {
		r.Detail += ", but the environment proxy works"
	}
	res[ProbeInternet] = r
}
