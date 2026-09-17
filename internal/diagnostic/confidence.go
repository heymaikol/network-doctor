package diagnostic

// Diagnosis confidence: how strongly a finished run's observations support one
// finding as an explanation of what is happening, given the alternatives
// Network Doctor was able to evaluate.
//
// It is not a probability, and none of the four values is a number wearing a
// word. It is not severity, not the verdict, not a probe status, and not a
// count of how many checks passed. A run can be certain that a service is down
// and still be unable to say why, and confidence is about the why.
//
// The derivation lives here and nowhere else. It reads two things and nothing
// else: what kind of claim the conclusion is, which is a fixed property of the
// diagnosis identity and is written down in the tables below, and what this
// particular run's structured evidence left standing. It never reads a summary
// sentence, never scores, never weights, and never counts.

// Confidence is the stable vocabulary. Values are lower_snake_case and
// permanent; renaming one is a breaking change to the JSON report and the
// .ndoc file. docs/reference.md documents the whole set, and
// TestConfidenceIsDocumented keeps that honest.
type Confidence string

const (
	// ConfidenceHigh: a probe observed the condition that distinguishes this
	// conclusion from its alternatives, and no named alternative or missing
	// observation is left open.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium: the conclusion is the best explanation the run
	// supports, but an ambiguity remains: an inference the probes could not
	// observe directly, an alternative weakened without being excluded, or an
	// observation the run was unable to make.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow: there is a real basis for naming this, but the evidence
	// identifies the rung rather than the cause, and several plausible causes
	// remain equally consistent with it.
	ConfidenceLow Confidence = "low"
	// ConfidenceInsufficientEvidence: the run cannot responsibly make a causal
	// claim at all. This is what an explicitly untested or unexplained
	// situation gets, and it is deliberately not "high confidence that we know
	// nothing": being sure the information is missing is not evidence for a
	// cause.
	ConfidenceInsufficientEvidence Confidence = "insufficient_evidence"
)

// confidenceClass is the strongest claim a conclusion of this kind can support
// even when every observation lines up. It is a property of what the diagnosis
// asserts, not of one run, which is why it is a table keyed by identity: the
// question "could this ever be known directly?" has the same answer every time
// the identity is produced, and answering it once beside the vocabulary is what
// keeps the rule auditable instead of scattered through the truth table.
type confidenceClass int

const (
	// classUnresolved: the finding's own meaning is that netdoc could not tell.
	// It may be entirely certain of that, which is not the same as having an
	// explanation.
	classUnresolved confidenceClass = iota
	// classBroad: the finding names the rung that broke and nothing narrower,
	// with several causes left equally live.
	classBroad
	// classInferred: the observation is consistent with the conclusion but does
	// not separate it from explanations the run had no way to test. A
	// correlation, or a state whose cause is not localized.
	classInferred
	// classObserved: a probe observed the specific condition that separates
	// this conclusion from its plausible alternatives.
	classObserved
)

// ceiling is the level a class permits before this run's own evidence is
// considered.
func (c confidenceClass) ceiling() Confidence {
	switch c {
	case classObserved:
		return ConfidenceHigh
	case classInferred:
		return ConfidenceMedium
	case classBroad:
		return ConfidenceLow
	}
	return ConfidenceInsufficientEvidence
}

// diagnosisConfidence is the epistemic class of every diagnosis identity, in
// the order finding.go declares them. Every declared ID appears exactly once;
// TestEveryDiagnosisIDHasAConfidenceClass fails the build on one that does not,
// so a new identity cannot be added without deciding what kind of claim it is.
var diagnosisConfidence = map[DiagnosisID]confidenceClass{
	// Link and path. A dead link, an interception, and an impairment the egress
	// probe measured for itself are observed states, and so is the proxy
	// carrying traffic the direct path did not.
	//
	// The egress row's failures are weaker than they look, because that row
	// dials a fixed pair of reference addresses. "Direct egress is blocked"
	// generalizes from that sample to every destination, which no observation
	// in the run separates from those addresses alone being unreachable, so it
	// is an inference however cleanly the row failed. Being offline, or blaming
	// this machine's own egress, is inferred for the same reason plus one more:
	// from one host, a broken link, a broken upstream, and a network that drops
	// this traffic look identical. Local egress is only ever concluded where
	// the routing and neighbor tables classified the dead path, which is the
	// observation the identity rests on rather than the silence around it.
	DiagnosisNoUsableInterface:    classObserved,
	DiagnosisCaptivePortal:        classObserved,
	DiagnosisOffline:              classInferred,
	DiagnosisDirectEgressBlocked:  classInferred,
	DiagnosisDirectEgressDegraded: classObserved,
	DiagnosisProxyOnlyNetwork:     classObserved,
	DiagnosisLocalEgressFailure:   classInferred,
	// The one reference-egress failure a run can settle: the endpoint under
	// test answered a direct connection while the reference addresses did not,
	// which is the controlled comparison that separates unreachable
	// destinations from unreachable egress.
	DiagnosisReferenceEgressUnreachable: classObserved,
	// Its opposite. Everything the run tried was silent and nothing observed
	// where, which is the definition of no causal claim rather than a weak one.
	DiagnosisReachabilityUnlocalized: classUnresolved,
	// Two stalls that correlate, which is what a black hole looks like and also
	// what a slow server looks like. The identity says "probable" for the same
	// reason this says inferred.
	DiagnosisProbablePathMTU: classInferred,

	// Name resolution. Two resolvers asked the same question is a controlled
	// comparison, and their agreeing on a negative answer is observed: a name
	// with no records has none whichever resolver is asked. Their disagreeing
	// is weaker than it looks. One query each, at one moment, shows the
	// configured resolver failing then, and does not separate a resolver that
	// is broken or filtering from a name whose own servers were briefly
	// failing for everyone. A resolver failing with no second opinion names
	// the rung and no cause; a difference in answers is as often a design as a
	// fault; and an encrypted resolver that cannot complete an exchange looks
	// the same whether it is unavailable or interfered with.
	DiagnosisSystemDNSFailure:        classInferred,
	DiagnosisDNSNameNotFound:         classObserved,
	DiagnosisDNSFailure:              classBroad,
	DiagnosisDNSDisagreement:         classInferred,
	DiagnosisEncryptedDNSUnavailable: classInferred,

	// Paths beside the direct one, each proved by the direct path working at
	// the same moment the sibling did not.
	DiagnosisQUICUnavailable: classObserved,
	DiagnosisProxyFailure:    classObserved,

	// A refusal observes an explicit rejection, without identifying who sent it.
	// Successful reference egress does not locate target silence: filtering,
	// destination-specific routing, a broken return path and a silent peer all
	// remain possible, for local devices as well as public targets. These name
	// only the failed rung. Family and address comparisons are narrower observed
	// contrasts, without claiming why the unsuccessful alternative failed.
	DiagnosisTCPConnectionRefused:   classObserved,
	DiagnosisTargetUnreachable:      classBroad,
	DiagnosisLocalDeviceUnreachable: classBroad,
	DiagnosisReachabilityUntested:   classUnresolved,
	DiagnosisIPv4TargetUnreachable:  classObserved,
	DiagnosisIPv6TargetUnreachable:  classObserved,
	DiagnosisPartialReachability:    classObserved,
	// The scoped failure is certain about the attempts it names and says in
	// its own meaning that the cause behind them was not established: a
	// rewritten record and an endpoint whose node was silent produce the same
	// evidence, and the addresses that would have told them apart were never
	// tried. Being sure of that is not an explanation.
	DiagnosisUncorroboratedEndpointFailure: classUnresolved,

	// TLS. Where the handshake classified the rejection, the classification is
	// the observation. A timeout, a close, and a dial that could not reach a
	// port the endpoint check reached are all events whose cause stays open,
	// and an unclassifiable handshake failure is the broad case by definition.
	//
	// The two date rejections are observed only once the clock is: they are
	// read against this machine's own now, so a wrong clock produces them from
	// a perfectly good certificate. mustRuleOut below is what holds them to
	// that.
	DiagnosisTLSCertificateExpired:     classObserved,
	DiagnosisTLSCertificateNotYetValid: classObserved,
	DiagnosisTLSHostnameMismatch:       classObserved,
	DiagnosisTLSUntrustedIssuer:        classObserved,
	DiagnosisTLSClockSkew:              classObserved,
	DiagnosisTLSTimeout:                classInferred,
	DiagnosisTLSConnectionClosed:       classInferred,
	DiagnosisTLSTCPUnreachable:         classInferred,
	DiagnosisTLSHandshakeFailure:       classBroad,

	// The application on a working connection. Each of these is silence at a
	// protocol: real, and no more specific than the rung it happened on.
	DiagnosisHTTPSNoResponse:      classInferred,
	DiagnosisHTTPNoResponse:       classInferred,
	DiagnosisServiceBannerFailure: classInferred,
	DiagnosisServiceBannerMissing: classInferred,

	// A selection that removed the rungs which would have explained the
	// failure. These identities exist to say a check failed and nothing here
	// explains it, which is the definition of no causal claim.
	DiagnosisSelectedDNSCheckFailed:     classUnresolved,
	DiagnosisSelectedServiceCheckFailed: classUnresolved,
	DiagnosisSelectedNetworkCheckFailed: classUnresolved,
}

// mustRuleOut names the one competing identity that an observed conclusion has
// to have excluded before it can claim the strongest level, for the identities
// where the supporting observation is not by itself the differential.
//
// A certificate-date rejection is the case: the handshake compares the
// certificate's validity window against this machine's clock, so "the
// certificate is expired" and "the clock is fast" produce the same rejection,
// and netdoc has a separate identity for the second. The truth table already
// separates them, but only in the arm where the egress probe took a clock
// reading. Without that reading the run has not looked, and the difference
// between having looked and not having looked is exactly what confidence is
// for. Left to the two rules below it would be invisible, because a branch
// that records nothing about an alternative reads the same as one that
// settled it.
//
// One candidate per identity, because this is a specific claim about a
// specific pair, not a scoring input to be extended by degrees.
var mustRuleOut = map[DiagnosisID]DiagnosisID{
	DiagnosisTLSCertificateExpired:     DiagnosisTLSClockSkew,
	DiagnosisTLSCertificateNotYetValid: DiagnosisTLSClockSkew,
}

// confidenceFor is the whole derivation: the class ceiling, lowered by what
// this run's evidence left open. Nothing else feeds in, so the same finding
// always produces the same value and a maintainer can predict it from the
// tables above plus the finding's own evidence.
//
// An identity with no class is deliberately the most conservative answer rather
// than a guess. A test makes the table total, so this only fires for a finding
// built outside the interpretation pass.
func confidenceFor(f DiagnosisFinding) Confidence {
	class, known := diagnosisConfidence[f.ID]
	if !known {
		return ConfidenceInsufficientEvidence
	}
	if class == classObserved && (unresolvedAlternative(f.Evidence) ||
		missingDifferential(f.Evidence) || !excludes(f.Evidence, mustRuleOut[f.ID])) {
		return ConfidenceMedium
	}
	return class.ceiling()
}

// excludes reports whether the evidence puts a named candidate out of the
// running. An identity with nothing to rule out passes trivially, which is
// most of them.
func excludes(evidence []CausalEvidence, candidate DiagnosisID) bool {
	if candidate == "" {
		return true
	}
	for _, e := range evidence {
		if e.Kind == EvidenceRuledOut && e.Candidate == candidate {
			return true
		}
	}
	return false
}

// unresolvedAlternative reports whether the finding left a named competing
// explanation standing. In this model a contradiction says the observation
// weakens that candidate without excluding it, so a candidate that is
// contradicted and never ruled out is still a live explanation of the same
// symptoms, and a conclusion with one of those beside it has not earned the
// strongest claim.
//
// Presence decides it and nothing else. Two surviving alternatives are not
// worse than one, and a tenth ruled-out alternative buys nothing the first did
// not: this asks whether the differential is finished, never how big it is.
func unresolvedAlternative(evidence []CausalEvidence) bool {
	excluded := make(map[DiagnosisID]bool, len(evidence))
	for _, e := range evidence {
		if e.Kind == EvidenceRuledOut {
			excluded[e.Candidate] = true
		}
	}
	for _, e := range evidence {
		if e.Kind == EvidenceContradiction && !excluded[e.Candidate] {
			return true
		}
	}
	return false
}

// missingDifferential reports whether an observation that could have separated
// this conclusion from another was never made, for a reason that leaves the
// question open.
//
// The reason is the whole of it, which is why NotEvaluatedReason exists. A
// check skipped because its prerequisite failed, or one that never applied, is
// a consequence of the very failure being diagnosed: a TLS row skipped behind a
// dead resolver says nothing about the resolver, and letting it lower the DNS
// conclusion would punish a diagnosis for being right. A check the run was
// never asked to make, or one it never finished, is the opposite case: the
// observation that would have settled the question was simply not taken.
func missingDifferential(evidence []CausalEvidence) bool {
	for _, e := range evidence {
		if e.Kind != EvidenceNotEvaluated {
			continue
		}
		switch e.Reason {
		case NotEvaluatedNotSelected, NotEvaluatedIncomplete:
			return true
		}
	}
	return false
}
