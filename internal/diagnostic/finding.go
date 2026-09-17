package diagnostic

import "slices"

// DiagnosisID is the stable machine-readable identity of one diagnostic
// conclusion: what netdoc decided is wrong, independent of the sentence it
// prints. Prose gets reworded; an ID does not, so scripts branch on this and
// never on English.
//
// These are Network Doctor's own conclusions about a network. They are not the
// simulator's hunt findings, which are defects discovered in Network Doctor
// itself and live in internal/simulation under Hunt-prefixed names.
//
// An ID names a condition netdoc can actually prove from probe evidence. There
// is deliberately no ID for a guess: a run that establishes nothing specific
// reports its broad verdict and no finding at all, rather than being pushed
// into an identity it did not earn.
type DiagnosisID string

// The diagnosis vocabulary, grouped by the rung the conclusion is about.
// Values are lower_snake_case and permanent; renaming one is a breaking
// change to the JSON report. docs/reference.md tabulates the whole set, and
// TestDiagnosisIDsAreDocumented keeps that table honest.
const (
	// Link and path.
	DiagnosisNoUsableInterface    DiagnosisID = "no_usable_interface"
	DiagnosisCaptivePortal        DiagnosisID = "captive_portal"
	DiagnosisOffline              DiagnosisID = "offline"
	DiagnosisDirectEgressBlocked  DiagnosisID = "direct_egress_blocked"
	DiagnosisDirectEgressDegraded DiagnosisID = "direct_egress_degraded"
	DiagnosisProxyOnlyNetwork     DiagnosisID = "proxy_only_network"
	DiagnosisLocalEgressFailure   DiagnosisID = "local_egress_failure"
	DiagnosisProbablePathMTU      DiagnosisID = "probable_path_mtu_problem"
	// The egress row dials a fixed pair of reference addresses, so these two
	// are what is left of a reference failure once the run's other
	// observations have had their say: one where a public destination
	// answered a direct connection anyway, and one where nothing answered and
	// nothing observed where the path breaks.
	DiagnosisReferenceEgressUnreachable DiagnosisID = "reference_egress_unreachable"
	DiagnosisReachabilityUnlocalized    DiagnosisID = "reachability_unlocalized"

	// Name resolution.
	DiagnosisSystemDNSFailure        DiagnosisID = "system_dns_failure"
	DiagnosisDNSNameNotFound         DiagnosisID = "dns_name_not_found"
	DiagnosisDNSFailure              DiagnosisID = "dns_failure"
	DiagnosisDNSDisagreement         DiagnosisID = "dns_disagreement"
	DiagnosisEncryptedDNSUnavailable DiagnosisID = "encrypted_dns_unavailable"

	// Paths that run beside the direct one.
	DiagnosisQUICUnavailable DiagnosisID = "quic_unavailable"
	DiagnosisProxyFailure    DiagnosisID = "proxy_failure"

	// Reaching the endpoint under test.
	DiagnosisTCPConnectionRefused   DiagnosisID = "tcp_connection_refused"
	DiagnosisTargetUnreachable      DiagnosisID = "target_unreachable"
	DiagnosisLocalDeviceUnreachable DiagnosisID = "local_device_unreachable"
	DiagnosisReachabilityUntested   DiagnosisID = "reachability_untested"
	DiagnosisIPv4TargetUnreachable  DiagnosisID = "ipv4_target_unreachable"
	DiagnosisIPv6TargetUnreachable  DiagnosisID = "ipv6_target_unreachable"
	DiagnosisPartialReachability    DiagnosisID = "partial_endpoint_reachability"
	// DiagnosisUncorroboratedEndpointFailure is the scope of a failed reach
	// attempt rather than a conclusion about what was being reached. Every
	// address the check tried came from the system resolver alone, while the
	// independent resolver answered the same name in the same family with
	// addresses this run never tried, so the failure is established and the
	// broader claim above it is not. It is deliberately not a statement about
	// either resolver: a rewritten record and a healthy anycast node that was
	// not answering leave the same evidence, and nothing a run records
	// separates them.
	DiagnosisUncorroboratedEndpointFailure DiagnosisID = "uncorroborated_endpoint_failure"

	// TLS, which keeps the fine-grained causes the handshake already
	// classified rather than flattening them into one service failure.
	DiagnosisTLSCertificateExpired     DiagnosisID = "tls_certificate_expired"
	DiagnosisTLSCertificateNotYetValid DiagnosisID = "tls_certificate_not_yet_valid"
	DiagnosisTLSHostnameMismatch       DiagnosisID = "tls_hostname_mismatch"
	DiagnosisTLSUntrustedIssuer        DiagnosisID = "tls_untrusted_issuer"
	DiagnosisTLSClockSkew              DiagnosisID = "tls_clock_skew"
	DiagnosisTLSTimeout                DiagnosisID = "tls_timeout"
	DiagnosisTLSConnectionClosed       DiagnosisID = "tls_connection_closed"
	DiagnosisTLSTCPUnreachable         DiagnosisID = "tls_tcp_unreachable"
	DiagnosisTLSHandshakeFailure       DiagnosisID = "tls_handshake_failure"

	// The application on top of a working connection.
	DiagnosisHTTPSNoResponse      DiagnosisID = "https_no_response"
	DiagnosisHTTPNoResponse       DiagnosisID = "http_no_response"
	DiagnosisServiceBannerFailure DiagnosisID = "service_banner_failure"
	DiagnosisServiceBannerMissing DiagnosisID = "service_banner_missing"

	// A selection of checks whose failure no other case is about. These are
	// what --check and --skip can leave behind: a run with the rungs that
	// would have explained the failure taken out of it.
	DiagnosisSelectedDNSCheckFailed     DiagnosisID = "selected_dns_check_failed"
	DiagnosisSelectedServiceCheckFailed DiagnosisID = "selected_service_check_failed"
	DiagnosisSelectedNetworkCheckFailed DiagnosisID = "selected_network_check_failed"
)

// EvidenceKind is the relationship between one observed fact and a diagnosis.
// It is deliberately not a confidence score: each value says only what the
// fact proves in the branch that selected the finding.
type EvidenceKind string

const (
	EvidenceSupport       EvidenceKind = "support"
	EvidenceContradiction EvidenceKind = "contradiction"
	EvidenceRuledOut      EvidenceKind = "ruled_out"
	EvidenceNotEvaluated  EvidenceKind = "not_evaluated"
)

// ObservationID identifies the measured field an evidence item references.
// The value itself stays on ProbeResult, so evidence records a typed
// relationship and provenance rather than copying observations into a second
// store.
type ObservationID string

const (
	ObservationStatusPass       ObservationID = "status_pass"
	ObservationStatusWarn       ObservationID = "status_warn"
	ObservationStatusFail       ObservationID = "status_fail"
	ObservationStatusSkip       ObservationID = "status_skip"
	ObservationStatusNA         ObservationID = "status_not_applicable"
	ObservationCause            ObservationID = "cause"
	ObservationDNSAnswers       ObservationID = "dns_answers"
	ObservationDNSNotFound      ObservationID = "dns_not_found"
	ObservationCaptivePortal    ObservationID = "captive_portal"
	ObservationTimeout          ObservationID = "timeout"
	ObservationClockOffset      ObservationID = "clock_offset"
	ObservationStatusDowngraded ObservationID = "status_downgraded"
	ObservationFamilyReachable  ObservationID = "family_reachable"
	ObservationFamilyFailed     ObservationID = "family_failed"
	ObservationAddressSucceeded ObservationID = "address_succeeded"
	ObservationAddressFailed    ObservationID = "address_failed"
	// Route observations. Each one is a fact about the path this row's own
	// traffic takes, so it can be checked against the row that recorded it.
	// A statement about two paths is made by two items, one per row, rather
	// than by one item nobody can verify from either.
	//
	// None of these is a verdict. A tunnel in the path is the normal state of
	// a machine on a VPN, and route evidence exists to explain a conclusion
	// the probes already reached, never to reach one on its own.
	ObservationRouteTunneled    ObservationID = "route_tunneled"
	ObservationRouteDirect      ObservationID = "route_direct"
	ObservationRouteUnreachable ObservationID = "route_unreachable"
	ObservationRoutePathDiffers ObservationID = "route_path_differs"
	// ObservationRouteNextHopDiffers is this row's traffic being handed to a
	// router other than the one named in Value, down what is otherwise the
	// same interface. Two flows can leave a machine by one link and still be
	// routed apart, and the interface name matching is exactly what hides it.
	ObservationRouteNextHopDiffers ObservationID = "route_next_hop_differs"
	// ObservationRouteTableDiffers is the kernel having resolved this row's
	// destination in a routing table other than the one general traffic used.
	// It is evidence that another routing domain was selected and nothing
	// more: which rule, mark, VRF, or application policy sent the flow there
	// is not something a route lookup reports, and this never claims it.
	ObservationRouteTableDiffers ObservationID = "route_table_differs"
	ObservationRouteFamilySplit  ObservationID = "route_family_split"
	ObservationRouteInterfaceMTU ObservationID = "route_interface_mtu"
)

type CounterfactualVariable string

const (
	CounterfactualDNSResolver     CounterfactualVariable = "dns_resolver"
	CounterfactualAddressFamily   CounterfactualVariable = "address_family"
	CounterfactualResolvedAddress CounterfactualVariable = "resolved_address"
)

type CounterfactualOutcome string

const (
	CounterfactualSucceeded CounterfactualOutcome = "succeeded"
	CounterfactualFailed    CounterfactualOutcome = "failed"
	CounterfactualNotFound  CounterfactualOutcome = "not_found"
)

// NotEvaluatedReason keeps the ways a relevant check can lack an observation
// distinct. In particular, a failed prerequisite is not the same as a check
// that was not selected, did not apply, or never completed.
type NotEvaluatedReason string

const (
	NotEvaluatedPrerequisite  NotEvaluatedReason = "prerequisite_failed"
	NotEvaluatedNotSelected   NotEvaluatedReason = "not_selected"
	NotEvaluatedNotApplicable NotEvaluatedReason = "not_applicable"
	NotEvaluatedIncomplete    NotEvaluatedReason = "incomplete"
)

// CausalEvidence is one typed interpretation of one observed fact. Check and
// Observation identify the provenance. Candidate is set only when the fact
// contradicts or rules out another diagnosis. Reason is set only when the
// relevant check was not evaluated.
type CausalEvidence struct {
	Kind        EvidenceKind
	Check       ProbeID
	Observation ObservationID
	// Value identifies the member of a structured observation, such as an IP
	// address or address family. Empty for whole-row observations.
	Value     string
	Candidate DiagnosisID
	Reason    NotEvaluatedReason
}

// Counterfactual records the controlled alternatives behind a conclusion.
// Each alternative points back to CausalEvidence instead of copying a probe
// result, so Diagnosis remains the sole interpretation of the run.
type Counterfactual struct {
	Variable     CounterfactualVariable
	Alternatives []CounterfactualAlternative
}

type CounterfactualAlternative struct {
	Value    string
	Outcome  CounterfactualOutcome
	Evidence []CausalEvidence
}

// DiagnosisFinding is one specific thing a run proved wrong, with everything a
// caller needs to act on it without diagnosing the run a second time: the
// stable identity, the sentence, the broad class that identity falls into, the
// row whose remediation and evidence belong to it, and the rows the conclusion
// rests on.
//
// It carries no remedy text of its own. Fix hints live on the probe rows,
// which is the single place they are written, and Focus is the row to take
// this finding's hint from.
type DiagnosisFinding struct {
	ID DiagnosisID
	// Verdict is this finding's broad class, from the same vocabulary as
	// Diagnosis.Verdict. It doubles as the finding's severity: ok and degraded
	// are impairments, dns/network/service are failures.
	Verdict string
	Summary string
	// Focus is the probe row the sentence is about, empty when the conclusion
	// is about no single row.
	Focus ProbeID
	// Evidence records the facts the conclusion was drawn from, Focus first.
	// Each item points back to the ProbeResult field that supplied the fact and
	// states how that fact bears on the selected or an alternative diagnosis.
	Evidence []CausalEvidence
	// Counterfactual is present when this conclusion compares controlled
	// alternatives observed during the same run.
	Counterfactual *Counterfactual
	// Confidence is how strongly the evidence above supports this finding as an
	// explanation. It is descriptive metadata: nothing in the engine reads it
	// back, so it can never decide an identity, a verdict, a focused row, or a
	// remedy. Set once, by confidence.go, after every stage that can add
	// evidence has run. Empty only on a finding built outside that pass.
	Confidence Confidence
}

// EvidenceRows is the compatibility projection used by the original JSON and
// snapshot evidence fields: unique observed check IDs in reasoning order. A
// not-evaluated check is deliberately absent because it supplied no observed
// fact. New consumers should read the typed causal evidence beside it.
func (f DiagnosisFinding) EvidenceRows() []ProbeID {
	var rows []ProbeID
	for _, e := range f.Evidence {
		if e.Kind == EvidenceNotEvaluated || e.Check == "" || slices.Contains(rows, e.Check) {
			continue
		}
		rows = append(rows, e.Check)
	}
	return rows
}

// Diagnosis is the one authoritative interpretation of a finished run: what
// the run's overall state is, and which specific conclusions it supports.
//
// The run's broad status and a specific finding are deliberately separate. A
// healthy run, a run still in progress, a run with nothing selected, and a run
// that is degraded in a way no single case is about all have a verdict and a
// sentence with no finding under them, because forcing an identity onto them
// would be inventing one.
//
// Findings is a slice because a run can hold more than one conclusion. The
// first finding owns the summary; later findings add compatible deductions.
type Diagnosis struct {
	// Verdict is the run's broad class, the stable vocabulary the JSON report
	// has always published. See the Verdict constants.
	Verdict string
	// Summary is the plain-English headline, and the sentence the primary
	// finding is about when there is one.
	Summary string
	// Blamed is the row a caller should put a cursor on: the row the diagnosis
	// names, or the first failed row when it names none. Unlike a finding's
	// Focus it is a presentation answer, so it falls back rather than staying
	// empty. Empty when nothing failed.
	Blamed   ProbeID
	Findings []DiagnosisFinding
}

// Focus is the row the diagnosis itself blames, empty when it blames none.
// Unlike Blamed this never falls back to a row the diagnosis is not about.
func (d Diagnosis) Focus() ProbeID {
	if len(d.Findings) == 0 {
		return ""
	}
	return d.Findings[0].Focus
}

// tlsDiagnosisID turns the cause the TLS probe already classified into the
// diagnosis identity. The prose for a failed handshake is deliberately hedged,
// because netdoc cannot always tell a bad certificate from a MITM proxy from a
// wrong clock; the cause, where the handshake produced one, can, and the
// identity is where that precision belongs. An unclassified failure keeps the
// generic handshake identity rather than being assigned a specific one.
func tlsDiagnosisID(cause string) DiagnosisID {
	switch cause {
	case TLSCauseCertificateExpired:
		return DiagnosisTLSCertificateExpired
	case TLSCauseCertificateNotYet:
		return DiagnosisTLSCertificateNotYetValid
	case TLSCauseHostnameMismatch:
		return DiagnosisTLSHostnameMismatch
	case TLSCauseUntrustedIssuer:
		return DiagnosisTLSUntrustedIssuer
	case TLSCauseTimeout:
		return DiagnosisTLSTimeout
	case TLSCauseConnectionClosed:
		return DiagnosisTLSConnectionClosed
	case TLSCauseTCPUnreachable:
		return DiagnosisTLSTCPUnreachable
	}
	return DiagnosisTLSHandshakeFailure
}
