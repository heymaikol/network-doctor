// Package peer implements Network Doctor's authenticated two-ended diagnosis.
package peer

import (
	"slices"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

const (
	ProtocolVersion = 1
	ResultSchema    = "netdoc.peer.v1"

	RoleListener  = "listener"
	RoleConnector = "connector"

	DirectionListenerToConnector = "listener_to_connector"
	DirectionConnectorToListener = "connector_to_listener"

	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"

	CauseFamilyUnavailable        = "family_unavailable"
	CausePeerAddressUnverified    = "peer_address_unverified"
	CauseConnectionTimeout        = diagnostic.ConnectionCauseTimeout
	CauseConnectionUnreachable    = diagnostic.ConnectionCauseUnreachable
	CauseTLSAuthenticationFailed  = "tls_authentication_failed"
	CauseApplicationTrafficFailed = "application_traffic_failed"
)

const (
	DiagnosisBidirectionalOK    = "peer_bidirectional_ok"
	DiagnosisDirectionalFailure = "peer_directional_failure"
	DiagnosisSymmetricFailure   = "peer_symmetric_failure"
	DiagnosisFamilyAsymmetry    = "peer_address_family_asymmetry"
	DiagnosisLocalOnlyListener  = "peer_listener_local_only"
	DiagnosisApplicationFailure = "peer_application_failure"
	DiagnosisSecurityFailure    = "peer_security_failure"
	DiagnosisIncompleteEvidence = "peer_incomplete_evidence"
)

// EndpointIdentity is the endpoint information relevant to this session. The
// addresses are the short-lived listeners Network Doctor opened, not a dump of
// the host's interfaces.
type EndpointIdentity struct {
	Role            string   `json:"role"`
	Name            string   `json:"name,omitempty"`
	ListenAddresses []string `json:"listen_addresses"`
	ObservedAddress string   `json:"observed_address,omitempty"`
}

// ChannelObservation records the authenticated control path separately from
// the independent directional tests. A completed result always has one; its
// success does not overwrite a later test failure.
type ChannelObservation struct {
	Established bool   `json:"established"`
	Family      string `json:"family"`
	Local       string `json:"local"`
	Remote      string `json:"remote"`
	Ms          int64  `json:"ms"`
}

// Observation is one endpoint's independently measured attempt in one
// direction and address family. Phase booleans keep reasoning out of prose.
type Observation struct {
	Direction          string `json:"direction"`
	Family             string `json:"family"`
	Source             string `json:"source,omitempty"`
	Destination        string `json:"destination,omitempty"`
	Status             string `json:"status"`
	Cause              string `json:"cause,omitempty"`
	TCPConnected       bool   `json:"tcp_connected"`
	TLSAuthenticated   bool   `json:"tls_authenticated"`
	ApplicationTraffic bool   `json:"application_traffic"`
	PayloadBytes       int    `json:"payload_bytes"`
	Ms                 int64  `json:"ms"`
}

// CombinedDiagnosis separates the proven headline from explanations that the
// evidence cannot distinguish.
type CombinedDiagnosis struct {
	ID           string   `json:"id"`
	Verdict      string   `json:"verdict"`
	Summary      string   `json:"summary"`
	Evidence     []string `json:"evidence"`
	Ambiguous    bool     `json:"ambiguous"`
	Alternatives []string `json:"alternatives,omitempty"`
}

// Result is the peer-specific stable JSON contract. It is intentionally
// separate from internal/report.Report, so ordinary --json output is unchanged.
type Result struct {
	Schema          string             `json:"schema"`
	Version         string             `json:"version"`
	ProtocolVersion int                `json:"protocol_version"`
	Local           EndpointIdentity   `json:"local"`
	Remote          EndpointIdentity   `json:"remote"`
	Channel         ChannelObservation `json:"channel"`
	Observations    []Observation      `json:"observations"`
	Diagnosis       CombinedDiagnosis  `json:"diagnosis"`
	OK              bool               `json:"ok"`
}

func buildResult(localRole, version string, listener, connector EndpointIdentity, channel ChannelObservation, observations []Observation) Result {
	observations = completeObservations(observations)
	local, remote := listener, connector
	if localRole == RoleConnector {
		local, remote = connector, listener
	}
	diagnosis := Analyze(listener, connector, observations)
	return Result{
		Schema: ResultSchema, Version: version, ProtocolVersion: ProtocolVersion,
		Local: local, Remote: remote, Channel: channel, Observations: observations, Diagnosis: diagnosis,
		OK: diagnosis.ID == DiagnosisBidirectionalOK,
	}
}

// Analyze interprets structured peer observations without touching sockets.
// It names only what the truth table proves and lists competing explanations
// whenever several remain possible.
func Analyze(listener, connector EndpointIdentity, observations []Observation) CombinedDiagnosis {
	observations = completeObservations(observations)
	evidence := func(match func(Observation) bool) []string {
		var out []string
		for _, observation := range observations {
			if match(observation) {
				out = append(out, observation.Direction+"/"+observation.Family)
			}
		}
		return out
	}
	failed := func(observation Observation) bool { return observation.Status == diagnostic.StatusFail.String() }
	passed := func(observation Observation) bool { return observation.Status == diagnostic.StatusPass.String() }

	if app := evidence(func(observation Observation) bool {
		return failed(observation) && observation.TCPConnected && observation.TLSAuthenticated && !observation.ApplicationTraffic
	}); len(app) > 0 {
		return CombinedDiagnosis{
			ID: DiagnosisApplicationFailure, Verdict: diagnostic.VerdictService,
			Summary:  "TCP and authenticated TLS succeed, but the fixed peer payload exchange fails.",
			Evidence: app, Ambiguous: true,
			Alternatives: []string{"the peer application stopped responding", "application traffic was interrupted after the TLS handshake"},
		}
	}
	if security := evidence(func(observation Observation) bool {
		return failed(observation) && observation.TCPConnected && !observation.TLSAuthenticated
	}); len(security) > 0 {
		return CombinedDiagnosis{
			ID: DiagnosisSecurityFailure, Verdict: diagnostic.VerdictService,
			Summary:  "TCP reaches an endpoint, but the authenticated TLS peer check fails.",
			Evidence: security, Ambiguous: true,
			Alternatives: []string{"the address no longer belongs to the paired Network Doctor session", "the peer session ended or changed credentials", "the TLS handshake was interrupted or timed out on the path"},
		}
	}

	for _, candidate := range []struct {
		identity  EndpointIdentity
		direction string
		label     string
	}{{listener, DirectionConnectorToListener, "listener"}, {connector, DirectionListenerToConnector, "connector"}} {
		loopbackFamily := ""
		rows := evidence(func(observation Observation) bool {
			if observation.Direction != candidate.direction || !failed(observation) ||
				!onlyLoopbackForFamily(candidate.identity.ListenAddresses, observation.Family) {
				return false
			}
			loopbackFamily = observation.Family
			return true
		})
		if len(rows) > 0 {
			summary := "The " + candidate.label + " endpoint is listening only on loopback, so another machine cannot reach it."
			if !onlyLoopback(candidate.identity.ListenAddresses) {
				summary = "The " + candidate.label + " endpoint for " + strings.ToUpper(loopbackFamily) + " is bound only to loopback, so another machine cannot reach it."
			}
			return CombinedDiagnosis{
				ID: DiagnosisLocalOnlyListener, Verdict: diagnostic.VerdictNetwork,
				Summary:  summary,
				Evidence: rows, Ambiguous: false,
			}
		}
	}

	directionState := func(direction string) (hasPass, hasFail, tested bool, allRefused bool) {
		allRefused = true
		for _, observation := range observations {
			if observation.Direction != direction || observation.Status == diagnostic.StatusNA.String() {
				continue
			}
			tested = true
			hasPass = hasPass || passed(observation)
			if failed(observation) {
				hasFail = true
				allRefused = allRefused && observation.Cause == diagnostic.ConnectionCauseRefused
			}
		}
		return
	}
	lcPass, lcFail, lcTested, lcRefused := directionState(DirectionListenerToConnector)
	clPass, clFail, clTested, clRefused := directionState(DirectionConnectorToListener)
	if lcPass && !lcFail && clFail && !clPass || clPass && !clFail && lcFail && !lcPass {
		failedDirection, destination := DirectionConnectorToListener, "listener"
		refused := clRefused
		if clPass {
			failedDirection, destination, refused = DirectionListenerToConnector, "connector", lcRefused
		}
		summary := "Connections toward the " + destination + " fail, while connections in the other direction succeed."
		alternatives := []string{"inbound filtering at the destination", "routing or reachability on the failing path", "address translation that does not admit the reverse connection"}
		verdict := diagnostic.VerdictNetwork
		if refused {
			summary = "Connections toward the " + destination + " are explicitly refused, while connections in the other direction succeed."
			alternatives = []string{"nothing is listening on the tested address and port", "a filter is actively rejecting the connection"}
			verdict = diagnostic.VerdictService
		}
		return CombinedDiagnosis{
			ID: DiagnosisDirectionalFailure, Verdict: verdict, Summary: summary,
			Evidence: evidence(func(observation Observation) bool {
				return observation.Direction == failedDirection && failed(observation) || observation.Direction != failedDirection && passed(observation)
			}),
			Ambiguous: true, Alternatives: alternatives,
		}
	}

	familyState := func(family string) (hasPass, hasFail, tested bool) {
		for _, observation := range observations {
			if observation.Family != family || observation.Status == diagnostic.StatusNA.String() {
				continue
			}
			tested = true
			hasPass = hasPass || passed(observation)
			hasFail = hasFail || failed(observation)
		}
		return
	}
	v4Pass, v4Fail, v4Tested := familyState(FamilyIPv4)
	v6Pass, v6Fail, v6Tested := familyState(FamilyIPv6)
	state := func(direction, family string) string {
		for _, observation := range observations {
			if observation.Direction == direction && observation.Family == family {
				return observation.Status
			}
		}
		return diagnostic.StatusNA.String()
	}
	familyPatternsDiffer := state(DirectionListenerToConnector, FamilyIPv4) != state(DirectionListenerToConnector, FamilyIPv6) ||
		state(DirectionConnectorToListener, FamilyIPv4) != state(DirectionConnectorToListener, FamilyIPv6)
	if v4Tested && v6Tested && familyPatternsDiffer && (v4Pass || v6Pass) && (v4Fail || v6Fail) {
		summary := "Peer reachability differs by address family and direction."
		if v4Pass && !v4Fail && v6Fail && !v6Pass {
			summary = "IPv4 peer traffic succeeds while IPv6 peer traffic fails."
		} else if v6Pass && !v6Fail && v4Fail && !v4Pass {
			summary = "IPv6 peer traffic succeeds while IPv4 peer traffic fails."
		}
		return CombinedDiagnosis{
			ID: DiagnosisFamilyAsymmetry, Verdict: diagnostic.VerdictNetwork,
			Summary:      summary,
			Evidence:     evidence(func(observation Observation) bool { return observation.Status != diagnostic.StatusNA.String() }),
			Ambiguous:    true,
			Alternatives: []string{"address-family routing differs", "filtering differs by address family", "one endpoint's address-family configuration is incomplete"},
		}
	}

	if lcTested && clTested && lcFail && clFail && !lcPass && !clPass {
		verdict := diagnostic.VerdictNetwork
		if lcRefused && clRefused {
			verdict = diagnostic.VerdictService
		}
		return CombinedDiagnosis{
			ID: DiagnosisSymmetricFailure, Verdict: verdict,
			Summary:  "The bounded peer connection tests fail in both directions.",
			Evidence: evidence(failed), Ambiguous: true,
			Alternatives: []string{"filtering at one or both endpoints", "routing or reachability failures on the paths", "the advertised listener addresses are not reachable from the other endpoint"},
		}
	}
	if lcPass && clPass && !lcFail && !clFail {
		return CombinedDiagnosis{
			ID: DiagnosisBidirectionalOK, Verdict: diagnostic.VerdictOK,
			Summary:  "Authenticated peer traffic succeeds in both directions.",
			Evidence: evidence(passed), Ambiguous: false,
		}
	}
	return CombinedDiagnosis{
		ID: DiagnosisIncompleteEvidence, Verdict: diagnostic.VerdictIncomplete,
		Summary:      "The peer session completed without enough two-ended evidence to localize the failure.",
		Evidence:     evidence(func(observation Observation) bool { return observation.Status != diagnostic.StatusNA.String() }),
		Ambiguous:    true,
		Alternatives: []string{"one direction or address family could not be tested", "the direct peer endpoint is not reachable from this topology"},
	}
}

func completeObservations(observations []Observation) []Observation {
	byKey := make(map[string]Observation, 4)
	for _, observation := range observations {
		byKey[observation.Direction+"/"+observation.Family] = observation
	}
	out := make([]Observation, 0, 4)
	for _, direction := range []string{DirectionListenerToConnector, DirectionConnectorToListener} {
		for _, family := range []string{FamilyIPv4, FamilyIPv6} {
			observation, ok := byKey[direction+"/"+family]
			if !ok {
				observation = Observation{
					Direction: direction, Family: family, Status: diagnostic.StatusNA.String(), Cause: CauseFamilyUnavailable,
				}
			}
			out = append(out, observation)
		}
	}
	return out
}

func onlyLoopback(addresses []string) bool {
	if len(addresses) == 0 {
		return false
	}
	return !slices.ContainsFunc(addresses, func(address string) bool {
		addr, ok := endpointAddr(address)
		return !ok || !addr.IsLoopback()
	})
}

func onlyLoopbackForFamily(addresses []string, family string) bool {
	found := false
	for _, address := range addresses {
		addr, ok := endpointAddr(address)
		if !ok || familyForAddr(addr) != family {
			continue
		}
		found = true
		if !addr.IsLoopback() {
			return false
		}
	}
	return found
}
