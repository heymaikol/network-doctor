package peer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

func pass(direction, family string) Observation {
	return Observation{
		Direction: direction, Family: family, Status: diagnostic.StatusPass.String(),
		TCPConnected: true, TLSAuthenticated: true, ApplicationTraffic: true, PayloadBytes: payloadSize, Ms: 1,
	}
}

func fail(direction, family, cause string) Observation {
	return Observation{Direction: direction, Family: family, Status: diagnostic.StatusFail.String(), Cause: cause, Ms: 1}
}

func TestCombinedDiagnosisTruthTable(t *testing.T) {
	listener := EndpointIdentity{Role: RoleListener, ListenAddresses: []string{"192.0.2.1:1"}}
	connector := EndpointIdentity{Role: RoleConnector, ListenAddresses: []string{"192.0.2.2:2"}}
	applicationFailure := fail(DirectionListenerToConnector, FamilyIPv4, CauseApplicationTrafficFailed)
	applicationFailure.TCPConnected, applicationFailure.TLSAuthenticated = true, true
	tests := []struct {
		name         string
		observations []Observation
		wantID       string
		wantVerdict  string
		ambiguous    bool
		contains     string
	}{
		{
			name:         "successful bidirectional traffic",
			observations: []Observation{pass(DirectionListenerToConnector, FamilyIPv4), pass(DirectionConnectorToListener, FamilyIPv4)},
			wantID:       DiagnosisBidirectionalOK,
		},
		{
			name:         "asymmetric reachability toward listener",
			observations: []Observation{pass(DirectionListenerToConnector, FamilyIPv4), fail(DirectionConnectorToListener, FamilyIPv4, CauseConnectionTimeout)},
			wantID:       DiagnosisDirectionalFailure, ambiguous: true, contains: "toward the listener",
		},
		{
			name: "directional failure outranks one unverified reverse family",
			observations: []Observation{
				pass(DirectionListenerToConnector, FamilyIPv4),
				{Direction: DirectionListenerToConnector, Family: FamilyIPv6, Status: "N/A", Cause: CausePeerAddressUnverified},
				fail(DirectionConnectorToListener, FamilyIPv4, CauseConnectionTimeout),
				fail(DirectionConnectorToListener, FamilyIPv6, CauseConnectionTimeout),
			},
			wantID: DiagnosisDirectionalFailure, ambiguous: true, contains: "toward the listener",
		},
		{
			name:         "asymmetric reachability toward connector",
			observations: []Observation{fail(DirectionListenerToConnector, FamilyIPv4, CauseConnectionUnreachable), pass(DirectionConnectorToListener, FamilyIPv4)},
			wantID:       DiagnosisDirectionalFailure, ambiguous: true, contains: "toward the connector",
		},
		{
			name:         "connection refusal stays conservative",
			observations: []Observation{pass(DirectionListenerToConnector, FamilyIPv4), fail(DirectionConnectorToListener, FamilyIPv4, diagnostic.ConnectionCauseRefused)},
			wantID:       DiagnosisDirectionalFailure, wantVerdict: diagnostic.VerdictService, ambiguous: true, contains: "explicitly refused",
		},
		{
			name:         "symmetric failure",
			observations: []Observation{fail(DirectionListenerToConnector, FamilyIPv4, CauseConnectionTimeout), fail(DirectionConnectorToListener, FamilyIPv4, CauseConnectionUnreachable)},
			wantID:       DiagnosisSymmetricFailure, ambiguous: true, contains: "both directions",
		},
		{
			name: "address family asymmetry",
			observations: []Observation{
				pass(DirectionListenerToConnector, FamilyIPv4), pass(DirectionConnectorToListener, FamilyIPv4),
				fail(DirectionListenerToConnector, FamilyIPv6, CauseConnectionTimeout), fail(DirectionConnectorToListener, FamilyIPv6, CauseConnectionUnreachable),
			},
			wantID: DiagnosisFamilyAsymmetry, ambiguous: true, contains: "IPv4 peer traffic succeeds",
		},
		{
			name: "crossed address family asymmetry",
			observations: []Observation{
				pass(DirectionListenerToConnector, FamilyIPv4), fail(DirectionConnectorToListener, FamilyIPv4, CauseConnectionTimeout),
				fail(DirectionListenerToConnector, FamilyIPv6, CauseConnectionTimeout), pass(DirectionConnectorToListener, FamilyIPv6),
			},
			wantID: DiagnosisFamilyAsymmetry, ambiguous: true, contains: "differs by address family and direction",
		},
		{
			name: "crossed asymmetry with one unverified reverse family",
			observations: []Observation{
				fail(DirectionListenerToConnector, FamilyIPv4, CauseConnectionTimeout),
				{Direction: DirectionListenerToConnector, Family: FamilyIPv6, Status: "N/A", Cause: CausePeerAddressUnverified},
				pass(DirectionConnectorToListener, FamilyIPv4),
				fail(DirectionConnectorToListener, FamilyIPv6, CauseConnectionTimeout),
			},
			wantID: DiagnosisFamilyAsymmetry, ambiguous: true, contains: "differs by address family and direction",
		},
		{
			name:         "tcp succeeds but application traffic fails",
			observations: []Observation{applicationFailure, pass(DirectionConnectorToListener, FamilyIPv4)},
			wantID:       DiagnosisApplicationFailure, ambiguous: true, contains: "payload exchange fails",
		},
		{
			name:         "insufficient reverse evidence",
			observations: []Observation{pass(DirectionConnectorToListener, FamilyIPv4)},
			wantID:       DiagnosisIncompleteEvidence, ambiguous: true, contains: "without enough",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Analyze(listener, connector, test.observations)
			if got.ID != test.wantID || got.Ambiguous != test.ambiguous || !strings.Contains(got.Summary, test.contains) {
				t.Fatalf("diagnosis = %+v, want id %q ambiguity %v containing %q", got, test.wantID, test.ambiguous, test.contains)
			}
			if test.wantVerdict != "" && got.Verdict != test.wantVerdict {
				t.Fatalf("verdict = %q, want %q", got.Verdict, test.wantVerdict)
			}
		})
	}
}

func TestCombinedDiagnosisProvesLoopbackOnlyBinding(t *testing.T) {
	listener := EndpointIdentity{Role: RoleListener, ListenAddresses: []string{"127.0.0.1:1", "[::1]:1"}}
	connector := EndpointIdentity{Role: RoleConnector, ListenAddresses: []string{"192.0.2.2:2"}}
	got := Analyze(listener, connector, []Observation{
		pass(DirectionListenerToConnector, FamilyIPv4),
		fail(DirectionConnectorToListener, FamilyIPv4, CauseConnectionUnreachable),
	})
	if got.ID != DiagnosisLocalOnlyListener || got.Ambiguous {
		t.Fatalf("diagnosis = %+v, want proven local-only listener", got)
	}
}

func TestCombinedDiagnosisProvesOneFamilyIsBoundToLoopback(t *testing.T) {
	listener := EndpointIdentity{Role: RoleListener, ListenAddresses: []string{"192.0.2.1:1", "[::1]:1"}}
	connector := EndpointIdentity{Role: RoleConnector, ListenAddresses: []string{"192.0.2.2:2", "[2001:db8::2]:2"}}
	got := Analyze(listener, connector, []Observation{
		pass(DirectionListenerToConnector, FamilyIPv4), pass(DirectionConnectorToListener, FamilyIPv4),
		pass(DirectionListenerToConnector, FamilyIPv6), fail(DirectionConnectorToListener, FamilyIPv6, diagnostic.ConnectionCauseRefused),
	})
	if got.ID != DiagnosisLocalOnlyListener || got.Ambiguous || !strings.Contains(got.Summary, "IPV6") {
		t.Fatalf("diagnosis = %+v, want proven IPv6 loopback-only listener", got)
	}
}

func TestPeerResultJSONIsDeterministicAndContainsNoCredentials(t *testing.T) {
	listener := EndpointIdentity{Role: RoleListener, Name: "alpha", ListenAddresses: []string{"192.0.2.1:1"}}
	connector := EndpointIdentity{Role: RoleConnector, Name: "beta", ListenAddresses: []string{"192.0.2.2:2"}}
	result := buildResult(RoleListener, "test", listener, connector, ChannelObservation{Established: true, Family: FamilyIPv4, Local: "192.0.2.1:1", Remote: "192.0.2.2:2", Ms: 1}, []Observation{
		pass(DirectionConnectorToListener, FamilyIPv4), pass(DirectionListenerToConnector, FamilyIPv4),
	})
	first, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("serialization changed:\n%s\n%s", first, second)
	}
	text := string(first)
	for _, forbidden := range []string{"token", "pairing", "certificate", encodedByte(tokenSize, 7)} {
		if strings.Contains(text, forbidden) {
			t.Errorf("result contains credential marker %q: %s", forbidden, text)
		}
	}
	if !result.OK || len(result.Observations) != 4 || result.Observations[0].Direction != DirectionListenerToConnector || result.Observations[0].Family != FamilyIPv4 {
		t.Fatalf("result ordering/status = %+v", result)
	}
}

func TestPeerNameIsSanitizedAndBounded(t *testing.T) {
	got := cleanName("host\x1b]52;c;aGk=\a\u202eevil" + strings.Repeat("x", 200))
	if len(got) > maxPeerNameSize || strings.ContainsAny(got, "\x1b\a\u202e") {
		t.Fatalf("cleanName = %q", got)
	}
}
