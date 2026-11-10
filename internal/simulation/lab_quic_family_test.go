package simulation

import (
	"context"
	"testing"

	d "github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
)

func labQUICRow(t *testing.T, s LabScenario) snapshot.Check {
	t.Helper()
	r, err := RunLab(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Views[0].Snapshot.Checks {
		if c.ID == string(d.ProbeQUIC) {
			return c
		}
	}
	t.Fatal("no QUIC row")
	return snapshot.Check{}
}

// The modeled QUIC row records what it tried, in the shape the live dialer
// records it: the address that answered, an address with no route as its own
// failure, and a silent address as an attempt the probe deadline ended.
func TestLabQUICRowRecordsItsAttempts(t *testing.T) {
	healthy, err := FindLabScenario("healthy-dual-stack")
	if err != nil {
		t.Fatal(err)
	}
	row := labQUICRow(t, healthy)
	if row.Status != snapshot.StatusPass || row.Observed == nil || len(row.Observed.Attempts) == 0 {
		t.Fatalf("healthy QUIC row = %+v, want a pass that records the address that answered", row)
	}
	if last := row.Observed.Attempts[len(row.Observed.Attempts)-1]; last.IP != row.Observed.SelectedIP || last.Cause != "" {
		t.Errorf("winning attempt = %+v, selected %s", last, row.Observed.SelectedIP)
	}

	silent := healthy
	silent.Faults = []LabFault{{ID: "quic-drop", Layer: "transport", Scope: "internet", Network: &Fault{Type: FaultDrop, Node: "internet", Protocol: "udp", Port: 443, Direction: DirectionInbound}}}
	row = labQUICRow(t, silent)
	if row.Status != snapshot.StatusFail || row.Observed == nil || len(row.Observed.Attempts) == 0 {
		t.Fatalf("QUIC row with UDP/443 dropped = %+v, want a failure that records its attempts", row)
	}
	for _, a := range row.Observed.Attempts {
		if a.Cause != d.ConnectionCauseTimeout || !a.Aborted {
			t.Errorf("silent attempt = %+v, want a timeout the probe deadline ended", a)
		}
	}
}

// labQUICAnswers replaces what every modeled resolver answers for the QUIC
// reference endpoint.
func labQUICAnswers(s *LabScenario, addrs ...string) {
	for i := range s.Network.Topology.Nodes {
		for j := range s.Network.Topology.Nodes[i].Services {
			svc := &s.Network.Topology.Nodes[i].Services[j]
			if len(svc.Records) == 0 {
				continue
			}
			var records []DNSRecord
			for _, r := range svc.Records {
				if r.Name != d.ConnectivityProbeHost {
					records = append(records, r)
				}
			}
			for _, a := range addrs {
				records = append(records, DNSRecord{Name: d.ConnectivityProbeHost, Address: a})
			}
			svc.Records = records
		}
	}
}

// The QUIC reference endpoint is dual-stack, as the real one is. A dual-stack
// world that loses IPv4 still completes QUIC over IPv6, and a view bound to a
// source with no address in the only family the endpoint has tries nothing.
func TestLabQUICReferenceIsDualStack(t *testing.T) {
	dual, err := FindLabScenario("healthy-dual-stack")
	if err != nil {
		t.Fatal(err)
	}
	v4Dropped := dual
	v4Dropped.Faults = []LabFault{{ID: "family-drop", Layer: "transport", Scope: "gateway", Network: &Fault{Type: FaultDrop, Node: "gateway", Direction: DirectionInbound, Family: "ipv4"}}}
	row := labQUICRow(t, v4Dropped)
	if row.Status != snapshot.StatusPass || row.Observed == nil || row.Observed.SelectedIP != labReference6 {
		t.Fatalf("QUIC row with IPv4 dropped = %+v, want a handshake over IPv6", row)
	}
	if len(row.Observed.Attempts) != 2 || row.Observed.Attempts[0].Cause != d.ConnectionCauseTimeout || !row.Observed.Attempts[0].Aborted {
		t.Errorf("attempts = %+v, want the silent IPv4 address and then the IPv6 one that answered", row.Observed.Attempts)
	}

	v4Only, err := FindLabScenario("healthy-ipv4")
	if err != nil {
		t.Fatal(err)
	}
	labQUICAnswers(&v4Only, labReference6)
	if row := labQUICRow(t, v4Only); row.Status != snapshot.StatusNA || row.Observed != nil && len(row.Observed.Attempts) != 0 {
		t.Errorf("QUIC row on an IPv4-only source with an IPv6-only endpoint = %+v, want not applicable and nothing tried", row)
	}
}
