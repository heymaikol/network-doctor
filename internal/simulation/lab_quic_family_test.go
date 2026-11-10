package simulation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
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

// The generator reaches a dual-stack world whose QUIC reference endpoint is
// answered in one family only, in both families, and the first such case is
// pinned the way the generator's own vector is.
func TestLabFuzzVariesTheQUICReferenceAnswerFamily(t *testing.T) {
	seen := map[string]uint64{}
	for i := uint64(0); i < 200; i++ {
		c, err := GenerateLabFuzz(847293, i, 4, true)
		if err != nil {
			t.Fatal(err)
		}
		dual := false
		var v4, v6 bool
		for _, n := range c.Worlds[0].Network.Topology.Nodes {
			if n.Name == "client" {
				dual = n.Interfaces[0].IPv4 != "" && n.Interfaces[0].IPv6 != ""
			}
			for _, svc := range n.Services {
				for _, r := range svc.Records {
					if svc.Name == "system-dns" && r.Name == d.ConnectivityProbeHost {
						if strings.Contains(r.Address, ":") {
							v6 = true
						} else {
							v4 = true
						}
					}
				}
			}
		}
		if !dual {
			continue
		}
		key := fmt.Sprintf("ipv4=%v ipv6=%v", v4, v6)
		if _, ok := seen[key]; !ok {
			seen[key] = i
		}
	}
	for _, key := range []string{"ipv4=true ipv6=true", "ipv4=true ipv6=false", "ipv4=false ipv6=true"} {
		if _, ok := seen[key]; !ok {
			t.Errorf("no dual-stack world with QUIC reference answers %s in the first 200 cases: %v", key, seen)
		}
	}
	const wantIndex, wantDigest = uint64(18), "0b9c2ae0a36ceacec243bc001e5ae0ec5aa284e43b79f4ed4e8863ec2a48fbbb"
	index := seen["ipv4=true ipv6=false"]
	c, err := GenerateLabFuzz(847293, index, 4, true)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(c)
	if digest := fmt.Sprintf("%x", sha256.Sum256(data)); index != wantIndex || digest != wantDigest {
		t.Fatalf("first dual-stack case with an IPv4-only QUIC reference = %d, digest %s; review and version deliberate generator changes", index, digest)
	}
}
