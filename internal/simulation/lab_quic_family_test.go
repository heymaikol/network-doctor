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
	// IPv6 is tried first and wins, so the IPv4 handshake never reaches a
	// deadline and the live dialer would record nothing for it.
	if len(row.Observed.Attempts) != 1 || row.Observed.Attempts[0].IP != labReference6 || row.Observed.Attempts[0].Cause != "" {
		t.Errorf("attempts = %+v, want only the IPv6 address that answered", row.Observed.Attempts)
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

// Through the production runner: a QUIC endpoint answered in one family, on a
// dual-stack network that loses that family, is not UDP/443 being blocked. The
// same endpoint with UDP/443 dropped, on a network whose families both work,
// still is.
func TestLabQUICIsNotCalledUnavailableWithoutAReferenceInItsFamily(t *testing.T) {
	familyDrop := func(family string) LabFault {
		return LabFault{ID: "family-drop", Layer: "transport", Scope: "gateway", Network: &Fault{Type: FaultDrop, Node: "gateway", Direction: DirectionInbound, Family: family}}
	}
	udpDrop := LabFault{ID: "quic-drop", Layer: "transport", Scope: "internet", Network: &Fault{Type: FaultDrop, Node: "internet", Protocol: "udp", Port: 443, Direction: DirectionInbound}}
	for _, tc := range []struct {
		name    string
		answers []string
		fault   LabFault
		generic bool
		want    d.DiagnosisID
	}{
		{"IPv4-only QUIC answer, IPv4 dropped", []string{"10.20.2.20"}, familyDrop("ipv4"), false, d.DiagnosisFamilyReachabilityUnlocalized},
		{"IPv6-only QUIC answer, IPv6 dropped", []string{labReference6}, familyDrop("ipv6"), false, d.DiagnosisFamilyReachabilityUnlocalized},
		{"IPv4-only QUIC answer, IPv4 dropped, no target", []string{"10.20.2.20"}, familyDrop("ipv4"), true, d.DiagnosisFamilyReachabilityUnlocalized},
		{"dual-stack QUIC answer, UDP/443 dropped", []string{"10.20.2.20", labReference6}, udpDrop, false, d.DiagnosisQUICUnavailable},
		{"IPv4-only QUIC answer, UDP/443 dropped", []string{"10.20.2.20"}, udpDrop, false, d.DiagnosisQUICUnavailable},
		{"dual-stack QUIC answer, UDP/443 dropped, no target", []string{"10.20.2.20", labReference6}, udpDrop, true, d.DiagnosisQUICUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := FindLabScenario("healthy-dual-stack")
			if err != nil {
				t.Fatal(err)
			}
			labQUICAnswers(&s, tc.answers...)
			s.Faults = []LabFault{tc.fault}
			if tc.generic {
				s.Views[0].Target = ""
			}
			r, err := RunLab(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			snap := r.Views[0].Snapshot
			got, err := d.ReplaySnapshot(snap)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Findings) == 0 || got.Findings[0].ID != tc.want || got.Blamed != d.ProbeQUIC || got.Verdict != d.VerdictDegraded {
				t.Fatalf("verdict = %s, blamed = %s, findings = %+v, want %s on the QUIC row (summary: %s)", got.Verdict, got.Blamed, got.Findings, tc.want, got.Summary)
			}
			if problems := ValidateLabEvidence(snap, got); len(problems) > 0 {
				t.Errorf("evidence problems: %v", problems)
			}
			if err := snapshot.Validate(snap); err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			data, err := json.Marshal(snapshot.SanitizeForSupport(snap))
			if err != nil {
				t.Fatal(err)
			}
			var back snapshot.Snapshot
			if err := json.Unmarshal(data, &back); err != nil {
				t.Fatal(err)
			}
			replayed, err := d.ReplaySnapshot(back)
			if err != nil {
				t.Fatalf("sanitized replay: %v", err)
			}
			if replayed.Verdict != got.Verdict || replayed.Blamed != got.Blamed || len(replayed.Findings) == 0 || replayed.Findings[0].ID != tc.want {
				t.Errorf("sanitized replay = %s %s %+v", replayed.Verdict, replayed.Blamed, replayed.Findings)
			}
		})
	}
}

// What each way of failing leaves on the modeled row, held to what the live
// dialer records for the same thing.
func TestLabQUICAttemptsMatchTheLiveDialer(t *testing.T) {
	dual := func(t *testing.T) LabScenario {
		t.Helper()
		s, err := FindLabScenario("healthy-dual-stack")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	udpDrop := LabFault{ID: "quic-drop", Layer: "transport", Scope: "internet", Network: &Fault{Type: FaultDrop, Node: "internet", Protocol: "udp", Port: 443, Direction: DirectionInbound}}
	noDefault4 := LabFault{ID: "no-default", Layer: "routing", Scope: "client", Network: &Fault{Type: FaultNoDefaultRoute, Node: "client", Family: "ipv4"}}
	type want struct {
		ip, cause string
		aborted   bool
	}
	for _, tc := range []struct {
		name    string
		answers []string
		faults  []LabFault
		status  string
		cause   string
		want    []want
	}{
		// Both silent: the probe runs to its deadline, which ends both.
		{"both families silent", []string{"10.20.2.20", labReference6}, []LabFault{udpDrop}, snapshot.StatusFail, d.QUICCauseTimeout,
			[]want{{labReference6, d.ConnectionCauseTimeout, true}, {"10.20.2.20", d.ConnectionCauseTimeout, true}}},
		// No route fails at once and by itself, so the run never waits.
		{"IPv4 only, no IPv4 route", []string{"10.20.2.20"}, []LabFault{noDefault4}, snapshot.StatusFail, d.QUICCauseHandshake,
			[]want{{"10.20.2.20", d.ConnectionCauseUnreachable, false}}},
		// A host that is reached and has nothing on UDP/443 refuses.
		{"endpoint name answered with a host that has no QUIC", []string{labTarget4}, nil, snapshot.StatusFail, d.QUICCauseHandshake,
			[]want{{labTarget4, d.ConnectionCauseRefused, false}}},
		// A refusal and a silence in one run: the refusal first, as it
		// completed first, and the deadline cause for the row.
		{"one address refuses and one is silent", []string{labTarget4, labReference6}, []LabFault{udpDrop}, snapshot.StatusFail, d.QUICCauseTimeout,
			[]want{{labTarget4, d.ConnectionCauseRefused, false}, {labReference6, d.ConnectionCauseTimeout, true}}},
		// A fast failure before the winner is kept beside it.
		{"IPv6 answers after IPv4 had no route", []string{"10.20.2.20", labReference6}, []LabFault{noDefault4}, snapshot.StatusPass, "",
			[]want{{labReference6, "", false}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dual(t)
			labQUICAnswers(&s, tc.answers...)
			s.Faults = tc.faults
			row := labQUICRow(t, s)
			if row.Status != tc.status || row.Cause != tc.cause || row.Observed == nil || len(row.Observed.Attempts) != len(tc.want) {
				t.Fatalf("row = %s cause %q, observed %+v; want %s cause %q with %d attempts", row.Status, row.Cause, row.Observed, tc.status, tc.cause, len(tc.want))
			}
			for i, w := range tc.want {
				if a := row.Observed.Attempts[i]; a.IP != w.ip || a.Cause != w.cause || a.Aborted != w.aborted {
					t.Errorf("attempt %d = %+v, want %+v", i, a, w)
				}
			}
		})
	}
}

// A generated case says which construction made it, generating it twice gives
// the same bytes, and a case that claims the earlier construction is refused
// instead of being read as one of this one's: the two build different worlds
// for the same seed and case number.
func TestLabFuzzCasesAreVersionedAndDeterministic(t *testing.T) {
	if LabFuzzVersion != "reasoning-v2" {
		t.Fatalf("generator version = %q; a construction change needs a version review and this test updated", LabFuzzVersion)
	}
	for _, index := range []uint64{0, 18, 4187} {
		c, err := GenerateLabFuzz(847293, index, 4, true)
		if err != nil {
			t.Fatal(err)
		}
		again, err := GenerateLabFuzz(847293, index, 4, true)
		if err != nil {
			t.Fatal(err)
		}
		first, _ := json.Marshal(c)
		second, _ := json.Marshal(again)
		if c.Version != LabFuzzVersion || string(first) != string(second) {
			t.Fatalf("case %d: version %q, generated twice equal = %v", index, c.Version, string(first) == string(second))
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("case %d: %v", index, err)
		}
		c.Version = "reasoning-v1"
		if err := c.Validate(); err == nil {
			t.Fatalf("case %d: a reasoning-v1 case was accepted as %s", index, LabFuzzVersion)
		}
	}
}
