package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/heymaikol/network-doctor/v2/internal/compare"
	d "github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
	"reflect"
	"slices"
	"sync"
	"testing"
)

func TestLabCorpus(t *testing.T) {
	for _, s := range LabScenarios() {
		t.Run(s.Name, func(t *testing.T) {
			r, err := RunLab(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range r.Views {
				t.Logf("%s: %s %+v", v.Node, v.Snapshot.Diagnosis.Verdict, v.Snapshot.Diagnosis.Findings)
			}
			if !slices.Equal(r.Problems, s.KnownIssues) {
				t.Errorf("unexpected validation problems: %v; known: %v", r.Problems, s.KnownIssues)
			}
			again, err := RunLab(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(r)
			b, _ := json.Marshal(again)
			if string(a) != string(b) {
				t.Fatal("nondeterministic run")
			}
		})
	}
}

func TestLabRejectsInvalidStructure(t *testing.T) {
	tests := []struct {
		name   string
		change func(*LabScenario)
	}{
		{"duplicate node", func(s *LabScenario) {
			s.Network.Topology.Nodes = append(s.Network.Topology.Nodes, s.Network.Topology.Nodes[0])
		}},
		{"unknown segment", func(s *LabScenario) { s.Network.Topology.Nodes[0].Interfaces[0].Segment = "absent" }},
		{"overlap", func(s *LabScenario) { s.Network.Topology.Segments[1].IPv4 = "10.20.1.0/25" }},
		{"wrong address family", func(s *LabScenario) { s.Network.Topology.Nodes[0].Interfaces[0].IPv4 = "2001:db8::1/64" }},
		{"mapped IPv6", func(s *LabScenario) { s.Network.Topology.Nodes[0].Interfaces[0].IPv6 = "::ffff:10.20.1.10/120" }},
		{"outside subnet", func(s *LabScenario) { s.Network.Topology.Nodes[0].Interfaces[0].IPv4 = "10.99.1.10/24" }},
		{"off-link next hop", func(s *LabScenario) { s.Network.Topology.Routes[0].Via = "10.99.1.1" }},
		{"unknown route owner", func(s *LabScenario) { s.Network.Topology.Routes[0].Node = "missing" }},
		{"wrong next-hop family", func(s *LabScenario) { s.Network.Topology.Routes[0].Via = "2001:db8::1" }},
		{"unknown tunnel", func(s *LabScenario) { s.Tunnels = []string{"missing"} }},
		{"unknown view", func(s *LabScenario) { s.Views[0].Node = "missing" }},
		{"unknown source", func(s *LabScenario) { s.Views[0].SourceSegment = "uplink" }},
		{"unknown target", func(s *LabScenario) { s.Views[0].Target = "https://" }},
		{"contradictory oracle", func(s *LabScenario) {
			s.Views[0].Expected.Required = []d.DiagnosisID{d.DiagnosisOffline}
			s.Views[0].Expected.Forbidden = []d.DiagnosisID{d.DiagnosisOffline}
		}},
		{"unknown check", func(s *LabScenario) { s.Views[0].Expected.Checks = []ExpectedCheck{{ID: "invented", Status: "PASS"}} }},
		{"invalid confidence", func(s *LabScenario) {
			s.Views[0].Expected.Required = []d.DiagnosisID{d.DiagnosisOffline}
			s.Views[0].Expected.Confidence = []LabConfidence{{Finding: d.DiagnosisOffline, Min: d.ConfidenceHigh, Max: d.ConfidenceLow}}
		}},
		{"missing mutation", func(s *LabScenario) { s.Faults = []LabFault{{ID: "empty", Layer: "dns", Scope: "resolver"}} }},
		{"unknown service", func(s *LabScenario) {
			s.Faults = []LabFault{{ID: "missing", Layer: "dns", Scope: "missing", Service: &Service{Name: "missing", Type: ServiceDNS}}}
		}},
		{"multiple mutations", func(s *LabScenario) {
			s.Faults = []LabFault{{ID: "two", Layer: "dns", Scope: "resolver", Network: &Fault{Type: FaultLinkDown, Node: "resolver", Segment: "ethernet"}, ResolverNode: "client", Resolver: "10.20.1.53"}}
		}},
		{"unsupported timing", func(s *LabScenario) {
			s.Faults = []LabFault{{ID: "delay", Layer: "transport", Scope: "client", Network: &Fault{Type: FaultNetem, Node: "client", Delay: "1s"}}}
		}},
		{"impossible pmtu", func(s *LabScenario) {
			s.Faults = []LabFault{{ID: "mtu", Layer: "transport", Scope: "client", Network: &Fault{Type: FaultPMTUBlackhole, Node: "client", Segment: "ethernet", MTU: 1280}}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := LabScenarios()[0]
			tt.change(&s)
			if _, err := RunLab(context.Background(), s); err == nil {
				t.Fatal("invalid scenario accepted")
			}
		})
	}
}

func TestLabRouteAndTransportSemantics(t *testing.T) {
	s, _ := FindLabScenario("vpn-split-tunnel")
	m, err := s.compile()
	if err != nil {
		t.Fatal(err)
	}
	x := m.exchange("", "client", labTarget4, "", "tcp", 443, 64, 0)
	if x.Outcome != labDelivered || x.Forward[0].Segment != "vpn" || x.Return[0].NextHop != "10.20.2.2" {
		t.Fatalf("specific route/return path: %+v", x)
	}
	x = m.exchange("", "client", "1.1.1.1", "", "tcp", 443, 64, 0)
	if x.Outcome != labDelivered || x.Forward[0].Segment != "ethernet" {
		t.Fatalf("default route: %+v", x)
	}
	s, _ = FindLabScenario("asymmetric-routing")
	m, err = s.compile()
	if err != nil {
		t.Fatal(err)
	}
	x = m.exchange("", "client", labTarget4, "", "tcp", 443, 64, 0)
	if x.Outcome != "timeout" || len(x.Forward) == 0 || len(x.Return) == 0 || x.Return[0].NextHop != "10.20.2.254" {
		t.Fatalf("return path did not cause failure: %+v", x)
	}
	s, _ = FindLabScenario("mtu-blackhole")
	m, err = s.compile()
	if err != nil {
		t.Fatal(err)
	}
	small := m.exchange("", "client", labTarget4, "", "tcp", 443, 64, 0)
	boundary := m.exchange("", "client", labTarget4, "", "tcp", 443, 1280, 0)
	large := m.exchange("", "client", labTarget4, "", "tcp", 443, 1281, 0)
	if small.Outcome != labDelivered || boundary.Outcome != labDelivered || large.Outcome != "timeout" || len(large.MatchedFaults) != 1 {
		t.Fatalf("MTU boundary: %+v %+v %+v", small, boundary, large)
	}
	// An unreachable public-looking address is still just a modeled no-route
	// result. The model never delegates a missing node to the host network.
	if x := m.exchange("", "client", "9.9.9.9", "", "tcp", 443, 64, 0); x.Outcome == labDelivered {
		t.Fatal("unowned address delivered")
	}
}

func TestLabRoutePreferenceLoopsAndSourceSelection(t *testing.T) {
	s, _ := FindLabScenario("vpn-split-tunnel")
	s.Network.Topology.Routes = append(s.Network.Topology.Routes, Route{Node: "client", Destination: labTarget4 + "/32", Via: "10.20.1.1", Metric: 50})
	m, err := s.compile()
	if err != nil {
		t.Fatal(err)
	}
	i, source, via, _, ok := m.route(m.scenario.Client(), labAddr(labTarget4), "")
	if !ok || i.Segment != "vpn" || source.String() != "10.20.3.10" || via.String() != "10.20.3.1" {
		t.Fatalf("metric/source selection: %v %v %v", i, source, via)
	}
	i, _, _, _, ok = m.route(m.scenario.Client(), labAddr(labTarget4), "ethernet")
	if !ok || i.Segment != "ethernet" {
		t.Fatal("source selection ignored")
	}
	// A valid set of on-link routes can form a loop. It must terminate without
	// inventing delivery or waiting for a timeout on the host.
	s.Network.Topology.Routes = append(s.Network.Topology.Routes, Route{Node: "gateway", Destination: "9.9.9.9/32", Via: "10.20.1.10"})
	m, err = s.compile()
	if err != nil {
		t.Fatal(err)
	}
	if x := m.exchange("", "client", "9.9.9.9", "", "tcp", 443, 64, 0); x.Outcome != "not_forwarding" {
		t.Fatalf("non-router transit accepted: %+v", x)
	}
}

func TestLabFaultCompositionAndLossAreDeterministic(t *testing.T) {
	base := LabScenarios()[0]
	a, _ := FindLabScenario("dns-resolver-unreachable")
	b, _ := FindLabScenario("tls-certificate-mismatch")
	base.Faults = append(a.Faults, b.Faults...)
	before, _ := json.Marshal(base)
	first, err := RunLab(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(base)
	if string(before) != string(after) {
		t.Fatal("run mutated authored scenario")
	}
	slices.Reverse(base.Faults)
	second, err := RunLab(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Views[0].Snapshot, second.Views[0].Snapshot) {
		t.Fatal("independent faults did not commute")
	}
	for _, c := range first.Views[0].Measured {
		if c.ID == "tls" && (c.Ran || c.Status != "SKIP") {
			t.Fatal("hidden TLS fault reached the observer")
		}
	}
	base = LabScenarios()[0]
	base.Faults = []LabFault{{ID: "loss", Layer: "transport", Scope: "gateway/uplink", Network: &Fault{Type: FaultNetem, Node: "gateway", Segment: "uplink", Loss: "30%", Seed: 42}}}
	m, err := base.compile()
	if err != nil {
		t.Fatal(err)
	}
	lost := 0
	for i := range 100 {
		x := m.exchange("", "client", labTarget4, "", "tcp", 443, 64, i)
		_ = m.exchange("", "remote", "1.1.1.1", "", "udp", 53, 128, 99) // unrelated flow cannot consume entropy
		y := m.exchange("", "client", labTarget4, "", "tcp", 443, 64, i)
		if !reflect.DeepEqual(x, y) {
			t.Fatal("loss depends on execution order")
		}
		if x.Outcome != labDelivered {
			lost++
		}
	}
	if lost == 0 || lost == 100 {
		t.Fatalf("loss did not produce both outcomes: %d", lost)
	}
}

func TestLabPairwiseFaults(t *testing.T) {
	names := []string{"dns-resolver-unreachable", "tls-certificate-mismatch", "tcp-port-blocked", "reference-egress-unreachable", "mtu-blackhole"}
	// Ordered by the pairs below. DNS loss masks target probes; TCP loss
	// masks TLS and MTU; MTU loss prevents certificate observation. Independent
	// reference loss alone must not erase an observed certificate rejection.
	expected := []struct {
		verdict string
		id      d.DiagnosisID
	}{
		{d.VerdictDNS, d.DiagnosisSystemDNSFailure}, {d.VerdictDNS, d.DiagnosisSystemDNSFailure},
		{d.VerdictDNS, d.DiagnosisSystemDNSFailure}, {d.VerdictDNS, d.DiagnosisSystemDNSFailure},
		{d.VerdictService, d.DiagnosisTargetUnreachable}, {d.VerdictService, d.DiagnosisTLSHostnameMismatch},
		{d.VerdictNetwork, d.DiagnosisProbablePathMTU}, {d.VerdictNetwork, d.DiagnosisReachabilityUnlocalized},
		{d.VerdictService, d.DiagnosisTargetUnreachable}, {d.VerdictNetwork, d.DiagnosisProbablePathMTU},
	}
	pair := 0
	for i, a := range names {
		for _, b := range names[i+1:] {
			want := expected[pair]
			pair++
			t.Run(a+"+"+b, func(t *testing.T) {
				s := LabScenarios()[0]
				one, _ := FindLabScenario(a)
				two, _ := FindLabScenario(b)
				s.Faults = append(one.Faults, two.Faults...)
				r, err := RunLab(context.Background(), s)
				if err != nil {
					t.Fatal(err)
				}
				snap := r.Views[0].Snapshot

				diagnosis, err := d.ReplaySnapshot(snap)
				if err != nil {
					t.Fatal(err)
				}
				// The oracle is declared from prerequisite masking, not copied
				// from the diagnosis under test.
				props := LabExpected{Verdict: want.verdict, Required: []d.DiagnosisID{want.id}, Forbidden: []d.DiagnosisID{d.DiagnosisOffline, d.DiagnosisTLSCertificateExpired}}
				if p := ValidateLabDiagnosis(props, snap, diagnosis); len(p) > 0 {
					t.Fatal(p)
				}
				for _, c := range r.Views[0].Measured {
					if c.Status == "SKIP" && c.Ran {
						t.Fatal("skipped row claims execution")
					}
				}
				again, err := RunLab(context.Background(), s)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(r, again) {
					t.Fatal("pairwise run not deterministic")
				}
				slices.Reverse(s.Faults)
				reversed, err := RunLab(context.Background(), s)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(r.Views[0].Snapshot, reversed.Views[0].Snapshot) || !reflect.DeepEqual(r.Views[0].Measured, reversed.Views[0].Measured) {
					t.Fatal("independent pair did not commute")
				}
				if len(reversed.Truth) != 2 {
					t.Fatal("composition erased ground truth")
				}
			})
		}
	}
}

func TestLabValidatorRejectsUnsupportedClaims(t *testing.T) {
	s, _ := FindLabScenario("tls-certificate-mismatch")
	r, err := RunLab(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	snap := r.Views[0].Snapshot
	for _, change := range []struct {
		name   string
		mutate func(*d.Diagnosis)
	}{
		{"wrong cause family", func(v *d.Diagnosis) { v.Findings[0].ID = d.DiagnosisOffline }},
		{"missing required", func(v *d.Diagnosis) { v.Findings = nil }},
		{"invented observation", func(v *d.Diagnosis) {
			v.Findings[0].Evidence = append(v.Findings[0].Evidence, d.CausalEvidence{Kind: d.EvidenceSupport, Check: d.ProbeDNS, Observation: d.ObservationCaptivePortal})
		}},
		{"unmeasured support", func(v *d.Diagnosis) {
			v.Findings[0].Evidence = []d.CausalEvidence{{Kind: d.EvidenceSupport, Check: d.ProbeHTTPS, Observation: d.ObservationStatusPass}}
		}},
		{"missing row", func(v *d.Diagnosis) {
			v.Findings[0].Evidence = []d.CausalEvidence{{Kind: d.EvidenceSupport, Check: "invented", Observation: d.ObservationStatusPass}}
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			v, err := d.ReplaySnapshot(snap)
			if err != nil {
				t.Fatal(err)
			}
			change.mutate(&v)
			if len(ValidateLabDiagnosis(s.Views[0].Expected, snap, v)) == 0 {
				t.Fatal("unsupported claim accepted")
			}
		})
	}
	// Snapshot replay must ignore every historical diagnosis field.
	original, _ := d.ReplaySnapshot(snap)
	snap.Diagnosis = snapshot.Diagnosis{Verdict: "network", Summary: "invented historical diagnosis"}
	replay, err := d.ReplaySnapshot(snap)
	if err != nil || !reflect.DeepEqual(original, replay) {
		t.Fatal("replay trusted stored diagnosis", err)
	}
}

func TestLabTwoSidedUsesActualDifferentEndpoints(t *testing.T) {
	s, _ := FindLabScenario("unrelated-dns-answers")
	r, err := RunLab(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	var selected []string
	for _, v := range r.Views {
		for _, c := range v.Snapshot.Checks {
			if c.ID == "target_tcp" {
				selected = append(selected, c.Observed.SelectedIP)
			}
		}
	}
	if len(selected) != 2 || selected[0] == selected[1] || r.TwoSided.Diagnosis.Side != compare.SideNone || r.Comparison == nil {
		t.Fatalf("lost endpoint distinction: %v %+v", selected, r.TwoSided)
	}
	// Healthy target naming does not prove common destinations. Pin the blind
	// spot without reimplementing localization in the simulator.
	s.Views[1].Target = "https://different.test"
	if _, err := RunLab(context.Background(), s); err == nil {
		t.Fatal("different named targets were compared")
	}
}

func TestLabConcurrentRunsAndCancellation(t *testing.T) {
	for _, s := range LabScenarios() {
		want, err := RunLab(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				got, err := RunLab(context.Background(), s)
				if err != nil || !labJSONEqual(want, got) {
					t.Errorf("concurrent run changed: %v", err)
				}
			})
		}
		wg.Wait()
	}
	s := LabScenarios()[0]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunLab(ctx, s); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}

func TestLabServiceControlsAndWrongFamilyAnswers(t *testing.T) {
	s := LabScenarios()[0]
	for i := range s.Network.Topology.Nodes {
		for j := range s.Network.Topology.Nodes[i].Services {
			svc := &s.Network.Topology.Nodes[i].Services[j]
			if svc.Name == "target-http" {
				svc.Status = 503
			}
		}
	}
	r, err := RunLab(context.Background(), s)
	if err != nil || !r.Passed() {
		t.Fatalf("HTTP 503 stopped being delivery: %v %+v", err, r.Problems)
	}
	for i := range s.Network.Topology.Nodes {
		for j := range s.Network.Topology.Nodes[i].Services {
			svc := &s.Network.Topology.Nodes[i].Services[j]
			if svc.Name == "target-tls" {
				svc.Type = ServiceTCP
				svc.Certificate = nil
			}
		}
	}
	s.Views[0].Expected = LabExpected{Verdict: d.VerdictService, Required: []d.DiagnosisID{d.DiagnosisTLSHandshakeFailure}, Checks: []ExpectedCheck{{ID: "target_tcp", Status: "PASS"}, {ID: "tls", Status: "FAIL", Cause: d.TLSCauseHandshake}}}
	r, err = RunLab(context.Background(), s)
	if err != nil || !r.Passed() {
		t.Fatalf("plain service treated as TLS: %v %+v", err, r.Problems)
	}
	s = LabScenarios()[0]
	for i := range s.Network.Topology.Nodes {
		for j := range s.Network.Topology.Nodes[i].Services {
			svc := &s.Network.Topology.Nodes[i].Services[j]
			if svc.Type == ServiceDNS {
				for k := range svc.Records {
					if svc.Records[k].Name == labHost {
						svc.Records[k].Address = labTarget6
					}
				}
			}
		}
	}
	r, err = RunLab(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Views[0].Measured {
		switch c.ID {
		case "dns":
			if c.Status != "PASS" {
				t.Fatal("valid AAAA answer rejected as invalid DNS")
			}
		case "target_tcp":
			if c.Status != "FAIL" {
				t.Fatal("IPv4-only source delivered IPv6")
			}
		}
	}
}

func TestLabMeasuredAndReconciledEvidenceStaySeparate(t *testing.T) {
	for _, name := range []string{"reference-egress-unreachable", "ipv6-unavailable"} {
		s, _ := FindLabScenario(name)
		r, err := RunLab(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		changed := false
		for i, c := range r.Views[0].Measured {
			final := r.Views[0].Snapshot.Checks[i]
			if name == "reference-egress-unreachable" && c.ID == "internet_tcp" {
				changed = c.Status == "FAIL" && final.Status == "WARN"
			}
			if name == "ipv6-unavailable" && c.ID == "target_tcp" {
				changed = c.Observed.Families.IPv6 == d.FamilyUnreachable && final.Observed.Families.IPv6 == ""
			}
		}
		if !changed {
			t.Fatalf("lost measurement/reconciliation distinction in %s", name)
		}
	}
}

func TestLabHTTPTimeoutReachesProductionMTUCorrelation(t *testing.T) {
	s, _ := FindLabScenario("mtu-blackhole")
	s.Views[0].Target = "http://" + labHost
	s.Views[0].Expected = LabExpected{Verdict: d.VerdictNetwork, Required: []d.DiagnosisID{d.DiagnosisProbablePathMTU}, Checks: []ExpectedCheck{{ID: "target_tcp", Status: "PASS"}, {ID: "path_mtu", Status: "WARN"}, {ID: "http", Status: "FAIL"}}}
	s.Faults = append(s.Faults, LabFault{ID: "silent-http", Layer: "http", Scope: "target-http", HTTPNoResponse: "target-http"})
	r, err := RunLab(context.Background(), s)
	if err != nil || !r.Passed() {
		t.Fatalf("HTTP timeout lost at observation boundary: %v %+v", err, r.Problems)
	}
}

func TestLabIdentityAndOracleCannotChangeEvidence(t *testing.T) {
	s, _ := FindLabScenario("dns-resolver-unreachable")
	first, err := RunLab(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	s.Name = "healthy-ipv4"
	s.Faults[0].ID = "arbitrary-fault-name"
	s.Views[0].Expected = LabExpected{Verdict: d.VerdictOK}
	second, err := RunLab(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Views[0].Snapshot, second.Views[0].Snapshot) || !reflect.DeepEqual(first.Views[0].Measured, second.Views[0].Measured) {
		t.Fatal("scenario identity or oracle drove simulated evidence")
	}
	if second.Passed() {
		t.Fatal("incorrect oracle was treated as the result")
	}
}

func TestLabLeakAndIntentionalSplitHaveIdenticalObservableEvidence(t *testing.T) {
	intentional, _ := FindLabScenario("vpn-split-tunnel")
	leak, _ := FindLabScenario("vpn-dns-leak")
	a, err := RunLab(context.Background(), intentional)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RunLab(context.Background(), leak)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(a.Truth, b.Truth) {
		t.Fatal("missing independent policy difference")
	}
	if !reflect.DeepEqual(a.Views[0].Snapshot, b.Views[0].Snapshot) {
		t.Fatal("ground-truth policy entered observed evidence")
	}
	dnsIface, targetIface := "", ""
	for _, c := range a.Views[0].Snapshot.Checks {
		if c.Observed == nil {
			continue
		}
		switch c.ID {
		case "dns":
			dnsIface = c.Observed.Routes[0].Interface
		case "target_tcp":
			targetIface = c.Observed.Interface
		}
	}
	if dnsIface != "ethernet" || targetIface != "vpn" {
		t.Fatalf("lost visible path split: DNS=%s target=%s", dnsIface, targetIface)
	}
}

func TestLabAuditCounterexamples(t *testing.T) {
	t.Run("normalized zone keys", func(t *testing.T) {
		s := LabScenarios()[0]
		svc := &s.Network.Topology.Nodes[2].Services[0]
		svc.Records = nil
		svc.Zone = map[string]string{"APP.TEST.": labTarget4}
		m, err := s.compile()
		if err != nil {
			t.Fatal(err)
		}
		got := m.records(&m.scenario.Topology.Nodes[2].Services[0], labHost)
		if len(got) != 1 || got[0].String() != labTarget4 {
			t.Fatalf("valid DNS key lost: %v", got)
		}
	})
	t.Run("last default replacement wins", func(t *testing.T) {
		s := LabScenarios()[0]
		s.Faults = []LabFault{
			{ID: "first", Layer: "routing", Scope: "client", Network: &Fault{Type: FaultReplaceDefaultRoute, Node: "client", Family: "ipv4", Via: "10.20.1.254"}},
			{ID: "second", Layer: "routing", Scope: "client", Network: &Fault{Type: FaultReplaceDefaultRoute, Node: "client", Family: "ipv4", Via: "10.20.1.1"}},
		}
		m, err := s.compile()
		if err != nil {
			t.Fatal(err)
		}
		_, _, via, _, _ := m.route(m.scenario.Client(), labAddr(labTarget4), "")
		if via.String() != "10.20.1.1" {
			t.Fatalf("earlier replacement survived: %s", via)
		}
	})
	t.Run("configured IPv6 outage", func(t *testing.T) {
		s, _ := FindLabScenario("ipv6-unavailable")
		r, err := RunLab(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range r.Views[0].Measured {
			if c.ID == "internet_tcp" && (c.Status != "WARN" || c.Cause != d.FamilyCauseIPv6Unreachable) {
				t.Fatalf("native egress warning lost: %+v", c)
			}
		}
	})
	t.Run("borrowed support", func(t *testing.T) {
		s, _ := FindLabScenario("tls-certificate-mismatch")
		r, err := RunLab(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		snap := r.Views[0].Snapshot
		diagnosis, _ := d.ReplaySnapshot(snap)
		diagnosis.Findings[0].Evidence = []d.CausalEvidence{{Kind: d.EvidenceSupport, Check: d.ProbeDNS, Observation: d.ObservationDNSAnswers}}
		if len(ValidateLabDiagnosis(s.Views[0].Expected, snap, diagnosis)) == 0 {
			t.Fatal("TLS claim accepted with only healthy DNS support")
		}
	})
	t.Run("counterfactual outcome inversion", func(t *testing.T) {
		s, _ := FindLabScenario("dns-resolver-unreachable")
		r, err := RunLab(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		snap := r.Views[0].Snapshot
		diagnosis, _ := d.ReplaySnapshot(snap)
		for i := range diagnosis.Findings {
			if cf := diagnosis.Findings[i].Counterfactual; cf != nil {
				cf.Alternatives[0].Outcome = d.CounterfactualSucceeded
			}
		}
		if len(ValidateLabDiagnosis(s.Views[0].Expected, snap, diagnosis)) == 0 {
			t.Fatal("failed resolver mislabeled successful")
		}
	})
}

func labJSONEqual(a, b LabReport) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	return err == nil && string(x) == string(y)
}

func TestLabReferenceServiceObservations(t *testing.T) {
	t.Run("silent portal is not interception", func(t *testing.T) {
		s, _ := FindLabScenario("captive-portal")
		s.Faults = append(s.Faults, LabFault{ID: "silent-controls", Layer: "http", Scope: "reference-http", HTTPNoResponse: "reference-http"})
		r, err := RunLab(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range r.Views[0].Measured {
			if c.ID == "internet_tcp" && c.Observed.Portal != nil {
				t.Fatal("no HTTP response invented portal evidence")
			}
		}
	})
	t.Run("encrypted DNS must answer the query", func(t *testing.T) {
		s := LabScenarios()[0]
		for i := range s.Network.Topology.Nodes {
			for j := range s.Network.Topology.Nodes[i].Services {
				svc := &s.Network.Topology.Nodes[i].Services[j]
				if svc.Type == ServiceEncryptedDNS {
					svc.Records = nil
				}
			}
		}
		r, err := RunLab(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range r.Views[0].Measured {
			if c.ID == "dns_encrypted" && c.Status != "WARN" {
				t.Fatalf("mere connection counted as successful DNS: %s", c.Status)
			}
		}
	})
}

func TestLabReportOwnsTruthAndExpectations(t *testing.T) {
	s, _ := FindLabScenario("dns-resolver-unreachable")
	r, err := RunLab(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(r)
	s.Faults[0].Network.Port = 443
	s.Faults[0].ID = "changed-after-run"
	s.Views[0].Expected.Checks[0].Status = "PASS"
	after, _ := json.Marshal(r)
	if string(before) != string(after) {
		t.Fatal("authored state mutated a completed report")
	}
}

// Equal-shaped packets from distinct probes are different logical operations.
// They must not share the entire loss sequence merely because ordinal is zero.
func TestLabLossSeparatesProbeIdentities(t *testing.T) {
	s := LabScenarios()[0]
	s.Faults = []LabFault{{ID: "loss", Layer: "transport", Scope: "gateway", Network: &Fault{Type: FaultNetem, Node: "gateway", Segment: "uplink", Loss: "50%", Seed: 42}}}
	m, err := s.compile()
	if err != nil {
		t.Fatal(err)
	}
	different := false
	for i := range 100 {
		a := m.exchange("target_tcp", "client", labTarget4, "", "tcp", 443, 64, i)
		b := m.exchange("tls", "client", labTarget4, "", "tcp", 443, 64, i)
		different = different || a.Outcome != b.Outcome
		if !reflect.DeepEqual(a, m.exchange("target_tcp", "client", labTarget4, "", "tcp", 443, 64, i)) {
			t.Fatal("packet draw changed on replay")
		}
	}
	if !different {
		t.Fatal("unrelated probes share every packet loss decision")
	}
}

func TestLabPublicDNSNameScope(t *testing.T) {
	for _, input := range []string{"app.test.", "app.test", "printer"} {
		t.Run(input, func(t *testing.T) {
			scenario, _ := FindLabScenario("healthy-ipv4")
			scenario.Views[0].Target = "https://" + input
			report, err := RunLab(context.Background(), scenario)
			if err != nil {
				t.Fatal(err)
			}
			publicRows := 0
			for _, check := range report.Views[0].Snapshot.Checks {
				if check.ID != "dns_public" {
					continue
				}
				publicRows++
				_, want := d.PublicDNSQueryName(input)
				if check.Observed == nil {
					if input != "printer" || check.Status != "N/A" {
						t.Fatalf("missing observation: %+v", check)
					}
					continue
				}
				if check.Observed.DNSNameScope != want {
					t.Fatalf("scope=%q want %q", check.Observed.DNSNameScope, want)
				}
				if input == "printer" && (len(check.Observed.ResolverTargets) > 0 || check.Status != "N/A") {
					t.Fatalf("short public lookup: %+v", check)
				}
			}
			if publicRows != 1 {
				t.Fatalf("public DNS rows=%d, want 1", publicRows)
			}
		})
	}
}
