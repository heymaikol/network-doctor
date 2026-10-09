package diagnostic

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"
)

func findingByID(d Diagnosis, id DiagnosisID) (DiagnosisFinding, bool) {
	for _, finding := range d.Findings {
		if finding.ID == id {
			return finding, true
		}
	}
	return DiagnosisFinding{}, false
}

func TestDNSCounterfactualTruthTable(t *testing.T) {
	v4a := net.ParseIP("192.0.2.1")
	v4b := net.ParseIP("198.51.100.1")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic}
	base := func() map[ProbeID]ProbeResult {
		return map[ProbeID]ProbeResult{
			ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass),
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{v4a}},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{v4a}},
		}
	}
	tests := []struct {
		name string
		set  func(map[ProbeID]ProbeResult)
		id   DiagnosisID
		cf   bool
	}{
		{"system fails and independent succeeds", func(r map[ProbeID]ProbeResult) {
			r[ProbeDNS] = ProbeResult{Status: StatusFail, Cause: DNSCauseTimeout}
		}, DiagnosisSystemDNSFailure, true},
		{"both report not found", func(r map[ProbeID]ProbeResult) {
			r[ProbeDNS] = ProbeResult{Status: StatusFail, DNSNotFound: true}
			r[ProbeDNSPublic] = ProbeResult{Status: StatusPass, DNSNotFound: true}
		}, DiagnosisDNSNameNotFound, true},
		{"both fail without attribution", func(r map[ProbeID]ProbeResult) {
			r[ProbeDNS] = ProbeResult{Status: StatusFail, Cause: DNSCauseTimeout}
			r[ProbeDNSPublic] = ProbeResult{Status: StatusFail, Cause: DNSCauseTimeout}
		}, DiagnosisDNSFailure, false},
		{"different answer networks", func(r map[ProbeID]ProbeResult) {
			r[ProbeDNSPublic] = ProbeResult{Status: StatusWarn, Addrs: []net.IP{v4b}}
		}, DiagnosisDNSDisagreement, true},
		{"system answer and independent not found", func(r map[ProbeID]ProbeResult) {
			r[ProbeDNSPublic] = ProbeResult{Status: StatusWarn, DNSNotFound: true}
		}, DiagnosisDNSDisagreement, true},
		{"same answer network", func(map[ProbeID]ProbeResult) {}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := base()
			tt.set(res)
			d := Interpret(nil, order, res)
			if tt.id == "" {
				if _, ok := findingByID(d, DiagnosisDNSDisagreement); ok {
					t.Fatalf("agreeing resolvers produced a disagreement: %+v", d.Findings)
				}
				return
			}
			finding, ok := findingByID(d, tt.id)
			if !ok {
				t.Fatalf("findings = %+v, want %s", d.Findings, tt.id)
			}
			if (finding.Counterfactual != nil) != tt.cf {
				t.Fatalf("counterfactual = %+v, want present %t", finding.Counterfactual, tt.cf)
			}
			if tt.cf && (finding.Counterfactual.Variable != CounterfactualDNSResolver || len(finding.Counterfactual.Alternatives) != 2) {
				t.Errorf("counterfactual = %+v", finding.Counterfactual)
			}
		})
	}
}

func TestTargetFamilyCounterfactualTruthTable(t *testing.T) {
	v4, v6 := net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoNone}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}
	base := func() map[ProbeID]ProbeResult {
		return map[ProbeID]ProbeResult{
			ProbeIface:    ok(StatusPass),
			ProbeInternet: {Status: StatusPass, Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyReachable}},
			ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{v4, v6}},
			ProbeTargetTCP: {Status: StatusPass, SelectedIP: v4,
				Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyReachable},
				Attempts: []Attempt{{IP: v4}, {IP: v6}}},
		}
	}
	tests := []struct {
		name string
		set  func(map[ProbeID]ProbeResult)
		id   DiagnosisID
	}{
		{"IPv4 succeeds IPv6 fails", func(r map[ProbeID]ProbeResult) {
			r[ProbeTargetTCP] = ProbeResult{Status: StatusWarn, SelectedIP: v4,
				Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyUnreachable}}
		}, DiagnosisIPv6TargetUnreachable},
		{"IPv6 succeeds IPv4 fails", func(r map[ProbeID]ProbeResult) {
			r[ProbeTargetTCP] = ProbeResult{Status: StatusWarn, SelectedIP: v6,
				Families: &FamilyConnectivity{IPv4: FamilyUnreachable, IPv6: FamilyReachable}}
		}, DiagnosisIPv4TargetUnreachable},
		{"dual stack healthy", func(map[ProbeID]ProbeResult) {}, ""},
		{"IPv4 only target", func(r map[ProbeID]ProbeResult) {
			r[ProbeDNS] = ProbeResult{Status: StatusPass, Addrs: []net.IP{v4}}
			r[ProbeTargetTCP] = ProbeResult{Status: StatusPass, SelectedIP: v4, Families: &FamilyConnectivity{IPv4: FamilyReachable}}
		}, ""},
		{"IPv6 only target", func(r map[ProbeID]ProbeResult) {
			r[ProbeDNS] = ProbeResult{Status: StatusPass, Addrs: []net.IP{v6}}
			r[ProbeTargetTCP] = ProbeResult{Status: StatusPass, SelectedIP: v6, Families: &FamilyConnectivity{IPv6: FamilyReachable}}
		}, ""},
		{"host has no usable IPv6 path", func(r map[ProbeID]ProbeResult) {
			r[ProbeInternet] = ProbeResult{Status: StatusPass, Families: &FamilyConnectivity{IPv4: FamilyReachable}}
			r[ProbeTargetTCP] = ProbeResult{Status: StatusPass, SelectedIP: v4,
				Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyUnreachable},
				Attempts: []Attempt{{IP: v6, Err: errors.New("unreachable"), Cause: ConnectionCauseUnreachable}, {IP: v4}}}
		}, ""},
		{"both families fail", func(r map[ProbeID]ProbeResult) {
			r[ProbeTargetTCP] = ProbeResult{Status: StatusFail,
				Families: &FamilyConnectivity{IPv4: FamilyUnreachable, IPv6: FamilyUnreachable}}
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := base()
			tt.set(res)
			d := Interpret(target, order, res)
			if tt.id == "" {
				for _, id := range []DiagnosisID{DiagnosisIPv4TargetUnreachable, DiagnosisIPv6TargetUnreachable} {
					if _, ok := findingByID(d, id); ok {
						t.Fatalf("findings = %+v, did not want %s", d.Findings, id)
					}
				}
				return
			}
			finding, ok := findingByID(d, tt.id)
			if !ok || finding.Counterfactual == nil || finding.Counterfactual.Variable != CounterfactualAddressFamily {
				t.Fatalf("findings = %+v, want family counterfactual %s", d.Findings, tt.id)
			}
			if !slices.Contains(finding.Evidence, CausalEvidence{Kind: EvidenceSupport, Check: ProbeInternet,
				Observation: ObservationFamilyReachable, Value: map[DiagnosisID]string{
					DiagnosisIPv4TargetUnreachable: "ipv4", DiagnosisIPv6TargetUnreachable: "ipv6",
				}[tt.id]}) {
				t.Errorf("family finding does not cite independent path evidence: %+v", finding.Evidence)
			}
		})
	}
}

func TestTargetTCPProbeObservesBothFamiliesIndependently(t *testing.T) {
	v4, v6 := net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")
	ops := &netops{
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			if network == "tcp4" {
				return fakeConn{local: &net.TCPAddr{IP: net.ParseIP("192.0.2.20")}}, nil
			}
			return nil, errors.New("IPv6 unreachable")
		},
		interfaces: func() ([]net.Interface, error) { return nil, nil },
	}
	r := ops.targetTCPProbe(443, nil)(context.Background(), map[ProbeID]ProbeResult{
		ProbeDNS: {Addrs: []net.IP{v4, v6}},
	})
	if r.Status != StatusPass || r.Families == nil || r.Families.IPv4 != FamilyReachable || r.Families.IPv6 != FamilyUnreachable {
		t.Fatalf("result = %+v, want IPv4 reachable and IPv6 failed before reconciliation", r)
	}
	if len(r.Attempts) != 2 || !slices.ContainsFunc(r.Attempts, func(a Attempt) bool { return a.IP.Equal(v4) && a.Err == nil }) ||
		!slices.ContainsFunc(r.Attempts, func(a Attempt) bool { return a.IP.Equal(v6) && a.Err != nil }) {
		t.Errorf("attempts = %+v, want one actual attempt per family", r.Attempts)
	}
}

func TestTargetTCPProbeSelectsTheFasterWorkingFamily(t *testing.T) {
	v4, v6 := net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")
	ops := &netops{
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			if network == "tcp6" {
				time.Sleep(20 * time.Millisecond)
			}
			return fakeConn{local: &net.TCPAddr{IP: net.ParseIP("192.0.2.20")}}, nil
		},
		interfaces: func() ([]net.Interface, error) { return nil, nil },
	}
	r := ops.targetTCPProbe(443, nil)(context.Background(), map[ProbeID]ProbeResult{
		ProbeDNS: {Addrs: []net.IP{v4, v6}},
	})
	if r.Status != StatusPass || !r.SelectedIP.Equal(v4) || r.Families == nil ||
		r.Families.IPv4 != FamilyReachable || r.Families.IPv6 != FamilyReachable {
		t.Fatalf("result = %+v, want faster IPv4 selected and both families reachable", r)
	}
}

func TestResolvedAddressCounterfactualTruthTable(t *testing.T) {
	a, b, c := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.3")
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoNone}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}
	failure := func(ip net.IP) Attempt {
		return Attempt{IP: ip, Err: errors.New("unreachable"), Cause: ConnectionCauseUnreachable}
	}
	base := func(addrs []net.IP, selected net.IP, attempts []Attempt) map[ProbeID]ProbeResult {
		return map[ProbeID]ProbeResult{
			ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass),
			ProbeDNS: {Status: StatusPass, Addrs: addrs},
			ProbeTargetTCP: {Status: StatusWarn, SelectedIP: selected,
				Families: &FamilyConnectivity{IPv4: FamilyReachable}, Attempts: attempts},
		}
	}
	tests := []struct {
		name string
		res  map[ProbeID]ProbeResult
		want bool
	}{
		{"first fails second succeeds", base([]net.IP{a, b}, b, []Attempt{failure(a), {IP: b}}), true},
		{"second fails first succeeds", base([]net.IP{a, b}, a, []Attempt{failure(b), {IP: a}}), true},
		{"multiple fail then success", base([]net.IP{a, b, c}, c, []Attempt{failure(a), failure(b), {IP: c}}), true},
		{"all fail", base([]net.IP{a, b}, nil, []Attempt{failure(a), failure(b)}), false},
		{"single address healthy", base([]net.IP{a}, a, []Attempt{{IP: a}}), false},
		{"resolved but unattempted", base([]net.IP{a, b}, a, []Attempt{{IP: a}}), false},
		{"canceled loser", base([]net.IP{a, b}, b, []Attempt{{IP: a, Err: context.Canceled, Cause: ConnectionCauseCanceled}, {IP: b}}), false},
		{"global timeout loser", base([]net.IP{a, b}, b, []Attempt{{IP: a, Err: context.DeadlineExceeded, Cause: ConnectionCauseTimeout, Aborted: true}, {IP: b}}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Interpret(target, order, tt.res)
			finding, ok := findingByID(d, DiagnosisPartialReachability)
			if ok != tt.want {
				t.Fatalf("partial finding present = %t, want %t: %+v", ok, tt.want, d.Findings)
			}
			if ok && (finding.Counterfactual == nil || finding.Counterfactual.Variable != CounterfactualResolvedAddress) {
				t.Errorf("counterfactual = %+v", finding.Counterfactual)
			}
			if ok && !slices.ContainsFunc(finding.Evidence, func(e CausalEvidence) bool {
				return e.Check == ProbeDNS && e.Observation == ObservationDNSAnswers && e.Value != ""
			}) {
				t.Errorf("partial finding does not cite exact DNS answer: %+v", finding.Evidence)
			}
		})
	}
}

func TestCounterfactualEvidenceIsDeterministicAndReferencesObservedRows(t *testing.T) {
	c := matrixCaseNamed(t, "one target address fails before another succeeds")
	want := Interpret(c.target, c.order, c.res).Findings
	for range 20 {
		got := Interpret(c.target, c.order, c.res).Findings
		if !slices.EqualFunc(got, want, func(a, b DiagnosisFinding) bool { return a.ID == b.ID && slices.Equal(a.Evidence, b.Evidence) }) {
			t.Fatalf("findings changed: %+v, want %+v", got, want)
		}
	}
}

func TestProvedFamilyFailureIsNotAlsoASickBackendAddress(t *testing.T) {
	v4, v6 := net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoNone}
	res := map[ProbeID]ProbeResult{
		ProbeIface: ok(StatusPass),
		ProbeInternet: {Status: StatusPass,
			Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyReachable}},
		ProbeDNS: {Status: StatusPass, Addrs: []net.IP{v4, v6}},
		ProbeTargetTCP: {Status: StatusWarn, SelectedIP: v4,
			Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyUnreachable},
			Attempts: []Attempt{
				{IP: v6, Err: errors.New("unreachable"), Cause: ConnectionCauseUnreachable},
				{IP: v4},
			}},
	}
	d := Interpret(target, []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}, res)
	if _, found := findingByID(d, DiagnosisIPv6TargetUnreachable); !found {
		t.Fatalf("findings = %+v, want the IPv6 family finding", d.Findings)
	}
	if finding, found := findingByID(d, DiagnosisPartialReachability); found {
		t.Errorf("the down family also became a failed backend address: %+v", finding)
	}
}
