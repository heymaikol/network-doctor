package diagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

func TestTwoSidedReconciledFailureIsNotCalledPassing(t *testing.T) {
	// The same direct failure occurs on both machines. A successful proxy on
	// B changes only its final status, exactly as downgradeEgress specifies.
	probes := []Probe{{ID: ProbeInternet}, {ID: ProbeProxy}}
	results := map[ProbeID]ProbeResult{
		ProbeInternet: {Status: StatusFail, Cause: RouteCauseSelectedPathFailed},
		ProbeProxy:    {Status: StatusNA},
	}
	Finalize(results)
	a := BuildSnapshot(nil, probes, results)
	results[ProbeProxy] = ProbeResult{Status: StatusPass}
	Finalize(results)
	b := BuildSnapshot(nil, probes, results)
	if b.Checks[0].Status != snapshot.StatusWarn || b.Checks[0].Derived == nil || !b.Checks[0].Derived.StatusDowngraded {
		t.Fatal("fixture did not downgrade")
	}
	got, err := compare.TwoSidedSnapshots(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Diagnosis.Side != compare.SideA || !got.Diagnosis.Ambiguous {
		t.Fatal(got.Diagnosis)
	}
	if strings.Contains(got.Diagnosis.Summary, "passes") || !strings.Contains(got.Diagnosis.Summary, "final FAIL") {
		t.Fatal(got.Diagnosis.Summary)
	}
	if !slices.ContainsFunc(got.Checks[0].Evidence, func(e compare.EvidenceComparison) bool {
		return e.Dimension == "derived.status_downgraded" && len(e.B) == 1 && e.Relation == "unknown"
	}) {
		t.Fatal("downgrade evidence lost")
	}
}

// These are production probe bodies with deterministic transport/OS answers,
// followed by the ordinary finalization and artifact boundary. No socket opens.
func TestTwoSidedProductionEvidence(t *testing.T) {
	target := &Target{Host: "evidence.test", Raw: "https://evidence.test", Port: 443, Proto: ProtoTLSHTTP}
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}
	tcp := func(addresses []net.IP, fail string, tunnel TunnelState) ProbeResult {
		o := &netops{interfaces: func() ([]net.Interface, error) { return nil, nil }}
		o.dialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			if network == "udp" {
				return nil, connectionRefusedErrno
			}
			host, _, _ := net.SplitHostPort(addr)
			if fail == "all refused" || fail == host {
				return nil, connectionRefusedErrno
			}
			if fail == "all timeout" {
				return nil, context.DeadlineExceeded
			}
			return fakeConn{local: &net.TCPAddr{IP: ips[0]}}, nil
		}
		o.routeFor = func(dst, _ net.IP) (RouteDecision, bool) {
			return RouteDecision{Destination: dst, Family: "ipv4", Iface: "link", Tunnel: tunnel}, true
		}
		o.routes = newRouteCache(o.routeFor, nil)
		ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
		defer cancel()
		return o.targetTCPProbe(443)(ctx, map[ProbeID]ProbeResult{ProbeDNS: {Addrs: addresses}})
	}
	tlsResult := func(err error) ProbeResult {
		o := &netops{dialTLS: func(context.Context, string, string, *tls.Config) (net.Conn, error) { return nil, err }}
		return o.tlsProbe(target.Host, target.Port)(context.Background(), map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: ips[0]}})
	}
	dns := func(err error) ProbeResult {
		o := &netops{lookupIP: func(context.Context, string) ([]net.IP, []string, error) { return nil, nil, err }}
		return o.dnsProbe(target.Host, nil)(context.Background(), nil)
	}
	familyCause := func(v4 bool) ProbeResult {
		o := &netops{interfaces: func() ([]net.Interface, error) { return nil, nil },
			dialContext: func(context.Context, string, string) (net.Conn, error) { return nil, connectionRefusedErrno },
			routeCause: func(ip net.IP) string {
				if (ip.To4() != nil) == v4 {
					return RouteCauseSelectedPathFailed
				}
				return ""
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
		defer cancel()
		return o.internetProbe(ctx, nil)
	}
	artifact := func(id ProbeID, r ProbeResult) snapshot.Snapshot {
		r.ID, r.Dur = id, time.Millisecond
		results := map[ProbeID]ProbeResult{id: r}
		probes := []Probe{{ID: id, Name: string(id)}}
		if id == ProbeTargetTCP || id == ProbeTLS {
			var addresses []net.IP
			for _, route := range r.Routes {
				addresses = append(addresses, route.Destination)
			}
			if id == ProbeTLS {
				addresses = ips[:1]
				results[ProbeTargetTCP] = tcp(addresses, "", TunnelDirect)
				probes = append([]Probe{{ID: ProbeTargetTCP, Deps: []ProbeID{ProbeDNS}}}, probes...)
			}
			results[ProbeDNS] = ProbeResult{Status: StatusPass, Addrs: addresses}
			probes = append([]Probe{{ID: ProbeDNS}}, probes...)
		}
		Finalize(results)
		s := BuildSnapshot(target, probes, timedResults(results))
		s.CreatedAt = "2000-01-01T00:00:00Z"
		data, err := snapshot.Encode(withSnapshotProvenance(s))
		if err != nil {
			t.Fatal(err)
		}
		s, err = snapshot.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReplaySnapshot(s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, tc := range []struct {
		name      string
		id        ProbeID
		a, b      ProbeResult
		dimension string
	}{
		{"timeout versus refusal", ProbeTargetTCP, tcp(ips[:1], "all timeout", TunnelDirect), tcp(ips[:1], "all refused", TunnelDirect), "attempt_outcomes"},
		{"same cause different endpoint", ProbeTargetTCP, tcp(ips[:1], "all refused", TunnelDirect), tcp(ips[1:], "all refused", TunnelDirect), "attempts"},
		{"different selected endpoint", ProbeTargetTCP, tcp(ips[:1], "", TunnelDirect), tcp(ips[1:], "", TunnelDirect), "selected_ip"},
		{"different partial failures", ProbeTargetTCP, tcp(ips, ips[0].String(), TunnelDirect), tcp([]net.IP{ips[0], net.ParseIP("192.0.2.3")}, ips[0].String(), TunnelDirect), "attempts"},
		{"direct versus tunnel", ProbeTargetTCP, tcp(ips[:1], "all refused", TunnelDirect), tcp(ips[:1], "all refused", TunnelKnown), "route_tunnel_states"},
		{"TLS identity versus timeout", ProbeTLS, tlsResult(x509.HostnameError{Certificate: &x509.Certificate{}, Host: target.Host}), tlsResult(context.DeadlineExceeded), "cause"},
		{"DNS timeout versus negative", ProbeDNS, dns(&net.DNSError{IsTimeout: true}), dns(&net.DNSError{IsNotFound: true}), "dns_outcome"},
		{"same cause different family", ProbeInternet, familyCause(true), familyCause(false), "cause_family"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := artifact(tc.id, tc.a), artifact(tc.id, tc.b)
			ac, bc := a.Checks[len(a.Checks)-1], b.Checks[len(b.Checks)-1]
			if ac.Status != bc.Status {
				t.Fatalf("not equal-status: %+v %+v", a.Checks, b.Checks)
			}
			base, err := compare.TwoSidedSnapshots(a, a)
			if err != nil {
				t.Fatal(err)
			}
			got, err := compare.TwoSidedSnapshots(a, b)
			if err != nil {
				t.Fatal(err)
			}
			row := got.Checks[len(got.Checks)-1]
			if !slices.ContainsFunc(row.Evidence, func(e compare.EvidenceComparison) bool {
				return e.Dimension == tc.dimension && e.Relation == "different"
			}) {
				t.Fatalf("lost %s: %+v", tc.dimension, row)
			}
			if !reflect.DeepEqual(base.Diagnosis, got.Diagnosis) {
				t.Fatal("observation divergence changed localization")
			}
		})
	}
}
