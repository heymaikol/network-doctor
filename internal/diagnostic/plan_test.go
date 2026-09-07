package diagnostic

import (
	"context"
	"net"
	"reflect"
	"testing"
)

func TestProbePlanHasProductionMetadataAndNoExecutableBodies(t *testing.T) {
	for _, raw := range []string{"", "app.test:9999", "https://app.test", "http://app.test", "app.test:22", "app.test:25", "1.1.1.1:443", "[2001:db8::1]:443"} {
		var target *Target
		if raw != "" {
			var err error
			target, err = ParseTarget(raw)
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, public := range []string{"", DefaultPublicDNS} {
			for _, auto := range []bool{false, true} {
				production := BuildProbesFromSources(target, nil, public, auto)
				// Construction must not even consult the host operations table.
				saved := defaultOps
				defaultOps = nil
				plan := ProbePlan(target, public, auto)
				defaultOps = saved
				for i := range production {
					production[i].Run = nil
				}
				if !reflect.DeepEqual(plan, production) {
					t.Fatalf("graph metadata differs for %q, public=%q, auto=%t", raw, public, auto)
				}
				for _, p := range plan {
					if p.Run != nil {
						t.Fatalf("%s retained an executable probe", p.ID)
					}
				}
			}
		}
	}
}

// These setters must preserve the same private observation bits the live
// probes write. They must not perform classification, reconciliation or I/O.
func TestObservationSettersPreserveNativeRepresentation(t *testing.T) {
	for _, timedOut := range []bool{false, true} {
		native := ProbeResult{Status: StatusFail, Cause: FamilyCauseIPv6Unreachable, causeFamily: "ipv6", timedOut: timedOut}
		modeled := ProbeResult{Status: StatusFail}
		modeled.SetFailureCause(FamilyCauseIPv6Unreachable, "ipv6")
		modeled.SetProtocolTimeout(timedOut)
		if !reflect.DeepEqual(native, modeled) {
			t.Fatal("setter changed observation representation")
		}
	}
}

// Test-only bridge: external package conformance tests can exercise live probe
// classification over stubbed operations without exporting netops to production.
func NativeLabControlsForTest(dual, failIPv6, portal, dnsTimeout bool) map[ProbeID]ProbeResult {
	sources := &SourceAddresses{IPv4: net.ParseIP("10.20.1.10"), Iface: "ethernet"}
	if dual {
		sources.IPv6 = net.ParseIP("2001:db8:20:1::a")
	}
	o := &netops{sources: sources,
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		dialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			if failIPv6 && net.ParseIP(host).To4() == nil {
				return nil, context.DeadlineExceeded
			}
			return fakeConn{local: &net.TCPAddr{IP: sources.IPv4, Port: 40000}}, nil
		},
		portalCheck: func(_ context.Context, _ portalEndpoint) (portalObservation, error) {
			if portal {
				return portalObservation{code: 302, redirect: "http://portal.test/signin"}, nil
			}
			return portalObservation{clean: true}, nil
		},
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			if dnsTimeout {
				return nil, []string{"10.20.1.53:53"}, &net.DNSError{IsTimeout: true, Err: "timeout"}
			}
			ips := []net.IP{net.ParseIP("93.184.216.34")}
			if dual {
				ips = append(ips, net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"))
			}
			return ips, []string{"10.20.1.53:53"}, nil
		},
	}
	return map[ProbeID]ProbeResult{ProbeInternet: o.internetProbe(context.Background(), nil), ProbeDNS: o.dnsProbe("app.test", nil)(context.Background(), nil)}
}
