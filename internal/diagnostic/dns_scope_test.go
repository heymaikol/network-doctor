package diagnostic

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
)

func TestPublicDNSUnqualifiedNeverLooksUp(t *testing.T) {
	for _, input := range []string{"printer", "bücher"} {
		t.Run(input, func(t *testing.T) {
			target := mustTarget(t, input)
			calls := 0
			o := &netops{lookupPublicIP: func(context.Context, string, string) ([]net.IP, []string, error) {
				calls++
				return nil, nil, errNoDNSAllowed
			}}
			r := o.publicDNSProbe(target.Host, nil, PublicDNSCandidates(DefaultPublicDNS, true))(context.Background(), nil)
			if calls != 0 || r.Status != StatusNA || len(r.ResolverTargets) != 0 {
				t.Fatalf("unqualified public lookup: calls=%d result=%+v", calls, r)
			}
		})
	}
}

func TestUnknownDNSNameScopeCannotSupportComparisons(t *testing.T) {
	for _, input := range []string{"service.example", "service.example."} {
		t.Run(input, func(t *testing.T) {
			target := mustTarget(t, input+":8443")
			order := planOrder(t, target)
			systemIP, publicIP := net.ParseIP("192.0.2.7"), net.ParseIP("198.51.100.20")
			results := settle(t, target, order, map[ProbeID]ProbeResult{
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{systemIP}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{publicIP}},
				ProbeTargetTCP: {Status: StatusFail, Attempts: []Attempt{{IP: systemIP, Err: context.DeadlineExceeded, Cause: ConnectionCauseTimeout}}},
			})
			if results[ProbeDNSPublic].Status != StatusPass || results[ProbeDNSPublic].answerComparison != comparisonUnrecorded {
				t.Fatalf("unknown scope reconciled: %+v", results[ProbeDNSPublic])
			}
			if uncorroboratedEndpointFailure(results, ProbeTargetTCP, resolvedByTheSystemDNSRow) {
				t.Fatal("unknown scope supplied an endpoint alternative")
			}
			if finding, ok := dnsCounterfactual(target, results); ok {
				t.Fatalf("unknown scope supplied DNS counterfactual: %+v", finding)
			}
		})
	}
}

func TestPublicDNSNamePolicy(t *testing.T) {
	for _, tc := range []struct {
		input, query string
		scope        snapshot.DNSNameScope
	}{
		{"printer", "", ""}, {"bücher", "", ""},
		{"printer.", "printer.", snapshot.DNSNameAbsolute},
		{"server.internal", "server.internal.", snapshot.DNSNameRootedRelative},
		{"server.internal.", "server.internal.", snapshot.DNSNameAbsolute},
		{"bücher.example", "xn--bcher-kva.example.", snapshot.DNSNameRootedRelative},
		{"bücher.example.", "xn--bcher-kva.example.", snapshot.DNSNameAbsolute},
		{ConnectivityProbeHost, ConnectivityProbeHost + ".", snapshot.DNSNameRootedRelative},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + ".", snapshot.DNSNameRootedRelative},
	} {
		t.Run(tc.input, func(t *testing.T) {
			target := mustTarget(t, tc.input)
			query, scope := PublicDNSQueryName(target.Host)
			if query != tc.query || scope != tc.scope {
				t.Fatalf("query=%q scope=%q", query, scope)
			}
		})
	}
}

func TestDNSNameScopeDiagnosisAndReplay(t *testing.T) {
	for _, scope := range []snapshot.DNSNameScope{"", snapshot.DNSNameRootedRelative, snapshot.DNSNameAbsolute} {
		for _, negative := range []bool{false, true} {
			for _, generic := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/negative=%t/generic=%t", scope, negative, generic), func(t *testing.T) {
					var target *Target
					if !generic {
						target = mustTarget(t, "service.example.:8443")
					}
					order := planOrder(t, target)
					systemIP, publicIP := net.ParseIP("192.0.2.7"), net.ParseIP("198.51.100.20")
					system := ProbeResult{Status: StatusPass, Addrs: []net.IP{systemIP}}
					public := ProbeResult{Status: StatusPass, Addrs: []net.IP{publicIP}, DNSNameScope: scope}
					if negative {
						system = ProbeResult{Status: StatusFail, DNSNotFound: true}
						public.Addrs = nil
						public.DNSNotFound = true
					}
					res := settle(t, target, order, map[ProbeID]ProbeResult{
						ProbeDNS: system, ProbeDNSPublic: public,
						ProbeTargetTCP: {Status: StatusFail, Attempts: []Attempt{{IP: systemIP, Err: context.DeadlineExceeded, Cause: ConnectionCauseTimeout}}},
						ProbeQUIC:      {Status: StatusFail, Attempts: []Attempt{{IP: systemIP, Err: context.DeadlineExceeded, Cause: ConnectionCauseTimeout}}},
					})
					comparable := scope == snapshot.DNSNameAbsolute
					if dnsNamesComparable(res) != comparable {
						t.Fatal("wrong comparison scope")
					}
					if _, ok := dnsCounterfactual(target, res); ok != comparable {
						t.Fatalf("counterfactual=%t", ok)
					}
					failedProbe := ProbeTargetTCP
					if generic {
						failedProbe = ProbeQUIC
					}
					if !negative && uncorroboratedEndpointFailure(res, failedProbe, resolvedByTheSystemDNSRow) != comparable {
						t.Fatal("wrong endpoint alternative")
					}
					probes := make([]Probe, len(order))
					for i, id := range order {
						probes[i] = Probe{ID: id, Name: string(id)}
					}
					for _, sanitize := range []bool{false, true} {
						artifact := BuildSnapshot(target, probes, timedResults(res))
						if sanitize {
							artifact = snapshot.SanitizeForSupport(artifact)
						}
						// This test leaves legacy inference to its dedicated table below.
						if scope == "" && !sanitize && target != nil {
							artifact.Target.Host = "service.example"
						}
						data, err := snapshot.Encode(withSnapshotProvenance(artifact))
						if err != nil {
							t.Fatal(err)
						}
						decoded, err := snapshot.Decode(data)
						if err != nil {
							t.Fatal(err)
						}
						got, err := ReplaySnapshot(decoded)
						if err != nil {
							t.Fatal(err)
						}
						for _, id := range []DiagnosisID{DiagnosisDNSDisagreement, DiagnosisDNSNameNotFound, DiagnosisUncorroboratedEndpointFailure} {
							if _, ok := findingByID(got, id); ok && !comparable {
								t.Fatalf("unsupported replay finding %s: %+v", id, got)
							}
						}
						if comparable {
							assertDiagnosisSemantics(t, got, Interpret(target, order, res))
						}
					}
				})
			}
		}
	}
}

func TestLegacyDNSNameScopeReplay(t *testing.T) {
	for _, input := range []string{"service.example", "service.example."} {
		for _, sanitize := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/sanitize=%t", input, sanitize), func(t *testing.T) {
				target := mustTarget(t, input+":8443")
				order := planOrder(t, target)
				systemIP, publicIP := net.ParseIP("192.0.2.7"), net.ParseIP("198.51.100.20")
				res := settle(t, target, order, map[ProbeID]ProbeResult{
					ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{systemIP}},
					ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{publicIP}, DNSNameScope: snapshot.DNSNameAbsolute},
					ProbeTargetTCP: {Status: StatusFail, Attempts: []Attempt{{IP: systemIP, Err: context.DeadlineExceeded, Cause: ConnectionCauseTimeout}}},
				})
				probes := make([]Probe, len(order))
				for i, id := range order {
					probes[i] = Probe{ID: id, Name: string(id)}
				}
				artifact := BuildSnapshot(target, probes, timedResults(res))
				for i := range artifact.Checks {
					if artifact.Checks[i].ID == string(ProbeDNSPublic) {
						artifact.Checks[i].Observed.DNSNameScope = ""
					}
				}
				if sanitize {
					artifact = snapshot.SanitizeForSupport(artifact)
				}
				got, err := ReplaySnapshot(artifact)
				if err != nil {
					t.Fatal(err)
				}
				comparable := strings.HasSuffix(input, ".") && !sanitize
				for _, id := range []DiagnosisID{DiagnosisDNSDisagreement, DiagnosisUncorroboratedEndpointFailure} {
					_, found := findingByID(got, id)
					if found != comparable {
						t.Fatalf("finding %s=%t want %t: %+v", id, found, comparable, got)
					}
				}
				// Replay consumes typed evidence and never changes the stored historical rows.
				for _, check := range artifact.Checks {
					if check.ID == string(ProbeDNSPublic) && (check.Status != "WARN" || len(check.Observed.Addresses) != 1 || check.Observed.DNSNameScope != "") {
						t.Fatal("replay changed historical evidence")
					}
				}
			})
		}
	}
}

func TestWatchPublicDNSNamePolicy(t *testing.T) {
	for _, input := range []string{"", "service.example.", "service.example", "printer"} {
		t.Run(input, func(t *testing.T) {
			var target *Target
			host := ConnectivityProbeHost
			if input != "" {
				target = mustTarget(t, input)
				host = target.Host
			}
			n := newWatchNet()
			calls := 0
			ops := &netops{lookupPublicIP: func(context.Context, string, string) ([]net.IP, []string, error) {
				calls++
				return []net.IP{n.addr}, []string{"8.8.8.8:53"}, nil
			}}
			base := ProbePlan(target, DefaultPublicDNS, true)
			for i := range base {
				id := base[i].ID
				base[i].Run = func(context.Context, map[ProbeID]ProbeResult) ProbeResult { return n.result(id) }
				if id == ProbeDNSPublic {
					base[i].Run = ops.publicDNSProbe(host, nil, PublicDNSCandidates(DefaultPublicDNS, true))
				}
			}
			clock := newWatchClock()
			session := NewWatchSession(clock.Now)
			defer session.Close()
			for pass := 1; pass <= 2; pass++ {
				p := session.Begin(base, time.Second)
				results := RunAll(context.Background(), p.Probes(), time.Second)
				_ = p.Publish(results)
				got := results[ProbeDNSPublic]
				_, want := PublicDNSQueryName(host)
				if got.DNSNameScope != want {
					t.Fatalf("pass %d scope=%q want %q", pass, got.DNSNameScope, want)
				}
				wantCalls := pass
				if input == "printer" {
					wantCalls = 0
					if got.Status != StatusNA {
						t.Fatal("short name must be N/A")
					}
				}
				if calls != wantCalls {
					t.Fatalf("lookup calls=%d want %d", calls, wantCalls)
				}
				if _, reused := got.ReusedFrom(); reused {
					t.Fatal("public name scope reused")
				}
				clock.Advance(5 * time.Second)
			}
		})
	}
}
