package diagnostic

import (
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var githubFixtureTargets = []string{"https://github.com", "https://api.github.com", "ssh://github.com:22", "ssh://ssh.github.com:443"}

func profileFixtureSelection(target *Target) ProbeSelection {
	checks := []ProbeID{ProbeInternet, ProbeProxy, ProbeDNSPublic, ProbePMTU, ProbeSSH}
	if target.Proto == ProtoTLSHTTP {
		checks = []ProbeID{ProbeInternet, ProbeProxy, ProbeDNSPublic, ProbePMTU, ProbeHTTP, ProbeHTTPS}
	}
	s := ProbeSelection{Check: map[ProbeID]struct{}{}}
	for _, id := range checks {
		s.Check[id] = struct{}{}
	}
	return s
}

// Replace native Run bodies before sharing, so counters measure actual work,
// rather than the component rows that still run their own schedulers.
func githubProbeFixture(t testing.TB, shared bool, counts *sync.Map, result func(int, ProbeID) ProbeResult) [][]Probe {
	t.Helper()
	var pass *ProfilePass
	if shared {
		pass = NewProfilePass(nil)
	}
	graphs := make([][]Probe, len(githubFixtureTargets))
	for component, raw := range githubFixtureTargets {
		target, err := ParseTarget(raw)
		if err != nil {
			t.Fatal(err)
		}
		var o *netops
		if shared {
			copyOps := pass.ops
			o = &copyOps
		} else {
			o = opsFromSources(nil)
		}
		probeOps(target, o)
		selection := profileFixtureSelection(target)
		probes := selection.Apply(o.timedProbes(target, DefaultPublicDNS, true, slices.Collect(maps.Keys(selection.Check))...))
		for i, p := range probes {
			counter, _ := counts.LoadOrStore(p.ID, new(atomic.Int64))
			probes[i].Run = func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
				counter.(*atomic.Int64).Add(1)
				if result != nil {
					return result(component, p.ID)
				}
				return ProbeResult{Status: StatusPass, Detail: "controlled observation"}
			}
		}
		if shared {
			pass.share(probes, o)
		}
		graphs[component] = probes
	}
	return graphs
}

func runProfileFixture(graphs [][]Probe) []map[ProbeID]ProbeResult {
	results := make([]map[ProbeID]ProbeResult, len(graphs))
	var wg sync.WaitGroup
	for i, probes := range graphs {
		wg.Go(func() { results[i] = RunAll(context.Background(), probes, DefaultProbeTimeout) })
	}
	wg.Wait()
	return results
}

func fixtureExecutionCount(counts *sync.Map) int64 {
	var total int64
	counts.Range(func(_, counter any) bool {
		total += counter.(*atomic.Int64).Load()
		return true
	})
	return total
}

func TestProfilePassGitHubExecutionCount(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared=%t", shared), func(t *testing.T) {
			var counts sync.Map
			graphs := githubProbeFixture(t, shared, &counts, nil)
			nodes := 0
			for _, probes := range graphs {
				nodes += len(probes)
			}
			if nodes != 36 {
				t.Fatalf("selected GitHub graph has %d nodes, want 36", nodes)
			}
			runProfileFixture(graphs)
			want := int64(36)
			sharedCount := int64(4)
			if shared {
				want, sharedCount = 27, 1
			}
			if got := fixtureExecutionCount(&counts); got != want {
				t.Fatalf("underlying executions = %d, want %d", got, want)
			}
			for _, id := range []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeDNSPublic, ProbeTargetTCP, ProbePMTU} {
				want := int64(4)
				if slices.Contains([]ProbeID{ProbeIface, ProbeInternet, ProbeProxy}, id) {
					want = sharedCount
				}
				counter, _ := counts.Load(id)
				if got := counter.(*atomic.Int64).Load(); got != want {
					t.Errorf("%s executions = %d, want %d", id, got, want)
				}
			}
		})
	}
}

func TestProfilePassMatchesIndependentDiagnosis(t *testing.T) {
	for _, observation := range []ProbeID{ProbeIface, ProbeInternet, ProbeProxy} {
		for _, status := range []Status{StatusPass, StatusWarn, StatusFail, StatusSkip, StatusNA} {
			t.Run(fmt.Sprintf("%s/%s", observation, status), func(t *testing.T) {
				fixture := func(component int, id ProbeID) ProbeResult {
					r := ProbeResult{Status: StatusPass, Detail: "controlled observation"}
					if id == observation {
						r.Status = status
					}
					if id == ProbeProxy && observation != ProbeProxy {
						r.Status = StatusNA
					}
					if id == ProbeDNS || id == ProbeDNSPublic {
						r.Addrs = []net.IP{net.ParseIP("140.82.112.3")}
					}
					if id == ProbeTargetTCP {
						r.SelectedIP = net.ParseIP("140.82.112.3")
						if component%2 == 1 {
							r.Status, r.Cause = StatusFail, ConnectionCauseRefused
						}
					}
					return r
				}
				var independentCounts, sharedCounts sync.Map
				independent := githubProbeFixture(t, false, &independentCounts, fixture)
				shared := githubProbeFixture(t, true, &sharedCounts, fixture)
				want, got := runProfileFixture(independent), runProfileFixture(shared)
				for i, raw := range githubFixtureTargets {
					if !reflect.DeepEqual(got[i], want[i]) {
						t.Errorf("%s results differ:\ngot %+v\nwant %+v", raw, got[i], want[i])
					}
					target, _ := ParseTarget(raw)
					order := make([]ProbeID, len(shared[i]))
					for j, p := range shared[i] {
						order[j] = p.ID
					}
					if actual, expected := Interpret(target, order, got[i]), Interpret(target, order, want[i]); !reflect.DeepEqual(actual, expected) {
						t.Errorf("%s diagnosis differs:\ngot %+v\nwant %+v", raw, actual, expected)
					}
					if observation == ProbeInternet && status == StatusFail {
						expected := StatusWarn
						if i%2 == 1 {
							expected = StatusFail
						}
						if got[i][ProbeInternet].Status != expected {
							t.Errorf("component %d shared raw failure finalized as %s, want %s", i, got[i][ProbeInternet].Status, expected)
						}
					}
				}
			})
		}
	}
}

func TestProfilePassClonesEveryMutableResultField(t *testing.T) {
	original := ProbeResult{
		Status: StatusWarn, Families: &FamilyConnectivity{IPv4: FamilyReachable}, Portal: &Portal{RedirectURL: "https://portal.invalid"},
		Addrs: []net.IP{net.ParseIP("192.0.2.1")}, SelectedIP: net.ParseIP("192.0.2.2"), Source: net.ParseIP("192.0.2.3"),
		ResolverTargets: []string{"192.0.2.53:53"}, Attempts: []Attempt{{IP: net.ParseIP("192.0.2.4")}},
		Routes:            []RouteDecision{{Destination: net.ParseIP("1.1.1.1"), Gateway: net.ParseIP("192.0.2.5"), Source: net.ParseIP("192.0.2.6"), Competing: []CompetingRoute{{Iface: "other"}}}},
		alternateDefaults: map[string][]defaultRouteState{"ipv4": {{gateway: net.ParseIP("192.0.2.7")}}},
	}
	var sample profileObservation
	p := Probe{ID: ProbeIface, Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult { return original }}
	first := sample.run(context.Background(), p, nil)
	want := sample.run(context.Background(), p, nil)
	mutate := func(r ProbeResult) {
		r.Families.IPv4 = "changed"
		r.Portal.RedirectURL = "changed"
		r.Addrs[0][0] ^= 1
		r.Addrs = append(r.Addrs, net.IPv4zero)
		r.SelectedIP[0] ^= 1
		r.Source[0] ^= 1
		r.ResolverTargets[0] = "changed"
		r.Attempts[0].IP[0] ^= 1
		r.Attempts[0].Cause = "changed"
		r.Routes[0].Destination[0] ^= 1
		r.Routes[0].Gateway[0] ^= 1
		r.Routes[0].Source[0] ^= 1
		r.Routes[0].Competing[0].Iface = "changed"
		r.alternateDefaults["ipv4"][0].gateway[0] ^= 1
		r.alternateDefaults["ipv4"][0].iface = "changed"
		r.alternateDefaults["ipv6"] = nil
	}
	for _, input := range []struct {
		name   string
		result ProbeResult
	}{{"producer", original}, {"component", first}} {
		mutate(input.result)
		if got := sample.run(context.Background(), p, nil); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s mutation changed retained observation:\ngot %+v\nwant %+v", input.name, got, want)
		}
	}
}

// A watchdog bounds deadlocked regressions, never measured probe performance.
func profileReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("profile worker did not finish")
		var zero T
		return zero
	}
}

func TestProfilePassWaiterCancellation(t *testing.T) {
	started, release, leaderDone := make(chan struct{}), make(chan struct{}), make(chan ProbeResult, 1)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	var sample profileObservation
	var count atomic.Int64
	p := Probe{ID: ProbeInternet, Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
		count.Add(1)
		close(started)
		<-release
		return ProbeResult{Status: StatusPass}
	}}
	go func() { leaderDone <- sample.run(context.Background(), p, nil) }()
	profileReceive(t, started)
	for _, deadline := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		want := ConnectionCauseCanceled
		if deadline {
			ctx, cancel = context.WithDeadline(context.Background(), time.Time{})
			want = ConnectionCauseTimeout
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		waiter := make(chan ProbeResult, 1)
		go func() { waiter <- sample.run(ctx, p, nil) }()
		r := profileReceive(t, waiter)
		cancel()
		if r.ID != p.ID || r.Status != StatusFail || r.Cause != want {
			t.Errorf("canceled waiter result = %+v, want failure %s", r, want)
		}
	}
	close(release)
	if r := profileReceive(t, leaderDone); r.Status != StatusPass {
		t.Errorf("waiter canceled the leader: %+v", r)
	}
	if r := sample.run(context.Background(), p, nil); r.Status != StatusPass || count.Load() != 1 {
		t.Errorf("waiter changed retained result or reran work: %+v, count %d", r, count.Load())
	}
}

func TestProfilePassLeaderCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	var sample profileObservation
	p := Probe{ID: ProbeIface, Run: func(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
		close(started)
		<-ctx.Done()
		return ProbeResult{Status: StatusFail, Cause: ConnectionCauseCanceled}
	}}
	leader := make(chan ProbeResult, 1)
	go func() { leader <- sample.run(ctx, p, nil) }()
	profileReceive(t, started)
	waiter := make(chan ProbeResult, 1)
	go func() { waiter <- sample.run(context.Background(), p, nil) }()
	cancel()
	if a, b := profileReceive(t, leader), profileReceive(t, waiter); a.Status != StatusFail || !reflect.DeepEqual(a, b) {
		t.Fatalf("leader cancellation did not release waiter with same failure: %+v / %+v", a, b)
	}
}

func BenchmarkProfilePassGitHub(b *testing.B) {
	for _, rounds := range []int{0, 2000} {
		for _, shared := range []bool{false, true} {
			b.Run(fmt.Sprintf("rounds=%d/shared=%t", rounds, shared), func(b *testing.B) {
				b.ReportAllocs()
				var counts sync.Map
				fixture := func(component int, id ProbeID) ProbeResult {
					digest := sha256.Sum256([]byte(id))
					for range rounds {
						digest = sha256.Sum256(digest[:])
					}
					return ProbeResult{Status: StatusPass, Detail: string(digest[:])}
				}
				for range b.N {
					runProfileFixture(githubProbeFixture(b, shared, &counts, fixture))
				}
				b.ReportMetric(float64(fixtureExecutionCount(&counts))/float64(b.N), "executions/pass")
			})
		}
	}
}
