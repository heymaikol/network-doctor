package diagnostic

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
)

// Keep DepsState as an independent semantic oracle, including waiting for all
// parents before skipping. The scheduler must not infer readiness from only
// the first blocking result.
func TestProbeSchedulerDependencies(t *testing.T) {
	for _, status := range []Status{StatusPass, StatusWarn, StatusNA, StatusFail, StatusSkip} {
		for _, reversed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reversed=%v", status, reversed), func(t *testing.T) {
				probes := []Probe{
					{ID: "root"}, {ID: "other"},
					{ID: "left", Deps: []ProbeID{"root"}},
					{ID: "right", Deps: []ProbeID{"root"}},
					{ID: "join", Deps: []ProbeID{"left", "right", "other"}},
					{ID: "tail", Deps: []ProbeID{"join"}},
				}
				if reversed {
					slices.Reverse(probes)
				}
				started := map[ProbeID]bool{}
				results := map[ProbeID]ProbeResult{}
				s := NewProbeScheduler(probes, started, nil)
				var pending []Probe
				drain := func() {
					for {
						i, blocked, ok := s.Next()
						if !ok {
							break
						}
						p := probes[i]
						ready, wantBlocked := DepsState(p.Deps, results)
						if !ready || blocked != wantBlocked {
							t.Fatalf("%s ready=%v blocked=%v, want %v", p.ID, ready, blocked, wantBlocked)
						}
						if blocked {
							r := SkipPrereq(p.ID)
							results[p.ID] = r
							s.Complete(r)
						} else {
							pending = append(pending, p)
						}
					}
				}
				drain()
				if len(pending) != 2 {
					t.Fatalf("roots=%d, want 2", len(pending))
				}
				// Root finishes first, with the independent parent still in flight.
				root := slices.IndexFunc(pending, func(p Probe) bool { return p.ID == "root" })
				pending = slices.Delete(pending, root, root+1)
				r := ProbeResult{ID: "root", Status: status}
				results[r.ID] = r
				s.Complete(r)
				s.Complete(r)
				drain()
				if _, ok := results["join"]; ok {
					t.Fatal("join skipped before every parent completed")
				}
				for len(pending) > 0 {
					i := len(pending) - 1
					p := pending[i]
					pending = pending[:i]
					r := ProbeResult{ID: p.ID, Status: StatusPass}
					results[p.ID] = r
					s.Complete(r)
					drain()
				}
				if len(results) != len(probes) || len(started) != len(probes) {
					t.Fatalf("results/started=%d/%d", len(results), len(started))
				}
				for _, p := range probes {
					want := StatusPass
					if p.ID == "root" {
						want = status
					} else if p.ID != "other" && (status == StatusFail || status == StatusSkip) {
						want = StatusSkip
					}
					if results[p.ID].Status != want {
						t.Errorf("%s=%v, want %v", p.ID, results[p.ID].Status, want)
					}
				}
				if s.head != len(probes) || len(s.ready) != len(probes) {
					t.Fatal("queue did not visit each probe exactly once")
				}
			})
		}
	}
}

func TestProbeSchedulerResumesAndIsolatesResults(t *testing.T) {
	probes := []Probe{{ID: "done"}, {ID: "inflight"}, {ID: "child", Deps: []ProbeID{"done", "inflight"}}}
	started := map[ProbeID]bool{"done": true, "inflight": true}
	results := map[ProbeID]ProbeResult{"done": {ID: "done", Status: StatusWarn}}
	s := NewProbeScheduler(probes, started, results)
	if _, _, ok := s.Next(); ok {
		t.Fatal("dispatched already-started probe")
	}
	results["done"] = ProbeResult{ID: "done", Status: StatusFail}
	s.Complete(ProbeResult{ID: "inflight", Status: StatusNA})
	i, blocked, ok := s.Next()
	if !ok || blocked || probes[i].ID != "child" {
		t.Fatalf("next=%d/%v/%v", i, blocked, ok)
	}
	s.Complete(ProbeResult{ID: "inflight", Status: StatusFail})
	if _, _, ok := s.Next(); ok {
		t.Fatal("duplicate completion dispatched child twice")
	}
}

// Roots, fan-out/fan-in, and reversed skip chains pin the queue's work: each
// node is queued and consumed once, and the reverse index holds each edge once.
func TestProbeSchedulerWide(t *testing.T) {
	for _, n := range []int{10, 100, 1000} {
		for _, shape := range []string{"roots", "wide", "skip chain"} {
			t.Run(fmt.Sprintf("%s/%d", shape, n), func(t *testing.T) {
				probes := schedulerGraph(n, shape)
				s := NewProbeScheduler(probes, nil, nil)
				edges := 0
				for _, p := range probes {
					edges += len(p.Deps)
				}
				indexed := 0
				for _, dependents := range s.dependents {
					indexed += len(dependents)
				}
				if indexed != edges {
					t.Fatalf("indexed edges=%d, want %d", indexed, edges)
				}
				visited := map[ProbeID]bool{}
				for {
					i, blocked, ok := s.Next()
					if !ok {
						break
					}
					id := probes[i].ID
					if visited[id] {
						t.Fatalf("duplicate dispatch %s", id)
					}
					visited[id] = true
					status := StatusPass
					if shape == "skip chain" {
						status = StatusSkip
						if id != "0" && !blocked {
							t.Fatalf("%s did not inherit skip", id)
						}
					}
					s.Complete(ProbeResult{ID: id, Status: status})
				}
				if len(visited) != n || s.head != n || len(s.ready) != n {
					t.Fatalf("visited/head/queued=%d/%d/%d, want %d", len(visited), s.head, len(s.ready), n)
				}
				if !reflect.DeepEqual(s.remaining, make([]int, n)) {
					t.Fatal("unresolved dependency counts remain")
				}
				t.Logf("P=%d E=%d initialized=%d queued=%d consumed=%d", n, edges, len(s.remaining), len(s.ready), s.head)
			})
		}
	}
}

func schedulerGraph(n int, shape string) []Probe {
	probes := make([]Probe, n)
	for i := range probes {
		probes[i].ID = ProbeID(fmt.Sprint(i))
		switch shape {
		case "wide":
			if i == n-1 {
				for j := 1; j < i; j++ {
					probes[i].Deps = append(probes[i].Deps, ProbeID(fmt.Sprint(j)))
				}
			} else if i > 0 {
				probes[i].Deps = []ProbeID{"0"}
			}
		case "skip chain":
			if i > 0 {
				probes[i].Deps = []ProbeID{ProbeID(fmt.Sprint(i - 1))}
			}
		}
	}
	if shape == "skip chain" {
		slices.Reverse(probes)
	}
	return probes
}

func BenchmarkProbeScheduler(b *testing.B) {
	for _, n := range []int{100, 1000} {
		for _, shape := range []string{"roots", "wide", "skip chain"} {
			b.Run(fmt.Sprintf("%s/%d", shape, n), func(b *testing.B) {
				probes := schedulerGraph(n, shape)
				b.ReportAllocs()
				for b.Loop() {
					s := NewProbeScheduler(probes, nil, nil)
					for {
						i, _, ok := s.Next()
						if !ok {
							break
						}
						s.Complete(ProbeResult{ID: probes[i].ID, Status: StatusPass})
					}
				}
			})
		}
	}
}
