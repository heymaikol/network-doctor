package routepath

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
)

// blastFile is the file a blast run reads, built from observations.
func blastFile(t *testing.T, obs []netmodel.Observation) File {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	return File{Model: m}
}

// singleRun is the simulation from src alone, which a blast run must match.
func singleRun(t *testing.T, f File, src Start, fail Failure, extra ...netip.Addr) Simulation {
	t.Helper()
	f.Source = src
	s, err := Simulate(f, fail, extra...)
	if err != nil {
		t.Fatalf("Simulate from %s (%s): %v", src.Node, src.VRF, err)
	}
	return s
}

// unwalked is the rating of an affected destination: everything the source
// decides without its walk.
func unwalked(a Affected) Affected {
	a.After = nil
	return a
}

// assertSameRatings checks that a source in a blast run rates every destination
// as its own single-source run does. The shared listing may omit a walk the
// single run lists, and then the simulation must say it is truncated. It may
// never list a walk the single run omits.
func assertSameRatings(t *testing.T, got, want Simulation) {
	t.Helper()
	who := want.Source.Node + " (" + want.Source.VRF + ")"
	switch {
	case !reflect.DeepEqual(got.Failure, want.Failure), got.Source != want.Source,
		!reflect.DeepEqual(got.Adjacency, want.Adjacency), !reflect.DeepEqual(got.Gateway, want.Gateway):
		t.Fatalf("%s: failure, source, adjacency, or gateway differs from its single run", who)
	case got.Considered != want.Considered, got.Unchanged != want.Unchanged:
		t.Fatalf("%s: considered %d unchanged %d, single run %d and %d", who, got.Considered, got.Unchanged, want.Considered, want.Unchanged)
	case len(got.Affected) != len(want.Affected):
		t.Fatalf("%s: %d affected, single run has %d", who, len(got.Affected), len(want.Affected))
	case want.Truncated && !got.Truncated:
		t.Fatalf("%s: single run is truncated, blast run is not", who)
	}
	for i := range want.Affected {
		g, w := got.Affected[i], want.Affected[i]
		if !reflect.DeepEqual(unwalked(g), unwalked(w)) {
			t.Fatalf("%s: %s rated %+v, single run rates %+v", who, w.Destination, unwalked(g), unwalked(w))
		}
		switch {
		case g.After == nil && w.After != nil && !got.Truncated:
			t.Errorf("%s: %s walk omitted, but the simulation is not truncated", who, w.Destination)
		case g.After != nil && w.After == nil:
			t.Errorf("%s: %s walk listed, but its single run omits it", who, w.Destination)
		case g.After != nil && !reflect.DeepEqual(g.After, w.After):
			t.Errorf("%s: %s walk differs from its single run", who, w.Destination)
		}
	}
}

// blastLine is n routers, r00 to r(n-1), in a line. Each holds ten addresses on
// its lan and forwards 10.0.0.0/8 toward the next router, so a walk from r00
// reaches any address by crossing every router before it. The last router's
// FIB is empty, since it owns what is past the line.
func blastLine(n int) []netmodel.Observation {
	var obs []netmodel.Observation
	for i := range n {
		var lan []string
		for k := 1; k <= 10; k++ {
			lan = append(lan, fmt.Sprintf("10.99.%d.%d/24", i, k))
		}
		ifaces := []netmodel.Interface{ifc("lan", lan...)}
		var routes []netmodel.Route
		if i > 0 {
			ifaces = append(ifaces, ifc("left", fmt.Sprintf("10.0.%d.2/30", i-1)))
		}
		if i < n-1 {
			ifaces = append(ifaces, ifc("right", fmt.Sprintf("10.0.%d.1/30", i)))
			routes = append(routes, route("10.0.0.0/8", "kernel", nh(fmt.Sprintf("10.0.%d.2", i), "right")))
		}
		node := fmt.Sprintf("r%02d", i)
		obs = append(obs,
			configured(node, "default", ifaces),
			table(netmodel.PlaneFIB, node, "default", true, routes...))
	}
	return obs
}

// notFailed is the sources of f that a failure leaves to simulate, in the
// canonical order a named run uses.
func notFailed(f File, fail Failure) []Start {
	var out []Start
	for _, s := range ModeledSources(f) {
		if !removesSource(fail, s) {
			out = append(out, s)
		}
	}
	return out
}

func TestBlastRatingsMatchEachSingleSourceRun(t *testing.T) {
	cases := []struct {
		name  string
		obs   []netmodel.Observation
		fail  Failure
		extra []netip.Addr
	}{
		{"router", diamond(), Failure{Node: "r2"}, []netip.Addr{addr(dest)}},
		{"interface", diamond(), Failure{Node: "r1", Interface: "eth1"}, nil},
		{"ospf adjacency", ospfDiamond(), lostR1R2, nil},
		{"next hop", gatewayLAN(), lostGateway, nil},
		{"routing domains", twoDomains(), Failure{Node: "r2", Interface: "lan"}, nil},
		{"shared walk budget", blastLine(20), Failure{Node: "r10"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := blastFile(t, c.obs)
			all, err := SimulateBlast(f, c.fail, true, nil, c.extra...)
			if err != nil {
				t.Fatalf("all: %v", err)
			}
			if got, want := len(all.Sources)+len(all.Excluded), len(ModeledSources(f)); got != want {
				t.Fatalf("all: %d simulated and excluded, file models %d", got, want)
			}
			for _, s := range all.Sources {
				assertSameRatings(t, s, singleRun(t, f, s.Source, c.fail, c.extra...))
			}
			named, err := SimulateBlast(f, c.fail, false, notFailed(f, c.fail), c.extra...)
			if err != nil {
				t.Fatalf("named: %v", err)
			}
			for _, s := range named.Sources {
				assertSameRatings(t, s, singleRun(t, f, s.Source, c.fail, c.extra...))
			}
			// Only all lists the excluded sources, so the rest must match.
			if a, b := mustJSON(t, all.Sources), mustJSON(t, named.Sources); a != b {
				t.Errorf("all and the same sources named differ:\n%s\n%s", a, b)
			}
			if a, b := mustJSON(t, all.Summary), mustJSON(t, named.Summary); a != b {
				t.Errorf("all and the same sources named differ in summary:\n%s\n%s", a, b)
			}
		})
	}
}

// TestBlastSharedWalkBudgetLimitsTheListing runs a failure that every upstream
// source reaches, with walks long enough to spend the shared budget. The first
// source lists as it does alone. Later sources lose their walks, and their
// ratings stay as their single runs rate them.
func TestBlastSharedWalkBudgetLimitsTheListing(t *testing.T) {
	f := blastFile(t, blastLine(20))
	fail := Failure{Node: "r10"}
	b, err := SimulateBlast(f, fail, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Sources) != 19 || len(b.Excluded) != 1 {
		t.Fatalf("simulated %d sources and excluded %d, want 19 and 1", len(b.Sources), len(b.Excluded))
	}
	listed, omittedLater := 0, false
	for i, s := range b.Sources {
		single := singleRun(t, f, s.Source, fail)
		assertSameRatings(t, s, single)
		if i == 0 && !reflect.DeepEqual(s.Affected, single.Affected) {
			t.Errorf("first source %s lists differently from its single run", s.Source.Node)
		}
		if i > 0 && s.Truncated && !single.Truncated {
			omittedLater = true
		}
		for _, a := range s.Affected {
			if a.After != nil {
				walkHops(a.After, func(*Hop) { listed++ })
			}
		}
	}
	if listed < maxStates || listed > 2*maxStates-1 {
		t.Errorf("shared listing holds %d hops, want between %d and %d", listed, maxStates, 2*maxStates-1)
	}
	if !omittedLater {
		t.Error("no later source lost a walk to the shared budget, so the fixture does not test it")
	}
	if !b.Truncated {
		t.Error("the run omits walks, but is not truncated")
	}
}

func TestBlastCapsTheSourceCount(t *testing.T) {
	var obs []netmodel.Observation
	for i := range maxBlastSources + 2 {
		obs = append(obs, configured(fmt.Sprintf("n%02d", i), "default", []netmodel.Interface{ifc("eth0", fmt.Sprintf("10.2.%d.1/24", i))}))
	}
	f := blastFile(t, obs)
	b, err := SimulateBlast(f, Failure{Node: "n00", Interface: "eth0"}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Sources) != maxBlastSources || b.Skipped != 2 || !b.Truncated {
		t.Fatalf("simulated %d, skipped %d, truncated %v; want %d, 2, true", len(b.Sources), b.Skipped, b.Truncated, maxBlastSources)
	}
	if last := b.Sources[maxBlastSources-1].Source.Node; last != "n63" {
		t.Errorf("last simulated source is %s, want n63: the cap keeps the first sources in canonical order", last)
	}
	if !strings.Contains(b.Text(), "The run simulates at most 64 sources; 2 more were not simulated.") {
		t.Errorf("text does not report the skipped sources:\n%s", b.Text())
	}
}

// TestBlastRefusesAFailedNamedSourceBeyondTheCap names every source, with the
// failed router last in canonical order, past the cap. The cap must not drop
// the refusal, or the run reads as a success that skipped the failed source.
func TestBlastRefusesAFailedNamedSourceBeyondTheCap(t *testing.T) {
	var obs []netmodel.Observation
	for i := range maxBlastSources + 2 {
		obs = append(obs, configured(fmt.Sprintf("n%02d", i), "default", []netmodel.Interface{ifc("eth0", fmt.Sprintf("10.2.%d.1/24", i))}))
	}
	f := blastFile(t, obs)
	fail := Failure{Node: "n65"}
	t.Run("named", func(t *testing.T) {
		_, err := SimulateBlast(f, fail, false, ModeledSources(f))
		if err == nil || !strings.Contains(err.Error(), "nothing leaves a failed source") {
			t.Errorf("err = %v, want the failed source refused", err)
		}
	})
	t.Run("all excludes it without spending the cap", func(t *testing.T) {
		b, err := SimulateBlast(f, fail, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Excluded) != 1 || b.Excluded[0].Source.Node != "n65" || len(b.Sources) != maxBlastSources || b.Skipped != 1 {
			t.Errorf("excluded %+v, simulated %d, skipped %d; want n65 alone, %d, and 1", b.Excluded, len(b.Sources), b.Skipped, maxBlastSources)
		}
	})
}

// TestBlastSummaryCountsEachOwnerOnce pins the accounting: a node counts a
// rating once, a routing domain once per domain that holds it, and an unowned
// rating only as unowned.
func TestBlastSummaryCountsEachOwnerOnce(t *testing.T) {
	red, blue := Start{Node: "r1", VRF: "red"}, Start{Node: "r1", VRF: "blue"}
	other := Start{Node: "r2", VRF: "default"}
	sims := []Simulation{
		{Source: Start{Node: "r9", VRF: "default"}, Unchanged: 2, Affected: []Affected{
			{Destination: "10.0.0.1", Owners: []Start{red, blue}, Impact: ImpactReachabilityLost},
			{Destination: "10.0.0.2", Owners: []Start{other}, Impact: ImpactUnknown},
			{Destination: "10.0.0.3", Impact: ImpactRedundancyLost},
		}},
		{Source: Start{Node: "r8", VRF: "default"}, Affected: []Affected{
			{Destination: "10.0.0.1", Owners: []Start{red}, Impact: ImpactReachabilityLost},
		}},
	}
	s := summarize(sims)
	want := Summary{
		Unchanged: 2,
		Ratings:   Counts{ReachabilityLost: 2, RedundancyLost: 1, Unknown: 1},
		Unowned:   Counts{RedundancyLost: 1},
		Nodes: []NodeGroup{
			{Node: "r1", Counts: Counts{ReachabilityLost: 2}},
			{Node: "r2", Counts: Counts{Unknown: 1}},
		},
		Domains: []DomainGroup{
			{Node: "r1", VRF: "blue", Counts: Counts{ReachabilityLost: 1}},
			{Node: "r1", VRF: "red", Counts: Counts{ReachabilityLost: 2}},
			{Node: "r2", VRF: "default", Counts: Counts{Unknown: 1}},
		},
	}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("summary\n got %+v\nwant %+v", s, want)
	}
	b := Blast{Failure: Failure{Node: "r9"}, Summary: s, Sources: []Simulation{}}
	line := "Blast radius: 2 affected nodes, 3 affected routing domains, 4 affected ratings (reachability_lost 2, redundancy_lost 1, unknown 1), 1 unowned, 2 unchanged."
	one := Blast{Failure: Failure{Node: "r9"}, Summary: Summary{Nodes: []NodeGroup{{Node: "r1"}}, Domains: []DomainGroup{{Node: "r1", VRF: "red"}}, Ratings: Counts{Unknown: 1}, Unchanged: 0}, Sources: []Simulation{}}
	if got := "Blast radius: 1 affected node, 1 affected routing domain, 1 affected rating (reachability_lost 0, redundancy_lost 0, unknown 1), 0 unowned, 0 unchanged."; !strings.Contains(one.Text(), got) {
		t.Errorf("singular counts: text lacks %q:\n%s", got, one.Text())
	}
	if !strings.Contains(b.Text(), line) {
		t.Errorf("text lacks %q:\n%s", line, b.Text())
	}
}

// TestBlastCountsAnUnownedDestination checks that a destination no node holds
// is rated as usual and summarized as unowned.
func TestBlastCountsAnUnownedDestination(t *testing.T) {
	f := blastFile(t, singleHomed())
	fail := Failure{Node: "r2"}
	b, err := SimulateBlast(f, fail, true, nil, addr("10.20.40.9"))
	if err != nil {
		t.Fatal(err)
	}
	var unowned int
	for _, s := range b.Sources {
		for _, a := range s.Affected {
			if len(a.Owners) == 0 {
				unowned++
			}
		}
	}
	if unowned == 0 {
		t.Fatal("no unowned rating, so the fixture does not test the unowned count")
	}
	if got := b.Summary.Unowned.total(); got != unowned {
		t.Errorf("unowned %d, want %d: one per rating with no owner", got, unowned)
	}
}

func TestBlastSourceSelection(t *testing.T) {
	f := blastFile(t, singleHomed())
	cut := Failure{Node: "r2", Interface: "eth1"}

	t.Run("duplicates collapse to one source", func(t *testing.T) {
		b, err := SimulateBlast(f, cut, false, []Start{{Node: "r1", VRF: "default"}, {Node: "r1", VRF: "default"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Sources) != 1 {
			t.Errorf("simulated %d sources, want 1", len(b.Sources))
		}
	})

	t.Run("order of the named sources does not matter", func(t *testing.T) {
		ab, err := SimulateBlast(f, cut, false, []Start{{Node: "r1", VRF: "default"}, {Node: "r3", VRF: "default"}})
		if err != nil {
			t.Fatal(err)
		}
		ba, err := SimulateBlast(f, cut, false, []Start{{Node: "r3", VRF: "default"}, {Node: "r1", VRF: "default"}})
		if err != nil {
			t.Fatal(err)
		}
		if mustJSON(t, ab) != mustJSON(t, ba) {
			t.Error("the same sources in another order give other output")
		}
	})

	t.Run("all with an interface failure simulates every modeled source", func(t *testing.T) {
		all, err := SimulateBlast(f, cut, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(all.Sources) != len(ModeledSources(f)) || len(all.Excluded) != 0 {
			t.Errorf("simulated %d, excluded %d, want every modeled source and none excluded", len(all.Sources), len(all.Excluded))
		}
	})

	t.Run("all excludes the failed router and says why", func(t *testing.T) {
		b, err := SimulateBlast(f, Failure{Node: "r2"}, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Excluded) != 1 || b.Excluded[0].Source.Node != "r2" {
			t.Fatalf("excluded %+v, want r2 alone", b.Excluded)
		}
		if !strings.Contains(b.Text(), "Excluded source r2 (default): router r2 is the source; nothing leaves a failed source.") {
			t.Errorf("text does not explain the exclusion:\n%s", b.Text())
		}
	})

	t.Run("all with only the failed router modeled simulates nothing and says so", func(t *testing.T) {
		lone := blastFile(t, []netmodel.Observation{configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.1.1/24")})})
		b, err := SimulateBlast(lone, Failure{Node: "r1"}, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Sources) != 0 || len(b.Excluded) != 1 || b.Truncated {
			t.Errorf("simulated %d, excluded %d, truncated %v; want 0, 1, false", len(b.Sources), len(b.Excluded), b.Truncated)
		}
		if !strings.Contains(b.Text(), "Failure simulation across 0 sources: router r1 unavailable") {
			t.Errorf("text does not say no source was simulated:\n%s", b.Text())
		}
	})

	t.Run("a named failed router is refused", func(t *testing.T) {
		_, err := SimulateBlast(f, Failure{Node: "r2"}, false, []Start{{Node: "r2", VRF: "default"}})
		if err == nil || !strings.Contains(err.Error(), "nothing leaves a failed source") {
			t.Errorf("err = %v, want the failed source refused", err)
		}
	})

	t.Run("no routing domain is an error", func(t *testing.T) {
		_, err := SimulateBlast(f, cut, false, nil)
		if err == nil || !strings.Contains(err.Error(), "models no routing domain") {
			t.Errorf("err = %v, want no routing domain", err)
		}
	})

	t.Run("routing domains resolve only when unambiguous", func(t *testing.T) {
		two := blastFile(t, twoDomains())
		if _, err := ResolveSource(two, "r1", ""); err == nil || !strings.Contains(err.Error(), "name one as r1@VRF") {
			t.Errorf("ambiguous r1: err = %v", err)
		}
		if s, err := ResolveSource(two, "r1", "blue"); err != nil || s != (Start{Node: "r1", VRF: "blue"}) {
			t.Errorf("r1@blue = %+v, %v", s, err)
		}
		if s, err := ResolveSource(two, "r7", ""); err != nil || s != (Start{Node: "r7", VRF: "default"}) {
			t.Errorf("r7 = %+v, %v", s, err)
		}
		if _, err := ResolveSource(two, "r7", "red"); err == nil || !strings.Contains(err.Error(), "no modeled routing domain") {
			t.Errorf("r7@red: err = %v", err)
		}
		if _, err := ResolveSource(two, "r9", ""); err == nil || !strings.Contains(err.Error(), "no modeled node") {
			t.Errorf("r9: err = %v", err)
		}
	})
}

// TestBlastJSONAndTextAgree rebuilds the summary line from the JSON counts. The
// text and the JSON must describe the same run.
func TestBlastJSONAndTextAgree(t *testing.T) {
	b, err := SimulateBlast(blastFile(t, diamond()), Failure{Node: "r2"}, true, nil, addr(dest))
	if err != nil {
		t.Fatal(err)
	}
	var doc Blast
	if err := json.Unmarshal([]byte(mustJSON(t, b)), &doc); err != nil {
		t.Fatal(err)
	}
	s := doc.Summary
	line := fmt.Sprintf("Blast radius: %s, %s, %s (reachability_lost %d, redundancy_lost %d, unknown %d), %d unowned, %d unchanged.",
		count(len(s.Nodes), "affected node", "affected nodes"),
		count(len(s.Domains), "affected routing domain", "affected routing domains"),
		count(s.Ratings.total(), "affected rating", "affected ratings"),
		s.Ratings.ReachabilityLost, s.Ratings.RedundancyLost, s.Ratings.Unknown, s.Unowned.total(), s.Unchanged)
	if !strings.Contains(b.Text(), line) {
		t.Errorf("text lacks the JSON counts %q:\n%s", line, b.Text())
	}
	for name, out := range map[string]string{"JSON": doc.Scope, "text": b.Text()} {
		if !strings.Contains(out, "Recorded FIB only") || !strings.Contains(out, "Convergence is not predicted.") {
			t.Errorf("%s lacks the recorded-model boundary or the convergence banner", name)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
