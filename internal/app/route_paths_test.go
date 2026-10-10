package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// The test network: r1 is the topology's source at 192.0.2.10 and owns the
// address the destination replies to. r2 owns the destination 93.184.216.34.
// Side A's machine chose 192.0.2.10 as its source toward the target, and side B
// is a different machine whose own source is 203.0.113.9.
const (
	routeTarget  = "93.184.216.34"
	routeSourceA = "192.0.2.10"
	routeSourceB = "203.0.113.9"
)

const symmetricTopology = `{
 "version": 1,
 "source": {"node": "r1", "vrf": "default", "address": "192.0.2.10"},
 "observations": [
  {"source": "r1-control", "collected_at": "2026-01-02T03:00:00Z", "plane": "control", "node": "r1", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["192.0.2.10/24"]}, {"name": "eth1", "addresses": ["198.51.100.1/30"]}],
   "routes": [{"prefix": "93.184.216.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.2", "interface": "eth1"}]}]},
  {"source": "r1-fib", "collected_at": "2026-01-02T03:00:00Z", "plane": "fib", "node": "r1", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["192.0.2.10/24"]}, {"name": "eth1", "addresses": ["198.51.100.1/30"]}],
   "routes": [{"prefix": "93.184.216.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.2", "interface": "eth1"}]}]},
  {"source": "r2-control", "collected_at": "2026-01-02T03:00:00Z", "plane": "control", "node": "r2", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["198.51.100.2/30"]}, {"name": "eth1", "addresses": ["93.184.216.34/24"]}],
   "routes": [{"prefix": "192.0.2.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.1", "interface": "eth0"}]}]},
  {"source": "r2-fib", "collected_at": "2026-01-02T03:00:00Z", "plane": "fib", "node": "r2", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["198.51.100.2/30"]}, {"name": "eth1", "addresses": ["93.184.216.34/24"]}],
   "routes": [{"prefix": "192.0.2.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.1", "interface": "eth0"}]}]}
 ]
}`

// asymmetricTopology sends the reply through r3. The forward path crosses r2
// only, and the return crosses r2, r3, then r1, so the two routes differ.
const asymmetricTopology = `{
 "version": 1,
 "source": {"node": "r1", "vrf": "default", "address": "192.0.2.10"},
 "observations": [
  {"source": "r1-control", "collected_at": "2026-01-02T03:00:00Z", "plane": "control", "node": "r1", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["192.0.2.10/24"]}, {"name": "eth1", "addresses": ["198.51.100.1/30"]}, {"name": "eth2", "addresses": ["198.51.100.9/30"]}],
   "routes": [{"prefix": "93.184.216.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.2", "interface": "eth1"}]}]},
  {"source": "r1-fib", "collected_at": "2026-01-02T03:00:00Z", "plane": "fib", "node": "r1", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["192.0.2.10/24"]}, {"name": "eth1", "addresses": ["198.51.100.1/30"]}, {"name": "eth2", "addresses": ["198.51.100.9/30"]}],
   "routes": [{"prefix": "93.184.216.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.2", "interface": "eth1"}]}]},
  {"source": "r2-control", "collected_at": "2026-01-02T03:00:00Z", "plane": "control", "node": "r2", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["198.51.100.2/30"]}, {"name": "eth1", "addresses": ["93.184.216.34/24"]}, {"name": "eth2", "addresses": ["198.51.100.5/30"]}],
   "routes": [{"prefix": "192.0.2.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.6", "interface": "eth2"}]}]},
  {"source": "r2-fib", "collected_at": "2026-01-02T03:00:00Z", "plane": "fib", "node": "r2", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["198.51.100.2/30"]}, {"name": "eth1", "addresses": ["93.184.216.34/24"]}, {"name": "eth2", "addresses": ["198.51.100.5/30"]}],
   "routes": [{"prefix": "192.0.2.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.6", "interface": "eth2"}]}]},
  {"source": "r3-control", "collected_at": "2026-01-02T03:00:00Z", "plane": "control", "node": "r3", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["198.51.100.6/30"]}, {"name": "eth1", "addresses": ["198.51.100.10/30"]}],
   "routes": [{"prefix": "192.0.2.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.9", "interface": "eth1"}]}]},
  {"source": "r3-fib", "collected_at": "2026-01-02T03:00:00Z", "plane": "fib", "node": "r3", "vrf": "default", "routes_complete": true,
   "interfaces": [{"name": "eth0", "addresses": ["198.51.100.6/30"]}, {"name": "eth1", "addresses": ["198.51.100.10/30"]}],
   "routes": [{"prefix": "192.0.2.0/24", "origin": "static", "next_hops": [{"addr": "198.51.100.9", "interface": "eth1"}]}]}
 ]
}`

// editTopology decodes a topology, lets edit change it, and returns the JSON.
// The edit sees the file as generic maps, so each variant states only what
// changes.
func editTopology(t *testing.T, base string, edit func(doc map[string]any)) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(base), &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func observationsOf(doc map[string]any) []map[string]any {
	var out []map[string]any
	for _, o := range doc["observations"].([]any) {
		out = append(out, o.(map[string]any))
	}
	return out
}

// routeSide loads one golden run and makes it a probe of routeTarget. src is the
// local address this machine chose toward that target, and edit may change the
// result afterwards.
func routeSide(t *testing.T, base, src string, edit func(*snapshot.Snapshot)) snapshot.Snapshot {
	t.Helper()
	// #nosec G304 -- base is one of this test's literal fixture names.
	data, err := os.ReadFile(filepath.Join("testdata", "twosided", base+".ndoc"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	s.Target = &snapshot.Target{Raw: routeTarget, Host: routeTarget, IP: routeTarget, Port: 443, Protocol: "tls+http"}
	for i := range s.Checks {
		if s.Checks[i].ID != "target_tcp" {
			continue
		}
		if s.Checks[i].Observed == nil {
			s.Checks[i].Observed = &snapshot.Observed{}
		}
		o := s.Checks[i].Observed
		o.SelectedIP, o.SourceIP = routeTarget, src
		// The gateway and prefix are what r1 forwards with in both topologies. The
		// interface name is a machine-local spelling, so it differs on purpose.
		o.Routes = []snapshot.Route{{Destination: routeTarget, Family: "ipv4", Interface: "en0", Gateway: "198.51.100.2", Source: src, Prefix: "93.184.216.0/24"}}
	}
	if edit != nil {
		edit(&s)
	}
	return s
}

// unsetTargetIP makes the target a name, as a user typing a hostname would.
func unsetTargetIP(s *snapshot.Snapshot) {
	s.Target.Raw, s.Target.Host, s.Target.IP = "example.com", "example.com", ""
}

// setTargetV6 makes the target an IPv6 literal while the recorded rows stay IPv4.
func setTargetV6(s *snapshot.Snapshot) {
	s.Target.Raw, s.Target.Host, s.Target.IP = "2001:db8::34", "2001:db8::34", "2001:db8::34"
}

// setTargetParsed replaces the target with what the real parser and snapshot
// projection record for spelling, so these cases test the stored target itself.
func setTargetParsed(t *testing.T, spelling string) func(*snapshot.Snapshot) {
	t.Helper()
	tgt, err := diagnostic.ParseTarget(spelling)
	if err != nil {
		t.Fatalf("ParseTarget(%q): %v", spelling, err)
	}
	return func(s *snapshot.Snapshot) {
		s.Target = diagnostic.BuildSnapshotWithDiagnosis(tgt, nil, nil, diagnostic.Diagnosis{}).Target
	}
}

// targetCheck returns the target_tcp row of a route side, where the source
// records live.
func targetCheck(s *snapshot.Snapshot) *snapshot.Observed {
	for i := range s.Checks {
		if s.Checks[i].ID == "target_tcp" {
			return s.Checks[i].Observed
		}
	}
	return nil
}

// runRoute runs offline two-sided reading on two snapshots with optional route
// files and returns stdout, stderr, and the exit code.
func runRoute(t *testing.T, a, b snapshot.Snapshot, files routeFiles, jsonOut bool) (string, string, int) {
	t.Helper()
	dir := t.TempDir()
	pa := writeSnapshotFile(t, dir, "a.ndoc", a)
	pb := writeSnapshotFile(t, dir, "b.ndoc", b)
	var stdout, stderr bytes.Buffer
	code := runTwoSided([]string{pa, pb}, map[string]bool{}, files, jsonOut, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func writeTopologyFile(t *testing.T, name, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// routeReport is the part of the JSON reading these tests read back.
type routeReport struct {
	RoutePaths []struct {
		Side        string `json:"side"`
		Status      string `json:"status"`
		Reason      string `json:"reason"`
		Destination string `json:"destination"`
		Source      string `json:"source"`
		Basis       *struct {
			Expected   string `json:"expected"`
			Forwarding string `json:"forwarding"`
			Return     string `json:"return"`
			Checks     string `json:"checks"`
		} `json:"basis"`
		FirstHop    string   `json:"first_hop"`
		Compared    []string `json:"compared"`
		NotCompared []string `json:"not_compared"`
		Explanation struct {
			Asymmetry *struct {
				Assessment string `json:"assessment"`
			} `json:"asymmetry"`
		} `json:"explanation"`
	} `json:"route_paths"`
}

func TestRouteBindingOutcomes(t *testing.T) {
	symmetric := symmetricTopology
	asymmetric := asymmetricTopology
	partial := editTopology(t, symmetricTopology, func(doc map[string]any) {
		for _, o := range observationsOf(doc) {
			if o["node"] == "r2" && o["plane"] == "fib" {
				o["routes_complete"] = false
			}
		}
	})
	named := editTopology(t, symmetricTopology, func(doc map[string]any) {
		doc["source"].(map[string]any)["vrf"] = "blue"
		for _, o := range observationsOf(doc) {
			o["vrf"] = "blue"
		}
	})
	ecmp := editTopology(t, symmetricTopology, func(doc map[string]any) {
		for _, o := range observationsOf(doc) {
			if o["node"] == "r1" && o["plane"] == "fib" {
				route := o["routes"].([]any)[0].(map[string]any)
				route["next_hops"] = append(route["next_hops"].([]any), map[string]any{"addr": "198.51.100.3", "interface": "eth1"})
			}
		}
	})
	partialSource := editTopology(t, symmetricTopology, func(doc map[string]any) {
		for _, o := range observationsOf(doc) {
			if o["node"] == "r1" && o["plane"] == "fib" {
				o["routes_complete"] = false
			}
		}
	})
	interfaceOnly := editTopology(t, symmetricTopology, func(doc map[string]any) {
		for _, o := range observationsOf(doc) {
			if o["node"] == "r1" && o["plane"] == "fib" {
				route := o["routes"].([]any)[0].(map[string]any)
				route["next_hops"] = []any{map[string]any{"interface": "eth1"}}
			}
		}
	})
	stale := editTopology(t, symmetricTopology, func(doc map[string]any) {
		for _, o := range observationsOf(doc) {
			o["collected_at"] = "2025-12-30T00:00:00Z"
		}
	})
	twoOwners := editTopology(t, symmetricTopology, func(doc map[string]any) {
		doc["observations"] = append(doc["observations"].([]any), map[string]any{
			"source": "r9-control", "collected_at": "2026-01-02T03:00:00Z", "plane": "control", "node": "r9", "vrf": "default",
			"routes_complete": false, "interfaces": []any{map[string]any{"name": "eth0", "addresses": []any{"192.0.2.10/24"}}},
		})
	})
	cases := []struct {
		name        string
		topo        string
		side        string
		editA       func(*snapshot.Snapshot)
		editB       func(*snapshot.Snapshot)
		status      string
		reason      string
		assess      string
		hop         string
		compared    string
		notCompared string
	}{
		{name: "symmetric return binds", topo: symmetric, side: "a", status: compare.RouteBound, assess: "symmetric", notCompared: "routing_table"},
		{name: "asymmetric return is context", topo: asymmetric, side: "a", status: compare.RouteBound, assess: "asymmetric_benign"},
		{name: "partial return stays unknown", topo: partial, side: "a", status: compare.RouteBound, assess: "unknown"},
		{name: "source owned by two nodes", topo: twoOwners, side: "a", status: compare.RouteUnbound, reason: "several nodes"},
		{name: "rows outside the window", topo: stale, side: "a", status: compare.RouteUnbound, reason: "more than 24 hours"},
		{name: "source this side did not record", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "not the source this side recorded",
			editA: func(s *snapshot.Snapshot) {
				o := targetCheck(s)
				o.SourceIP, o.Routes[0].Source = "192.0.2.99", "192.0.2.99"
			}},
		{name: "no recorded source", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "no source address",
			editA: func(s *snapshot.Snapshot) { o := targetCheck(s); o.Routes, o.SourceIP = nil, "" }},
		{name: "several recorded sources", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "several source addresses",
			editA: func(s *snapshot.Snapshot) { targetCheck(s).SourceIP = "192.0.2.11" }},
		{name: "non-main routing domain", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "routing domain",
			editA: func(s *snapshot.Snapshot) {
				r := &targetCheck(s).Routes[0]
				r.Table, r.TableKnown = "table 100", true
			}},
		{name: "name target binds no address", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "resolves on each machine",
			editA: unsetTargetIP, editB: unsetTargetIP},
		{name: "IPv6 target against IPv4 source", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "address families",
			editA: setTargetV6, editB: setTargetV6},
		{name: "link-local target cannot name an interface", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "link-local",
			editA: setTargetParsed(t, "[fe80::1%eth1]:443"), editB: setTargetParsed(t, "[fe80::1%eth1]:443")},
		{name: "percent in a URL path is not a zone", topo: symmetric, side: "a", status: compare.RouteBound, assess: "symmetric",
			editA: setTargetParsed(t, "https://93.184.216.34/a%20b"), editB: setTargetParsed(t, "https://93.184.216.34/a%20b")},
		{name: "next hop contradicts the topology FIB", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "next hop", hop: compare.FirstHopConflicts,
			editA: func(s *snapshot.Snapshot) { targetCheck(s).Routes[0].Gateway = "192.0.2.1" }},
		{name: "matched prefix contradicts the topology FIB", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "matches", hop: compare.FirstHopConflicts,
			editA: func(s *snapshot.Snapshot) { targetCheck(s).Routes[0].Prefix = "0.0.0.0/0" }},
		{name: "main table against a named VRF", topo: named, side: "a", status: compare.RouteUnbound, reason: "VRF",
			editA: func(s *snapshot.Snapshot) { r := &targetCheck(s).Routes[0]; r.Table, r.TableKnown = "", true }},
		{name: "unreported table against a named VRF", topo: named, side: "a", status: compare.RouteUnbound, reason: "VRF"},
		{name: "known main table binds on the default VRF", topo: symmetric, side: "a", status: compare.RouteBound, assess: "symmetric", compared: "routing_table",
			editA: func(s *snapshot.Snapshot) { r := &targetCheck(s).Routes[0]; r.Table, r.TableKnown = "", true }},
		{name: "absent prefix is not compared", topo: symmetric, side: "a", status: compare.RouteBound, assess: "symmetric", notCompared: "prefix",
			editA: func(s *snapshot.Snapshot) { targetCheck(s).Routes[0].Prefix = "" }},
		{name: "next hop is one ECMP member", topo: ecmp, side: "a", status: compare.RouteBound, assess: "unknown",
			editA: func(s *snapshot.Snapshot) { targetCheck(s).Routes[0].Gateway = "198.51.100.3" }},
		{name: "link-local next hop is not comparable", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "link-local", hop: compare.FirstHopNotComparable,
			editA: func(s *snapshot.Snapshot) { targetCheck(s).Routes[0].Gateway = "fe80::1" }},
		{name: "no recorded next hop is not comparable", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "no next hop", hop: compare.FirstHopNotComparable,
			editA: func(s *snapshot.Snapshot) { targetCheck(s).Routes[0].Gateway = "" }},
		{name: "on-link record against a forwarded route conflicts", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "on link", hop: compare.FirstHopConflicts,
			editA: func(s *snapshot.Snapshot) { r := &targetCheck(s).Routes[0]; r.Gateway, r.Reason = "", "on_link" }},
		{name: "kernel no-route against a forwarded route conflicts", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "no route for the target", hop: compare.FirstHopConflicts,
			editA: func(s *snapshot.Snapshot) { targetCheck(s).Routes[0].Unreachable = true }},
		{name: "several recorded routes are not comparable", topo: symmetric, side: "a", status: compare.RouteUnbound, reason: "several routes", hop: compare.FirstHopNotComparable,
			editA: func(s *snapshot.Snapshot) {
				o := targetCheck(s)
				o.Routes = append(o.Routes, snapshot.Route{Destination: routeTarget, Family: "ipv4", Interface: "en1", Gateway: "198.51.100.2", Source: routeSourceA, Prefix: "93.184.216.0/25"})
			}},
		{name: "partial source FIB is not comparable", topo: partialSource, side: "a", status: compare.RouteUnbound, reason: "no next hop to compare", hop: compare.FirstHopNotComparable},
		{name: "interface-only topology hop is not comparable", topo: interfaceOnly, side: "a", status: compare.RouteUnbound, reason: "no address to compare", hop: compare.FirstHopNotComparable},
		{name: "other side's file is refused", topo: symmetric, side: "b", status: compare.RouteUnbound, reason: "not the source this side recorded",
			editB: func(s *snapshot.Snapshot) {
				targetCheck(s).SourceIP = routeSourceB
				targetCheck(s).Routes[0].Source = routeSourceB
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := routeSide(t, "here", routeSourceA, c.editA)
			b := routeSide(t, "there", routeSourceB, c.editB)
			path := writeTopologyFile(t, "topology.json", c.topo)
			files := routeFiles{a: path}
			if c.side == "b" {
				files = routeFiles{b: path}
			}
			stdout, stderr, _ := runRoute(t, a, b, files, true)
			if stderr != "" {
				t.Fatalf("stderr = %q, want none", stderr)
			}
			var got routeReport
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.RoutePaths) != 1 {
				t.Fatalf("route_paths = %+v, want one entry", got.RoutePaths)
			}
			p := got.RoutePaths[0]
			if p.Status != c.status {
				t.Fatalf("status = %q, want %q (reason %q)", p.Status, c.status, p.Reason)
			}
			if c.status == compare.RouteBound {
				if p.FirstHop != compare.FirstHopAgrees || !slices.Contains(p.Compared, "next_hop") || !slices.Contains(p.NotCompared, "interface") {
					t.Fatalf("first_hop = %q compared %v not_compared %v, want agreement on the next hop, interface names unchecked", p.FirstHop, p.Compared, p.NotCompared)
				}
				if c.compared != "" && !slices.Contains(p.Compared, c.compared) {
					t.Fatalf("compared = %v, want %q", p.Compared, c.compared)
				}
				if c.notCompared != "" && !slices.Contains(p.NotCompared, c.notCompared) {
					t.Fatalf("not_compared = %v, want %q", p.NotCompared, c.notCompared)
				}
			}
			if c.hop != "" && p.FirstHop != c.hop {
				t.Fatalf("first_hop = %q, want %q (reason %q)", p.FirstHop, c.hop, p.Reason)
			}
			if c.status == compare.RouteUnbound && c.hop == "" && p.FirstHop != "" {
				t.Fatalf("first_hop = %q on a refusal before the forwarding comparison, want none", p.FirstHop)
			}
			if c.status == compare.RouteUnbound {
				if !strings.Contains(p.Reason, c.reason) {
					t.Fatalf("reason = %q, want it to contain %q", p.Reason, c.reason)
				}
				// The reason is this package's own prose, so it may not name a cause the
				// reading did not establish.
				for _, forbidden := range []string{"firewall", "router", "nat ", "vpn", "is blocking", "is caused by"} {
					if strings.Contains(strings.ToLower(p.Reason), forbidden) {
						t.Fatalf("reason %q claims %q", p.Reason, forbidden)
					}
				}
				return
			}
			if p.Explanation.Asymmetry == nil || p.Explanation.Asymmetry.Assessment != c.assess {
				t.Fatalf("asymmetry = %+v, want %q", p.Explanation.Asymmetry, c.assess)
			}
			if p.Basis == nil || p.Basis.Checks != "recorded_elsewhere" || p.Basis.Expected != "control_plane_prediction" {
				t.Fatalf("basis = %+v, want labeled predictions and recorded checks", p.Basis)
			}
		})
	}
}

// The bound topology must supply the return route, never the other machine. In
// the asymmetric network the return crosses r3, which only the topology names.
func TestRouteReturnComesFromTopologyNotTheOtherSide(t *testing.T) {
	a := routeSide(t, "here", routeSourceA, nil)
	b := routeSide(t, "there", routeSourceB, nil)
	stdout, _, _ := runRoute(t, a, b, routeFiles{a: writeTopologyFile(t, "topology.json", asymmetricTopology)}, false)
	if !strings.Contains(stdout, "r3") {
		t.Fatalf("return route should cross r3 from the topology:\n%s", stdout)
	}
	if strings.Contains(stdout, routeSourceB) {
		t.Fatalf("side B's recorded address leaked into side A's route context:\n%s", stdout)
	}
	if !strings.Contains(stdout, "not measured replies") {
		t.Fatalf("route context must say it is not a measured reply:\n%s", stdout)
	}
	if !strings.Contains(stdout, "recorded elsewhere") {
		t.Fatalf("route context must say its checks were recorded elsewhere:\n%s", stdout)
	}
}

// Route context never changes the reading. The no-evidence output must be a
// prefix of the output with route context, and the exit code must match.
func TestRouteContextNeverChangesPlacementOrExit(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		exit int
	}{
		{"divergent failure stays placed", "here", "there", 1},
		{"passing pair stays passing", "there", "there", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := routeSide(t, c.a, routeSourceA, nil)
			b := routeSide(t, c.b, routeSourceB, nil)
			plain, _, plainExit := runRoute(t, a, b, routeFiles{}, false)
			withRoute, _, routeExit := runRoute(t, a, b, routeFiles{a: writeTopologyFile(t, "topology.json", symmetricTopology)}, false)
			if plainExit != c.exit || routeExit != c.exit {
				t.Fatalf("exit = %d and %d, want %d for both", plainExit, routeExit, c.exit)
			}
			if !strings.HasPrefix(withRoute, plain) {
				t.Fatalf("placement text changed with route context\n--- plain\n%s\n--- with route\n%s", plain, withRoute)
			}
			if !strings.Contains(withRoute[len(plain):], "Route context from topology files") {
				t.Fatalf("route context missing:\n%s", withRoute)
			}
		})
	}
}

// JSON with route context must equal JSON without it once route_paths is
// removed, so every existing field keeps its value.
func TestRouteContextLeavesExistingJSONUnchanged(t *testing.T) {
	a := routeSide(t, "here", routeSourceA, nil)
	b := routeSide(t, "there", routeSourceB, nil)
	plain, _, _ := runRoute(t, a, b, routeFiles{}, true)
	withRoute, _, _ := runRoute(t, a, b, routeFiles{a: writeTopologyFile(t, "topology.json", symmetricTopology)}, true)
	var before, after map[string]any
	if err := json.Unmarshal([]byte(plain), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(withRoute), &after); err != nil {
		t.Fatal(err)
	}
	if _, ok := before["route_paths"]; ok {
		t.Fatal("route_paths present without route files")
	}
	delete(after, "route_paths")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("existing JSON fields changed with route context")
	}
}

// Equivalent input orders must print identical bytes.
func TestRouteContextIsDeterministicAcrossObservationOrder(t *testing.T) {
	reversed := editTopology(t, symmetricTopology, func(doc map[string]any) {
		obs := observationsOf(doc)
		out := make([]any, 0, len(obs))
		for i := len(obs) - 1; i >= 0; i-- {
			out = append(out, obs[i])
		}
		doc["observations"] = out
	})
	a := routeSide(t, "here", routeSourceA, nil)
	b := routeSide(t, "there", routeSourceB, nil)
	first, _, _ := runRoute(t, a, b, routeFiles{a: writeTopologyFile(t, "one.json", symmetricTopology)}, true)
	second, _, _ := runRoute(t, a, b, routeFiles{a: writeTopologyFile(t, "two.json", reversed)}, true)
	if first != second {
		t.Fatal("observation order changed the route context")
	}
}

// A support artifact's addresses are pseudonyms, so it can never tie to a
// topology. The generic pair has no target, so only the sanitized side is refused.
func TestSanitizedSideNeverBindsARoute(t *testing.T) {
	generic := func(edit func(*snapshot.Snapshot)) snapshot.Snapshot {
		s := routeSide(t, "here", routeSourceA, nil)
		s.Target = nil
		if edit != nil {
			edit(&s)
		}
		return s
	}
	a := generic(func(s *snapshot.Snapshot) {
		s.Redaction = &snapshot.Redaction{Sanitized: true, Policy: snapshot.SupportRedactionPolicy}
	})
	b := generic(nil)
	stdout, _, _ := runRoute(t, a, b, routeFiles{a: writeTopologyFile(t, "topology.json", symmetricTopology)}, true)
	var got routeReport
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.RoutePaths) != 1 || got.RoutePaths[0].Status != compare.RouteUnbound || !strings.Contains(got.RoutePaths[0].Reason, "sanitized") {
		t.Fatalf("route_paths = %+v, want the sanitized side unbound", got.RoutePaths)
	}
}

// Invalid input and insufficient evidence differ. Invalid input is exit 2 and
// names the problem, so a typo never looks like a quiet, unbound file.
func TestRouteInputRefusals(t *testing.T) {
	a := routeSide(t, "here", routeSourceA, nil)
	b := routeSide(t, "there", routeSourceB, nil)
	noVRF := editTopology(t, symmetricTopology, func(doc map[string]any) {
		doc["source"].(map[string]any)["vrf"] = ""
	})
	cases := []struct {
		name  string
		files routeFiles
		want  string
	}{
		{"same file for both sides", routeFiles{a: "x.json", b: "x.json"}, "same topology file"},
		{"unknown field", routeFiles{a: writeTopologyFile(t, "bad.json", strings.Replace(symmetricTopology, `"version": 1,`, `"version": 1, "extra": 1,`, 1))}, "unknown field"},
		{"no vrf on the source", routeFiles{a: writeTopologyFile(t, "novrf.json", noVRF)}, "vrf"},
		// The OS wording differs between platforms, so the test checks the name it was given.
		{"missing file", routeFiles{a: filepath.Join(t.TempDir(), "absent.json")}, "absent.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, stderr, code := runRoute(t, a, b, c.files, false)
			if code != 2 {
				t.Fatalf("exit = %d, want 2; stderr %q", code, stderr)
			}
			if !strings.Contains(stderr, c.want) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr, c.want)
			}
		})
	}
}

// One vantage point gets one route file, however its name is spelled. A hard
// link names the same file, so it is refused like a repeated name.
func TestRouteFileAliasIsRefused(t *testing.T) {
	a := routeSide(t, "here", routeSourceA, nil)
	b := routeSide(t, "there", routeSourceB, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "topology.json")
	if err := os.WriteFile(path, []byte(symmetricTopology), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.json")
	if err := os.Link(path, alias); err != nil {
		t.Skipf("hard links unavailable here: %v", err)
	}
	_, stderr, code := runRoute(t, a, b, routeFiles{a: path, b: alias}, false)
	if code != 2 || !strings.Contains(stderr, "same topology file") {
		t.Fatalf("exit = %d, stderr %q; want exit 2 naming the same topology file", code, stderr)
	}
}

// Route files mean something only for an offline two-sided reading. Elsewhere
// they are refused, never silently ignored.
func TestRouteFlagsRefusedOutsideOfflineTwoSided(t *testing.T) {
	cases := [][]string{
		{"--two-sided", "--via", "remote", "--route-a", "t.json", "example.com"},
		{"--explain", "--route-a", "t.json", "topo.json", "93.184.216.34"},
		{"--compare", "--route-a", "t.json", "a.ndoc", "b.ndoc"},
		{"--route-a", "t.json", "example.com"},
		{"--version", "--route-a", "t.json"},
		{"--list-checks", "--route-a", "t.json"},
		{"--profile", "list", "--route-a", "t.json"},
		{"--two-sided", "--route-a", "", "a.ndoc", "b.ndoc"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("run(%q) exit = %d, want 2; stderr %q", args, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "-route-") {
			t.Fatalf("run(%q) stderr = %q, want it to name the route flags", args, stderr.String())
		}
	}
}
