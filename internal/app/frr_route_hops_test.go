package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// G1: a route with one forwarding hop and two advertisers reads as two next hops
// in the text report, because the text prints the raw element count. The JSON
// reports one forwarding hop with both advertisers. This test pins that limit
// and the sentence in docs/reference.md that states it.
func TestRouteOneHopTwoAdvertisersTextCountsElements(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	addFRRLSDB(t, dir, manifest, "steady", "r1")
	addFRRLSDB(t, dir, manifest, "steady", "r2")
	editFRRJSON(t, filepath.Join(dir, "steady-r1-E-show_ip_ospf_route_json.json"), func(m map[string]any) {
		route := m["10.10.2.0/24"].(map[string]any)
		hops := route["nexthops"].([]any)
		route["nexthops"] = append(hops, map[string]any{"ip": "10.0.1.2", "via": "e1", "advertisedRouter": "1.1.1.1"})
	})

	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 0 {
		t.Fatalf("text exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	want := "route 10.10.2.0/24, type N, cost 20, area 0.0.0.0, next hops 2"
	if !strings.Contains(stdout, want) {
		t.Fatalf("text lacks %q\n%s", want, stdout)
	}

	code, stdoutJ, stderrJ := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
	if code != 0 {
		t.Fatalf("json exit %d, want 0\nstderr:\n%s", code, stderrJ)
	}
	var report struct {
		OSPFLSDB struct {
			Nodes []struct {
				Node   string           `json:"node"`
				Routes []map[string]any `json:"routes"`
			} `json:"nodes"`
		} `json:"ospf_lsdb"`
	}
	if err := json.Unmarshal([]byte(stdoutJ), &report); err != nil {
		t.Fatal(err)
	}
	var route map[string]any
	for _, n := range report.OSPFLSDB.Nodes {
		if n.Node != "r1" {
			continue
		}
		for _, r := range n.Routes {
			if r["prefix"] == "10.10.2.0/24" {
				route = r
			}
		}
	}
	if route == nil {
		t.Fatal("no r1 route 10.10.2.0/24 in the JSON")
	}
	if route["next_hops"] != float64(2) || route["next_hop_status"] != "complete" || route["forwarding_hop_count"] != float64(1) {
		t.Fatalf("route = %v; want next_hops 2, complete, one forwarding hop", route)
	}
	hops, _ := route["forwarding_hops"].([]any)
	if len(hops) != 1 {
		t.Fatalf("forwarding_hops = %v; want one hop", route["forwarding_hops"])
	}
	advs, err := json.Marshal(hops[0].(map[string]any)["advertised_by"])
	if err != nil {
		t.Fatal(err)
	}
	if string(advs) != `["1.1.1.1","2.2.2.2"]` {
		t.Fatalf("advertised_by = %s; want both advertisers, sorted", advs)
	}
}
