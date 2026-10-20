package app

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/routepath"
)

// blastGoldenDir holds the pinned --sources reports. Each case reads one
// failure kind, or a named list instead of all, so a change to the shared part
// of a blast run shows in a golden.
const blastGoldenDir = "testdata/blast/golden"

// blastGoldenCases names each pinned report: the topology it reads and the
// flags after the destination.
func blastGoldenCases() []struct {
	name, topology string
	args           []string
} {
	return []struct {
		name, topology string
		args           []string
	}{
		{"router", omittedInterfaceTopology, []string{"--fail", "r2", "--sources", "all"}},
		{"ospf-adjacency", ospfAdjacencyTopology, []string{"--fail-ospf", "r1:eth1:r2", "--sources", "all"}},
		{"ospf-adjacency-named", ospfAdjacencyTopology, []string{"--fail-ospf", "r1:eth1:r2", "--sources", "r2,r1"}},
		{"next-hop", nextHopTopology, []string{"--fail-next-hop", "r1:10.0.1.2", "--sources", "all"}},
	}
}

// TestBlastReportIsByteStable pins the text and JSON of each blast run.
func TestBlastReportIsByteStable(t *testing.T) {
	for _, c := range blastGoldenCases() {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"--explain", writeTopology(t, c.topology), "10.20.40.8"}, c.args...)
			code, text, stderr := runNetdoc(t, args...)
			if code != 0 {
				t.Fatalf("text exit %d, want 0; stderr %q", code, stderr)
			}
			code, js, stderr := runNetdoc(t, append(slices.Clone(args), "--json")...)
			if code != 0 {
				t.Fatalf("json exit %d, want 0; stderr %q", code, stderr)
			}
			dir := filepath.Join(blastGoldenDir, c.name)
			assertGolden(t, filepath.Join(dir, "text.txt"), text)
			assertGolden(t, filepath.Join(dir, "json.json"), js)
		})
	}
}

// blastLine matches the summary line of a blast text report, and its groups.
var blastLine = regexp.MustCompile(`(?m)^Blast radius: (\d+) affected nodes?, (\d+) affected routing domains?, (\d+) affected ratings? \(reachability_lost (\d+), redundancy_lost (\d+), unknown (\d+)\), (\d+) unowned, (\d+) unchanged\.$`)

// TestBlastTextMatchesJSON reads the counts and names back from the text and
// checks them against the JSON summary of the same run.
func TestBlastTextMatchesJSON(t *testing.T) {
	for _, c := range blastGoldenCases() {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"--explain", writeTopology(t, c.topology), "10.20.40.8"}, c.args...)
			_, text, _ := runNetdoc(t, args...)
			_, js, _ := runNetdoc(t, append(slices.Clone(args), "--json")...)
			var doc struct {
				Blast routepath.Blast `json:"blast"`
			}
			if err := json.Unmarshal([]byte(js), &doc); err != nil {
				t.Fatal(err)
			}
			m := blastLine.FindStringSubmatch(text)
			if m == nil {
				t.Fatalf("text has no blast summary line:\n%s", text)
			}
			s := doc.Blast.Summary
			want := []int{len(s.Nodes), len(s.Domains), s.Ratings.ReachabilityLost + s.Ratings.RedundancyLost + s.Ratings.Unknown,
				s.Ratings.ReachabilityLost, s.Ratings.RedundancyLost, s.Ratings.Unknown, s.Unowned.ReachabilityLost + s.Unowned.RedundancyLost + s.Unowned.Unknown, s.Unchanged}
			for i, w := range want {
				if got, err := strconv.Atoi(m[i+1]); err != nil || got != w {
					t.Errorf("summary field %d: text says %s, JSON says %d", i, m[i+1], w)
				}
			}
			var nodes, domains []string
			for _, n := range s.Nodes {
				nodes = append(nodes, n.Node)
			}
			for _, d := range s.Domains {
				domains = append(domains, d.Node+" ("+d.VRF+")")
			}
			if !strings.Contains(text, "Affected nodes: "+joinOrNone(nodes)+".") {
				t.Errorf("text lists other affected nodes than JSON %v", nodes)
			}
			if !strings.Contains(text, "Affected routing domains: "+joinOrNone(domains)+".") {
				t.Errorf("text lists other affected routing domains than JSON %v", domains)
			}
		})
	}
}

// TestBlastKeepsTheBoundaryBanner checks that the recorded-model boundary and
// the convergence banner appear in both forms of every blast report.
func TestBlastKeepsTheBoundaryBanner(t *testing.T) {
	for _, c := range blastGoldenCases() {
		args := append([]string{"--explain", writeTopology(t, c.topology), "10.20.40.8"}, c.args...)
		_, text, _ := runNetdoc(t, args...)
		_, js, _ := runNetdoc(t, append(slices.Clone(args), "--json")...)
		for _, banner := range []string{"Recorded FIB only", "Convergence is not predicted."} {
			if !strings.Contains(text, banner) {
				t.Errorf("%s: text lacks %q", c.name, banner)
			}
			if !strings.Contains(js, banner) {
				t.Errorf("%s: JSON lacks %q", c.name, banner)
			}
		}
	}
}

// TestSourcesRefusesBadSelections exits 2 on each malformed or unusable
// -sources selection, and names the reason on stderr.
func TestSourcesRefusesBadSelections(t *testing.T) {
	path := writeTopology(t, omittedInterfaceTopology)
	explain := []string{"--explain", path, "10.20.40.8"}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"without explain", []string{"--sources", "all", path}, "-sources needs -explain"},
		{"without a failure", append(slices.Clone(explain), "--sources", "all"), "-sources needs -explain"},
		{"empty list", append(slices.Clone(explain), "--fail", "r2", "--sources", ""), "-sources needs -explain"},
		{"all beside a node", append(slices.Clone(explain), "--fail", "r2", "--sources", "all,r1"), "all stands alone"},
		{"trailing comma", append(slices.Clone(explain), "--fail", "r2", "--sources", "r1,"), `"" is not node[@vrf] or all`},
		{"empty routing domain", append(slices.Clone(explain), "--fail", "r2", "--sources", "r1@"), `"r1@" is not node[@vrf] or all`},
		{"unknown node", append(slices.Clone(explain), "--fail", "r2", "--sources", "nosuch"), `no modeled node "nosuch"`},
		{"unknown routing domain", append(slices.Clone(explain), "--fail", "r2", "--sources", "r1@red"), `no modeled routing domain "red" on node "r1"`},
		{"named failed router", append(slices.Clone(explain), "--fail", "r2", "--sources", "r2"), "nothing leaves a failed source"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, stderr := runNetdoc(t, c.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stdout %q", code, out)
			}
			if !strings.Contains(stderr, c.want) {
				t.Errorf("stderr %q lacks %q", stderr, c.want)
			}
		})
	}
}

// TestSourcesReportsEachFailureUnderItsOwnFlag checks that a failure target
// refused during a -sources run names its own flag, and that a source selector
// refused before the run still names -sources.
func TestSourcesReportsEachFailureUnderItsOwnFlag(t *testing.T) {
	omitted := writeTopology(t, omittedInterfaceTopology)
	ospf := writeTopology(t, ospfAdjacencyTopology)
	hop := writeTopology(t, nextHopTopology)
	empty := writeTopology(t, `{"version": 1, "source": {"node": "r1", "vrf": "default"}, "observations": []}`)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad -fail", []string{"--explain", omitted, "10.20.40.8", "--fail", "nosuch", "--sources", "r1"},
			`netdoc: -fail: no configured, control, or fib observation describes node "nosuch"` + "\n"},
		{"named failed router", []string{"--explain", omitted, "10.20.40.8", "--fail", "r2", "--sources", "r2"},
			"netdoc: -fail: router r2 is the source; nothing leaves a failed source\n"},
		{"empty file all", []string{"--explain", empty, "10.20.40.8", "--fail", "r1", "--sources", "all"},
			"netdoc: -sources: the file models no routing domain to simulate from\n"},
		{"bad -fail-ospf", []string{"--explain", ospf, "10.20.40.8", "--fail-ospf", "r1:eth1:nosuch", "--sources", "r2,r1"},
			`netdoc: -fail-ospf: no control-plane OSPF neighbor record on node "r1" interface "eth1" names neighbor "nosuch"` + "\n"},
		{"bad -fail-next-hop", []string{"--explain", hop, "10.20.40.8", "--fail-next-hop", "r1:10.9.9.9", "--sources", "r2"},
			`netdoc: -fail-next-hop: no fib route of node "r1" names next hop 10.9.9.9` + "\n"},
		{"unknown source", []string{"--explain", omitted, "10.20.40.8", "--fail", "r2", "--sources", "nosuch"},
			`netdoc: -sources: no modeled node "nosuch"` + "\n"},
		{"malformed source", []string{"--explain", omitted, "10.20.40.8", "--fail", "r2", "--sources", "r1,"},
			`netdoc: -sources: "" is not node[@vrf] or all` + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, stderr := runNetdoc(t, c.args...)
			if code != 2 || out != "" || stderr != c.want {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 2, no stdout, stderr %q", code, out, stderr, c.want)
			}
		})
	}
}

func joinOrNone(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	return strings.Join(xs, ", ")
}
