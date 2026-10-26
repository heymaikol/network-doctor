package simulation

import (
	"encoding/json"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/routepath"
)

// TestIPIPCommittedEvidence checks the immutable captures and replays their import
// and fault grades offline. It does not replace the kernel-backed acceptance run.
func TestIPIPCommittedEvidence(t *testing.T) {
	for _, phase := range []string{"before-import", "imported"} {
		for _, c := range ipipAcceptanceCases {
			t.Run(phase+"/"+c.name, func(t *testing.T) {
				dir := filepath.Join("testdata", "ipip_acceptance_live", phase, strings.ReplaceAll(c.name, " ", "-"))
				sums := readTestSums(t, dir)
				want := ipipEvidenceFiles()
				slices.Sort(want)
				if !slices.Equal(slices.Sorted(maps.Keys(sums)), want) {
					t.Fatal("evidence manifest does not cover the expected files")
				}
				for name, hash := range sums {
					if got := testFileSum(t, filepath.Join(dir, name)); got != hash {
						t.Fatalf("%s checksum mismatch: got %s, want %s", name, got, hash)
					}
				}
				var entries []tunnelEvidenceEntry
				if err := json.Unmarshal([]byte(readTestFile(t, filepath.Join(dir, "metadata.json"))), &entries); err != nil {
					t.Fatal(err)
				}
				if len(entries) != len(ipipEvidenceNodes)*len(ipipCaptureKinds) {
					t.Fatalf("%d capture entries, want 20", len(entries))
				}
				var captures []routepath.TunnelCapture
				for _, e := range entries {
					if e.File != e.Source+".json" || filepath.Base(e.File) != e.File || e.CollectedAt.IsZero() {
						t.Fatalf("invalid capture provenance: %+v", e)
					}
					captures = append(captures, routepath.TunnelCapture{Source: e.Source, Node: e.Node, Command: e.Command, CollectedAt: e.CollectedAt, Data: []byte(readTestFile(t, filepath.Join(dir, e.File)))})
				}
				base, err := routepath.Decode([]byte(readTestFile(t, filepath.Join(dir, "base-topology.json"))))
				if err != nil {
					t.Fatal(err)
				}
				imp, err := routepath.ImportTunnels(base.Model, captures)
				if err != nil || len(imp.Tunnels) != 2 || len(imp.Rules) != 4 {
					t.Fatalf("import = %+v, %v", imp, err)
				}
				merged, err := routepath.MergeTunnelImport(base, imp)
				if err != nil {
					t.Fatal(err)
				}
				sim, err := routepath.Simulate(merged, c.fault)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, a := range sim.Affected {
					if a.Destination == ipipOverlay {
						found = true
						if a.Impact != c.impact {
							t.Fatalf("overlay grade %s, want %s", a.Impact, c.impact)
						}
					}
				}
				if !found {
					t.Fatal("overlay destination absent from the simulation")
				}
				outcome := readTestFile(t, filepath.Join(dir, "outcome.txt"))
				if !strings.Contains(outcome, "path before the fault at ") || !strings.Contains(outcome, "path after the fault at ") {
					t.Fatal("missing before/after kernel observations")
				}
			})
		}
	}
}

// ipipDevice is the configured IPIP tunnel the acceptance cases create on r1 and r3.
// Its name is not tunl0, the kernel fallback the import reads as inert.
const (
	ipipDevice  = "ipip1"
	ipipOverlay = "172.32.0.2"
)

// ipipEvidenceNodes are the diamond's four routers, which each live case captures.
var ipipEvidenceNodes = []string{"r1", "r2", "r3", "r4"}

// ipipCaptureKinds are the commands each router is captured with, by the prefix of the
// source label. They are the commands tunnelCaptures runs, in the same order.
var ipipCaptureKinds = []struct{ kind, command string }{
	{"ip-link", routepath.TunnelCommandIPLink},
	{"ip-rule", routepath.TunnelCommandRules},
	{"ip-addr", routepath.TunnelCommandAddr},
	{"ip-route4", routepath.TunnelCommandRoute4},
	{"ip-route6", routepath.TunnelCommandRoute6},
}

// ipipAcceptanceCase is one live IPIP case. Its expectations are fixed here, not read
// back from the simulator. impact and bare are the grades the overlay must get with and
// without the tunnel record, and delivered is whether a dial still crosses after the
// fault. segment is the segment the fault takes down, or "" when the tunnel device
// itself is brought down. unaffected, when set, must be predicted none and delivered
// before and after the fault.
type ipipAcceptanceCase struct {
	name       string
	segment    string
	fault      routepath.Failure
	impact     routepath.Impact
	delivered  bool
	bare       routepath.Impact
	unaffected string
}

// ipipAcceptanceCases are the two IPIP cases the slice requires. The underlay case takes
// down r1's s14 leg, the leg the tunnel's outer packets are pinned to, so the overlay is
// unknown with the record and none without it. The device case takes down the tunnel's
// own interface, so the overlay is lost with or without the record.
var ipipAcceptanceCases = []ipipAcceptanceCase{
	{name: "ipip underlay leg down pinned", segment: "s14", fault: routepath.Failure{Node: "r1", Interface: "s14"}, impact: routepath.ImpactUnknown, delivered: false, bare: routepath.ImpactNone},
	{name: "ipip tunnel device down", fault: routepath.Failure{Node: "r1", Interface: ipipDevice}, impact: routepath.ImpactReachabilityLost, delivered: false, bare: routepath.ImpactReachabilityLost, unaffected: "10.71.14.4"},
}

// ipipEvidenceDir is the directory one IPIP case writes its evidence to under root:
// ipip-acceptance/<case name with dashes>. The IPIP cases keep their own subtree, so
// their directories cannot meet the GRE cases', and writeTunnelEvidence refuses a
// directory that already holds files.
func ipipEvidenceDir(root, name string) string {
	return filepath.Join(root, "ipip-acceptance", strings.ReplaceAll(name, " ", "-"))
}

// ipipEvidenceFiles lists what one IPIP case directory holds once written: a capture per
// router and command, named <source>.json (ip-link-r1.json and so on), then
// metadata.json, base-topology.json, and outcome.txt. SHA256SUMS is written last, over
// every other file, so it is not listed.
func ipipEvidenceFiles() []string {
	var out []string
	for _, node := range ipipEvidenceNodes {
		for _, k := range ipipCaptureKinds {
			out = append(out, k.kind+"-"+node+".json")
		}
	}
	return append(out, "metadata.json", "base-topology.json", "outcome.txt")
}

// TestIPIPAcceptanceManifest checks the IPIP cases against the slice: the underlay leg
// down grades the overlay unknown, the tunnel device down grades it reachability_lost,
// and the evidence a case writes is named and covered by SHA256SUMS as the draft
// expects. It runs the evidence writer on synthetic bytes, so no namespace is needed.
func TestIPIPAcceptanceManifest(t *testing.T) {
	if len(ipipAcceptanceCases) != 2 {
		t.Fatalf("%d IPIP cases, want the underlay case and the device case", len(ipipAcceptanceCases))
	}
	if c := ipipAcceptanceCases[0]; c.fault.Interface != "s14" || c.impact != routepath.ImpactUnknown || c.bare != routepath.ImpactNone {
		t.Errorf("underlay case = %+v, want s14 down graded unknown, and none without the record", c)
	}
	if c := ipipAcceptanceCases[1]; c.fault.Interface != ipipDevice || c.segment != "" || c.impact != routepath.ImpactReachabilityLost {
		t.Errorf("device case = %+v, want %s down graded reachability_lost", c, ipipDevice)
	}

	root := t.TempDir()
	names := map[string]bool{}
	for _, c := range ipipAcceptanceCases {
		if names[c.name] {
			t.Errorf("case %q is listed twice", c.name)
		}
		names[c.name] = true
		dir := ipipEvidenceDir(root, c.name)
		if filepath.Dir(dir) != filepath.Join(root, "ipip-acceptance") {
			t.Errorf("case %q writes to %s, outside ipip-acceptance", c.name, dir)
		}
		var captures []routepath.TunnelCapture
		for _, node := range ipipEvidenceNodes {
			for _, k := range ipipCaptureKinds {
				captures = append(captures, routepath.TunnelCapture{Source: k.kind + "-" + node, Node: node, Command: k.command, Data: []byte("[]\n")})
			}
		}
		if err := writeTunnelEvidence(dir, captures, []byte("{}\n"), "outcome\n"); err != nil {
			t.Fatal(err)
		}
		got := slices.Sorted(maps.Keys(readTestSums(t, dir)))
		want := ipipEvidenceFiles()
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("case %q: SHA256SUMS lists\n%s\nwant\n%s", c.name, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}
