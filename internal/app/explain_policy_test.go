package app

import (
	"encoding/json"
	"fmt"
	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/routepath"
)

const policyTopology = "../routepath/testdata/policy/topology.json"
const livePolicySelector = "r1:default:import:10.0.3.3:R3-IN"

func TestExplainPolicyPredictionGradedAgainstLiveFRR(t *testing.T) {
	args := []string{"--explain", policyTopology, "10.10.2.2", "--change-route-policy", livePolicySelector}
	code, text, stderr := runNetdoc(t, args...)
	if code != 0 {
		t.Fatalf("text exit %d: %s", code, stderr)
	}
	code, js, stderr := runNetdoc(t, append(args, "--json")...)
	if code != 0 {
		t.Fatalf("JSON exit %d: %s", code, stderr)
	}
	var out explainOutput
	if err := json.Unmarshal([]byte(js), &out); err != nil {
		t.Fatal(err)
	}
	s := out.Failure
	if s == nil || s.Policy == nil || s.Considered != s.Unchanged+len(s.Affected) {
		t.Fatal("missing or inconsistent simulation")
	}
	if !strings.Contains(text, fmt.Sprintf("%d destinations considered, %d unchanged.", s.Considered, s.Unchanged)) {
		t.Fatal("text and JSON counts disagree")
	}
	before := policyLabObject(t, "r1", "before", "show ip bgp json", false)["routes"].(map[string]any)
	after := policyLabObject(t, "r1", "after", "show ip bgp json", false)["routes"].(map[string]any)
	best := func(routes map[string]any, prefix string) string {
		t.Helper()
		out := ""
		for _, p := range routes[prefix].([]any) {
			m := p.(map[string]any)
			if m["bestpath"] == true {
				if out != "" {
					t.Fatal("ambiguous observed bestpath")
				}
				out = m["peerId"].(string)
			}
		}
		if out == "" {
			t.Fatal("missing observed bestpath")
		}
		return out
	}
	changed := 0
	for _, r := range s.Policy.Routes {
		observed := best(after, r.Prefix)
		if r.SelectedBefore != best(before, r.Prefix) {
			t.Fatalf("wrong baseline: %+v", r)
		}
		if r.SelectionAfter == "unchanged" && observed != r.SelectedBefore {
			t.Fatalf("unchanged prediction contradicted by live FRR: %+v", r)
		}
		if observed != r.SelectedBefore {
			changed++
			if r.SelectionAfter != "unknown" {
				t.Fatalf("recomputation was claimed proven: %+v", r)
			}
		}
		if !strings.Contains(text, r.Prefix+": selected before "+r.SelectedBefore+", selection after "+r.SelectionAfter) {
			t.Fatal("text and JSON selection disagree")
		}
	}
	if changed != 1 {
		t.Fatalf("lab changed %d selected routes, want 1", changed)
	}
	for _, a := range s.Affected {
		if a.Impact != routepath.ImpactUnknown {
			t.Fatalf("unproven forwarding claim: %+v", a)
		}
	}
	if !strings.Contains(text, "no replacement route") || !strings.Contains(text, "Downstream forwarding stays recorded") {
		t.Fatal("missing conservative scope")
	}
}

func TestExplainPolicyCLIRefusals(t *testing.T) {
	base := []string{"--explain", policyTopology, "10.10.2.2", "--change-route-policy", livePolicySelector}
	cases := [][]string{
		{"--change-route-policy", livePolicySelector},
		{"--explain", policyTopology, "10.10.2.2", "--change-route-policy", ""},
		{"--explain", policyTopology, "10.10.2.2", "--change-route-policy", "r1:import:10.0.3.3:R3-IN"},
		{"--explain", policyTopology, "10.10.2.2", "--change-route-policy", "r1:default:import:10.0.3.9:R3-IN"},
		{"--explain", policyTopology, "10.10.2.2", "--change-route-policy", "r1:default:import:10.0.3.3:OTHER"},
		append(append([]string{}, base...), "--fail", "r2"),
		append(append([]string{}, base...), "--fail-ospf", "r1:e1:r2"),
		append(append([]string{}, base...), "--fail-next-hop", "r1:10.0.1.2"),
		append(append([]string{}, base...), "--sources", "all"),
	}
	for _, args := range cases {
		code, out, errOut := runNetdoc(t, args...)
		if code != 2 || out != "" || !strings.Contains(errOut, "change-route-policy") {
			t.Errorf("%v: exit %d stdout %q stderr %q", args, code, out, errOut)
		}
	}
}

func TestExplainPolicyUnusedEvidenceKeepsLegacyCLIBytes(t *testing.T) {
	raw, err := os.ReadFile(policyTopology)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	delete(file, "route_policies")
	plain, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTopology(t, string(plain))
	for _, flags := range [][]string{nil, {"--json"}, {"--fail", "r2"}, {"--fail", "r2", "--json"}} {
		args := append([]string{"--explain", policyTopology, "10.10.2.2"}, flags...)
		a, textA, errA := runNetdoc(t, args...)
		args[1] = path
		b, textB, errB := runNetdoc(t, args...)
		if a != b || textA != textB || errA != errB {
			t.Fatalf("unused evidence changed legacy CLI bytes for %v", flags)
		}
	}
}

func TestPolicyReplayUsesPreservedRawBytes(t *testing.T) {
	raw, err := os.ReadFile(policyTopology)
	if err != nil {
		t.Fatal(err)
	}
	f, err := routepath.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range f.Policies {
		for _, c := range p.Captures {
			if c.Raw != readCommitted(t, policyLab, c.Source) {
				t.Fatalf("%s is not the preserved capture", c.Source)
			}
			stamp := strings.TrimSpace(readCommitted(t, policyLab, strings.TrimSuffix(c.Source, ".raw")+".collected_at"))
			if c.CollectedAt.Format(time.RFC3339Nano) != stamp {
				t.Fatalf("%s collection time changed", c.Source)
			}
		}
	}
	for _, o := range f.Model.Observations() {
		if o.Source != o.Node+"-before-ip-route.json" || o.Plane != netmodel.PlaneFIB || !o.RoutesComplete {
			t.Fatalf("wrong kernel observation: %+v", o)
		}
		var rows []struct {
			Destination string `json:"dst"`
			Protocol    string `json:"protocol"`
			Gateway     string `json:"gateway"`
			Device      string `json:"dev"`
		}
		if err := json.Unmarshal([]byte(readCommitted(t, policyLab, o.Source)), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != len(o.Routes) {
			t.Fatal("kernel route inventory changed")
		}
		for _, r := range o.Routes {
			found := false
			for _, v := range rows {
				if r.Prefix.String() == v.Destination && r.Origin == v.Protocol && len(r.NextHops) == 1 && r.NextHops[0].Interface == v.Device && (v.Gateway == "" && !r.NextHops[0].Addr.IsValid() || r.NextHops[0].Addr.String() == v.Gateway) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s route was not recorded by the kernel: %+v", o.Node, r)
			}
		}
	}
}
