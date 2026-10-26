package routepath

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func policyFile(t *testing.T) File {
	t.Helper()
	raw, err := os.ReadFile("testdata/policy/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPolicyEvidenceRoundTripsWithoutChangingLegacyEncoding(t *testing.T) {
	f := policyFile(t)
	data, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !sameEvidence(f, back) || !reflect.DeepEqual(f.Policies, back.Policies) {
		t.Fatal("policy evidence was dropped or changed")
	}
	f.Policies = nil
	legacy, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(legacy, []byte("route_policies")) {
		t.Fatal("empty policy evidence changed legacy encoding")
	}
	f.Policies = []PolicyChange{}
	if _, err := Encode(f); err != nil {
		t.Fatalf("empty policy list: %v", err)
	}
	f = policyFile(t)
	now := time.Now()
	for i := range f.Policies[0].Captures {
		f.Policies[0].Captures[i].CollectedAt = now
	}
	if _, err := Encode(f); err != nil {
		t.Fatalf("monotonic timestamp: %v", err)
	}
}

// The topology's FIB observations are derived from the independently captured
// kernel tables. The BGP-to-FIB relationship is deliberately not inferred.
func TestPolicySimulationAgainstGenuineFRREvidence(t *testing.T) {
	f := policyFile(t)
	baseline, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	selector := f.Policies[0].PolicySelector
	s, err := Simulate(f, Failure{Policy: &selector}, addr("10.10.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Considered != s.Unchanged+len(s.Affected) {
		t.Fatal("destination accounting does not reconcile")
	}
	if s.Policy.Considered != 4 || s.Policy.Unchanged != 3 {
		t.Fatalf("policy candidates: %+v", s.Policy)
	}
	a := affected(t, s, "10.10.2.2")
	if a.Impact != ImpactUnknown || a.After.Node != "r1" || a.After.Decision.Kind != KindUnknown || !strings.Contains(a.Reason, "recomputation") {
		t.Fatalf("changed route must stay unknown: %+v", a)
	}
	if len(a.After.Next) != 0 {
		t.Fatal("invented a replacement route")
	}
	for _, a := range s.Affected {
		if a.Impact != ImpactUnknown {
			t.Fatalf("unproven forwarding claim: %+v", a)
		}
	}
	after, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseline, after) {
		t.Fatal("simulation changed its input or downstream observations")
	}
	for _, node := range []string{"r2", "r3"} {
		f.Source = Start{node, "default"}
		dest := "10.10.2.2"
		if node == "r3" {
			dest = "10.10.2.3"
		}
		s, err := Simulate(f, Failure{Policy: &selector}, addr(dest))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := impacts(s)[dest]; ok {
			t.Errorf("%s changed its recorded local delivery", node)
		}
	}
}

func TestPolicyIdentityAndExportRatings(t *testing.T) {
	for _, direction := range []string{"import", "export"} {
		f := policyFile(t)
		p := &f.Policies[0]
		p.Direction = direction
		if direction == "import" {
			// Permitting every prefix without assigning attributes proves a no-op
			// even for candidates absent from the sequential baseline captures.
			editPolicy(t, p, 0, `"weight 100"`, "")
		}
		s, err := Simulate(f, Failure{Policy: &p.PolicySelector}, addr("10.10.2.2"))
		if err != nil {
			t.Fatal(err)
		}
		got := impacts(s)["10.10.2.2"]
		if direction == "import" && got != "" {
			t.Errorf("identity policy impact %s, want none", got)
		}
		if direction == "import" && s.Policy.UnrecordedAfter != "unchanged" {
			t.Fatal("global identity policy did not prove unchanged unrecorded candidates")
		}
		if direction == "export" && got != ImpactUnknown {
			t.Errorf("export impact %s, want unknown", got)
		}
	}
}

func TestPolicySelectorAndTopologyRefusals(t *testing.T) {
	f := policyFile(t)
	s := f.Policies[0].PolicySelector
	cases := []struct {
		name string
		edit func(*File, *Failure)
	}{
		{"missing evidence", func(f *File, _ *Failure) { f.Policies = nil }},
		{"duplicate evidence", func(f *File, _ *Failure) { f.Policies = append(f.Policies, f.Policies[0]) }},
		{"wrong node", func(_ *File, p *Failure) { s := *p.Policy; s.Node = "r9"; p.Policy = &s }},
		{"wrong policy", func(_ *File, p *Failure) { s := *p.Policy; s.Policy = "OTHER"; p.Policy = &s }},
		{"wrong peer", func(_ *File, p *Failure) { s := *p.Policy; s.Peer = "10.0.3.9"; p.Policy = &s }},
		{"wrong VRF", func(_ *File, p *Failure) { s := *p.Policy; s.VRF = "blue"; p.Policy = &s }},
		{"mixed failure", func(_ *File, p *Failure) { p.Interface = "e1" }},
		{"contradictory failure node", func(_ *File, p *Failure) { p.Node = "r2" }},
		{"tunnel dependencies unproven", func(f *File, _ *Failure) { f.Tunnels = []Tunnel{{Node: "r2"}} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := policyFile(t)
			p := Failure{Policy: &s}
			c.edit(&f, &p)
			if _, err := Simulate(f, p, addr("10.10.2.2")); err == nil {
				t.Fatal("accepted unsafe policy selector")
			}
		})
	}
	raw, err := os.ReadFile("testdata/policy/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{`"route_policies": [`, `"route_policies": [], "route_policies": [`}, {`"route_policies": [`, `"Route_policies": [`}, {`"direction": "import"`, `"direction": "import", "direction": "export"`}, {`"command": "show route-map json"`, `"Command": "show route-map json"`}, {`"policy": "R3-IN"`, `"policy": "R3-IN", "unknown": true`}} {
		if _, err := Decode(bytes.Replace(raw, []byte(pair[0]), []byte(pair[1]), 1)); err == nil {
			t.Fatalf("accepted malformed new evidence: %s", pair[1])
		}
	}
	if _, err := SimulateBlast(f, Failure{Policy: &s}, true, nil); err == nil {
		t.Fatal("accepted unsupported multi-source policy simulation")
	}
}

func TestPolicyLegacyExplainOutputIsByteIdenticalWhenUnused(t *testing.T) {
	f := policyFile(t)
	with := Explain(f, addr("10.10.2.2"))
	f.Policies = nil
	without := Explain(f, addr("10.10.2.2"))
	a, _ := json.Marshal(with)
	b, _ := json.Marshal(without)
	if !bytes.Equal(a, b) || with.Text() != without.Text() {
		t.Fatal("unused policy evidence changed legacy explanation bytes")
	}
	// Existing structural selectors also keep their byte-identical reports.
	f = policyFile(t)
	withSim, err := Simulate(f, Failure{Node: "r2"}, addr("10.10.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	f.Policies = nil
	withoutSim, err := Simulate(f, Failure{Node: "r2"}, addr("10.10.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	a, _ = json.Marshal(withSim)
	b, _ = json.Marshal(withoutSim)
	if !bytes.Equal(a, b) || withSim.Text() != withoutSim.Text() {
		t.Fatal("unused policies changed structural simulation bytes")
	}
}

func TestPolicyEmptyExportTableStillHasUnknownForwarding(t *testing.T) {
	f := policyFile(t)
	p := &f.Policies[0]
	p.Direction = "export"
	editPolicy(t, p, 2, `"acceptedPrefixCounter":2`, `"acceptedPrefixCounter":0`)
	c := &p.Captures[3]
	body, err := policyBody(*c, p.Node, policyTableCommand, false)
	if err != nil {
		t.Fatal(err)
	}
	var table map[string]any
	if err := json.Unmarshal(body, &table); err != nil {
		t.Fatal(err)
	}
	table["routes"] = map[string]any{}
	table["totalRoutes"], table["totalPaths"], table["numRoutes"] = 0, 0, 0
	raw, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	c.Raw = policyTableCommand + "\r\n" + string(raw) + "\r\nr1> "
	sum := sha256.Sum256([]byte(c.Raw))
	c.SHA256 = hex.EncodeToString(sum[:])
	s, err := Simulate(f, Failure{Policy: &p.PolicySelector}, addr("10.10.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	if a := affected(t, s, "10.10.2.2"); a.Impact != ImpactUnknown {
		t.Fatalf("empty export table claimed known forwarding: %+v", a)
	}
	if s.Policy.Considered != 0 || s.Policy.UnrecordedAfter != "unknown" {
		t.Fatalf("empty export inventory claimed complete identities: %+v", s.Policy)
	}
}
