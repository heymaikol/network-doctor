package routepath

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func livePolicy(t *testing.T) PolicyChange {
	t.Helper()
	raw, err := os.ReadFile("testdata/policy/topology.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Policies []PolicyChange `json:"route_policies"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	return file.Policies[0]
}

// editPolicy is explicitly synthetic: it changes a copy, never a live capture.
func editPolicy(t *testing.T, p *PolicyChange, index int, old, new string) {
	t.Helper()
	c := &p.Captures[index]
	if !strings.Contains(c.Raw, old) {
		t.Fatalf("fixture lacks %q", old)
	}
	c.Raw = strings.Replace(c.Raw, old, new, 1)
	sum := sha256.Sum256([]byte(c.Raw))
	c.SHA256 = hex.EncodeToString(sum[:])
}

func TestPolicyEvaluationAgainstLiveCaptures(t *testing.T) {
	p := livePolicy(t)
	got, err := EvaluatePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Considered != 4 || got.Unchanged != 3 || len(got.Routes) != 4 || len(got.Evidence) != 4 {
		t.Fatalf("unexpected counts: %+v", got)
	}
	for _, r := range got.Routes {
		want := "unchanged"
		if r.Prefix == "10.10.2.0/24" {
			want = "unknown"
			if r.SelectedBefore != "10.0.1.2" || !strings.Contains(r.Reason, "recomputation") {
				t.Fatalf("bad changed selection: %+v", r)
			}
		}
		if r.SelectionAfter != want {
			t.Errorf("%s = %s, want %s", r.Prefix, r.SelectionAfter, want)
		}
	}
	// A synthetic identity policy proves the unchanged rating; export stays conservative.
	for _, direction := range []string{"import", "export"} {
		p := livePolicy(t)
		p.Direction = direction
		editPolicy(t, &p, 0, `"weight 100"`, `"weight 0"`)
		got, err := EvaluatePolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		if direction == "import" && got.Unchanged != got.Considered {
			t.Errorf("import identity policy: %+v", got)
		}
		if direction == "export" {
			if got.Affected != got.Considered {
				t.Fatalf("export eligibility claimed proven: %+v", got)
			}
			for _, r := range got.Routes {
				if r.SelectionAfter != "unchanged" || r.AdvertisementAfter != "unknown" || r.Outcome != "unknown" {
					t.Fatalf("invalid export claim: %+v", r)
				}
			}
		}
	}
}

func TestPolicyRefusesIncompleteAmbiguousAndContradictoryEvidence(t *testing.T) {
	cases := []struct {
		name string
		edit func(*PolicyChange)
	}{
		{"missing node", func(p *PolicyChange) { p.Node = "" }},
		{"unknown direction", func(p *PolicyChange) { p.Direction = "in" }},
		{"unverified VRF", func(p *PolicyChange) { p.VRF = "blue" }},
		{"unclean identifier", func(p *PolicyChange) { p.Policy = "R3-IN\n" }},
		{"unknown peer", func(p *PolicyChange) { p.Peer = "10.0.3.9" }},
		{"IPv6 producer unavailable", func(p *PolicyChange) { p.Peer = "2001:db8::1" }},
		{"incomplete capture set", func(p *PolicyChange) { p.Captures = p.Captures[:3] }},
		{"duplicate command", func(p *PolicyChange) { p.Captures[1] = p.Captures[0] }},
		{"duplicate source", func(p *PolicyChange) { p.Captures[1].Source = p.Captures[0].Source }},
		{"whitespace source", func(p *PolicyChange) { p.Captures[0].Source = " " }},
		{"missing source", func(p *PolicyChange) { p.Captures[0].Source = "" }},
		{"missing timestamp", func(p *PolicyChange) { p.Captures[0].CollectedAt = time.Time{} }},
		{"wrong version", func(p *PolicyChange) { p.Captures[0].FRRVersion = "10.8.0" }},
		{"checksum mismatch", func(p *PolicyChange) { p.Captures[0].SHA256 = strings.Repeat("0", 64) }},
		{"wrong command", func(p *PolicyChange) { p.Captures[0].Command = "show route-map" }},
		{"wrong prompt", func(p *PolicyChange) { editPolicy(t, p, 0, "r1# ", "r9# ") }},
		{"trailing data", func(p *PolicyChange) { editPolicy(t, p, 0, "r1# ", "r1# extra") }},
		{"UTF8", func(p *PolicyChange) { editPolicy(t, p, 0, `"R3-IN"`, `"R3-IN`+string([]byte{255})+`"`) }},
		{"duplicate key", func(p *PolicyChange) { editPolicy(t, p, 0, `"rules":[`, `"rules":[],"rules":[`) }},
		{"null rule", func(p *PolicyChange) { editPolicy(t, p, 0, `"sequenceNumber":10`, `"sequenceNumber":null`) }},
		{"unknown policy", func(p *PolicyChange) { p.Policy = "missing" }},
		{"missing clauses", func(p *PolicyChange) { editPolicy(t, p, 0, `"matchClauses":[`, `"matchClauses":null,"extra":[`) }},
		{"unsupported match", func(p *PolicyChange) { editPolicy(t, p, 0, "ip address prefix-list P10-2", "community C") }},
		{"multiple matches", func(p *PolicyChange) {
			editPolicy(t, p, 0, `"ip address prefix-list P10-2"`, `"ip address prefix-list P10-2","ip address prefix-list P10-2"`)
		}},
		{"unsupported set", func(p *PolicyChange) { editPolicy(t, p, 0, "weight 100", "local-preference 100") }},
		{"weight overflow", func(p *PolicyChange) { editPolicy(t, p, 0, "weight 100", "weight 65536") }},
		{"weight noncanonical", func(p *PolicyChange) { editPolicy(t, p, 0, "weight 100", "weight 0100") }},
		{"call or goto", func(p *PolicyChange) { editPolicy(t, p, 0, "Exit routemap", "Goto 20") }},
		{"duplicate rule order", func(p *PolicyChange) { editPolicy(t, p, 0, `"sequenceNumber":20`, `"sequenceNumber":10`) }},
		{"rule sequence overflow", func(p *PolicyChange) { editPolicy(t, p, 0, `"sequenceNumber":20`, `"sequenceNumber":65536`) }},
		{"pending route map", func(p *PolicyChange) { editPolicy(t, p, 0, `"processedChange":false`, `"processedChange":true`) }},
		{"unknown semantic field", func(p *PolicyChange) { editPolicy(t, p, 0, `"rules":[`, `"call":"OTHER","rules":[`) }},
		{"missing referenced list", func(p *PolicyChange) { editPolicy(t, p, 1, `"P10-2"`, `"OTHER"`) }},
		{"prefix length range unverified", func(p *PolicyChange) { editPolicy(t, p, 1, `"sequenceNumber":5`, `"sequenceNumber":5,"ge":24`) }},
		{"noncanonical prefix", func(p *PolicyChange) { editPolicy(t, p, 1, "10.10.2.0/24", "10.10.2.1/24") }},
		{"wrong prefix family", func(p *PolicyChange) { editPolicy(t, p, 1, `"IPv4"`, `"IPv6"`) }},
		{"contradictory AS", func(p *PolicyChange) { editPolicy(t, p, 2, `"localAs":65001`, `"localAs":65009`) }},
		{"contradictory router ID", func(p *PolicyChange) { editPolicy(t, p, 2, "1.1.1.1", "9.9.9.9") }},
		{"peer down", func(p *PolicyChange) { editPolicy(t, p, 2, `"Established"`, `"Active"`) }},
		{"existing policy", func(p *PolicyChange) {
			editPolicy(t, p, 2, `"acceptedPrefixCounter":2`, `"routeMapForIncomingAdvertisements":"OLD","acceptedPrefixCounter":2`)
		}},
		{"malformed policy identifier", func(p *PolicyChange) {
			editPolicy(t, p, 2, `"acceptedPrefixCounter":2`, `"routeMapForIncomingAdvertisements":false,"acceptedPrefixCounter":2`)
		}},
		{"wrong table VRF", func(p *PolicyChange) { editPolicy(t, p, 3, `"vrfName": "default"`, `"vrfName": "blue"`) }},
		{"table incomplete", func(p *PolicyChange) { editPolicy(t, p, 3, `"totalPaths": 6`, `"totalPaths": 5`) }},
		{"missing bestpath", func(p *PolicyChange) { editPolicy(t, p, 3, `"bestpath":true`, `"bestpath":false`) }},
		{"ambiguous bestpath", func(p *PolicyChange) {
			editPolicy(t, p, 3, `"peerId":"10.0.1.2","path":"65002"`, `"bestpath":true,"peerId":"10.0.1.2","path":"65002"`)
		}},
		{"stale path", func(p *PolicyChange) { editPolicy(t, p, 3, `"weight":32768`, `"stale":true,"weight":32768`) }},
		{"invalid path", func(p *PolicyChange) { editPolicy(t, p, 3, `"valid":true`, `"valid":false`) }},
		{"missing weight", func(p *PolicyChange) { editPolicy(t, p, 3, `"weight":32768`, `"unreadWeight":32768`) }},
		{"contradictory path prefix", func(p *PolicyChange) { editPolicy(t, p, 3, `"network":"10.10.2.0/24"`, `"network":"10.10.9.0/24"`) }},
		{"contradictory prefix length", func(p *PolicyChange) { editPolicy(t, p, 3, `"prefixLen":24`, `"prefixLen":25`) }},
		{"policy older than baseline", func(p *PolicyChange) { p.Captures[0].CollectedAt = p.Captures[3].CollectedAt.Add(-time.Second) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := livePolicy(t)
			c.edit(&p)
			if _, err := EvaluatePolicy(p); err == nil {
				t.Fatal("accepted unsafe evidence")
			}
		})
	}
}

func TestPolicyImplicitDenyAndExplicitDenyStayUnknown(t *testing.T) {
	for _, direction := range []string{"import", "export"} {
		p := livePolicy(t)
		p.Direction = direction
		editPolicy(t, &p, 0, `"sequenceNumber":20,`+"\r\n"+`        "type":"permit"`, `"sequenceNumber":20,`+"\r\n"+`        "type":"deny"`)
		got, err := EvaluatePolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		if got.Unchanged == got.Considered {
			t.Fatal("deny did not affect any candidate")
		}
		for _, r := range got.Routes {
			if r.SelectionAfter != "unknown" && r.SelectionAfter != "unchanged" {
				t.Fatal("invented replacement route")
			}
		}
	}
}

func TestPolicySelectorNamesEveryScopeElement(t *testing.T) {
	for _, spec := range []string{"r1:default:import:10.0.3.3:R3-IN", "r1:default:export:10.0.3.3:R3-IN"} {
		if _, err := ParsePolicySelector(spec); err != nil {
			t.Fatal(err)
		}
	}
	for _, spec := range []string{"r1", "r1:import:10.0.3.3:R3-IN", "r1::import:10.0.3.3:R3-IN", "r1:default:import::R3-IN", "r1:default:import:10.0.3.3:"} {
		if _, err := ParsePolicySelector(spec); err == nil {
			t.Errorf("accepted %q", spec)
		}
	}
}

func TestPolicyPrefixListFirstDenyWins(t *testing.T) {
	p := livePolicy(t)
	editPolicy(t, &p, 1, `"type":"permit",`+"\r\n"+`        "prefix":"10.10.2.0/24"`, `"type":"deny",`+"\r\n"+`        "prefix":"10.10.2.0/24"`)
	editPolicy(t, &p, 1, `"entries":[`, `"entries":[{"sequenceNumber":1,"type":"deny","prefix":"10.10.2.0/24"},`)
	// A later permit for the same exact prefix must not overwrite the first deny.
	editPolicy(t, &p, 1, `"sequenceNumber":5,`+"\r\n"+`        "type":"deny"`, `"sequenceNumber":5,`+"\r\n"+`        "type":"permit"`)
	got, err := EvaluatePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Unchanged != got.Considered {
		t.Fatalf("later permit overwrote the first deny: %+v", got)
	}
}

func FuzzPolicyChange(f *testing.F) {
	raw, err := os.ReadFile("testdata/policy/topology.json")
	if err != nil {
		f.Fatal(err)
	}
	var file struct {
		Policies []json.RawMessage `json:"route_policies"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(file.Policies[0]))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > policyMaxBytes {
			return
		}
		var p PolicyChange
		if json.Unmarshal(data, &p) != nil {
			return
		}
		got, err := EvaluatePolicy(p)
		if err != nil {
			return
		}
		if got.Considered != got.Unchanged+got.Affected || got.Considered != len(got.Routes) {
			t.Fatal("policy counts do not reconcile")
		}
		for _, r := range got.Routes {
			if r.SelectionAfter != "unchanged" && r.SelectionAfter != "unknown" {
				t.Fatal("invented replacement route")
			}
		}
	})
}

func TestPolicyDefaultRouteNullPrefixLengthIsRefused(t *testing.T) {
	p := livePolicy(t)
	c := &p.Captures[3]
	body, err := policyBody(*c, p.Node, policyTableCommand, false)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	path := doc["routes"].(map[string]any)["10.10.3.0/24"].([]any)[0].(map[string]any)
	path["network"], path["prefix"], path["prefixLen"] = "0.0.0.0/0", "0.0.0.0", nil
	doc["routes"] = map[string]any{"0.0.0.0/0": []any{path}}
	doc["totalRoutes"], doc["totalPaths"], doc["numRoutes"] = 1, 1, 1
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	c.Raw = policyTableCommand + "\r\n" + string(raw) + "\r\nr1> "
	sum := sha256.Sum256([]byte(c.Raw))
	c.SHA256 = hex.EncodeToString(sum[:])
	if _, err := EvaluatePolicy(p); err == nil {
		t.Fatal("null prefix length was treated as zero")
	}
}

func TestPolicyExportPeerNeedsNoIncomingPath(t *testing.T) {
	p := livePolicy(t)
	p.Peer = "10.0.3.9"
	c := &p.Captures[2]
	c.Command = "show ip bgp neighbors 10.0.3.9 json"
	c.Raw = strings.ReplaceAll(c.Raw, "10.0.3.3", "10.0.3.9")
	sum := sha256.Sum256([]byte(c.Raw))
	c.SHA256 = hex.EncodeToString(sum[:])
	editPolicy(t, &p, 2, `"acceptedPrefixCounter":2`, `"acceptedPrefixCounter":0`)
	if _, err := EvaluatePolicy(p); err == nil {
		t.Fatal("import with no peer paths was accepted")
	}
	p.Direction = "export"
	got, err := EvaluatePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Affected != got.Considered || got.Unchanged != 0 {
		t.Fatalf("export eligibility claimed proven: %+v", got)
	}
}

func TestPolicyPeerRejectsNonUnicastAddresses(t *testing.T) {
	for _, peer := range []string{"0.0.0.0", "0.1.2.3", "224.0.0.1", "240.0.0.1", "255.255.255.255"} {
		p := livePolicy(t)
		p.Peer = peer
		p.Direction = "export"
		if _, err := EvaluatePolicy(p); err == nil {
			t.Errorf("accepted non-peer %s", peer)
		}
	}
	for _, peer := range []string{"10.0.3.3", "127.0.0.1", "169.254.1.1"} {
		if !policyIPv4(peer) {
			t.Errorf("rejected unicast %s", peer)
		}
	}
}
