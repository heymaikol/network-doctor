package routepath

import (
	"encoding/json"
	"strings"
	"testing"
)

// editPolicyRoutes mutates a synthetic copy and keeps its table totals consistent.
func editPolicyRoutes(t *testing.T, p *PolicyChange, edit func(map[string][]map[string]any)) {
	t.Helper()
	body, err := policyBody(p.Captures[3], p.Node, policyTableCommand, false)
	if err != nil {
		t.Fatal(err)
	}
	var table map[string]json.RawMessage
	if err := json.Unmarshal(body, &table); err != nil {
		t.Fatal(err)
	}
	var routes map[string][]map[string]any
	if err := json.Unmarshal(table["routes"], &routes); err != nil {
		t.Fatal(err)
	}
	edit(routes)
	paths := 0
	for _, rows := range routes {
		paths += len(rows)
	}
	for key, value := range map[string]any{"routes": routes, "totalRoutes": len(routes), "numRoutes": len(routes), "totalPaths": paths} {
		table[key], err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	editPolicy(t, p, 3, string(body), string(raw))
}

func TestPolicyRefusesContradictoryPeerPrefixInventory(t *testing.T) {
	for _, direction := range []string{"import", "export"} {
		t.Run(direction, func(t *testing.T) {
			p := livePolicy(t)
			p.Direction = direction
			// Greptile's reproduction: omit the changed candidate, retaining the
			// selected path and updating every table total to match its contents.
			editPolicyRoutes(t, &p, func(routes map[string][]map[string]any) {
				var kept []map[string]any
				for _, path := range routes["10.10.2.0/24"] {
					if path["peerId"] != p.Peer {
						kept = append(kept, path)
					}
				}
				routes["10.10.2.0/24"] = kept
			})
			got, err := EvaluatePolicy(p)
			if err == nil || !strings.Contains(err.Error(), "peer prefix inventory") {
				t.Fatalf("contradictory peer inventory accepted: %+v, %v", got, err)
			}
			if got.Considered != 0 || len(got.Routes) != 0 {
				t.Fatal("refused inventory returned policy ratings")
			}
		})
	}
}

func TestPolicyRequiresValidAcceptedPrefixCount(t *testing.T) {
	for _, direction := range []string{"import", "export"} {
		for _, value := range []string{"missing", "null", "-1", "-0", "2.0", "2e0", `"2"`, "true", "[]", "{}", "18446744073709551616", "18446744073709551615", "4294967296", "0", "1", "3"} {
			t.Run(direction+"/"+value, func(t *testing.T) {
				p := livePolicy(t)
				p.Direction = direction
				if value == "missing" {
					editPolicy(t, &p, 2, `"acceptedPrefixCounter":2,`, "")
				} else {
					editPolicy(t, &p, 2, `"acceptedPrefixCounter":2`, `"acceptedPrefixCounter":`+value)
				}
				got, err := EvaluatePolicy(p)
				if err == nil {
					t.Fatalf("accepted invalid count: %+v", got)
				}
				if got.Considered != 0 || len(got.Routes) != 0 {
					t.Fatal("invalid count returned policy ratings")
				}
			})
		}
	}
}

func TestPolicyCountsPeerPrefixesInsteadOfPaths(t *testing.T) {
	for _, direction := range []string{"import", "export"} {
		t.Run(direction, func(t *testing.T) {
			p := livePolicy(t)
			p.Direction = direction
			editPolicyRoutes(t, &p, func(routes map[string][]map[string]any) {
				for _, path := range routes["10.10.2.0/24"] {
					if path["peerId"] == p.Peer {
						additional := make(map[string]any, len(path))
						for k, v := range path {
							additional[k] = v
						}
						additional["weight"] = 5
						routes["10.10.2.0/24"] = append(routes["10.10.2.0/24"], additional)
						return
					}
				}
				t.Fatal("fixture lacks the unselected peer path")
			})
			got, err := EvaluatePolicy(p)
			if err != nil || got.Considered != 4 || got.Affected == 0 {
				t.Fatalf("multiple paths counted as multiple prefixes: %+v, %v", got, err)
			}
		})
	}
}

func TestPolicyMatchingCountsDoNotProveCandidateIdentity(t *testing.T) {
	for _, swap := range []bool{false, true} {
		f := policyFile(t)
		p := &f.Policies[0]
		if swap {
			// Preserve cardinality while hiding the candidate affected by weight 100.
			editPolicyRoutes(t, p, func(routes map[string][]map[string]any) {
				for _, path := range routes["10.10.2.0/24"] {
					if path["peerId"] == p.Peer {
						path["peerId"] = "10.0.1.2"
					}
				}
				routes["10.10.9.0/24"][0]["peerId"] = p.Peer
			})
		} else {
			// Matching recorded weights do not prove the attributes of unseen paths.
			editPolicy(t, p, 0, "weight 100", "weight 0")
		}
		s, err := Simulate(f, Failure{Policy: &p.PolicySelector}, addr("10.10.2.2"))
		if err != nil {
			t.Fatal(err)
		}
		if s.Policy.Unchanged != s.Policy.Considered {
			t.Fatal("recorded candidate no-op ratings changed")
		}
		if s.Policy.UnrecordedAfter != "unknown" || !strings.Contains(s.Text(), "Unrecorded candidate effects: unknown") {
			t.Fatal("route identity uncertainty missing from JSON or text")
		}
		if got := impacts(s)["10.10.2.2"]; got != ImpactUnknown {
			t.Fatalf("matching counts claimed complete identities (swap=%v): impact %q", swap, got)
		}
	}
}
