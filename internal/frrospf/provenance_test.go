package frrospf

import "testing"

// TestFixtureInterfacesBelongToTheirNode checks that each node's interface capture
// names only that node's interfaces and router ID. Two daemons that share a
// control socket answer each other's queries, and this check catches that.
func TestFixtureInterfacesBelongToTheirNode(t *testing.T) {
	want := map[string]map[string]string{ // node -> interface -> router ID
		"r1": {"e1": "1.1.1.1", "stub1": "1.1.1.1"},
		"r2": {"e2": "2.2.2.2", "stub2": "2.2.2.2"},
	}
	for _, scenario := range []string{"bcast", "p2p", "mtu"} {
		for node, ifaces := range want {
			c := fixture(t, scenario, node, CommandInterface)
			raw, reason := decodeInterfaces(c.Data)
			if reason != "" {
				t.Fatalf("%s %s: %s", scenario, node, reason)
			}
			if len(raw) != len(ifaces) {
				t.Errorf("%s %s lists %d interfaces, want %d", scenario, node, len(raw), len(ifaces))
			}
			for name, rid := range ifaces {
				rec, ok := raw[name]
				if !ok {
					t.Errorf("%s %s lacks interface %s", scenario, node, name)
					continue
				}
				if rec.RouterID == nil || *rec.RouterID != rid {
					t.Errorf("%s %s interface %s router ID = %v, want %s", scenario, node, name, rec.RouterID, rid)
				}
			}
		}
	}
}
