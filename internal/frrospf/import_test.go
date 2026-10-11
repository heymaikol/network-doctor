package frrospf

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// The mutation cases below edit copies of genuine lab captures, or add a record
// by hand. Each case names the edit it makes. A hand-built record shows how the
// importer treats that shape. It is not evidence of what FRR prints.

// neighborsOf returns the neighbors the result wrote for one node, across all of
// its neighbor observations.
func neighborsOf(res Result, node string) []netmodel.Neighbor {
	var out []netmodel.Neighbor
	for _, o := range res.Observations {
		if o.Node == node {
			out = append(out, o.Neighbors...)
		}
	}
	return out
}

// attr returns the value of one attribute, or "" with false when it is absent.
func attr(attrs []netmodel.Attribute, key string) (string, bool) {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value, true
		}
	}
	return "", false
}

// recordWant is the expected outcome of one neighbor record, matched by
// position among the records of the node under test.
type recordWant struct {
	mapped bool
	reason string // substring of Reason; checked only when not mapped
}

// checkRecords compares the records of one node, in report order, with want.
func checkRecords(t *testing.T, recs []Record, node string, want []recordWant) {
	t.Helper()
	var got []Record
	for _, r := range recs {
		if r.Node == node {
			got = append(got, r)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%s has %d records, want %d: %+v", node, len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Mapped != w.mapped {
			t.Errorf("%s record %d mapped=%v, want %v (reason %q)", node, i, got[i].Mapped, w.mapped, got[i].Reason)
		}
		if !w.mapped && !strings.Contains(got[i].Reason, w.reason) {
			t.Errorf("%s record %d reason %q does not contain %q", node, i, got[i].Reason, w.reason)
		}
	}
}

// capNotes returns the notes of the capture for node and command.
func capNotes(t *testing.T, res Result, node, command string) []string {
	t.Helper()
	for _, cr := range res.Report.Captures {
		if cr.Node == node && cr.Command == command {
			return cr.Notes
		}
	}
	t.Fatalf("no capture report for %s %s", node, command)
	return nil
}

// find returns the index of the capture for node and command in caps.
func find(t *testing.T, caps []Capture, node, command string) int {
	t.Helper()
	for i, c := range caps {
		if c.Node == node && c.Command == command {
			return i
		}
	}
	t.Fatalf("no capture for %s %s", node, command)
	return -1
}

// editFirstNeighbor applies edit to the first neighbor record of a detail payload.
// The lab captures hold one neighbor key, so the choice is deterministic.
func editFirstNeighbor(t testing.TB, data []byte, edit func(rec map[string]any)) []byte {
	t.Helper()
	return mutateJSON(t, data, func(top map[string]any) {
		nbrs := top["neighbors"].(map[string]any)
		key := slices.Sorted(maps.Keys(nbrs))[0]
		edit(nbrs[key].([]any)[0].(map[string]any))
	})
}

// editInterface applies edit to one named interface of an interface payload.
func editInterface(t testing.TB, data []byte, name string, edit func(rec map[string]any)) []byte {
	t.Helper()
	return mutateJSON(t, data, func(top map[string]any) {
		ifaces := top["interfaces"].(map[string]any)
		edit(ifaces[name].(map[string]any))
	})
}

// TestFixturesAreGenuineFramedOutput checks every recorded capture used here. Each
// must be a single strict JSON object after unframing, and each scenario's
// version record must name FRR 10.7.0. A fixture that drifts from this fails.
func TestFixturesAreGenuineFramedOutput(t *testing.T) {
	scenarios, err := filepath.Glob(filepath.Join(fixtureRoot, "*", "ospfd-version.txt"))
	if err != nil || len(scenarios) == 0 {
		t.Fatalf("no scenarios under %s: %v", fixtureRoot, err)
	}
	for _, vf := range scenarios {
		scenario := filepath.Base(filepath.Dir(vf))
		version := readFile(t, vf)
		if !strings.Contains(string(version), "ospfd version 10.7.0") {
			t.Errorf("%s: version record %q does not name 10.7.0", scenario, version)
		}
		for _, node := range []string{"r1", "r2"} {
			for _, cmd := range []string{CommandNeighborDetail, CommandInterface} {
				raw := filepath.Join(fixtureRoot, scenario, node+"-"+strings.ReplaceAll(cmd, " ", "_")+".raw")
				if _, err := os.Stat(raw); err != nil {
					continue // this scenario did not run that node
				}
				c := fixture(t, scenario, node, cmd)
				if err := checkStrictJSON(c.Data); err != nil {
					t.Errorf("%s %s %s: payload is not strict JSON: %v", scenario, node, cmd, err)
				}
			}
		}
	}
}

// TestImportBroadcastCapturesMapBothWays imports the genuine broadcast lab and
// checks that each router's neighbor record names the other router's interface.
func TestImportBroadcastCapturesMapBothWays(t *testing.T) {
	res, err := Import(broadcastCaptures(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range res.Report.Captures {
		if !cr.Accepted {
			t.Errorf("%s refused: %s", cr.Source, cr.Reason)
		}
	}
	if len(res.Observations) != 4 {
		t.Fatalf("got %d observations, want 4", len(res.Observations))
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{mapped: true}})
	checkRecords(t, res.Report.Records, "r2", []recordWant{{mapped: true}})

	want := map[string]struct{ local, remoteNode, remoteIface, addr, rid string }{
		"r1": {"e1", "r2", "e2", "10.0.1.2", "2.2.2.2"},
		"r2": {"e2", "r1", "e1", "10.0.1.1", "1.1.1.1"},
	}
	for node, w := range want {
		recs := neighborsOf(res, node)
		if len(recs) != 1 {
			t.Fatalf("%s has %d neighbors, want 1", node, len(recs))
		}
		n := recs[0]
		if n.LocalInterface != w.local || n.RemoteNode != w.remoteNode || n.RemoteInterface != w.remoteIface || n.RemoteAddr.String() != w.addr {
			t.Errorf("%s neighbor = %+v, want local %s to %s %s at %s", node, n, w.local, w.remoteNode, w.remoteIface, w.addr)
		}
		if state, ok := attr(n.Attributes, keyState); !ok || state != "Full" {
			t.Errorf("%s ospf.state = %q, want Full", node, state)
		}
		if rid, ok := attr(n.Attributes, keyRouterID); !ok || rid != w.rid {
			t.Errorf("%s ospf.router_id = %q, want %s", node, rid, w.rid)
		}
	}

	detail := fixture(t, "bcast", "r1", CommandNeighborDetail)
	for _, o := range res.Observations {
		if o.Plane != netmodel.PlaneControl {
			t.Errorf("%s plane = %q, want control", o.Node, o.Plane)
		}
		if o.NeighborsComplete || o.RoutesComplete {
			t.Errorf("%s observation claims completeness: neighbors=%v routes=%v", o.Node, o.NeighborsComplete, o.RoutesComplete)
		}
		if o.Node == "r1" && len(o.Neighbors) > 0 {
			if o.Source != detail.Source || !o.CollectedAt.Equal(detail.CollectedAt) {
				t.Errorf("provenance = %+v, want source %q at %s", o.Provenance, detail.Source, detail.CollectedAt)
			}
		}
	}
}

// TestImportInterfaceObservationsCarryAddressAndRouterID checks the interface
// side: each captured address and router ID reaches the observation.
func TestImportInterfaceObservationsCarryAddressAndRouterID(t *testing.T) {
	res, err := Import(broadcastCaptures(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range res.Observations {
		if o.Node != "r1" || len(o.Neighbors) > 0 {
			continue
		}
		byName := map[string]netmodel.Interface{}
		for _, i := range o.Interfaces {
			byName[i.Name] = i
		}
		e1, ok := byName["e1"]
		if !ok {
			t.Fatalf("r1 interfaces %v lack e1", o.Interfaces)
		}
		if len(e1.Addresses) != 1 || e1.Addresses[0].String() != "10.0.1.1/24" {
			t.Errorf("e1 addresses = %v, want 10.0.1.1/24", e1.Addresses)
		}
		if rid, _ := attr(e1.Attributes, keyRouterID); rid != "1.1.1.1" {
			t.Errorf("e1 ospf.router_id = %q, want 1.1.1.1", rid)
		}
		if stub, ok := byName["stub1"]; !ok || len(stub.Addresses) != 1 {
			t.Errorf("stub1 not written with its address: %+v", stub)
		}
	}
}

// TestImportNonFullStatesPassThrough imports the genuine MTU-mismatch lab, where
// the adjacency stays below Full. Each side's state is written as FRR reports it.
func TestImportNonFullStatesPassThrough(t *testing.T) {
	res, err := Import([]Capture{
		fixture(t, "mtu", "r1", CommandInterface),
		fixture(t, "mtu", "r1", CommandNeighborDetail),
		fixture(t, "mtu", "r2", CommandInterface),
		fixture(t, "mtu", "r2", CommandNeighborDetail),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"r1": "Exchange", "r2": "ExStart"}
	for node, state := range want {
		recs := neighborsOf(res, node)
		if len(recs) != 1 {
			t.Fatalf("%s has %d neighbors, want 1", node, len(recs))
		}
		if got, _ := attr(recs[0].Attributes, keyState); got != state {
			t.Errorf("%s ospf.state = %q, want %q", node, got, state)
		}
	}
}

// TestImportEmptyAndUnavailableOutput separates evidence from failure. A valid
// empty list is accepted. Output that carries no neighbors or interfaces object
// is refused, so a command that did not run is never read as an empty neighbor
// list.
func TestImportEmptyAndUnavailableOutput(t *testing.T) {
	tests := []struct {
		name     string
		c        Capture
		accepted bool
		empty    bool
		reason   string
	}{
		{"empty list, no neighbors", fixture(t, "empty", "r1", CommandNeighborDetail), true, true, ""},
		{"empty list with a configured NBMA neighbor absent", fixture(t, "nbma", "r1", CommandNeighborDetail), true, true, ""},
		{"OSPF not running, neighbor command", fixture(t, "noinst", "r2", CommandNeighborDetail), false, false, `no "neighbors" object`},
		{"OSPF not running, interface command", fixture(t, "noinst", "r2", CommandInterface), false, false, `no "interfaces" object`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Import([]Capture{tt.c})
			if err != nil {
				t.Fatal(err)
			}
			cr := res.Report.Captures[0]
			if cr.Accepted != tt.accepted || cr.Empty != tt.empty {
				t.Errorf("accepted=%v empty=%v, want accepted=%v empty=%v (reason %q)", cr.Accepted, cr.Empty, tt.accepted, tt.empty, cr.Reason)
			}
			if !strings.Contains(cr.Reason, tt.reason) {
				t.Errorf("reason %q does not contain %q", cr.Reason, tt.reason)
			}
			if tt.accepted && len(res.Observations) != 1 {
				t.Errorf("accepted empty capture wrote %d observations, want 1", len(res.Observations))
			}
			if !tt.accepted && len(res.Observations) != 0 {
				t.Errorf("refused capture wrote %d observations, want 0", len(res.Observations))
			}
		})
	}
}

// TestImportRefusesCaptureMetadata checks the declared facts. A capture with any
// missing or invalid fact is refused whole, and nothing is inferred to fill in.
func TestImportRefusesCaptureMetadata(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(c *Capture)
		reason string
	}{
		{"empty source", func(c *Capture) { c.Source = "" }, "source is empty"},
		{"control characters in source", func(c *Capture) { c.Source = "frr\x1b[2J" }, "control or invisible characters"},
		{"empty node", func(c *Capture) { c.Node = "" }, "node is empty"},
		{"control characters in node", func(c *Capture) { c.Node = "r1\n" }, "control or invisible characters"},
		{"empty vrf", func(c *Capture) { c.VRF = "" }, "vrf is empty"},
		{"zero collection time", func(c *Capture) { c.CollectedAt = time.Time{} }, "collected_at is zero"},
		{"other FRR version", func(c *Capture) { c.FRRVersion = "10.7.1" }, "FRR version"},
		{"version not declared", func(c *Capture) { c.FRRVersion = "" }, "FRR version"},
		{"unsupported command", func(c *Capture) { c.Command = "show ip ospf vrf all neighbor detail json" }, "not supported"},
		{"output over the size limit", func(c *Capture) { c.Data = []byte(strings.Repeat(" ", MaxCaptureBytes+1)) }, "exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fixture(t, "bcast", "r1", CommandNeighborDetail)
			tt.edit(&c)
			res, err := Import([]Capture{c})
			if err != nil {
				t.Fatal(err)
			}
			cr := res.Report.Captures[0]
			if cr.Accepted || !strings.Contains(cr.Reason, tt.reason) {
				t.Errorf("accepted=%v reason=%q, want refused with %q", cr.Accepted, cr.Reason, tt.reason)
			}
			if len(res.Observations) != 0 {
				t.Errorf("refused capture wrote %d observations", len(res.Observations))
			}
		})
	}
}

// TestImportRefusesDuplicateCaptures refuses every capture that repeats a source
// label or a node, VRF, and command. Neither side is chosen. Captures that do not
// repeat are still accepted.
func TestImportRefusesDuplicateCaptures(t *testing.T) {
	tests := []struct {
		name     string
		extra    func(r1Detail, r2Detail Capture) Capture
		refused  int
		accepted int
		reason   string
		r1Want   []recordWant
	}{
		{
			name: "source label reused",
			extra: func(r1Detail, r2Detail Capture) Capture {
				c := r2Detail
				c.Node, c.Source = "r3", r1Detail.Source
				return c
			},
			refused:  2,
			accepted: 3,
			reason:   "source label",
			r1Want:   nil,
		},
		{
			name: "node, VRF, and command repeated under a new label",
			extra: func(_, r2Detail Capture) Capture {
				c := r2Detail
				c.Source = "copy of r2 neighbor detail"
				return c
			},
			refused:  2,
			accepted: 3,
			reason:   "captures give",
			r1Want:   []recordWant{{mapped: true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := broadcastCaptures(t)
			r1Detail := caps[find(t, caps, "r1", CommandNeighborDetail)]
			r2Detail := caps[find(t, caps, "r2", CommandNeighborDetail)]
			caps = append(caps, tt.extra(r1Detail, r2Detail))

			res, err := Import(caps)
			if err != nil {
				t.Fatal(err)
			}
			var refused, accepted int
			for _, cr := range res.Report.Captures {
				if cr.Accepted {
					accepted++
					continue
				}
				refused++
				if !strings.Contains(cr.Reason, tt.reason) {
					t.Errorf("%s refused with %q, want %q", cr.Source, cr.Reason, tt.reason)
				}
			}
			if refused != tt.refused || accepted != tt.accepted {
				t.Errorf("refused %d and accepted %d, want %d and %d", refused, accepted, tt.refused, tt.accepted)
			}
			checkRecords(t, res.Report.Records, "r1", tt.r1Want)
		})
	}
}

// TestImportRefusesPayloadShapes checks the strict decoder and the command and
// payload pairing. Each row is output that must not reach an observation.
func TestImportRefusesPayloadShapes(t *testing.T) {
	detail := fixture(t, "bcast", "r1", CommandNeighborDetail)
	ifaceRaw := fixture(t, "bcast", "r1", CommandInterface)
	vrfAll := fixture(t, "bcast", "r1", "show ip ospf vrf all neighbor detail json")
	tests := []struct {
		name   string
		data   []byte
		reason string
	}{
		{"vtysh error line", []byte("% No OSPF instance found\n"), "not JSON output: % No OSPF instance found"},
		{"empty output", nil, "output is empty"},
		{"truncated object", detail.Data[:len(detail.Data)/2], ""},
		{"repeated key", replaceOnce(t, detail.Data, `"neighbors":`, `"neighbors":{},"neighbors":`), "duplicate key"},
		{"data after the object", append(bytes.Clone(detail.Data), "{}"...), "data follows the JSON object"},
		{"interfaces object on the neighbor command", ifaceRaw.Data, "holds an interfaces object"},
		{"neighbors set to null", mutateJSON(t, detail.Data, func(top map[string]any) { top["neighbors"] = nil }), `"neighbors" is null`},
		{"ifaceAddress of the wrong JSON type", editFirstNeighbor(t, detail.Data, func(rec map[string]any) { rec["ifaceAddress"] = 10 }), "malformed neighbor output"},
		{"nesting past the depth bound", []byte(`{"neighbors":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`), "nests too deeply"},
		{"VRF listing under the default-VRF command", vrfAll.Data, `no "neighbors" object`},
		{"neighbor field spelled in a second case", editFirstNeighbor(t, detail.Data, func(rec map[string]any) { rec["NBRSTATE"] = "Full/DR" }), `differs from "nbrState"`},
		{"neighbor field with a folded spelling", editFirstNeighbor(t, detail.Data, func(rec map[string]any) { rec["ifaceAddreſs"] = "10.0.1.2" }), `differs from "ifaceAddress"`},
		{"top-level key in a second case", mutateJSON(t, detail.Data, func(top map[string]any) { top["Neighbors"] = map[string]any{} }), `differs from "neighbors"`},
		{"router ID key that is not an address", mutateJSON(t, detail.Data, func(top map[string]any) {
			top["neighbors"].(map[string]any)["bogus key"] = []any{}
		}), "is not a dotted IPv4 router ID"},
		{"router ID with an empty list", mutateJSON(t, detail.Data, func(top map[string]any) {
			top["neighbors"].(map[string]any)["9.9.9.9"] = []any{}
		}), "is empty"},
		{"router ID with a null list", mutateJSON(t, detail.Data, func(top map[string]any) {
			top["neighbors"].(map[string]any)["9.9.9.9"] = nil
		}), "is null"},
		{"neighbor entries past the bound", []byte(`{"neighbors":{"2.2.2.2":[` + strings.Repeat("{},", 4096) + "{}]}}"), "more than 4096 is refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := detail
			c.Data = tt.data
			res, err := Import([]Capture{c})
			if err != nil {
				t.Fatal(err)
			}
			cr := res.Report.Captures[0]
			if cr.Accepted {
				t.Fatalf("accepted payload; want refusal")
			}
			if !strings.Contains(cr.Reason, tt.reason) {
				t.Errorf("reason %q does not contain %q", cr.Reason, tt.reason)
			}
			if len(res.Observations) != 0 {
				t.Errorf("refused payload wrote %d observations", len(res.Observations))
			}
		})
	}
}

// TestImportRefusesRecordFields refuses one neighbor record for each bad field,
// and keeps the capture. A bad record never refuses its capture.
func TestImportRefusesRecordFields(t *testing.T) {
	base := fixture(t, "bcast", "r1", CommandNeighborDetail)
	tests := []struct {
		name   string
		edit   func(rec map[string]any)
		reason string
	}{
		{"ifaceName carries an address", func(rec map[string]any) { rec["ifaceName"] = "e1:10.0.1.1" }, "address label"},
		{"ifaceName missing", func(rec map[string]any) { delete(rec, "ifaceName") }, "ifaceName is missing"},
		{"ifaceAddress missing", func(rec map[string]any) { delete(rec, "ifaceAddress") }, "ifaceAddress is missing"},
		{"ifaceAddress not IPv4", func(rec map[string]any) { rec["ifaceAddress"] = "10.0.1" }, "not IPv4"},
		{"ifaceAddress IPv4 mapped in IPv6", func(rec map[string]any) { rec["ifaceAddress"] = "::ffff:10.0.1.2" }, "not IPv4"},
		{"nbrState missing", func(rec map[string]any) { delete(rec, "nbrState") }, "nbrState is missing"},
		{"nbrState without a role", func(rec map[string]any) { rec["nbrState"] = "Full" }, "not a state and role pair"},
		{"nbrState with two slashes", func(rec map[string]any) { rec["nbrState"] = "Full/DR/x" }, "not a state and role pair"},
		{"nbrState with an unknown state", func(rec map[string]any) { rec["nbrState"] = "Bogus/DR" }, "not a neighbor state"},
		{"nbrState with an unknown role", func(rec map[string]any) { rec["nbrState"] = "Full/Foo" }, "not DR, Backup, DROther, or -"},
		{"areaId not dotted IPv4", func(rec map[string]any) { rec["areaId"] = "zero" }, "not a dotted IPv4 area"},
		{"areaId with an unknown qualifier", func(rec map[string]any) { rec["areaId"] = "0.0.0.0 [Foo]" }, "qualifier"},
		{"areaId missing", func(rec map[string]any) { delete(rec, "areaId") }, "areaId is missing"},
		{"localIfaceAddress disagrees with the interface", func(rec map[string]any) { rec["localIfaceAddress"] = "10.0.1.9" }, "disagrees with interface"},
		{"localIfaceAddress not IPv4", func(rec map[string]any) { rec["localIfaceAddress"] = "bogus" }, "not IPv4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := broadcastCaptures(t)
			caps[find(t, caps, "r1", CommandNeighborDetail)].Data = editFirstNeighbor(t, base.Data, tt.edit)
			res, err := Import(caps)
			if err != nil {
				t.Fatal(err)
			}
			for _, cr := range res.Report.Captures {
				if !cr.Accepted {
					t.Fatalf("%s refused for a record field: %s", cr.Source, cr.Reason)
				}
			}
			checkRecords(t, res.Report.Records, "r1", []recordWant{{mapped: false, reason: tt.reason}})
		})
	}
}

// TestImportIdentityByAddress covers how a neighbor record finds its peer. Only
// a unique owner of the address in the same VRF maps, and the router ID is a
// cross-check, never a key.
func TestImportIdentityByAddress(t *testing.T) {
	iface := func(caps []Capture) int { return find(t, caps, "r2", CommandInterface) }
	detail := func(caps []Capture) int { return find(t, caps, "r1", CommandNeighborDetail) }
	tests := []struct {
		name  string
		edit  func(caps []Capture) []Capture
		want  []recordWant
		notes string // substring of a peer capture note, when set
	}{
		{
			name: "address owned by two captured interfaces",
			edit: func(caps []Capture) []Capture {
				dup := caps[iface(caps)]
				dup.Node, dup.Source = "r3", "copy of r2 interface"
				return append(caps, dup)
			},
			want: []recordWant{{false, "owned by 2 captured interfaces"}},
		},
		{
			name: "neighbor address is the node's own",
			edit: func(caps []Capture) []Capture {
				i := detail(caps)
				caps[i].Data = editFirstNeighbor(t, caps[i].Data, func(rec map[string]any) { rec["ifaceAddress"] = "10.0.1.1" })
				return caps
			},
			want: []recordWant{{false, "own address"}},
		},
		{
			name: "peer interface address removed",
			edit: func(caps []Capture) []Capture {
				i := iface(caps)
				caps[i].Data = editInterface(t, caps[i].Data, "e2", func(rec map[string]any) {
					delete(rec, "ipAddress")
					delete(rec, "ipAddressPrefixlen")
				})
				return caps
			},
			want:  []recordWant{{false, "has no ipAddress; address ownership incomplete"}},
			notes: "ipAddress is missing",
		},
		{
			name: "peer prefix length out of range",
			edit: func(caps []Capture) []Capture {
				i := iface(caps)
				caps[i].Data = editInterface(t, caps[i].Data, "e2", func(rec map[string]any) { rec["ipAddressPrefixlen"] = 33 })
				return caps
			},
			want:  []recordWant{{false, "whose prefix length is unusable"}},
			notes: "no valid ipAddressPrefixlen",
		},
		{
			name: "address claimed by a second interface whose prefix is missing",
			edit: func(caps []Capture) []Capture {
				dup := caps[iface(caps)]
				dup.Node, dup.Source = "r3", "copy of r2 interface without prefix"
				dup.Data = editInterface(t, dup.Data, "e2", func(rec map[string]any) { delete(rec, "ipAddressPrefixlen") })
				return append(caps, dup)
			},
			want: []recordWant{{false, "owned by 2 captured interfaces"}},
		},
		{
			name: "node's own address held by an interface whose prefix is missing",
			edit: func(caps []Capture) []Capture {
				i := find(t, caps, "r1", CommandInterface)
				caps[i].Data = editInterface(t, caps[i].Data, "stub1", func(rec map[string]any) {
					rec["ipAddress"] = "10.0.1.2"
					delete(rec, "ipAddressPrefixlen")
				})
				return caps
			},
			want: []recordWant{{false, "own address"}},
		},
		{
			name: "valid record with a refused twin on the same link",
			edit: func(caps []Capture) []Capture {
				i := detail(caps)
				caps[i].Data = mutateJSON(t, caps[i].Data, func(top map[string]any) {
					nbrs := top["neighbors"].(map[string]any)
					nbrs["2.2.2.2"] = append(nbrs["2.2.2.2"].([]any), map[string]any{
						"ifaceAddress": "10.0.1.2",
						"areaId":       "0.0.0.0 [Foo]",
						"ifaceName":    "e1",
						"nbrState":     "Init/DR",
					})
				})
				return caps
			},
			want: []recordWant{{false, "2 records for"}, {false, "qualifier"}},
		},
		{
			name: "no interface capture for the node",
			edit: func(caps []Capture) []Capture {
				return []Capture{caps[detail(caps)]}
			},
			want: []recordWant{{false, "no accepted interface capture"}},
		},
		{
			// Refused before mapping, so the node yields no records at all.
			name: "node in a non-default VRF is refused, not mapped",
			edit: func(caps []Capture) []Capture {
				i := detail(caps)
				caps[i].VRF = "blue"
				return caps
			},
			want: nil,
		},
		{
			name: "peer interface in a non-default VRF is refused",
			edit: func(caps []Capture) []Capture {
				i := iface(caps)
				caps[i].VRF = "blue"
				return caps
			},
			want: []recordWant{{false, "address ownership incomplete"}},
		},
		{
			name: "router ID contradicts the peer's report",
			edit: func(caps []Capture) []Capture {
				i := detail(caps)
				caps[i].Data = mutateJSON(t, caps[i].Data, func(top map[string]any) {
					nbrs := top["neighbors"].(map[string]any)
					nbrs["9.9.9.9"] = nbrs["2.2.2.2"]
					delete(nbrs, "2.2.2.2")
				})
				return caps
			},
			want: []recordWant{{false, "disagrees with node"}},
		},
		{
			name: "same local interface and address listed twice",
			edit: func(caps []Capture) []Capture {
				i := detail(caps)
				caps[i].Data = mutateJSON(t, caps[i].Data, func(top map[string]any) {
					nbrs := top["neighbors"].(map[string]any)
					recs := nbrs["2.2.2.2"].([]any)
					nbrs["2.2.2.2"] = append(recs, recs[0])
				})
				return caps
			},
			want: []recordWant{{false, "2 records for"}, {false, "2 records for"}},
		},
		{
			name: "parallel record on another link is refused alone",
			edit: func(caps []Capture) []Capture {
				i := detail(caps)
				caps[i].Data = mutateJSON(t, caps[i].Data, func(top map[string]any) {
					nbrs := top["neighbors"].(map[string]any)
					recs := nbrs["2.2.2.2"].([]any)
					extra := map[string]any{
						"ifaceAddress": "10.10.2.1",
						"areaId":       "0.0.0.0",
						"ifaceName":    "stub1",
						"nbrState":     "Full/DR",
					}
					nbrs["2.2.2.2"] = append(recs, extra)
				})
				return caps
			},
			want: []recordWant{{true, ""}, {false, `outside interface "stub1" subnet`}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := tt.edit(broadcastCaptures(t))
			res, err := Import(caps)
			if err != nil {
				t.Fatal(err)
			}
			checkRecords(t, res.Report.Records, "r1", tt.want)
			if tt.notes != "" {
				found := false
				for _, n := range capNotes(t, res, "r2", CommandInterface) {
					found = found || strings.Contains(n, tt.notes)
				}
				if !found {
					t.Errorf("r2 interface notes %v lack %q", capNotes(t, res, "r2", CommandInterface), tt.notes)
				}
			}
		})
	}
}

// TestImportNoNbrIDNeverIdentifiesAPeer checks the placeholder FRR uses for a
// neighbor with no router ID yet. Its address resolves to r2 here, but the
// record has no router ID to confirm the peer, so it stays unmapped and writes
// no neighbor. The state and address are kept in the report.
func TestImportNoNbrIDNeverIdentifiesAPeer(t *testing.T) {
	caps := broadcastCaptures(t)
	renameNeighborKey(t, caps, "noNbrId")
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{mapped: false, reason: "has no router ID"}})
	if rec := res.Report.Records[0]; rec.State != "Attempt/DROther" || rec.NeighborAddr != "10.0.1.2" {
		t.Errorf("placeholder record lost its state or address: state %q, address %q", rec.State, rec.NeighborAddr)
	}
	if recs := neighborsOf(res, "r1"); len(recs) != 0 {
		t.Errorf("placeholder record wrote %d neighbors, want 0", len(recs))
	}
}

// TestImportNoNbrIDOnlyForAttempt refuses the placeholder for a neighbor in any
// state but Attempt. FRR prints the placeholder only for Attempt, so a Full
// neighbor under it is out of contract, even when its address resolves.
func TestImportNoNbrIDOnlyForAttempt(t *testing.T) {
	caps := broadcastCaptures(t)
	i := find(t, caps, "r1", CommandNeighborDetail)
	caps[i].Data = mutateJSON(t, caps[i].Data, func(top map[string]any) {
		nbrs := top["neighbors"].(map[string]any)
		nbrs["noNbrId"] = nbrs["2.2.2.2"]
		delete(nbrs, "2.2.2.2")
	})
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "printed only for an Attempt neighbor"}})
}

// TestImportDuplicateBlocksEvenWhenTwinHasBadMetadata checks that a capture
// refused for its own metadata still blocks a valid twin with the same node, VRF,
// and command. Both are refused, and nothing is chosen between them.
func TestImportDuplicateBlocksEvenWhenTwinHasBadMetadata(t *testing.T) {
	caps := broadcastCaptures(t)
	twin := caps[find(t, caps, "r2", CommandNeighborDetail)]
	twin.Source, twin.FRRVersion = "copy of r2 neighbor detail", "10.7.1"
	res, err := Import(append(caps, twin))
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range res.Report.Captures {
		if cr.Node == "r2" && cr.Command == CommandNeighborDetail && cr.Accepted {
			t.Errorf("r2 neighbor capture accepted beside its twin: %+v", cr)
		}
	}
}

// TestRefusedCaptureReportHoldsNoControlText checks that the report repeats the
// declared facts of a refused capture only after sanitizing them.
func TestRefusedCaptureReportHoldsNoControlText(t *testing.T) {
	c := fixture(t, "bcast", "r1", CommandNeighborDetail)
	c.Source, c.Node, c.VRF, c.Command = "frr\x1b[31m", "r1\x07", "blue\u202e", "show\n"
	res, err := Import([]Capture{c})
	if err != nil {
		t.Fatal(err)
	}
	cr := res.Report.Captures[0]
	if cr.Accepted {
		t.Fatal("capture with control text accepted")
	}
	for _, s := range []string{cr.Source, cr.Node, cr.VRF, cr.Command} {
		if !plain(s) {
			t.Errorf("report repeats control text %q", s)
		}
	}
}

// TestRefusedTextStaysValidUTF8 checks that a refusal quoting a long vtysh line
// is shortened on a character boundary, not in the middle of one.
func TestRefusedTextStaysValidUTF8(t *testing.T) {
	_, reason := decodeNeighborDetail([]byte("%" + strings.Repeat("é", 60) + "\n"))
	if !strings.HasPrefix(reason, "not JSON output") {
		t.Fatalf("reason %q is not the vtysh refusal", reason)
	}
	if strings.ToValidUTF8(reason, "?") != reason {
		t.Errorf("refusal is not valid UTF-8: %q", reason)
	}
}

// TestImportRefusesNonDefaultVRF checks that default-VRF output cannot be relabeled.
// Both supported commands read the default VRF when none is named, so any other
// VRF label is refused, and nothing maps into that VRF.
func TestImportRefusesNonDefaultVRF(t *testing.T) {
	caps := broadcastCaptures(t)
	for i := range caps {
		caps[i].VRF = "blue"
	}
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range res.Report.Captures {
		if cr.Accepted {
			t.Errorf("default-VRF output accepted under VRF blue: %+v", cr)
		}
		if !strings.Contains(cr.Reason, "only the default VRF") {
			t.Errorf("reason %q does not name the VRF rule", cr.Reason)
		}
	}
	if len(res.Observations) != 0 {
		t.Errorf("%d observations written for VRF blue", len(res.Observations))
	}
}

// TestImportVRFLabelIsExact checks that only the exact label default is read. A
// label that differs in case, spacing, or script is a different VRF name, so it is
// refused rather than folded onto the default VRF.
func TestImportVRFLabelIsExact(t *testing.T) {
	for _, label := range []string{"Default", "DEFAULT", "default ", " default", "dеfault"} {
		c := fixture(t, "bcast", "r1", CommandInterface)
		c.VRF = label
		res, err := Import([]Capture{c})
		if err != nil {
			t.Fatal(err)
		}
		if cr := res.Report.Captures[0]; cr.Accepted {
			t.Errorf("VRF label %q accepted as the default VRF", label)
		}
	}
}

// TestImportRefusesNumberedInstance checks that an ospfInstance field refuses the
// capture whatever its value and spelling. FRR prints the field only for a
// numbered instance, so a capture that carries it is never read as instance zero.
func TestImportRefusesNumberedInstance(t *testing.T) {
	commands := []struct {
		name    string
		capture Capture
	}{
		{CommandNeighborDetail, fixture(t, "bcast", "r1", CommandNeighborDetail)},
		{CommandInterface, fixture(t, "bcast", "r1", CommandInterface)},
	}
	spellings := []string{"ospfInstance", "OSPFINSTANCE", "ospfInſtance"}
	values := []any{1, 0, nil}
	for _, cmd := range commands {
		for _, key := range spellings {
			for _, value := range values {
				t.Run(fmt.Sprintf("%s %s=%v", cmd.name, key, value), func(t *testing.T) {
					c := cmd.capture
					c.Data = mutateJSON(t, c.Data, func(top map[string]any) { top[key] = value })
					res, err := Import([]Capture{c})
					if err != nil {
						t.Fatal(err)
					}
					cr := res.Report.Captures[0]
					if cr.Accepted {
						t.Fatalf("capture with %s=%v accepted", key, value)
					}
					if !strings.Contains(cr.Reason, "numbered OSPF instance") {
						t.Errorf("reason %q does not name the instance rule", cr.Reason)
					}
				})
			}
		}
	}
}

// TestImportDuplicateIgnoresVRFLabel checks that a copy labeled with another VRF
// still conflicts with the default-VRF capture for the same node and command. The
// label on a refused capture cannot be trusted, so it must not split the pair.
func TestImportDuplicateIgnoresVRFLabel(t *testing.T) {
	for _, command := range []string{CommandNeighborDetail, CommandInterface} {
		t.Run(command, func(t *testing.T) {
			caps := broadcastCaptures(t)
			orig := caps[find(t, caps, "r2", command)]
			twin := orig
			twin.Source, twin.VRF = "copy labeled blue", "blue"
			res, err := Import(append(caps, twin))
			if err != nil {
				t.Fatal(err)
			}
			for _, cr := range res.Report.Captures {
				if cr.Node != "r2" || cr.Command != command || cr.VRF != "default" {
					continue
				}
				if cr.Accepted {
					t.Errorf("r2 capture accepted beside its blue twin: %+v", cr)
				}
				if !strings.Contains(cr.Reason, "captures give") {
					t.Errorf("reason %q does not name the duplicate rule", cr.Reason)
				}
			}
		})
	}
}

// TestImportDuplicateSeesSanitizedNode checks that a twin whose node name differs
// only by an invisible character still blocks the valid capture. The report shows
// the sanitized name, so the two must count as one.
func TestImportDuplicateSeesSanitizedNode(t *testing.T) {
	caps := broadcastCaptures(t)
	twin := caps[find(t, caps, "r2", CommandNeighborDetail)]
	twin.Source, twin.Node = "copy of r2 neighbor detail", "r2\u200b"
	res, err := Import(append(caps, twin))
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range res.Report.Captures {
		if cr.Node == "r2" && cr.Command == CommandNeighborDetail && cr.Accepted {
			t.Errorf("r2 neighbor capture accepted beside its invisible-character twin: %+v", cr)
		}
	}
}

// TestRefusedReasonHoldsNoControlText checks that a refusal quoting a key from the
// input is sanitized. encoding/json puts map keys into its type errors, so a
// crafted key reaches the reason unless the report cleans it.
func TestRefusedReasonHoldsNoControlText(t *testing.T) {
	neighbors := fixture(t, "bcast", "r1", CommandNeighborDetail)
	neighbors.Data = []byte(`{"neighbors":{"\u001b[2J\u202eEVIL":[{"ifaceAddress":10}]}}`)
	ifaces := fixture(t, "bcast", "r1", CommandInterface)
	ifaces.Data = []byte(`{"interfaces":{"\u001b]0;pwn\u0007x":{"ipAddress":10}}}`)
	for _, c := range []Capture{neighbors, ifaces} {
		res, err := Import([]Capture{c})
		if err != nil {
			t.Fatal(err)
		}
		cr := res.Report.Captures[0]
		if cr.Accepted {
			t.Fatalf("capture with a crafted key accepted: %+v", cr)
		}
		if !plain(cr.Reason) {
			t.Errorf("reason repeats control text: %q", cr.Reason)
		}
	}
}

// TestDecodeLimitsCountRecords checks the entry bounds. The neighbor bound counts
// records, not router-ID keys. The interface bound counts interfaces.
func TestDecodeLimitsCountRecords(t *testing.T) {
	neighbors := func(n int) []byte {
		return []byte(`{"neighbors":{"2.2.2.2":[` + strings.Repeat("{},", n-1) + "{}]}}")
	}
	if _, reason := decodeNeighborDetail(neighbors(maxEntries)); reason != "" {
		t.Errorf("%d records refused: %s", maxEntries, reason)
	}
	if _, reason := decodeNeighborDetail(neighbors(maxEntries + 1)); !strings.Contains(reason, "4097 neighbor records") {
		t.Errorf("%d records: reason %q", maxEntries+1, reason)
	}
	ifaces := func(n int) []byte {
		var b strings.Builder
		b.WriteString(`{"interfaces":{`)
		for i := range n {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"e%d":{}`, i)
		}
		b.WriteString("}}")
		return []byte(b.String())
	}
	if _, reason := decodeInterfaces(ifaces(maxEntries)); reason != "" {
		t.Errorf("%d interfaces refused: %s", maxEntries, reason)
	}
	if _, reason := decodeInterfaces(ifaces(maxEntries + 1)); !strings.Contains(reason, "4097 interfaces") {
		t.Errorf("%d interfaces: reason %q", maxEntries+1, reason)
	}
}

// TestDecodeRefusesTheSameKeyEveryRun checks that one input with several bad
// router-ID keys gives the same refusal on every run. Keys are walked in order.
func TestDecodeRefusesTheSameKeyEveryRun(t *testing.T) {
	data := []byte(`{"neighbors":{"bad c":[],"bad a":[],"bad b":[]}}`)
	for range 20 {
		if _, reason := decodeNeighborDetail(data); !strings.Contains(reason, `"bad a"`) {
			t.Fatalf("reason %q does not name the first sorted key", reason)
		}
	}
}

// TestInterfaceNamesAreNotFieldNames checks that a map key naming an interface is
// not held to the decoded field names, while a field spelled in a second case
// still is.
func TestInterfaceNamesAreNotFieldNames(t *testing.T) {
	if err := checkStrictJSON([]byte(`{"interfaces":{"RouterId":{"ipAddress":"10.0.0.1"}}}`)); err != nil {
		t.Errorf("interface named like a field refused: %v", err)
	}
	if err := checkStrictJSON([]byte(`{"interfaces":{"e1":{"routerid":"1.1.1.1"}}}`)); err == nil {
		t.Error(`field spelled "routerid" accepted`)
	}
	if err := checkStrictJSON([]byte(`{"interfaces":{"ospfInstance":{}}}`)); err != nil {
		t.Errorf("interface named ospfInstance refused: %v", err)
	}
}

// TestDecodedKeysMatchJSONTags checks that the folding guard lists exactly the
// JSON names the decoders read, so a new tag cannot skip the guard.
func TestDecodedKeysMatchJSONTags(t *testing.T) {
	want := map[string]bool{}
	for _, k := range structDecodedKeys {
		want[k] = true
	}
	got := map[string]bool{}
	for _, v := range []any{detailPayload{}, detailRecord{}, interfacePayload{}, interfaceRecord{}} {
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			got[rt.Field(i).Tag.Get("json")] = true
		}
	}
	if !maps.Equal(got, want) {
		t.Errorf("json tags %v differ from decodedKeys %v", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
	}
}

// TestImportNoNbrIDFromLabStaysUnmapped uses the placeholder record that FRR
// printed in the NBMA lab. The peer never came up, so no captured interface owns
// its address. The record is kept, unmapped, and writes no neighbor.
func TestImportNoNbrIDFromLabStaysUnmapped(t *testing.T) {
	res, err := Import([]Capture{
		fixture(t, "nbma", "r1", CommandInterface),
		earlyNBMANeighbors(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{
		{mapped: false, reason: "has no router ID"},
	})
	if recs := neighborsOf(res, "r1"); len(recs) != 0 {
		t.Errorf("unmapped placeholder wrote %d neighbors, want 0", len(recs))
	}
}

// TestImportIsIndependentOfCaptureOrder checks that the same captures give the
// same report in any input order.
func TestImportIsIndependentOfCaptureOrder(t *testing.T) {
	forward := broadcastCaptures(t)
	reversed := slices.Clone(forward)
	slices.Reverse(reversed)

	a, err := Import(forward)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Import(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("results differ with input order:\n%+v\n%+v", a.Report, b.Report)
	}
}

// TestImportRefusesUnknownCommandShapesWhenPaired checks that a payload cannot
// satisfy a command it does not hold, even when it is otherwise valid JSON.
func TestImportRefusesUnknownCommandShapesWhenPaired(t *testing.T) {
	ifaceAsDetail := fixture(t, "bcast", "r2", CommandInterface)
	ifaceAsDetail.Command = CommandNeighborDetail
	ifaceAsDetail.Source = "interface payload labeled as detail"
	res, err := Import([]Capture{ifaceAsDetail})
	if err != nil {
		t.Fatal(err)
	}
	if cr := res.Report.Captures[0]; cr.Accepted || !strings.Contains(cr.Reason, "holds an interfaces object") {
		t.Errorf("accepted=%v reason=%q; want refusal for an interface payload under the detail command", cr.Accepted, cr.Reason)
	}
}
