package frrospf

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// claim is an interface capture for a node whose interface e3 holds 10.0.1.2/24,
// the address the lab's r2 owns. A non-empty rid adds the router ID the
// interface reports. The node is not one the lab captured.
func claim(node, rid string) Capture {
	iface := map[string]any{"ipAddress": "10.0.1.2", "ipAddressPrefixlen": 24}
	if rid != "" {
		iface["routerId"] = rid
	}
	data, err := json.Marshal(map[string]any{"interfaces": map[string]any{"e3": iface}})
	if err != nil {
		panic(err)
	}
	return Capture{
		Node:        node,
		VRF:         "default",
		Source:      node + " interface claim",
		CollectedAt: time.Date(2026, 10, 10, 17, 41, 19, 0, time.UTC),
		FRRVersion:  Version,
		Command:     CommandInterface,
		Data:        data,
	}
}

// renameNeighborKey moves the lab's r1 neighbor record for 2.2.2.2 under key,
// and sets its state to Attempt, as FRR prints a neighbor with no router ID.
func renameNeighborKey(t *testing.T, caps []Capture, key string) {
	t.Helper()
	i := find(t, caps, "r1", CommandNeighborDetail)
	caps[i].Data = mutateJSON(t, caps[i].Data, func(top map[string]any) {
		nbrs := top["neighbors"].(map[string]any)
		recs := nbrs["2.2.2.2"].([]any)
		recs[0].(map[string]any)["nbrState"] = "Attempt/DROther"
		nbrs[key] = recs
		delete(nbrs, "2.2.2.2")
	})
}

// The next tests each describe one hazard in the merged importer. Each fails
// on that importer and passes once identity needs an unambiguous owner, a
// confirmed router ID, and a record that carries one.

// A refused capture for r2 leaves its address unaccounted for. r3 claims the
// address with no router ID, so the record must not map to r3.
func TestImportRefusedPeerCaptureBlocksOwnershipOfItsAddresses(t *testing.T) {
	caps := broadcastCaptures(t)
	i := find(t, caps, "r2", CommandInterface)
	caps[i].FRRVersion = "10.6.0"
	caps = append(caps, claim("r3", ""))
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "address ownership incomplete"}})
	if recs := neighborsOf(res, "r1"); len(recs) != 0 {
		t.Errorf("r1 wrote %d neighbors, want 0", len(recs))
	}
}

// r2 is never captured. r3 claims the record's address and reports no router
// ID, so nothing confirms that r3 is the peer.
func TestImportOmittedPeerWithoutRouterIDLeavesNeighborUnmapped(t *testing.T) {
	caps := broadcastCaptures(t)
	caps = slicesDropNode(caps, "r2")
	caps = append(caps, claim("r3", ""))
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "unconfirmed"}})
}

// The router ID agrees, but r2's relabeled interface capture is refused. Its
// address is still unaccounted for, so the agreement cannot decide ownership.
func TestImportMislabeledRefusedCaptureBlocksOwnershipEvenWithMatchingRouterID(t *testing.T) {
	caps := broadcastCaptures(t)
	i := find(t, caps, "r2", CommandInterface)
	caps[i].VRF = "blue"
	caps = append(caps, claim("r3", "2.2.2.2"))
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "address ownership incomplete"}})
}

// A neighbor with no router ID is identified by its address alone, so an
// uncaptured peer that claims the address must not take it.
func TestImportNoNbrIDNeverMapsOnAddressAlone(t *testing.T) {
	caps := slicesDropNode(broadcastCaptures(t), "r2")
	renameNeighborKey(t, caps, "noNbrId")
	caps = append(caps, claim("r3", ""))
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "has no router ID"}})
	if recs := neighborsOf(res, "r1"); len(recs) != 0 {
		t.Errorf("r1 wrote %d neighbors, want 0", len(recs))
	}
}

// The NBMA lab's early placeholder record, with r2 refused under a mislabel and
// r3 claiming the address. The placeholder must stay unmapped.
func TestImportNoNbrIDWithMislabeledRefusedCaptureStaysUnmapped(t *testing.T) {
	r2 := fixture(t, "bcast", "r2", CommandInterface)
	r2.VRF = "blue"
	res, err := Import([]Capture{
		fixture(t, "nbma", "r1", CommandInterface),
		earlyNBMANeighbors(t),
		r2,
		claim("r3", ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The gate decides first. The record has no router ID either, and that
	// reason is tested on its own above.
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "address ownership incomplete"}})
}

// The peer reports no router ID, so the record's router ID cannot be confirmed.
func TestImportPeerRouterIDAbsentLeavesNeighborUnmapped(t *testing.T) {
	caps := broadcastCaptures(t)
	i := find(t, caps, "r2", CommandInterface)
	caps[i].Data = editInterface(t, caps[i].Data, "e2", func(rec map[string]any) { delete(rec, "routerId") })
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "unconfirmed"}})
}

// The peer reports a router ID that is not dotted IPv4, so it cannot confirm.
func TestImportPeerRouterIDUnparseableLeavesNeighborUnmapped(t *testing.T) {
	caps := broadcastCaptures(t)
	i := find(t, caps, "r2", CommandInterface)
	caps[i].Data = editInterface(t, caps[i].Data, "e2", func(rec map[string]any) { rec["routerId"] = "bogus" })
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "unconfirmed"}})
}

// 0.0.0.0 is FRR's no-router-ID value, so it cannot confirm anything.
func TestImportPeerRouterIDUnspecifiedLeavesNeighborUnmapped(t *testing.T) {
	caps := broadcastCaptures(t)
	i := find(t, caps, "r2", CommandInterface)
	caps[i].Data = editInterface(t, caps[i].Data, "e2", func(rec map[string]any) { rec["routerId"] = "0.0.0.0" })
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "unconfirmed"}})
}

// r2 holds an address that is not IPv4. That interface cannot be matched, so
// the address it may hold is unknown, and r3's claim must not decide ownership.
func TestImportUnusablePeerAddressBlocksOwnership(t *testing.T) {
	caps := broadcastCaptures(t)
	i := find(t, caps, "r2", CommandInterface)
	caps[i].Data = editInterface(t, caps[i].Data, "e2", func(rec map[string]any) { rec["ipAddress"] = "fe80::1" })
	caps = append(caps, claim("r3", "2.2.2.2"))
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "address ownership incomplete"}})
}

// rawInterfaceCapture is an interface capture for node whose only interface,
// e3, holds iface exactly as given. A test uses it to write an address field
// absent, null, or malformed.
func rawInterfaceCapture(t *testing.T, node string, iface map[string]any) Capture {
	t.Helper()
	data, err := json.Marshal(map[string]any{"interfaces": map[string]any{"e3": iface}})
	if err != nil {
		t.Fatal(err)
	}
	return Capture{
		Node:        node,
		VRF:         "default",
		Source:      node + " interface",
		CollectedAt: time.Date(2026, 10, 10, 17, 41, 19, 0, time.UTC),
		FRRVersion:  Version,
		Command:     CommandInterface,
		Data:        data,
	}
}

// A third captured node whose interface has no usable address may hold the
// address r2 owns, so the ownership of that address is unknown and no record
// maps on it. The interface stays in the report with its note, and nothing is
// written for it as a negative fact.
func TestImportInterfaceWithoutAddressBlocksOwnership(t *testing.T) {
	cases := []struct {
		name   string
		iface  map[string]any
		reason string // substring of the record's reason
		note   string // substring of the interface capture's note
	}{
		{"ipAddress absent", map[string]any{"ipAddressPrefixlen": 24}, "has no ipAddress", "ipAddress is missing"},
		{"ipAddress null", map[string]any{"ipAddress": nil, "ipAddressPrefixlen": 24}, "has no ipAddress", "ipAddress is missing"},
		{"ipAddress empty", map[string]any{"ipAddress": "", "ipAddressPrefixlen": 24}, "has an ipAddress that is not IPv4", "is not IPv4"},
		{"ipAddress IPv6", map[string]any{"ipAddress": "fe80::1", "ipAddressPrefixlen": 24}, "has an ipAddress that is not IPv4", "is not IPv4"},
		{"ipAddress malformed", map[string]any{"ipAddress": "10.0.1", "ipAddressPrefixlen": 24}, "has an ipAddress that is not IPv4", "is not IPv4"},
		{"ipAddress unspecified", map[string]any{"ipAddress": "0.0.0.0", "ipAddressPrefixlen": 24}, "has an ipAddress that is unspecified, multicast, or broadcast", "is unspecified, multicast, or broadcast"},
		{"ipAddress broadcast", map[string]any{"ipAddress": "255.255.255.255", "ipAddressPrefixlen": 24}, "has an ipAddress that is unspecified, multicast, or broadcast", "is unspecified, multicast, or broadcast"},
		{"ipAddress multicast", map[string]any{"ipAddress": "224.0.0.5", "ipAddressPrefixlen": 24}, "has an ipAddress that is unspecified, multicast, or broadcast", "is unspecified, multicast, or broadcast"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caps := append(broadcastCaptures(t), rawInterfaceCapture(t, "r3", tc.iface))
			res, err := Import(caps)
			if err != nil {
				t.Fatal(err)
			}
			checkRecords(t, res.Report.Records, "r1", []recordWant{{false, tc.reason}})
			if recs := neighborsOf(res, "r1"); len(recs) != 0 {
				t.Errorf("r1 wrote %d neighbors, want 0", len(recs))
			}
			if notes := capNotes(t, res, "r3", CommandInterface); !slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, tc.note) }) {
				t.Errorf("r3 interface notes %q lack %q", notes, tc.note)
			}
			var ifaces int
			for _, o := range res.Observations {
				if o.Node == "r3" {
					ifaces += len(o.Interfaces)
				}
			}
			if ifaces != 1 {
				t.Errorf("r3 observation holds %d interfaces, want 1", ifaces)
			}
		})
	}
}

// An interface whose prefix length is missing still holds a known address, so
// the ownership of every address is complete. The gate stays open and r1 keeps
// its mapping to r2.
func TestImportPrefixlessInterfaceKeepsUnrelatedMapping(t *testing.T) {
	caps := append(broadcastCaptures(t), rawInterfaceCapture(t, "r3", map[string]any{"ipAddress": "10.0.9.1"}))
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{mapped: true}})
	for _, r := range res.Report.Records {
		if r.Node == "r1" && (r.RemoteNode != "r2" || r.RemoteInterface != "e2") {
			t.Errorf("r1 record maps to %s %s, want r2 e2", r.RemoteNode, r.RemoteInterface)
		}
	}
}

// An interface that holds r2's address but reports no prefix length still owns
// that address, so the record stays unmapped. Its subnet is unverified, so it
// cannot be told apart from r2's interface on the address alone.
func TestImportPrefixlessClaimantOfPeerAddressLeavesNeighborUnmapped(t *testing.T) {
	caps := append(broadcastCaptures(t), rawInterfaceCapture(t, "r3", map[string]any{"ipAddress": "10.0.1.2"}))
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkRecords(t, res.Report.Records, "r1", []recordWant{{false, "owned by 2 captured interfaces"}})
	if recs := neighborsOf(res, "r1"); len(recs) != 0 {
		t.Errorf("r1 wrote %d neighbors, want 0", len(recs))
	}
}

// FRR can report a loopback or link-local address on an interface. Both are
// valid unicast, so the interface owns its address and closes no gate: r1 still
// maps to r2, the only owner of r1's neighbor address.
func TestImportLoopbackAndLinkLocalAddressesKeepTheGateOpen(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		plen int
	}{
		{"loopback", "127.0.0.1", 8},
		{"link-local", "169.254.8.7", 16},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caps := append(broadcastCaptures(t), rawInterfaceCapture(t, "r3", map[string]any{"ipAddress": tc.ip, "ipAddressPrefixlen": tc.plen}))
			res, err := Import(caps)
			if err != nil {
				t.Fatal(err)
			}
			checkRecords(t, res.Report.Records, "r1", []recordWant{{mapped: true}})
			for _, r := range res.Report.Records {
				if r.Node == "r1" && (r.RemoteNode != "r2" || r.RemoteInterface != "e2") {
					t.Errorf("r1 record maps to %s %s, want r2 e2", r.RemoteNode, r.RemoteInterface)
				}
			}
			for _, n := range capNotes(t, res, "r3", CommandInterface) {
				if strings.Contains(n, "unicast") {
					t.Errorf("r3 note %q marks a valid address unusable", n)
				}
			}
		})
	}
}

// slicesDropNode returns caps without the captures for node.
func slicesDropNode(caps []Capture, node string) []Capture {
	var out []Capture
	for _, c := range caps {
		if c.Node != node {
			out = append(out, c)
		}
	}
	return out
}
