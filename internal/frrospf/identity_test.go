package frrospf

import (
	"encoding/json"
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
