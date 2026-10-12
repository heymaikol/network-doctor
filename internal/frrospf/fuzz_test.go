package frrospf

import (
	"encoding/json"
	"maps"
	"math"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/ospf"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// FuzzImportNeighborDetail feeds arbitrary neighbor-detail output for r1, next
// to the genuine interface captures of r1 and r2. For any input it must not
// panic, netmodel must accept what Import writes, and a neighbor may map only to
// r2's e2, the sole owner of 10.0.1.2 in the default VRF.
//
// The first seed is the genuine detail payload written compactly. The others are
// short hand-written shapes that exercise the placeholder and the empty list.
func FuzzImportNeighborDetail(f *testing.F) {
	f.Add([]byte(`{"neighbors":{"2.2.2.2":[{"ifaceAddress":"10.0.1.2","areaId":"0.0.0.0","ifaceName":"e1","localIfaceAddress":"10.0.1.1","nbrState":"Full/DR"}]}}`))
	f.Add([]byte(`{"neighbors":{"noNbrId":[{"ifaceAddress":"10.0.1.2","areaId":"0.0.0.0","ifaceName":"e1","nbrState":"Attempt/-"}]}}`))
	f.Add([]byte(`{"neighbors":{}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`% No OSPF instance found`))

	ifaces := []Capture{
		fixture(f, "bcast", "r1", CommandInterface),
		fixture(f, "bcast", "r2", CommandInterface),
	}
	meta := fixture(f, "bcast", "r1", CommandNeighborDetail)

	f.Fuzz(func(t *testing.T, data []byte) {
		caps := append(slices.Clone(ifaces), Capture{
			Node:        "r1",
			VRF:         "default",
			Source:      "fuzz r1 neighbor detail",
			CollectedAt: meta.CollectedAt,
			FRRVersion:  Version,
			Command:     CommandNeighborDetail,
			Data:        data,
		})
		res, err := Import(caps)
		if err != nil {
			t.Fatalf("netmodel refused what Import wrote: %v", err)
		}

		accepted := 0
		for _, cr := range res.Report.Captures {
			if !plain(cr.Reason) {
				t.Fatalf("capture reason repeats control text: %q", cr.Reason)
			}
			if cr.Accepted {
				accepted++
			}
		}
		for _, r := range res.Report.Records {
			if !plain(r.Reason) {
				t.Fatalf("record reason repeats control text: %q", r.Reason)
			}
		}
		if accepted != len(res.Observations) {
			t.Fatalf("%d accepted captures wrote %d observations", accepted, len(res.Observations))
		}

		written := 0
		for _, o := range res.Observations {
			written += len(o.Neighbors)
		}
		mapped := 0
		for _, r := range res.Report.Records {
			if !r.Mapped {
				continue
			}
			mapped++
			if r.RemoteNode != "r2" || r.RemoteInterface != "e2" || r.NeighborAddr != "10.0.1.2" || r.LocalInterface != "e1" {
				t.Fatalf("mapped record names a peer nothing captured: %+v", r)
			}
		}
		if mapped != written {
			t.Fatalf("%d records mapped but %d neighbors written", mapped, written)
		}
	})
}

// FuzzImportInterfaceFacts feeds arbitrary interface output for r3, next to the
// genuine broadcast captures of r1 and r2. For any input it must not panic,
// netmodel must accept what Import writes, every fact written must come from its
// closed vocabulary, and each key may be written at most once per interface.
//
// The first seed is the genuine broadcast interface output of r1. The others are
// short shapes that exercise each fact field.
func FuzzImportInterfaceFacts(f *testing.F) {
	f.Add(fixture(f, "bcast", "r1", CommandInterface).Data)
	f.Add([]byte(`{"interfaces":{"e3":{"ipAddress":"10.99.9.1","ipAddressPrefixlen":24,"cost":0,"networkType":"POINTOPOINT","state":"Point-To-Point","timerPassiveIface":true}}}`))
	f.Add([]byte(`{"interfaces":{"e3":{"ipAddress":"10.99.9.1","ipAddressPrefixlen":24,"cost":65536,"networkType":"Null","state":null,"timerPassiveIface":false,"timerHelloInMsecs":"9000"}}}`))
	f.Add([]byte(`{"interfaces":{"e3":{"ipAddress":"10.99.9.1","ipAddressPrefixlen":24,"timerPassiveIface":true,"timerHelloInMsecs":9000,"drAddress":"10.99.9.9","bdrAddress":"10.1.1.1"}}}`))
	f.Add([]byte(`{"interfaces":{"e3":{"ipAddress":"10.99.9.1","ipAddressPrefixlen":24,"drAddress":"0.0.0.0","bdrAddress":"not-an-address"}}}`))
	f.Add([]byte(`{"interfaces":{"e3":{"ipAddress":"10.99.9.1","ipAddressPrefixlen":24,"timerHelloInMsecs":1.5}}}`))
	f.Add([]byte(`{"interfaces":{"e3":{"ipAddress":"10.99.9.1","ipAddressPrefixlen":24,"timerHelloInMsecs":-1}}}`))
	f.Add([]byte(`{"interfaces":{"e3":{"ipAddress":"10.99.9.1","ipAddressPrefixlen":24,"timerHelloInMsecs":1e300}}}`))
	f.Add([]byte(`{"interfaces":{"e3":{"ipAddress":"10.99.9.1","ipAddressPrefixlen":24,"timerHelloInMsecs":65535001}}}`))
	f.Add([]byte(`{}`))

	ifaces := []Capture{
		fixture(f, "bcast", "r1", CommandInterface),
		fixture(f, "bcast", "r2", CommandInterface),
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		caps := append(slices.Clone(ifaces), Capture{
			Node:        "r3",
			VRF:         "default",
			Source:      "fuzz r3 interface",
			CollectedAt: ifaces[0].CollectedAt,
			FRRVersion:  Version,
			Command:     CommandInterface,
			Data:        data,
		})
		res, err := Import(caps)
		if err != nil {
			t.Fatalf("netmodel refused what Import wrote: %v", err)
		}
		for _, cr := range res.Report.Captures {
			if !plain(cr.Reason) {
				t.Fatalf("capture reason repeats control text: %q", cr.Reason)
			}
			for _, n := range cr.Notes {
				if !plain(n) {
					t.Fatalf("note repeats control text: %q", n)
				}
			}
		}
		for _, o := range res.Observations {
			for _, i := range o.Interfaces {
				seen := map[string]bool{}
				for _, a := range i.Attributes {
					if seen[a.Key] {
						t.Fatalf("%s %s writes %s twice", o.Node, i.Name, a.Key)
					}
					seen[a.Key] = true
					if !inVocabulary(a) {
						t.Fatalf("%s %s writes %s = %q, outside its vocabulary", o.Node, i.Name, a.Key, a.Value)
					}
					if o.Node == "r3" && i.Name == "e3" && a.Key == keyPassive && a.Value == "false" && !activeRecord(data) {
						t.Fatalf("r3 e3 writes ospf.passive false without an in-range integer hello timer: %q", data)
					}
				}
			}
		}
	})
}

// activeRecord reports whether the e3 record in data is the only shape that writes
// ospf.passive false: an integer hello timer in range and no timerPassiveIface.
func activeRecord(data []byte) bool {
	var doc struct {
		Interfaces map[string]map[string]json.RawMessage `json:"interfaces"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return false
	}
	rec := doc.Interfaces["e3"]
	if _, ok := rec["timerPassiveIface"]; ok {
		return false
	}
	var n int64
	return json.Unmarshal(rec["timerHelloInMsecs"], &n) == nil && n >= 0 && n <= maxHelloMsecs
}

// inVocabulary reports whether an interface attribute holds a value its key may
// hold. It reads the closed maps in facts.go, so a fact written outside them fails.
func inVocabulary(a netmodel.Attribute) bool {
	switch a.Key {
	case keyCost:
		n, err := strconv.Atoi(a.Value)
		return err == nil && n >= 0 && n <= maxCost && strconv.Itoa(n) == a.Value
	case keyNetworkType:
		return slices.Contains(slices.Collect(maps.Values(networkTypes)), a.Value)
	case keyInterfaceState:
		return slices.Contains(slices.Collect(maps.Values(interfaceStates)), a.Value)
	case keyPassive:
		return a.Value == "true" || a.Value == "false"
	}
	return true
}

// FuzzDecodeManifest feeds arbitrary manifest bytes. It must not panic, and every
// error must be plain text. A manifest it accepts must hold what the importer
// relies on: version 1, a bounded capture count, file paths that name a file,
// plain text, unique source labels and file names after cleaning, UTC times, and
// a source node that names a captured node.
func FuzzDecodeManifest(f *testing.F) {
	f.Add(manifestBytes(f, nil))
	f.Add([]byte(`{"version":1,"captures":[]}`))
	f.Add([]byte(`{"version":1,"version":1,"captures":[]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := DecodeManifest(data)
		if err != nil {
			if !plain(err.Error()) {
				t.Fatalf("error repeats control text: %q", err)
			}
			return
		}
		if m.Version != ManifestVersion || len(m.Captures) == 0 || len(m.Captures) > MaxCaptures {
			t.Fatalf("accepted version %d with %d captures", m.Version, len(m.Captures))
		}
		sources := map[string]bool{}
		files := map[string]bool{}
		sourceNamed := m.SourceNode == ""
		for _, c := range m.Captures {
			if !filepath.IsLocal(c.File) || filepath.Clean(c.File) == "." {
				t.Fatalf("accepted file path %q", c.File)
			}
			for _, s := range []string{c.File, c.Source, c.Node, c.VRF, c.FRRVersion, c.Command} {
				if !plain(s) {
					t.Fatalf("accepted text with control characters: %q", s)
				}
			}
			src := textsafe.Clean(c.Source)
			if sources[src] {
				t.Fatalf("accepted duplicate source label %q", src)
			}
			sources[src] = true
			name := filepath.Clean(c.File)
			if files[name] {
				t.Fatalf("accepted duplicate file %q", name)
			}
			files[name] = true
			if c.CollectedAt.Location() != time.UTC {
				t.Fatalf("collected_at location = %v, want UTC", c.CollectedAt.Location())
			}
			if c.Node == m.SourceNode {
				sourceNamed = true
			}
		}
		if !sourceNamed {
			t.Fatalf("accepted source_node %q that names no capture", m.SourceNode)
		}
	})
}

// FuzzDecodeLSDB feeds arbitrary bytes to each LSDB decoder. A refusal must be
// plain text. An accepted LSDB must hold valid prefixes and checksums in range,
// so a crafted capture cannot reach the comparison in an unusable shape.
func FuzzDecodeLSDB(f *testing.F) {
	for _, sc := range []string{"steady", "kill9"} {
		f.Add(lsdbCapture(f, sc, "r1", "A").Data)
		f.Add(lsdbCapture(f, sc, "r1", "B").Data)
		f.Add(lsdbCapture(f, sc, "r1", "E").Data)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"routerId":"1.1.1.1"}`))
	f.Add([]byte(`{"routeType":"N"}`))
	// One route object per seed, each exercising a next hop shape.
	for _, route := range []string{
		`{"routeType":"N","area":"0.0.0.0","cost":50,"nexthops":[{"ip":" ","directlyAttachedTo":"e1"}]}`,
		`{"routeType":"N","area":"0.0.0.0","cost":60,"nexthops":[{"ip":"10.0.1.2","via":"e1","advertisedRouter":"2.2.2.2"}]}`,
		`{"routeType":"N","area":"0.0.0.0","cost":20,"nexthops":[{"ip":"10.0.1.2","via":"e1","advertisedRouter":"2.2.2.2"},{"ip":"10.0.3.2","via":"e3","advertisedRouter":"2.2.2.2"}]}`,
		`{"routeType":"N","area":"0.0.0.0","cost":20,"nexthops":[{"ip":"10.0.1.2","via":"e1","advertisedRouter":"1.1.1.1"},{"ip":"10.0.1.2","via":"e1","advertisedRouter":"2.2.2.2"}]}`,
		`{"routeType":"N","area":"0.0.0.0","cost":20,"nexthops":[{}]}`,
		`{"routeType":"N","area":"0.0.0.0","cost":20,"nexthops":[]}`,
		`{"routeType":"N","area":"0.0.0.0","cost":20,"nexthops":[null,{"ip":"10.0.1.2","via":"e1","advertisedRouter":"2.2.2.2"}]}`,
		`{"routeType":"N","area":"0.0.0.0","cost":20,"nexthops":[{"IP":"10.0.1.2","via":"e1","advertisedRouter":"2.2.2.2"}]}`,
		`{"routeType":"N E1","cost":30,"nexthops":[{"ip":"10.0.1.2","via":"e1","advertisedRouter":"2.2.2.2"}]}`,
		`{"routeType":"N E2","cost":10,"type2cost":20,"nexthops":[{"ip":"10.0.1.2","via":"e1","advertisedRouter":"2.2.2.2"}]}`,
		`{"routeType":"N","area":"0.0.0.0","cost":4294967296,"nexthops":[{"ip":" ","directlyAttachedTo":"e1"}]}`,
	} {
		f.Add([]byte(`{"10.0.1.0/24":` + route + `}`))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if db, reason := decodeLSDB(data); reason != "" {
			if !plain(reason) {
				t.Fatalf("LSDB refusal repeats control text: %q", reason)
			}
		} else {
			for _, l := range db.LSAs {
				if l.Checksum > 0xffff {
					t.Fatalf("accepted checksum %#x out of range", l.Checksum)
				}
				for _, p := range l.Prefixes {
					if !p.Prefix.IsValid() {
						t.Fatalf("accepted an invalid prefix in %s %s", l.Type, l.LinkStateID)
					}
				}
			}
		}
		if _, reason := decodeProcessState(data); reason != "" && !plain(reason) {
			t.Fatalf("process refusal repeats control text: %q", reason)
		}
		rt, reason := decodeRoutes(data)
		if reason != "" && !plain(reason) {
			t.Fatalf("route refusal repeats control text: %q", reason)
		}
		if reason == "" {
			checkRouteHops(t, rt)
		}
	})
}

// checkRouteHops holds the next hop invariants of an accepted route table: the
// status and count agree, the lists are sorted, unique, and never nil, and the
// metric status matches the printed values. Conflict and repeat handling is
// covered by the unit tests, not here.
func checkRouteHops(t *testing.T, rt ospf.Routes) {
	t.Helper()
	for _, r := range rt.Entries {
		if r.ForwardingHops == nil || r.DirectInterfaces == nil {
			t.Fatalf("route %s: a hop list is null", r.Prefix)
		}
		switch r.NextHopStatus {
		case ospf.NextHopComplete, ospf.NextHopExplicitlyEmpty:
			if r.ForwardingHopCount == nil || *r.ForwardingHopCount != len(r.ForwardingHops)+len(r.DirectInterfaces) {
				t.Fatalf("route %s: %s count does not equal the listed hops", r.Prefix, r.NextHopStatus)
			}
		case ospf.NextHopAmbiguous, ospf.NextHopIncomplete:
			if r.ForwardingHopCount != nil {
				t.Fatalf("route %s: %s route has a count", r.Prefix, r.NextHopStatus)
			}
		default:
			t.Fatalf("route %s: next_hop_status %q", r.Prefix, r.NextHopStatus)
		}
		if (r.NextHops == 0) != (r.NextHopStatus == ospf.NextHopExplicitlyEmpty) {
			t.Fatalf("route %s: %d nexthops with status %s", r.Prefix, r.NextHops, r.NextHopStatus)
		}
		for i, h := range r.ForwardingHops {
			if !h.Address.Is4() || h.Address.IsUnspecified() || h.Interface == "" || len(h.AdvertisedBy) == 0 {
				t.Fatalf("route %s: forwarding hop %d is not an identity: %+v", r.Prefix, i, h)
			}
			if !slices.IsSortedFunc(h.AdvertisedBy, netip.Addr.Compare) || len(slices.Compact(slices.Clone(h.AdvertisedBy))) != len(h.AdvertisedBy) {
				t.Fatalf("route %s: advertisers of hop %d are not sorted and unique", r.Prefix, i)
			}
			if i > 0 {
				p := r.ForwardingHops[i-1]
				if c := p.Address.Compare(h.Address); c > 0 || (c == 0 && p.Interface >= h.Interface) {
					t.Fatalf("route %s: forwarding hops are not sorted and unique", r.Prefix)
				}
			}
		}
		if !slices.IsSorted(r.DirectInterfaces) || len(slices.Compact(slices.Clone(r.DirectInterfaces))) != len(r.DirectInterfaces) {
			t.Fatalf("route %s: direct interfaces are not sorted and unique", r.Prefix)
		}
		unrepresentable := r.Cost > math.MaxUint32 || (r.Type2Cost != nil && *r.Type2Cost > math.MaxUint32)
		if unrepresentable != (r.MetricStatus == ospf.MetricUnrepresentable) {
			t.Fatalf("route %s: metric_status %q for cost %d", r.Prefix, r.MetricStatus, r.Cost)
		}
	}
}
