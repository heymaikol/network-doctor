package frrbgp

import (
	"io/fs"
	"math"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// FuzzDecodeSummary feeds arbitrary transcripts to Decode. A refusal must be an
// error with a zero Summary. An accepted summary must hold only what Decode
// promises: a canonical IPv4 router ID, AS numbers that are not reserved, peers in
// strict address order, and plain state text. Decoding the same bytes twice must
// give the same result.
func FuzzDecodeSummary(f *testing.F) {
	for _, node := range []string{"r1", "r2"} {
		data, err := fs.ReadFile(os.DirFS(steadyDir), node+"-show_ip_bgp_summary_json.raw")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, node)
	}
	f.Add(transcript("r1", oneEstablishedOneActive), "r1")
	f.Add(transcript("r1", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{}}}`), "r1")
	f.Add(transcript("r1", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":4294967295,"peers":{"::1":{"localAs":1,"remoteAs":0,"state":"Idle (Admin)"}}}}`), "r1")
	f.Add(transcript("r1", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"as":65002,"peers":{}}}`), "r1")
	f.Add(transcript("r1", `{"ipv4Unicast":{"routerId":"1.1.1.1","AS":65001,"peers":{"swp1":{"localAs":65001,"remoteAs":65002,"state":"Established"}}}}`), "r1")
	f.Add(transcript("r1", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"10.0.1.2":{"localAs":65001,"remoteAs":65002,"state":"Est\u001b[2Jablished"}}}}`), "r1")
	f.Add([]byte(CommandSummary+"\r\n% Unknown command\r\nr1> "), "r1")

	f.Fuzz(func(t *testing.T, data []byte, node string) {
		s, err := Decode(data, node)
		if err != nil {
			if !reflect.DeepEqual(s, Summary{}) {
				t.Fatalf("refusal %q returned a summary %+v", err, s)
			}
			return
		}
		if again, err := Decode(data, node); err != nil || !reflect.DeepEqual(again, s) {
			t.Fatalf("second decode differs: %+v, %v; first %+v", again, err, s)
		}
		if a, err := netip.ParseAddr(s.RouterID); err != nil || !a.Is4() || a.String() != s.RouterID {
			t.Fatalf("router ID %q is not canonical IPv4", s.RouterID)
		}
		checkAS(t, "local AS", s.LocalAS)
		if s.Peers == nil {
			t.Fatal("accepted summary has a nil peer list; an observed empty list must stay distinct")
		}
		for i, p := range s.Peers {
			if !p.Address.IsValid() || p.Address.Zone() != "" {
				t.Fatalf("peer %d address %v is not a plain address", i, p.Address)
			}
			if i > 0 && s.Peers[i-1].Address.Compare(p.Address) >= 0 {
				t.Fatalf("peers out of order or repeated: %v then %v", s.Peers[i-1].Address, p.Address)
			}
			checkAS(t, "peer local AS", p.LocalAS)
			checkAS(t, "peer remote AS", p.RemoteAS)
			if p.State == "" || textsafe.Clean(p.State) != p.State {
				t.Fatalf("peer %v state %q is not plain text", p.Address, p.State)
			}
		}
	})
}

// FuzzDecodeRouteCapture feeds arbitrary transcripts to DecodeRouteCapture. A
// refusal must be an error with a zero RouteTable. An accepted table must hold
// canonical IPv4 prefixes in strict order, at least one path per prefix, a peer
// only on a learned path, and text fields that need no further cleaning.
// Decoding the same bytes twice must give the same result.
func FuzzDecodeRouteCapture(f *testing.F) {
	for _, node := range []string{"r1", "r2"} {
		raw, err := routeReadCapture(node)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw, node)
	}
	f.Add(routeTranscript("r1", routeDoc("10.0.0.0/8", routeOnePath)), "r1")
	f.Add(routeTranscript("r1", `{"routerId":"1.1.1.1","localAS":65001,"vrfName":"default","routes":{}}`), "r1")
	f.Add(routeTranscript("r1", routePeerDoc(`"(unspec)"`)), "r1")
	f.Add(routeTranscript("r1", routePeerDoc(`"::ffff:240.0.0.1"`)), "r1")
	f.Add(routeTranscript("r1", routeHopDoc(`[{"ip":"fe80::1%eth0"}]`)), "r1")
	f.Add(routeTranscript("r1", routeDoc("10.0.0.1/8", routeOnePath)), "r1")
	f.Add(routeTranscript("r1", `{"routes":{"10.0.0.0/8":[{"pathFrom":"ext`+"\u202e"+`ernal","path":"65002","origin":"IGP","nexthops":[]}]}} `), "r1")
	f.Add(routeTranscript("r1", `{"routes":{},"Routes":{}}`), "r1")
	f.Add(routeTranscript("r1", routeDoc("10.0.0.0/8", `{"stale":true,"peerId":"10.0.1.2","pathFrom":"external","path":"65002","origin":"IGP","nexthops":[]},{"stale":false,"pathFrom":"external","path":"65002","origin":"IGP","nexthops":[]}`)), "r1")
	f.Add(routeTranscript("r1", routeDoc("10.0.0.0/8", `{"Stale":true,"pathFrom":"external","path":"65002","origin":"IGP","nexthops":[]}`)), "r1")
	during, err := fs.ReadFile(os.DirFS(routeFixtureRoot), "bgp/session/gr/r1-during-show_ip_bgp_json.raw")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(during, "r1")

	f.Fuzz(func(t *testing.T, data []byte, node string) {
		table, err := DecodeRouteCapture(data, node)
		if err != nil {
			if !reflect.DeepEqual(table, RouteTable{}) {
				t.Fatalf("refusal %q returned a table %+v", err, table)
			}
			return
		}
		if again, err := DecodeRouteCapture(data, node); err != nil || !reflect.DeepEqual(again, table) {
			t.Fatalf("second decode differs: %+v, %v; first %+v", again, err, table)
		}
		if table.RouterID != "" {
			if a, err := netip.ParseAddr(table.RouterID); err != nil || !a.Is4() || a.String() != table.RouterID {
				t.Fatalf("router ID %q is not canonical IPv4", table.RouterID)
			}
		}
		if table.LocalAS == math.MaxUint32 {
			t.Fatalf("local AS %d is reserved", table.LocalAS)
		}
		if textsafe.Clean(table.VRFName) != table.VRFName {
			t.Fatalf("VRF name %q is not plain text", table.VRFName)
		}
		for i, e := range table.Routes {
			if !e.Prefix.Addr().Is4() || e.Prefix != e.Prefix.Masked() {
				t.Fatalf("prefix %v is not a canonical IPv4 prefix", e.Prefix)
			}
			if i > 0 {
				prev := table.Routes[i-1].Prefix
				if c := prev.Addr().Compare(e.Prefix.Addr()); c > 0 || c == 0 && prev.Bits() >= e.Prefix.Bits() {
					t.Fatalf("prefixes out of order or repeated: %v then %v", prev, e.Prefix)
				}
			}
			if len(e.Paths) == 0 {
				t.Fatalf("prefix %v has no paths", e.Prefix)
			}
			for _, p := range e.Paths {
				if p.Stale != StaleNotRecorded && p.Stale != StaleFalse && p.Stale != StaleTrue {
					t.Fatalf("prefix %v path stale flag %d is not one of the three values", e.Prefix, p.Stale)
				}
				if (p.Source == RouteSourceLearned) != p.Peer.IsValid() {
					t.Fatalf("prefix %v path source %d with peer %v", e.Prefix, p.Source, p.Peer)
				}
				if p.Source == RouteSourceLearned && (p.Peer.Unmap().IsMulticast() || p.Peer.Unmap().IsUnspecified()) {
					t.Fatalf("prefix %v learned from %v, which names no peer", e.Prefix, p.Peer)
				}
				for _, s := range []string{p.PathFrom, p.ASPath, p.Origin} {
					if textsafe.Clean(s) != s {
						t.Fatalf("prefix %v path text %q is not clean", e.Prefix, s)
					}
				}
				for _, h := range p.NextHops {
					if !h.IsValid() || h.Zone() != "" {
						t.Fatalf("prefix %v next hop %v is not a plain address", e.Prefix, h)
					}
				}
			}
		}
	})
}

// checkAS fails when an accepted AS number is one of the reserved values Decode
// refuses.
func checkAS(t *testing.T, what string, as uint32) {
	t.Helper()
	if as == 0 || as == math.MaxUint32 {
		t.Fatalf("%s %d is reserved", what, as)
	}
}
