package frrospf

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/ospf"
)

// lsdbCapture loads one bracket capture of the LSDB lab. role is A or D for the
// process state, B for the LSDB, and E for the calculated routes. The stems are
// listed in testdata/frr/10.7.0/lsdb/README.md.
func lsdbCapture(tb testing.TB, scenario, node, role string) Capture {
	tb.Helper()
	var command string
	switch role {
	case "A", "D":
		command = CommandProcessState
	case "B":
		command = CommandLSDB
	case "E":
		command = CommandRoute
	default:
		tb.Fatalf("unknown role %q", role)
	}
	stem := node + "-" + role + "-" + strings.ReplaceAll(command, " ", "_")
	return loadCapture(tb, "lsdb/"+scenario, stem, node, command, scenario+" "+node+" "+role)
}

// stubMask is the stub link of router 1.1.1.1 in the steady B capture, with its
// dotted mask. It occurs once in that capture.
const stubMask = `"networkAddress":"10.10.1.0",
              "networkMask":"255.255.255.0"`

// TestGenuineBracketCapturesPassTheStrictCheck is the first check on the
// decoder: every captured output in the lab must pass the strict JSON rules, or
// the rules are wrong for FRR's own spelling.
func TestGenuineBracketCapturesPassTheStrictCheck(t *testing.T) {
	for _, sc := range []struct {
		scenario, node string
	}{{"steady", "r1"}, {"steady", "r2"}, {"flap", "r1"}, {"flap", "r2"}, {"kill9", "r1"}} {
		for _, role := range []string{"A", "B", "D", "E"} {
			c := lsdbCapture(t, sc.scenario, sc.node, role)
			if err := checkStrictJSON(c.Data); err != nil {
				t.Errorf("%s %s %s: strict check refused genuine output: %v", sc.scenario, sc.node, role, err)
			}
		}
	}
}

func TestProcessStateDecodesTheCountersThatReconcile(t *testing.T) {
	p, reason := decodeProcessState(lsdbCapture(t, "steady", "r1", "A").Data)
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	if p.RouterID != "1.1.1.1" || p.HoldtimeMaxMs != 5000 || p.SPFDelayMs != 0 {
		t.Fatalf("router %q holdtime %d delay %d", p.RouterID, p.HoldtimeMaxMs, p.SPFDelayMs)
	}
	if p.External != (ospf.Count{Number: 1, Checksum: 64412}) {
		t.Fatalf("external = %+v", p.External)
	}
	area := p.Areas["0.0.0.0"]
	if area.SPFExecuted != 4 {
		t.Fatalf("spf executed = %d; want 4", area.SPFExecuted)
	}
	if area.Counts[ospf.LSARouter] != (ospf.Count{Number: 2, Checksum: 24702}) {
		t.Fatalf("router count = %+v", area.Counts[ospf.LSARouter])
	}
	if area.Counts[ospf.LSANetwork] != (ospf.Count{Number: 1, Checksum: 10767}) {
		t.Fatalf("network count = %+v", area.Counts[ospf.LSANetwork])
	}
}

func TestNotRunningProcessStateIsEmptyNotLSDB(t *testing.T) {
	p, reason := decodeProcessState([]byte("{}\n"))
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	if p.RouterID != "" || len(p.Areas) != 0 {
		t.Fatalf("not running decoded as %+v", p)
	}
}

func TestProcessStateRefusals(t *testing.T) {
	data := lsdbCapture(t, "steady", "r1", "A").Data
	cases := map[string][]byte{
		"missing counter":  replaceOnce(t, data, `"lsaNetworkChecksum":10767,`, ""),
		"negative count":   replaceOnce(t, data, `"spfExecutedCounter":4,`, `"spfExecutedCounter":-4,`),
		"fractional":       replaceOnce(t, data, `"lsaRouterNumber":2,`, `"lsaRouterNumber":2.5,`),
		"bad router ID":    replaceOnce(t, data, `"routerId":"1.1.1.1"`, `"routerId":"1.1.1"`),
		"areas not object": replaceOnce(t, data, `"areas":{`, `"areas":[{`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, reason := decodeProcessState(raw); reason == "" {
				t.Fatal("accepted; want a refusal")
			}
		})
	}
}

func TestLSDBDecodesTypesAgesAndHexChecksums(t *testing.T) {
	db, reason := decodeLSDB(lsdbCapture(t, "kill9", "r1", "B").Data)
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	if db.RouterID != "1.1.1.1" {
		t.Fatalf("router ID = %q", db.RouterID)
	}
	byKey := map[string]ospf.LSA{}
	for _, l := range db.LSAs {
		byKey[string(l.Type)+" "+l.LinkStateID+" "+l.AdvertisingRouter] = l
	}
	if got := byKey["router 2.2.2.2 2.2.2.2"]; got.Checksum != 0x1fca || got.Age != 110 || got.Sequence != "80000005" {
		t.Fatalf("router 2.2.2.2 = %+v", got)
	}
	if got := byKey["network 10.0.1.1 1.1.1.1"]; got.Age != 3600 || got.Checksum != 0xe564 {
		t.Fatalf("MaxAge network LSA = %+v; want age 3600 and checksum 0xe564", got)
	}
	if got := byKey["external 10.20.0.0 2.2.2.2"]; got.Metric == nil || *got.Metric != 20 {
		t.Fatalf("external metric = %v; want 20", got.Metric)
	}
}

func TestLSDBDerivesStubsAndLengthPrefixes(t *testing.T) {
	db, reason := decodeLSDB(lsdbCapture(t, "steady", "r1", "B").Data)
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	prefixes := map[string][]string{}
	for _, l := range db.LSAs {
		var ps []string
		for _, p := range l.Prefixes {
			ps = append(ps, p.Prefix.String())
		}
		prefixes[string(l.Type)+" "+l.LinkStateID] = ps
	}
	want := map[string][]string{
		"router 1.1.1.1":     {"10.10.1.0/24"}, // the transit link gives no prefix
		"router 2.2.2.2":     {"10.10.2.0/24"},
		"network 10.0.1.2":   {"10.0.1.0/24"},
		"external 10.20.0.0": {"10.20.0.0/24"},
	}
	for key, w := range want {
		if got := prefixes[key]; strings.Join(got, ",") != strings.Join(w, ",") {
			t.Errorf("%s prefixes = %v; want %v", key, got, w)
		}
	}
}

// mutatedLSDB returns the steady r1 LSDB capture with one edit. The anchor must
// occur exactly once in the genuine output, so the test changes one thing.
func mutatedLSDB(t *testing.T, old, new string) []byte {
	t.Helper()
	return replaceOnce(t, lsdbCapture(t, "steady", "r1", "B").Data, old, new)
}

func TestPrefixDerivationRules(t *testing.T) {
	t.Run("host bits in a link state ID are masked and noted", func(t *testing.T) {
		db, reason := decodeLSDB(mutatedLSDB(t, `"linkStateId":"10.0.1.2"`, `"linkStateId":"10.0.1.7"`))
		if reason != "" {
			t.Fatalf("refused: %s", reason)
		}
		for _, l := range db.LSAs {
			if l.Type == ospf.LSANetwork && l.LinkStateID == "10.0.1.7" {
				if l.Prefixes[0].Prefix != netip.MustParsePrefix("10.0.1.0/24") || l.Prefixes[0].Note == "" {
					t.Fatalf("prefix %+v; want 10.0.1.0/24 with a note", l.Prefixes[0])
				}
				return
			}
		}
		t.Fatal("network LSA with the edited link state ID not found")
	})
	t.Run("non-contiguous dotted mask is refused", func(t *testing.T) {
		raw := mutatedLSDB(t, stubMask, `"networkAddress":"10.10.1.0",
              "networkMask":"255.0.255.0"`)
		if _, reason := decodeLSDB(raw); reason == "" {
			t.Fatal("accepted a non-contiguous mask")
		}
	})
	t.Run("dotted mask on a Type 5 is refused", func(t *testing.T) {
		raw := mutatedLSDB(t, `"networkMask":24,
      "metricType"`, `"networkMask":"255.255.255.0",
      "metricType"`)
		if _, reason := decodeLSDB(raw); reason == "" {
			t.Fatal("accepted a dotted mask on an AS-external LSA")
		}
	})
	t.Run("integer mask on a stub link is refused", func(t *testing.T) {
		raw := mutatedLSDB(t, stubMask, `"networkAddress":"10.10.1.0",
              "networkMask":24`)
		if _, reason := decodeLSDB(raw); reason == "" {
			t.Fatal("accepted an integer mask on a stub link")
		}
	})
	t.Run("length 33 is refused", func(t *testing.T) {
		raw := mutatedLSDB(t, `"networkMask":24,
      "metricType"`, `"networkMask":33,
      "metricType"`)
		if _, reason := decodeLSDB(raw); reason == "" {
			t.Fatal("accepted a length of 33")
		}
	})
}

func TestRoutesDecodeEveryRouteType(t *testing.T) {
	rt, reason := decodeRoutes(lsdbCapture(t, "steady", "r1", "E").Data)
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	if !rt.Known {
		t.Fatal("a populated table is not known")
	}
	if rt.Routers != 1 {
		t.Fatalf("routers = %d; want 1 (2.2.2.2 is an ABSR router entry)", rt.Routers)
	}
	byPrefix := map[string]ospf.Route{}
	for _, r := range rt.Entries {
		byPrefix[r.Prefix.String()] = r
	}
	if r := byPrefix["10.20.0.0/24"]; r.RouteType != "N E2" || r.Cost != 10 || r.Type2Cost == nil || *r.Type2Cost != 20 {
		t.Fatalf("E2 route = %+v", r)
	}
	if r := byPrefix["10.10.2.0/24"]; r.RouteType != "N" || r.Cost != 20 || r.NextHops != 1 {
		t.Fatalf("N route = %+v", r)
	}
	if _, ok := byPrefix["2.2.2.2/32"]; ok {
		t.Fatal("a router key was parsed as a prefix")
	}
}

func TestEmptyRouteObjectIsUnknown(t *testing.T) {
	rt, reason := decodeRoutes([]byte("{}\n"))
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	if rt.Known || len(rt.Entries) != 0 {
		t.Fatalf("empty object decoded as %+v; want unknown", rt)
	}
}

func TestRouteRefusals(t *testing.T) {
	data := lsdbCapture(t, "steady", "r1", "E").Data
	cases := map[string][]byte{
		"non-canonical prefix": replaceOnce(t, data, `"10.10.1.0/24"`, `"10.10.1.5/24"`),
		"unknown route type":   replaceOnce(t, data, `"routeType":"N E2"`, `"routeType":"N E9"`),
		"router key not IPv4":  replaceOnce(t, data, `"2.2.2.2":{`, `"2.2.2.x":{`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, reason := decodeRoutes(raw); reason == "" {
				t.Fatal("accepted; want a refusal")
			}
		})
	}
}

func TestLSDBRefusals(t *testing.T) {
	steady := lsdbCapture(t, "steady", "r1", "B").Data
	cases := map[string][]byte{
		// Two router LSAs with one link state ID and advertising router.
		"duplicate LSA identity": replaceOnce(t, steady,
			`"linkStateId":"2.2.2.2",
          "advertisingRouter":"2.2.2.2"`,
			`"linkStateId":"1.1.1.1",
          "advertisingRouter":"1.1.1.1"`),
		"section key disagrees with lsaType": replaceOnce(t, steady,
			`"lsaType":"network-LSA",
          "linkStateId":"10.0.1.2"`,
			`"lsaType":"router-LSA",
          "linkStateId":"10.0.1.2"`),
		"missing routerId": replaceOnce(t, steady, `"routerId":"1.1.1.1",`, ""),
		"missing section":  replaceOnce(t, steady, `"asExternalLinkStates":[`, `"asExternalLinkStatesX":[`),
		"malformed JSON":   []byte(`{"routerId":"1.1.1.1",`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, reason := decodeLSDB(raw); reason == "" {
				t.Fatal("accepted; want a refusal")
			}
		})
	}
}

func TestLSDBUnknownContentIsReadableNotRefused(t *testing.T) {
	steady := lsdbCapture(t, "steady", "r1", "B").Data

	unknown := replaceOnce(t, steady, `"asExternalOpaqueLsa":[]`, `"asExternalOpaqueLsa":[],"futureLsa":{"areas":{"0.0.0.0":[{"x":1}]}}`)
	db, reason := decodeLSDB(unknown)
	if reason != "" {
		t.Fatalf("refused unknown content: %s", reason)
	}
	if len(db.Unknown) != 1 || db.Unknown[0].Section != "futureLsa" || db.Unknown[0].Area != "0.0.0.0" {
		t.Fatalf("unknown = %+v; want futureLsa scoped to area 0.0.0.0", db.Unknown)
	}

	empty := replaceOnce(t, steady, `"asExternalOpaqueLsa":[]`, `"asExternalOpaqueLsa":[],"futureLsa":{"areas":{}}`)
	db, reason = decodeLSDB(empty)
	if reason != "" || len(db.Unknown) != 0 {
		t.Fatalf("empty unknown section: reason %q unknown %+v; want none", reason, db.Unknown)
	}
}

func TestOpaqueContentIsUnsupportedNotUnknown(t *testing.T) {
	steady := lsdbCapture(t, "steady", "r1", "B").Data
	raw := replaceOnce(t, steady, `"asExternalOpaqueLsa":[]`, `"asExternalOpaqueLsa":[{"lsaAge":1}]`)
	db, reason := decodeLSDB(raw)
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	if len(db.Unknown) != 0 {
		t.Fatalf("opaque entries reported as unknown: %+v", db.Unknown)
	}
	if len(db.Unsupported) != 1 || db.Unsupported[0].Entries != 1 {
		t.Fatalf("unsupported = %+v; want one opaque entry counted", db.Unsupported)
	}
}
