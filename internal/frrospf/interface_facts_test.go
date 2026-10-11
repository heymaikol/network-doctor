package frrospf

import (
	"encoding/json"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/ospf"
)

// labScenarios are the committed FRR 10.7.0 lab directories that hold interface
// output. Scenarios that lack a capture for a node are skipped for that node.
var labScenarios = []string{"bcast", "p2p", "mtu", "area", "nbma", "secondary", "passive1", "cost50", "mixp2p", "secp1", "secp2", "down1"}

// labCaptures loads every committed interface and neighbor-detail capture of one
// scenario, for the nodes that have one.
func labCaptures(t *testing.T, scenario string) []Capture {
	t.Helper()
	var out []Capture
	for _, node := range []string{"r1", "r2"} {
		for _, command := range []string{CommandInterface, CommandNeighborDetail} {
			stem := node + "-" + strings.ReplaceAll(command, " ", "_")
			if _, err := os.Stat(filepath.Join(fixtureRoot, scenario, stem+".raw")); err != nil {
				continue
			}
			out = append(out, fixture(t, scenario, node, command))
		}
	}
	return out
}

// ifaceFacts returns the control-plane attributes of one interface, one value
// per key. A key that repeats on one interface fails the test, because the
// importer writes one value per key. It returns nil when the interface is absent.
func ifaceFacts(t *testing.T, res Result, node, name string) map[string]string {
	t.Helper()
	i, ok := controlInterfaces(res)[node][name]
	if !ok {
		return nil
	}
	out := map[string]string{}
	for _, a := range i.Attributes {
		if _, dup := out[a.Key]; dup {
			t.Fatalf("%s %s repeats %s", node, name, a.Key)
		}
		out[a.Key] = a.Value
	}
	return out
}

// checkFacts requires each wanted key to hold its wanted value.
func checkFacts(t *testing.T, where string, got, want map[string]string) {
	t.Helper()
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if v, ok := got[k]; !ok || v != want[k] {
			t.Errorf("%s: %s = %q (present %v), want %q", where, k, v, ok, want[k])
		}
	}
}

// checkAbsent requires each named key to be missing.
func checkAbsent(t *testing.T, where string, got map[string]string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if v, ok := got[k]; ok {
			t.Errorf("%s: %s = %q, want absent", where, k, v)
		}
	}
}

// noteWith returns the first note that holds sub, or "" when none does.
func noteWith(notes []string, sub string) string {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return n
		}
	}
	return ""
}

// evidenceRows returns the evidence of a finding as the JSON rows a report reader
// sees, so a test checks the written field names too.
func evidenceRows(t *testing.T, f ospf.Finding) []map[string]any {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Evidence []map[string]any `json:"evidence"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Evidence
}

// synthIface is an FRR-shaped interface record for a synthetic capture on node
// r3, interface e3. Each test that calls it names the change it makes. The
// values are not FRR output unless a test says so.
func synthIface(set map[string]any, drop ...string) map[string]any {
	rec := map[string]any{
		"ifUp": true, "ospfEnabled": true,
		"ipAddress": "10.99.9.1", "ipAddressPrefixlen": 24,
		"routerId": "3.3.3.3", "area": "0.0.0.0",
		"cost": 10, "networkType": "BROADCAST", "state": "DR",
		"timerHelloInMsecs": 9000,
	}
	for _, k := range drop {
		delete(rec, k)
	}
	maps.Copy(rec, set)
	return rec
}

// importSynth imports one synthetic interface capture for r3.
func importSynth(t *testing.T, rec map[string]any) Result {
	t.Helper()
	res, err := Import([]Capture{rawInterfaceCapture(t, "r3", rec)})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestBroadcastInterfaceFacts reads the interface facts of the broadcast lab,
// where r1 is Backup on e1 and its stub is passive.
func TestBroadcastInterfaceFacts(t *testing.T) {
	res, err := Import([]Capture{fixture(t, "bcast", "r1", CommandInterface)})
	if err != nil {
		t.Fatal(err)
	}
	checkFacts(t, "bcast r1 e1", ifaceFacts(t, res, "r1", "e1"), map[string]string{
		"ospf.interface_state": "backup",
		"ospf.network_type":    "broadcast",
		"ospf.cost":            "10",
		"ospf.passive":         "false",
	})
	checkFacts(t, "bcast r1 stub1", ifaceFacts(t, res, "r1", "stub1"), map[string]string{
		"ospf.interface_state": "dr",
		"ospf.network_type":    "broadcast",
		"ospf.cost":            "10",
		"ospf.passive":         "true",
	})
}

// TestPointToPointInterfaceFacts reads the point-to-point lab. FRR prints the
// state as Point-To-Point, and the network type as POINTOPOINT.
func TestPointToPointInterfaceFacts(t *testing.T) {
	res, err := Import([]Capture{fixture(t, "p2p", "r1", CommandInterface)})
	if err != nil {
		t.Fatal(err)
	}
	checkFacts(t, "p2p r1 e1", ifaceFacts(t, res, "r1", "e1"), map[string]string{
		"ospf.interface_state": "point-to-point",
		"ospf.network_type":    "point-to-point",
		"ospf.passive":         "false",
	})
}

// TestNBMANetworkTypeIsNotOSPFIfType reads the NBMA lab. FRR prints ospfIfType
// Broadcast for this interface, and the network type NBMA. The network type wins.
func TestNBMANetworkTypeIsNotOSPFIfType(t *testing.T) {
	res, err := Import([]Capture{fixture(t, "nbma", "r1", CommandInterface)})
	if err != nil {
		t.Fatal(err)
	}
	checkFacts(t, "nbma r1 e1", ifaceFacts(t, res, "r1", "e1"), map[string]string{
		"ospf.network_type": "nbma",
	})
}

// TestCostMismatchStaysFacts imports the cost lab. The two ends hold cost 50 and
// cost 10. Both facts are written, and the adjacency adds no finding of its own.
func TestCostMismatchStaysFacts(t *testing.T) {
	res, err := Import(labCaptures(t, "cost50"))
	if err != nil {
		t.Fatal(err)
	}
	checkFacts(t, "cost50 r1 e1", ifaceFacts(t, res, "r1", "e1"), map[string]string{"ospf.cost": "50"})
	checkFacts(t, "cost50 r2 e2", ifaceFacts(t, res, "r2", "e2"), map[string]string{"ospf.cost": "10"})
	for _, f := range ospf.Analyze(mustModel(t, res)).Findings {
		if f.Kind != ospf.KindNeighborState {
			t.Errorf("cost mismatch added a %s finding; facts only", f.Kind)
		}
	}
}

// TestNetworkTypeMismatchStaysFacts imports the mixed lab, where r1 e1 is
// point-to-point and r2 e2 is broadcast. Each side writes its own network type,
// and no finding besides neighbor state is added.
func TestNetworkTypeMismatchStaysFacts(t *testing.T) {
	res, err := Import(labCaptures(t, "mixp2p"))
	if err != nil {
		t.Fatal(err)
	}
	checkFacts(t, "mixp2p r1 e1", ifaceFacts(t, res, "r1", "e1"), map[string]string{"ospf.network_type": "point-to-point"})
	checkFacts(t, "mixp2p r2 e2", ifaceFacts(t, res, "r2", "e2"), map[string]string{"ospf.network_type": "broadcast"})
	for _, f := range ospf.Analyze(mustModel(t, res)).Findings {
		if f.Kind != ospf.KindNeighborState {
			t.Errorf("network type mismatch added a %s finding; facts only", f.Kind)
		}
	}
}

// TestMixedNetworkTypeRouteTablesLackPeerRoute reads the route captures of the
// mixed lab. Each router's OSPF route table lacks the peer's stub network. This
// shows only that the calculated route entries are absent from the captured OSPF
// route tables. It shows no kernel FIB failure and no loss of connectivity.
func TestMixedNetworkTypeRouteTablesLackPeerRoute(t *testing.T) {
	for _, tc := range []struct{ node, absent string }{{"r1", "10.10.2.0/24"}, {"r2", "10.10.1.0/24"}} {
		rt, reason := decodeRoutes(fixture(t, "mixp2p", tc.node, CommandRoute).Data)
		if reason != "" {
			t.Fatalf("%s route capture refused: %s", tc.node, reason)
		}
		if !rt.Known {
			t.Fatalf("%s route capture holds no routes object", tc.node)
		}
		want := netip.MustParsePrefix(tc.absent)
		for _, e := range rt.Entries {
			if e.Prefix == want {
				t.Errorf("%s OSPF route table holds %s, want it absent", tc.node, tc.absent)
			}
		}
	}
}

// mustModel builds the netmodel of an import, for analyzers that read it.
func mustModel(t *testing.T, res Result) netmodel.Model {
	t.Helper()
	m, err := netmodel.New(res.Observations...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestSecpPassiveMixingWithholdsName imports the two secondary-address labs with
// a passive setting on one address. The record holds passive and hello timers
// together (D1), so the name's OSPF facts are withheld and a note says why.
func TestSecpPassiveMixingWithholdsName(t *testing.T) {
	for _, scenario := range []string{"secp1", "secp2"} {
		t.Run(scenario, func(t *testing.T) {
			res, err := Import([]Capture{fixture(t, scenario, "r1", CommandInterface)})
			if err != nil {
				t.Fatal(err)
			}
			checkAbsent(t, scenario+" r1 e1", ifaceFacts(t, res, "r1", "e1"),
				"ospf.effective_area", "ospf.cost", "ospf.network_type", "ospf.interface_state", "ospf.passive")
			if n := noteWith(capNotes(t, res, "r1", CommandInterface), `interface "e1": facts withheld`); n == "" {
				t.Errorf("no note says e1 facts are withheld; notes = %q", capNotes(t, res, "r1", CommandInterface))
			}
		})
	}
}

// TestSecondaryOutsideSubnetWithholdsName imports the secondary lab. The record
// reports a bdrAddress outside its own subnet, so the name's facts are withheld
// and the note names the address and the subnet.
func TestSecondaryOutsideSubnetWithholdsName(t *testing.T) {
	res, err := Import([]Capture{fixture(t, "secondary", "r1", CommandInterface)})
	if err != nil {
		t.Fatal(err)
	}
	checkAbsent(t, "secondary r1 e1", ifaceFacts(t, res, "r1", "e1"),
		"ospf.effective_area", "ospf.cost", "ospf.network_type", "ospf.interface_state", "ospf.passive")
	if n := noteWith(capNotes(t, res, "r1", CommandInterface), "bdrAddress 10.0.1.1 is outside 10.0.2.0/24"); n == "" {
		t.Errorf("no note names the out-of-subnet bdrAddress; notes = %q", capNotes(t, res, "r1", CommandInterface))
	}
}

// TestD2SkippedWithoutUsablePrefix gives a record an out-of-subnet bdrAddress and
// no usable prefix length. No subnet can be built, so the DR check is skipped and
// the facts stay. The note says the check was skipped.
func TestD2SkippedWithoutUsablePrefix(t *testing.T) {
	res := importSynth(t, synthIface(map[string]any{"bdrAddress": "10.0.1.1", "ipAddress": "10.0.2.1"}, "ipAddressPrefixlen"))
	checkFacts(t, "r3 e3", ifaceFacts(t, res, "r3", "e3"), map[string]string{"ospf.cost": "10", "ospf.interface_state": "dr"})
	if n := noteWith(capNotes(t, res, "r3", CommandInterface), "subnet check skipped"); n == "" {
		t.Errorf("no note says the DR subnet check was skipped; notes = %q", capNotes(t, res, "r3", CommandInterface))
	}
}

// TestSingleOSPFInterfaceNameNotWithheld imports labs where each name holds one
// OSPF interface. None of them is withheld, and every per-interface fact is
// present.
func TestSingleOSPFInterfaceNameNotWithheld(t *testing.T) {
	for _, scenario := range []string{"bcast", "p2p", "nbma", "mtu"} {
		t.Run(scenario, func(t *testing.T) {
			res, err := Import([]Capture{fixture(t, scenario, "r1", CommandInterface)})
			if err != nil {
				t.Fatal(err)
			}
			if n := noteWith(capNotes(t, res, "r1", CommandInterface), "withheld"); n != "" {
				t.Errorf("single-interface name withheld: %q", n)
			}
			checkFacts(t, scenario+" r1 e1", ifaceFacts(t, res, "r1", "e1"), map[string]string{"ospf.cost": "10"})
			for _, k := range []string{"ospf.network_type", "ospf.interface_state", "ospf.passive", "ospf.effective_area"} {
				if _, ok := ifaceFacts(t, res, "r1", "e1")[k]; !ok {
					t.Errorf("%s r1 e1 lacks %s", scenario, k)
				}
			}
		})
	}
}

// TestNeighborRoleIsNotInterfaceState imports the broadcast lab with its
// neighbor records. The neighbor is Full as DR, but the interface itself is
// Backup, and the interface fact is the interface's own state.
func TestNeighborRoleIsNotInterfaceState(t *testing.T) {
	res, err := Import(labCaptures(t, "bcast"))
	if err != nil {
		t.Fatal(err)
	}
	checkFacts(t, "bcast r1 e1", ifaceFacts(t, res, "r1", "e1"), map[string]string{"ospf.interface_state": "backup"})
}

// TestAbsentInterfaceRecordIsUnknown imports the lab where r1 e1 went down. FRR
// left e1 out of the interface listing, so no OSPF fact is written for it. The
// absence is unknown, not down.
func TestAbsentInterfaceRecordIsUnknown(t *testing.T) {
	res, err := Import(labCaptures(t, "down1"))
	if err != nil {
		t.Fatal(err)
	}
	for k := range ifaceFacts(t, res, "r1", "e1") {
		if strings.HasPrefix(k, "ospf.") {
			t.Errorf("r1 e1 holds %s, want no OSPF fact for an absent record", k)
		}
	}
}

// TestNoDRFieldsImported checks that the DR and BDR fields are read for leak
// detection only. No attribute carries them.
func TestNoDRFieldsImported(t *testing.T) {
	for _, scenario := range labScenarios {
		res, err := Import(labCaptures(t, scenario))
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range res.Observations {
			for _, i := range o.Interfaces {
				for _, a := range i.Attributes {
					if strings.HasPrefix(a.Key, "ospf.dr_") || strings.HasPrefix(a.Key, "ospf.bdr_") {
						t.Errorf("%s %s %s holds %s", scenario, o.Node, i.Name, a.Key)
					}
				}
			}
		}
	}
}

// TestOSPFIfTypeIsNeverNetworkType checks that the point-to-point lab, which
// prints ospfIfType Broadcast, writes point-to-point as the network type.
func TestOSPFIfTypeIsNeverNetworkType(t *testing.T) {
	res, err := Import([]Capture{fixture(t, "p2p", "r1", CommandInterface)})
	if err != nil {
		t.Fatal(err)
	}
	if got := ifaceFacts(t, res, "r1", "e1")["ospf.network_type"]; got == "broadcast" {
		t.Errorf("network type = %q from ospfIfType, want point-to-point", got)
	}
}

// TestCostZeroIsValid uses a synthetic record. A loopback reports cost 0, and
// zero is a value, not a missing one.
func TestCostZeroIsValid(t *testing.T) {
	res := importSynth(t, synthIface(map[string]any{"cost": 0}))
	checkFacts(t, "synthetic cost 0", ifaceFacts(t, res, "r3", "e3"), map[string]string{"ospf.cost": "0"})
}

// TestCostOutOfRangeIsUnreadable uses synthetic records. A cost outside 0 to
// 65535 writes nothing, and the note quotes the value.
func TestCostOutOfRangeIsUnreadable(t *testing.T) {
	for _, v := range []int{-1, 65536} {
		res := importSynth(t, synthIface(map[string]any{"cost": v}))
		checkAbsent(t, "synthetic cost out of range", ifaceFacts(t, res, "r3", "e3"), "ospf.cost")
		if noteWith(capNotes(t, res, "r3", CommandInterface), "cost "+strconv.Itoa(v)) == "" {
			t.Errorf("cost %d: no note quotes the value", v)
		}
	}
}

// TestNewFieldWrongTypeOnlyLosesThatField uses a synthetic record with a string
// cost on r3, next to the committed broadcast labs. The wrong type loses the cost
// only. The neighbors of r1 stay mapped, so the ownership gate stays open.
func TestNewFieldWrongTypeOnlyLosesThatField(t *testing.T) {
	caps := append(broadcastCaptures(t), rawInterfaceCapture(t, "r3", synthIface(map[string]any{"cost": "10"})))
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	checkAbsent(t, "r3 e3", ifaceFacts(t, res, "r3", "e3"), "ospf.cost")
	if n := noteWith(capNotes(t, res, "r3", CommandInterface), "cost"); n == "" {
		t.Errorf("no note names the wrong-typed cost; notes = %q", capNotes(t, res, "r3", CommandInterface))
	}
	if len(neighborsOf(res, "r1")) == 0 {
		t.Errorf("r1 lost its neighbors to a wrong-typed fact field")
	}
}

// TestNullNewFieldIsUnreadable uses synthetic records with null cost, state, and
// network type. Each writes nothing, and each note names its key.
func TestNullNewFieldIsUnreadable(t *testing.T) {
	res := importSynth(t, synthIface(map[string]any{"cost": nil, "state": nil, "networkType": nil}))
	checkAbsent(t, "null fields", ifaceFacts(t, res, "r3", "e3"), "ospf.cost", "ospf.interface_state", "ospf.network_type")
	notes := capNotes(t, res, "r3", CommandInterface)
	for _, key := range []string{"cost", "state", "networkType"} {
		if noteWith(notes, key) == "" {
			t.Errorf("no note names null %s; notes = %q", key, notes)
		}
	}
}

// TestUnknownVocabularyIsUnreadable uses synthetic records with a network type
// and state outside the vocabulary. Neither is written, and each note quotes the
// value that was refused.
func TestUnknownVocabularyIsUnreadable(t *testing.T) {
	res := importSynth(t, synthIface(map[string]any{"networkType": "Null", "state": "Foo"}))
	checkAbsent(t, "unknown vocabulary", ifaceFacts(t, res, "r3", "e3"), "ospf.network_type", "ospf.interface_state")
	notes := capNotes(t, res, "r3", CommandInterface)
	for _, v := range []string{"Null", "Foo"} {
		if noteWith(notes, v) == "" {
			t.Errorf("no note quotes %s; notes = %q", v, notes)
		}
	}
}

// TestPassiveFalseIsMalformed uses a synthetic record that holds timerPassiveIface
// false. FRR never writes false, so no passive value is written and a note says so.
func TestPassiveFalseIsMalformed(t *testing.T) {
	res := importSynth(t, synthIface(map[string]any{"timerPassiveIface": false}))
	checkAbsent(t, "timerPassiveIface false", ifaceFacts(t, res, "r3", "e3"), "ospf.passive")
	if noteWith(capNotes(t, res, "r3", CommandInterface), "timerPassiveIface") == "" {
		t.Errorf("no note names the malformed timerPassiveIface")
	}
}

// TestPassiveNeitherKeyIsNotEvaluated uses a synthetic record with neither passive
// key nor a hello timer. No passive value is written, and no conflict is claimed.
func TestPassiveNeitherKeyIsNotEvaluated(t *testing.T) {
	res := importSynth(t, synthIface(nil, "timerHelloInMsecs"))
	checkAbsent(t, "neither key", ifaceFacts(t, res, "r3", "e3"), "ospf.passive")
	if noteWith(capNotes(t, res, "r3", CommandInterface), "both ways") != "" {
		t.Errorf("neither key claimed a conflict")
	}
}

// TestPassiveBothKeysIsConflicting uses a synthetic record with passive true and
// a hello timer. Both keys on one record are a conflict, so no passive value is
// written.
func TestPassiveBothKeysIsConflicting(t *testing.T) {
	res := importSynth(t, synthIface(map[string]any{"timerPassiveIface": true}))
	checkAbsent(t, "both keys", ifaceFacts(t, res, "r3", "e3"), "ospf.passive")
}

// helloCases are the timerHelloInMsecs values a record may carry, as the wire
// writes them. FRR writes an integer count of milliseconds from 0 to 65535000,
// the largest hello interval the router accepts. want is the passive value an
// active record without timerPassiveIface then reads, or "" when the value is
// unreadable and no passive value is written.
var helloCases = []struct {
	name, raw, want string
}{
	{"zero", `0`, "false"},
	{"typical", `9000`, "false"},
	{"largest FRR writes", `65535000`, "false"},
	{"fractional", `1.5`, ""},
	{"negative", `-1`, ""},
	{"exponent", `1e300`, ""},
	{"just above the bound", `65535001`, ""},
	{"beyond int64", `99999999999999999999`, ""},
	{"string", `"9000"`, ""},
	{"boolean", `true`, ""},
	{"null", `null`, ""},
}

// TestHelloTimerMustBeAnInteger puts each helloCases value on a synthetic active
// record. Only an integer in range establishes the active state. The others write
// no passive value and get a note that names the timer.
func TestHelloTimerMustBeAnInteger(t *testing.T) {
	for _, c := range helloCases {
		t.Run(c.name, func(t *testing.T) {
			res := importSynth(t, synthIface(map[string]any{"timerHelloInMsecs": json.RawMessage(c.raw)}))
			if got := ifaceFacts(t, res, "r3", "e3")["ospf.passive"]; got != c.want {
				t.Errorf("timerHelloInMsecs %s: ospf.passive = %q, want %q", c.raw, got, c.want)
			}
			if c.want == "" && noteWith(capNotes(t, res, "r3", CommandInterface), "timerHelloInMsecs") == "" {
				t.Errorf("timerHelloInMsecs %s: no note names the timer", c.raw)
			}
		})
	}
}

// TestHelloTimerMissingWritesNoPassive drops the hello timer from an otherwise
// active-looking record. Neither key is present, so no passive value is written.
func TestHelloTimerMissingWritesNoPassive(t *testing.T) {
	res := importSynth(t, synthIface(nil, "timerHelloInMsecs"))
	checkAbsent(t, "hello timer missing", ifaceFacts(t, res, "r3", "e3"), "ospf.passive")
}

// TestHelloTimerMixedWithPassiveStillWithholds sets timerPassiveIface true beside
// each helloCases value. The record holds both keys, so the D1 withholding applies
// whatever the hello value is: no passive value and no other fact of the name.
func TestHelloTimerMixedWithPassiveStillWithholds(t *testing.T) {
	for _, c := range helloCases {
		t.Run(c.name, func(t *testing.T) {
			res := importSynth(t, synthIface(map[string]any{"timerPassiveIface": true, "timerHelloInMsecs": json.RawMessage(c.raw)}))
			checkAbsent(t, "mixed "+c.raw, ifaceFacts(t, res, "r3", "e3"), "ospf.passive", "ospf.cost", "ospf.network_type", "ospf.interface_state")
		})
	}
}

// TestHelloTimerBadValueKeepsTheCapture puts a fractional hello timer on a synthetic
// record beside the broadcast labs. The import succeeds and the neighbors of r1 stay
// mapped, so the bad value does not refuse the capture or close the ownership gate.
func TestHelloTimerBadValueKeepsTheCapture(t *testing.T) {
	caps := append(broadcastCaptures(t), rawInterfaceCapture(t, "r3", synthIface(map[string]any{"timerHelloInMsecs": json.RawMessage(`1.5`)})))
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	if len(neighborsOf(res, "r1")) == 0 {
		t.Errorf("r1 lost its neighbors to a malformed hello timer")
	}
}

// TestNewFieldValuesAreSanitized uses a synthetic state with a terminal escape.
// The note quotes the value without the escape character.
func TestNewFieldValuesAreSanitized(t *testing.T) {
	res := importSynth(t, synthIface(map[string]any{"state": "DR\x1b[2J"}))
	notes := capNotes(t, res, "r3", CommandInterface)
	n := noteWith(notes, "DR")
	if n == "" {
		t.Fatalf("no note quotes the unreadable state; notes = %q", notes)
	}
	if strings.ContainsRune(n, 0x1b) {
		t.Errorf("note %q carries the escape character", n)
	}
}

// TestNoRouteOrFIBClaim checks that no interface capture writes a route or a
// claim about forwarding. The interface facts describe OSPF interfaces only.
func TestNoRouteOrFIBClaim(t *testing.T) {
	for _, scenario := range labScenarios {
		res, err := Import(labCaptures(t, scenario))
		if err != nil {
			t.Fatal(err)
		}
		for _, cr := range res.Report.Captures {
			for _, n := range cr.Notes {
				for _, word := range []string{"FIB", "RIB", "forward"} {
					if strings.Contains(n, word) {
						t.Errorf("%s note %q mentions %s", scenario, n, word)
					}
				}
			}
		}
	}
}

// TestTopologyBytesDeterministic imports the broadcast capture in two orders and
// compares the written topology byte for byte.
func TestTopologyBytesDeterministic(t *testing.T) {
	caps := labCaptures(t, "bcast")
	rev := slices.Clone(caps)
	slices.Reverse(rev)
	a, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Import(rev)
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a.Observations)
	jb, _ := json.Marshal(b.Observations)
	if string(ja) != string(jb) {
		t.Errorf("import order changed the topology bytes")
	}
}

// findingSummaries lists the kinds and strengths of every finding one scenario
// yields from its captures alone, with no declared overlay.
func findingSummaries(t *testing.T, scenario string) []string {
	t.Helper()
	res, err := Import(labCaptures(t, scenario))
	if err != nil {
		t.Fatal(err)
	}
	return summarize(ospf.Analyze(mustModel(t, res)))
}

// TestFindingsUnchangedForCommittedCaptures pins the findings each committed lab
// yields from its captures alone. The new facts and the withholding must not add
// or remove a finding for any of them. The expected lists are the output at the
// base commit, before PR 6 changed the importer.
func TestFindingsUnchangedForCommittedCaptures(t *testing.T) {
	reported := []string{"neighbor_state/reported", "neighbor_state/reported"}
	want := map[string][]string{
		"bcast":     reported,
		"p2p":       reported,
		"mtu":       reported,
		"area":      nil,
		"nbma":      nil,
		"secondary": nil,
		"passive1":  nil,
		"cost50":    reported,
		"mixp2p":    reported,
		"secp1":     nil,
		"secp2":     nil,
		"down1":     nil,
	}
	for _, scenario := range labScenarios {
		if got := findingSummaries(t, scenario); !slices.Equal(got, want[scenario]) {
			t.Errorf("%s findings = %v, want %v", scenario, got, want[scenario])
		}
	}
}

// TestEveryFRRNetworkTypeAndStateIsMapped checks each value FRR 10.7.0 prints for
// networkType and for an interface's own state. Each maps to the lowercase name
// the topology uses. Null is not an FRR network type, and TestNullNewFieldIsUnreadable
// covers it.
func TestEveryFRRNetworkTypeAndStateIsMapped(t *testing.T) {
	for frr, want := range map[string]string{
		"POINTOPOINT": "point-to-point", "BROADCAST": "broadcast", "NBMA": "nbma",
		"POINTOMULTIPOINT": "point-to-multipoint", "VIRTUALLINK": "virtual-link", "LOOPBACK": "loopback",
	} {
		res := importSynth(t, synthIface(map[string]any{"networkType": frr}))
		checkFacts(t, "networkType "+frr, ifaceFacts(t, res, "r3", "e3"), map[string]string{keyNetworkType: want})
	}
	for frr, want := range map[string]string{
		"DependUpon": "dependupon", "Down": "down", "Loopback": "loopback", "Waiting": "waiting",
		"Point-To-Point": "point-to-point", "DROther": "drother", "Backup": "backup", "DR": "dr",
	} {
		res := importSynth(t, synthIface(map[string]any{"state": frr}))
		checkFacts(t, "state "+frr, ifaceFacts(t, res, "r3", "e3"), map[string]string{keyInterfaceState: want})
	}
}

// TestUnspecifiedDRIsNotChecked gives a point-to-point and a waiting broadcast
// record drAddress and bdrAddress 0.0.0.0, the value FRR prints when no DR
// exists. An unspecified address is no DR, so the subnet check does not treat it
// as outside the subnet, and every fact stays.
func TestUnspecifiedDRIsNotChecked(t *testing.T) {
	cases := []struct {
		name string
		set  map[string]any
		want map[string]string
	}{
		{"point-to-point", map[string]any{"networkType": "POINTOPOINT", "state": "Point-To-Point", "drAddress": "0.0.0.0", "bdrAddress": "0.0.0.0"},
			map[string]string{"ospf.cost": "10", "ospf.network_type": "point-to-point", "ospf.interface_state": "point-to-point", "ospf.passive": "false"}},
		{"waiting broadcast", map[string]any{"state": "Waiting", "drAddress": "0.0.0.0", "bdrAddress": "0.0.0.0"},
			map[string]string{"ospf.cost": "10", "ospf.network_type": "broadcast", "ospf.interface_state": "waiting", "ospf.passive": "false"}},
	}
	for _, c := range cases {
		res := importSynth(t, synthIface(c.set))
		checkFacts(t, c.name, ifaceFacts(t, res, "r3", "e3"), c.want)
		notes := capNotes(t, res, "r3", CommandInterface)
		if n := noteWith(notes, "facts withheld"); n != "" {
			t.Errorf("%s: unspecified DR withheld facts: %s", c.name, n)
		}
		if n := noteWith(notes, "is outside"); n != "" {
			t.Errorf("%s: unspecified DR reported as outside the subnet: %s", c.name, n)
		}
	}
}
