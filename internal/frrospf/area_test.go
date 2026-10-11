package frrospf

import (
	"reflect"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// controlInterfaces returns each control-plane interface of an import by node
// and name, so a test can read its attributes.
func controlInterfaces(res Result) map[string]map[string]netmodel.Interface {
	out := map[string]map[string]netmodel.Interface{}
	for _, o := range res.Observations {
		if o.Plane != netmodel.PlaneControl {
			continue
		}
		if out[o.Node] == nil {
			out[o.Node] = map[string]netmodel.Interface{}
		}
		for _, i := range o.Interfaces {
			out[o.Node][i.Name] = i
		}
	}
	return out
}

// TestImportWritesEffectiveAreaFromGenuineCaptures imports the area lab, where
// r2 sits in 0.0.0.1 and r1 in 0.0.0.0. Each control interface carries the area
// its own side reports, and no interface carries the ospf.area key.
func TestImportWritesEffectiveAreaFromGenuineCaptures(t *testing.T) {
	res, err := Import([]Capture{
		fixture(t, "area", "r1", CommandInterface),
		fixture(t, "area", "r2", CommandInterface),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"r1": {"e1": "0.0.0.0", "stub1": "0.0.0.0"},
		"r2": {"e2": "0.0.0.1", "stub2": "0.0.0.1"},
	}
	got := controlInterfaces(res)
	for node, ifaces := range want {
		for name, area := range ifaces {
			i, ok := got[node][name]
			if !ok {
				t.Fatalf("%s lacks interface %s", node, name)
			}
			if v, _ := attr(i.Attributes, "ospf.effective_area"); v != area {
				t.Errorf("%s %s ospf.effective_area = %q, want %q", node, name, v, area)
			}
		}
	}
	for node, ifaces := range got {
		for name, i := range ifaces {
			if _, ok := attr(i.Attributes, "ospf.area"); ok {
				t.Errorf("%s %s wrote ospf.area; the import writes only ospf.effective_area", node, name)
			}
		}
	}
}

// TestImportSecondaryAddressShowsOneAreaPerInterfaceName imports the secondary
// lab. r1 e1 holds a primary address in 0.0.0.0 and a secondary in 0.0.0.1, and
// FRR prints only the secondary's record under the name e1. The import writes
// that one value and nothing else for e1.
func TestImportSecondaryAddressShowsOneAreaPerInterfaceName(t *testing.T) {
	res, err := Import([]Capture{fixture(t, "secondary", "r1", CommandInterface)})
	if err != nil {
		t.Fatal(err)
	}
	e1 := controlInterfaces(res)["r1"]["e1"]
	var values []string
	for _, a := range e1.Attributes {
		if a.Key == "ospf.effective_area" {
			values = append(values, a.Value)
		}
	}
	if len(values) != 1 || values[0] != "0.0.0.1" {
		t.Errorf("e1 ospf.effective_area values = %q, want exactly [0.0.0.1]", values)
	}
}

// TestImportNotesAreaThatIsNotAPlainDottedID checks that a qualified, incomplete,
// invalid, or absent area leaves the interface without an effective area. The
// capture is still accepted, and the note says why.
func TestImportNotesAreaThatIsNotAPlainDottedID(t *testing.T) {
	tests := []struct {
		name string
		edit func(rec map[string]any)
		note string
	}{
		{"stub qualifier", func(rec map[string]any) { rec["area"] = "0.0.0.0 [Stub]" }, "carries a qualifier"},
		{"nssa qualifier", func(rec map[string]any) { rec["area"] = "0.0.0.0 [NSSA]" }, "carries a qualifier"},
		{"unknown qualifier", func(rec map[string]any) { rec["area"] = "0.0.0.0 [Foo]" }, "is not a dotted area ID"},
		{"incomplete", func(rec map[string]any) { rec["area"] = "(incomplete)" }, "(incomplete)"},
		{"decimal", func(rec map[string]any) { rec["area"] = "0" }, "is not a dotted area ID"},
		{"empty", func(rec map[string]any) { rec["area"] = "" }, "is not a dotted area ID"},
		{"null", func(rec map[string]any) { rec["area"] = nil }, "area is missing"},
		{"absent", func(rec map[string]any) { delete(rec, "area") }, "area is missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fixture(t, "bcast", "r2", CommandInterface)
			c.Data = editInterface(t, c.Data, "e2", tt.edit)
			res, err := Import([]Capture{c})
			if err != nil {
				t.Fatal(err)
			}
			cr := res.Report.Captures[0]
			if !cr.Accepted {
				t.Fatalf("capture refused: %s", cr.Reason)
			}
			if !strings.Contains(strings.Join(cr.Notes, "\n"), tt.note) {
				t.Errorf("notes %q lack %q", cr.Notes, tt.note)
			}
			e2 := controlInterfaces(res)["r2"]["e2"]
			if v, ok := attr(e2.Attributes, "ospf.effective_area"); ok {
				t.Errorf("e2 wrote ospf.effective_area = %q; want none", v)
			}
			if len(e2.Addresses) != 1 {
				t.Errorf("e2 lost its address: %v", e2.Addresses)
			}
		})
	}
}

// TestImportRefusesNonStringArea checks that an area of the wrong JSON type
// refuses the whole capture, as the other interface fields do.
func TestImportRefusesNonStringArea(t *testing.T) {
	for _, v := range []any{1, true, []any{"0.0.0.0"}, map[string]any{"id": "0.0.0.0"}} {
		c := fixture(t, "bcast", "r2", CommandInterface)
		c.Data = editInterface(t, c.Data, "e2", func(rec map[string]any) { rec["area"] = v })
		res, err := Import([]Capture{c})
		if err != nil {
			t.Fatal(err)
		}
		if cr := res.Report.Captures[0]; cr.Accepted || !strings.Contains(cr.Reason, "malformed interface output") {
			t.Errorf("area %v: accepted=%v reason=%q, want refused as malformed", v, cr.Accepted, cr.Reason)
		}
	}
}

// TestImportAreaKeyIsSpelledExactly checks that a folded spelling of area is
// refused the same way as a folded spelling of any other decoded field.
func TestImportAreaKeyIsSpelledExactly(t *testing.T) {
	if err := checkStrictJSON([]byte(`{"interfaces":{"e1":{"Area":"0.0.0.0"}}}`)); err == nil {
		t.Error(`field spelled "Area" accepted`)
	}
}

// TestImportClaimsNoCompleteness checks that importing interface and neighbor
// captures claims neither neighbors nor routes complete.
func TestImportClaimsNoCompleteness(t *testing.T) {
	res, err := Import(broadcastCaptures(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range res.Observations {
		if o.NeighborsComplete || o.RoutesComplete {
			t.Errorf("%s %s claims completeness: neighbors %v routes %v", o.Node, o.Plane, o.NeighborsComplete, o.RoutesComplete)
		}
	}
}

// TestImportAreaIsIndependentOfCaptureOrder checks that the area lab, where the
// two sides disagree, gives one result whichever capture is read first.
func TestImportAreaIsIndependentOfCaptureOrder(t *testing.T) {
	forward := []Capture{
		fixture(t, "area", "r1", CommandInterface),
		fixture(t, "area", "r2", CommandInterface),
	}
	reversed := []Capture{forward[1], forward[0]}
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

// TestImportWithholdsAreaThatANeighborContradicts imports the secondary lab.
// FRR prints one interface record for e1, the secondary's, while the Full
// adjacency is on the primary address. The adjacency's neighbor record names a
// local address that the interface record does not give, so the area on that
// record is not this adjacency's. The area is withheld with a note, and the
// neighbor record stays unmapped, as it was before.
func TestImportWithholdsAreaThatANeighborContradicts(t *testing.T) {
	res, err := Import([]Capture{
		fixture(t, "secondary", "r1", CommandInterface),
		fixture(t, "secondary", "r1", CommandNeighborDetail),
		fixture(t, "secondary", "r2", CommandInterface),
		fixture(t, "secondary", "r2", CommandNeighborDetail),
	})
	if err != nil {
		t.Fatal(err)
	}
	ifaces := controlInterfaces(res)
	if v, ok := attr(ifaces["r1"]["e1"].Attributes, "ospf.effective_area"); ok {
		t.Errorf("r1 e1 wrote ospf.effective_area = %q; the adjacency's area is unknown", v)
	}
	if v, _ := attr(ifaces["r2"]["e2"].Attributes, "ospf.effective_area"); v != "0.0.0.0" {
		t.Errorf("r2 e2 ospf.effective_area = %q, want 0.0.0.0; its record agrees with the adjacency", v)
	}
	var notes string
	for _, c := range res.Report.Captures {
		if c.Node == "r1" && c.Command == CommandInterface {
			notes = strings.Join(c.Notes, "\n")
		}
	}
	if !strings.Contains(notes, `interface "e1": area withheld`) {
		t.Errorf("r1 interface notes %q lack the withheld area", notes)
	}
	var unmapped bool
	for _, r := range res.Report.Records {
		if r.Node == "r1" && r.LocalInterface == "e1" && !r.Mapped && strings.Contains(r.Reason, "localIfaceAddress") {
			unmapped = true
		}
	}
	if !unmapped {
		t.Errorf("r1 e1 neighbor record is not reported as unmapped on its local address: %+v", res.Report.Records)
	}
}

// TestImportKeepsAreaWhenNeighborsAgree checks that the withholding does not
// touch a lab where every neighbor record names the interface's own address.
func TestImportKeepsAreaWhenNeighborsAgree(t *testing.T) {
	res, err := Import(broadcastCaptures(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Report.Captures {
		if strings.Contains(strings.Join(c.Notes, "\n"), "area withheld") {
			t.Errorf("%s %s withheld an area although its neighbors agree: %v", c.Node, c.Command, c.Notes)
		}
	}
	if v, _ := attr(controlInterfaces(res)["r1"]["e1"].Attributes, "ospf.effective_area"); v != "0.0.0.0" {
		t.Errorf("r1 e1 ospf.effective_area = %q, want 0.0.0.0", v)
	}
}
