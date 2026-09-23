package snapshot

import (
	"reflect"
	"testing"
)

// allocatingRedactor is a redactor past collection, holding only the pinned
// local identity, so each test decides what is mapped after the replacement
// table was first built.
func allocatingRedactor(t *testing.T) *redactor {
	t.Helper()
	pinLocalIdentity(t)
	r := newRedactor()
	r.finishCollection()
	if r.replaceKnown("warm") != "warm" || r.replacements == nil {
		t.Fatal("replacement table was not built from the seeded identity")
	}
	return r
}

func TestReplacementTableCachesEmptyResult(t *testing.T) {
	r := &redactor{
		aliases: map[string]map[string]string{},
		ips:     map[string]string{},
	}

	if got := r.replacementTable(); got == nil {
		t.Fatal("empty replacement table was not cached")
	}
	if r.replacements == nil {
		t.Fatal("empty replacement table left cache invalid")
	}

	if got := r.replacementTable(); got == nil {
		t.Fatal("cached empty replacement table was lost")
	}
}

func TestReplacementTableSeesAliasAddedAfterItWasBuilt(t *testing.T) {
	r := allocatingRedactor(t)
	alias := r.alias("interface", "bench-wg0")
	if got, want := r.replaceKnown("via bench-wg0"), "via "+alias; got != want {
		t.Fatalf("replaceKnown = %q, want %q", got, want)
	}
}

func TestReplacementTableSeesAddressAddedAfterItWasBuilt(t *testing.T) {
	r := allocatingRedactor(t)
	alias := r.address("10.77.0.9")
	if got, want := r.replaceKnown("gateway 10.77.0.9 down"), "gateway "+alias+" down"; got != want {
		t.Fatalf("replaceKnown = %q, want %q", got, want)
	}
}

// A second spelling of a mapped host takes the existing alias without
// allocating one, and the table still has to learn the new spelling.
func TestReplacementTableSeesEquivalentSpellingAddedAfterItWasBuilt(t *testing.T) {
	r := allocatingRedactor(t)
	alias := r.alias("host", "Corp.Example")
	if got := r.replaceKnown("corp.example. failed"); got != "corp.example. failed" {
		t.Fatalf("spelling was replaced before it was mapped: %q", got)
	}
	if got := r.alias("host", "corp.example."); got != alias {
		t.Fatalf("equivalent spelling alias = %q, want %q", got, alias)
	}
	if got, want := r.replaceKnown("corp.example. failed"), alias+" failed"; got != want {
		t.Fatalf("replaceKnown = %q, want %q", got, want)
	}
}

// The local short name is mapped by finishCollection itself rather than by
// alias(), after the collection pass already ran the text pass.
func TestReplacementTableSeesLocalShortNameMappedByFinishCollection(t *testing.T) {
	pinLocalIdentity(t)
	r := newRedactor()
	r.text("sanitizer-test-box is up")
	r.finishCollection()
	alias := r.aliases["host"]["sanitizer-test-box.example"]
	if got, want := r.replaceKnown("sanitizer-test-box is up"), alias+" is up"; alias == "" || got != want {
		t.Fatalf("replaceKnown = %q, want %q", got, want)
	}
}

func TestReplacementTableIsReusedUntilAMappingChanges(t *testing.T) {
	r := allocatingRedactor(t)
	r.alias("interface", "bench-wg0")
	r.text("first field")
	built := r.replacements
	r.text("second field")
	r.text("third field names bench-wg0")
	if len(r.replacements) == 0 || &r.replacements[0] != &built[0] {
		t.Fatal("replacement table was rebuilt without a mapping change")
	}
	r.address("10.77.0.9")
	if r.replacements != nil {
		t.Fatal("new address mapping left the replacement table in place")
	}
}

// Longest key first, then byte order, then the target, which only matters
// when one spelling is a key in two mappings. This pins determinism only:
// which pseudonym free text gets for a spelling that is also a recorded
// address is replaceKnown's rule, tested with the value semantics.
func TestReplacementTableOrder(t *testing.T) {
	want := []replacement{
		{"192.0.2.1", "10.0.0.1"}, {"192.0.2.1", "interface-1"}, {"abc", "x"},
		{"ab", "x"}, {"ba", "x"}, {"a", "x"}, {"b", "x"},
	}
	for range 20 {
		r := &redactor{aliases: map[string]map[string]string{}, ips: map[string]string{}}
		r.aliases["value"] = map[string]string{"b": "x", "ab": "x", "a": "x", "ba": "x", "abc": "x"}
		r.aliases["interface"] = map[string]string{"192.0.2.1": "interface-1"}
		r.ips["192.0.2.1"] = "10.0.0.1"
		if got := r.replacementTable(); !reflect.DeepEqual(got, want) {
			t.Fatalf("replacement table = %v, want %v", got, want)
		}
	}
}
