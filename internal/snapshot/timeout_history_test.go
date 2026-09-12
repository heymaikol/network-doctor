package snapshot

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// options.probe_timeout_ms is an integer millisecond field, and the only thing
// zero can mean in it is "this artifact does not say". Two histories produce
// that: a producer predating the field, whose JSON omits the key, and a
// producer old enough to have truncated a sub-millisecond timeout into it.
// Neither is a reason to refuse the file, so both still decode, and the reader
// is not tightened to chase the newer producer's guarantee.
func TestHistoricalSnapshotsWithNoRecordedTimeoutStillDecode(t *testing.T) {
	// #nosec G304 -- a repository-owned fixture path.
	data, err := os.ReadFile("testdata/example.ndoc")
	if err != nil {
		t.Fatal(err)
	}
	base, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if base.Options.ProbeTimeoutMs != 4000 {
		t.Fatalf("fixture probe_timeout_ms = %d, want 4000", base.Options.ProbeTimeoutMs)
	}
	for _, tc := range []struct{ name, json string }{
		{"field absent", strings.Replace(string(data), `"probe_timeout_ms": 4000,`, "", 1)},
		{"field zero", strings.Replace(string(data), `"probe_timeout_ms": 4000`, `"probe_timeout_ms": 0`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(tc.json, "probe_timeout_ms") != map[string]int{"field absent": 0, "field zero": 1}[tc.name] {
				t.Fatalf("fixture edit did not apply: %q", tc.name)
			}
			s, err := Decode([]byte(tc.json))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if s.Options.ProbeTimeoutMs != 0 {
				t.Errorf("probe_timeout_ms = %d, want 0", s.Options.ProbeTimeoutMs)
			}
			// Unchanged otherwise: an absent timeout is not an absent artifact.
			s.Options.ProbeTimeoutMs = base.Options.ProbeTimeoutMs
			got, want := mustJSON(t, s), mustJSON(t, base)
			if got != want {
				t.Errorf("the rest of the artifact changed:\n got %s\nwant %s", got, want)
			}
		})
	}
}

// A negative count is not a history, it is a corrupt field, and it stays
// refused. The upper end is deliberately not validated here: this reader never
// turns the number into a time.Duration, so an out-of-range value has nothing
// to overflow, and tightening it would refuse artifacts written before the
// producer's own bound existed.
func TestProbeTimeoutValidationBoundsOnlyWhatTheArtifactCanEstablish(t *testing.T) {
	for _, tc := range []struct {
		name string
		ms   int64
		ok   bool
	}{
		{"negative", -1, false},
		{"absent", 0, true},
		{"smallest recorded", 1, true},
		{"ordinary", 4000, true},
		{"beyond a Duration", 9223372036855, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInvocation(nil, Options{ProbeTimeoutMs: tc.ms, PublicDNS: "8.8.8.8"})
			if tc.ok && err != nil {
				t.Errorf("probe_timeout_ms = %d rejected: %v", tc.ms, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("probe_timeout_ms = %d accepted, want rejected", tc.ms)
			}
		})
	}
}

func mustJSON(t *testing.T, s Snapshot) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
