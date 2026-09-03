package snapshot

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// goldenPath is the fixture internal/diagnostic writes and this package reads.
// One file, two packages: the builder test proves netdoc still produces these
// bytes, and the tests here prove they are still readable by a decoder that
// has never seen a probe.
const goldenPath = "testdata/example.ndoc"

func golden(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden snapshot: %v", err)
	}
	return data
}

// The whole point of the package boundary: a snapshot decodes with no probe
// structs, no live run, and no network in reach. If this file ever needs an
// import from internal/diagnostic to make sense of a .ndoc, the format has
// leaked runtime detail and TestPackageLayering will say so first.
func TestDecodeGoldenWithoutRuntimeStructs(t *testing.T) {
	s, err := Decode(golden(t))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if s.Schema != Schema {
		t.Errorf("schema = %q, want %q", s.Schema, Schema)
	}
	if s.Target == nil || s.Target.Host != "example.com" || s.Target.Port != 443 {
		t.Fatalf("target = %+v", s.Target)
	}
	if s.Target.Raw != "example.com" || s.Target.Protocol != "tls+http" {
		t.Errorf("target spelling/protocol = %+v", s.Target)
	}
	if s.OK {
		t.Error("ok = true, want false: the fixture has a failing check")
	}
	if s.Diagnosis.FailedStage != "target_tcp" {
		t.Errorf("failed_stage = %q, want target_tcp", s.Diagnosis.FailedStage)
	}
	if len(s.Checks) == 0 {
		t.Fatal("no checks decoded")
	}
	byID := map[string]Check{}
	for _, c := range s.Checks {
		byID[c.ID] = c
	}
	dns, ok := byID["dns"]
	if !ok {
		t.Fatal("no dns check in the fixture")
	}
	if dns.Observed == nil || len(dns.Observed.Addresses) != 2 {
		t.Fatalf("dns observed = %+v", dns.Observed)
	}
	if got := byID["tls"]; got.Ran || got.DurationMs != 0 {
		t.Errorf("tls ran = %v (%dms), want a row that never ran", got.Ran, got.DurationMs)
	}
}

// A snapshot written by a later netdoc must be refused outright. Decoding it
// as v1 would read fields whose meaning may have changed, which is worse than
// saying no.
func TestDecodeRejectsUnsupportedSchema(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"future version", `{"schema":"netdoc.snapshot.v2","checks":[]}`, "netdoc.snapshot.v2"},
		{"another artifact", `{"schema":"netdoc.peer.v1"}`, "netdoc.peer.v1"},
		{"no schema at all", `{"checks":[]}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Decode([]byte(tt.data))
			var unsupported UnsupportedSchemaError
			if !errors.As(err, &unsupported) {
				t.Fatalf("Decode error = %v, want UnsupportedSchemaError", err)
			}
			if unsupported.Found != tt.want {
				t.Errorf("found = %q, want %q", unsupported.Found, tt.want)
			}
			if s.Schema != "" || len(s.Checks) != 0 {
				t.Errorf("decoded %+v, want the zero snapshot", s)
			}
			if !strings.Contains(err.Error(), Schema) {
				t.Errorf("error %q never says which schema this build reads", err)
			}
		})
	}
}

// The schema check happens before anything else is looked at, so a v2 file is
// refused even when the rest of it is nonsense a v1 decode would choke on.
func TestDecodeChecksSchemaBeforeContent(t *testing.T) {
	_, err := Decode([]byte(`{"schema":"netdoc.snapshot.v2","checks":"not an array"}`))
	var unsupported UnsupportedSchemaError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want the schema refusal, not a type error", err)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode([]byte("not json at all")); err == nil {
		t.Fatal("Decode accepted a non-JSON file")
	}
}

// An added optional field is the compatible change the version policy promises,
// so a decoder must ignore what it does not know rather than refuse the file.
func TestDecodeIgnoresUnknownFields(t *testing.T) {
	s, err := Decode([]byte(`{"schema":"` + Schema + `","ok":true,"invented_later":{"a":1}}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !s.OK {
		t.Error("ok = false, want the value that was in the file")
	}
}

func TestDecodePreEvidenceV1DoesNotInventCausalEvidence(t *testing.T) {
	data := []byte(`{"schema":"` + Schema + `","checks":[{"id":"dns","status":"FAIL","ran":true,"duration_ms":1}],"diagnosis":{"verdict":"dns","summary":"DNS failed","findings":[{"id":"dns_failure","verdict":"dns","summary":"DNS failed","focus":"dns","evidence":["dns"]}]},"ok":false}`)
	s, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode pre-evidence v1: %v", err)
	}
	if len(s.Diagnosis.Findings) != 1 || s.Diagnosis.Findings[0].CausalEvidence != nil {
		t.Fatalf("old snapshot gained historical evidence: %+v", s.Diagnosis.Findings)
	}
	reencoded, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reencoded), "causal_evidence") {
		t.Errorf("round trip invented causal evidence:\n%s", reencoded)
	}
}

func TestCausalEvidenceValidation(t *testing.T) {
	base := func() Snapshot {
		return Snapshot{
			Checks: []Check{
				{ID: "dns", Status: StatusFail, Ran: true, DurationMs: 1},
				{ID: "public_dns", Status: StatusPass, Ran: true, DurationMs: 1,
					Observed: &Observed{Addresses: []string{"192.0.2.1"}}},
				{ID: "target_tcp", Status: StatusSkip},
			},
			Diagnosis: Diagnosis{Findings: []Finding{{
				ID: "system_dns_failure",
				CausalEvidence: []CausalEvidence{
					{Kind: EvidenceSupport, Check: "dns", Observation: ObservationStatusFail},
					{Kind: EvidenceRuledOut, Check: "public_dns", Observation: ObservationDNSAnswers, Candidate: "dns_name_not_found"},
					{Kind: EvidenceNotEvaluated, Check: "target_tcp", Observation: ObservationStatusSkip, Reason: NotEvaluatedPrerequisite},
				},
			}}},
		}
	}
	if _, err := Encode(base()); err != nil {
		t.Fatalf("valid causal evidence rejected: %v", err)
	}
	tests := []struct {
		name string
		edit func(*Snapshot)
		want string
	}{
		{"missing check", func(s *Snapshot) { s.Diagnosis.Findings[0].CausalEvidence[0].Check = "missing" }, "not in the snapshot"},
		{"absent observation", func(s *Snapshot) { s.Diagnosis.Findings[0].CausalEvidence[0].Observation = ObservationDNSAnswers }, "observation is absent"},
		{"ruled out from skipped", func(s *Snapshot) {
			s.Diagnosis.Findings[0].CausalEvidence[1] = CausalEvidence{Kind: EvidenceRuledOut, Check: "target_tcp", Observation: ObservationStatusSkip, Candidate: "target_unreachable"}
		}, "cannot use an unevaluated observation"},
		{"unknown not-evaluated reason", func(s *Snapshot) { s.Diagnosis.Findings[0].CausalEvidence[2].Reason = "unknown" }, "unknown not-evaluated reason"},
		{"duplicate", func(s *Snapshot) {
			s.Diagnosis.Findings[0].CausalEvidence = append(s.Diagnosis.Findings[0].CausalEvidence, s.Diagnosis.Findings[0].CausalEvidence[0])
		}, "repeats causal evidence"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := base()
			tt.edit(&s)
			if _, err := Encode(s); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Encode error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// Confidence is a closed vocabulary, so it round-trips exactly and a value
// from outside the set is refused in both directions like every other rule
// here: reading an unknown strength would be reading a claim this build cannot
// interpret. Absence stays absent, because a producer that assessed nothing is
// not the same as one that assessed a weak conclusion.
func TestConfidenceRoundTripsAndRejectsUnknownValues(t *testing.T) {
	base := func(confidence string) Snapshot {
		return Snapshot{
			Checks: []Check{{ID: "dns", Status: StatusFail, Ran: true, DurationMs: 1}},
			Diagnosis: Diagnosis{Findings: []Finding{{
				ID: "dns_failure", Verdict: "dns", Summary: "DNS is failing.", Confidence: confidence,
			}}},
		}
	}
	for _, level := range []string{"", ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceInsufficientEvidence} {
		data, err := Encode(base(level))
		if err != nil {
			t.Fatalf("Encode %q: %v", level, err)
		}
		if level == "" && strings.Contains(string(data), "confidence") {
			t.Errorf("an unassessed finding published a confidence key:\n%s", data)
		}
		decoded, err := Decode(data)
		if err != nil {
			t.Fatalf("Decode %q: %v", level, err)
		}
		if got := decoded.Diagnosis.Findings[0].Confidence; got != level {
			t.Errorf("confidence round-tripped as %q, want %q", got, level)
		}
	}

	if _, err := Encode(base("very_high")); err == nil || !strings.Contains(err.Error(), "unknown confidence") {
		t.Errorf("Encode error = %v, want it to refuse an unknown confidence", err)
	}
	valid, err := Encode(base(ConfidenceHigh))
	if err != nil {
		t.Fatal(err)
	}
	future := strings.Replace(string(valid), `"confidence": "high"`, `"confidence": "certain"`, 1)
	if _, err := Decode([]byte(future)); err == nil || !strings.Contains(err.Error(), "unknown confidence") {
		t.Errorf("Decode error = %v, want it to refuse an unknown confidence", err)
	}
}

// Encode stamps the schema itself, so a caller cannot publish a file that
// claims to be something else, or forget to claim anything.
func TestEncodeStampsSchema(t *testing.T) {
	data, err := Encode(Snapshot{Schema: "netdoc.snapshot.v99"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	s, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if s.Schema != Schema {
		t.Errorf("schema = %q, want %q", s.Schema, Schema)
	}
}

// The serialized shape is the contract, not the Go struct. This pins the
// top-level key set and its order by reading the raw JSON rather than
// unmarshalling into the type that produced it, which would agree with itself
// no matter what the names were.
func TestSerializedTopLevelShape(t *testing.T) {
	want := []string{"schema", "created_at", "tool", "target", "options", "checks", "diagnosis", "ok"}
	got := topLevelKeys(t, golden(t))
	if len(got) != len(want) {
		t.Fatalf("top-level keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %d = %q, want %q (order is part of the deterministic encoding)", i, got[i], want[i])
		}
	}
}

// topLevelKeys reads object keys in file order, without a struct in the way.
func topLevelKeys(t *testing.T, data []byte) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(data)))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("first token = %v (%v), want an object", tok, err)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		key, ok := tok.(string)
		if !ok {
			t.Fatalf("key token = %v, want a string", tok)
		}
		keys = append(keys, key)
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			t.Fatalf("skip value of %q: %v", key, err)
		}
	}
	return keys
}

// A target-less run publishes target: null, not a missing key and not an empty
// object, because "this run had no target" is a fact a comparison reads.
func TestGenericRunKeepsExplicitNullTarget(t *testing.T) {
	data, err := Encode(Snapshot{Checks: []Check{}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.Contains(string(data), `"target": null`) {
		t.Errorf("no explicit null target in:\n%s", data)
	}
}

// Two encodes of the same snapshot are the same bytes. The schema uses no maps
// anywhere, which is what makes that true rather than lucky.
func TestEncodeIsDeterministic(t *testing.T) {
	s, err := Decode(golden(t))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	first, err := Encode(s)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for i := 0; i < 8; i++ {
		again, err := Encode(s)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if string(again) != string(first) {
			t.Fatalf("encode %d differs from the first", i)
		}
	}
	// A decoded golden re-encodes to the file it came from: the round trip is
	// lossless and stable, which is what lets a future reader diff two files
	// line by line instead of parsing both.
	if string(first) != string(golden(t)) {
		t.Errorf("re-encoded golden differs from the file on disk:\n%s", first)
	}
}

// Optional state has to survive the round trip as the distinct thing it is: an
// absent reading, a false boolean, and a zero measurement must not collapse
// into each other.
func TestRoundTripPreservesOptionalStates(t *testing.T) {
	zero := int64(0)
	s := Snapshot{
		Checks: []Check{
			{ID: "never_ran", Name: "Never ran", Status: "SKIP"},
			{ID: "instant", Name: "Instant", Status: "PASS", Ran: true, DurationMs: 1},
			{ID: "measured_zero_skew", Name: "Zero skew", Status: "PASS", Ran: true, DurationMs: 2,
				Observed: &Observed{ClockOffsetMs: &zero}},
			{ID: "portal_no_url", Name: "Portal", Status: "WARN", Ran: true, DurationMs: 3,
				Observed: &Observed{Portal: &Portal{}}},
			{ID: "one_family", Name: "One family", Status: "WARN", Ran: true, DurationMs: 4,
				Observed: &Observed{Families: &Families{IPv4: "reachable"}}},
			{ID: "downgraded", Name: "Downgraded", Status: "WARN", Ran: true, DurationMs: 5,
				Derived: &Derived{StatusDowngraded: true}},
		},
	}
	data, err := Encode(s)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	byID := map[string]Check{}
	for _, c := range got.Checks {
		byID[c.ID] = c
	}
	if c := byID["never_ran"]; c.Ran || c.DurationMs != 0 || c.Observed != nil || c.Derived != nil {
		t.Errorf("never_ran = %+v, want an unmeasured row", c)
	}
	if c := byID["instant"]; !c.Ran || c.DurationMs != 1 {
		t.Errorf("instant = %+v, want ran with 1ms", c)
	}
	// The one that a plain omitempty int would destroy: a measured offset of
	// exactly zero is a reading, and it must not read as "no reading".
	c := byID["measured_zero_skew"]
	if c.Observed == nil || c.Observed.ClockOffsetMs == nil || *c.Observed.ClockOffsetMs != 0 {
		t.Errorf("measured zero clock offset lost: %+v", c.Observed)
	}
	if c := byID["portal_no_url"]; c.Observed == nil || c.Observed.Portal == nil || c.Observed.Portal.RedirectURL != "" {
		t.Errorf("portal without a URL lost: %+v", c.Observed)
	}
	if c := byID["one_family"]; c.Observed == nil || c.Observed.Families == nil ||
		c.Observed.Families.IPv4 != "reachable" || c.Observed.Families.IPv6 != "" {
		t.Errorf("single-family state lost: %+v", c.Observed)
	}
	if c := byID["downgraded"]; c.Derived == nil || !c.Derived.StatusDowngraded {
		t.Errorf("inferred status lost: %+v", c.Derived)
	}
}

func TestIncidentRoundTripAndOlderV1Compatibility(t *testing.T) {
	before := &Snapshot{CreatedAt: "2026-08-25T12:03:51Z", OK: true, Checks: []Check{}}
	during := &Snapshot{CreatedAt: "2026-08-25T12:04:01Z", Checks: []Check{}}
	recovered := &Snapshot{CreatedAt: "2026-08-25T12:04:06Z", OK: true, Checks: []Check{}}
	onset := Snapshot{
		CreatedAt: "2026-08-25T12:03:56Z", Checks: []Check{},
		Incident: &Incident{
			StartedAt: "2026-08-25T12:03:56Z", EndedAt: "2026-08-25T12:04:06Z", Passes: 2,
			Before: before, During: during, Recovered: recovered,
		},
	}
	data, err := Encode(onset)
	if err != nil {
		t.Fatalf("Encode incident: %v", err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode incident: %v", err)
	}
	if got.Incident == nil || got.Incident.Passes != 2 || got.Incident.Before == nil || got.Incident.During == nil || got.Incident.Recovered == nil {
		t.Fatalf("incident round trip = %+v", got.Incident)
	}
	reencoded, err := Encode(got)
	if err != nil || string(reencoded) != string(data) {
		t.Fatalf("incident encoding is not deterministic after round trip: err=%v", err)
	}
	for name, nested := range map[string]*Snapshot{"before": got.Incident.Before, "during": got.Incident.During, "recovered": got.Incident.Recovered} {
		if nested.Schema != Schema {
			t.Errorf("%s schema = %q, want %q", name, nested.Schema, Schema)
		}
	}
	// Encode stamps copies. Callers can reuse their in-memory run records
	// without the artifact writer changing them behind their back.
	if before.Schema != "" || during.Schema != "" || recovered.Schema != "" {
		t.Errorf("Encode mutated nested schemas: %q %q %q", before.Schema, during.Schema, recovered.Schema)
	}

	old, err := Decode([]byte(`{"schema":"` + Schema + `","created_at":"2026-08-25T12:00:00Z","target":null,"options":{"probe_timeout_ms":0,"public_dns":""},"checks":[],"diagnosis":{"verdict":"ok","summary":"healthy"},"ok":true}`))
	if err != nil {
		t.Fatalf("Decode older v1 snapshot: %v", err)
	}
	if old.Incident != nil {
		t.Fatalf("older v1 snapshot invented an incident: %+v", old.Incident)
	}
}

func TestIncidentValidationRejectsImpossibleHistory(t *testing.T) {
	valid := func() Snapshot {
		return Snapshot{
			Schema: Schema, CreatedAt: "2026-08-25T12:03:56Z", Checks: []Check{},
			Incident: &Incident{
				StartedAt: "2026-08-25T12:03:56Z", EndedAt: "2026-08-25T12:04:06Z", Passes: 2,
				Before:    &Snapshot{Schema: Schema, CreatedAt: "2026-08-25T12:03:51Z", OK: true, Checks: []Check{}},
				During:    &Snapshot{Schema: Schema, CreatedAt: "2026-08-25T12:04:01Z", Checks: []Check{}},
				Recovered: &Snapshot{Schema: Schema, CreatedAt: "2026-08-25T12:04:06Z", OK: true, Checks: []Check{}},
			},
		}
	}
	tests := []struct {
		name string
		edit func(*Snapshot)
		want string
	}{
		{"invalid start", func(s *Snapshot) { s.Incident.StartedAt = "yesterday" }, "RFC 3339 UTC"},
		{"onset mismatch", func(s *Snapshot) { s.CreatedAt = "2026-08-25T12:03:55Z" }, "does not match"},
		{"healthy onset", func(s *Snapshot) { s.OK = true }, "reported ok"},
		{"no passes", func(s *Snapshot) { s.Incident.Passes = 0 }, "at least the pass"},
		{"missing recovered run", func(s *Snapshot) { s.Incident.Recovered = nil }, "end time without"},
		{"end before start", func(s *Snapshot) { s.Incident.EndedAt = "2026-08-25T12:03:50Z" }, "ended before"},
		{"late baseline", func(s *Snapshot) { s.Incident.Before.CreatedAt = "2026-08-25T12:03:57Z" }, "before state"},
		{"healthy during", func(s *Snapshot) { s.Incident.During.OK = true }, "during state reports"},
		{"late during", func(s *Snapshot) { s.Incident.During.CreatedAt = "2026-08-25T12:04:07Z" }, "outside"},
		{"recovery mismatch", func(s *Snapshot) { s.Incident.Recovered.CreatedAt = "2026-08-25T12:04:07Z" }, "does not match"},
		{"nested schema", func(s *Snapshot) { s.Incident.Before.Schema = "netdoc.snapshot.v2" }, "has schema"},
		{"nested incident", func(s *Snapshot) { s.Incident.Before.Incident = &Incident{} }, "incident of its own"},
		{"mixed redaction", func(s *Snapshot) {
			s.Redaction = &Redaction{Sanitized: true, Policy: SupportRedactionPolicy}
		}, "different redaction metadata"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := valid()
			tt.edit(&s)
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Decode error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestWriteFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incident"+Extension)
	want := Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Checks: []Check{{ID: "iface", Status: "PASS", Ran: true, DurationMs: 1}}}
	if err := WriteFile(path, want); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// #nosec G304 -- path is this test's temporary snapshot file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CreatedAt != want.CreatedAt || len(got.Checks) != 1 || got.Checks[0].ID != "iface" {
		t.Errorf("round trip = %+v", got)
	}
	if !strings.HasSuffix(string(data), "}\n") {
		t.Errorf("file does not end in a newline:\n%q", data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %v, want 0600: a snapshot is the owner's to share", perm)
		}
	}
}

// Replacing an existing snapshot leaves no other file behind, and no temporary
// one either.
func TestWriteFileReplacesAndLeavesNoTemporaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incident"+Extension)
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Checks: []Check{}}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("directory holds %v, want only the snapshot", names)
	}
	// #nosec G304 -- path is this test's temporary snapshot file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err != nil {
		t.Errorf("the replaced file is not a snapshot: %v", err)
	}
}

// A destination that cannot be written reports why and leaves whatever was
// there alone, rather than truncating it into a half-written artifact.
func TestWriteFileFailureLeavesTheOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing-dir", "incident"+Extension)
	err := WriteFile(path, Snapshot{Checks: []Check{}})
	if err == nil {
		t.Fatal("WriteFile accepted a path whose directory does not exist")
	}
	if !strings.Contains(err.Error(), "missing-dir") {
		t.Errorf("error %q does not name the path that failed", err)
	}

	// And the same for a path that exists but is a directory.
	if err := WriteFile(dir, Snapshot{Checks: []Check{}}); err == nil {
		t.Error("WriteFile accepted a directory as the destination")
	}
}

// The four row states have to be four distinct strings in the file, because a
// consumer reads the file and not the Go struct that made it. This checks the
// raw JSON: an unmarshal into Check would agree with whatever the encoder did.
func TestSerializedStatusDistinguishesRowStates(t *testing.T) {
	data, err := Encode(Snapshot{Checks: []Check{
		{ID: "passed", Status: StatusPass, Ran: true, DurationMs: 1},
		{ID: "failed", Status: StatusFail, Ran: true, DurationMs: 2},
		{ID: "skipped", Status: StatusSkip},
		{ID: "unreported", Status: StatusIncomplete},
	}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var raw struct {
		Checks []map[string]json.RawMessage `json:"checks"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Literal strings on purpose. Renaming a constant must not be able to
	// change what is on disk without this failing.
	want := []struct{ id, status string }{
		{"passed", `"PASS"`},
		{"failed", `"FAIL"`},
		{"skipped", `"SKIP"`},
		{"unreported", `"INCOMPLETE"`},
	}
	if len(raw.Checks) != len(want) {
		t.Fatalf("%d rows encoded, want %d", len(raw.Checks), len(want))
	}
	for i, w := range want {
		if got := string(raw.Checks[i]["id"]); got != `"`+w.id+`"` {
			t.Fatalf("row %d id = %s", i, got)
		}
		if got := string(raw.Checks[i]["status"]); got != w.status {
			t.Errorf("%s status = %s, want %s", w.id, got, w.status)
		}
		if _, ok := raw.Checks[i]["status"]; !ok {
			t.Errorf("%s has no status key at all", w.id)
		}
	}
	// The whole point, stated as the thing a consumer would do wrong.
	if string(raw.Checks[3]["status"]) == `"`+StatusPass+`"` {
		t.Error("an unreported row serialized as a pass")
	}

	// And the distinction survives the trip back, without collapsing into ran.
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	byID := map[string]Check{}
	for _, c := range got.Checks {
		byID[c.ID] = c
	}
	if byID["passed"].Status != StatusPass || !byID["passed"].Ran {
		t.Errorf("passed = %+v", byID["passed"])
	}
	if byID["failed"].Status != StatusFail || !byID["failed"].Ran {
		t.Errorf("failed = %+v", byID["failed"])
	}
	// Two rows that both report ran false, told apart by their status alone.
	if byID["skipped"].Status != StatusSkip || byID["skipped"].Ran {
		t.Errorf("skipped = %+v", byID["skipped"])
	}
	if byID["unreported"].Status != StatusIncomplete || byID["unreported"].Ran {
		t.Errorf("unreported = %+v", byID["unreported"])
	}
}

// Encode is the boundary that keeps the invariant from being something a
// future caller has to remember: a row whose outcome is a Go zero value, or an
// unreported row dressed up as a completed or a clean one, never reaches a file.
func TestEncodeRefusesRowsThatDoNotSayWhatTheyAre(t *testing.T) {
	tests := []struct {
		name string
		s    Snapshot
		want string
	}{
		{
			"the zero check",
			Snapshot{Checks: []Check{{ID: "iface"}}},
			"no status",
		},
		{
			"incomplete but claiming to have run",
			Snapshot{Checks: []Check{{ID: "iface", Status: StatusIncomplete, Ran: true}}},
			"also ran",
		},
		{
			"incomplete inside a run called ok",
			Snapshot{OK: true, Checks: []Check{{ID: "iface", Status: StatusIncomplete}}},
			"cannot be reported ok",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := Encode(tt.s)
			if err == nil {
				t.Fatalf("Encode published:\n%s", data)
			}
			if !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "iface") {
				t.Errorf("error = %q, want it to name the row and say %q", err, tt.want)
			}
			if data != nil {
				t.Errorf("bytes returned alongside the refusal: %s", data)
			}
		})
	}
	// The same rows, honestly labelled, are perfectly publishable.
	if _, err := Encode(Snapshot{Checks: []Check{{ID: "iface", Status: StatusIncomplete}}}); err != nil {
		t.Errorf("Encode refused a well-formed incomplete row: %v", err)
	}
}

// WriteFile inherits the refusal, so a rejected snapshot creates no file at all
// rather than a valid-looking one nobody meant to publish.
func TestWriteFileRefusesAnUnlabelledRow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incident"+Extension)
	if err := WriteFile(path, Snapshot{Checks: []Check{{ID: "iface"}}}); err == nil {
		t.Fatal("WriteFile published a row with no status")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("directory holds %d entries, want nothing written", len(entries))
	}
}

// Decode applies the rules Encode enforces, so a reader cannot be handed a row
// that says nothing about itself. A hand-edited or truncated file is where this
// comes from: Encode never wrote one, which is exactly why a decoder that
// accepted it would hold an invariant only by luck. A comparison reading two
// files is the first consumer that would have silently compared the gap.
func TestDecodeRefusesRowsEncodeWouldRefuseToWrite(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"a row with no status", `"checks":[{"id":"iface"}]`, "no status"},
		{"incomplete but claiming to have run",
			`"checks":[{"id":"iface","status":"INCOMPLETE","ran":true}]`, "also ran"},
		{"incomplete inside a run called ok",
			`"ok":true,"checks":[{"id":"iface","status":"INCOMPLETE"}]`, "cannot be reported ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode([]byte(`{"schema":"` + Schema + `",` + tt.body + `}`))
			if err == nil {
				t.Fatal("Decode accepted a file Encode would refuse to write")
			}
			if !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "iface") {
				t.Errorf("error = %q, want it to name the row and say %q", err, tt.want)
			}
		})
	}
	// The honest spellings of the same rows still decode.
	if _, err := Decode([]byte(`{"schema":"` + Schema + `","checks":[{"id":"iface","status":"INCOMPLETE"}]}`)); err != nil {
		t.Errorf("Decode refused a well-formed incomplete row: %v", err)
	}
	// And a snapshot with no checks at all is still a snapshot: an empty probe
	// selection produces one.
	if _, err := Decode([]byte(`{"schema":"` + Schema + `","checks":[],"ok":true}`)); err != nil {
		t.Errorf("Decode refused a run with no checks: %v", err)
	}
}

// routeCheck is one row carrying route decisions, so the tests below state
// only the part they are about.
func routeCheck(id string, routes ...Route) Check {
	return Check{ID: id, Status: StatusFail, Ran: true, DurationMs: 1, Observed: &Observed{Routes: routes}}
}

func metricOf(n int) *int { return &n }

// Route decisions survive a round trip field for field, including the ones
// whose absence has to stay distinguishable from a zero.
func TestRoundTripPreservesRouteDecisions(t *testing.T) {
	routes := []Route{
		{
			Destination: "198.51.100.7", Family: "ipv4", Interface: "wg0",
			Source: "10.20.0.2", Prefix: "10.20.0.0/16", Metric: metricOf(0),
			Table: "table 51820", TableKnown: true, InterfaceMTU: 1420, Tunnel: TunnelStateTunnel,
			TunnelKind: "wireguard", Reason: "more_specific_than_default",
			Competing: []CompetingRoute{{Interface: "wlan0", Metric: 600}},
		},
		{Destination: "2001:db8::7", Family: "ipv6", Unreachable: true},
		{Destination: "192.168.1.1", Family: "ipv4", Interface: "eth0", Gateway: "192.168.1.1", Tunnel: TunnelStateDirect},
		{Destination: "1.1.1.1", Family: "ipv4", Interface: "eth0", TableKnown: true},
	}
	s := Snapshot{Schema: Schema, Checks: []Check{routeCheck("target_tcp", routes...)}}
	data, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	got := back.Checks[0].Observed.Routes
	if !reflect.DeepEqual(got, routes) {
		t.Errorf("routes did not survive the round trip:\n%+v\nwant\n%+v", got, routes)
	}
	// A metric of 0 is a real metric and must not come back as absence, and an
	// unreported metric must not come back as 0.
	if got[0].Metric == nil || *got[0].Metric != 0 {
		t.Errorf("metric 0 came back as %v, want a recorded zero", got[0].Metric)
	}
	if got[1].Metric != nil {
		t.Errorf("an unreported metric came back as %v, want absent", *got[1].Metric)
	}
	if !strings.Contains(string(data), `"gateway"`) {
		t.Error("a recorded gateway was dropped from the encoding")
	}
	if strings.Contains(string(data), `"interface_mtu":0`) {
		t.Errorf("an unknown interface MTU was written as zero:\n%s", data)
	}
	// The main table is a named table with an empty name, so the flag is the
	// only thing separating "the OS said main" from "the OS said nothing".
	if !got[0].TableKnown || got[0].Table != "table 51820" {
		t.Errorf("a named non-main table came back as %q/%v", got[0].Table, got[0].TableKnown)
	}
	if !got[3].TableKnown || got[3].Table != "" {
		t.Errorf("a known main table came back as %q/%v, want a known empty name", got[3].Table, got[3].TableKnown)
	}
	if got[1].TableKnown || got[2].TableKnown {
		t.Error("a route the platform said nothing about came back claiming a routing table")
	}
	if strings.Contains(string(data), `"table_known":false`) {
		t.Errorf("an unknown routing table was written as a field:\n%s", data)
	}
}

// A snapshot written before routing tables were distinguishable reads as
// "unknown" rather than as the main table, which is the reading that would
// silently make every old artifact agree with a machine that has no policy
// routing at all.
func TestDecodePreTableKnowledgeV1ReadsAsUnknown(t *testing.T) {
	data := []byte(`{"schema":"` + Schema + `","checks":[{"id":"target_tcp","status":"FAIL","ran":true,"duration_ms":1,` +
		`"observed":{"routes":[{"destination":"198.51.100.7","family":"ipv4","interface":"eth0"}]}}],"ok":false}`)
	s, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode pre-table v1: %v", err)
	}
	if route := s.Checks[0].Observed.Routes[0]; route.TableKnown {
		t.Errorf("an old snapshot gained table knowledge: %+v", route)
	}
}

// A snapshot written before route intelligence existed still loads, reads as
// "this run recorded no route decisions", and does not gain any on the way
// back out.
func TestDecodePreRouteV1DoesNotInventRoutes(t *testing.T) {
	data := []byte(`{"schema":"` + Schema + `","checks":[{"id":"target_tcp","status":"FAIL","ran":true,"duration_ms":1,"observed":{"addresses":["198.51.100.7"]}}],"ok":false}`)
	s, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode pre-route v1: %v", err)
	}
	if s.Checks[0].Observed.Routes != nil {
		t.Fatalf("an old snapshot gained routes: %+v", s.Checks[0].Observed.Routes)
	}
	reencoded, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reencoded), "routes") {
		t.Errorf("round trip invented routes:\n%s", reencoded)
	}
}

// Every route observation has to be verifiable against the row that carries
// it, in both directions: a real one is accepted, and one the row cannot
// support is refused rather than written to a file that reads as evidence.
func TestRouteObservationsAreVerifiedAgainstTheirOwnRow(t *testing.T) {
	tunnel := Route{Destination: "198.51.100.7", Family: "ipv4", Interface: "wg0", Tunnel: TunnelStateTunnel, TunnelKind: "wireguard", InterfaceMTU: 1420}
	direct := Route{Destination: "1.1.1.1", Family: "ipv4", Interface: "eth0", Tunnel: TunnelStateDirect}
	v6 := Route{Destination: "2001:db8::7", Family: "ipv6", Interface: "eth0", Tunnel: TunnelStateDirect}
	v6main := Route{Destination: "2001:db8::7", Family: "ipv6", Interface: "eth0", TableKnown: true, Tunnel: TunnelStateDirect}
	noRoute := Route{Destination: "203.0.113.9", Family: "ipv4", Unreachable: true}
	viaRouter := Route{Destination: "1.1.1.1", Family: "ipv4", Interface: "eth0", Gateway: "10.0.0.1", Tunnel: TunnelStateDirect}
	policy := Route{Destination: "1.1.1.1", Family: "ipv4", Interface: "eth0", Table: "table 51820", TableKnown: true, Tunnel: TunnelStateDirect}
	mainTable := Route{Destination: "1.1.1.1", Family: "ipv4", Interface: "eth0", TableKnown: true, Tunnel: TunnelStateDirect}
	ownTable := Route{Destination: "127.0.0.1", Family: "ipv4", Interface: "lo", Table: "local", TableKnown: true, Tunnel: TunnelStateDirect}
	v6own := Route{Destination: "::1", Family: "ipv6", Interface: "lo", Table: "local", TableKnown: true, Tunnel: TunnelStateDirect}
	v4own := Route{Destination: "127.0.0.1", Family: "ipv4", Interface: "lo", TableKnown: true, Tunnel: TunnelStateDirect}
	cases := []struct {
		name  string
		check Check
		e     CausalEvidence
		want  bool
	}{
		{"tunnel on the row that took it", routeCheck("target_tcp", tunnel), CausalEvidence{Observation: ObservationRouteTunneled, Value: "wg0"}, true},
		{"tunnel claimed for the wrong interface", routeCheck("target_tcp", tunnel), CausalEvidence{Observation: ObservationRouteTunneled, Value: "eth0"}, false},
		{"tunnel claimed on a direct row", routeCheck("iface", direct), CausalEvidence{Observation: ObservationRouteTunneled, Value: "eth0"}, false},
		{"direct on the row that took it", routeCheck("iface", direct), CausalEvidence{Observation: ObservationRouteDirect, Value: "eth0"}, true},
		{"direct claimed for an unclassified interface", routeCheck("iface", Route{Interface: "eth0"}), CausalEvidence{Observation: ObservationRouteDirect, Value: "eth0"}, false},
		{"no route to the named destination", routeCheck("target_tcp", noRoute), CausalEvidence{Observation: ObservationRouteUnreachable, Value: "203.0.113.9"}, true},
		{"no route claimed for a reachable destination", routeCheck("target_tcp", tunnel), CausalEvidence{Observation: ObservationRouteUnreachable, Value: "198.51.100.7"}, false},
		{"path differs from the named other path", routeCheck("dns", direct), CausalEvidence{Observation: ObservationRoutePathDiffers, Value: "wg0"}, true},
		{"path differs from itself", routeCheck("dns", direct), CausalEvidence{Observation: ObservationRoutePathDiffers, Value: "eth0"}, false},
		{"path differs with no other path named", routeCheck("dns", direct), CausalEvidence{Observation: ObservationRoutePathDiffers}, false},
		{"next hop differs from the named other next hop", routeCheck("dns", viaRouter), CausalEvidence{Observation: ObservationRouteNextHopDiffers, Value: "192.168.1.1"}, true},
		{"next hop differs from itself", routeCheck("dns", viaRouter), CausalEvidence{Observation: ObservationRouteNextHopDiffers, Value: "10.0.0.1"}, false},
		{"next hop differs with no other next hop named", routeCheck("dns", viaRouter), CausalEvidence{Observation: ObservationRouteNextHopDiffers}, false},
		{"next hop differs claimed on a row with no next hop", routeCheck("dns", direct), CausalEvidence{Observation: ObservationRouteNextHopDiffers, Value: "192.168.1.1"}, false},
		{"another routing table on the row that used one", routeCheck("dns", policy), CausalEvidence{Observation: ObservationRouteTableDiffers}, true},
		{"another routing table claimed on a main-table row", routeCheck("dns", mainTable), CausalEvidence{Observation: ObservationRouteTableDiffers}, false},
		{"another routing table claimed where none was read", routeCheck("dns", direct), CausalEvidence{Observation: ObservationRouteTableDiffers}, false},
		{"another routing table claimed for the kernel's own local one", routeCheck("dns", ownTable), CausalEvidence{Observation: ObservationRouteTableDiffers}, false},
		{"families on different interfaces", routeCheck("target_tcp", tunnel, v6), CausalEvidence{Observation: ObservationRouteFamilySplit}, true},
		{"families in different known tables", routeCheck("target_tcp", policy, v6main), CausalEvidence{Observation: ObservationRouteFamilySplit}, true},
		{"families in the same known table", routeCheck("target_tcp", mainTable, v6main), CausalEvidence{Observation: ObservationRouteFamilySplit}, false},
		{"families whose tables are not both known", routeCheck("target_tcp", policy, v6), CausalEvidence{Observation: ObservationRouteFamilySplit}, false},
		{"localhost in the kernel's own two tables", routeCheck("target_tcp", v4own, v6own), CausalEvidence{Observation: ObservationRouteFamilySplit}, false},
		{"families on the same interface", routeCheck("target_tcp", direct, v6), CausalEvidence{Observation: ObservationRouteFamilySplit}, false},
		{"single stack claims no split", routeCheck("target_tcp", direct), CausalEvidence{Observation: ObservationRouteFamilySplit}, false},
		{"interface MTU on the row that has one", routeCheck("target_tcp", tunnel), CausalEvidence{Observation: ObservationRouteInterfaceMTU, Value: "wg0"}, true},
		{"interface MTU claimed where none was read", routeCheck("target_tcp", direct), CausalEvidence{Observation: ObservationRouteInterfaceMTU, Value: "eth0"}, false},
		{"a route observation on a row with no routes", Check{ID: "dns", Status: StatusFail, Ran: true, DurationMs: 1}, CausalEvidence{Observation: ObservationRouteTunneled, Value: "wg0"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := observationMatches(c.e, c.check); got != c.want {
				t.Errorf("observationMatches(%+v) = %v, want %v", c.e, got, c.want)
			}
		})
	}
}

// The validator refuses a file whose route evidence the file itself does not
// support, so an artifact cannot claim a tunnel it never recorded.
func TestEncodeRefusesUnsupportedRouteEvidence(t *testing.T) {
	s := Snapshot{
		Schema: Schema,
		Checks: []Check{routeCheck("target_tcp", Route{Destination: "198.51.100.7", Family: "ipv4", Interface: "eth0", Tunnel: TunnelStateDirect})},
		Diagnosis: Diagnosis{
			Verdict: "network", Summary: "unreachable",
			Findings: []Finding{{
				ID: "target_unreachable", Verdict: "network", Summary: "unreachable", Focus: "target_tcp",
				CausalEvidence: []CausalEvidence{{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationRouteTunneled, Value: "wg0"}},
			}},
		},
	}
	if _, err := Encode(s); err == nil {
		t.Error("a tunnel claim with no tunnel in the file was written anyway")
	}
}

// public_dns has held a resolver address or the empty opt-out since v1, and a
// reader of any vintage parses it that way. Whether the run named that resolver
// is a second fact, so it gets a second field rather than a word this one has
// never been able to hold: changing what an existing field means is a new
// schema, and this feature does not need one.
func TestPublicDNSAutoIsAdditiveToTheV1Option(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"automatic default", Options{PublicDNS: "8.8.8.8", PublicDNSAuto: true}},
		{"resolver the user named", Options{PublicDNS: "8.8.8.8"}},
		{"switched off", Options{PublicDNS: ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := Encode(Snapshot{Options: tc.opts})
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			// The v1 reader netdoc used to be: it knows public_dns and nothing
			// about the field beside it.
			var legacy struct {
				Schema  string `json:"schema"`
				Options struct {
					PublicDNS string `json:"public_dns"`
				} `json:"options"`
			}
			if err := json.Unmarshal(data, &legacy); err != nil {
				t.Fatalf("legacy decode: %v", err)
			}
			if legacy.Schema != Schema {
				t.Errorf("schema = %q, want %q: an added option is not a new format", legacy.Schema, Schema)
			}
			if legacy.Options.PublicDNS != tc.opts.PublicDNS {
				t.Errorf("legacy public_dns = %q, want %q", legacy.Options.PublicDNS, tc.opts.PublicDNS)
			}
			if got := legacy.Options.PublicDNS; got != "" && net.ParseIP(got) == nil {
				t.Errorf("legacy public_dns = %q, want an address or empty", got)
			}
			// Absent rather than false, so a file from a run that named its
			// resolver is byte-identical to one an older netdoc would write.
			if _, present := optionKeys(t, data)["public_dns_auto"]; present != tc.opts.PublicDNSAuto {
				t.Errorf("public_dns_auto present = %v, want %v", present, tc.opts.PublicDNSAuto)
			}
			// And the round trip a current reader makes of it.
			back, err := Decode(data)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if back.Options.PublicDNS != tc.opts.PublicDNS || back.Options.PublicDNSAuto != tc.opts.PublicDNSAuto {
				t.Errorf("options = %+v, want %+v", back.Options, tc.opts)
			}
		})
	}
}

// A file written before this field existed has no automatic bit, and absence
// means the run named the resolver it recorded. Reading it any other way would
// credit an old snapshot with a fallback its probes never had.
func TestDecodeReadsAMissingPublicDNSAutoAsAResolverThatWasNamed(t *testing.T) {
	s, err := Decode([]byte(`{"schema":"` + Schema + `","options":{"public_dns":"8.8.8.8"}}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if s.Options.PublicDNS != "8.8.8.8" || s.Options.PublicDNSAuto {
		t.Errorf("options = %+v, want 8.8.8.8 with auto=false", s.Options)
	}
}

// optionKeys is the key set of the options object as written, read without the
// struct that produced it so an omitempty that stopped working is visible.
func optionKeys(t *testing.T, data []byte) map[string]json.RawMessage {
	t.Helper()
	var doc struct {
		Options map[string]json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("read options: %v", err)
	}
	return doc.Options
}

// The answer comparison is a closed vocabulary for the same reason confidence
// is, with one extra rule that matters more here: absence is a third state.
// A run that had nothing to compare and a run that compared and agreed are
// different facts, so an omitted key must never decode as agreement.
func TestAnswerComparisonRoundTripsAndRejectsUnknownValues(t *testing.T) {
	base := func(comparison AnswerComparison) Snapshot {
		return Snapshot{
			Checks: []Check{{
				ID: "dns_public", Status: StatusWarn, Ran: true, DurationMs: 1,
				Derived: &Derived{AnswerComparison: comparison},
			}},
		}
	}
	for _, comparison := range []AnswerComparison{"", AnswerComparisonAgree, AnswerComparisonDisagree} {
		data, err := Encode(base(comparison))
		if err != nil {
			t.Fatalf("Encode %q: %v", comparison, err)
		}
		if comparison == "" && strings.Contains(string(data), "answer_comparison") {
			t.Errorf("a row that compared nothing published an answer_comparison key:\n%s", data)
		}
		decoded, err := Decode(data)
		if err != nil {
			t.Fatalf("Decode %q: %v", comparison, err)
		}
		if got := decoded.Checks[0].Derived.AnswerComparison; got != comparison {
			t.Errorf("answer comparison round-tripped as %q, want %q", got, comparison)
		}
	}

	if _, err := Encode(base("maybe")); err == nil || !strings.Contains(err.Error(), "unknown answer comparison") {
		t.Errorf("Encode error = %v, want it to refuse an unknown answer comparison", err)
	}
	valid, err := Encode(base(AnswerComparisonAgree))
	if err != nil {
		t.Fatal(err)
	}
	future := strings.Replace(string(valid), `"answer_comparison": "agree"`, `"answer_comparison": "maybe"`, 1)
	if _, err := Decode([]byte(future)); err == nil || !strings.Contains(err.Error(), "unknown answer comparison") {
		t.Errorf("Decode error = %v, want it to refuse an unknown answer comparison", err)
	}
}
