package snapshot

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// causalEvidenceSourceFile is a constant so reading it needs no gosec
// exemption. It is where both the observation vocabulary and the table that
// gives each observation its meaning are declared.
const causalEvidenceSourceFile = "snapshot.go"

// observationConstants reads the Observation* vocabulary out of the source
// rather than restating it here. A constant added without a rule beside it is
// what this exists to catch: the switch this table replaced accepted a new
// observation only by falling through to false, and a rule added for it
// somewhere else would have been unreachable from the ledger.
func observationConstants(t *testing.T) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), causalEvidenceSourceFile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			name := value.Names[0].Name
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || !strings.HasPrefix(name, "Observation") {
				continue
			}
			text, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			out[name] = text
		}
	}
	if len(out) == 0 {
		t.Fatalf("no observation constants found in %s", causalEvidenceSourceFile)
	}
	return out
}

// Adding an observation to the v1 vocabulary is adding a claim readers will
// check, so it cannot land without saying what its Value means and what the
// referenced row has to have recorded. Neither half is optional: a rule with
// no constant is a rule nothing can name, and a constant with no rule is a
// claim the file format cannot verify.
func TestEveryObservationHasValueSemanticsAndARule(t *testing.T) {
	constants := observationConstants(t)
	semantics := CausalEvidenceValueSemantics()
	for name, id := range constants {
		rule, ok := causalObservations[id]
		if !ok {
			t.Errorf("%s (%q) has no entry in causalObservations: declare how it reads Value and what proves it", name, id)
			continue
		}
		switch rule.value {
		case EvidenceValueAbsent, EvidenceValueOptional, EvidenceValueRequired:
		default:
			t.Errorf("%s (%q) has unrecognized value semantics %q", name, id, rule.value)
		}
		if rule.present == nil {
			t.Errorf("%s (%q) has no rule proving it against a row", name, id)
		}
		if semantics[id] != rule.value {
			t.Errorf("CausalEvidenceValueSemantics()[%q] = %q, want %q", id, semantics[id], rule.value)
		}
	}
	declared := map[string]bool{}
	for _, id := range constants {
		declared[id] = true
	}
	for id := range causalObservations {
		if !declared[id] {
			t.Errorf("causalObservations has a rule for %q, which no observation constant names", id)
		}
	}
	if len(semantics) != len(causalObservations) {
		t.Errorf("CausalEvidenceValueSemantics() has %d entries, want %d", len(semantics), len(causalObservations))
	}
}

// An observation that names no value has to refuse one, and an observation
// that is only readable as a claim about a named value has to refuse its
// absence. Both are the same question: whether a run could have written this.
func TestObservationValueArityIsEnforced(t *testing.T) {
	// One row carrying every reading the vocabulary can rest on, so an
	// observation refused below is refused for its value and not for a
	// missing measurement.
	offset := int64(ClockOffsetEvidenceMs)
	row := Check{
		ID: "target_tcp", Status: StatusFail, Ran: true, DurationMs: 1,
		Cause: "timeout", CauseFamily: "ipv4",
		Derived: &Derived{StatusDowngraded: true},
		Observed: &Observed{
			Addresses: []string{"192.0.2.1"}, DNSNotFound: true, Timeout: true,
			ClockOffsetMs: &offset, Portal: &Portal{}, Families: &Families{IPv4: "reachable", IPv6: "unreachable"},
			Attempts: []Attempt{{IP: "192.0.2.1"}, {IP: "192.0.2.2", Error: "refused", Cause: "connection_refused"}},
			Routes: []Route{
				{Destination: "192.0.2.1", Family: "ipv4", Interface: "wg0", Gateway: "10.0.0.1",
					Tunnel: TunnelStateTunnel, TunnelKind: "wireguard", InterfaceMTU: 1420,
					Table: "table 51820", TableKnown: true},
				{Destination: "2001:db8::1", Family: "ipv6", Interface: "eth0", Tunnel: TunnelStateDirect},
				{Destination: "203.0.113.9", Family: "ipv4", Unreachable: true},
			},
		},
	}
	// One value per observation that the row above really recorded, so the
	// only thing varying is whether naming it is legal.
	recorded := map[string]string{
		ObservationCause:               "ipv4",
		ObservationDNSAnswers:          "192.0.2.1",
		ObservationFamilyReachable:     "ipv4",
		ObservationFamilyFailed:        "ipv6",
		ObservationAddressSucceeded:    "192.0.2.1",
		ObservationAddressFailed:       "192.0.2.2",
		ObservationRouteTunneled:       "wg0",
		ObservationRouteDirect:         "eth0",
		ObservationRouteUnreachable:    "203.0.113.9",
		ObservationRoutePathDiffers:    "ppp0",
		ObservationRouteNextHopDiffers: "192.168.1.1",
		ObservationRouteInterfaceMTU:   "wg0",
	}
	// The status observations are about a row's outcome, and this row has one
	// of them, so the rest are checked on rows that have theirs.
	rows := map[string]Check{
		ObservationStatusPass: checkRow("pass", StatusPass),
		ObservationStatusWarn: checkRow("warn", StatusWarn),
		ObservationStatusSkip: checkRow("skip", StatusSkip),
		ObservationStatusNA:   checkRow("na", StatusNA),
	}
	for id, rule := range causalObservations {
		check := row
		if other, ok := rows[id]; ok {
			check = other
		}
		value := recorded[id]
		if rule.value != EvidenceValueAbsent && value == "" {
			t.Fatalf("observation %q names a value but the test recorded none for it", id)
		}
		if !observationMatches(CausalEvidence{Observation: id, Value: value}, check) {
			t.Fatalf("observation %q was not proved by a row that recorded it", id)
		}
		switch rule.value {
		case EvidenceValueAbsent:
			for _, wrong := range []string{"ipv4", "eth0", "192.0.2.1", "arbitrary"} {
				if observationMatches(CausalEvidence{Observation: id, Value: wrong}, check) {
					t.Errorf("observation %q accepted value %q, which names nothing it observes", id, wrong)
				}
			}
		case EvidenceValueRequired:
			if observationMatches(CausalEvidence{Observation: id}, check) {
				t.Errorf("observation %q accepted evidence naming no value", id)
			}
		}
	}
}

// The producer records the offset it measured and concludes from it only past
// the threshold, so a stored offset is a measurement and only a large one is a
// reason. An artifact citing a small one is claiming reasoning no netdoc did.
func TestClockOffsetEvidenceNeedsAnOffsetLargeEnoughToExplainAnything(t *testing.T) {
	row := func(ms int64) Check {
		return Check{ID: "internet_tcp", Status: StatusPass, Ran: true, DurationMs: 1,
			Observed: &Observed{ClockOffsetMs: &ms}}
	}
	for _, tc := range []struct {
		ms   int64
		want bool
	}{
		{0, false}, {17, false}, {-17, false},
		{ClockOffsetEvidenceMs - 1, false}, {-(ClockOffsetEvidenceMs - 1), false},
		{ClockOffsetEvidenceMs, true}, {-ClockOffsetEvidenceMs, true},
		{7200000, true}, {-7200000, true},
	} {
		e := CausalEvidence{Kind: EvidenceSupport, Check: "internet_tcp", Observation: ObservationClockOffset}
		if got := observationMatches(e, row(tc.ms)); got != tc.want {
			t.Errorf("clock offset %dms accepted = %v, want %v", tc.ms, got, tc.want)
		}
	}
	// A row that recorded no offset at all still proves nothing.
	if observationMatches(CausalEvidence{Observation: ObservationClockOffset},
		Check{ID: "internet_tcp", Status: StatusPass, Ran: true, DurationMs: 1}) {
		t.Error("clock offset evidence was accepted against a row that measured none")
	}
	rejectsBothWays(t, clockSkewSnapshot(17), "clock_offset")
	if _, err := Encode(clockSkewSnapshot(ClockOffsetEvidenceMs)); err != nil {
		t.Errorf("an offset at the threshold was refused: %v", err)
	}
}

func clockSkewSnapshot(ms int64) Snapshot {
	offset := ms
	return Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Checks: []Check{{ID: "internet_tcp", Status: StatusPass, Ran: true, DurationMs: 1,
			Observed: &Observed{ClockOffsetMs: &offset}}},
		OK: true,
		Diagnosis: Diagnosis{Verdict: "service", Summary: "clock", Findings: []Finding{{
			ID: "tls_clock_skew", Verdict: "service", Summary: "clock", Focus: "internet_tcp",
			Evidence:       []string{"internet_tcp"},
			CausalEvidence: []CausalEvidence{{Kind: EvidenceSupport, Check: "internet_tcp", Observation: ObservationClockOffset}},
		}}},
	}
}

// cause evidence names the address family that supplied the cause, which is
// the row's own cause_family. That field is younger than the evidence: v1.15.1
// wrote "ipv4" or "ipv6" beside rows that had nowhere to record it, and those
// artifacts stay readable. What they never contained is a value outside the
// family vocabulary, so that is where the rule holds instead of the row.
func TestCauseEvidenceFamilyStaysReadableOnRowsWithoutTheField(t *testing.T) {
	row := func(family string) Check {
		return Check{ID: "internet_tcp", Status: StatusFail, Ran: true, DurationMs: 1,
			Cause: "selected_path_failed", CauseFamily: family}
	}
	for _, tc := range []struct {
		name   string
		family string
		value  string
		want   bool
	}{
		{"no family named on either side", "", "", true},
		{"the row's own family", "ipv4", "ipv4", true},
		{"evidence naming nothing beside a family", "ipv4", "", true},
		{"the other family", "ipv4", "ipv6", false},
		{"a pre-cause_family artifact", "", "ipv4", true},
		{"a pre-cause_family artifact, other family", "", "ipv6", true},
		{"a value outside the family vocabulary", "", "eth0", false},
		{"a value outside the family vocabulary beside a family", "ipv4", "eth0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := CausalEvidence{Kind: EvidenceSupport, Check: "internet_tcp", Observation: ObservationCause, Value: tc.value}
			if got := observationMatches(e, row(tc.family)); got != tc.want {
				t.Errorf("cause evidence value %q on cause_family %q accepted = %v, want %v", tc.value, tc.family, got, tc.want)
			}
		})
	}
}

// The artifact boundary refuses what the rule refuses, in both directions, so
// a hand-edited file cannot carry a claim the producer could not have made.
func TestEncodeAndDecodeRefuseValuesOnParameterlessObservations(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check Check
		e     CausalEvidence
	}{
		{"a status that names a family", checkRow("internet_tcp", StatusPass),
			CausalEvidence{Kind: EvidenceSupport, Check: "internet_tcp", Observation: ObservationStatusPass, Value: "ipv4"}},
		{"a captive portal that names an address", Check{ID: "internet_http", Status: StatusWarn, Ran: true, DurationMs: 1,
			Observed: &Observed{Portal: &Portal{}}},
			CausalEvidence{Kind: EvidenceSupport, Check: "internet_http", Observation: ObservationCaptivePortal, Value: "192.0.2.1"}},
		{"a cause that names something that is not a family", Check{ID: "internet_tcp", Status: StatusFail, Ran: true, DurationMs: 1, Cause: "no_default_route"},
			CausalEvidence{Kind: EvidenceSupport, Check: "internet_tcp", Observation: ObservationCause, Value: "eth0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
				Checks: []Check{tc.check},
				OK:     tc.check.Status != StatusFail,
				Diagnosis: Diagnosis{Verdict: "network", Summary: "unreachable", Findings: []Finding{{
					ID: "offline", Verdict: "network", Summary: "unreachable", Focus: tc.check.ID,
					Evidence: []string{tc.check.ID}, CausalEvidence: []CausalEvidence{tc.e},
				}}},
			}
			if tc.check.Status == StatusFail {
				s.Diagnosis.FailedStage = tc.check.ID
			}
			rejectsBothWays(t, s, "observation is absent")
		})
	}
}

// A JSON decode of a file is the boundary a support artifact actually arrives
// through, so the rule has to hold there and not only on a struct built here.
func TestDecodeRefusesAHandEditedEvidenceValue(t *testing.T) {
	data := golden(t)
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	findings, _ := raw["diagnosis"].(map[string]any)["findings"].([]any)
	if len(findings) == 0 {
		t.Skip("golden snapshot carries no findings")
	}
	edited := 0
	for _, finding := range findings {
		items, _ := finding.(map[string]any)["causal_evidence"].([]any)
		for _, item := range items {
			e, _ := item.(map[string]any)
			if e == nil || e["value"] != nil {
				continue
			}
			if CausalEvidenceValueSemantics()[e["observation"].(string)] != EvidenceValueAbsent {
				continue
			}
			e["value"] = "arbitrary"
			edited++
		}
	}
	if edited == 0 {
		t.Skip("golden snapshot carries no parameterless causal evidence")
	}
	mutated, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(mutated); err == nil {
		t.Fatal("Decode accepted causal evidence values the producer cannot write")
	} else if !strings.Contains(err.Error(), "observation is absent") {
		t.Errorf("Decode error = %q, want it to say the observation is absent", err)
	}
}
