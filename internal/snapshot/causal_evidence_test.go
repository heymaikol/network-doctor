package snapshot

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
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
		t.Fatal("golden snapshot carries no findings")
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
		t.Fatal("golden snapshot carries no parameterless causal evidence")
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

// One address has more than one spelling, and an artifact records whichever
// one its producer wrote. Where an observation says the evidence value names
// an address, matching that value to the row it cites is a question about
// addresses and not about text: the same rule the rest of the format reads a
// recorded address by.
const (
	compressedV6 = "2606:2800:220:1:248:1893:25c8:1946"
	expandedV6   = "2606:2800:0220:0001:0248:1893:25c8:1946"
	otherV6      = "2606:2800:220:1:248:1893:25c8:1947"
)

// The classification is the whole of what changes, so it is pinned here
// rather than left to the rules that read it. An observation moved into the
// address-valued kind is a claim that its value is an IP, and one taken out of
// it silently would put a textual equality back without failing anything. The
// same table decides what support redaction may write into each value, so a
// wrong kind here is also an artifact that no longer checks against its rows.
func TestEveryObservationValueHasTheKindItsRuleReads(t *testing.T) {
	want := map[string]string{
		ObservationDNSAnswers:          valueKindAddress,
		ObservationAddressSucceeded:    valueKindAddress,
		ObservationAddressFailed:       valueKindAddress,
		ObservationRouteUnreachable:    valueKindAddress,
		ObservationRouteNextHopDiffers: valueKindAddress,
		ObservationRouteTunneled:       valueKindInterface,
		ObservationRouteDirect:         valueKindInterface,
		ObservationRoutePathDiffers:    valueKindInterface,
		ObservationRouteInterfaceMTU:   valueKindInterface,
		ObservationCause:               valueKindVocabulary,
		ObservationFamilyReachable:     valueKindVocabulary,
		ObservationFamilyFailed:        valueKindVocabulary,
	}
	for id := range want {
		if _, known := causalObservations[id]; !known {
			t.Errorf("%q is given a value kind but is not in the vocabulary", id)
		}
	}
	for id, rule := range causalObservations {
		kind := causalValueKinds[id].kind
		if kind != want[id] {
			t.Errorf("%q has value kind %q, want %q", id, kind, want[id])
		}
		// Arity and kind are two answers about one field and have to agree:
		// an observation that names no value has nothing to give a kind to,
		// and one that may name a value is unreadable without one.
		if (rule.value == EvidenceValueAbsent) != (kind == "") {
			t.Errorf("%q has arity %q and value kind %q, which cannot both be true", id, rule.value, kind)
		}
		if CausalEvidenceValueIsAddress(id) != (want[id] == valueKindAddress) {
			t.Errorf("CausalEvidenceValueIsAddress(%q) = %v, want %v", id, CausalEvidenceValueIsAddress(id), want[id] == valueKindAddress)
		}
	}
	for id := range causalValueKinds {
		if _, known := causalObservations[id]; !known {
			t.Errorf("causalValueKinds names %q, which no observation rule names", id)
		}
	}
	// An observation this build does not know names nothing, least of all an
	// address.
	if CausalEvidenceValueIsAddress("route_moon_phase") {
		t.Error("an unknown observation was classified as address-valued")
	}
}

// The counterfactual variables answer the same question about the same kind
// of field, so they are pinned the same way. A variable whose alternatives
// stopped being addresses would otherwise change both what comparison reads
// and what redaction writes, without failing anything.
func TestEveryCounterfactualVariableHasTheKindItsAlternativesName(t *testing.T) {
	want := map[string]valueSemantics{
		counterfactualResolvedAddress: {kind: valueKindAddress},
		counterfactualDNSResolver:     {kind: valueKindVocabulary, words: []string{"system", "independent"}},
		counterfactualAddressFamily:   {kind: valueKindVocabulary, words: []string{"ipv4", "ipv6"}},
	}
	if len(counterfactualValueKinds) != len(want) {
		t.Errorf("counterfactualValueKinds has %d variables, want %d", len(counterfactualValueKinds), len(want))
	}
	for variable, semantics := range want {
		got := counterfactualValueKinds[variable]
		if got.kind != semantics.kind || !slices.Equal(got.words, semantics.words) {
			t.Errorf("%q has value semantics %+v, want %+v", variable, got, semantics)
		}
		if CounterfactualValueIsAddress(variable) != (semantics.kind == valueKindAddress) {
			t.Errorf("CounterfactualValueIsAddress(%q) = %v, want %v",
				variable, CounterfactualValueIsAddress(variable), semantics.kind == valueKindAddress)
		}
	}
	if CounterfactualValueIsAddress("moon_phase") {
		t.Error("an unknown counterfactual variable was classified as address-valued")
	}
}

// evidenceRow is one row carrying every address-valued reading, spelled the
// way the fixture's producer happened to write it.
func evidenceRow(address, gateway string) Check {
	return Check{
		ID: "target_tcp", Status: StatusFail, Ran: true, DurationMs: 1,
		Cause: "timeout", CauseFamily: "ipv6",
		Observed: &Observed{
			Addresses: []string{address},
			Attempts: []Attempt{
				{IP: address, Error: "deadline exceeded", Cause: "timeout"},
				{IP: "2001:db8::9"},
			},
			Routes: []Route{
				{Destination: address, Family: "ipv6", Interface: "eth0", Gateway: gateway, Tunnel: TunnelStateDirect},
				{Destination: "2001:db8::5", Family: "ipv6", Unreachable: true},
			},
		},
	}
}

// Every observation whose value names an address matches the row it cites
// through address identity, so the spelling the evidence carries and the
// spelling the row carries do not have to agree letter for letter. An address
// that really is another one still matches nothing.
func TestAddressValuedEvidenceMatchesItsRowByAddressIdentity(t *testing.T) {
	for _, tc := range []struct {
		name        string
		observation string
		value       string
		want        bool
	}{
		{"an answer spelled the way the row spells it", ObservationDNSAnswers, compressedV6, true},
		{"the same answer expanded", ObservationDNSAnswers, expandedV6, true},
		{"an answer the row never recorded", ObservationDNSAnswers, otherV6, false},
		{"an answer named by no value at all", ObservationDNSAnswers, "", true},

		{"a failed attempt expanded", ObservationAddressFailed, expandedV6, true},
		{"a failed attempt that is another address", ObservationAddressFailed, otherV6, false},
		{"a succeeded attempt expanded", ObservationAddressSucceeded, "2001:0db8:0000:0000:0000:0000:0000:0009", true},
		{"a succeeded attempt that is another address", ObservationAddressSucceeded, "2001:db8::8", false},

		{"an unreachable destination expanded", ObservationRouteUnreachable, "2001:0db8:0000:0000:0000:0000:0000:0005", true},
		{"an unreachable destination that is another address", ObservationRouteUnreachable, "2001:db8::6", false},

		// The row's own next hop, spelled differently, is still the row's own
		// next hop. A respelling cannot prove that two flows went to two
		// routers; a genuinely different router can.
		{"this row's own next hop", ObservationRouteNextHopDiffers, "2001:db8::1", false},
		{"this row's own next hop expanded", ObservationRouteNextHopDiffers, "2001:0db8:0000:0000:0000:0000:0000:0001", false},
		{"this row's own next hop in another case", ObservationRouteNextHopDiffers, "2001:DB8::1", false},
		{"a genuinely different next hop", ObservationRouteNextHopDiffers, "2001:db8::2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := CausalEvidence{Kind: EvidenceSupport, Check: "target_tcp", Observation: tc.observation, Value: tc.value}
			if got := observationMatches(e, evidenceRow(compressedV6, "2001:db8::1")); got != tc.want {
				t.Errorf("%s value %q accepted = %v, want %v", tc.observation, tc.value, got, tc.want)
			}
		})
	}
}

// A mapped IPv4 address is IPv4 here, the way every producer of a recorded
// address already writes one.
func TestAddressValuedEvidenceReadsAMappedIPv4AddressAsIPv4(t *testing.T) {
	row := Check{ID: "dns", Status: StatusPass, Ran: true, DurationMs: 1,
		Observed: &Observed{Addresses: []string{"192.0.2.10"}}}
	e := CausalEvidence{Kind: EvidenceSupport, Check: "dns", Observation: ObservationDNSAnswers, Value: "::ffff:192.0.2.10"}
	if !observationMatches(e, row) {
		t.Error("an answer recorded in its IPv4-mapped form was read as another address")
	}
}

// The other half of the classification. An observation whose value names an
// interface or an address family keeps textual equality, and nothing starts
// parsing one of those values as an address because it could be read as one.
func TestTextualEvidenceValuesKeepTextualEquality(t *testing.T) {
	// An interface named like an address is still an interface name, and the
	// only thing that matches it is that name.
	row := Check{ID: "target_tcp", Status: StatusFail, Ran: true, DurationMs: 1,
		Observed: &Observed{Routes: []Route{{
			Destination: "2001:db8::7", Family: "ipv6", Interface: "2001:db8::1",
			Tunnel: TunnelStateTunnel, TunnelKind: "wireguard", InterfaceMTU: 1420,
		}}}}
	for _, observation := range []string{ObservationRouteTunneled, ObservationRouteInterfaceMTU} {
		e := CausalEvidence{Kind: EvidenceSupport, Check: "target_tcp", Observation: observation, Value: "2001:db8::1"}
		if !observationMatches(e, row) {
			t.Errorf("%s did not match the interface name the row recorded", observation)
		}
		e.Value = "2001:0db8:0000:0000:0000:0000:0000:0001"
		if observationMatches(e, row) {
			t.Errorf("%s read an interface name as an address", observation)
		}
	}
	// route_path_differs names the other row's interface, and difference there
	// is textual for the same reason.
	e := CausalEvidence{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationRoutePathDiffers, Value: "2001:0db8::1"}
	if !observationMatches(e, row) {
		t.Error("route_path_differs stopped comparing interface names as names")
	}
	// A family stays a word from a two-word vocabulary.
	families := Check{ID: "target_tcp", Status: StatusFail, Ran: true, DurationMs: 1, Cause: "timeout", CauseFamily: "ipv6",
		Observed: &Observed{Families: &Families{IPv4: "reachable", IPv6: "unreachable"}}}
	for _, tc := range []struct {
		observation, value string
		want               bool
	}{
		{ObservationFamilyReachable, "ipv4", true},
		{ObservationFamilyReachable, "192.0.2.1", false},
		{ObservationFamilyFailed, "ipv6", true},
		{ObservationCause, "ipv6", true},
		{ObservationCause, "2001:db8::1", false},
	} {
		e := CausalEvidence{Kind: EvidenceSupport, Check: "target_tcp", Observation: tc.observation, Value: tc.value}
		if got := observationMatches(e, families); got != tc.want {
			t.Errorf("%s value %q accepted = %v, want %v", tc.observation, tc.value, got, tc.want)
		}
	}
}

// The support artifact's erasure marker is not an address, and no address rule
// may start reading it as one. Two erased readings are the same erasure and
// nothing more; an erasure beside a recorded address names neither.
func TestRedactionMarkerIsNeverReadAsAnAddressByEvidence(t *testing.T) {
	row := Check{ID: "target_tcp", Status: StatusFail, Ran: true, DurationMs: 1,
		Observed: &Observed{
			Addresses: []string{redactedAddress},
			Routes:    []Route{{Destination: redactedAddress, Family: "ipv6", Interface: "eth0", Gateway: redactedAddress, Tunnel: TunnelStateDirect}},
		}}
	answer := func(value string) CausalEvidence {
		return CausalEvidence{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationDNSAnswers, Value: value}
	}
	if !observationMatches(answer(redactedAddress), row) {
		t.Error("an erased answer stopped matching the erased reading beside it")
	}
	if observationMatches(answer("2001:db8::1"), row) {
		t.Error("an erased reading was read as some particular address")
	}
	// An erased next hop is not evidence that this row went somewhere else.
	nextHop := CausalEvidence{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationRouteNextHopDiffers, Value: redactedAddress}
	if observationMatches(nextHop, row) {
		t.Error("two erased next hops were read as two different routers")
	}
	// A sanitized artifact still validates: the redactor assigns one pseudonym
	// per address, so evidence and the row it cites stay one address.
	s := SanitizeForSupport(addressEvidenceSnapshot(compressedV6, expandedV6))
	if _, err := Encode(s); err != nil {
		t.Errorf("a sanitized artifact carrying address-valued evidence was refused: %v", err)
	}
}

// addressEvidenceSnapshot is a whole artifact whose dns row recorded one
// answer and whose finding cites that answer, with the two spellings the
// caller chooses.
func addressEvidenceSnapshot(recorded, cited string) Snapshot {
	return Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Checks: []Check{{ID: "dns", Name: "dns", Status: StatusPass, Ran: true, DurationMs: 1,
			Observed: &Observed{Addresses: []string{recorded}}}},
		OK: true,
		Diagnosis: Diagnosis{Verdict: "degraded", Summary: "one answer", Findings: []Finding{{
			ID: "dns_disagreement", Verdict: "degraded", Summary: "one answer", Focus: "dns",
			Evidence: []string{"dns"},
			CausalEvidence: []CausalEvidence{{
				Kind: EvidenceSupport, Check: "dns", Observation: ObservationDNSAnswers, Value: cited,
			}},
		}}},
	}
}

// The reported false rejection, at the artifact boundary this time: a file
// whose evidence spells the answer it cites differently from the row is one
// netdoc could have written, and it has to load.
func TestArtifactWithRespelledDNSEvidenceIsAccepted(t *testing.T) {
	data, err := Encode(addressEvidenceSnapshot(compressedV6, expandedV6))
	if err != nil {
		t.Fatalf("an artifact citing one answer in two spellings was refused: %v", err)
	}
	if _, err := Decode(data); err != nil {
		t.Fatalf("Decode refused what Encode published: %v", err)
	}
	// An answer the row never recorded is still absent.
	rejectsBothWays(t, addressEvidenceSnapshot(compressedV6, otherV6), "observation is absent")
}

// nextHopSnapshot is a whole artifact claiming this row's traffic went to a
// router other than the one its evidence names.
func nextHopSnapshot(gateway, cited string) Snapshot {
	return Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Checks: []Check{{ID: "target_tcp", Name: "target_tcp", Status: StatusFail, Ran: true, DurationMs: 1,
			Cause: "timeout", CauseFamily: "ipv6",
			Observed: &Observed{Routes: []Route{{
				Destination: "2001:db8::7", Family: "ipv6", Interface: "eth0", Gateway: gateway, Tunnel: TunnelStateDirect,
			}}}}},
		Diagnosis: Diagnosis{Verdict: "network", Summary: "unreachable", Blamed: "target_tcp", FailedStage: "target_tcp",
			Findings: []Finding{{
				ID: "target_unreachable", Verdict: "network", Summary: "unreachable", Focus: "target_tcp",
				Evidence: []string{"target_tcp"},
				CausalEvidence: []CausalEvidence{{
					Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationRouteNextHopDiffers, Value: cited,
				}},
			}}},
	}
}

// The reported false acceptance. "This row went to a different router" is a
// claim about two addresses, so two spellings of one router cannot establish
// it, and a router that really is another one still can.
func TestArtifactCannotProveADifferentNextHopByRespellingOne(t *testing.T) {
	rejectsBothWays(t, nextHopSnapshot("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"), "observation is absent")
	rejectsBothWays(t, nextHopSnapshot("2001:db8::1", "2001:db8::1"), "observation is absent")
	if _, err := Encode(nextHopSnapshot("2001:db8::1", "2001:db8::2")); err != nil {
		t.Errorf("an artifact naming a genuinely different next hop was refused: %v", err)
	}
}

// dnsEvidenceSnapshot is a finding resting on the dns row's answers, with the
// causal evidence and optional counterfactual the caller supplies.
func dnsEvidenceSnapshot(evidence []CausalEvidence, counterfactual *Counterfactual) Snapshot {
	return Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Checks: []Check{{ID: "dns", Name: "dns", Status: StatusPass, Ran: true, DurationMs: 1,
			Observed: &Observed{Addresses: []string{compressedV6, otherV6}}}},
		OK: true,
		Diagnosis: Diagnosis{Verdict: "degraded", Summary: "answers", Findings: []Finding{{
			ID: "dns_disagreement", Verdict: "degraded", Summary: "answers", Focus: "dns",
			Evidence: []string{"dns"}, CausalEvidence: evidence, Counterfactual: counterfactual,
		}}},
	}
}

func dnsAnswerEvidence(value string) CausalEvidence {
	return CausalEvidence{Kind: EvidenceSupport, Check: "dns", Observation: ObservationDNSAnswers, Value: value}
}

// An address-valued item is the claim it makes, not the spelling it was
// written in, so one answer cited twice is one claim repeated however it is
// spelled. This is the strict direction of the same identity: a finding must
// not be able to look better supported by respelling what it already carries.
func TestOneAddressSpelledTwiceIsOneCausalEvidenceClaim(t *testing.T) {
	rejectsBothWays(t, dnsEvidenceSnapshot([]CausalEvidence{
		dnsAnswerEvidence(compressedV6), dnsAnswerEvidence(expandedV6),
	}, nil), "repeats causal evidence")
	// Two answers that really are two are still two claims, and so are two
	// items that differ anywhere else in their identity.
	for _, tc := range []struct {
		name     string
		evidence []CausalEvidence
	}{
		{"different addresses", []CausalEvidence{dnsAnswerEvidence(compressedV6), dnsAnswerEvidence(otherV6)}},
		{"different kind and candidate", []CausalEvidence{
			dnsAnswerEvidence(compressedV6),
			{Kind: EvidenceContradiction, Check: "dns", Observation: ObservationDNSAnswers, Value: expandedV6, Candidate: "dns_name_not_found"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Encode(dnsEvidenceSnapshot(tc.evidence, nil)); err != nil {
				t.Errorf("two distinct claims were read as one: %v", err)
			}
		})
	}
}

// A counterfactual alternative references a fact the finding already carries.
// Reference, not transcription: the finding's evidence is now held by
// identity, so an alternative naming one of those facts in another spelling
// names a fact the finding carries, and refusing it would be the same false
// rejection in a second place.
func TestCounterfactualAlternativeReferencesEvidenceByIdentity(t *testing.T) {
	counterfactual := func(cited string) *Counterfactual {
		return &Counterfactual{Variable: "dns_resolver", Alternatives: []CounterfactualAlternative{
			{Value: "system", Outcome: "succeeded", Evidence: []CausalEvidence{dnsAnswerEvidence(cited)}},
			{Value: "independent", Outcome: "succeeded", Evidence: []CausalEvidence{dnsAnswerEvidence(otherV6)}},
		}}
	}
	carried := []CausalEvidence{dnsAnswerEvidence(compressedV6), dnsAnswerEvidence(otherV6)}
	for _, cited := range []string{compressedV6, expandedV6} {
		if _, err := Encode(dnsEvidenceSnapshot(carried, counterfactual(cited))); err != nil {
			t.Errorf("an alternative citing a carried answer as %q was refused: %v", cited, err)
		}
	}
	// A fact the finding does not carry is still not carried.
	rejectsBothWays(t, dnsEvidenceSnapshot(carried, counterfactual("2001:db8::1")),
		"counterfactual references evidence not carried by the finding")
}

// Alternatives are the ordered records the run observed, not a keyed set: v1
// states no identity for them and has never refused two that name the same
// value, so nothing here reads two of them as one. The evidence inside each
// one is still held to the identity above.
func TestCounterfactualAlternativesAreOrderedRecordsNotIdentities(t *testing.T) {
	for _, tc := range []struct{ name, first, second string }{
		{"identical values", compressedV6, compressedV6},
		{"equivalent spellings", compressedV6, expandedV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dnsEvidenceSnapshot([]CausalEvidence{dnsAnswerEvidence(compressedV6)},
				&Counterfactual{Variable: counterfactualResolvedAddress, Alternatives: []CounterfactualAlternative{
					{Value: tc.first, Outcome: "succeeded", Evidence: []CausalEvidence{dnsAnswerEvidence(compressedV6)}},
					{Value: tc.second, Outcome: "failed", Evidence: []CausalEvidence{dnsAnswerEvidence(expandedV6)}},
				}})
			if _, err := Encode(s); err != nil {
				t.Errorf("alternatives were read as identities: %v", err)
			}
		})
	}
}
