package compare

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// twoSided reads a pair that is supposed to be readable, so every test below
// asserts on the reading rather than on the plumbing that produced it.
func twoSided(t *testing.T, a, b snapshot.Snapshot) TwoSided {
	t.Helper()
	got, err := TwoSidedSnapshots(a, b)
	if err != nil {
		t.Fatalf("TwoSidedSnapshots: %v", err)
	}
	return got
}

func setStatus(t *testing.T, s *snapshot.Snapshot, id, status string) {
	t.Helper()
	check(t, s, id).Status = status
}

func rowFor(t *testing.T, got TwoSided, id string) SideRow {
	t.Helper()
	for _, row := range got.Checks {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("no check row %q", id)
	return SideRow{}
}

// The whole point of the command: a row that fails from one machine and passes
// from the other places the failure on that machine's vantage point, and says
// so without naming a device.
func TestOneSidedFailureIsPlacedOnThatSide(t *testing.T) {
	a, b := fixture(t), fixture(t)
	setStatus(t, &b, "target_tcp", snapshot.StatusPass)
	got := twoSided(t, a, b)
	if got.Diagnosis.Side != SideA || got.Diagnosis.ID != TwoSidedOneSideFails {
		t.Fatalf("side = %q id = %q, want %q %q", got.Diagnosis.Side, got.Diagnosis.ID, SideA, TwoSidedOneSideFails)
	}
	if !slices.Equal(got.Diagnosis.Evidence, []string{"target_tcp"}) {
		t.Errorf("evidence = %v, want [target_tcp]", got.Diagnosis.Evidence)
	}
	if !got.Placed() {
		t.Error("Placed() = false for a failure placed on side A")
	}
	if !got.Diagnosis.Ambiguous || len(got.Diagnosis.Alternatives) == 0 {
		t.Error("a one-sided placement must stay ambiguous and list what it did not rule out")
	}
}

// The mirror case, so the reading is not accidentally written for one argument
// order only.
func TestOneSidedFailureOnTheOtherSide(t *testing.T) {
	a, b := fixture(t), fixture(t)
	setStatus(t, &a, "target_tcp", snapshot.StatusPass)
	got := twoSided(t, a, b)
	if got.Diagnosis.Side != SideB || got.Diagnosis.ID != TwoSidedOneSideFails {
		t.Fatalf("side = %q id = %q, want %q %q", got.Diagnosis.Side, got.Diagnosis.ID, SideB, TwoSidedOneSideFails)
	}
	if !strings.Contains(got.Diagnosis.Summary, "side B") {
		t.Errorf("summary does not name the side it placed the failure on: %q", got.Diagnosis.Summary)
	}
}

// A failure both machines see is the case the command must refuse to blame a
// machine for, which is as much of the contract as the placement itself.
func TestSharedFailureIsPlacedOnNeitherSide(t *testing.T) {
	got := twoSided(t, fixture(t), fixture(t))
	if got.Diagnosis.Side != SideShared || got.Diagnosis.ID != TwoSidedSharedFailure {
		t.Fatalf("side = %q id = %q, want %q %q", got.Diagnosis.Side, got.Diagnosis.ID, SideShared, TwoSidedSharedFailure)
	}
	if !got.Diagnosis.Ambiguous {
		t.Error("a shared failure must stay ambiguous")
	}
	if !got.Placed() {
		t.Error("Placed() = false while a failure exists on both machines")
	}
}

func TestNoFailureOnEitherSide(t *testing.T) {
	a, b := fixture(t), fixture(t)
	setStatus(t, &a, "target_tcp", snapshot.StatusPass)
	setStatus(t, &b, "target_tcp", snapshot.StatusPass)
	got := twoSided(t, a, b)
	if got.Diagnosis.Side != SideNone || got.Diagnosis.ID != TwoSidedNoFailure {
		t.Fatalf("side = %q id = %q, want %q %q", got.Diagnosis.Side, got.Diagnosis.ID, SideNone, TwoSidedNoFailure)
	}
	if got.Placed() {
		t.Error("Placed() = true with nothing failing on either machine")
	}
	if got.Diagnosis.Ambiguous || len(got.Diagnosis.Alternatives) != 0 {
		t.Error("nothing failing is not an ambiguous finding")
	}
}

// A shared failure plus one machine's extra failure is two facts, and the
// reading has to keep them apart rather than collapse to either one.
func TestOneSideFailingMoreKeepsBothFacts(t *testing.T) {
	a, b := fixture(t), fixture(t)
	setStatus(t, &a, "dns", snapshot.StatusFail)
	got := twoSided(t, a, b)
	if got.Diagnosis.Side != SideA || got.Diagnosis.ID != TwoSidedOneSideFailsMore {
		t.Fatalf("side = %q id = %q, want %q %q", got.Diagnosis.Side, got.Diagnosis.ID, SideA, TwoSidedOneSideFailsMore)
	}
	if !slices.Equal(got.Diagnosis.Evidence, []string{"target_tcp", "dns"}) {
		t.Errorf("evidence = %v, want the shared row then the one-sided row", got.Diagnosis.Evidence)
	}
}

func TestEachSideFailingSomethingElseIsNotOnePlacement(t *testing.T) {
	a, b := fixture(t), fixture(t)
	setStatus(t, &a, "dns", snapshot.StatusFail)
	setStatus(t, &a, "target_tcp", snapshot.StatusPass)
	got := twoSided(t, a, b)
	if got.Diagnosis.Side != SideBoth || got.Diagnosis.ID != TwoSidedDivergentFailures {
		t.Fatalf("side = %q id = %q, want %q %q", got.Diagnosis.Side, got.Diagnosis.ID, SideBoth, TwoSidedDivergentFailures)
	}
}

// A row that measured nothing on one side is not evidence about either machine,
// so it must not decide a placement.
func TestUnmeasuredRowsAreNotComparable(t *testing.T) {
	for _, status := range []string{snapshot.StatusSkip, snapshot.StatusNA, snapshot.StatusIncomplete} {
		t.Run(status, func(t *testing.T) {
			a, b := fixture(t), fixture(t)
			setStatus(t, &a, "target_tcp", snapshot.StatusPass)
			setStatus(t, &b, "target_tcp", snapshot.StatusPass)
			setStatus(t, &a, "dns", snapshot.StatusFail)
			setStatus(t, &b, "dns", status)
			got := twoSided(t, a, b)
			if row := rowFor(t, got, "dns"); row.Comparable {
				t.Errorf("dns row with %s on one side reads as comparable", status)
			}
			if got.Diagnosis.Side != SideNone {
				t.Errorf("side = %q, want %q: the only failure was in a row that measured nothing on side B",
					got.Diagnosis.Side, SideNone)
			}
			if !hasCaveat(got, "did not produce a measured outcome") {
				t.Errorf("caveats never mention the unread row: %v", got.Caveats)
			}
		})
	}
}

// WARN is a row that worked, the same reading the snapshot's own OK field and
// netdoc's exit code take.
func TestWarnIsNotAFailure(t *testing.T) {
	a, b := fixture(t), fixture(t)
	setStatus(t, &a, "target_tcp", snapshot.StatusPass)
	setStatus(t, &b, "target_tcp", snapshot.StatusPass)
	setStatus(t, &a, "dns", snapshot.StatusWarn)
	got := twoSided(t, a, b)
	if got.Diagnosis.Side != SideNone {
		t.Fatalf("side = %q, want %q; a WARN row is not a failure to place", got.Diagnosis.Side, SideNone)
	}
	if row := rowFor(t, got, "dns"); !row.Comparable {
		t.Error("a WARN row measured an outcome and must stay comparable")
	}
}

func TestNoComparableChecksPlacesNothing(t *testing.T) {
	a, b := fixture(t), fixture(t)
	for i := range b.Checks {
		b.Checks[i].Status = snapshot.StatusSkip
	}
	got := twoSided(t, a, b)
	if got.Diagnosis.Side != SideUnknown || got.Diagnosis.ID != TwoSidedNoComparableChecks {
		t.Fatalf("side = %q id = %q, want %q %q", got.Diagnosis.Side, got.Diagnosis.ID, SideUnknown, TwoSidedNoComparableChecks)
	}
	// Not a pass: the question was left open, and the exit code has to say so.
	if !got.Placed() {
		t.Error("Placed() = false for a reading that could not place anything")
	}
}

// Two endpoints seen once each is not one endpoint seen twice, and the reading
// refuses rather than producing a placement no row supports.
func TestDifferentTargetsAreRefused(t *testing.T) {
	a, b := fixture(t), fixture(t)
	b.Target.Host = "other.example"
	_, err := TwoSidedSnapshots(a, b)
	if err == nil {
		t.Fatal("two snapshots of different targets produced a reading")
	}
	var wanted DifferentTargetsError
	if !errors.As(err, &wanted) {
		t.Fatalf("error = %v, want a DifferentTargetsError", err)
	}
	if !strings.Contains(err.Error(), "example.com") || !strings.Contains(err.Error(), "other.example") {
		t.Errorf("error does not name both endpoints: %v", err)
	}
}

func TestGenericRunAgainstATargetedOneIsRefused(t *testing.T) {
	a, b := fixture(t), fixture(t)
	b.Target = nil
	if _, err := TwoSidedSnapshots(a, b); err == nil {
		t.Fatal("a generic run read against a targeted one produced a reading")
	}
}

// Two generic runs are one question asked from two places, so they are read.
func TestTwoGenericRunsAreRead(t *testing.T) {
	a, b := fixture(t), fixture(t)
	a.Target, b.Target = nil, nil
	got := twoSided(t, a, b)
	if !got.SameTarget {
		t.Error("two generic runs must read as the same target")
	}
}

// Two different machines is the premise, so their tools differing is expected
// and must not be reported as something that weakens the reading.
func TestDifferentToolsAreNotACaveat(t *testing.T) {
	a, b := fixture(t), fixture(t)
	b.Tool.OS, b.Tool.Arch, b.Tool.Version = "windows", "amd64", "9.9.9"
	got := twoSided(t, a, b)
	if hasCaveat(got, "windows") || hasCaveat(got, "9.9.9") {
		t.Errorf("a different machine on the other side was reported as a caveat: %v", got.Caveats)
	}
}

func TestSettingsThatChangeWhatWasMeasuredAreCaveats(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*snapshot.Snapshot)
		want   string
	}{
		{"timeout", func(s *snapshot.Snapshot) { s.Options.ProbeTimeoutMs = 9000 }, "probe timeouts differ"},
		{"public dns", func(s *snapshot.Snapshot) { s.Options.PublicDNS = "9.9.9.9" }, "second-opinion resolvers differ"},
		{"selection", func(s *snapshot.Snapshot) { s.Options.Skip = []string{"dns"} }, "selected different probes"},
		// The same resolver, reached two different ways: only the side that did
		// not name it could have crossed to the other address family.
		{"public dns chosen two ways", func(s *snapshot.Snapshot) { s.Options.PublicDNSAuto = true }, "took the default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := fixture(t), fixture(t)
			tc.mutate(&b)
			if got := twoSided(t, a, b); !hasCaveat(got, tc.want) {
				t.Errorf("caveats = %v, want one mentioning %q", got.Caveats, tc.want)
			}
		})
	}
}

// The selection is compared as a set, the same rule the comparison applies: the
// order probe IDs were typed in is not the shape of anything.
func TestProbeSelectionOrderIsNotACaveat(t *testing.T) {
	a, b := fixture(t), fixture(t)
	a.Options.Check = []string{"dns", "iface"}
	b.Options.Check = []string{"iface", "dns"}
	if got := twoSided(t, a, b); hasCaveat(got, "different probes") {
		t.Errorf("a reordered selection was reported as a caveat: %v", got.Caveats)
	}
}

func TestCaptureGapIsACaveat(t *testing.T) {
	a, b := fixture(t), fixture(t)
	b.CreatedAt = "2026-01-02T09:04:05Z"
	got := twoSided(t, a, b)
	if !hasCaveat(got, "6 hours apart") {
		t.Errorf("caveats = %v, want one naming the gap", got.Caveats)
	}
	// Two runs started together are the intended way to use the command, and it
	// must not warn about the seconds between them.
	a2, b2 := fixture(t), fixture(t)
	b2.CreatedAt = "2026-01-02T03:04:35Z"
	if got := twoSided(t, a2, b2); hasCaveat(got, "apart") {
		t.Errorf("half a minute was reported as a gap: %v", got.Caveats)
	}
}

// Preserve the existing target-spelling gate for support artifacts. Independent
// redaction mappings do not prove original identity; the reading says so in a
// caveat and never compares pseudonyms as address evidence.
func TestSanitizedArtifactsFollowTheSameTargetRule(t *testing.T) {
	a := snapshot.SanitizeForSupport(fixture(t))
	b := snapshot.SanitizeForSupport(fixture(t))
	if _, err := TwoSidedSnapshots(a, b); err != nil {
		t.Fatalf("two support artifacts of one target were refused: %v", err)
	}
	// Paired with a full-fidelity run, the pseudonym is a different endpoint,
	// and refusing is the right answer: every name on one side is a stand-in.
	if _, err := TwoSidedSnapshots(fixture(t), b); err == nil {
		t.Error("a sanitized artifact read against a full-fidelity one produced a placement")
	}
	// A generic run has no target to rename, which is the one shape where a
	// mixed-fidelity pair is read at all, and it is read with a caveat.
	generic, sanitizedGeneric := fixture(t), snapshot.SanitizeForSupport(fixture(t))
	generic.Target, sanitizedGeneric.Target = nil, nil
	got := twoSided(t, generic, sanitizedGeneric)
	if !hasCaveat(got, "sanitized support artifact") {
		t.Errorf("caveats = %v, want one naming the mixed fidelity", got.Caveats)
	}
}

func TestMixedFidelityIsACaveat(t *testing.T) {
	a, b := fixture(t), fixture(t)
	b.Redaction = &snapshot.Redaction{Sanitized: true, Policy: snapshot.SupportRedactionPolicy}
	if got := twoSided(t, a, b); !hasCaveat(got, "sanitized support artifact") {
		t.Errorf("caveats = %v, want one naming the mixed fidelity", got.Caveats)
	}
	// Two sanitized artifacts are comparable with each other.
	a2, b2 := fixture(t), fixture(t)
	policy := &snapshot.Redaction{Sanitized: true, Policy: snapshot.SupportRedactionPolicy}
	a2.Redaction, b2.Redaction = policy, policy
	if got := twoSided(t, a2, b2); hasCaveat(got, "sanitized support artifact") {
		t.Errorf("two sanitized artifacts were reported as mixed fidelity: %v", got.Caveats)
	}
}

// A placement is a statement about a machine, never about a device on it. The
// vocabulary the diagnosis is forbidden to reach for is worth pinning, because
// it is the one mistake that would make the command untrustworthy.
func TestPlacementNeverNamesADevice(t *testing.T) {
	pairs := []struct{ a, b func(*snapshot.Snapshot) }{
		{func(s *snapshot.Snapshot) {}, func(s *snapshot.Snapshot) { s.Checks[5].Status = snapshot.StatusPass }},
		{func(s *snapshot.Snapshot) { s.Checks[5].Status = snapshot.StatusPass }, func(s *snapshot.Snapshot) {}},
		{func(s *snapshot.Snapshot) {}, func(s *snapshot.Snapshot) {}},
	}
	for _, pair := range pairs {
		a, b := fixture(t), fixture(t)
		pair.a(&a)
		pair.b(&b)
		got := twoSided(t, a, b)
		text := strings.ToLower(got.Diagnosis.Summary + " " + strings.Join(got.Diagnosis.Alternatives, " "))
		for _, forbidden := range []string{"firewall", "router", "nat ", "vpn", "is blocking", "is caused by"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s claims %q without evidence for it: %q", got.Diagnosis.ID, forbidden, text)
			}
		}
	}
}

// The document is published to scripts, so its keys and its vocabulary are a
// contract and not an implementation detail.
func TestTwoSidedJSONShape(t *testing.T) {
	a, b := fixture(t), fixture(t)
	setStatus(t, &b, "target_tcp", snapshot.StatusPass)
	data, err := json.Marshal(twoSided(t, a, b))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema", "a", "b", "same_target", "checks", "caveats", "diagnosis"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("two-sided JSON has no %q key", key)
		}
	}
	if got := string(raw["schema"]); got != `"`+TwoSidedSchema+`"` {
		t.Errorf("schema = %s, want %q", got, TwoSidedSchema)
	}
	// Empty collections encode as arrays, so a consumer never reads a finding
	// out of a null.
	c, cb := fixture(t), fixture(t)
	setStatus(t, &c, "target_tcp", snapshot.StatusPass)
	setStatus(t, &cb, "target_tcp", snapshot.StatusPass)
	clean, err := json.Marshal(twoSided(t, c, cb))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(clean), "null") {
		t.Errorf("a reading with no caveats encodes a null: %s", clean)
	}
	var doc struct {
		Diagnosis struct {
			Evidence []string `json:"evidence"`
		} `json:"diagnosis"`
		Caveats []string `json:"caveats"`
	}
	if err := json.Unmarshal(clean, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Caveats == nil || doc.Diagnosis.Evidence == nil {
		t.Error("caveats and evidence must encode as arrays, not null")
	}
}

func TestTwoSidedIsDeterministic(t *testing.T) {
	a, b := fixture(t), fixture(t)
	setStatus(t, &b, "target_tcp", snapshot.StatusPass)
	first, second := twoSided(t, a, b), twoSided(t, a, b)
	one, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	two, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Error("two readings of the same pair produced different documents")
	}
	if first.Text() != second.Text() {
		t.Error("two readings of the same pair produced different text")
	}
}

// Row order follows side A's own run, so the table reads in the order the
// machine the user is sitting at executed its probes.
func TestRowOrderFollowsSideA(t *testing.T) {
	a, b := fixture(t), fixture(t)
	b.Checks = append([]snapshot.Check{{ID: "extra", Status: snapshot.StatusSkip}}, b.Checks...)
	got := twoSided(t, a, b)
	if got.Checks[0].ID != a.Checks[0].ID {
		t.Errorf("first row = %q, want side A's first check %q", got.Checks[0].ID, a.Checks[0].ID)
	}
	if got.Checks[len(got.Checks)-1].ID != "extra" {
		t.Errorf("last row = %q, want the check only side B has", got.Checks[len(got.Checks)-1].ID)
	}
	if row := rowFor(t, got, "extra"); row.Comparable {
		t.Error("a check only one side has cannot be comparable")
	}
}

func TestTwoSidedTextAnswersTheQuestionAndStaysInert(t *testing.T) {
	a, b := fixture(t), fixture(t)
	setStatus(t, &b, "target_tcp", snapshot.StatusPass)
	a.Tool.Version = "1.0\x1b[31m0"
	text := twoSided(t, a, b).Text()
	for _, want := range []string{
		"Network Doctor two-sided diagnosis", "SIDE A", "SIDE B",
		"Failure placed on: side A", "side A only", "Ambiguous:", "Possible:",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text is missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b") {
		t.Errorf("hostile text from an artifact reached the terminal:\n%q", text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimRight(line, " ") != line {
			t.Errorf("trailing whitespace on %q", line)
		}
	}
}

func TestTwoSidedTextWithHeadingsSanitizesVantageLabels(t *testing.T) {
	text := twoSided(t, fixture(t), fixture(t)).TextWithHeadings("LOCAL (SIDE A)", "ideapad\x1b[31m (SIDE B)")
	for _, want := range []string{"LOCAL (SIDE A)", "ideapad (SIDE B)"} {
		if !strings.Contains(text, want) {
			t.Errorf("text is missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b") {
		t.Errorf("hostile vantage label reached the terminal:\n%q", text)
	}
}

func hasCaveat(got TwoSided, want string) bool {
	for _, caveat := range got.Caveats {
		if strings.Contains(caveat, want) {
			return true
		}
	}
	return false
}

// These are ordinary snapshot observations, independent of Scenario Lab.
// DNS overlap is not proof of a common contacted endpoint. Even a shared
// contacted address cannot exclude backend selection, policy or time changes.
func TestEndpointAlternativesSurviveTwoSidedPlacement(t *testing.T) {
	const first, second = "203.0.113.99", "93.184.216.34"
	for _, tc := range []struct {
		name                   string
		dnsA, dnsB             []string
		contactedA, contactedB string
		literal                bool
	}{
		{"disjoint DNS", []string{first}, []string{second}, first, second, false},
		{"identical DNS different selections", []string{first, second}, []string{first, second}, first, second, false},
		{"overlapping DNS", []string{first, second}, []string{second}, first, second, false},
		{"missing DNS", nil, []string{second}, "", second, false},
		{"no address evidence", nil, nil, "", "", false},
		{"same contacted address", []string{first, second}, []string{second}, second, second, false},
		{"identical singleton DNS", []string{second}, []string{second}, second, second, false},
		{"IP literal", nil, nil, second, second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := &snapshot.Target{Host: "app.test", Port: 443, Protocol: "tls+http"}
			if tc.literal {
				target.Host, target.IP = second, second
			}
			a := snapshot.Snapshot{Schema: snapshot.Schema, Target: target, Checks: []snapshot.Check{
				{ID: "dns", Name: "dns", Status: snapshot.StatusPass, Ran: true, Observed: &snapshot.Observed{Addresses: tc.dnsA}},
				{ID: "target_tcp", Name: "target_tcp", Status: snapshot.StatusFail, Ran: true},
			}}
			if tc.contactedA != "" {
				a.Checks[1].Observed = &snapshot.Observed{Attempts: []snapshot.Attempt{{IP: tc.contactedA, Cause: "connection_refused"}}}
			}
			b := snapshot.Snapshot{Schema: snapshot.Schema, Target: target, Checks: []snapshot.Check{
				{ID: "dns", Name: "dns", Status: snapshot.StatusPass, Ran: true, Observed: &snapshot.Observed{Addresses: tc.dnsB}},
				{ID: "target_tcp", Name: "target_tcp", Status: snapshot.StatusPass, Ran: true, Observed: &snapshot.Observed{SelectedIP: tc.contactedB}},
			}}
			for _, s := range []snapshot.Snapshot{a, b} {
				if _, err := snapshot.Encode(s); err != nil {
					t.Fatal(err)
				}
			}
			for _, shared := range []bool{false, true} {
				if shared {
					a.Checks = append(a.Checks, snapshot.Check{ID: "tls", Status: snapshot.StatusFail})
					b.Checks = append(b.Checks, snapshot.Check{ID: "tls", Status: snapshot.StatusFail})
				}
				for _, reverse := range []bool{false, true} {
					left, right, want := a, b, SideA
					if reverse {
						left, right, want = b, a, SideB
					}
					got := twoSided(t, left, right)
					if got.Diagnosis.Side != want || !rowFor(t, got, "target_tcp").Comparable {
						t.Fatalf("lost observed failing side: %+v", got)
					}
					if !got.Diagnosis.Ambiguous || !strings.Contains(strings.Join(got.Diagnosis.Alternatives, " "), "endpoint-specific failure") {
						t.Fatalf("endpoint explanation excluded: %+v", got.Diagnosis)
					}
					if strings.Contains(got.Diagnosis.Summary, "specific to side") || strings.Contains(got.Diagnosis.Summary, "rather than to the endpoint") {
						t.Fatalf("observation became causal localization: %+v", got.Diagnosis)
					}
				}
			}
			// Different causes on the same failed row do not establish one shared cause.
			b.Checks[1].Status = snapshot.StatusFail
			b.Checks[1].Cause = "timeout"
			got := twoSided(t, a, b)
			if got.Diagnosis.Side != SideShared || !got.Diagnosis.Ambiguous || !strings.Contains(strings.Join(got.Diagnosis.Alternatives, " "), "different endpoints") {
				t.Fatalf("same failed row became proof of a shared cause: %+v", got.Diagnosis)
			}
		})
	}
}
