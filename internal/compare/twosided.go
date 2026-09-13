package compare

import (
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// A second reading of the same two artifacts, answering a different question.
//
// Snapshots above asks what changed between two runs. This asks where a
// failure is, given two runs of the same target from two machines: on this
// side, on the other side, on something they share, or nowhere the evidence
// can place it. The two readings are deliberately separate commands, because
// they draw opposite conclusions from the same row moving: a check that is
// PASS on one file and FAIL on the other is a change over time to one and a
// difference between two vantage points to the other, and a reader has to have
// said which they meant.
//
// Nothing here probes, resolves, or reaches the network. Both machines'
// observations were already gathered, by an ordinary local run on one side and
// by an ordinary run on the other, whether that one was started by hand, by
// --via over SSH, or by whoever sent the file. This only reads them.

// TwoSidedSchema is the identity of the machine-readable two-sided reading,
// versioned separately from the comparison and from the snapshots it reads
// because it is published to scripts in its own right.
const TwoSidedSchema = "netdoc.twosided.v1"

// Where the evidence places the failure. These are the answers to the question
// the reading exists to ask, and each one is a distinct finding rather than a
// degree of confidence in the same one.
const (
	// SideNone is no failure to place: nothing failed on either machine.
	SideNone = "none"
	// SideA and SideB are the failures that one machine has and the other does
	// not, in rows both machines measured.
	SideA = "a"
	SideB = "b"
	// SideShared is the same failures on both machines, which places them on
	// neither one in particular.
	SideShared = "shared"
	// SideBoth is each machine failing rows the other passes, which is two
	// findings and not one.
	SideBoth = "both"
	// SideUnknown is too little comparable evidence to place anything.
	SideUnknown = "unknown"
)

// Two-sided reading IDs. Branch on these; the summary beside them is a derived
// sentence and is not parsed back, the same rule the rest of netdoc follows.
const (
	TwoSidedNoFailure          = "two_sided_no_failure"
	TwoSidedOneSideFails       = "two_sided_one_side_fails"
	TwoSidedOneSideFailsMore   = "two_sided_one_side_fails_more"
	TwoSidedSharedFailure      = "two_sided_shared_failure"
	TwoSidedDivergentFailures  = "two_sided_divergent_failures"
	TwoSidedNoComparableChecks = "two_sided_no_comparable_checks"
)

// TwoSided is the whole answer: the two runs it read, one row per check with
// whether that row was comparable at all, the conditions that weaken the
// reading, and where the evidence places the failure.
type TwoSided struct {
	Schema string `json:"schema"`
	A      Side   `json:"a"`
	B      Side   `json:"b"`
	// SameTarget means the same logical host, port and protocol. A hostname
	// can resolve to different endpoints on the two machines.
	SameTarget bool `json:"same_target"`
	// Checks is every check ID in either snapshot, in the order the first run
	// executed them, then the ones only the second run had. Comparable says
	// whether the localization below was allowed to read the row.
	Checks []SideRow `json:"checks"`
	// Caveats are the conditions that weaken the reading: a gap between the two
	// captures, settings that differ, rows only one side has. They are prose
	// for a person and are not parsed back.
	Caveats   []string     `json:"caveats"`
	Diagnosis Localization `json:"diagnosis"`
}

// SideRow is one probe's outcome on both machines.
type SideRow struct {
	ID string `json:"id"`
	A  string `json:"a"`
	B  string `json:"b"`
	// Comparable is true only when both machines measured an outcome that can
	// be set against the other: PASS, WARN, or FAIL on both sides. A row that
	// was skipped, did not apply, or never reported on either side measured
	// nothing to compare, and the localization does not read it.
	Comparable bool `json:"comparable"`
	// Evidence compares recorded dimensions independently of failure placement.
	// Absent means no structured dimension was compared, never equivalence.
	Evidence []EvidenceComparison `json:"evidence,omitempty"`
}

// Localization is where the evidence places the failure, and what it does not
// establish. It mirrors the shape of the peer session's combined diagnosis on
// purpose: both are two-machine readings, and a person who has read one should
// not have to learn a second vocabulary for the other.
type Localization struct {
	ID   string `json:"id"`
	Side string `json:"side"`
	// Summary states what the two runs showed and the narrowest conclusion that
	// follows. It never names a firewall, router, NAT, VPN, or host as the
	// cause, because two snapshots cannot establish one.
	Summary string `json:"summary"`
	// Evidence is the check IDs the finding rests on, in row order.
	Evidence []string `json:"evidence"`
	// Ambiguous is true whenever more than one explanation survives the
	// evidence, which is every finding except an unqualified pass.
	Ambiguous    bool     `json:"ambiguous"`
	Alternatives []string `json:"alternatives,omitempty"`
}

// DifferentTargetsError is what TwoSidedSnapshots returns for two runs that did
// name the same logical target. It is refused rather than reported, which is
// the deliberate difference from Snapshots: a comparison of two endpoints is a
// question with an answer, and a localization across two endpoints is not.
type DifferentTargetsError struct{ A, B string }

func (e DifferentTargetsError) Error() string {
	return "the two snapshots observed different targets (" + display(e.A) + " and " + display(e.B) +
		"); a two-sided reading needs one endpoint seen from two machines"
}

// TwoSidedSnapshots reads two snapshots of one target as two vantage points on
// it. a is this machine's run and b the other machine's; the words are the
// caller's, and nothing here reads the timestamps to decide which is which.
func TwoSidedSnapshots(a, b snapshot.Snapshot) (TwoSided, error) {
	if !sameTarget(a.Target, b.Target) {
		return TwoSided{}, DifferentTargetsError{A: targetDisplay(a.Target), B: targetDisplay(b.Target)}
	}
	t := TwoSided{
		Schema: TwoSidedSchema, A: sideOf(a), B: sideOf(b), SameTarget: true,
		Checks: sideRows(a.Checks, b.Checks, isSanitized(a) || isSanitized(b)), Caveats: []string{},
	}
	t.Caveats = caveats(a, b, t.Checks)
	t.Diagnosis = localize(t.Checks)
	return t, nil
}

// Placed reports whether the reading put a failure anywhere, which is what the
// command's exit code says. A reading that could not place one is not a pass:
// it is a question left open, and it counts as placed for that reason.
func (t TwoSided) Placed() bool { return t.Diagnosis.Side != SideNone }

func sideRows(a, b []snapshot.Check, redacted bool) []SideRow {
	byA, byB := checksByID(a), checksByID(b)
	// b first inside mergedOrder means a's own order leads, since it takes the
	// second argument first.
	order := mergedOrder(checkIDs(b), checkIDs(a))
	rows := make([]SideRow, 0, len(order))
	for _, id := range order {
		rowA, inA := byA[id]
		rowB, inB := byB[id]
		row := SideRow{
			ID: id, A: rowA.Status, B: rowB.Status,
			Comparable: inA && inB && measured(rowA.Status) && measured(rowB.Status),
		}
		if row.Comparable {
			row.Evidence = checkEvidence(rowA, rowB, redacted)
		}
		rows = append(rows, row)
	}
	return rows
}

// measured is whether a row produced an outcome two machines can be set
// against each other on. SKIP, N/A, and INCOMPLETE are three different reasons
// nothing was measured, and none of them is evidence about a machine.
func measured(status string) bool {
	switch status {
	case snapshot.StatusPass, snapshot.StatusWarn, snapshot.StatusFail:
		return true
	}
	return false
}

// failed treats WARN as not failed, the same rule the snapshot's own OK field
// and netdoc's exit code follow: a warned row is a row that worked.
func failed(status string) bool { return status == snapshot.StatusFail }

func localize(rows []SideRow) Localization {
	var comparable, onlyA, onlyB, shared []string
	for _, row := range rows {
		if !row.Comparable {
			continue
		}
		comparable = append(comparable, row.ID)
		switch {
		case failed(row.A) && failed(row.B):
			shared = append(shared, row.ID)
		case failed(row.A):
			onlyA = append(onlyA, row.ID)
		case failed(row.B):
			onlyB = append(onlyB, row.ID)
		}
	}
	switch {
	case len(comparable) == 0:
		return Localization{
			ID: TwoSidedNoComparableChecks, Side: SideUnknown, Evidence: []string{},
			Summary:   "No check produced a measured outcome on both machines, so there is nothing to place on either side.",
			Ambiguous: true,
			Alternatives: []string{
				"the two runs selected different probes",
				"one run was interrupted before its checks reported",
				"the checks that ran did not apply on one of the machines",
			},
		}
	case len(shared) == 0 && len(onlyA) == 0 && len(onlyB) == 0:
		return Localization{
			ID: TwoSidedNoFailure, Side: SideNone, Evidence: comparable,
			Summary: "No check that both machines measured failed on either of them.",
		}
	case len(onlyA) > 0 && len(onlyB) > 0:
		return Localization{
			ID: TwoSidedDivergentFailures, Side: SideBoth, Evidence: append(append(append([]string{}, shared...), onlyA...), onlyB...),
			Summary:   "Each machine has final FAIL checks with non-FAIL outcomes on the other. These are different placements by check, not proof of separate causes.",
			Ambiguous: true,
			Alternatives: []string{
				"each machine has a separate fault",
				"one shared cause affects the two machines differently",
				"the endpoint or the path changed between the two runs",
			},
		}
	case len(onlyA) > 0 || len(onlyB) > 0:
		return oneSided(onlyA, onlyB, shared)
	default:
		return Localization{
			ID: TwoSidedSharedFailure, Side: SideShared, Evidence: shared,
			Summary:   "Every failed check fails from both machines, so the evidence does not place the failure on one of them.",
			Ambiguous: true,
			Alternatives: []string{
				"the endpoint is failing for both machines",
				"the two machines share the path, resolver, or network that is failing",
				"different endpoints or separate faults produce failures in the same checks",
			},
		}
	}
}

// oneSided is the finding the whole reading exists for: rows that fail from one
// machine and pass from the other.
//
// Placement identifies the observed failing side, not the cause's location.
// Even one hostname can select different servers. Matching addresses also do
// not exclude endpoint policy, backend selection or changes between captures.
func oneSided(onlyA, onlyB, shared []string) Localization {
	side, name, other, only := SideA, "A", "B", onlyA
	if len(onlyB) > 0 {
		side, name, other, only = SideB, "B", "A", onlyB
	}
	alternatives := []string{
		"side " + name + "'s own network state",
		"side " + name + "'s path to the endpoint",
		"endpoint-specific failure, including different servers behind the same name or different treatment by address or policy",
		"the endpoint or the path changing between the two runs",
	}
	if len(shared) == 0 {
		return Localization{
			ID: TwoSidedOneSideFails, Side: side, Evidence: only,
			Summary: "Every check with a final FAIL has a non-FAIL outcome on side " + other + ", so final FAIL outcomes occur only on side " +
				name + ". This does not locate the cause on that side or exclude an endpoint-specific cause.",
			Ambiguous: true, Alternatives: alternatives,
		}
	}
	return Localization{
		ID: TwoSidedOneSideFailsMore, Side: side, Evidence: append(append([]string{}, shared...), only...),
		Summary: "Some checks have final FAIL outcomes on both machines, and side " + name +
			" has others with non-FAIL outcomes on side " + other + ". Those additional final FAIL outcomes occur only on side " + name + "; their causes are not localized.",
		Ambiguous:    true,
		Alternatives: append([]string{"a shared cause behind the checks that fail on both machines"}, alternatives...),
	}
}

// caveats names the conditions under which the rows above are less comparable
// than they look. Everything here is a fact taken from the two files: settings
// the runs did not share, rows only one of them has, a gap between the
// captures, and a side whose values are pseudonyms.
//
// Tool differences are deliberately not caveats. Two machines is the premise of
// the reading, so a different operating system, architecture, or netdoc build
// on the other side is the expected case and not a warning.
func caveats(a, b snapshot.Snapshot, rows []SideRow) []string {
	out := []string{}
	if gap := captureGap(a.CreatedAt, b.CreatedAt); gap != "" {
		out = append(out, "The two runs were captured "+gap+" apart, so anything that changed in between is inside the evidence.")
	}
	if a.Options.ProbeTimeoutMs != b.Options.ProbeTimeoutMs {
		out = append(out, "The probe timeouts differ ("+msWord(a.Options.ProbeTimeoutMs)+" and "+msWord(b.Options.ProbeTimeoutMs)+
			"), so a timed-out row may be a shorter budget rather than a slower path.")
	}
	if a.Options.PublicDNS != b.Options.PublicDNS {
		out = append(out, "The second-opinion resolvers differ ("+display(a.Options.PublicDNS)+" and "+display(b.Options.PublicDNS)+
			"), so the public DNS row asked two different questions.")
	} else if a.Options.PublicDNSAuto != b.Options.PublicDNSAuto {
		// Same address, and still not the same question: only the side that
		// did not name it could have crossed to the other address family.
		out = append(out, "One run named its second-opinion resolver and the other took the default, "+
			"so only one of them could try a second address family.")
	}
	if !sameSet(a.Options.Check, b.Options.Check) || !sameSet(a.Options.Skip, b.Options.Skip) {
		out = append(out, "The two runs selected different probes, so they did not measure the same set of checks.")
	}
	if binding := sourceBindingCaveat(a.Options.Source, b.Options.Source); binding != "" {
		out = append(out, binding)
	}
	if n := incomparable(rows); n > 0 {
		out = append(out, strconv.Itoa(n)+" "+plural(n, "check")+" did not produce a measured outcome on both machines and "+
			plural2(n, "was", "were")+" not read.")
	}
	if isSanitized(a) != isSanitized(b) {
		out = append(out, "One side is a sanitized support artifact and the other is full fidelity, so the names and addresses below are not comparable.")
	}
	if isSanitized(a) || isSanitized(b) {
		out = append(out, "Support pseudonyms are local to each artifact. Matching target names or addresses do not establish matching original identities; address-based evidence comparison is unknown.")
	}
	return out
}

// sourceBindingCaveat reads the two runs' --iface bindings as policy, never as
// identity. Two machines have different interface names and different local
// addresses the same way they have different hostnames, so setting those values
// against each other would report the premise of the reading as a warning. This
// is also the one path where independently bound runs are supposed to meet:
// live --two-sided --via refuses --iface because one spelling cannot name an
// interface on both machines, and the documented answer is to save two ordinary
// snapshots and read them here.
//
// What is comparable is what the binding did to the probes. They bind by the
// resolved addresses rather than by the interface name, so the two facts that
// changed what was measured are whether a source was chosen at all and which
// address families the chosen source could dial from. Both are read from the
// artifact's structure and never from a value, so a sanitized support artifact
// yields the same sentence as the run behind it and no interface name or
// address reaches this text.
func sourceBindingCaveat(a, b *snapshot.Source) string {
	switch {
	case (a == nil) != (b == nil):
		return "One run bound its probes to a chosen local source and the other used the machine's own routing choice, " +
			"so a row that fails on one side may follow from that binding rather than from the machine."
	case a == nil:
		return ""
	case bindingFamilies(a) != bindingFamilies(b):
		return "The two source bindings did not cover the same address families (side A " + bindingFamilies(a) +
			", side B " + bindingFamilies(b) + "), so one run could attempt an address family the other never tried."
	}
	return ""
}

// bindingFamilies is the address families a binding left probes able to dial
// from. It reads which fields are present, never what they hold, so a pseudonym
// in a support artifact answers the same as the address it stands for.
func bindingFamilies(s *snapshot.Source) string {
	switch {
	case s.IPv4 != "" && s.IPv6 != "":
		return "IPv4 and IPv6"
	case s.IPv4 != "":
		return "IPv4 only"
	case s.IPv6 != "":
		return "IPv6 only"
	}
	return "no address family"
}

func incomparable(rows []SideRow) int {
	n := 0
	for _, row := range rows {
		if !row.Comparable {
			n++
		}
	}
	return n
}

// captureGap is how far apart the two runs were, in the coarsest unit that
// still says something. An unparsable or missing timestamp yields no caveat
// rather than a guessed one.
func captureGap(a, b string) string {
	first, errA := time.Parse(time.RFC3339, a)
	second, errB := time.Parse(time.RFC3339, b)
	if errA != nil || errB != nil {
		return ""
	}
	gap := first.Sub(second)
	if gap < 0 {
		gap = -gap
	}
	switch {
	case gap < time.Minute:
		return ""
	case gap < time.Hour:
		return countWord(int(gap.Minutes()), "minute")
	case gap < 24*time.Hour:
		return countWord(int(gap.Hours()), "hour")
	}
	return countWord(int(gap.Hours()/24), "day")
}

func countWord(n int, unit string) string {
	return strconv.Itoa(n) + " " + plural(n, unit)
}

func msWord(ms int64) string { return strconv.FormatInt(ms, 10) + "ms" }

func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// sameSet compares two selections as sets, the same rule Snapshots applies to
// them: the order a person typed probe IDs in is not the shape of anything.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
		if seen[v] < 0 {
			return false
		}
	}
	return true
}

// Text renders the human reading: what the two runs were, one row per check
// with which side each outcome belongs to, where the failure is placed, and
// what that placement does not establish.
//
// Everything printed comes out of a file the user was handed, which may not be
// a file netdoc wrote, so all of it goes through the same sanitizer the probes'
// output does before it reaches a terminal.
func (t TwoSided) Text() string { return t.text("SIDE A", "SIDE B") }

// TextWithHeadings keeps the stable reading while letting a live caller name
// which machine supplied side A and side B. The labels are presentation only.
func (t TwoSided) TextWithHeadings(a, b string) string { return t.text(clean(a), clean(b)) }

func (t TwoSided) text(aHeading, bHeading string) string {
	var b strings.Builder
	b.WriteString("Network Doctor two-sided diagnosis\n\n")
	rows := [][3]string{
		{"Target", t.A.Target, t.B.Target},
		{"Captured", t.A.CreatedAt, t.B.CreatedAt},
		{"Tool", toolWord(t.A), toolWord(t.B)},
		{"Verdict", t.A.Verdict, t.B.Verdict},
		{"Overall", okWord(t.A.OK), okWord(t.B.OK)},
	}
	if t.A.Sanitized || t.B.Sanitized {
		rows = append(rows, [3]string{"Fidelity", fidelityWord(t.A.Sanitized), fidelityWord(t.B.Sanitized)})
	}
	writeColumns(&b, "", aHeading, bHeading, rows, make([]string, len(rows)))
	if len(t.Checks) > 0 {
		b.WriteString("\n")
		checks := make([][3]string, len(t.Checks))
		notes := make([]string, len(t.Checks))
		for i, row := range t.Checks {
			checks[i] = [3]string{row.ID, row.A, row.B}
			notes[i] = sideNote(row)
		}
		writeColumns(&b, "Checks", aHeading, bHeading, checks, notes)
	}
	var observations [][3]string
	var relations []string
	for _, row := range t.Checks {
		for _, e := range row.Evidence {
			observations = append(observations, [3]string{row.ID + "/" + e.Dimension, evidenceWord(e.A), evidenceWord(e.B)})
			note := e.Relation
			if e.Reason != "" {
				note += " (" + e.Reason + ")"
			}
			relations = append(relations, note)
		}
	}
	if len(observations) > 0 {
		b.WriteString("\n")
		writeColumns(&b, "Recorded evidence", aHeading, bHeading, observations, relations)
		b.WriteString("\nEquivalence applies only to the named dimension. Missing evidence is unknown. Differences describe observations, not different root causes or a localized cause.\n")
	}
	b.WriteString("\n" + placedWord(t.Diagnosis.Side) + "\n" + clean(t.Diagnosis.Summary) + "\n")
	if len(t.Diagnosis.Evidence) > 0 {
		b.WriteString("Evidence: " + clean(strings.Join(t.Diagnosis.Evidence, ", ")) + "\n")
	}
	if t.Diagnosis.Ambiguous {
		b.WriteString("\nAmbiguous: the two runs do not identify one unique cause.\n")
		for _, alternative := range t.Diagnosis.Alternatives {
			b.WriteString("  Possible: " + clean(alternative) + "\n")
		}
	}
	if len(t.Caveats) > 0 {
		b.WriteString("\nCaveats:\n")
		for _, caveat := range t.Caveats {
			b.WriteString("  " + clean(caveat) + "\n")
		}
	}
	return b.String()
}

// placedWord is the headline: the one line a reader needs before the prose.
func placedWord(side string) string {
	switch side {
	case SideNone:
		return "Failure placed on: neither side"
	case SideA:
		return "Failure placed on: side A"
	case SideB:
		return "Failure placed on: side B"
	case SideShared:
		return "Failure placed on: neither side in particular; it is shared"
	case SideBoth:
		return "Failure placed on: both sides, separately"
	}
	return "Failure placed on: not enough comparable evidence"
}

// sideNote is the trailing word on a check row: which side that row's failure
// belongs to, so a long table does not have to be read column against column.
func sideNote(row SideRow) string {
	switch {
	case !row.Comparable:
		return "not comparable"
	case failed(row.A) && failed(row.B):
		return "fails on both"
	case failed(row.A):
		return "side A only"
	case failed(row.B):
		return "side B only"
	}
	return ""
}
