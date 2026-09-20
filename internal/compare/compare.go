// Package compare answers one question about two diagnostic snapshots: what
// changed. It reads nothing but the two artifacts, opens no socket, and runs
// no probe, so the answer is the same on any machine at any time.
//
// The comparison is semantic, not a JSON diff. Every field is named here on
// purpose, which is what lets a timestamp, a probe's wall time, and a derived
// sentence full of measurements be left out, and what lets a set of resolved
// addresses be compared as a set while a dependency list is compared in order.
// A field nobody named is a field nobody compares, and that is a deliberate
// property: an optional field added to a future snapshot cannot start
// producing differences on its own.
//
// The model here carries no formatting. Text renders the human report and the
// same struct encodes as the machine-readable one, so the two can never
// describe different comparisons.
package compare

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// Schema is the identity of the machine-readable comparison, versioned on its
// own because a comparison is published to scripts and the snapshot format it
// reads is not the same contract.
const Schema = "netdoc.comparison.v1"

// What happened to one piece of state. A field whose absence is spelled as an
// empty string uses Added and Removed for the two edges, so a reader never has
// to decide whether "" was a value.
const (
	KindAdded     = "added"
	KindRemoved   = "removed"
	KindChanged   = "changed"
	KindUnchanged = "unchanged"
)

// Which part of the snapshot a change belongs to. The order they are listed in
// is the order they are reported in.
const (
	SectionTarget    = "target"
	SectionTool      = "tool"
	SectionOptions   = "options"
	SectionDiagnosis = "diagnosis"
	// SectionPaths is how traffic left the machine: which interface each kind
	// of traffic took, and whether two kinds took the same one. It is derived
	// from the route decisions the checks recorded rather than stored a second
	// time, so it can never describe a different run than they do.
	SectionPaths = "paths"
	SectionCheck = "check"
)

// Direction is set only where the vocabulary has an ordering to move along:
// PASS, WARN, and FAIL, and the run's overall ok. SKIP, N/A, and INCOMPLETE
// are outcomes without a rank, so a move to or from one of them carries no
// direction rather than a guessed one.
const (
	DirectionBetter = "better"
	DirectionWorse  = "worse"
)

// absent is what an empty value reads as in the human report. It is a display
// word only; the machine-readable form uses an empty string and says which
// edge it is through Kind.
const absent = "none"

// Comparison is the whole answer: the two runs it read, whether they observed
// the same endpoint, one row per check, and every difference it found.
type Comparison struct {
	Schema string `json:"schema"`
	Before Side   `json:"before"`
	After  Side   `json:"after"`
	// SameTarget is true only when the two artifacts establish that they
	// observed one endpoint. Comparing two that did not is still allowed,
	// because "the same host, entered differently" and "a different host" are
	// questions the snapshot's own target fields exist to answer, but every row
	// below then describes two different endpoints and the report says so
	// first.
	//
	// False therefore covers two readings, and the line between them is which
	// dimensions survive sanitization. Whether a run had a target at all, the
	// port, the protocol, and whether the target was an IP literal rather than
	// a name are recorded verbatim in a support artifact, so a difference in
	// any of them is a difference at any fidelity and false means the two runs
	// named different endpoints, sanitized or not. Only once all of those agree
	// does identity come down to a host or an address, and only then does
	// fidelity matter: full fidelity on both sides settles it, while a support
	// pseudonym on either side leaves it unestablished, because an alias is a
	// name inside one artifact and a match across two establishes neither one
	// endpoint nor two. The caveats below are what say that second reading
	// applies.
	SameTarget bool `json:"same_target"`
	// Checks is every check ID in either snapshot, in the order the later run
	// executed them, then the ones only the earlier run had, in its order.
	// Unchanged rows are kept: a comparison has to be able to say what stayed
	// the same as well as what did not.
	Checks []CheckRow `json:"checks"`
	// Changes is every meaningful difference, in section order and then in the
	// order the snapshot itself lists the state. Empty means the two runs
	// describe the same network state.
	Changes []Change `json:"changes"`
	// Caveats are the conditions that weaken every row above. Today there is
	// one family of them: a side written by --support carries pseudonyms that
	// belong to that one file, so a value read across the pair establishes
	// neither one original nor two. They are prose for a person and are not
	// parsed back, the same rule the two-sided reading's caveats follow.
	Caveats []string `json:"caveats"`
	// relation is the three-state reading same_target had to flatten. It is
	// unexported because it is not part of the published document, and Text
	// is only ever called on a comparison this package built.
	relation targetRelation
}

// Same reports whether the two snapshots hold the same diagnostic state.
func (c Comparison) Same() bool { return len(c.Changes) == 0 }

// Side is the identity of one of the two runs, for the header of the report.
// Nothing here is compared field by field; the changes below carry that.
type Side struct {
	CreatedAt string        `json:"created_at"`
	Tool      snapshot.Tool `json:"tool"`
	// Target is the endpoint in display form, empty for a generic run.
	Target  string `json:"target"`
	Verdict string `json:"verdict"`
	Summary string `json:"summary"`
	OK      bool   `json:"ok"`
	// Sanitized is true when this side was prepared for sharing with --support.
	// It is read from the artifact's own redaction metadata and never inferred
	// from values that happen to look like placeholders. A comparison of two
	// sanitized files is still meaningful, but the names and addresses in it
	// are pseudonyms, and a reader has to be told which it is looking at.
	Sanitized bool `json:"sanitized,omitempty"`
}

// CheckRow is one probe's outcome on both sides. Before and After are the
// row's status, empty when that snapshot had no such check at all.
type CheckRow struct {
	ID     string `json:"id"`
	Before string `json:"before"`
	After  string `json:"after"`
	// Kind is about the status alone: added and removed mean the check itself
	// is on one side only.
	Kind      string `json:"kind"`
	Direction string `json:"direction,omitempty"`
	// Differs is true when anything about this check changed, including
	// evidence underneath a status that stayed the same. A row can be
	// unchanged and still differ.
	Differs bool `json:"differs"`
}

// Change is one difference. Path is its stable identity, spelled as the field
// path inside the snapshot, so two runs of the comparison name the same
// difference the same way and a script can key on it.
type Change struct {
	Section string `json:"section"`
	// Check is the stable probe ID the change belongs to, empty outside the
	// check section.
	Check  string `json:"check,omitempty"`
	Path   string `json:"path"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Before string `json:"before"`
	After  string `json:"after"`
	// Direction is "better" or "worse" where the values have an ordering, and
	// empty everywhere else. It is a statement about the two readings, not
	// about what caused them to differ.
	Direction string `json:"direction,omitempty"`
	Summary   string `json:"summary"`
}

// Snapshots compares two decoded snapshots. before is the earlier or known
// good run, after the later or broken one; the words are the caller's, and
// nothing here reads the timestamps to decide which is which.
func Snapshots(before, after snapshot.Snapshot) Comparison {
	c := Comparison{
		Schema:   Schema,
		Before:   sideOf(before),
		After:    sideOf(after),
		relation: targetRelationOf(before, after),
		Checks:   []CheckRow{},
		Changes:  []Change{},
		Caveats:  redactionCaveats(before, after),
	}
	c.SameTarget = c.relation == targetsSame
	d := &diff{changes: []Change{}}
	diffTarget(d, before.Target, after.Target)
	diffTool(d, before.Tool, after.Tool)
	diffOptions(d, before.Options, after.Options)
	diffDiagnosis(d, before, after)
	diffPaths(d, before, after)
	c.Checks = diffChecks(d, before.Checks, after.Checks)
	c.Changes = d.changes
	return c
}

func sideOf(s snapshot.Snapshot) Side {
	return Side{
		CreatedAt: s.CreatedAt, Tool: s.Tool, Target: targetDisplay(s.Target),
		Verdict: s.Diagnosis.Verdict, Summary: s.Diagnosis.Summary, OK: s.OK,
		Sanitized: isSanitized(s),
	}
}

// isSanitized reads the artifact's own redaction metadata. Privacy is never
// inferred from values that happen to look like placeholders.
func isSanitized(s snapshot.Snapshot) bool {
	return s.Redaction != nil && s.Redaction.Sanitized
}

// targetDisplay is the endpoint as one word for a header row. It is display
// text and nothing compares it; the target fields underneath are compared one
// at a time.
func targetDisplay(t *snapshot.Target) string {
	if t == nil {
		return ""
	}
	host := t.Host
	if host == "" {
		host = t.IP
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(t.Port) + " " + t.Protocol
}

// A support artifact's names are pseudonyms, and a pseudonym is a name inside
// one artifact and nowhere else. SanitizeForSupport builds a fresh mapping per
// call, so two files sanitized separately are two vocabularies that happen to
// spell their aliases the same way: one endpoint can be host-1.invalid in one
// file and host-3.invalid in the other, and two unrelated endpoints can both
// be host-2.invalid. Across that boundary a match establishes nothing and a
// mismatch establishes nothing either, and there is deliberately no stable
// identifier that would let it, because that is the property --support sells.
//
// So every reading that treats one of those values as an identity has to ask
// first whether the two artifacts share the vocabulary it is written in.
// Everything redaction leaves alone (statuses, causes, ports, protocols,
// booleans, derived conclusions) keeps its full meaning across two support
// artifacts, which is what makes comparing them worth doing at all.
func sharedRedactionVocabulary(a, b snapshot.Snapshot) bool {
	return !isSanitized(a) && !isSanitized(b)
}

// targetRelation is what the two artifacts establish about their endpoints.
// Three states, because a pair that cannot answer the question is not the same
// thing as a pair that answered "different", and collapsing them loses the
// distinction the report and the two-sided refusal both need.
//
// targetsDifferent is the zero value so that a Comparison nobody filled in
// reads the way it always did.
type targetRelation int

const (
	targetsDifferent targetRelation = iota
	targetsSame
	targetsUnknown
)

// targetRelationOf answers it for one pair, asking the dimensions redaction
// leaves alone before the ones it rewrites.
//
// Whether a run had a target at all, the port, the protocol, and whether the
// target was an IP literal rather than a name are all recorded verbatim by
// SanitizeForSupport. A difference in any of them is therefore a difference in
// the endpoint at any fidelity, and saying "unknown" there would throw away an
// answer the two files do carry. Only once those agree does the question come
// down to a host or an address, and only then does the vocabulary matter.
func targetRelationOf(a, b snapshot.Snapshot) targetRelation {
	before, after := a.Target, b.Target
	if before == nil || after == nil {
		if before == nil && after == nil {
			return targetsSame
		}
		return targetsDifferent
	}
	if before.Port != after.Port || before.Protocol != after.Protocol ||
		(before.IP == "") != (after.IP == "") {
		return targetsDifferent
	}
	if !sharedRedactionVocabulary(a, b) {
		return targetsUnknown
	}
	if sameEndpointName(before.Host, after.Host) && sameEndpointName(before.IP, after.IP) {
		return targetsSame
	}
	return targetsDifferent
}

// sameEndpointName answers whether two recorded spellings name one endpoint.
// It is the semantic half of target identity, kept apart from the presentation
// half: Raw is the spelling a person typed and stays free to differ, while
// these two fields are what the run actually addressed.
//
// Two rules, one per kind of name. An address is compared as a parsed address,
// so the compressed and expanded spellings of one IPv6 address are one
// endpoint, which a string comparison of a field the snapshot canonicalized
// only happens to get right. netip.Addr rather than net.IP.Equal, because it
// keeps the distinction net.IP drops: an IPv4 address and its IPv4-mapped IPv6
// form stay two endpoints here, since netdoc diagnoses address-family
// behavior and calling those two spellings one target would decide a question
// this comparison has no business deciding. A DNS name is compared the way DNS
// reads it: case-insensitively, and ignoring the terminal root dot, since
// example.com, EXAMPLE.COM and example.com. are one name in the protocol.
// Everything else still has to match byte for byte, so two different hosts and
// two different addresses stay two endpoints.
//
// Both fields go through it, including the pair of empty strings a hostname
// target leaves in IP, which no rule here treats specially: empty equals
// empty. A file netdoc did not write can carry a spelling ParseTarget would
// have rejected, and one that will not parse as an address falls through to
// the name rule rather than being called equal to anything.
func sameEndpointName(a, b string) bool {
	addrA, errA := netip.ParseAddr(a)
	addrB, errB := netip.ParseAddr(b)
	if errA == nil && errB == nil {
		return addrA == addrB
	}
	// EqualFold is ASCII case folding on the only names that can reach here
	// from ParseTarget: an internationalized name is converted to its A-label
	// before it is ever recorded, so a hostname in a snapshot is ASCII.
	return strings.EqualFold(trimRootDot(a), trimRootDot(b))
}

// trimRootDot drops the one trailing dot that spells the DNS root, and only
// one: a name ending in two dots has an empty label and is a different name,
// not a respelling.
func trimRootDot(host string) string { return strings.TrimSuffix(host, ".") }

// The identity of an address-valued recording, in one place. Every reading in
// this package that has to decide whether two recorded spellings name one
// address goes through these three, so the comparison and the two-sided
// reading cannot grow two answers to that question again.
//
// Deliberately not sameEndpointName. Target identity is a different rule for a
// different field: it also has to read hostnames, and it keeps an IPv4 address
// apart from its IPv4-mapped IPv6 form because netdoc diagnoses address-family
// behavior at the target, where a run that reached ::ffff:203.0.113.9 and a run
// that reached 203.0.113.9 are two facts worth keeping apart.
//
// An observation is the opposite case, and unmaps. Every producer of these
// fields already writes a mapped IPv4 address as IPv4: the snapshot builder
// spells addresses, attempts and sources through net.IP.String, the per-OS
// route readers call Unmap before recording a destination, both paths that
// accept -public-dns canonicalize through net.ParseIP(...).String(), and the
// support redactor unmaps before it assigns a pseudonym. Unmapping here agrees
// with what netdoc itself wrote rather than inventing a distinction no producer
// of an observation records, and it is what the two-sided evidence already did.
//
// A value that will not parse is its own identity, spelled exactly as recorded.
// That is what keeps the empty string apart from any address, keeps the
// support artifact's <address-redacted> marker from being read as one, and
// leaves a file netdoc did not write comparing byte for byte rather than being
// called equal to something it does not name. A canonical form always parses,
// so an unparseable recording can never collide with one.
//
// Identity only, and internal. These keys decide what corresponds to what and
// go no further: a difference that survives one of them is reported with the
// spellings the two files carry, in Change.Path as much as in Before and
// After. So netdoc.comparison.v1 paths stay what they were, and a file netdoc
// did not write is never quoted back in a spelling it does not use.

// addressKey is the identity of a bare IP observation.
func addressKey(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return value
	}
	return address.Unmap().String()
}

// endpointKey is the identity of an address-and-port observation. It is a
// separate rule because it is a separate value type: the port is part of the
// identity, so one resolver reached on two ports stays two recordings.
func endpointKey(value string) string {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		return value
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()).String()
}

// prefixKey is the identity of a CIDR observation, and it normalizes the
// spelling of the address inside it and nothing else.
//
// Masked deliberately not applied. A route prefix is the entry the kernel said
// it matched, and every producer that fills one derives it with Prefix on an
// already-unmapped destination, so a recorded entry is masked before it is
// written. Masking here would therefore change no artifact netdoc wrote, and
// would silently equate two structurally different entries in one it did not.
// Unmap is left out for the same reason: it would have to move the prefix
// length by 96 as well, which is a claim about a different entry rather than a
// respelling of this one.
func prefixKey(value string) string {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return value
	}
	return prefix.String()
}

// sameResolverAddress answers whether two recorded spellings name one
// second-opinion resolver, through the shared bare-address rule above.
func sameResolverAddress(a, b string) bool { return addressKey(a) == addressKey(b) }

// targetsNotComparable is the third state, kept for the report. It is not a
// JSON key: same_target stays the one published boolean, and a machine reader
// that needs the difference has the caveats and the two sanitized flags, which
// is the same material the sentence is written from.
func (c Comparison) targetsNotComparable() bool { return c.relation == targetsUnknown }

// redactionCaveats states what the values below are worth when a support
// artifact is on either side. It is the comparison's counterpart to the
// sentence the two-sided reading already carries, and it covers every
// pseudonymized field at once rather than annotating them one by one: target,
// addresses, resolvers, interfaces, SSIDs, routes, prefixes, route tables and
// the derived paths read off them are all the same kind of name.
func redactionCaveats(before, after snapshot.Snapshot) []string {
	out := []string{}
	if sharedRedactionVocabulary(before, after) {
		return out
	}
	out = append(out, "Support pseudonyms are assigned inside one artifact. A host, address, interface, SSID, "+
		"route, prefix or table name that matches across these two files does not establish one original value, "+
		"and one that differs does not establish two.")
	if isSanitized(before) != isSanitized(after) {
		out = append(out, "One side is a sanitized support artifact and the other is full fidelity, so a name or "+
			"address that redaction replaces may differ for that reason alone. No difference among those values "+
			"establishes that an identity changed.")
	}
	return out
}

// diff accumulates changes in the order they are recorded, which is the order
// the sections and fields are named in this file. Nothing sorts afterwards, so
// the report's order is the source's order and is the same every run.
//
// changes starts empty rather than nil so a comparison that finds nothing
// encodes as an empty array. "No differences" is the answer this command exists
// to give as often as any other, and a consumer must not have to read it out of
// a null.
type diff struct{ changes []Change }

// field records one scalar difference, or nothing when the two readings agree.
// An empty string on either side is absence, which is why the kind is decided
// here rather than by the caller: every field that can be missing spells it the
// same way.
func (d *diff) field(section, check, path, label, before, after string) {
	if before == after {
		return
	}
	c := Change{
		Section: section, Check: check, Path: path, Label: label,
		Kind: KindChanged, Before: before, After: after,
	}
	switch {
	case before == "":
		c.Kind = KindAdded
	case after == "":
		c.Kind = KindRemoved
	}
	c.Summary = label + " changed from " + display(before) + " to " + display(after)
	d.changes = append(d.changes, c)
}

// identityField records one scalar difference between two recordings of the
// same address-valued field, read through key. Two spellings of one address
// are not a difference; anything key separates is reported by field above,
// with the spellings the two artifacts carry rather than the normalized pair.
func (d *diff) identityField(key func(string) string, section, check, path, label, before, after string) {
	if key(before) == key(after) {
		return
	}
	d.field(section, check, path, label, before, after)
}

// member records one item of an unordered collection that is on one side only.
// A collection whose membership is the whole question reports its items this
// way rather than as one changed list, so a reader can act on the item.
func (d *diff) member(section, check, path, label, key string, added bool) {
	c := Change{Section: section, Check: check, Path: path, Label: label, Kind: KindRemoved, Before: key}
	side := "before"
	if added {
		c.Kind, c.Before, c.After, side = KindAdded, "", key, "after"
	}
	c.Summary = label + " " + key + " is in the " + side + " snapshot only"
	d.changes = append(d.changes, c)
}

// rank orders the outcomes that have an ordering. The three a probe can move
// between on a healthy-to-broken axis are ranked; the rest are not, and a move
// involving one of them gets no direction at all.
func rank(status string) (int, bool) {
	switch status {
	case snapshot.StatusPass:
		return 0, true
	case snapshot.StatusWarn:
		return 1, true
	case snapshot.StatusFail:
		return 2, true
	}
	return 0, false
}

// direction says which way a status moved, and says nothing when either end is
// an outcome with no rank. It is a comparison of two readings and never a claim
// about why they differ.
func direction(before, after string) string {
	b, okB := rank(before)
	a, okA := rank(after)
	switch {
	case !okB || !okA || a == b:
		return ""
	case a > b:
		return DirectionWorse
	}
	return DirectionBetter
}

func display(v string) string {
	if v == "" {
		return absent
	}
	return v
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func diffTarget(d *diff, before, after *snapshot.Target) {
	if before == nil || after == nil {
		if before == after {
			return
		}
		// A generic run against a targeted one. One change, not a field-by-field
		// list of a target that only exists on one side.
		d.field(SectionTarget, "", "target", "target", targetDisplay(before), targetDisplay(after))
		return
	}
	d.field(SectionTarget, "", "target.host", "target host", before.Host, after.Host)
	d.field(SectionTarget, "", "target.ip", "target IP literal", before.IP, after.IP)
	d.field(SectionTarget, "", "target.port", "target port", strconv.Itoa(before.Port), strconv.Itoa(after.Port))
	d.field(SectionTarget, "", "target.protocol", "target protocol", before.Protocol, after.Protocol)
	d.field(SectionTarget, "", "target.port_explicit", "target port given explicitly", yesNo(before.PortExplicit), yesNo(after.PortExplicit))
	// Last, and on its own: the same endpoint typed two ways is worth
	// reporting, but it is the least of the target differences and must not
	// lead the list when a real one is also present.
	d.field(SectionTarget, "", "target.raw", "target as typed", before.Raw, after.Raw)
}

func diffTool(d *diff, before, after snapshot.Tool) {
	d.field(SectionTool, "", "tool.version", "netdoc version", before.Version, after.Version)
	d.field(SectionTool, "", "tool.os", "operating system", before.OS, after.OS)
	d.field(SectionTool, "", "tool.arch", "architecture", before.Arch, after.Arch)
}

func diffOptions(d *diff, before, after snapshot.Options) {
	d.field(SectionOptions, "", "options.probe_timeout_ms", "probe timeout",
		strconv.FormatInt(before.ProbeTimeoutMs, 10)+"ms", strconv.FormatInt(after.ProbeTimeoutMs, 10)+"ms")
	// Read as an address, not as text: one resolver spelled two ways is one
	// resolver. The recorded spellings still go into the change when the
	// resolvers really do differ.
	if !sameResolverAddress(before.PublicDNS, after.PublicDNS) {
		d.field(SectionOptions, "", "options.public_dns", "second-opinion resolver", before.PublicDNS, after.PublicDNS)
	}
	// Beside the address rather than folded into it: the same resolver reached
	// two different ways is a real difference, because only the run that did
	// not name it could cross to the other address family.
	d.field(SectionOptions, "", "options.public_dns_auto", "second-opinion resolver chosen by netdoc",
		yesNo(before.PublicDNSAuto), yesNo(after.PublicDNSAuto))
	// The selection is a set. The snapshot keeps the order it was typed in
	// because that is what the user wrote, but the run applied it as a set, so
	// a reordered --check is not a different run.
	d.field(SectionOptions, "", "options.check", "check selection", sortedList(before.Check), sortedList(after.Check))
	d.field(SectionOptions, "", "options.skip", "skip selection", sortedList(before.Skip), sortedList(after.Skip))
	b, a := before.Source, after.Source
	if b == nil {
		b = &snapshot.Source{}
	}
	if a == nil {
		a = &snapshot.Source{}
	}
	d.field(SectionOptions, "", "options.source.interface", "bound interface", b.Interface, a.Interface)
	// Both bound sources are addresses, recorded through net.IP.String by the
	// same producer as every observed address, so they read by the same rule.
	d.identityField(addressKey, SectionOptions, "", "options.source.ipv4", "bound IPv4 source", b.IPv4, a.IPv4)
	d.identityField(addressKey, SectionOptions, "", "options.source.ipv6", "bound IPv6 source", b.IPv6, a.IPv6)
}

// sortedSet normalizes an unordered selection to what the run actually applied:
// its distinct members, in one stable order. The runtime selection is a set, so
// a probe named twice on the command line selected the same probe once, and two
// spellings of one selection have to normalize to one value. Working on a copy,
// never the caller's slice: the snapshot is the caller's, it keeps the spelling
// the user typed, and comparing it must not rewrite it.
//
// This is the one place the set rule lives. Both readings normalize through it
// so neither can drift into comparing order or repetition again.
func sortedSet(values []string) []string {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}

// sortedList renders an unordered selection as one comparable value.
func sortedList(values []string) string {
	return strings.Join(sortedSet(values), ",")
}

func diffDiagnosis(d *diff, before, after snapshot.Snapshot) {
	okBefore, okAfter := okWord(before.OK), okWord(after.OK)
	if okBefore != okAfter {
		dir := DirectionWorse
		if after.OK {
			dir = DirectionBetter
		}
		d.changes = append(d.changes, Change{
			Section: SectionDiagnosis, Path: "ok", Label: "overall result", Kind: KindChanged,
			Before: okBefore, After: okAfter, Direction: dir,
			Summary: "overall result changed from " + okBefore + " to " + okAfter,
		})
	}
	d.field(SectionDiagnosis, "", "diagnosis.verdict", "verdict", before.Diagnosis.Verdict, after.Diagnosis.Verdict)
	d.field(SectionDiagnosis, "", "diagnosis.blamed", "blamed check", before.Diagnosis.Blamed, after.Diagnosis.Blamed)
	d.field(SectionDiagnosis, "", "diagnosis.failed_stage", "first failed check", before.Diagnosis.FailedStage, after.Diagnosis.FailedStage)
	// Findings are a set keyed by ID, except for the first one: the diagnosis
	// states its primary conclusion by putting it there, so that one position
	// carries meaning and is compared as such.
	d.field(SectionDiagnosis, "", "diagnosis.findings.primary", "primary finding",
		primaryFinding(before.Diagnosis.Findings), primaryFinding(after.Diagnosis.Findings))
	beforeFindings := findingsByID(before.Diagnosis.Findings)
	afterFindings := findingsByID(after.Diagnosis.Findings)
	for _, id := range mergedOrder(findingIDs(before.Diagnosis.Findings), findingIDs(after.Diagnosis.Findings)) {
		b, inBefore := beforeFindings[id]
		a, inAfter := afterFindings[id]
		if inBefore != inAfter {
			d.member(SectionDiagnosis, "", "diagnosis.findings."+id, "finding", id, inAfter)
			continue
		}
		d.field(SectionDiagnosis, "", "diagnosis.findings."+id+".verdict", "finding "+id+" verdict", b.Verdict, a.Verdict)
		d.field(SectionDiagnosis, "", "diagnosis.findings."+id+".focus", "finding "+id+" focus", b.Focus, a.Focus)
		// Confidence is how strongly the run's observations supported this
		// conclusion. It decides nothing, but it is the producer's assessment
		// and a published vocabulary, so a move between two levels is a change
		// in the diagnosis rather than noise.
		d.field(SectionDiagnosis, "", "diagnosis.findings."+id+".confidence", "finding "+id+" confidence",
			b.Confidence, a.Confidence)
		// Evidence keeps its order: the diagnosis lists the rows it reasoned
		// from in the order it reasoned over them.
		d.field(SectionDiagnosis, "", "diagnosis.findings."+id+".evidence", "finding "+id+" evidence",
			strings.Join(b.Evidence, ","), strings.Join(a.Evidence, ","))
		d.field(SectionDiagnosis, "", "diagnosis.findings."+id+".causal_evidence", "finding "+id+" causal evidence",
			canonicalList(b.CausalEvidence), canonicalList(a.CausalEvidence))
		diffCounterfactual(d, id, b.Counterfactual, a.Counterfactual)
	}
}

// diffCounterfactual compares the controlled alternatives a finding observed.
// Presence is its own difference: a conclusion that stopped carrying one, or
// started, is a different conclusion. When both sides have one, the variable
// and the alternatives are reported apart, so a reader sees which of the two
// moved.
func diffCounterfactual(d *diff, id string, before, after *snapshot.Counterfactual) {
	path := "diagnosis.findings." + id + ".counterfactual"
	label := "finding " + id + " counterfactual"
	if before == nil || after == nil {
		d.field(SectionDiagnosis, "", path, label, canonicalValue(before), canonicalValue(after))
		return
	}
	d.field(SectionDiagnosis, "", path+".variable", label+" variable", before.Variable, after.Variable)
	d.field(SectionDiagnosis, "", path+".alternatives", label+" alternatives",
		canonicalList(before.Alternatives), canonicalList(after.Alternatives))
}

// canonicalList and canonicalValue spell a structured value as one comparable
// string. JSON rather than a joined string, because every field inside is
// external text: an address carries colons, and a separator that can occur
// inside a field makes two different structures compare equal. That is not a
// theoretical worry, since the causal-evidence value names the observation
// member being cited, which is routinely an IPv6 address.
//
// Empty is spelled as the empty string rather than as "null" or "[]", so a
// value that appears on one side only is reported as added or removed like
// every other absence in this file. Encoding cannot fail: these are structs of
// strings and slices of them, with no map and no channel in reach.
func canonicalList[T any](items []T) string {
	if len(items) == 0 {
		return ""
	}
	data, _ := json.Marshal(items)
	return string(data)
}

func canonicalValue[T any](value *T) string {
	if value == nil {
		return ""
	}
	data, _ := json.Marshal(value)
	return string(data)
}

func okWord(ok bool) string {
	if ok {
		return "ok"
	}
	return "not ok"
}

func primaryFinding(findings []snapshot.Finding) string {
	if len(findings) == 0 {
		return ""
	}
	return findings[0].ID
}

func findingIDs(findings []snapshot.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}

func findingsByID(findings []snapshot.Finding) map[string]snapshot.Finding {
	byID := make(map[string]snapshot.Finding, len(findings))
	for _, f := range findings {
		if _, seen := byID[f.ID]; !seen {
			byID[f.ID] = f
		}
	}
	return byID
}

// mergedOrder is the reporting order for anything keyed by a stable ID: the
// later run's order first, because that is the run being explained, then
// whatever only the earlier run had, in its own order. Both orders come out of
// the artifacts, so no map is ever ranged over to decide what gets printed.
func mergedOrder(before, after []string) []string {
	order := make([]string, 0, len(before)+len(after))
	seen := make(map[string]bool, len(before)+len(after))
	for _, ids := range [][]string{after, before} {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				order = append(order, id)
			}
		}
	}
	return order
}

func diffChecks(d *diff, before, after []snapshot.Check) []CheckRow {
	beforeByID := checksByID(before)
	afterByID := checksByID(after)
	order := mergedOrder(checkIDs(before), checkIDs(after))
	rows := make([]CheckRow, 0, len(order))
	for _, id := range order {
		b, inBefore := beforeByID[id]
		a, inAfter := afterByID[id]
		row := CheckRow{ID: id, Before: b.Status, After: a.Status, Kind: KindUnchanged}
		if inBefore != inAfter {
			row.Kind = KindRemoved
			if inAfter {
				row.Kind = KindAdded
			}
			row.Differs = true
			d.member(SectionCheck, id, "checks."+id, "check", id, inAfter)
			rows = append(rows, row)
			continue
		}
		start := len(d.changes)
		diffCheck(d, id, b, a)
		row.Differs = len(d.changes) > start
		if b.Status != a.Status {
			row.Kind = KindChanged
			row.Direction = direction(b.Status, a.Status)
		}
		rows = append(rows, row)
	}
	return rows
}

func checkIDs(checks []snapshot.Check) []string {
	ids := make([]string, len(checks))
	for i, c := range checks {
		ids[i] = c.ID
	}
	return ids
}

func checksByID(checks []snapshot.Check) map[string]snapshot.Check {
	byID := make(map[string]snapshot.Check, len(checks))
	for _, c := range checks {
		if _, seen := byID[c.ID]; !seen {
			byID[c.ID] = c
		}
	}
	return byID
}

// diffCheck compares one probe row that both runs have.
//
// Name, detail, and fix are not here, and that is the point of naming fields by
// hand. All three are derived sentences the snapshot documents as never parsed
// back: name is built from the probe and the target, and detail and fix carry
// the measurements ("in 41ms") that make every rerun differ. Status and cause
// are the machine-readable form of what they say, and those are compared.
// duration_ms is left out for the same reason, being the measurement itself.
func diffCheck(d *diff, id string, before, after snapshot.Check) {
	statusBefore, statusAfter := before.Status, after.Status
	if statusBefore != statusAfter {
		d.changes = append(d.changes, Change{
			Section: SectionCheck, Check: id, Path: "checks." + id + ".status", Label: id,
			Kind: KindChanged, Before: statusBefore, After: statusAfter,
			Direction: direction(statusBefore, statusAfter),
			Summary:   id + " changed from " + display(statusBefore) + " to " + display(statusAfter),
		})
	}
	d.field(SectionCheck, id, "checks."+id+".cause", id+" cause", before.Cause, after.Cause)
	d.field(SectionCheck, id, "checks."+id+".cause_family", id+" cause family", before.CauseFamily, after.CauseFamily)
	// Whether the probe body executed at all, which duration_ms cannot answer
	// and status only narrows.
	d.field(SectionCheck, id, "checks."+id+".ran", id+" ran", yesNo(before.Ran), yesNo(after.Ran))
	// Ordered: a dependency list is the shape of the graph the run executed.
	d.field(SectionCheck, id, "checks."+id+".deps", id+" dependencies",
		strings.Join(before.Deps, ","), strings.Join(after.Deps, ","))
	// An inferred outcome and a measured one are not the same state, so the
	// mark that says which is compared alongside the status it rewrote.
	d.field(SectionCheck, id, "checks."+id+".derived.status_downgraded", id+" status relaxed by later reasoning",
		yesNo(before.Derived != nil && before.Derived.StatusDowngraded),
		yesNo(after.Derived != nil && after.Derived.StatusDowngraded))
	// Whether the two resolvers were found to point at the same place. It is a
	// conclusion drawn from the answers rather than a reading of them, and the
	// addresses above cannot stand in for it: a support artifact carries the
	// conclusion but only pseudonyms of what produced it.
	d.field(SectionCheck, id, "checks."+id+".derived.answer_comparison", id+" DNS answer comparison",
		string(answerComparisonOf(before)), string(answerComparisonOf(after)))
	diffObserved(d, id, observedOf(before), observedOf(after))
}

// answerComparisonOf reads a row's recorded DNS answer comparison, spelling an
// absent one as the empty value it already means: no comparison was recorded,
// which is a different state from either outcome.
func answerComparisonOf(c snapshot.Check) snapshot.AnswerComparison {
	if c.Derived == nil {
		return ""
	}
	return c.Derived.AnswerComparison
}

// observedOf reads a row's evidence, substituting the zero value for an absent
// one. Every field under it spells absence as an empty value already, so a row
// that measured nothing and a row whose readings were all empty compare the
// same way, which is what they mean.
func observedOf(c snapshot.Check) snapshot.Observed {
	if c.Observed == nil {
		return snapshot.Observed{}
	}
	return *c.Observed
}

func diffObserved(d *diff, id string, before, after snapshot.Observed) {
	path := "checks." + id + ".observed."
	// Resolver answers are a set. Which record came back first is the
	// resolver's business and changes between two identical lookups, so an
	// order-only difference is not a difference.
	diffSet(d, id, path+"addresses", id+" resolved address", addressKey, before.Addresses, after.Addresses)
	d.identityField(addressKey, SectionCheck, id, path+"selected_ip", id+" selected address", before.SelectedIP, after.SelectedIP)
	d.field(SectionCheck, id, path+"dns_not_found", id+" resolver answered with no records",
		yesNo(before.DNSNotFound), yesNo(after.DNSNotFound))
	d.identityField(addressKey, SectionCheck, id, path+"resolver", id+" resolver", before.Resolver, after.Resolver)
	// A resolver target carries its port, so it reads by the endpoint rule
	// rather than the bare-address one: one resolver on two ports is two.
	diffSet(d, id, path+"resolver_targets", id+" resolver target tried", endpointKey, before.ResolverTargets, after.ResolverTargets)
	d.identityField(addressKey, SectionCheck, id, path+"source_ip", id+" source address", before.SourceIP, after.SourceIP)
	d.field(SectionCheck, id, path+"interface", id+" interface", before.Interface, after.Interface)
	d.field(SectionCheck, id, path+"interface_ambiguous", id+" interface is ambiguous",
		yesNo(before.InterfaceAmbiguous), yesNo(after.InterfaceAmbiguous))
	d.field(SectionCheck, id, path+"ssid", id+" Wi-Fi network", before.SSID, after.SSID)
	bf, af := familiesOf(before), familiesOf(after)
	d.field(SectionCheck, id, path+"address_families.ipv4", id+" IPv4 egress", bf.IPv4, af.IPv4)
	d.field(SectionCheck, id, path+"address_families.ipv6", id+" IPv6 egress", bf.IPv6, af.IPv6)
	// A portal with no sign-in URL and no portal at all are different states,
	// so presence is its own field rather than something inferred from the URL.
	d.field(SectionCheck, id, path+"portal", id+" captive portal",
		portalWord(before.Portal), portalWord(after.Portal))
	d.field(SectionCheck, id, path+"portal.redirect_url", id+" captive portal sign-in URL",
		portalURL(before.Portal), portalURL(after.Portal))
	// This is a positive-only observation: false does not establish that the
	// client-to-proxy hop used TLS or that no cleartext hostname was sent.
	d.field(SectionCheck, id, path+"connect_cleartext", id+" plaintext HTTP CONNECT observation",
		recordedWord(before.ConnectCleartext), recordedWord(after.ConnectCleartext))
	diffAttempts(d, id, path, before.Attempts, after.Attempts)
	diffRoutes(d, id, path, before.Routes, after.Routes)
	// A clock reading is a measurement, and its milliseconds drift between two
	// runs of a correct clock. Compared at whole-second resolution: that keeps
	// the sign and the magnitude the diagnosis reasons about, and drops the
	// jitter that is not a change in anything.
	d.field(SectionCheck, id, path+"clock_offset_ms", id+" clock offset",
		clockOffset(before.ClockOffsetMs), clockOffset(after.ClockOffsetMs))
	d.field(SectionCheck, id, path+"timeout", id+" failed by timing out",
		yesNo(before.Timeout), yesNo(after.Timeout))
}

func recordedWord(recorded bool) string {
	if recorded {
		return "recorded"
	}
	return "not recorded"
}

func familiesOf(o snapshot.Observed) snapshot.Families {
	if o.Families == nil {
		return snapshot.Families{}
	}
	return *o.Families
}

func portalWord(p *snapshot.Portal) string {
	if p == nil {
		return ""
	}
	return "intercepted"
}

func portalURL(p *snapshot.Portal) string {
	if p == nil {
		return ""
	}
	return p.RedirectURL
}

func clockOffset(ms *int64) string {
	if ms == nil {
		return ""
	}
	return (time.Duration(*ms) * time.Millisecond).Round(time.Second).String()
}

// diffSet compares two unordered collections of values and reports what joined
// and what left, one change per value. Membership is decided by key, so a
// value spelled two ways is one member. What the change then carries is the
// spelling the artifact recorded, in the path as well as in the value, so the
// report names what is in the file rather than a normalized form of it.
// Sorted so the report is the same whichever order the artifacts happened to
// list them in.
func diffSet(d *diff, id, path, label string, key func(string) string, before, after []string) {
	inBefore, inAfter := recordedByIdentity(before, key), recordedByIdentity(after, key)
	union := make([]string, 0, len(inBefore)+len(inAfter))
	for v := range inBefore {
		union = append(union, v)
	}
	for v := range inAfter {
		if _, seen := inBefore[v]; !seen {
			union = append(union, v)
		}
	}
	slices.Sort(union)
	for _, v := range union {
		recorded, inB := inBefore[v]
		afterSpelling, inA := inAfter[v]
		if inB == inA {
			continue
		}
		if inA {
			recorded = afterSpelling
		}
		// The member is on one side only, so there is one recorded spelling
		// of it, and that is what the change carries.
		d.member(SectionCheck, id, path+"."+recorded, label, recorded, inA)
	}
}

// recordedByIdentity indexes a collection by what each value names, keeping
// the spelling the artifact used. The first spelling wins where one member was
// listed twice, which is the same rule every other identity map here follows.
func recordedByIdentity(values []string, key func(string) string) map[string]string {
	out := make(map[string]string, len(values))
	for _, v := range values {
		k := key(v)
		if _, seen := out[k]; !seen {
			out[k] = v
		}
	}
	return out
}

// diffAttempts compares connection attempts by the address they were made to.
// The address is the identity: the order the attempts were made in follows the
// resolver's answer order, which is already treated as unordered, and the time
// each one took is a measurement. What is left, and what matters, is which
// addresses were tried and what each one said.
//
// The address is read as an address, so two spellings of one of them are one
// attempt identity. How many attempts went to that identity is untouched by
// that: they are grouped, not merged, so a canceled attempt and the retry that
// verified it stay two recorded outcomes under one address.
func diffAttempts(d *diff, id, path string, before, after []snapshot.Attempt) {
	beforeByIP := attemptsByIP(before)
	afterByIP := attemptsByIP(after)
	for _, ip := range mergedOrder(attemptIPs(before), attemptIPs(after)) {
		b, inBefore := beforeByIP[ip]
		a, inAfter := afterByIP[ip]
		if inBefore != inAfter {
			recorded := b
			if inAfter {
				recorded = a
			}
			d.member(SectionCheck, id, path+"attempts."+recorded[0].IP, id+" connection attempt to", recorded[0].IP, inAfter)
			continue
		}
		// Both sides recorded this address, possibly spelled two ways. The
		// before artifact's spelling names it, which is the spelling the
		// comparison has always reported for a value present on both sides.
		spelling := b[0].IP
		attemptPath := path + "attempts." + spelling
		if len(b) == 1 && len(a) == 1 {
			d.field(SectionCheck, id, attemptPath+".error", id+" connection attempt to "+spelling, b[0].Error, a[0].Error)
			d.field(SectionCheck, id, attemptPath+".cause", id+" connection cause for "+spelling, b[0].Cause, a[0].Cause)
			d.field(SectionCheck, id, attemptPath+".aborted", id+" connection aborted for "+spelling, strconv.FormatBool(b[0].Aborted), strconv.FormatBool(a[0].Aborted))
		} else {
			d.field(SectionCheck, id, attemptPath+".outcomes", id+" connection outcomes for "+spelling, attemptOutcomes(b), attemptOutcomes(a))
		}
	}
}

func attemptIPs(attempts []snapshot.Attempt) []string {
	ips := make([]string, len(attempts))
	for i, a := range attempts {
		ips[i] = addressKey(a.IP)
	}
	return ips
}

func attemptsByIP(attempts []snapshot.Attempt) map[string][]snapshot.Attempt {
	byIP := make(map[string][]snapshot.Attempt, len(attempts))
	for _, a := range attempts {
		key := addressKey(a.IP)
		byIP[key] = append(byIP[key], a)
	}
	return byIP
}

func attemptOutcomes(attempts []snapshot.Attempt) string {
	out := make([]string, 0, len(attempts))
	for _, a := range attempts {
		out = append(out, "error="+strconv.Quote(a.Error)+", cause="+strconv.Quote(a.Cause)+", aborted="+strconv.FormatBool(a.Aborted))
	}
	slices.Sort(out)
	return strings.Join(slices.Compact(out), "; ")
}

// The route intelligence half of the comparison.
//
// Two things are compared, and they answer different questions. Per
// destination, below, is what the operating system decided for one address:
// which prefix matched, which interface it chose, what the next hop was. That
// is exact, and it is keyed by the address, so a destination present on one
// side only is reported as such rather than as a changed path.
//
// The paths section above it is the derived reading: which interface each kind
// of traffic left by, and whether two kinds left by the same one. It exists
// because the exact comparison cannot answer "the target moved onto the VPN"
// when the resolver handed back a different address between the two runs, and
// that question is the one a person asks first. Nothing stores it; it is
// computed from the same routes both times, so the two cannot disagree.

// diffRoutes compares the route decisions on one check row, keyed by the
// destination they were made for. The destination is the identity, because a
// route decision is per address by construction, and it is read as an address
// so that one destination spelled two ways is one decision. The next hop and
// the local source are addresses too and read the same way; the matched prefix
// is a CIDR entry and reads by its own rule.
func diffRoutes(d *diff, id, path string, before, after []snapshot.Route) {
	beforeByDst := routesByDestination(before)
	afterByDst := routesByDestination(after)
	for _, dst := range mergedOrder(routeDestinations(before), routeDestinations(after)) {
		b, inBefore := beforeByDst[dst]
		a, inAfter := afterByDst[dst]
		if inBefore != inAfter {
			recorded := b.Destination
			if inAfter {
				recorded = a.Destination
			}
			d.member(SectionCheck, id, path+"routes."+recorded, id+" route to", recorded, inAfter)
			continue
		}
		// Both sides recorded a decision for this destination. The before
		// artifact's spelling names it, as it did before identity became
		// semantic, so an artifact netdoc already accepted keeps its paths.
		dstSpelling := b.Destination
		routePath := path + "routes." + dstSpelling + "."
		label := id + " route to " + dstSpelling + " "
		d.field(SectionCheck, id, routePath+"unreachable", label+"has no route", yesNo(b.Unreachable), yesNo(a.Unreachable))
		d.identityField(prefixKey, SectionCheck, id, routePath+"prefix", label+"matched prefix", b.Prefix, a.Prefix)
		d.field(SectionCheck, id, routePath+"interface", label+"interface", b.Interface, a.Interface)
		d.identityField(addressKey, SectionCheck, id, routePath+"gateway", label+"next hop", b.Gateway, a.Gateway)
		d.identityField(addressKey, SectionCheck, id, routePath+"source", label+"source address", b.Source, a.Source)
		// Metric is absent on a platform that reports none, and 0 is a real
		// metric, so the two are spelled differently rather than both as "0".
		d.field(SectionCheck, id, routePath+"metric", label+"metric", metricWord(b.Metric), metricWord(a.Metric))
		// The routing domain, and separately whether the platform named one at
		// all. Both matter: a run that stops reporting a table has lost the
		// knowledge, which is not the same as having moved to the main one.
		d.field(SectionCheck, id, routePath+"table", label+"routing table", b.Table, a.Table)
		d.field(SectionCheck, id, routePath+"table_known", label+"named routing table", yesNo(b.TableKnown), yesNo(a.TableKnown))
		d.field(SectionCheck, id, routePath+"tunnel", label+"tunnel state", b.Tunnel, a.Tunnel)
		d.field(SectionCheck, id, routePath+"tunnel_kind", label+"tunnel kind", b.TunnelKind, a.TunnelKind)
		d.field(SectionCheck, id, routePath+"reason", label+"selection reason", b.Reason, a.Reason)
		// The link's own MTU. A change here is a reconfigured or swapped link,
		// and it is not a measured path MTU on either side.
		d.field(SectionCheck, id, routePath+"interface_mtu", label+"interface MTU", mtuWord(b.InterfaceMTU), mtuWord(a.InterfaceMTU))
		d.field(SectionCheck, id, routePath+"competing", label+"competing routes", competingWord(b.Competing), competingWord(a.Competing))
	}
}

func routeDestinations(routes []snapshot.Route) []string {
	out := make([]string, len(routes))
	for i, r := range routes {
		out[i] = addressKey(r.Destination)
	}
	return out
}

func routesByDestination(routes []snapshot.Route) map[string]snapshot.Route {
	byDst := make(map[string]snapshot.Route, len(routes))
	for _, r := range routes {
		key := addressKey(r.Destination)
		if _, seen := byDst[key]; !seen {
			byDst[key] = r
		}
	}
	return byDst
}

func metricWord(metric *int) string {
	if metric == nil {
		return ""
	}
	return strconv.Itoa(*metric)
}

func mtuWord(mtu int) string {
	if mtu <= 0 {
		return ""
	}
	return strconv.Itoa(mtu)
}

func competingWord(routes []snapshot.CompetingRoute) string {
	items := make([]string, len(routes))
	for i, r := range routes {
		items[i] = r.Interface + "@" + strconv.Itoa(r.Metric)
	}
	return strings.Join(items, ",")
}

// diffPaths reports how traffic left the machine, in the terms a person asks
// about: which interface the target's traffic took, whether it was tunnelled,
// and whether traffic to every recorded resolver target went the same way.
//
// It is derived on both sides from the routes the checks already recorded, so
// two snapshots written by different netdoc versions are read the same way.
// Every value is empty when the snapshot recorded no route to derive it from,
// which is what an older .ndoc and a platform netdoc cannot ask both produce,
// and an empty value on both sides is not a difference.
func diffPaths(d *diff, before, after snapshot.Snapshot) {
	b, a := pathsOf(before), pathsOf(after)
	d.field(SectionPaths, "", "paths.target.interface", "target interface", b.targetIface, a.targetIface)
	// The prefix a route decision recorded, or the words that stand in for one
	// where there is no route. Read by the CIDR rule, which leaves those words
	// comparing as themselves because they are not CIDR.
	d.identityField(prefixKey, SectionPaths, "", "paths.target.prefix", "target matched route", b.targetPrefix, a.targetPrefix)
	// How that route was selected, which is the field that still answers on a
	// platform naming no matched entry. There it is a comparison with the
	// general path rather than a statement about prefixes, and the vocabulary
	// keeps those apart, so this is labelled for what it is on both.
	d.field(SectionPaths, "", "paths.target.reason", "target route selection", b.targetReason, a.targetReason)
	d.field(SectionPaths, "", "paths.target.tunnel", "target tunnel state", b.targetTunnel, a.targetTunnel)
	d.field(SectionPaths, "", "paths.reference.interface", "general Internet interface", b.referenceIface, a.referenceIface)
	d.field(SectionPaths, "", "paths.resolver.interface", "resolver target interface", b.resolverIface, a.resolverIface)
	d.field(SectionPaths, "", "paths.resolver.agreement", "DNS and application traffic",
		b.resolverAgreement, a.resolverAgreement)
}

// runPaths is the derived reading of one snapshot's route decisions.
type runPaths struct {
	targetIface       string
	targetPrefix      string
	targetReason      string
	targetTunnel      string
	referenceIface    string
	resolverIface     string
	resolverAgreement string
}

// The words the derived resolver comparison uses. They are display words for
// a normalized state, and a split is deliberately not called a fault: split
// DNS is a design as often as it is a problem.
const (
	pathsSame      = "same path"
	pathsDifferent = "different paths"
)

func pathsOf(s snapshot.Snapshot) runPaths {
	checks := checksByID(s.Checks)
	target := selectedRoute(checks["target_tcp"])
	reference := firstRoute(checks["iface"])
	var resolvers []snapshot.Route
	if observed := checks["dns"].Observed; observed != nil {
		resolvers = observed.Routes
	}
	out := runPaths{
		targetIface:    target.Interface,
		targetPrefix:   target.Prefix,
		targetReason:   target.Reason,
		targetTunnel:   target.Tunnel,
		referenceIface: reference.Interface,
		resolverIface:  resolverInterfaces(resolvers),
	}
	if target.Unreachable {
		out.targetPrefix = "no route"
	}
	allKnown := len(resolvers) > 0 && target.Interface != ""
	for _, resolver := range resolvers {
		if resolver.Interface == "" {
			allKnown = false
			continue
		}
		if routesDiffer(resolver, target) {
			out.resolverAgreement = pathsDifferent
			return out
		}
	}
	if allKnown {
		out.resolverAgreement = pathsSame
	}
	return out
}

func resolverInterfaces(routes []snapshot.Route) string {
	seen := make(map[string]bool, len(routes))
	for _, route := range routes {
		if route.Interface != "" {
			seen[route.Interface] = true
		}
	}
	interfaces := make([]string, 0, len(seen))
	for iface := range seen {
		interfaces = append(interfaces, iface)
	}
	slices.Sort(interfaces)
	return strings.Join(interfaces, ",")
}

// routesDiffer reports that two recorded decisions took materially different
// paths: out of another interface, to another router, or through another
// routing domain. It is the same question internal/diagnostic asks of the live
// decisions, asked here of what an artifact stored, and it is more than an
// interface comparison for the same reason: two flows can share a link and
// still be routed apart.
//
// A routing table is compared only where both artifacts named one, and the
// tables an operating system consults on its own all read as the ordinary
// case. An absent table is unknown and never the main one, so silence on
// either side settles nothing.
func routesDiffer(a, b snapshot.Route) bool {
	domainA, knownA := a.RoutingDomain()
	domainB, knownB := b.RoutingDomain()
	return a.Interface != b.Interface || addressKey(a.Gateway) != addressKey(b.Gateway) ||
		knownA && knownB && domainA != domainB
}

// selectedRoute is the decision for the address the check actually used, which
// is the one the connection took. It falls back to the first recorded route,
// because a run where every address failed still chose a path.
func selectedRoute(check snapshot.Check) snapshot.Route {
	if check.Observed == nil {
		return snapshot.Route{}
	}
	// Matched as an address rather than as text, for the same reason the route
	// decisions themselves are keyed that way: the destination and the
	// selected address are two recordings that have to agree about one address
	// whatever spelling each of them carries.
	for _, r := range check.Observed.Routes {
		if r.Destination != "" && addressKey(r.Destination) == addressKey(check.Observed.SelectedIP) {
			return r
		}
	}
	return firstRoute(check)
}

func firstRoute(check snapshot.Check) snapshot.Route {
	if check.Observed == nil || len(check.Observed.Routes) == 0 {
		return snapshot.Route{}
	}
	return check.Observed.Routes[0]
}
