// Package snapshot defines the .ndoc diagnostic snapshot: Network Doctor's
// portable record of one finished run, and the only place its on-disk shape is
// written down.
//
// A snapshot is an external artifact, not a dump of runtime state. This package
// deliberately imports nothing from internal/diagnostic, so the file format
// cannot drift with a probe struct: a reader built years from now decodes an
// .ndoc with this package alone, no probes, no TUI, no network. The conversion
// from live results runs the other way, in internal/diagnostic, which is the
// only package that can see its own evidence.
//
// Every field is explicitly tagged and every type is a struct or a slice: no
// maps, so the encoder's output order is the declaration order here and two
// runs of the same data produce the same bytes.
package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Schema is the identity of the format this package reads and writes. It is
// the first thing in the file and the first thing Decode checks.
//
// The version is a whole number and it moves for one reason: a change a v1
// reader would misread. Adding an optional field is not that, which is why
// Decode never rejects unknown keys, and why every optional field is omitempty
// with an absent-means-unknown reading. Renaming a field, changing what one
// means, or changing a unit is that, and takes netdoc.snapshot.v2.
const Schema = "netdoc.snapshot.v1"

// ProfileSchema identifies an .ndoc artifact that contains several ordinary
// snapshots plus their service-profile interpretation. It is separate from
// Schema so a single-run reader never mistakes a multi-run artifact for one
// diagnosis.
const ProfileSchema = "netdoc.profile.v1"

// Extension is the conventional file suffix. Nothing here enforces it: the
// schema string in the file is the identity, not the name it was saved under.
const Extension = ".ndoc"

// MaxArtifactBytes bounds an ordinary offline .ndoc read. The format has no
// declared maximum row or dependency count, so this is deliberately generous
// rather than derived from a field-level limit: it exists to stop a corrupt
// or deliberately oversized file from being fully read into memory before
// validation, not to constrain any legitimate snapshot. Set above
// remote.MaxResponseBytes (8 MiB) since one snapshot can bundle more data
// than a single remote response.
const MaxArtifactBytes = 16 << 20 // 16 MiB

// The outcomes a check row can carry. They are written down here rather than
// borrowed from the runtime status type, because the vocabulary of the file is
// part of the file format: a reader decides what a row means by comparing
// against these, and never by trusting a Go zero value.
//
// StatusIncomplete is the one no probe can return. It marks a row that never
// produced a result at all, which happens when a run is cancelled or
// interrupted before that check reports. It exists because the alternative is
// worse: leaving the field empty would make the absence of evidence indistinct
// from a row whose outcome simply was not written down, and a snapshot is
// evidence. An incomplete row is not a skipped row either; nothing decided to
// leave it out, the run just ended first.
const (
	StatusPass       = "PASS"
	StatusWarn       = "WARN"
	StatusFail       = "FAIL"
	StatusSkip       = "SKIP"
	StatusNA         = "N/A"
	StatusIncomplete = "INCOMPLETE"
)

// Causal-evidence vocabulary is part of the v1 file contract. These mirror
// the diagnostic model without importing it, preserving the package boundary
// that lets snapshots be decoded without the live probe engine.
const (
	EvidenceSupport       = "support"
	EvidenceContradiction = "contradiction"
	EvidenceRuledOut      = "ruled_out"
	EvidenceNotEvaluated  = "not_evaluated"

	ObservationStatusPass       = "status_pass"
	ObservationStatusWarn       = "status_warn"
	ObservationStatusFail       = "status_fail"
	ObservationStatusSkip       = "status_skip"
	ObservationStatusNA         = "status_not_applicable"
	ObservationCause            = "cause"
	ObservationDNSAnswers       = "dns_answers"
	ObservationDNSNotFound      = "dns_not_found"
	ObservationCaptivePortal    = "captive_portal"
	ObservationTimeout          = "timeout"
	ObservationClockOffset      = "clock_offset"
	ObservationStatusDowngraded = "status_downgraded"
	ObservationFamilyReachable  = "family_reachable"
	ObservationFamilyFailed     = "family_failed"
	ObservationAddressSucceeded = "address_succeeded"
	ObservationAddressFailed    = "address_failed"
	// Route observations. Each is a fact about the path the row that carries
	// it takes, so it stays verifiable against that row alone.
	ObservationRouteTunneled       = "route_tunneled"
	ObservationRouteDirect         = "route_direct"
	ObservationRouteUnreachable    = "route_unreachable"
	ObservationRoutePathDiffers    = "route_path_differs"
	ObservationRouteNextHopDiffers = "route_next_hop_differs"
	ObservationRouteTableDiffers   = "route_table_differs"
	ObservationRouteFamilySplit    = "route_family_split"
	ObservationRouteInterfaceMTU   = "route_interface_mtu"

	NotEvaluatedPrerequisite  = "prerequisite_failed"
	NotEvaluatedNotSelected   = "not_selected"
	NotEvaluatedNotApplicable = "not_applicable"
	NotEvaluatedIncomplete    = "incomplete"
)

// The diagnosis-confidence vocabulary, part of the v1 file contract for the
// same reason the causal-evidence words are: a reader decides what a finding
// claims by comparing against these, never by trusting a Go zero value. None of
// them is a probability, and the set is closed, so a value outside it is a file
// this build cannot read rather than one to guess at.
const (
	ConfidenceHigh                 = "high"
	ConfidenceMedium               = "medium"
	ConfidenceLow                  = "low"
	ConfidenceInsufficientEvidence = "insufficient_evidence"
)

// UnsupportedSchemaError is what Decode returns for a file whose schema is not
// this one, including a future version. It carries the schema it found so a
// caller can say what it was handed rather than "not a snapshot".
type UnsupportedSchemaError struct{ Found string }

func (e UnsupportedSchemaError) Error() string {
	if e.Found == "" {
		return "not a Network Doctor snapshot (no schema field, want " + Schema + ")"
	}
	return fmt.Sprintf("unsupported snapshot schema %q, this build reads %s", e.Found, Schema)
}

// Snapshot is one finished diagnostic run, whole enough to reopen, compare, or
// attach to a report without rerunning a probe.
type Snapshot struct {
	Schema string `json:"schema"`
	// CreatedAt is RFC 3339 in UTC. It is when the snapshot was written, which
	// is the end of the run, not the start of it.
	CreatedAt string `json:"created_at"`
	Tool      Tool   `json:"tool"`
	// Target is null for a generic run, the same absence --json publishes.
	Target    *Target   `json:"target"`
	Options   Options   `json:"options"`
	Checks    []Check   `json:"checks"`
	Diagnosis Diagnosis `json:"diagnosis"`
	// OK means no check failed, the same rule as the JSON report and the exit
	// code. Warn, Skip, and N/A do not count against it.
	OK bool `json:"ok"`
	// Redaction is present only when this artifact was intentionally prepared
	// for sharing. Its absence means the snapshot is full fidelity.
	Redaction *Redaction `json:"redaction,omitempty"`
	// Incident is present when this run is the first failing pass of a watch
	// incident, and it carries the runs around that failure. Absent on every
	// ordinary snapshot, which is what a one-shot --save writes.
	Incident *Incident `json:"incident,omitempty"`
}

// ProfileSnapshot is one finished service-profile run. Each component is a
// complete ordinary snapshot, so existing diagnostic evidence keeps its
// original schema and meaning.
type ProfileSnapshot struct {
	Schema     string             `json:"schema"`
	CreatedAt  string             `json:"created_at"`
	Tool       Tool               `json:"tool"`
	Profile    ProfileIdentity    `json:"profile"`
	Components []ProfileComponent `json:"components"`
	Aggregate  ProfileAggregate   `json:"aggregate"`
	OK         bool               `json:"ok"`
	Redaction  *Redaction         `json:"redaction,omitempty"`
}

type ProfileIdentity struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Title   string `json:"title"`
}

type ProfileComponent struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Focus    string   `json:"focus"`
	Status   string   `json:"status"`
	Fallback string   `json:"fallback_for,omitempty"`
	Snapshot Snapshot `json:"snapshot"`
}

type ProfileAggregate struct {
	Status  string          `json:"status"`
	Summary string          `json:"summary"`
	Finding *ProfileFinding `json:"finding,omitempty"`
}

type ProfileFinding struct {
	ID                 string   `json:"id"`
	AffectedComponents []string `json:"affected_components,omitempty"`
	WorkingComponents  []string `json:"working_components,omitempty"`
}

// Redaction identifies the privacy policy applied before serialization.
// Sanitized is explicit so readers never infer privacy from placeholder-like
// values, and Policy lets a reader name the exact guarantees in effect.
type Redaction struct {
	Sanitized bool   `json:"sanitized"`
	Policy    string `json:"policy"`
}

// SupportRedactionPolicy is the redaction contract used by support artifacts.
const SupportRedactionPolicy = "support-v1"

// Incident is one failure a watch session observed, recorded around the run
// that carries it: the snapshot this hangs off is the incident's onset, the
// first pass that failed.
//
// The runs are stored and the differences between them are not. Everything a
// reader wants to say about what changed is a comparison of two of these
// records, computed the same way netdoc computes any other comparison, so a
// stored answer cannot fall out of step with the states it describes. That is
// the same reason remediation text is not stored beside a finding.
//
// Each nested record is itself a complete, valid snapshot, schema included: a
// reader may lift one out and hand it to anything that reads an .ndoc.
type Incident struct {
	// StartedAt is when the onset run was observed, RFC 3339 in UTC, and the
	// same instant as this snapshot's created_at.
	StartedAt string `json:"started_at"`
	// EndedAt is when the first non-failing run after it was observed. Absent
	// means the incident was still open when the file was written, which is
	// not the same as an incident that never recovered.
	EndedAt string `json:"ended_at,omitempty"`
	// Passes is how many watch passes saw this incident still failing,
	// counting the onset. It is a count of observations, never of seconds.
	Passes int `json:"passes"`
	// Before is the last run that was not failing before the onset. Absent
	// when the watch session began during the failure, in which case there is
	// no earlier state and nothing may be inferred about one.
	Before *Snapshot `json:"before,omitempty"`
	// During is the most recent failing run, recorded only when it differed
	// from the onset. Absent means the failing state never moved.
	During *Snapshot `json:"during,omitempty"`
	// Recovered is the first run after the incident that was not failing.
	// Absent alongside an absent ended_at, and never present without one.
	Recovered *Snapshot `json:"recovered,omitempty"`
}

// Tool is the build that produced the snapshot. GOOS and GOARCH are here
// because a diagnosis reads differently per platform, and because the
// remediation advice for a finding is chosen by OS: a later reader can
// reproduce the advice this run showed without guessing which machine ran it.
type Tool struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Target keeps the spelling the user typed next to what netdoc made of it, so
// a comparison can tell "the same host, entered differently" from "a different
// host". No credentials can reach Raw: the parser rejects userinfo outright.
type Target struct {
	Raw  string `json:"raw"`
	Host string `json:"host"`
	// IP is set only when the target was an IP literal, in which case the run
	// had no name to resolve.
	IP           string `json:"ip,omitempty"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	PortExplicit bool   `json:"port_explicit"`
}

// Options are the run settings that change what the probes did, and therefore
// what two snapshots can fairly be compared on. Flags that only affect
// presentation are not here: they change nothing a comparison would read.
type Options struct {
	ProbeTimeoutMs int64 `json:"probe_timeout_ms"`
	// PublicDNS is the second-opinion resolver, empty when that row was
	// switched off. It is an address or empty in every version of this schema,
	// so the automatic default records itself in PublicDNSAuto instead of
	// spending a word here: changing what this field can hold would change the
	// meaning of a v1 field, and that is a new schema, not a new flag.
	PublicDNS string `json:"public_dns"`
	// PublicDNSAuto says PublicDNS is the default rather than a resolver the
	// run named, which is what let the probe try the other address family when
	// that one could not be reached. Additive and absent when false, so a
	// reader that has never heard of it still sees the resolver the run
	// started from and reads the rest of the file unchanged.
	PublicDNSAuto bool `json:"public_dns_auto,omitempty"`
	// Check and Skip are the probe selection as given, absent when the run
	// took the whole graph.
	Check []string `json:"check,omitempty"`
	Skip  []string `json:"skip,omitempty"`
	// Source is the --iface binding in effect, absent when probes used the
	// system's own routing choice.
	Source *Source `json:"source,omitempty"`
}

// Source is the local binding probes were given, as netdoc resolved it. Either
// family may be absent, which means the selected interface had no address for
// it. Interface is the name that was named, empty when an exact local IP was
// given instead: what was asked for and what was used are different questions,
// and the second one is answered per check under Observed.
type Source struct {
	Interface string `json:"interface,omitempty"`
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
}

// Check is one probe row: its outcome, what it saw, and what was done to that
// outcome afterwards.
//
// Every check the run built appears here, including the ones that were skipped,
// did not apply, or never reported, because a comparison needs to know a row
// existed and was not reached. Status says which of those a row is, on its own:
// four states, four values, no cross-referencing.
//
// Ran is a second, narrower question, and only that: did the probe body
// execute. It separates a check that finished in under a millisecond from one
// that did not run, since DurationMs cannot, both being 0. It is not how a
// reader tells an incomplete row from a passing one; Status is.
type Check struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Deps are the probe IDs this row waited on, so a reader can rebuild the
	// dependency graph the run actually executed without a live probe list.
	Deps []string `json:"deps,omitempty"`
	// Status is one of the status constants above, never empty. A row with no
	// completed result reads StatusIncomplete, which is never a pass: no
	// consumer has to know that PASS happens to be a Go zero value, because a
	// snapshot in which it could mean "unknown" cannot be written. Encode
	// refuses one.
	Status string `json:"status"`
	// Cause is the stable machine-readable reason, empty when the outcome
	// needs none. Branch on this, never on Detail.
	Cause string `json:"cause,omitempty"`
	// CauseFamily identifies the address family that supplied Cause. It is
	// absent when the cause is shared, family-neutral, or unknown.
	CauseFamily string `json:"cause_family,omitempty"`
	Ran         bool   `json:"ran"`
	DurationMs  int64  `json:"duration_ms"`
	// Detail and Fix are derived human sentences. They are kept because a
	// snapshot is also read by a person, and never parsed back.
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
	// Observed is what this probe measured. Absent when it measured nothing
	// beyond its status, which is the case for every row that never ran.
	Observed *Observed `json:"observed,omitempty"`
	// Derived is what the cross-probe reasoning pass concluded about this row
	// after the probes finished. Absent when it reached no conclusion about it.
	// Its presence means reasoning added something the probe did not report,
	// which is not the same as the status above having been rewritten.
	Derived *Derived `json:"derived,omitempty"`
}

// Observed is evidence a probe measured directly. Everything here is a
// reading; nothing here is a conclusion.
type Observed struct {
	// Addresses are every record the resolver returned, SelectedIP the one
	// this probe actually used.
	Addresses  []string `json:"addresses,omitempty"`
	SelectedIP string   `json:"selected_ip,omitempty"`
	// DNSNotFound distinguishes "the resolver answered, with nothing" from
	// "the resolver did not answer", which have different fixes.
	DNSNotFound bool `json:"dns_not_found,omitempty"`
	// Resolver is the configured second-opinion DNS server this row queried.
	// It remains for compatibility; ResolverTargets is the direct Dial evidence
	// available to both system and second-opinion lookups.
	Resolver string `json:"resolver,omitempty"`
	// ResolverTargets are DNS service addresses recorded as tried. They do not
	// identify which target answered or supplied an address.
	ResolverTargets []string `json:"resolver_targets,omitempty"`
	// SourceIP and Interface are the local end of the connection this probe
	// made, as the kernel chose it.
	SourceIP  string `json:"source_ip,omitempty"`
	Interface string `json:"interface,omitempty"`
	// SSID is the connected Wi-Fi network name, absent when wired or unknown.
	// It is retained because it is often the thing that changed between two
	// snapshots, and it is the field a future redaction pass will want first.
	SSID string `json:"ssid,omitempty"`
	// Families is independently tested reachability per address family. An
	// absent family was never dialed.
	Families *Families `json:"address_families,omitempty"`
	Portal   *Portal   `json:"portal,omitempty"`
	Attempts []Attempt `json:"attempts,omitempty"`
	// ClockOffsetMs is this machine's clock minus the one the captive-portal
	// endpoint reported, positive when the local clock runs fast. Absent when
	// there was no usable reading. It is here because it is the only evidence
	// that separates a real certificate problem from a wrong local clock, and
	// it is gone the moment the process exits.
	ClockOffsetMs *int64 `json:"clock_offset_ms,omitempty"`
	// Timeout marks a failure that was a timeout rather than a refusal or a
	// reset, for the rows that do not already say so through Cause.
	Timeout bool `json:"timeout,omitempty"`
	// InterfaceAmbiguous means the source address resolved to more than one
	// interface, so Interface above is display text and not a name.
	InterfaceAmbiguous bool `json:"interface_ambiguous,omitempty"`
	// Routes are the operating system's own route decisions for the
	// destinations this row is about, one per destination address. Absent on a
	// row with no destination to look up and on a platform netdoc cannot ask,
	// and an absent list never means "there is no route": that is what a
	// present entry with unreachable set says.
	//
	// This is diagnostic information, not a routing table. Only destinations
	// the run already cared about are here, and each entry is the decision the
	// kernel reported for one of them.
	Routes []Route `json:"routes,omitempty"`
	// ConnectCleartext is true when the row reached its result over a plaintext
	// HTTP CONNECT: the destination hostname was sent to the proxy without TLS on
	// the client-to-proxy hop. It is recorded only for a tunnel that succeeded.
	// Absent means the observation was not recorded, never that a TLS hop to the
	// proxy was confirmed and never that no cleartext hostname was sent.
	ConnectCleartext bool `json:"connect_cleartext,omitempty"`
}

// Route is one destination's selected path, as the operating system reported
// its own decision at the time of the run.
//
// Every optional field is absent when the platform did not supply it, which a
// reader must take as "not known on that machine" and never as zero. Metric is
// a pointer for exactly that reason: 0 is a real route metric on Linux and on
// Windows, so absence cannot be spelled as 0.
type Route struct {
	Destination string `json:"destination"`
	// Family is "ipv4" or "ipv6", the same vocabulary the per-family
	// reachability fields use.
	Family    string `json:"family,omitempty"`
	Interface string `json:"interface,omitempty"`
	// Gateway is the next hop, absent when the destination is on-link.
	Gateway string `json:"gateway,omitempty"`
	// Source is the local address the kernel would send from.
	Source string `json:"source,omitempty"`
	// Prefix is the route entry the kernel said it matched, in CIDR form.
	Prefix string `json:"prefix,omitempty"`
	Metric *int   `json:"metric,omitempty"`
	// Table names the routing table or routing domain the decision came from,
	// and is meaningful only with TableKnown. The main table is written as an
	// absent value, since a decision from it is the unremarkable case.
	Table string `json:"table,omitempty"`
	// TableKnown is the platform having said which routing table or routing
	// domain resolved this destination, and is what keeps a known main table
	// apart from a platform that never said. Both leave table absent, and a
	// reader that took absence for the main table would report a routing
	// domain macOS and Windows do not expose. An artifact written before this
	// field existed has no table knowledge at all, which is unknown and never
	// the main table.
	TableKnown bool `json:"table_known,omitempty"`
	// InterfaceMTU is the selected link's own MTU. It is never a measured path
	// MTU: the path_mtu check is the only thing that measures one, and reading
	// this as an end-to-end number is the mistake the name exists to prevent.
	InterfaceMTU int `json:"interface_mtu,omitempty"`
	// Tunnel is "tunnel", "likely", or "direct", and absent when nothing
	// classified the interface. Absent is not "direct".
	Tunnel string `json:"tunnel,omitempty"`
	// TunnelKind is the operating system's own name for the device kind, set
	// only alongside a "tunnel" state.
	TunnelKind string `json:"tunnel_kind,omitempty"`
	// Unreachable is the kernel answering that no route exists.
	Unreachable bool `json:"unreachable,omitempty"`
	// Reason is why this route won, from the documented vocabulary.
	Reason string `json:"reason,omitempty"`
	// Competing are routes that covered the same destination and lost,
	// recorded only where seeing one explains the decision.
	Competing []CompetingRoute `json:"competing,omitempty"`
}

// CompetingRoute is one route that lost. Metric is not a pointer here because
// a competitor is only ever recorded on a platform that ranks routes by one.
type CompetingRoute struct {
	Interface string `json:"interface,omitempty"`
	Metric    int    `json:"metric"`
}

// Families is per-address-family reachability, using the same
// reachable/unreachable vocabulary as the JSON report.
type Families struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

// Portal is captive-portal evidence. Present means egress was intercepted
// rather than dead; RedirectURL is empty when the interception advertised no
// usable sign-in URL.
type Portal struct {
	RedirectURL string `json:"redirect_url,omitempty"`
}

// Attempt is one connection attempt against a single address.
type Attempt struct {
	IP         string `json:"ip"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	Cause      string `json:"cause,omitempty"`
	Aborted    bool   `json:"aborted,omitempty"`
}

// Derived is what the cross-probe reasoning pass concluded about this row: a
// structured conclusion, never a reading. It is the difference between "the
// probe reported this" and "netdoc concluded this", which a comparison that
// ignored it would read as the same state. Some of these conclusions rewrote
// the row's status and some left it alone, so its presence says reasoning
// reached a conclusion here, not that the status above was changed.
type Derived struct {
	// StatusDowngraded means an observed failure was relaxed because another
	// path proved the network still carries traffic.
	StatusDowngraded bool `json:"status_downgraded,omitempty"`
	// AnswerComparison is what the cross-probe pass concluded when it compared
	// this row's DNS answers against the system resolver's. Absent means no
	// comparison outcome was recorded: what every artifact written before this
	// field says, and what a run with nothing to compare says. It never means
	// the answers agreed. Both outcomes are recorded because the comparison is
	// made from the addresses the resolvers actually returned, and a sanitized
	// artifact no longer holds those.
	AnswerComparison AnswerComparison `json:"answer_comparison,omitempty"`
}

// AnswerComparison is the closed vocabulary for a recorded DNS answer-set
// comparison. The zero value means no comparison was recorded, which is a
// third state and never agreement.
type AnswerComparison string

const (
	AnswerComparisonAgree    AnswerComparison = "agree"
	AnswerComparisonDisagree AnswerComparison = "disagree"
)

// validAnswerComparison accepts the closed vocabulary and the empty value a
// producer that compared nothing wrote, and refuses anything else in both
// directions, exactly like validConfidence.
func validAnswerComparison(value AnswerComparison) bool {
	switch value {
	case "", AnswerComparisonAgree, AnswerComparisonDisagree:
		return true
	}
	return false
}

// Diagnosis is the run's single interpretation: its class, its sentence, and
// the specific conclusions it supports. It is stated once, so nothing in the
// snapshot can describe a different run than the checks above.
type Diagnosis struct {
	Verdict string `json:"verdict"`
	Summary string `json:"summary"`
	// Blamed is the row to put a cursor on, which falls back to the first
	// failed row when the diagnosis names none. Empty when nothing failed.
	Blamed string `json:"blamed,omitempty"`
	// FailedStage is the first check that failed, the one field a triage
	// script needs. Empty when none did.
	FailedStage string    `json:"failed_stage,omitempty"`
	Findings    []Finding `json:"findings,omitempty"`
}

// Finding is one conclusion the run proved, by stable ID. Remediation text is
// deliberately not stored: fix advice lives on the check rows, and the
// structured next action is regenerable from ID plus tool.os, so keeping a
// copy here would be a second catalogue to keep in step.
type Finding struct {
	ID      string `json:"id"`
	Verdict string `json:"verdict"`
	Summary string `json:"summary"`
	Focus   string `json:"focus,omitempty"`
	// Confidence is how strongly the run's observations supported this finding
	// as an explanation, in the vocabulary below. It is the producing version's
	// assessment, recorded like the rest of the interpretation; a reader that
	// wants this build's answer replays the checks. Optional, because a
	// snapshot written before the field existed recorded no such assessment,
	// and absence means exactly that rather than a weak one.
	Confidence string   `json:"confidence,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	// CausalEvidence preserves the interpretation made during the original
	// run. It is optional so pre-evidence v1 snapshots remain valid and load
	// without inventing relationships they never recorded.
	CausalEvidence []CausalEvidence `json:"causal_evidence,omitempty"`
	Counterfactual *Counterfactual  `json:"counterfactual,omitempty"`
}

// CausalEvidence is one typed relationship to an observed check fact. The
// observation value stays on the referenced Check; this records provenance
// and the interpretation selected at capture time.
type CausalEvidence struct {
	Kind        string `json:"kind"`
	Check       string `json:"check"`
	Observation string `json:"observation,omitempty"`
	Value       string `json:"value,omitempty"`
	Candidate   string `json:"candidate,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type Counterfactual struct {
	Variable     string                      `json:"variable"`
	Alternatives []CounterfactualAlternative `json:"alternatives"`
}

type CounterfactualAlternative struct {
	Value    string           `json:"value"`
	Outcome  string           `json:"outcome"`
	Evidence []CausalEvidence `json:"evidence"`
}

// Encode renders a snapshot as the bytes of an .ndoc file: indented JSON with
// a trailing newline, so it reads in a pager and diffs line by line. The same
// snapshot always produces the same bytes.
//
// It refuses a snapshot whose rows do not say what they are. An empty status
// is the zero value of a Go string and not an outcome, and a run holding a
// check that never reported is not a clean one, so neither can be published:
// the absence of evidence never leaves here looking like evidence.
func checkArtifactSize(buf []byte) ([]byte, error) {
	if len(buf) > MaxArtifactBytes {
		return nil, fmt.Errorf("snapshot exceeds maximum artifact size of %d bytes; the format has no smaller declared representation", MaxArtifactBytes)
	}
	return buf, nil
}
func Encode(s Snapshot) ([]byte, error) {
	s = stamped(s)
	if err := validate(s); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// SetEscapeHTML stays on, matching the encoder --json already uses, so the
	// two outputs escape a hostile detail string the same way.
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return checkArtifactSize(buf.Bytes())
}

// EncodeProfile renders a multi-run profile artifact without changing the
// single-run snapshot contract.
func EncodeProfile(profile ProfileSnapshot) ([]byte, error) {
	profile.Schema = ProfileSchema
	for i := range profile.Components {
		profile.Components[i].Snapshot = stamped(profile.Components[i].Snapshot)
	}
	if err := validateProfile(profile); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(profile); err != nil {
		return nil, err
	}
	return checkArtifactSize(buf.Bytes())
}

func validProfileName(name string) bool {
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, r := range name[1:] {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func validStatus(status string) bool {
	switch status {
	case StatusPass, StatusWarn, StatusFail, StatusSkip, StatusNA:
		return true
	}
	return false
}

// validCheckStatus is the ordinary check-row vocabulary, which is the profile
// component vocabulary plus INCOMPLETE. The two are deliberately separate
// functions: a component status is a profile's reading of a whole run and can
// never be INCOMPLETE, while a check row is one probe's outcome and can.
func validCheckStatus(status string) bool {
	return validStatus(status) || status == StatusIncomplete
}

// ExecutionContradicts reports whether a row's status and its ran flag
// describe an execution no run could have performed.
//
// The two fields are not independent. ran is the probe body's own measured
// duration read as a yes or no, so a row carrying a measured outcome ran, and
// a row nothing executed cannot carry one: a check skipped for a failed
// prerequisite is recorded by the scheduler without calling the probe, and an
// incomplete row was never called at all, so both read false.
//
// N/A is deliberately outside the rule. It is the one surviving status a probe
// decides from inside its own body after looking, which is why an N/A row
// normally ran, while a later netdoc that rules a row inapplicable before
// calling it would still be writing a v1 file rather than a broken one.
//
// It is exported because the scenario lab holds the same expectation over the
// artifacts it builds, and two spellings of one rule are two rules.
func ExecutionContradicts(c Check) bool {
	// The same fact read off the other field. ran is the duration asked
	// whether it is greater than zero, so a row that reports time spent ran,
	// whatever its status says. This direction only: a probe body that
	// finished faster than the unit could still round to zero in an artifact
	// an older netdoc wrote, and that file is not the contradiction.
	if !c.Ran && c.DurationMs != 0 {
		return true
	}
	switch c.Status {
	case StatusPass, StatusWarn, StatusFail:
		return !c.Ran
	case StatusSkip, StatusIncomplete:
		return c.Ran
	}
	return false
}

func validAggregateStatus(status string) bool {
	return status == StatusPass || status == StatusWarn || status == StatusFail
}

func validateProfile(profile ProfileSnapshot) error {
	if profile.Schema != ProfileSchema {
		return fmt.Errorf("profile snapshot has schema %q, want %q", profile.Schema, ProfileSchema)
	}
	if err := validateProvenance(profile.CreatedAt, profile.Tool); err != nil {
		return err
	}
	if !validProfileName(profile.Profile.Name) || profile.Profile.Version < 1 || profile.Profile.Title == "" {
		return fmt.Errorf("profile snapshot has invalid profile identity")
	}
	if len(profile.Components) == 0 {
		return fmt.Errorf("profile snapshot has no components")
	}
	if !validAggregateStatus(profile.Aggregate.Status) || profile.Aggregate.Summary == "" || profile.OK == (profile.Aggregate.Status == StatusFail) {
		return fmt.Errorf("profile snapshot has invalid aggregate result")
	}
	if profile.Redaction != nil && (!profile.Redaction.Sanitized || profile.Redaction.Policy != SupportRedactionPolicy) {
		return fmt.Errorf("profile snapshot has invalid redaction metadata")
	}
	ids := make(map[string]bool, len(profile.Components))
	outcomes := make([]ProfileComponentOutcome, len(profile.Components))
	for i, component := range profile.Components {
		if component.ID == "" || component.Label == "" || component.Focus == "" || !validStatus(component.Status) || ids[component.ID] {
			return fmt.Errorf("profile snapshot has invalid component %q", component.ID)
		}
		ids[component.ID] = true
		if component.Snapshot.Schema != Schema {
			return fmt.Errorf("profile component %q has schema %q, want %q", component.ID, component.Snapshot.Schema, Schema)
		}
		if err := validate(component.Snapshot); err != nil {
			return fmt.Errorf("profile component %q: %w", component.ID, err)
		}
		if (profile.Redaction == nil) != (component.Snapshot.Redaction == nil) ||
			profile.Redaction != nil && *profile.Redaction != *component.Snapshot.Redaction {
			return fmt.Errorf("profile component %q has different redaction metadata", component.ID)
		}
		// The component's status is the envelope's one-word reading of the run
		// nested directly beneath it. A file where the two disagree tells a
		// script one thing and its own evidence another, and there is no third
		// place to look to find out which was the run.
		want := ProfileComponentStatus(focusStatus(component), component.Snapshot.Diagnosis.Verdict, component.Snapshot.OK)
		if component.Status != want {
			return fmt.Errorf("profile component %q is %s, but its run reads as %s", component.ID, component.Status, want)
		}
		outcomes[i] = ProfileComponentOutcome{ID: component.ID, Status: component.Status, Fallback: component.Fallback}
	}
	for _, component := range profile.Components {
		if component.Fallback != "" && (!ids[component.Fallback] || component.Fallback == component.ID) {
			return fmt.Errorf("profile component %q has invalid fallback reference %q", component.ID, component.Fallback)
		}
	}
	return validateProfileAggregate(profile, AggregateProfile(outcomes))
}

// focusStatus is the status of the row the component was about, or empty when
// the nested run holds no such row. Empty is unambiguous: validate refuses a
// check with no status, so nothing else can produce it.
func focusStatus(component ProfileComponent) string {
	for _, check := range component.Snapshot.Checks {
		if check.ID == component.Focus {
			return check.Status
		}
	}
	return ""
}

// validateProfileAggregate holds the envelope's own conclusion to the one the
// components determine. Every field here is structurally derived, so there is
// nothing for a producer to decide and nothing for a reader to interpret: the
// artifact either says what its components say or it is two artifacts.
//
// The summary is the exception and is checked only for being present. It is a
// sentence built from labels this package does not have, and regenerating
// prose to compare it against would make a wording change a format break.
func validateProfileAggregate(profile ProfileSnapshot, conclusion ProfileAggregation) error {
	if profile.Aggregate.Status != conclusion.Status {
		return fmt.Errorf("profile snapshot aggregate is %s, but its components read as %s",
			profile.Aggregate.Status, conclusion.Status)
	}
	wantID := conclusion.FindingID(profile.Profile.Name)
	finding := profile.Aggregate.Finding
	if (finding == nil) != (wantID == "") {
		if wantID == "" {
			return fmt.Errorf("profile snapshot names aggregate finding %q, but every component passed", finding.ID)
		}
		return fmt.Errorf("profile snapshot names no aggregate finding, but its components read as %q", wantID)
	}
	if finding == nil {
		return nil
	}
	switch {
	case finding.ID != wantID:
		return fmt.Errorf("profile snapshot names aggregate finding %q, but its components read as %q", finding.ID, wantID)
	case !slices.Equal(finding.AffectedComponents, conclusion.Affected):
		return fmt.Errorf("profile snapshot finding %q lists affected components %v, but %v are not passing",
			finding.ID, finding.AffectedComponents, conclusion.Affected)
	case !slices.Equal(finding.WorkingComponents, conclusion.Working):
		return fmt.Errorf("profile snapshot finding %q lists working components %v, but %v are working",
			finding.ID, finding.WorkingComponents, conclusion.Working)
	}
	return nil
}

// stamped puts this build's schema on the snapshot and on every run record
// nested under an incident, so each of them decodes on its own rather than
// only as part of the file it arrived in. It copies the incident block rather
// than writing through the caller's pointers: encoding a snapshot must not
// edit the one the caller still holds.
func stamped(s Snapshot) Snapshot {
	s.Schema = Schema
	if s.Incident == nil {
		return s
	}
	incident := *s.Incident
	for _, nested := range []**Snapshot{&incident.Before, &incident.During, &incident.Recovered} {
		if *nested == nil {
			continue
		}
		record := **nested
		record.Schema = Schema
		*nested = &record
	}
	s.Incident = &incident
	return s
}

// Validate applies the same rules to a snapshot that arrived already decoded,
// and changes nothing about it.
//
// Decode is the reader for .ndoc bytes. This is for a snapshot that travelled
// inside some other envelope, where re-encoding it to reuse Encode would be
// the wrong check: Encode stamps the schema on the way through, so it would
// repair the one discrepancy most worth catching and then pronounce the
// repaired copy valid.
func Validate(s Snapshot) error {
	if s.Schema != Schema {
		return UnsupportedSchemaError{Found: s.Schema}
	}
	return validate(s)
}

// validate holds the rules a snapshot has to satisfy to be a snapshot, rather
// than valid JSON that happens to have these keys. Both directions apply them:
// Encode so a file that says nothing about a row never gets published, and
// Decode so a hand-edited or truncated file is refused instead of being read
// as one where a row simply had nothing to say. A reader that accepted what the
// writer refuses is a reader whose invariants are only true by luck.
func validate(s Snapshot) error {
	if err := validateProvenance(s.CreatedAt, s.Tool); err != nil {
		return err
	}
	if err := validateInvocation(s.Target, s.Options); err != nil {
		return err
	}
	if s.Redaction != nil && (!s.Redaction.Sanitized || s.Redaction.Policy != SupportRedactionPolicy) {
		return fmt.Errorf("snapshot has invalid redaction metadata")
	}
	checks := make(map[string]Check, len(s.Checks))
	impaired, firstFailed := "", ""
	for _, c := range s.Checks {
		_, repeated := checks[c.ID]
		switch {
		case c.ID == "":
			return fmt.Errorf("snapshot has a check with no id: a row nothing can name is a row nothing can cite")
		case repeated:
			return fmt.Errorf("snapshot lists check %q twice: one run observes a check once, and two rows under one id let two readers read two different runs", c.ID)
		case c.Status == "":
			return fmt.Errorf("snapshot check %q has no status: a row with no completed result must say %s", c.ID, StatusIncomplete)
		case !validCheckStatus(c.Status):
			return fmt.Errorf("snapshot check %q has unknown status %q", c.ID, c.Status)
		case c.CauseFamily != "" && c.Cause == "":
			return fmt.Errorf("snapshot check %q has a cause family without a cause", c.ID)
		case c.Derived != nil && !validAnswerComparison(c.Derived.AnswerComparison):
			return fmt.Errorf("snapshot check %q has unknown answer comparison %q", c.ID, c.Derived.AnswerComparison)
		case !c.Ran && c.DurationMs != 0:
			return fmt.Errorf("snapshot check %q never ran and reports %dms: ran is that duration read as a yes or no", c.ID, c.DurationMs)
		case ExecutionContradicts(c) && c.Ran:
			return fmt.Errorf("snapshot check %q is %s and also ran: a row that reported has an outcome", c.ID, c.Status)
		case ExecutionContradicts(c):
			return fmt.Errorf("snapshot check %q is %s and never ran: an outcome is what a probe body measured", c.ID, c.Status)
		case c.Status == StatusIncomplete && s.OK:
			return fmt.Errorf("snapshot check %q is %s, so the run cannot be reported ok", c.ID, StatusIncomplete)
		case c.Status == StatusFail && s.OK:
			return fmt.Errorf("snapshot check %q is %s, so the run cannot be reported ok", c.ID, StatusFail)
		}
		if err := validateObservation(c, s.Redaction != nil); err != nil {
			return fmt.Errorf("snapshot check %q: %w", c.ID, err)
		}
		checks[c.ID] = c
		if impaired == "" && (c.Status == StatusFail || c.Status == StatusIncomplete) {
			impaired = c.ID
		}
		if firstFailed == "" && c.Status == StatusFail {
			firstFailed = c.ID
		}
	}
	// The other half of the same rule. ok is the one field a script reads
	// first, and it is not an opinion the file gets to hold beside its rows:
	// it means no check failed and none was left unreported, so a run that
	// says otherwise while every row reported a survivable outcome is
	// describing a failure none of its evidence recorded.
	if !s.OK && impaired == "" {
		return fmt.Errorf("snapshot is reported not ok, but no check is %s or %s", StatusFail, StatusIncomplete)
	}
	// failed_stage is the field a triage script reads to route a bug report,
	// and it is derived the same way ok is: the first row that failed, in the
	// order the run executed them. Naming any other row, or naming none while
	// one failed, is the file disagreeing with its own evidence about where
	// the run broke.
	if s.Diagnosis.FailedStage != firstFailed {
		return fmt.Errorf("snapshot diagnosis names failed stage %q, but the first failed check is %q",
			s.Diagnosis.FailedStage, firstFailed)
	}
	if err := validateDependencyGraph(s.Checks, checks); err != nil {
		return err
	}
	if s.Diagnosis.Blamed != "" {
		if _, exists := checks[s.Diagnosis.Blamed]; !exists {
			return fmt.Errorf("snapshot diagnosis blames check %q, which is not in the snapshot", s.Diagnosis.Blamed)
		}
	}
	findings := make(map[string]bool, len(s.Diagnosis.Findings))
	for _, finding := range s.Diagnosis.Findings {
		// Identity first. Every consumer keys findings by this id, and a
		// diagnosis carrying an empty or a repeated one is read differently
		// depending on whether the reader takes list order, the primary
		// position, or a map: exactly the ambiguity the check rows above
		// refuse. The set of ids is deliberately not checked against this
		// build's vocabulary, because a newer netdoc naming a conclusion this
		// one has never heard of is an additive change, not a broken file.
		switch {
		case finding.ID == "":
			return fmt.Errorf("snapshot diagnosis has a finding with no id: a conclusion nothing can name is a conclusion nothing can act on")
		case findings[finding.ID]:
			return fmt.Errorf("snapshot diagnosis lists finding %q twice", finding.ID)
		case !validConfidence(finding.Confidence):
			return fmt.Errorf("snapshot finding %q has unknown confidence %q", finding.ID, finding.Confidence)
		}
		findings[finding.ID] = true
		if finding.Focus != "" {
			if _, exists := checks[finding.Focus]; !exists {
				return fmt.Errorf("snapshot finding %q focuses on check %q, which is not in the snapshot", finding.ID, finding.Focus)
			}
		}
		cited := make(map[string]bool, len(finding.Evidence))
		for _, id := range finding.Evidence {
			switch {
			case cited[id]:
				return fmt.Errorf("snapshot finding %q cites check %q twice", finding.ID, id)
			case !checkExists(checks, id):
				return fmt.Errorf("snapshot finding %q cites check %q, which is not in the snapshot", finding.ID, id)
			}
			cited[id] = true
		}
		seen := make(map[CausalEvidence]bool, len(finding.CausalEvidence))
		for _, evidence := range finding.CausalEvidence {
			if evidence.Check == "" {
				return fmt.Errorf("snapshot finding %q has causal evidence with no check", finding.ID)
			}
			if seen[evidence] {
				return fmt.Errorf("snapshot finding %q repeats causal evidence for check %q", finding.ID, evidence.Check)
			}
			seen[evidence] = true
			if err := validateCausalEvidence(evidence, checks); err != nil {
				return fmt.Errorf("snapshot finding %q: %w", finding.ID, err)
			}
		}
		// The two spellings of one fact have to agree where both are present.
		// Evidence is the compatibility projection of the typed evidence, so a
		// file carrying both and disagreeing gives an old consumer and a new
		// one different answers about what the conclusion rests on. A snapshot
		// written before typed evidence existed carries only the projection,
		// and nothing here asks it to invent the rest.
		if len(finding.CausalEvidence) > 0 && !slices.Equal(finding.Evidence, evidenceRows(finding.CausalEvidence)) {
			return fmt.Errorf("snapshot finding %q lists evidence %v, which is not the compatibility projection %v of its causal evidence",
				finding.ID, finding.Evidence, evidenceRows(finding.CausalEvidence))
		}
		if finding.Counterfactual != nil {
			if finding.Counterfactual.Variable == "" || len(finding.Counterfactual.Alternatives) < 2 {
				return fmt.Errorf("snapshot finding %q has an incomplete counterfactual", finding.ID)
			}
			for _, alternative := range finding.Counterfactual.Alternatives {
				if alternative.Value == "" || alternative.Outcome == "" || len(alternative.Evidence) == 0 {
					return fmt.Errorf("snapshot finding %q has an incomplete counterfactual alternative", finding.ID)
				}
				for _, evidence := range alternative.Evidence {
					if !seen[evidence] {
						return fmt.Errorf("snapshot finding %q counterfactual references evidence not carried by the finding", finding.ID)
					}
				}
			}
		}
	}
	return validateIncident(s)
}

// validateDependencyGraph holds a row's deps to what a run can have executed:
// the ids of other rows in this same snapshot, each named once, arranged so
// that every row could eventually have been reached.
//
// deps is the one field that says what the run's shape was, and the file is
// the only place that shape survives. A dependency on a row that is not here
// is an edge into nothing, a row that waits on itself never becomes ready, and
// a cycle is a set of rows none of which could have started, since a probe
// runs only once every row it waits on has a result. None of the three is a
// graph netdoc could have run, and a reader rebuilding one from the file gets
// a different answer about the run depending on how it walks the edges.
//
// What is deliberately not required is that a row's dependencies appear
// earlier in the slice. The order of checks is the order the graph was built,
// and both executors schedule by whether a row's dependencies have results
// rather than by position, so a graph listing a dependency after its dependent
// is executable and its snapshot is a real record of a real run.
//
// Unknown ids stay acceptable, as everywhere else here: this reads the rows
// against each other and never against this build's probe list, so a snapshot
// naming a check a later netdoc added is still a valid v1 file.
func validateDependencyGraph(order []Check, checks map[string]Check) error {
	for _, c := range order {
		named := make(map[string]bool, len(c.Deps))
		for _, dep := range c.Deps {
			switch {
			case named[dep]:
				return fmt.Errorf("snapshot check %q lists dependency %q twice: a row waits on another row once", c.ID, dep)
			case !checkExists(checks, dep):
				return fmt.Errorf("snapshot check %q depends on check %q, which is not in the snapshot", c.ID, dep)
			}
			named[dep] = true
		}
	}
	// Resolved the way the executor schedules a run, releasing a row once
	// every row it waits on is out, rather than by walking the edges: a file
	// arrives from outside and a walk over its edges is a recursion whose
	// depth it chooses, which is the same reason an incident's states are
	// checked one level deep.
	waiting := make(map[string]int, len(order))
	blocks := make(map[string][]string, len(order))
	ready := make([]string, 0, len(order))
	for _, c := range order {
		waiting[c.ID] = len(c.Deps)
		if len(c.Deps) == 0 {
			ready = append(ready, c.ID)
		}
		for _, dep := range c.Deps {
			blocks[dep] = append(blocks[dep], c.ID)
		}
	}
	for len(ready) > 0 {
		id := ready[len(ready)-1]
		ready = ready[:len(ready)-1]
		for _, dependent := range blocks[id] {
			waiting[dependent]--
			if waiting[dependent] == 0 {
				ready = append(ready, dependent)
			}
		}
	}
	// Whatever is still waiting is waiting on something that never came out,
	// which with every dependency present means a cycle. Reported in the
	// order the rows are written so one file always names the same row.
	for _, c := range order {
		if waiting[c.ID] > 0 {
			return fmt.Errorf("snapshot check %q waits on a dependency cycle: a row cannot wait on itself, directly or through the rows it waits on", c.ID)
		}
	}
	return nil
}

// validateIncident holds an incident record to what a watch session can
// actually have observed, in both directions like every other rule here.
//
// The four states are not interchangeable: the run this record hangs off is
// the onset and therefore failed, the run before it and the run that ended it
// did not, and a later failing state is still a failing one. A file that says
// otherwise is describing something no watch pass produced, and reading it
// would put an outage's before and after the wrong way round.
//
// A run record is one run, so it carries no incident of its own. That keeps
// the shape one level deep, which is what makes validating it a walk rather
// than a recursion a hostile file could steer.
func validateIncident(s Snapshot) error {
	if s.Incident == nil {
		return nil
	}
	i := *s.Incident
	switch {
	case i.StartedAt == "":
		return fmt.Errorf("snapshot incident has no start time")
	case i.Passes < 1:
		return fmt.Errorf("snapshot incident was observed %d times: an incident is at least the pass that opened it", i.Passes)
	case s.OK:
		return fmt.Errorf("snapshot incident hangs off a run that reported ok: the onset of an incident is a run that failed")
	case (i.EndedAt == "") != (i.Recovered == nil):
		return fmt.Errorf("snapshot incident records an end time without the run that ended it, or the reverse")
	}
	started, err := parseIncidentTime("start", i.StartedAt)
	if err != nil {
		return err
	}
	onset, err := parseIncidentTime("onset run", s.CreatedAt)
	if err != nil {
		return err
	}
	if !started.Equal(onset) {
		return fmt.Errorf("snapshot incident start time %q does not match its onset run %q", i.StartedAt, s.CreatedAt)
	}
	var ended time.Time
	if i.EndedAt != "" {
		ended, err = parseIncidentTime("end", i.EndedAt)
		if err != nil {
			return err
		}
		if ended.Before(started) {
			return fmt.Errorf("snapshot incident ended before it started")
		}
	}
	for _, state := range []struct {
		name    string
		record  *Snapshot
		failing bool
	}{
		{"before", i.Before, false},
		{"during", i.During, true},
		{"recovered", i.Recovered, false},
	} {
		if state.record == nil {
			continue
		}
		if state.record.Incident != nil {
			return fmt.Errorf("snapshot incident %s state carries an incident of its own: a run record is one run", state.name)
		}
		if state.record.Schema != Schema {
			return fmt.Errorf("snapshot incident %s state has schema %q, want %q", state.name, state.record.Schema, Schema)
		}
		if (s.Redaction == nil) != (state.record.Redaction == nil) ||
			s.Redaction != nil && *s.Redaction != *state.record.Redaction {
			return fmt.Errorf("snapshot incident %s state has different redaction metadata from its onset", state.name)
		}
		if state.record.OK == state.failing {
			return fmt.Errorf("snapshot incident %s state reports ok=%v, which is not what that point in an incident is", state.name, state.record.OK)
		}
		if reason := WatchSessionMismatch(s, *state.record); reason != "" {
			return fmt.Errorf("snapshot incident %s state has a different %s from its onset: an incident is one watch session, and passes of one session cannot disagree about it", state.name, reason)
		}
		if err := validate(*state.record); err != nil {
			return fmt.Errorf("snapshot incident %s state: %w", state.name, err)
		}
		at, err := parseIncidentTime(state.name+" state", state.record.CreatedAt)
		if err != nil {
			return err
		}
		switch state.name {
		case "before":
			if at.After(started) {
				return fmt.Errorf("snapshot incident before state was observed after the incident started")
			}
		case "during":
			if at.Before(started) || !ended.IsZero() && at.After(ended) {
				return fmt.Errorf("snapshot incident during state falls outside the incident")
			}
		case "recovered":
			if !at.Equal(ended) {
				return fmt.Errorf("snapshot incident recovery time %q does not match its recovered run %q", i.EndedAt, state.record.CreatedAt)
			}
		}
	}
	return nil
}

// WatchSessionMismatch is the one definition of what a watch session fixes:
// it names the first run setting two snapshots disagree about, and returns the
// empty string when they could be two passes of one session.
//
// A watch session is a single netdoc process watching one target with one set
// of run settings. Everything below is decided once, before the first pass,
// and cannot move while the session lasts: the tool is the running build, the
// target and the options come from the command line, and the check graph is
// built from those two and reused unchanged for every pass. The one setting a
// user can change from inside the TUI is the target, and changing it throws
// the incident timeline away and starts a new session, so even a respelling of
// a logically identical endpoint ends the old one.
//
// Everything else a snapshot carries is what the pass observed, which is the
// whole point of watching: statuses, causes, timings, routes, resolved
// addresses, resolvers, interfaces, network names and the diagnosis made of
// them are all expected to move, and an incident is the record of them moving.
//
// The check graph counts as a setting rather than an observation because a run
// records every probe it built, including the ones that were skipped, did not
// apply, or never reported. Two passes of one session therefore always list
// the same rows, under the same ids and names, with the same dependencies, in
// the same order. Only the outcomes differ.
func WatchSessionMismatch(a, b Snapshot) string {
	switch {
	case a.Tool != b.Tool:
		return "tool identity"
	case (a.Target == nil) != (b.Target == nil):
		return "target"
	case a.Target != nil && *a.Target != *b.Target:
		return "target"
	}
	if reason := watchOptionsMismatch(a.Options, b.Options); reason != "" {
		return reason
	}
	return watchGraphMismatch(a.Checks, b.Checks)
}

// watchOptionsMismatch reads the run settings one at a time rather than
// comparing the struct, because Options carries slices and because the name
// this returns is what the error tells a reader to look at.
func watchOptionsMismatch(a, b Options) string {
	switch {
	case a.ProbeTimeoutMs != b.ProbeTimeoutMs:
		return "probe timeout"
	case a.PublicDNS != b.PublicDNS || a.PublicDNSAuto != b.PublicDNSAuto:
		return "public DNS configuration"
	case !slices.Equal(a.Check, b.Check) || !slices.Equal(a.Skip, b.Skip):
		return "probe selection"
	case (a.Source == nil) != (b.Source == nil):
		return "source binding"
	case a.Source != nil && *a.Source != *b.Source:
		return "source binding"
	}
	return ""
}

// watchGraphMismatch compares the rows as a graph and not as results: the ids,
// the names, the dependencies, and the order they were executed in. What each
// row reported is deliberately not read here, since that is the evidence a
// watch session exists to collect.
func watchGraphMismatch(a, b []Check) string {
	if len(a) != len(b) {
		return "check graph"
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Name != b[i].Name || !slices.Equal(a[i].Deps, b[i].Deps) {
			return "check graph"
		}
	}
	return ""
}

func parseIncidentTime(name, value string) (time.Time, error) {
	at, err := time.Parse(time.RFC3339, value)
	_, offset := at.Zone()
	if err != nil || offset != 0 {
		return time.Time{}, fmt.Errorf("snapshot incident %s time %q is not RFC 3339 UTC", name, value)
	}
	return at, nil
}

// validConfidence accepts the closed vocabulary and the empty value, which is
// what a producer that never assessed confidence wrote. A value outside the set
// is refused in both directions like every other rule here: reading it as some
// unknown strength would be reading a claim this build cannot interpret, and
// widening the vocabulary is the kind of change that moves the schema version.
func validConfidence(value string) bool {
	switch value {
	case "", ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceInsufficientEvidence:
		return true
	}
	return false
}

func validateCausalEvidence(e CausalEvidence, checks map[string]Check) error {
	check, exists := checks[e.Check]
	switch e.Kind {
	case EvidenceSupport:
		if e.Candidate != "" || e.Reason != "" {
			return fmt.Errorf("support evidence for check %q has an alternative or not-evaluated reason", e.Check)
		}
	case EvidenceContradiction, EvidenceRuledOut:
		if e.Candidate == "" || e.Reason != "" {
			return fmt.Errorf("%s evidence for check %q must name one candidate and no reason", e.Kind, e.Check)
		}
		if e.Observation == ObservationStatusSkip || e.Observation == ObservationStatusNA {
			return fmt.Errorf("%s evidence for check %q cannot use an unevaluated observation", e.Kind, e.Check)
		}
	case EvidenceNotEvaluated:
		if e.Candidate != "" || e.Reason == "" {
			return fmt.Errorf("not-evaluated evidence for check %q must name one reason and no candidate", e.Check)
		}
		switch e.Reason {
		case NotEvaluatedNotSelected:
			if exists || e.Observation != "" {
				return fmt.Errorf("check %q is marked not selected but is present or has an observation", e.Check)
			}
			return nil
		case NotEvaluatedPrerequisite:
			if !exists || check.Status != StatusSkip || e.Observation != ObservationStatusSkip {
				return fmt.Errorf("check %q is marked prerequisite-blocked without a SKIP observation", e.Check)
			}
			return nil
		case NotEvaluatedNotApplicable:
			if !exists || check.Status != StatusNA || e.Observation != ObservationStatusNA {
				return fmt.Errorf("check %q is marked not applicable without an N/A observation", e.Check)
			}
			return nil
		case NotEvaluatedIncomplete:
			if !exists || check.Status != StatusIncomplete || e.Observation != "" {
				return fmt.Errorf("check %q is marked incomplete without an incomplete row", e.Check)
			}
			return nil
		default:
			return fmt.Errorf("check %q has unknown not-evaluated reason %q", e.Check, e.Reason)
		}
	default:
		return fmt.Errorf("check %q has unknown causal evidence kind %q", e.Check, e.Kind)
	}
	if !exists {
		return fmt.Errorf("causal evidence references check %q, which is not in the snapshot", e.Check)
	}
	// Measured evidence, so the row it rests on has to have been measured. A
	// support, contradiction, or ruled-out claim reads a row's recorded fields
	// as what a probe saw, and a row whose body never executed has fields only
	// because every row carries them: the status and the observation can still
	// line up, and the claim would be built out of nothing observed. The
	// not-evaluated kinds return above precisely because they claim the
	// opposite, and they keep their own meaning.
	if !check.Ran {
		return fmt.Errorf("%s evidence for check %q reads an observation off a row whose probe body did not run", e.Kind, e.Check)
	}
	if !observationMatches(e, check) {
		return fmt.Errorf("causal evidence references %s on check %q, but that observation is absent", e.Observation, e.Check)
	}
	return nil
}

// CausalEvidence.Value semantics, part of the v1 file contract. An
// observation either names a recorded value or it does not, and which one it
// is decides what a reader may do with the field: "absent" means the
// observation is the whole claim and the field carries nothing to check,
// "optional" means a producer may name one recorded value and need not,
// "required" means the claim is about one named value and is unreadable
// without it.
const (
	EvidenceValueAbsent   = "absent"
	EvidenceValueOptional = "optional"
	EvidenceValueRequired = "required"
)

// ClockOffsetEvidenceMs is how far this machine's clock has to be off before a
// recorded offset is evidence of anything. A smaller offset is measured and
// stored like any other reading, and nothing concludes from it, so an artifact
// citing one as causal evidence is claiming reasoning no netdoc performed.
const ClockOffsetEvidenceMs = 5 * 60 * 1000

// causalObservation is the whole v1 rule for one observation: how its evidence
// items may use Value, and what the row they reference has to have recorded
// for the claim to be true. The two belong together because they are one
// question asked twice: whether this artifact could have come from a run.
type causalObservation struct {
	value   string
	present func(e CausalEvidence, check Check) bool
}

// causalObservations is the authoritative description of the causal-evidence
// vocabulary. Every observation the format defines has exactly one entry, and
// an observation this build does not know stays refused rather than accepted
// unchecked: evidence is the one part of a snapshot whose whole purpose is to
// be verifiable against the rows beside it.
var causalObservations = map[string]causalObservation{
	// A row's outcome is the entire observation. There is no second thing to
	// name, and an item that names one is not something a run wrote.
	ObservationStatusPass: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return check.Status == StatusPass
	}},
	ObservationStatusWarn: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return check.Status == StatusWarn && (check.Derived == nil || !check.Derived.StatusDowngraded)
	}},
	ObservationStatusFail: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return check.Status == StatusFail
	}},
	ObservationStatusSkip: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return check.Status == StatusSkip
	}},
	ObservationStatusNA: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return check.Status == StatusNA
	}},
	// The address family that supplied the cause, which is this row's own
	// cause_family. Evidence that only points at the cause names nothing.
	//
	// A row written before cause_family existed carries none, and the evidence
	// beside it still named a family, so a value there is checked against the
	// family vocabulary rather than against the row: that artifact is real and
	// stays readable, and an arbitrary string was never one of its states.
	ObservationCause: {EvidenceValueOptional, func(e CausalEvidence, check Check) bool {
		return check.Cause != "" && (e.Value == "" || e.Value == check.CauseFamily ||
			check.CauseFamily == "" && validObservationFamily(e.Value))
	}},
	// One of the answers this row recorded, when the claim is about a single
	// address rather than about there having been answers at all.
	ObservationDNSAnswers: {EvidenceValueOptional, func(e CausalEvidence, check Check) bool {
		return check.Observed != nil && len(check.Observed.Addresses) > 0 &&
			(e.Value == "" || slices.Contains(check.Observed.Addresses, e.Value))
	}},
	ObservationDNSNotFound: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return check.Observed != nil && check.Observed.DNSNotFound
	}},
	ObservationCaptivePortal: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return check.Observed != nil && check.Observed.Portal != nil
	}},
	ObservationTimeout: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return (check.Observed != nil && check.Observed.Timeout) || check.Cause == "timeout"
	}},
	// A stored offset is a measurement; only one past the threshold is a
	// reason for anything, so the magnitude is part of the observation.
	ObservationClockOffset: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		if check.Observed == nil || check.Observed.ClockOffsetMs == nil {
			return false
		}
		offset := *check.Observed.ClockOffsetMs
		return offset >= ClockOffsetEvidenceMs || offset <= -ClockOffsetEvidenceMs
	}},
	ObservationStatusDowngraded: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return check.Derived != nil && check.Derived.StatusDowngraded
	}},
	// The family the claim is about. Neither state is readable without it.
	ObservationFamilyReachable: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return familyObservation(check, e.Value) == "reachable"
	}},
	ObservationFamilyFailed: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return familyObservation(check, e.Value) == "unreachable"
	}},
	// The address that was tried.
	ObservationAddressSucceeded: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return check.Observed != nil && slices.ContainsFunc(check.Observed.Attempts, func(a Attempt) bool {
			return a.IP == e.Value && a.Error == ""
		})
	}},
	ObservationAddressFailed: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return check.Observed != nil && slices.ContainsFunc(check.Observed.Attempts, func(a Attempt) bool {
			return a.IP == e.Value && a.Error != "" && !a.Aborted && a.Cause != "" && a.Cause != "canceled"
		})
	}},
	// The interface this row's traffic left by. A path with no interface was
	// never classified, so it is never one of these two states either.
	ObservationRouteTunneled: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return routeMatches(check, func(r Route) bool {
			return r.Interface == e.Value && (r.Tunnel == TunnelStateTunnel || r.Tunnel == TunnelStateLikely)
		})
	}},
	ObservationRouteDirect: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return routeMatches(check, func(r Route) bool {
			return r.Interface == e.Value && r.Tunnel == TunnelStateDirect
		})
	}},
	// The destination the kernel refused to route.
	ObservationRouteUnreachable: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return routeMatches(check, func(r Route) bool { return r.Destination == e.Value && r.Unreachable })
	}},
	// The value names the other path. The claim is checkable from this row
	// alone: its own selected interface is not that one.
	ObservationRoutePathDiffers: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return routeMatches(check, func(r Route) bool {
			return r.Interface != "" && r.Interface != e.Value
		})
	}},
	// The value names the other path's next hop. The claim is checkable from
	// this row alone: it has a next hop of its own and it is not that one.
	ObservationRouteNextHopDiffers: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return routeMatches(check, func(r Route) bool {
			return r.Gateway != "" && r.Gateway != e.Value
		})
	}},
	// This row's own routing domain, named by the platform and not the main
	// one. The value stays empty because there is nothing about the other row
	// to name: it is the main table or unknown, and neither is a value a
	// reader could check.
	ObservationRouteTableDiffers: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return routeMatches(check, func(r Route) bool {
			domain, _ := r.RoutingDomain()
			return domain != ""
		})
	}},
	// The split is the whole observation, and it is stated about the row that
	// holds both families, so neither family is a value to name.
	ObservationRouteFamilySplit: {EvidenceValueAbsent, func(_ CausalEvidence, check Check) bool {
		return routeFamilySplit(check)
	}},
	// The interface whose MTU this is.
	ObservationRouteInterfaceMTU: {EvidenceValueRequired, func(e CausalEvidence, check Check) bool {
		return routeMatches(check, func(r Route) bool {
			return r.Interface == e.Value && r.InterfaceMTU > 0
		})
	}},
}

// CausalEvidenceValueSemantics reports how each observation in the v1
// causal-evidence vocabulary reads CausalEvidence.Value. It is the validator's
// own table rather than a restatement of it, exported so that a producer can
// be held to the same contract without this package learning anything about
// probes.
func CausalEvidenceValueSemantics() map[string]string {
	out := make(map[string]string, len(causalObservations))
	for id, rule := range causalObservations {
		out[id] = rule.value
	}
	return out
}

func observationMatches(e CausalEvidence, check Check) bool {
	rule, known := causalObservations[e.Observation]
	if !known {
		return false
	}
	switch {
	case rule.value == EvidenceValueAbsent && e.Value != "":
		return false
	case rule.value == EvidenceValueRequired && e.Value == "":
		return false
	}
	return rule.present(e, check)
}

// The tunnel-state vocabulary, part of the v1 file contract. An absent state
// means nothing classified the interface, which is not the same as direct.
const (
	TunnelStateDirect = "direct"
	TunnelStateLikely = "likely"
	TunnelStateTunnel = "tunnel"
)

func routeMatches(check Check, match func(Route) bool) bool {
	return check.Observed != nil && slices.ContainsFunc(check.Observed.Routes, match)
}

// RoutingDomain is the routing table this decision came from, as anything
// reading the artifact should compare it: the tables an operating system
// consults on its own read as the ordinary case, and only a table something
// selected is a routing domain worth telling apart.
//
// Linux is the only platform that fills the field, and a machine with no
// policy routing at all still answers out of local for its own addresses and
// main for everything else, which is why a localhost destination lands in a
// different table per family. The second return is whether the platform said
// anything at all, which is not the same as saying "the ordinary one".
func (r Route) RoutingDomain() (string, bool) {
	if !r.TableKnown {
		return "", false
	}
	switch r.Table {
	case "", "local", "default":
		return "", true
	}
	return r.Table, true
}

// routeFamilySplit reports that this row's IPv4 and IPv6 destinations take
// materially different routes, which needs a named interface in both families.
//
// The dimensions are the family-neutral ones. Every dual-stack host uses a
// different next hop and a different source for the two families, so neither
// could ever be a split; a routing domain is not family-scoped that way, and a
// family a rule sent to another table is a real split even where both leave by
// one interface.
func routeFamilySplit(check Check) bool {
	if check.Observed == nil {
		return false
	}
	var v4, v6 Route
	for _, r := range check.Observed.Routes {
		switch {
		case r.Interface == "":
		case r.Family == "ipv4" && v4.Interface == "":
			v4 = r
		case r.Family == "ipv6" && v6.Interface == "":
			v6 = r
		}
	}
	if v4.Interface == "" || v6.Interface == "" {
		return false
	}
	v4Domain, v4Known := v4.RoutingDomain()
	v6Domain, v6Known := v6.RoutingDomain()
	return v4.Interface != v6.Interface || v4Known && v6Known && v4Domain != v6Domain
}

func familyObservation(check Check, family string) string {
	if check.Observed == nil || check.Observed.Families == nil {
		return ""
	}
	if family == "ipv4" {
		return check.Observed.Families.IPv4
	}
	if family == "ipv6" {
		return check.Observed.Families.IPv6
	}
	return ""
}

// Decode reads an .ndoc file. It refuses anything that is not this schema
// before looking at a single other field, so a v2 file written by a later
// netdoc is reported as unreadable rather than half understood.
//
// Unknown fields inside a v1 file are ignored on purpose: that is what makes
// an added optional field a compatible change. A row that does not say what it
// is, on the other hand, is not an unknown field: it is the one thing Encode
// refuses to write, and Decode refuses to read it back.
func Decode(data []byte) (Snapshot, error) {
	var head struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return Snapshot{}, fmt.Errorf("not a Network Doctor snapshot: %w", err)
	}
	if head.Schema != Schema {
		return Snapshot{}, UnsupportedSchemaError{Found: head.Schema}
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}, err
	}
	if err := validate(s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// DecodeProfile reads a multi-run profile .ndoc artifact. Decode remains the
// single-run reader, so old callers cannot silently discard profile components.
func DecodeProfile(data []byte) (ProfileSnapshot, error) {
	var head struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return ProfileSnapshot{}, fmt.Errorf("not a Network Doctor profile snapshot: %w", err)
	}
	if head.Schema != ProfileSchema {
		return ProfileSnapshot{}, UnsupportedProfileSchemaError{Found: head.Schema}
	}
	var profile ProfileSnapshot
	if err := json.Unmarshal(data, &profile); err != nil {
		return ProfileSnapshot{}, err
	}
	if err := validateProfile(profile); err != nil {
		return ProfileSnapshot{}, err
	}
	return profile, nil
}

type UnsupportedProfileSchemaError struct{ Found string }

func (e UnsupportedProfileSchemaError) Error() string {
	if e.Found == "" {
		return "not a Network Doctor profile snapshot (no schema field, want " + ProfileSchema + ")"
	}
	return fmt.Sprintf("unsupported profile snapshot schema %q, this build reads %s", e.Found, ProfileSchema)
}

// WriteFile saves a snapshot at path, replacing whatever was there.
//
// The bytes land in a temporary file in the same directory and are renamed
// over the destination only once all of them are written, so a write that
// fails, or a process killed partway through one, leaves the previous file
// intact rather than a truncated artifact that still parses as JSON right up
// to the point it stops. Same directory because a rename across filesystems is
// not atomic and, on Windows, not permitted at all.
//
// That covers this process failing, not the machine underneath it. Nothing
// here calls fsync, so a kernel crash or a power cut around the write can
// leave the destination holding the old snapshot, the new one, or, on a
// filesystem that commits the rename before the data it points at, an empty
// file. Nothing in netdoc reads a saved run back as state it depends on, and
// the repair is to run again, so the two syncs that would close that window
// are not worth their cost on every save.
//
// The file inherits os.CreateTemp's 0600 on the platforms where mode means
// anything: a snapshot carries the addresses, interface names, and network name
// of the machine that ran it, which is nobody else's business until its owner
// chooses to share it.
func WriteFile(path string, s Snapshot) error {
	data, err := Encode(s)
	if err != nil {
		return err
	}
	return writeFile(path, data)
}

// WriteProfileFile atomically saves a multi-run profile snapshot.
func WriteProfileFile(path string, profile ProfileSnapshot) error {
	data, err := EncodeProfile(profile)
	if err != nil {
		return err
	}
	return writeFile(path, data)
}

func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".netdoc-snapshot-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Best effort on every failure path: the rename below is what makes the
	// artifact real, so a leftover temp file is the only thing to clean up and
	// its removal failing is not worth reporting over the write error.
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// checkExists reports whether the snapshot holds a row under this id. An empty
// id is never a row, because validate refuses one, so a reference to "" is a
// reference to nothing rather than a lookup that happens to miss.
func checkExists(checks map[string]Check, id string) bool {
	_, exists := checks[id]
	return id != "" && exists
}

// evidenceRows is the compatibility projection a finding's Evidence field has
// always been: the unique check ids the typed evidence observed, in reasoning
// order. A not_evaluated item is absent because it supplied no observation.
//
// The rule is written here rather than imported because this package cannot
// see internal/diagnostic, which is where the producer spells the same rule
// for a live finding. TestBuiltSnapshotEvidenceProjectionsAgree encodes a
// built finding and so fails if the two ever part company.
func evidenceRows(evidence []CausalEvidence) []string {
	var rows []string
	for _, e := range evidence {
		if e.Kind == EvidenceNotEvaluated || e.Check == "" || slices.Contains(rows, e.Check) {
			continue
		}
		rows = append(rows, e.Check)
	}
	return rows
}
