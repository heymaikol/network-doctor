package simulation

import (
	"encoding/json"
	"fmt"
	"math"
)

// The hunt result byte budget.
//
// A merge reads shard results other processes wrote, so the reader has to know
// what a legitimate one can weigh before a decoder is handed any of it. The
// chain that makes that a definition rather than an estimate runs the other
// way round from the numbers below, so it is worth stating once.
//
// canonicalHuntReport keeps a fixed set of fields per row and clips every free
// string to huntCanonicalTextBytes or huntCanonicalNameBytes, so one row of any
// list a hunt stores has a maximum encoded size. The cardinality section below
// says how many rows of each list a hunt case may hold, derived from the hunt
// model rather than from measurement. HuntMaxCaseResultBytes is the encoded
// size of the case those two facts describe: every list at its maximum
// cardinality and every string at its ceiling, measured with the accounting
// WriteJSON uses. huntMaxCasesBytes is HuntMaxCases of those, and
// HuntMaxResultBytes adds the sections outside the case list.
//
// There used to be an exception, and then a weaker one. HuntMaxCaseResultBytes
// first bounded a simulation report that no producer wrote under a budget, and
// a case over it stored a stand-in that lost every finding derived from the
// report it replaced. Then canonicalHuntReport replaced that with per-section
// byte ceilings, which never changed a case's meaning at a threshold but did
// keep the longest fitting prefix of lists whose individual rows decide truth,
// coverage and findings. Neither is here now: a byte budget decides no semantic
// fact in a hunt case, because no semantic list is bounded by bytes at all.
//
// Weighing the encoded form is what settles JSON escaping. A rune that expands
// sixfold under encoding is counted after it expands, so the budget needs no
// separate allowance for it and cannot be defeated by choosing text that
// encodes badly.
const (
	// huntCanonicalNameBytes bounds the strings a hunt case carries out of the
	// model's own vocabularies: node, segment and service names, address
	// families, states, outcomes, results, verdicts, probe ids, addresses and
	// address:port endpoints. isSafeName holds every scenario name to 32 bytes
	// of letters, digits and dashes, an IPv6 address to 45 and an endpoint to
	// 53, and none of those escape under JSON, so this is roughly twice the
	// longest such string a validated scenario can produce and clips none of
	// them. It exists because these are the strings a case holds hundreds of.
	huntCanonicalNameBytes = 64
	// huntCanonicalHostBytes bounds the strings a hunt function compares as
	// names rather than displays: a resolver lookup's name, a queried name, a
	// test's target, a certificate's names and the server a handshake asked
	// for. Two different names clipped to a shared prefix would be the one way
	// text could change what a case means, so this sits above the 253 bytes a
	// DNS name can reach and clips none of them.
	huntCanonicalHostBytes = 256
	// huntCanonicalTextBytes bounds the prose: a netdoc check's detail, a
	// suggestion's message, a run's error, a failed timed event's state. All of
	// it reaches a finding's Summary or Evidence, which no fingerprint covers
	// and no hunt function reads, so clipping it costs a reader the tail of a
	// sentence and changes no derived value.
	huntCanonicalTextBytes = 256
	// huntReportCleanupBytes bounds the cleanup error list, which is the one
	// list left in a canonical report that a byte budget bounds. Nothing reads
	// its rows: Cleanup.Done decides the case status, and the list is joined
	// into that finding's evidence text.
	huntReportCleanupBytes = 2 << 10
)

// The hunt model's cardinalities.
//
// A hunt scenario is one of the eight bases in huntBaseNames with generated
// mutations applied. No operator in applyGeneratedMutation adds a node, a
// segment, an interface or an alias: they append faults, rewrite or delete one
// service, delete one route, or replace the test list with exactly three
// entries. So the largest base bounds every list the topology decides, and
// TestHuntModelCardinalityCoversTheHuntBases recomputes those maxima from the
// library and fails if a base outgrows a ceiling here.
//
// Each ceiling is roughly twice what the library reaches, which is the room a
// new base scenario has before this file has to be revisited. Crossing one is
// not a size to be truncated to: checkHuntCaseCardinality refuses the case and
// says which list it was, on the writing side and again on the reading side,
// because a list past its model maximum is a shape this program should not have
// produced rather than a case whose tail is expendable.
const (
	// Topology. The largest base holds 5 nodes, 4 interfaces on one node and 4
	// routes on one node.
	huntMaxTopologyNodes  = 8
	huntMaxNodeInterfaces = 4
	huntMaxNodeRoutes     = 8
	// Faults and the timeline they produce. A base declares at most one fault
	// and each of the at most HuntMaxFaults mutations appends at most two. A
	// fault a base declares may carry maxScheduledEvents scheduled events; the
	// scheduled faults the operators append carry at most three each.
	huntMaxReportFaults   = 16
	huntMaxTimelineEvents = maxScheduledEvents
	// Tests. Bases declare one or two; timeline.dns_outage, the one operator
	// that rewrites the list, replaces it with exactly three.
	huntMaxCanonicalTests = 4
	// One netdoc diagnosis. netdoc's stable probe graph is the registry that
	// decides both: diagnostic.StableProbes enumerates every probe any target
	// can select, opt-in checks included, each contributing at most one check
	// row, and a finding is raised over those same rows.
	// TestHuntDiagnosisCardinalityCoversTheProbeRegistry pins both against it.
	huntMaxDiagnosisChecks   = 16
	huntMaxDiagnosisFindings = 16
	// Probe dependency edges, the registry Report.dependencyContradictions walks.
	// TestHuntModelCardinalityCoversTheHuntBases pins this against probeDeps.
	huntMaxProbeDependencyEdges = 8
	// Suggestions a stored report keeps. Canonicalization drops every code
	// huntSuggestionClass does not name, because no hunt function reads one, so
	// the bound covers only the codes that become hunt findings. Per netdoc run
	// Report.timelineSuggestions raises at most one resampling gap per recovery
	// (a recovery needs a preceding impairment of the same fault, so at most
	// half a timeline can be recoveries), one permanent-wording note, one
	// missed-window note and one contradiction per probe dependency edge, and
	// TestOutcome.suggest adds at most one nondeterminism note. Outside the
	// runs, Report.routeSuggestions and Report.faultSuggestions return on their
	// first match, one suggestion each.
	huntMaxReportSuggestions = huntMaxCanonicalTests*
		(huntMaxTimelineEvents/2+3+huntMaxProbeDependencyEdges) + 2
	// Evidence. Every list here carries one row per node, per node and family,
	// per interface, per configured route, per controlled service or per
	// resolver lookup, so the topology maxima above bound all of them.
	huntMaxResolverLookups    = 8
	huntMaxLookupAddresses    = 8
	huntMaxSOCKSRequests      = 8
	huntMaxTLSHandshakes      = 8
	huntMaxCertificateNames   = 4
	huntMaxServiceReplies     = 16
	huntMaxTCPResets          = 8
	huntMaxPacketConditions   = 16
	huntMaxPacketDrops        = 16
	huntMaxLinks              = 16
	huntMaxRouteEvidence      = 32
	huntMaxRouteTables        = 16
	huntMaxKernelRoutes       = 16
	huntMaxRouters            = 8
	huntMaxControlledTargets  = 32
	huntMaxFamilyReachability = 16
	huntMaxViaHops            = 8
	// DNSQueries after canonicalHuntDNSQueries has reduced it: one row per
	// distinct node, service, name, query type and served outcome, plus the row
	// each service answered last inside each netdoc run's window. netdoc asks
	// for a handful of names over at most two record types, a scenario serves
	// at most a handful of resolvers, and a resolver serves one of six
	// outcomes, so this is the one ceiling that bounds a product of netdoc's
	// question set rather than of the topology.
	huntMaxCanonicalDNSQueries = 48
	// Findings the condition oracle can raise for one case: at most one
	// unrecognized and one unsupported condition per rule, plus the two
	// per-family reachability contradictions.
	huntMaxOracleFindings = 40
	// Findings one case may report, which is every producer in analyzeHuntCase
	// summed: one per failed timeline event, four per netdoc run, the oracle's
	// own, one for an unclassified reset, and one per suggestion the run
	// produced. TestHuntDiagnosisCardinalityCoversTheProbeRegistry recomputes
	// that sum and fails if it outgrows this.
	huntMaxCaseFindings = huntMaxTimelineEvents + 4*huntMaxCanonicalTests +
		huntMaxOracleFindings + 1 + huntMaxReportSuggestions
	// Mutations one case may carry, which the generator fixes directly.
	huntMaxCaseMutations = HuntMaxFaults
	// Operator ids one truth may list, one per mutation the evidence confirmed.
	huntMaxObservedFaults = HuntMaxFaults
)

const (
	// HuntMaxCaseResultBytes is one entry of case_results as WriteJSON writes
	// it, when every list in it holds its maximum cardinality of rows and every
	// string in it is clipped to its ceiling. It is measured rather than summed
	// so that the property names, braces, indentation and separators are in it
	// exactly once each, at their real cost, with nothing left over for a
	// structural allowance nobody derived.
	// TestHuntCaseCeilingIsTheSaturatedCanonicalCase builds that case from the
	// cardinality constants above and fails unless it encodes to exactly this.
	HuntMaxCaseResultBytes = 837394
	// huntMaxCasesBytes is the case_results section: HuntMaxCases entries at
	// what one entry may weigh, plus the two bytes an empty list occupies. It
	// is the product rather than an independent ceiling on purpose. Two
	// separately legal limits whose combination the writer rejects is not a
	// budget.
	huntMaxCasesBytes = 2 + HuntMaxCases*HuntMaxCaseResultBytes
	// huntMaxAggregateFindingsBytes bounds the findings section. Its rows are a
	// deduplicating projection of case findings, so their count is bounded only
	// by the cases, and their text is netdoc's. aggregateHuntFindings enforces
	// the ceiling by keeping the longest prefix of its own deterministic order
	// that fits, which costs a summary its tail rows and costs the artifact
	// nothing: every row here restates a finding case_results still carries in
	// full. That is what makes a byte bound the right instrument here and the
	// wrong one inside a case. A full HuntMaxCases run measures under 5 KiB.
	huntMaxAggregateFindingsBytes = 1 << 20
	// huntMaxAggregateSuggestionsBytes bounds the suggestions section the same
	// way, and for the same reason: it holds one row per suggestion code, each
	// quoting a finding summary the case results still carry.
	huntMaxAggregateSuggestionsBytes = 256 << 10
	// huntMaxRunSummaryBytes bounds everything outside those three sections:
	// the scalar run metadata and the coverage model. Every string there comes
	// from a fixed vocabulary except Error, which clip bounds, and coverage
	// holds one row per registry operator and one per oracle condition with
	// Cardinality no longer than HuntMaxFaults. checkHuntResultBudget weighs it
	// before any hunt result is written, so a future field or registry that
	// outgrows this ceiling refuses to serialize rather than producing an
	// artifact the reader will not take. TestHuntRunSummaryFitsItsBudget builds
	// the largest one the current vocabularies allow and shows the ceiling is
	// not a constraint hunts actually meet.
	huntMaxRunSummaryBytes = 64 << 10
	// HuntMaxResultBytes is the maximum encoded size of one hunt result. A
	// shard carries at most every case the hunt requested, because a shard
	// count of one is legal and HuntMaxCases bounds the request.
	HuntMaxResultBytes = huntMaxRunSummaryBytes + huntMaxAggregateFindingsBytes +
		huntMaxAggregateSuggestionsBytes + huntMaxCasesBytes
)

// huntListIndentPrefix is the indentation writeJSON gives an element of a
// top-level list in a hunt result: the result object indents its own fields one
// level, and the list indents its elements one more.
const huntListIndentPrefix = "    "

// huntEncodedElementSize is how many bytes one list element occupies in a hunt
// result written by WriteJSON, counting the indentation of its opening line and
// the separator that follows it. A value that cannot be encoded weighs more
// than any budget, so it is refused rather than waved through.
func huntEncodedElementSize(v any) int {
	blob, err := json.MarshalIndent(v, huntListIndentPrefix, "  ")
	if err != nil {
		return math.MaxInt32
	}
	return len(huntListIndentPrefix) + len(blob) + len(",\n")
}

// boundEncodedList keeps the longest prefix of an already ordered list that
// fits max bytes.
//
// It is deliberately confined to the three lists in a hunt result that restate
// something the artifact still holds in full: a hunt's aggregate findings, its
// aggregate suggestions, and a case's cleanup error prose. Dropping the tail of
// one of those costs a reader a repetition. Nothing a hunt derives is computed
// from them, which is the property that makes a byte bound legitimate, and
// which is why no list canonicalHuntReport keeps for the derive path is bounded
// this way.
func boundEncodedList[T any](items []T, max int) []T {
	total := len("[]")
	for i := range items {
		total += huntEncodedElementSize(items[i])
		if total > max {
			return items[:i]
		}
	}
	return items
}

// huntEncodedListSize is what one top-level list of a hunt result accounts for:
// the two bytes an empty list occupies plus the weight of every element. It is
// the same accounting boundEncodedList bounds a section by.
func huntEncodedListSize[T any](items []T) int {
	total := len("[]")
	for i := range items {
		total += huntEncodedElementSize(items[i])
	}
	return total
}

// huntRunSummarySize is how many bytes a hunt result costs outside its three
// weighed lists: the scalar run metadata and the coverage model, encoded
// exactly as writeJSON encodes them, with each list reduced to the two bytes of
// an empty one. Emptying the lists rather than dropping them keeps their
// property names and punctuation in the measurement, so the summary is charged
// for the structure it contributes to the document.
func huntRunSummarySize(r *HuntResult) (int, error) {
	summary := *r
	summary.Findings, summary.Suggestions, summary.Cases = []HuntFinding{}, []HuntSuggestion{}, []HuntCaseResult{}
	blob, err := json.MarshalIndent(&summary, "", "  ")
	if err != nil {
		return 0, err
	}
	// writeJSON encodes through json.Encoder.Encode, which ends the document
	// with a newline MarshalIndent does not write.
	return len(blob) + len("\n"), nil
}

// checkHuntCaseCardinality holds one case result to the model cardinalities.
//
// It is the loud half of the design in hunt_canonical.go. Canonicalization
// keeps every row of every semantic list, so a case that somehow carries more
// rows than the hunt model can produce is not trimmed to fit: it is refused
// here, named list by list, both where a hunt result is written and where an
// untrusted one is read. A case over one of these ceilings is a defect in this
// program or a document no hunt wrote, and either way losing rows quietly would
// change what the case means.
//
// It is also what bounds the decoder. Every ceiling below is checked against a
// length the decoder already materialized, and the ceilings are what make
// HuntMaxCaseResultBytes a real ceiling rather than an average.
func checkHuntCaseCardinality(item *HuntCaseResult) error {
	over := func(list string, n, max int) error {
		if n <= max {
			return nil
		}
		return fmt.Errorf("hunt case %d carries %d %s, over the model maximum of %d",
			item.Manifest.Case, n, list, max)
	}
	checks := []error{
		over("mutations", len(item.Manifest.Mutations), huntMaxCaseMutations),
		over("observed faults", len(item.Truth.ObservedFaults), huntMaxObservedFaults),
		over("findings", len(item.Findings), huntMaxCaseFindings),
	}
	if report := item.Report; report != nil {
		checks = append(checks,
			over("topology nodes", len(report.Topology), huntMaxTopologyNodes),
			over("faults", len(report.Faults), huntMaxReportFaults),
			over("timeline events", len(report.Timeline), huntMaxTimelineEvents),
			over("tests", len(report.Tests), huntMaxCanonicalTests),
			over("suggestions", len(report.Suggestions), huntMaxReportSuggestions))
		for _, node := range report.Topology {
			checks = append(checks,
				over("node interfaces", len(node.Interfaces), huntMaxNodeInterfaces),
				over("node routes", len(node.Routes), huntMaxNodeRoutes))
		}
		for _, test := range report.Tests {
			if test.Diagnosis == nil {
				continue
			}
			checks = append(checks,
				over("diagnosis checks", len(test.Diagnosis.Checks), huntMaxDiagnosisChecks),
				over("diagnosis findings", len(test.Diagnosis.Findings), huntMaxDiagnosisFindings))
		}
		checks = append(checks, checkHuntEvidenceCardinality(report.Evidence, over)...)
	}
	// The fingerprint is derived from the tests above rather than stored
	// independently, so its own two lists follow from their ceilings.
	checks = append(checks,
		over("fingerprint verdicts", len(item.DiagnosisFingerprint.Verdicts), huntMaxCanonicalTests),
		over("fingerprint probes", len(item.DiagnosisFingerprint.Probes), huntMaxCanonicalTests*huntMaxDiagnosisChecks))
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	return nil
}

func checkHuntEvidenceCardinality(e Evidence, over func(string, int, int) error) []error {
	out := []error{
		over("resolver lookups", len(e.ResolverLookups), huntMaxResolverLookups),
		over("DNS queries", len(e.DNSQueries), huntMaxCanonicalDNSQueries),
		over("SOCKS requests", len(e.SOCKSRequests), huntMaxSOCKSRequests),
		over("TLS handshakes", len(e.TLS), huntMaxTLSHandshakes),
		over("service replies", len(e.ServiceReplies), huntMaxServiceReplies),
		over("TCP resets", len(e.TCPResets), huntMaxTCPResets),
		over("packet conditions", len(e.PacketConditions), huntMaxPacketConditions),
		over("packet drops", len(e.PacketDrops), huntMaxPacketDrops),
		over("links", len(e.Links), huntMaxLinks),
		over("routes", len(e.Routes), huntMaxRouteEvidence),
		over("route tables", len(e.RouteTables), huntMaxRouteTables),
		over("routers", len(e.Routers), huntMaxRouters),
		over("controlled targets", len(e.ControlledTargets), huntMaxControlledTargets),
		over("family reachability records", len(e.FamilyReachability), huntMaxFamilyReachability),
		// The two lists canonicalHuntEvidence drops rather than projects. A
		// document that carries them is not one a hunt wrote.
		over("aggregated DNS records", len(e.DNS), 0),
		over("service states", len(e.ServiceStates), 0),
	}
	for _, item := range e.ResolverLookups {
		out = append(out, over("lookup addresses", len(item.Addresses), huntMaxLookupAddresses))
	}
	for _, item := range e.TLS {
		out = append(out, over("certificate names", len(item.CertificateDNS), huntMaxCertificateNames))
	}
	for _, table := range e.RouteTables {
		out = append(out, over("kernel routes", len(table.Routes), huntMaxKernelRoutes))
	}
	for _, item := range e.ControlledTargets {
		out = append(out, over("target path hops", len(item.Via), huntMaxViaHops))
	}
	for _, item := range e.FamilyReachability {
		out = append(out, over("family path hops", len(item.Via), huntMaxViaHops))
	}
	return out
}

// checkHuntResultBudget refuses a hunt result the budget does not cover. It is
// what makes the write side of that budget hold in production rather than only
// under the tests that measure it: a section that grows past its ceiling, a
// scalar field nobody budgeted for, or a registry that gained hundreds of rows
// stops the artifact from being written instead of producing one this program's
// own merge command would reject.
//
// The accounting is the document. A hunt result is its run summary plus its
// three lists, each list costs the two bytes of an empty one plus the weight of
// its elements, and that is exactly what the summary charges for an emptied
// list, so summary plus sections is the encoded length. The one inexactness is
// two bytes per list that is empty rather than absent, which the sum
// overstates, so a result this accepts is never larger than it measured.
func checkHuntResultBudget(r *HuntResult) error {
	if len(r.Cases) > HuntMaxCases {
		return fmt.Errorf("hunt result holds %d case results, over the maximum of %d",
			len(r.Cases), HuntMaxCases)
	}
	// One weighing per case, carried into the section total, because encoding a
	// case is the expensive part of this check and the section total is exactly
	// the sum of what was already weighed.
	cases := len("[]")
	for i := range r.Cases {
		if err := checkHuntCaseCardinality(&r.Cases[i]); err != nil {
			return err
		}
		size := huntEncodedElementSize(r.Cases[i])
		if size > HuntMaxCaseResultBytes {
			return fmt.Errorf("hunt case %d result is %d bytes, over the maximum of %d",
				r.Cases[i].Manifest.Case, size, HuntMaxCaseResultBytes)
		}
		cases += size
	}
	findings := huntEncodedListSize(r.Findings)
	if findings > huntMaxAggregateFindingsBytes {
		return fmt.Errorf("hunt findings are %d bytes, over the maximum of %d",
			findings, huntMaxAggregateFindingsBytes)
	}
	suggestions := huntEncodedListSize(r.Suggestions)
	if suggestions > huntMaxAggregateSuggestionsBytes {
		return fmt.Errorf("hunt suggestions are %d bytes, over the maximum of %d",
			suggestions, huntMaxAggregateSuggestionsBytes)
	}
	if cases > huntMaxCasesBytes {
		return fmt.Errorf("hunt case results are %d bytes, over the maximum of %d",
			cases, huntMaxCasesBytes)
	}
	summary, err := huntRunSummarySize(r)
	if err != nil {
		return err
	}
	if summary > huntMaxRunSummaryBytes {
		return fmt.Errorf("hunt run summary is %d bytes, over the maximum of %d",
			summary, huntMaxRunSummaryBytes)
	}
	if total := summary + findings + suggestions + cases; total > HuntMaxResultBytes {
		return fmt.Errorf("hunt result is %d bytes, over the maximum of %d", total, HuntMaxResultBytes)
	}
	return nil
}
