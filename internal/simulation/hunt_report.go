package simulation

import (
	"fmt"
	"io"
	"strings"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

func (r *HuntResult) WriteJSON(w io.Writer) error { return writeJSON(w, r) }

func (r *HuntResult) WriteText(w io.Writer) {
	fmt.Fprintln(w, "Network Doctor Hunt")
	fmt.Fprintf(w, "\nBase:      %s\nLane:      %s\nSeed:      %d\nCases:     %d\nGenerator: %s\n",
		textsafe.Clean(r.BaseScenario), r.Lane, r.HuntSeed, r.RequestedCases, r.GeneratorVersion)
	if r.Shard != nil {
		fmt.Fprintf(w, "Shard:     %d/%d (zero-based)\n", r.Shard.Index, r.Shard.Count)
	}
	if r.ExecutedCases == 0 {
		fmt.Fprintf(w, "\nGenerated: %d unique case(s); duplicates skipped: %d\n", r.GeneratedCases, r.DuplicateCandidates)
		for _, item := range r.Cases {
			fmt.Fprintf(w, "\nCase %d  seed %d  fingerprint %s\n", item.Manifest.Case, item.Manifest.CaseSeed, item.Manifest.CaseFingerprint)
			for _, mutation := range item.Manifest.Mutations {
				fmt.Fprintf(w, "  %-28s %s\n", mutation.ID, textsafe.Clean(mutation.Description))
			}
		}
	} else {
		fmt.Fprintf(w, "\nCases executed: %d\nClean:          %d\nFindings:       %d\nDuplicates:     %d\n",
			r.ExecutedCases, r.CleanCases, len(r.Findings), r.DuplicateCandidates)
	}
	r.writeCoverage(w)
	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "\nFindings")
		for _, finding := range r.Findings {
			fmt.Fprintf(w, "\n%-8s Case %-6d %s\n", strings.ToUpper(string(finding.Severity)), finding.FirstCase, finding.Code)
			fmt.Fprintf(w, "         %s\n", textsafe.Clean(finding.Summary))
			fmt.Fprintf(w, "         occurrences: %d  cases: %s\n", finding.Occurrences, intList(finding.ExampleCases))
			if finding.Evidence != "" {
				fmt.Fprintf(w, "         evidence: %s\n", textsafe.Clean(finding.Evidence))
			}
			fmt.Fprintf(w, "\n         Reproduce:\n           %s\n", finding.Reproduce.Command())
		}
	}
	if len(r.Suggestions) > 0 {
		fmt.Fprintln(w, "\nSuggested netdoc improvements")
		for i, suggestion := range r.Suggestions {
			fmt.Fprintf(w, "\n%d. %s\n", i+1, textsafe.Clean(suggestion.Description))
			fmt.Fprintf(w, "   code: %s  evidence: %d case(s)  highest severity: %s\n",
				suggestion.Code, suggestion.Evidence, suggestion.HighestSeverity)
			fmt.Fprintf(w, "   first reproduction: %s\n", suggestion.Reproduce.Command())
		}
	}
	if r.FailFastStopped {
		fmt.Fprintln(w, "\nStopped by --fail-fast after the first case with a reportable finding.")
	}
	if r.Error != "" {
		fmt.Fprintf(w, "\nError: %s\n", textsafe.Clean(r.Error))
	}
}

// writeCoverage prints what a clean result cannot say for itself: how much of
// the reachable mutation universe this hunt actually stood on. Counts first,
// because they are the summary; then the gaps, because those are the reasons a
// clean result deserves less confidence than its case count suggests.
func (r *HuntResult) writeCoverage(w io.Writer) {
	coverage := r.Coverage
	applicable, generated, observed, conditions, established := coverage.Counts()
	fmt.Fprintln(w, "\nCoverage")
	fmt.Fprintf(w, "  operators:   %d of %d applicable generated", generated, applicable)
	if r.ExecutedCases > 0 {
		fmt.Fprintf(w, ", %d independently observed", observed)
	}
	fmt.Fprintf(w, "\n  mutations:   %d distinct operator set(s), %d distinct experiment(s) in %d case(s)\n",
		coverage.MutationSets, coverage.DistinctExperiments, len(r.Cases))
	fmt.Fprintf(w, "  faults:      %d generated under a ceiling of %d (%s)", huntFaultsGenerated(coverage), r.MaxFaults,
		huntCardinality(coverage))
	if r.ExecutedCases > 0 {
		fmt.Fprintf(w, ", %d independently observed", huntFaultsObserved(coverage))
	}
	fmt.Fprintln(w)
	if coverage.LastNewSetCase >= 0 {
		fmt.Fprintf(w, "  saturation:  last new operator set at case %d\n", coverage.LastNewSetCase)
	}
	if r.ExecutedCases > 0 {
		fmt.Fprintf(w, "  conditions:  %d of %d reachable oracle condition(s) established", established, conditions)
		fmt.Fprintf(w, "; %d of %d executed case(s) were oracle-comparable\n", coverage.OracleCases, r.ExecutedCases)
		fmt.Fprintf(w, "  interaction: %d executed case(s) carried two or more independently observed faults at once\n",
			coverage.MultiFaultCases)
		var claimed, contradicted, unverified int
		for _, condition := range coverage.Conditions {
			claimed += condition.Claimed
			contradicted += condition.Contradicted
			unverified += condition.Unverified
		}
		fmt.Fprintf(w, "  claims:      %d assessed by reverse rules, %d independently contradicted, %d unverified\n", claimed, contradicted, unverified)
	}
	gaps := coverage.Gaps()
	if len(gaps) == 0 {
		return
	}
	fmt.Fprintln(w, "\n  Coverage gaps (limits on what this result means, not netdoc defects)")
	for _, gap := range gaps {
		fmt.Fprintf(w, "    %-30s %s\n", gap.Kind, textsafe.Clean(gap.ID))
	}
}

func intList(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprint(value)
	}
	return strings.Join(parts, ", ")
}

// The three readings below are sums over rows the coverage model already
// carries, kept here rather than in the model because only the report needs
// them. Generated against observed is the masking: faults the generator wrote
// into the scenario that no independent evidence caught happening, which is
// what says whether a taller fault ceiling bought anything or just built
// networks whose extra faults nobody could reach.
func huntFaultsGenerated(c HuntCoverage) int {
	total := 0
	for i, cases := range c.Cardinality {
		total += (i + 1) * cases
	}
	return total
}

func huntFaultsObserved(c HuntCoverage) int {
	total := 0
	for _, op := range c.Operators {
		total += op.Observed
	}
	return total
}

func huntCardinality(c HuntCoverage) string {
	if len(c.Cardinality) == 0 {
		return "no case carried a fault"
	}
	parts := make([]string, 0, len(c.Cardinality))
	for i, cases := range c.Cardinality {
		parts = append(parts, fmt.Sprintf("%d-fault: %d", i+1, cases))
	}
	return strings.Join(parts, ", ")
}
