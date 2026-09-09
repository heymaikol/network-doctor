package simulation

import (
	"encoding/json"
	"slices"
	"strings"
)

// Hunt coverage answers a different question from hunt findings: not "did this
// run disagree with Network Doctor" but "how much ground did it stand on while
// agreeing". A clean hunt over an operator the base scenario cannot host, over
// a fault the kernel never applied, or over cases the condition oracle could
// never compare, is clean about nothing, and the counters here are what let a
// reader tell those apart from a hunt that genuinely exercised its universe.
//
// Nothing here is an accusation. An operator that was never applicable is a
// fact about the base scenario, an operator that was generated and never
// observed is a fact about the simulator, and neither is a defect in Network
// Doctor. Coverage is also deliberately aggregate: every number is derived from
// the case results a hunt already carries, so a case report stays the size it
// was and a merged hunt recomputes the same totals as the unsharded one.

// HuntOperatorCoverage is one mutation operator's accounting for this hunt.
// Applicable, generated and observed are three separate claims in descending
// order of strength: the base could host it, the generator drew it, and the
// executed simulation independently showed its effect.
type HuntOperatorCoverage struct {
	ID string `json:"id"`
	// Contract is the operator's finding contract, which is what decides its
	// lane. It is carried here so a reader can tell an oracle-backed operator
	// from a stress one without holding the registry in their head.
	Contract   string `json:"contract"`
	Applicable bool   `json:"applicable"`
	Generated  int    `json:"generated_cases"`
	Observed   int    `json:"observed_cases"`
}

// HuntConditionCoverage is one oracle condition's accounting. Established
// counts the cases whose simulator evidence put the condition on the network
// with the oracle in a position to compare; recognized counts how many of those
// the diagnosis then named. The difference is exactly the false negatives this
// hunt reported for that condition, and a reachable condition established zero
// times is a hunt that never asked the question at all.
type HuntConditionCoverage struct {
	Condition NetworkCondition `json:"condition"`
	Family    string           `json:"family,omitempty"`
	// Reachable means this hunt could put the condition on the network: an
	// applicable operator declares it as its finding contract, or a case
	// actually established it. Faults reach conditions they never declared,
	// so this is a floor rather than the full reachable set: deleting the
	// default route also makes IPv4 unreachable, and only the second half of
	// this test sees that.
	Reachable   bool `json:"reachable"`
	Established int  `json:"established_cases"`
	Recognized  int  `json:"recognized_cases"`
	// Reverse coverage only counts rules with a positive contradiction test.
	// Unverified is a limit of the oracle, never a diagnosis defect.
	Claimed      int `json:"claimed_cases,omitempty"`
	Contradicted int `json:"contradicted_cases,omitempty"`
	Unverified   int `json:"unverified_claim_cases,omitempty"`
}

// HuntCoverage is the aggregate. Operators and Conditions are in registry
// order, which is stable API, so two runs of the same hunt emit the same rows
// in the same places.
type HuntCoverage struct {
	Operators  []HuntOperatorCoverage  `json:"operators"`
	Conditions []HuntConditionCoverage `json:"conditions"`
	// MutationSets counts distinct combinations of operator ids, which is the
	// semantic layer: how many different kinds of network this hunt built.
	MutationSets int `json:"mutation_sets"`
	// DistinctExperiments counts distinct fully materialized mutation lists.
	// Two cases sharing a set but not a parameter are two experiments; two
	// cases sharing both are one experiment run twice, whatever their case
	// numbers say.
	DistinctExperiments int `json:"distinct_experiments"`
	// LastNewSetCase is the global case number of the last case that
	// introduced a combination no earlier case had, which is where semantic
	// discovery saturated. -1 when no case did, including an empty hunt.
	LastNewSetCase int `json:"last_new_mutation_set_case"`
	// ExecutedCases counts cases that actually ran. Carried here so the model
	// is self-describing where triage embeds it alone, and so a dry run cannot
	// report that nothing was observed when nothing was ever run.
	ExecutedCases int `json:"executed_cases"`
	// OracleCases counts executed cases the condition oracle could compare at
	// all. Persistent shaping and timed path transitions deliberately are not
	// final-state comparisons, so a hunt full of them proves less than its
	// executed count suggests.
	OracleCases int `json:"oracle_comparable_cases"`
	// Cardinality[i] counts the cases carrying i+1 mutations, so the slice is
	// exactly as long as the largest case this hunt built. The fault ceiling
	// says what was asked for; this says what the base could deliver, and the
	// two differ whenever conflicting operators leave a ceiling unreachable.
	Cardinality []int `json:"mutation_cardinality"`
	// MultiFaultCases counts cases whose evidence independently confirmed two
	// or more faults on the same network. It is what the fault ceiling actually
	// buys, and the only number that says so: a case can establish several
	// oracle conditions from a single fault, since deleting a default route
	// takes IPv4 off the internet as well, so counting conditions would credit
	// a hunt that tested no interaction at all. Generated cardinality above
	// says what was asked for; this says what arrived together.
	MultiFaultCases int `json:"multi_fault_cases"`
}

// Hunt coverage gap kinds. A gap is a limit on what a clean result means, never
// a claim about Network Doctor.
const (
	HuntGapOperatorNotGenerated    = "operator_not_generated"
	HuntGapOperatorNotObserved     = "operator_not_observed"
	HuntGapConditionNotEstablished = "condition_not_established"
)

// HuntCoverageGap names one applicable thing this hunt did not reach.
type HuntCoverageGap struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Gaps is the derived reading of the rows above, in a fixed order: operators
// the base could host and the generator never drew, then operators drawn whose
// effect nothing independently observed, then oracle conditions an applicable
// operator promised and no case established.
func (c HuntCoverage) Gaps() []HuntCoverageGap {
	var out []HuntCoverageGap
	for _, op := range c.Operators {
		if op.Applicable && op.Generated == 0 {
			out = append(out, HuntCoverageGap{Kind: HuntGapOperatorNotGenerated, ID: op.ID})
		}
	}
	if c.ExecutedCases == 0 {
		// A hunt that ran nothing observed nothing, which is a fact about the
		// dry run rather than a limit on a result it never produced.
		return out
	}
	for _, op := range c.Operators {
		if op.Generated > 0 && op.Observed == 0 {
			out = append(out, HuntCoverageGap{Kind: HuntGapOperatorNotObserved, ID: op.ID})
		}
	}
	for _, condition := range c.Conditions {
		if condition.Reachable && condition.Established == 0 {
			out = append(out, HuntCoverageGap{Kind: HuntGapConditionNotEstablished, ID: string(condition.Condition)})
		}
	}
	return out
}

// Counts summarizes the operator and condition rows the way a human reads them:
// how many were reachable, how many were reached, and how far each got.
func (c HuntCoverage) Counts() (applicable, generated, observed, conditions, established int) {
	for _, op := range c.Operators {
		if op.Applicable {
			applicable++
		}
		if op.Generated > 0 {
			generated++
		}
		if op.Observed > 0 {
			observed++
		}
	}
	for _, condition := range c.Conditions {
		if condition.Reachable {
			conditions++
		}
		if condition.Established > 0 {
			established++
		}
	}
	return
}

// applicableHuntOperators is the universe one hunt could have drawn from: the
// lane's operators filtered by what the base scenario can host. It is resolved
// from the base's own library definition rather than from the cases, because
// the whole point is to report what a hunt could have generated and did not.
// An unresolvable base leaves every operator unmarked rather than guessing.
func applicableHuntOperators(version string, lane HuntLane, baseID string) map[string]bool {
	out := map[string]bool{}
	operators, err := huntOperatorsForLane(version, lane)
	if err != nil {
		return out
	}
	base, err := LibraryScenario(baseID)
	if err != nil {
		return out
	}
	validated := cloneScenario(base)
	canonicalScenarioInput(validated)
	if err := validated.Validate(); err != nil {
		return out
	}
	for _, op := range operators {
		if op.applicable(validated) {
			out[op.id] = true
		}
	}
	return out
}

// huntCoverageFor derives the whole model from case results. It reads nothing a
// merged hunt does not also hold, which is what makes merged coverage equal to
// the unsharded hunt's rather than something reassembled from partial sums.
func huntCoverageFor(version string, lane HuntLane, baseID string, cases []HuntCaseResult) HuntCoverage {
	coverage := HuntCoverage{Operators: []HuntOperatorCoverage{}, Conditions: []HuntConditionCoverage{},
		Cardinality: []int{}, LastNewSetCase: -1}
	applicable := applicableHuntOperators(version, lane, baseID)
	generated, observed := map[string]int{}, map[string]int{}
	established, recognized := map[NetworkCondition]int{}, map[NetworkCondition]int{}
	claimed, contradicted, unverified := map[NetworkCondition]int{}, map[NetworkCondition]int{}, map[NetworkCondition]int{}
	sets, experiments := map[string]bool{}, map[string]bool{}
	for _, item := range cases {
		if item.Status != "generated" {
			coverage.ExecutedCases++
		}
		ids := make([]string, 0, len(item.Manifest.Mutations))
		for _, mutation := range item.Manifest.Mutations {
			generated[mutation.ID]++
			ids = append(ids, mutation.ID)
		}
		for _, id := range item.Truth.ObservedFaults {
			observed[id]++
		}
		if len(item.Truth.ObservedFaults) > 1 {
			coverage.MultiFaultCases++
		}
		slices.Sort(ids)
		if key := strings.Join(ids, "\x00"); !sets[key] {
			sets[key] = true
			coverage.LastNewSetCase = item.Manifest.Case
		}
		blob, _ := json.Marshal(item.Manifest.Mutations)
		experiments[string(blob)] = true
		if n := len(item.Manifest.Mutations); n > 0 {
			for len(coverage.Cardinality) < n {
				coverage.Cardinality = append(coverage.Cardinality, 0)
			}
			coverage.Cardinality[n-1]++
		}
		caseEstablished, caseRecognized, comparable := caseConditions(item.Report, item.Truth)
		if !comparable {
			continue
		}
		coverage.OracleCases++
		observation := caseObservation(item.Report, item.Truth)
		for _, rule := range conditionOracle {
			if rule.contradicted == nil || !slices.Contains(caseRecognized, rule.condition) {
				continue
			}
			claimed[rule.condition]++
			if rule.contradicted(observation) {
				contradicted[rule.condition]++
			} else if !slices.Contains(caseEstablished, rule.condition) {
				unverified[rule.condition]++
			}
		}
		for _, condition := range caseEstablished {
			established[condition]++
			if slices.Contains(caseRecognized, condition) {
				recognized[condition]++
			}
		}
	}
	coverage.MutationSets, coverage.DistinctExperiments = len(sets), len(experiments)
	if operators, err := huntOperatorsForLane(version, lane); err == nil {
		for _, op := range operators {
			coverage.Operators = append(coverage.Operators, HuntOperatorCoverage{ID: op.id,
				Contract: string(op.contractFor(version)), Applicable: applicable[op.id],
				Generated: generated[op.id], Observed: observed[op.id]})
		}
	}
	for _, rule := range conditionOracle {
		coverage.Conditions = append(coverage.Conditions, HuntConditionCoverage{Condition: rule.condition,
			Family:      rule.family,
			Reachable:   established[rule.condition] > 0 || conditionDeclared(rule.condition, version, lane, applicable),
			Established: established[rule.condition], Recognized: recognized[rule.condition],
			Claimed: claimed[rule.condition], Contradicted: contradicted[rule.condition], Unverified: unverified[rule.condition]})
	}
	return coverage
}

// conditionDeclared reports whether any operator this base could host carries
// this condition as its finding contract. A condition no operator declares and
// no case established is one nothing in this hunt was aiming at, which is the
// difference between "the oracle asked and the answer was fine" and "the
// question was never on the table".
func conditionDeclared(condition NetworkCondition, version string, lane HuntLane, applicable map[string]bool) bool {
	operators, err := huntOperatorsForLane(version, lane)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(operators, func(op mutationOperator) bool {
		return applicable[op.id] && string(op.contractFor(version)) == string(condition)
	})
}
