package simulation

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// Code is semantic failure identity, never a sentence selected from a report.
// Detail is human evidence. Reducers preserve Property + Code + Relation.
type LabFuzzViolation struct{ Property, Code, Detail string }
type LabFuzzProperty struct {
	Name       string
	Applicable func(LabFuzzCase, []LabReport) bool
	Evaluate   func(context.Context, LabFuzzCase, []LabReport) ([]LabFuzzViolation, error)
}

func labViolation(code, detail string) []LabFuzzViolation {
	return []LabFuzzViolation{{Code: code, Detail: detail}}
}
func labEvidenceEqual(a, b LabReport) bool {
	if len(a.Views) != len(b.Views) {
		return false
	}
	for i, x := range a.Views {
		y := b.Views[i]
		if !labEqual(x.Measured, y.Measured) || !labEqual(x.Snapshot.Checks, y.Snapshot.Checks) || !labEqual(x.Snapshot.Target, y.Snapshot.Target) || !labEqual(x.Snapshot.Options, y.Snapshot.Options) {
			return false
		}
	}
	return true
}
func labInterpretationEqual(a, b LabReport) bool {
	if len(a.Views) != len(b.Views) {
		return false
	}
	for i, x := range a.Views {
		if !labEqual(x.Snapshot.Diagnosis, b.Views[i].Snapshot.Diagnosis) {
			return false
		}
	}
	return labEqual(a.TwoSided, b.TwoSided) && labEqual(a.Comparison, b.Comparison)
}

func LabFuzzProperties() []LabFuzzProperty {
	always := func(LabFuzzCase, []LabReport) bool { return true }
	return []LabFuzzProperty{
		{"determinism", always, func(ctx context.Context, c LabFuzzCase, r []LabReport) ([]LabFuzzViolation, error) {
			for i, s := range c.Worlds {
				again, err := RunLab(ctx, s)
				if err != nil {
					return nil, err
				}
				if !labEqual(r[i], again) {
					return labViolation("report-changed", "identical world produced different report, including traces and snapshots"), nil
				}
			}
			return nil, nil
		}},
		// RunLab already compares full native Interpret with ReplaySnapshot after
		// canonical snapshot encoding. This named evaluation also poisons history.
		{"replay-equivalence", always, func(_ context.Context, c LabFuzzCase, r []LabReport) ([]LabFuzzViolation, error) {
			for _, rep := range r {
				for _, v := range rep.Views {
					s := v.Snapshot
					before, err := diagnostic.ReplaySnapshot(s)
					if err != nil {
						return nil, err
					}
					s.Diagnosis.Summary = "untrusted historical interpretation"
					s.Diagnosis.Findings = nil
					after, err := diagnostic.ReplaySnapshot(s)
					if err != nil {
						return nil, err
					}
					if !labEqual(before, after) {
						return labViolation("historical-diagnosis-read", "replay depended on historical diagnosis"), nil
					}
				}
			}
			return nil, nil
		}},
		{"unsupported-claim-safety", always, func(_ context.Context, c LabFuzzCase, r []LabReport) ([]LabFuzzViolation, error) {
			var out []LabFuzzViolation
			for _, rep := range r {
				for _, v := range rep.Views {
					d, err := diagnostic.ReplaySnapshot(v.Snapshot)
					if err != nil {
						return nil, err
					}
					for _, p := range ValidateLabEvidence(v.Snapshot, d) {
						out = append(out, LabFuzzViolation{Code: p, Detail: v.Node + ": " + p})
					}
				}
			}
			return out, nil
		}},
		{"ground-truth-isolation", always, func(ctx context.Context, c LabFuzzCase, r []LabReport) ([]LabFuzzViolation, error) {
			for i, s := range c.Worlds {
				s = labCopy(s)
				s.Name = "renamed"
				s.Description = "hidden label"
				s.BlindSpots = []string{"annotation"}
				s.KnownIssues = []string{"not an oracle"}
				for j := range s.Faults {
					s.Faults[j].ID = fmt.Sprintf("hidden%d", j)
					s.Faults[j].Scope = "hidden"
					s.Faults[j].Layer = "dns"
					s.Faults[j].Localizable = !s.Faults[j].Localizable
				}
				for j := range s.Views {
					s.Views[j].Expected = LabExpected{Verdict: "dns"}
				}
				changed, err := RunLab(ctx, s)
				if err != nil {
					return nil, err
				}
				if !labEvidenceEqual(r[i], changed) || !labInterpretationEqual(r[i], changed) {
					return labViolation("metadata-leak", "truth or expectation metadata changed evidence or interpretation"), nil
				}
			}
			return nil, nil
		}},
		{"unobservable-perturbation", always, func(ctx context.Context, c LabFuzzCase, r []LabReport) ([]LabFuzzViolation, error) {
			for i, s := range c.Worlds {
				s = labCopy(s)
				// No interfaces connect this segment to any existing segment. The node
				// cannot forward and none of its addresses appear in an existing route.
				s.Network.Topology.Segments = append(s.Network.Topology.Segments, Segment{Name: "unobserved", IPv4: "192.0.2.0/24"})
				s.Network.Topology.Nodes = append(s.Network.Topology.Nodes, Node{Name: "unobserved", Interfaces: []Interface{{Segment: "unobserved", IPv4: "192.0.2.1/24"}}, Services: []Service{{Name: "unobserved", Type: ServiceHTTP, Port: 80}}})
				changed, err := RunLab(ctx, s)
				if err != nil {
					return nil, err
				}
				if !labEvidenceEqual(r[i], changed) {
					return labViolation("isolated-node-observed", "disconnected node changed production inputs (model/boundary defect)"), nil
				}
				if !labInterpretationEqual(r[i], changed) {
					return labViolation("equal-inputs-different-interpretation", "disconnected node changed interpretation despite equal inputs"), nil
				}
			}
			return nil, nil
		}},
		{"two-sided-symmetry", func(c LabFuzzCase, r []LabReport) bool { return len(r[0].Views) == 2 }, func(_ context.Context, c LabFuzzCase, r []LabReport) ([]LabFuzzViolation, error) {
			rep := r[0]
			a := *rep.TwoSided
			b, err := compare.TwoSidedSnapshots(rep.Views[1].Snapshot, rep.Views[0].Snapshot)
			if err != nil {
				return nil, err
			}
			x, y := labSideSemantics(a, false), labSideSemantics(b, true)
			for _, field := range []struct {
				name string
				a, b any
			}{
				{"identity", x.ID, y.ID}, {"placement", x.Side, y.Side}, {"ambiguity", x.Ambiguous, y.Ambiguous},
				{"target", x.SameTarget, y.SameTarget}, {"evidence", x.Evidence, y.Evidence},
				{"alternatives", x.Alternatives, y.Alternatives}, {"caveats", x.Caveats, y.Caveats},
				{"rows", x.Rows, y.Rows}, {"vantage-a", a.A, b.B}, {"vantage-b", a.B, b.A},
			} {
				if !labEqual(field.a, field.b) {
					return labViolation("swap:"+field.name, fmt.Sprintf("forward=%+v reverse=%+v", field.a, field.b)), nil
				}
			}
			return nil, nil
		}},
		// Stable causes are observations the report must carry faithfully when
		// both measured sides supplied them. This is an information-preservation
		// invariant, not the inverse of observational equivalence: no diagnosis,
		// placement or root cause is required to change. It reads only artifacts,
		// never simulator truth, and implements no diagnosis decision tree.
		{"two-sided-cause-preservation", func(_ LabFuzzCase, r []LabReport) bool { return len(r[0].Views) == 2 }, func(_ context.Context, _ LabFuzzCase, reports []LabReport) ([]LabFuzzViolation, error) {
			for _, r := range reports {
				if r.TwoSided == nil {
					continue
				}
				for _, a := range r.Views[0].Snapshot.Checks {
					if a.Cause == "" || !slices.Contains([]string{"PASS", "WARN", "FAIL"}, a.Status) {
						continue
					}
					other := slices.IndexFunc(r.Views[1].Snapshot.Checks, func(b snapshot.Check) bool { return b.ID == a.ID })
					if other < 0 {
						continue
					}
					b := r.Views[1].Snapshot.Checks[other]
					if b.Cause == "" || !slices.Contains([]string{"PASS", "WARN", "FAIL"}, b.Status) {
						continue
					}
					preserved := slices.ContainsFunc(r.TwoSided.Checks, func(row compare.SideRow) bool {
						return row.ID == a.ID && slices.ContainsFunc(row.Evidence, func(e compare.EvidenceComparison) bool {
							return e.Dimension == "cause" && len(e.A) == 1 && len(e.B) == 1 &&
								e.A[0].Value == a.Cause && e.B[0].Value == b.Cause
						})
					})
					if !preserved {
						return labViolation("observed-causes-lost", a.ID+": report must retain both recorded causes"), nil
					}
				}
			}
			return nil, nil
		}},
		{"fault-commutativity", func(c LabFuzzCase, r []LabReport) bool { return labIndependent(c.Worlds[0].Faults) }, func(ctx context.Context, c LabFuzzCase, r []LabReport) ([]LabFuzzViolation, error) {
			s := labCopy(c.Worlds[0])
			slices.Reverse(s.Faults)
			other, err := RunLab(ctx, s)
			if err != nil {
				return nil, err
			}
			if !labEvidenceEqual(r[0], other) {
				return labViolation("independent-order-changed-inputs", "disjoint service replacements produced order-dependent observations"), nil
			}
			return nil, nil
		}},
		{"observational-equivalence", labPairApplicable, func(_ context.Context, c LabFuzzCase, r []LabReport) ([]LabFuzzViolation, error) {
			if !labInterpretationEqual(r[0], r[1]) {
				return labViolation("equal-inputs-different-interpretation", c.Relation), nil
			}
			return nil, nil
		}},
		{"counterfactual-indistinguishability", labPairApplicable, func(_ context.Context, c LabFuzzCase, r []LabReport) ([]LabFuzzViolation, error) {
			return labSilenceClaims(r[0]), nil
		}},
	}
}
func labPairApplicable(c LabFuzzCase, r []LabReport) bool {
	if c.Relation != "endpoint-vs-transit-silence" || len(r) != 2 || !labEvidenceEqual(r[0], r[1]) {
		return false
	}
	// Require both distinct faults to have affected an actual target exchange.
	for _, rep := range r {
		witness := false
		for _, x := range rep.Views[0].Trace {
			if x.Probe == "target_tcp" && x.Outcome == "timeout" && len(x.MatchedFaults) > 0 {
				witness = true
			}
		}
		if !witness {
			return false
		}
	}
	return true
}
func labSilenceClaims(r LabReport) []LabFuzzViolation {
	var out []LabFuzzViolation
	for _, v := range r.Views {
		for _, f := range v.Snapshot.Diagnosis.Findings {
			// These two claims mean unlocalized silence, not a family/address contrast
			// or explicit refusal. We do not assert that either must be emitted.
			if f.ID == string(diagnostic.DiagnosisTargetUnreachable) || f.ID == string(diagnostic.DiagnosisLocalDeviceUnreachable) {
				if f.Confidence == string(diagnostic.ConfidenceHigh) || f.Confidence == string(diagnostic.ConfidenceMedium) {
					out = append(out, LabFuzzViolation{Code: "silence-causal-confidence:" + f.ID, Detail: "endpoint policy and transit filtering produced identical inputs; confidence=" + f.Confidence})
				}
			}
		}
	}
	return out
}

// Deliberately conservative independence: different service objects, with no
// packet impairments or route mutation. Conflicting packet filters are ordered.
func labIndependent(f []LabFault) bool {
	if len(f) < 2 {
		return false
	}
	seen := map[string]bool{}
	for _, x := range f {
		if x.Service == nil || seen[x.Service.Name] {
			return false
		}
		seen[x.Service.Name] = true
	}
	return true
}

type labSideMeaning struct {
	ID, Side                        string
	Ambiguous, SameTarget           bool
	Evidence, Alternatives, Caveats []string
	Rows                            []compare.SideRow
}

func labSideSemantics(t compare.TwoSided, swap bool) labSideMeaning {
	d := t.Diagnosis
	rewrite := func(s string) string {
		if swap {
			return strings.NewReplacer("side A", "side B", "side B", "side A").Replace(s)
		}
		return s
	}
	// Replacement is simultaneous, including already substituted placeholders.
	if swap {
		switch d.Side {
		case compare.SideA:
			d.Side = compare.SideB
		case compare.SideB:
			d.Side = compare.SideA
		}
	}
	alts := append([]string(nil), d.Alternatives...)
	for i := range alts {
		alts[i] = rewrite(alts[i])
	}
	slices.Sort(alts)
	evidence := append([]string(nil), d.Evidence...)
	slices.Sort(evidence)
	rows := append([]compare.SideRow(nil), t.Checks...)
	for i := range rows {
		if swap {
			rows[i].A, rows[i].B = rows[i].B, rows[i].A
			rows[i].Evidence = slices.Clone(rows[i].Evidence)
			for j := range rows[i].Evidence {
				e := &rows[i].Evidence[j]
				e.A, e.B = e.B, e.A
			}
		}
	}
	slices.SortFunc(rows, func(a, b compare.SideRow) int { return strings.Compare(a.ID, b.ID) })
	caveats := append([]string(nil), t.Caveats...)
	for i := range caveats {
		caveats[i] = rewrite(caveats[i])
	}
	slices.Sort(caveats)
	return labSideMeaning{d.ID, d.Side, d.Ambiguous, t.SameTarget, evidence, alts, caveats, rows}
}

func EvaluateLabFuzz(ctx context.Context, c LabFuzzCase, property string) ([]LabFuzzViolation, map[string]int, error) {
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}
	var reports []LabReport
	for _, s := range c.Worlds {
		r, err := RunLab(ctx, s)
		if err != nil {
			return nil, nil, err
		}
		reports = append(reports, r)
	}
	counts := map[string]int{}
	var failures []LabFuzzViolation
	found := property == ""
	for _, p := range LabFuzzProperties() {
		if property != "" && property != p.Name {
			continue
		}
		found = true
		if !p.Applicable(c, reports) {
			continue
		}
		counts[p.Name]++
		v, err := p.Evaluate(ctx, c, reports)
		if err != nil {
			return nil, counts, err
		}
		for _, f := range v {
			f.Property = p.Name
			failures = append(failures, f)
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("unknown property %q", property)
	}
	return failures, counts, nil
}
