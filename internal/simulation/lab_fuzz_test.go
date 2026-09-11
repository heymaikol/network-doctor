package simulation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

func TestLabTwoSidedCausePreservationDetectsErasure(t *testing.T) {
	a := snapshot.Snapshot{Schema: snapshot.Schema, Checks: []snapshot.Check{{ID: "tls", Status: snapshot.StatusFail, Cause: "hostname_mismatch"}}}
	b := snapshot.Snapshot{Schema: snapshot.Schema, Checks: []snapshot.Check{{ID: "tls", Status: snapshot.StatusFail, Cause: "timeout"}}}
	sides, err := compare.TwoSidedSnapshots(a, b)
	if err != nil {
		t.Fatal(err)
	}
	r := []LabReport{{Views: []LabObservation{{Snapshot: a}, {Snapshot: b}}, TwoSided: &sides}}
	for _, p := range LabFuzzProperties() {
		if p.Name != "two-sided-cause-preservation" {
			continue
		}
		if !p.Applicable(LabFuzzCase{}, r) {
			t.Fatal("property did not apply")
		}
		if violations, err := p.Evaluate(context.Background(), LabFuzzCase{}, r); err != nil || len(violations) != 0 {
			t.Fatalf("valid report: %v %v", violations, err)
		}
		// Erase only the additive observation dimension, leaving exactly the
		// status/placement reduction this investigation reproduced at HEAD.
		sides.Checks[0].Evidence = nil
		if violations, err := p.Evaluate(context.Background(), LabFuzzCase{}, r); err != nil || len(violations) != 1 {
			t.Fatalf("erasure undetected: %v %v", violations, err)
		}
		return
	}
	t.Fatal("preservation property missing")
}

func TestLabFuzzGenerator(t *testing.T) {
	ctx := context.Background()
	seen := map[string]bool{}
	paired := 0
	applicable := 0
	r := labRandom(0)
	if got := r.next(); got != 0xe220a8397b1dcdaf {
		t.Fatalf("PRNG contract changed: %x", got)
	}
	for i := uint64(0); i < 500; i++ {
		c, err := GenerateLabFuzz(847293, i, 6, true)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		again, err := GenerateLabFuzz(847293, i, 6, true)
		if err != nil || !labEqual(c, again) {
			t.Fatal("case not deterministic", i, err)
		}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		s := labCopy(c.Worlds[0])
		shape, _ := json.Marshal(s)
		seen[string(shape)] = true
		if len(c.Worlds) == 2 {
			paired++
			var reports []LabReport
			for _, w := range c.Worlds {
				rep, err := RunLab(ctx, w)
				if err != nil {
					t.Fatal(err)
				}
				reports = append(reports, rep)
			}
			if labPairApplicable(c, reports) {
				applicable++
			}
		}
		c.Worlds[0].Network.Topology.Nodes[0].Interfaces[0].Segment = "mutated"
		if !labEqual(again.Worlds[0], s) {
			t.Fatal("independent generation aliased")
		}
	}
	if len(seen) < 400 || paired < 20 || applicable < 10 {
		t.Fatalf("insufficient variation: %d pair=%d applicable=%d", len(seen), paired, applicable)
	}
	a, _ := GenerateLabFuzz(1, 0, 4, true)
	b, _ := GenerateLabFuzz(2, 0, 4, true)
	if labEqual(a.Worlds, b.Worlds) {
		t.Fatal("seeds do not vary worlds")
	}
	if _, err := GenerateLabFuzz(0, 0, 13, true); err == nil {
		t.Fatal("unbounded faults accepted")
	}
}

func TestLabFuzzPropertiesAndParallel(t *testing.T) {
	o := LabFuzzOptions{Seed: 847293, Cases: 80, MaxFaults: 4, Workers: 1, TwoSided: true}
	a, err := RunLabFuzz(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	o.Workers = 4
	b, err := RunLabFuzz(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	a.Options.Workers = 4
	if !reflect.DeepEqual(a, b) {
		t.Fatal("parallel result differs")
	}
	// Discoveries are not suppressed by this test. A changed implementation may
	// legitimately find a new defect; deterministic campaign output is the gate.
	for _, x := range a.Failures {
		ok, err := ReplayLabFuzzArtifact(context.Background(), x)
		if err != nil || !ok {
			t.Fatal("discovery did not replay", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunLabFuzz(ctx, o); err == nil {
		t.Fatal("cancellation ignored")
	}
	o.Property = "invented"
	if _, err := RunLabFuzz(context.Background(), o); err == nil {
		t.Fatal("unknown property accepted")
	}
}

func TestLabFuzzReducer(t *testing.T) {
	c, _ := GenerateLabFuzz(1, 0, 0, false)
	// Synthetic reducer predicate, not a claimed Network Doctor defect. Requires
	// one concrete service so topology, routes, answers and other services shrink.
	holds := func(c LabFuzzCase) (bool, error) {
		for _, n := range c.Worlds[0].Network.Topology.Nodes {
			for _, s := range n.Services {
				if s.Name == "target-tls" {
					return true, nil
				}
			}
		}
		return false, nil
	}
	a, attempts, accepted, err := labReduce(context.Background(), c, holds)
	if err != nil {
		t.Fatal(err)
	}
	b, n, m, err := labReduce(context.Background(), c, holds)
	if err != nil || !labEqual(a, b) || attempts != n || accepted != m {
		t.Fatal("reducer nondeterministic")
	}
	if accepted == 0 || len(a.Worlds[0].Network.Topology.Nodes) >= len(c.Worlds[0].Network.Topology.Nodes) || len(a.Worlds[0].Network.Topology.Routes) != 0 {
		t.Fatal("did not reduce", accepted)
	}
	t.Logf("synthetic reduction: nodes %d -> %d; routes %d -> %d; edits %d", len(c.Worlds[0].Network.Topology.Nodes), len(a.Worlds[0].Network.Topology.Nodes), len(c.Worlds[0].Network.Topology.Routes), len(a.Worlds[0].Network.Topology.Routes), accepted)
	for _, edit := range labReductions(a.Worlds[0]) {
		candidate := labCopy(a)
		edit(&candidate.Worlds[0])
		if candidate.Validate() == nil && !labEqual(a, candidate) {
			ok, _ := holds(candidate)
			if ok {
				t.Fatal("not a fixed point")
			}
		}
	}
}

func TestLabFuzzArtifact(t *testing.T) {
	c, _ := GenerateLabFuzz(1, 0, 0, false)
	a := LabFuzzArtifact{Format: labArtifactFormat, Original: c, Minimized: c, Failure: LabFuzzViolation{Property: "determinism", Code: "report-changed"}}
	data, _ := json.Marshal(a)
	decoded, err := DecodeLabFuzzArtifact(data)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := ReplayLabFuzzArtifact(context.Background(), decoded); err != nil || ok {
		t.Fatal("fabricated failure trusted", err)
	}
	for _, bad := range [][]byte{nil, []byte("{}"), append(append([]byte(nil), data...), []byte(" {}")...), append(append([]byte(nil), data...), []byte(" garbage")...), []byte(strings.Replace(string(data), labArtifactFormat, "future", 1)), []byte(strings.Replace(string(data), "\"Format\"", "\"Unknown\"", 1)), make([]byte, (4<<20)+1)} {
		if _, err := DecodeLabFuzzArtifact(bad); err == nil {
			t.Fatal("malformed artifact accepted")
		}
	}
	for _, p := range LabFuzzProperties() {
		if p.Name == "fault-commutativity" && p.Applicable(c, nil) {
			t.Fatal("zero faults commute vacuously")
		}
	}
}

func TestLabFuzzPairAndClaims(t *testing.T) {
	var c LabFuzzCase
	var reports []LabReport
	for i := uint64(0); i < 200; i++ {
		candidate, _ := GenerateLabFuzz(1, i, 4, true)
		if len(candidate.Worlds) != 2 {
			continue
		}
		var rs []LabReport
		for _, s := range candidate.Worlds {
			r, err := RunLab(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			rs = append(rs, r)
		}
		if labPairApplicable(candidate, rs) && slices.ContainsFunc(rs[0].Views[0].Snapshot.Diagnosis.Findings, func(f snapshot.Finding) bool { return f.ID == string(diagnostic.DiagnosisTargetUnreachable) }) {
			c, reports = candidate, rs
			break
		}
	}
	if len(reports) != 2 {
		t.Fatal("no evidence-equal witness")
	}
	if !labInterpretationEqual(reports[0], reports[1]) {
		t.Fatal("pair changed diagnosis")
	}
	// Confidence checker must detect a injected bad claim, but not a measured
	// address/family contrast merely because another address was silent.
	r := labCopy(reports[0])
	found := false
	for i := range r.Views[0].Snapshot.Diagnosis.Findings {
		f := &r.Views[0].Snapshot.Diagnosis.Findings[i]
		if f.ID == string(diagnostic.DiagnosisTargetUnreachable) {
			f.Confidence = "high"
			found = true
		}
	}
	if !found || len(labSilenceClaims(r)) == 0 {
		t.Fatal("bad confidence escaped")
	}
	holds := func(candidate LabFuzzCase) (bool, error) {
		var reports []LabReport
		for _, w := range candidate.Worlds {
			r, err := RunLab(context.Background(), w)
			if err != nil {
				return false, err
			}
			reports = append(reports, r)
		}
		return labPairApplicable(candidate, reports), nil
	}
	reduced, _, accepted, err := labReduce(context.Background(), c, holds)
	if err != nil || accepted == 0 || reduced.Validate() != nil {
		t.Fatal("paired minimization failed", err)
	}
	ok, err := holds(reduced)
	if err != nil || !ok {
		t.Fatal("pair lost its witness", err)
	}
	c.Worlds[1].Faults[0].Network.Node = "resolver"
	if c.Validate() == nil {
		t.Fatal("changed counterfactual relation accepted")
	}
	// Swapping twice is an involution for complete comparison semantics.
	s := LabScenarios()[0]
	s.Views = append(s.Views, s.Views[0])
	s.TwoSided = "none"
	rep, err := RunLab(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !labEqual(labSideSemantics(*rep.TwoSided, false), labSideSemantics(*rep.TwoSided, true)) {
		t.Fatal("identical-side swap changed semantics")
	}
}

func TestLabFuzzFirstFailureIsOrdered(t *testing.T) {
	// Synthetic failures exercise selection/dedup/minimization plumbing only.
	// No fake finding is retained as a diagnostic regression.
	evaluate := func(_ context.Context, c LabFuzzCase, _ string) ([]LabFuzzViolation, map[string]int, error) {
		counts := map[string]int{"determinism": 1}
		if c.Index >= 3 {
			return []LabFuzzViolation{{Property: "determinism", Code: "synthetic"}}, counts, nil
		}
		return nil, counts, nil
	}
	o := LabFuzzOptions{Seed: 1, Cases: 9, MaxFaults: 0, Workers: 1, StopOnFirst: true}
	a, err := runLabFuzz(context.Background(), o, evaluate)
	if err != nil {
		t.Fatal(err)
	}
	o.Workers = 4
	b, err := runLabFuzz(context.Background(), o, evaluate)
	if err != nil {
		t.Fatal(err)
	}
	a.Options.Workers = 4
	if !labEqual(a, b) || a.Cases != 4 || len(a.Failures) != 1 || a.Failures[0].Original.Index != 3 {
		t.Fatal("first failure depends on workers", a.Cases, b.Cases)
	}
	data, err := json.Marshal(a.Failures[0])
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := DecodeLabFuzzArtifact(data)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := replayLabFuzzArtifact(context.Background(), artifact, evaluate); err != nil || !ok {
		t.Fatal("serialized failure did not replay", err)
	}
	o.StopOnFirst = false
	c, err := runLabFuzz(context.Background(), o, evaluate)
	if err != nil {
		t.Fatal(err)
	}
	if c.FailingCases != 6 || c.Violations != 6 || len(c.Failures) != 1 {
		t.Fatal("semantic dedup lost counts")
	}
}

func TestLabFuzzVersionVector(t *testing.T) {
	c, err := GenerateLabFuzz(847293, 4187, 4, true)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(c)
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	const want = "87ccad67c65847f819c60badc80bf9caf89b65f67dd4a70a696c0a65cffc80b0"
	if digest != want {
		t.Fatalf("generator vector changed: %s; review and version deliberate generator changes", digest)
	}
}

func TestLabFuzzGeneratorBounds(t *testing.T) {
	for _, seed := range []uint64{0, 1, ^uint64(0)} {
		for _, maxFaults := range []int{0, 1, 12} {
			for i := uint64(0); i < 100; i++ {
				c, err := GenerateLabFuzz(seed, i, maxFaults, false)
				if err != nil {
					t.Fatalf("seed=%d case=%d max-faults=%d: %v", seed, i, maxFaults, err)
				}
				if len(c.Worlds[0].Faults) > maxFaults || len(c.Worlds[0].Views) != 1 {
					t.Fatal("options ignored")
				}
			}
		}
	}
}
