package simulation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

type LabFuzzArtifact struct {
	Format             string
	Failure            LabFuzzViolation
	Original           LabFuzzCase
	Minimized          LabFuzzCase
	Attempts, Accepted int
}

const labArtifactFormat = "lab-fuzz-artifact-v1"

// DecodeLabFuzzArtifact accepts one bounded, strictly decoded internal artifact.
// Stored failure text is never trusted as an evaluation result.
func DecodeLabFuzzArtifact(data []byte) (LabFuzzArtifact, error) {
	var a LabFuzzArtifact
	if len(data) > 4<<20 {
		return a, fmt.Errorf("artifact exceeds 4 MiB")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return a, fmt.Errorf("artifact must contain exactly one JSON value")
	}
	if a.Format != labArtifactFormat || a.Failure.Code == "" {
		return a, fmt.Errorf("invalid artifact header")
	}
	known := false
	for _, p := range LabFuzzProperties() {
		known = known || p.Name == a.Failure.Property
	}
	if !known {
		return a, fmt.Errorf("unknown property")
	}
	if err := a.Original.Validate(); err != nil {
		return a, err
	}
	if err := a.Minimized.Validate(); err != nil {
		return a, err
	}
	if a.Original.Relation != a.Minimized.Relation || a.Original.Seed != a.Minimized.Seed || a.Original.Index != a.Minimized.Index {
		return a, fmt.Errorf("artifact provenance or relation changed")
	}
	return a, nil
}
func ReplayLabFuzzArtifact(ctx context.Context, a LabFuzzArtifact) (bool, error) {
	return replayLabFuzzArtifact(ctx, a, EvaluateLabFuzz)
}
func replayLabFuzzArtifact(ctx context.Context, a LabFuzzArtifact, evaluate labFuzzEvaluator) (bool, error) {
	failures, _, err := evaluate(ctx, a.Minimized, a.Failure.Property)
	return slices.ContainsFunc(failures, func(v LabFuzzViolation) bool { return labSameFailure(v, a.Failure) }), err
}
func labSameFailure(a, b LabFuzzViolation) bool { return a.Property == b.Property && a.Code == b.Code }

func minimizeLabFuzz(ctx context.Context, c LabFuzzCase, f LabFuzzViolation, evaluate labFuzzEvaluator) (LabFuzzArtifact, error) {
	a := LabFuzzArtifact{Format: labArtifactFormat, Failure: f, Original: labCopy(c)}
	holds := func(candidate LabFuzzCase) (bool, error) {
		v, _, err := evaluate(ctx, candidate, f.Property)
		return slices.ContainsFunc(v, func(x LabFuzzViolation) bool { return labSameFailure(x, f) }), err
	}
	ok, err := holds(c)
	if err != nil {
		return a, err
	}
	if !ok {
		return a, fmt.Errorf("original no longer reproduces failure")
	}
	a.Minimized, a.Attempts, a.Accepted, err = labReduce(ctx, c, holds)
	return a, err
}

// Greedy deterministic delta reduction to a fixed point. Every edit is tested
// against structural validity, applicability and the original semantic code.
// Paired worlds receive identical base edits; their distinguishing faults stay.
func labReduce(ctx context.Context, c LabFuzzCase, holds func(LabFuzzCase) (bool, error)) (LabFuzzCase, int, int, error) {
	attempts, accepted := 0, 0
	for {
		changed := false
		for _, edit := range labReductions(c.Worlds[0]) {
			if err := ctx.Err(); err != nil {
				return c, attempts, accepted, err
			}
			candidate := labCopy(c)
			for i := range candidate.Worlds {
				edit(&candidate.Worlds[i])
			}
			if candidate.Relation != c.Relation || labEqual(c, candidate) {
				continue
			}
			attempts++
			if candidate.Validate() != nil {
				continue
			}
			ok, err := holds(candidate)
			if err != nil {
				return c, attempts, accepted, err
			}
			if ok {
				c = candidate
				accepted++
				changed = true
				break
			}
		}
		if !changed {
			return c, attempts, accepted, nil
		}
	}
}
func labReductions(s LabScenario) []func(*LabScenario) {
	var edits []func(*LabScenario)
	// Chunk deletion first, then single elements. Empty and malformed candidates
	// are cheap validation rejections, not special topology repair heuristics.
	for size := len(s.Faults); size >= 1; size /= 2 {
		for i := 0; i+size <= len(s.Faults); i += size {
			start, end := i, i+size
			edits = append(edits, func(s *LabScenario) { s.Faults = slices.Delete(s.Faults, start, end) })
		}
	}
	for i := range s.Views {
		edits = append(edits, func(s *LabScenario) { s.Views = slices.Delete(s.Views, i, i+1); s.TwoSided = "" })
	}
	for i := range s.Network.Topology.Routes {
		edits = append(edits, func(s *LabScenario) { s.Network.Topology.Routes = slices.Delete(s.Network.Topology.Routes, i, i+1) })
	}
	for i, n := range s.Network.Topology.Nodes {
		edits = append(edits, func(s *LabScenario) { s.Network.Topology.Nodes = slices.Delete(s.Network.Topology.Nodes, i, i+1) })
		for j := range n.Interfaces {
			edits = append(edits, func(s *LabScenario) {
				p := &s.Network.Topology.Nodes[i]
				p.Interfaces = slices.Delete(p.Interfaces, j, j+1)
			})
		}
		for j := range n.Aliases {
			edits = append(edits, func(s *LabScenario) { p := &s.Network.Topology.Nodes[i]; p.Aliases = slices.Delete(p.Aliases, j, j+1) })
		}
		for j, svc := range n.Services {
			edits = append(edits, func(s *LabScenario) {
				p := &s.Network.Topology.Nodes[i]
				p.Services = slices.Delete(p.Services, j, j+1)
			})
			for k := range svc.Records {
				edits = append(edits, func(s *LabScenario) {
					p := &s.Network.Topology.Nodes[i].Services[j]
					p.Records = slices.Delete(p.Records, k, k+1)
				})
			}
		}
	}
	for i := range s.Network.Topology.Segments {
		edits = append(edits, func(s *LabScenario) { s.Network.Topology.Segments = slices.Delete(s.Network.Topology.Segments, i, i+1) })
	}
	if len(s.Tunnels) > 0 {
		edits = append(edits, func(s *LabScenario) { s.Tunnels = nil })
	}
	for i, r := range s.Network.Topology.Routes {
		if r.Metric != 0 {
			edits = append(edits, func(s *LabScenario) { s.Network.Topology.Routes[i].Metric = 0 })
		}
	}
	for i, f := range s.Faults {
		if f.Network != nil && f.Network.Type == FaultPMTUBlackhole && f.Network.MTU != 1280 {
			edits = append(edits, func(s *LabScenario) { s.Faults[i].Network.MTU = 1280 })
		}
		if f.Service != nil {
			for j := range f.Service.Records {
				edits = append(edits, func(s *LabScenario) { p := s.Faults[i].Service; p.Records = slices.Delete(p.Records, j, j+1) })
			}
		}
	}
	// Coordinated family reduction removes dependent addresses/routes/answers.
	for _, v6 := range []bool{true, false} {
		edits = append(edits, func(s *LabScenario) { labRemoveFamily(s, v6) })
	}
	return edits
}
func labRemoveFamily(s *LabScenario, v6 bool) {
	matches := func(a string) bool { return strings.Contains(a, ":") == v6 && a != "" }
	for i := range s.Network.Topology.Segments {
		p := &s.Network.Topology.Segments[i]
		if v6 {
			p.IPv6 = ""
		} else {
			p.IPv4 = ""
			p.Subnet = ""
		}
	}
	for i := range s.Network.Topology.Nodes {
		n := &s.Network.Topology.Nodes[i]
		for j := range n.Interfaces {
			if v6 {
				n.Interfaces[j].IPv6 = ""
			} else {
				n.Interfaces[j].IPv4 = ""
				n.Interfaces[j].Address = ""
			}
		}
		n.Aliases = slices.DeleteFunc(n.Aliases, matches)
		for j := range n.Services {
			p := &n.Services[j]
			p.Records = slices.DeleteFunc(p.Records, func(r DNSRecord) bool { return matches(r.Address) })
		}
	}
	s.Network.Topology.Routes = slices.DeleteFunc(s.Network.Topology.Routes, func(r Route) bool { return matches(r.Destination) })
}
