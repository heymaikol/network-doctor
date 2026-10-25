package routepath

import (
	"errors"
	"fmt"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
)

func validatePolicies(policies []PolicyChange, m netmodel.Model) error {
	seen := map[PolicySelector]bool{}
	for i, p := range policies {
		if seen[p.PolicySelector] {
			return fmt.Errorf("route policy %d repeats an ambiguous selector", i)
		}
		seen[p.PolicySelector] = true
		if _, err := ResolveSource(File{Model: m}, p.Node, p.VRF); err != nil {
			return err
		}
		if _, err := EvaluatePolicy(p); err != nil {
			return fmt.Errorf("route policy %d: %w", i, err)
		}
	}
	return nil
}

func selectedPolicy(f File, fail Failure) (Failure, *PolicyEvaluation, error) {
	p := *fail.Policy
	if err := p.Validate(); err != nil {
		return fail, nil, err
	}
	if len(f.Tunnels) != 0 {
		return fail, nil, errors.New("route-policy simulation cannot prove tunnel underlay dependencies")
	}
	if fail.Interface != "" || fail.NextHop != "" || fail.OSPFNeighbor != "" || fail.Node != "" && fail.Node != p.Node || fail.VRF != "" && fail.VRF != p.VRF {
		return fail, nil, errors.New("policy selector cannot be combined with another failure")
	}
	if err := validatePolicies(f.Policies, f.Model); err != nil {
		return fail, nil, err
	}
	for _, candidate := range f.Policies {
		if candidate.PolicySelector != p {
			continue
		}
		evaluated, err := EvaluatePolicy(candidate)
		fail.Node, fail.VRF = p.Node, p.VRF
		return fail, &evaluated, err
	}
	return fail, nil, errors.New("no complete route-policy evidence matches the selector")
}

func policySupports(p *PolicyEvaluation) []Support {
	out := make([]Support, 0, len(p.Evidence))
	for _, e := range p.Evidence {
		out = append(out, Support{Source: e.Source, CollectedAt: utcText(e.CollectedAt)})
	}
	return out
}
