package diagnostic

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// Every route cause the platform backends can produce has to reach the user as
// its own advice. Computing the cause and filing it in JSON is not the same as
// telling anyone what to do about it, which is what this pins.
func TestRouteFixDistinguishesEveryKnownCause(t *testing.T) {
	seen := map[string]string{}
	for _, cause := range []string{
		RouteCauseNoDefaultRoute,
		RouteCauseGatewayUnreachable,
		RouteCauseSelectedPathFailed,
		RouteCausePreferredPathFailed,
	} {
		fix := routeFix(cause)
		if fix == egressFix {
			t.Errorf("%s: fix = the generic hint, want route-specific advice", cause)
		}
		if other, dup := seen[fix]; dup {
			t.Errorf("%s and %s share the fix %q, so the user cannot tell them apart", cause, other, fix)
		}
		seen[fix] = cause
	}
	// The two conditions the audit called indistinguishable.
	if routeFix(RouteCauseNoDefaultRoute) == routeFix(RouteCauseSelectedPathFailed) {
		t.Error("a host with no default route gets the same advice as a filtered upstream")
	}
	for _, cause := range []string{"", "not_a_route_cause"} {
		if fix := routeFix(cause); fix != egressFix {
			t.Errorf("routeFix(%q) = %q, want the generic fallback", cause, fix)
		}
	}
}

// The cause vocabulary itself is public surface shared with the simulator and
// Challenge Mode, so adding advice must not have renamed anything.
func TestRouteCauseValuesUnchanged(t *testing.T) {
	for cause, want := range map[string]string{
		RouteCauseNoDefaultRoute:      "no_default_route",
		RouteCauseGatewayUnreachable:  "gateway_unreachable",
		RouteCauseSelectedPathFailed:  "selected_path_failed",
		RouteCausePreferredPathFailed: "preferred_route_failed",
	} {
		if cause != want {
			t.Errorf("route cause = %q, want %q", cause, want)
		}
	}
}

// The whole path, from a dead dial to the string the TUI and the report print:
// the probe must carry the routing verdict into Fix, not just into Cause.
func TestInternetProbeSurfacesRouteCauseAsFix(t *testing.T) {
	deadOps := func(cause string) *netops {
		return &netops{
			dialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("network is unreachable")
			},
			interfaces: func() ([]net.Interface, error) { return nil, nil },
			routeCause: func(net.IP) string { return cause },
		}
	}
	for _, cause := range []string{
		RouteCauseNoDefaultRoute,
		RouteCauseGatewayUnreachable,
		RouteCauseSelectedPathFailed,
		RouteCausePreferredPathFailed,
	} {
		r := deadOps(cause).internetProbe(context.Background(), nil)
		if r.Status != StatusFail || r.Cause != cause || r.Fix != routeFix(cause) {
			t.Errorf("%s: probe = {status %v, cause %q, fix %q}, want the route-specific fix", cause, r.Status, r.Cause, r.Fix)
		}
		if !strings.HasPrefix(r.Detail, "no direct TCP egress to ") {
			t.Errorf("%s: detail = %q, want the unchanged egress detail", cause, r.Detail)
		}
	}
	// A platform with no routing evidence, and one whose backend answered with
	// something this build does not know, both keep the old generic hint.
	for _, ops := range []*netops{deadOps(""), deadOps("route_cause_from_a_future_release")} {
		if r := ops.internetProbe(context.Background(), nil); r.Fix != egressFix {
			t.Errorf("unclassified route failure fix = %q, want %q", r.Fix, egressFix)
		}
	}
}

// A proxy-only network is healthy, not a broken routing table. It legitimately
// has no default route, so the route hint must not survive the downgrade and
// tell a working machine to repair a route it does not need. The cause stays
// for the JSON.
func TestDowngradedEgressDropsRouteRepairAdvice(t *testing.T) {
	for _, c := range []struct {
		name string
		res  map[ProbeID]ProbeResult
	}{
		{"proxy carries the traffic", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail, Cause: RouteCauseNoDefaultRoute, Fix: routeFix(RouteCauseNoDefaultRoute)},
			ProbeDNS:      {Status: StatusFail},
			ProbeProxy:    {Status: StatusPass},
		}},
		{"another path works", map[ProbeID]ProbeResult{
			ProbeInternet:  {Status: StatusFail, Cause: RouteCauseSelectedPathFailed, Fix: routeFix(RouteCauseSelectedPathFailed)},
			ProbeDNS:       {Status: StatusPass},
			ProbeTargetTCP: {Status: StatusPass, SelectedIP: net.ParseIP("93.184.216.34")},
		}},
	} {
		Finalize(c.res)
		got := c.res[ProbeInternet]
		if got.Status != StatusWarn || !got.downgraded {
			t.Fatalf("%s: internet row = %v (downgraded=%t), want a downgraded WARN", c.name, got.Status, got.downgraded)
		}
		if got.Fix != egressFix {
			t.Errorf("%s: fix = %q, want the generic %q", c.name, got.Fix, egressFix)
		}
		if got.Cause == "" {
			t.Errorf("%s: the route cause was erased from the result", c.name)
		}
	}

	// The genuinely dead network keeps the repair: nothing proved a path.
	dead := map[ProbeID]ProbeResult{
		ProbeInternet: {Status: StatusFail, Cause: RouteCauseNoDefaultRoute, Fix: routeFix(RouteCauseNoDefaultRoute)},
		ProbeDNS:      {Status: StatusFail},
	}
	Finalize(dead)
	if got := dead[ProbeInternet]; got.Status != StatusFail || got.Fix != routeFix(RouteCauseNoDefaultRoute) {
		t.Errorf("offline host = {status %v, fix %q}, want the route fix to survive", got.Status, got.Fix)
	}
}
