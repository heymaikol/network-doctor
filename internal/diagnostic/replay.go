package diagnostic

import (
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

var errReplayedAttempt = errors.New("recorded connection attempt failed")

// ReplaySnapshot recomputes a diagnosis from one ordinary snapshot without
// constructing or running probes. The diagnosis stored in s is historical and
// is deliberately ignored.
func ReplaySnapshot(s snapshot.Snapshot) (Diagnosis, error) {
	if s.Schema != snapshot.Schema {
		return Diagnosis{}, fmt.Errorf("replay snapshot schema %q, want %q", s.Schema, snapshot.Schema)
	}
	if s.Incident != nil {
		return Diagnosis{}, errors.New("replay requires an ordinary snapshot, not a watch incident")
	}

	target, err := replayTarget(s.Target)
	if err != nil {
		return Diagnosis{}, err
	}
	order := make([]ProbeID, 0, len(s.Checks))
	results := make(map[ProbeID]ProbeResult, len(s.Checks))
	seen := make(map[ProbeID]bool, len(s.Checks))
	for _, check := range s.Checks {
		id := ProbeID(check.ID)
		if !replayProbeID(id) {
			return Diagnosis{}, fmt.Errorf("replay snapshot has unsupported check %q", check.ID)
		}
		if seen[id] {
			return Diagnosis{}, fmt.Errorf("replay snapshot repeats check %q", check.ID)
		}
		seen[id] = true
		order = append(order, id)
		if check.Status == snapshot.StatusIncomplete {
			continue
		}
		status, err := replayStatus(check.Status)
		if err != nil {
			return Diagnosis{}, fmt.Errorf("replay check %q: %w", check.ID, err)
		}
		result, err := replayResult(id, status, check)
		if err != nil {
			return Diagnosis{}, fmt.Errorf("replay check %q: %w", check.ID, err)
		}
		results[id] = result
	}
	return Interpret(target, order, results), nil
}

func replayTarget(in *snapshot.Target) (*Target, error) {
	if in == nil {
		return nil, nil
	}
	if in.Host == "" || in.Port < 1 || in.Port > 65535 {
		return nil, fmt.Errorf("replay snapshot has invalid target %q:%d", in.Host, in.Port)
	}
	proto, err := replayProto(in.Protocol)
	if err != nil {
		return nil, err
	}
	out := &Target{Raw: in.Raw, Host: in.Host, Port: in.Port, Proto: proto, PortExplicit: in.PortExplicit}
	if in.IP != "" {
		out.IP = net.ParseIP(in.IP)
		if out.IP == nil {
			return nil, fmt.Errorf("replay target has invalid IP %q", in.IP)
		}
	}
	return out, nil
}

func replayProto(value string) (Proto, error) {
	for proto := range protoNames {
		candidate := Proto(proto)
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return ProtoNone, fmt.Errorf("replay snapshot has unsupported target protocol %q", value)
}

func replayStatus(value string) (Status, error) {
	for status := range statusNames {
		candidate := Status(status)
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return StatusPass, fmt.Errorf("unsupported status %q", value)
}

func replayResult(id ProbeID, status Status, check snapshot.Check) (ProbeResult, error) {
	if check.CauseFamily != "" && check.Cause == "" {
		return ProbeResult{}, errors.New("cause family is present without a cause")
	}
	if check.CauseFamily != "" && check.CauseFamily != counterfactualIPv4 && check.CauseFamily != counterfactualIPv6 {
		return ProbeResult{}, fmt.Errorf("unsupported cause family %q", check.CauseFamily)
	}
	// An absent family is a state, not a gap: failedRouteCause deliberately
	// reports none when the same route fact held for both families, and an
	// artifact written before cause_family existed has none to report either.
	// The two family-specific causes are the exception, since only one family
	// can ever produce them, so they are recovered rather than left empty.
	causeFamily := check.CauseFamily
	if causeFamily == "" && id == ProbeInternet {
		switch check.Cause {
		case FamilyCauseIPv4Unreachable:
			causeFamily = counterfactualIPv4
		case FamilyCauseIPv6Unreachable:
			causeFamily = counterfactualIPv6
		}
	}
	result := ProbeResult{ID: id, Status: status, Cause: check.Cause, causeFamily: causeFamily}
	if check.Derived != nil {
		if check.Derived.StatusDowngraded && status != StatusWarn {
			return ProbeResult{}, errors.New("status downgrade is present on a non-WARN result")
		}
		result.downgraded = check.Derived.StatusDowngraded
		if check.Derived.AnswerComparison != "" {
			// answer_comparison is defined for the independent DNS row and no
			// other, because that is the only row the cross-probe pass
			// compares. Anywhere else it is derived state this version would
			// restore and never read, so the artifact is refused rather than
			// half believed.
			if id != ProbeDNSPublic {
				return ProbeResult{}, fmt.Errorf("answer comparison is present on %q, which is not the independent DNS row", id)
			}
			// Answers are what a comparison is made of, so a row that recorded
			// none cannot have produced either outcome. That is a property of
			// the stored row itself, unlike its status, which any later
			// reconciliation rule is free to rewrite for an unrelated reason.
			if check.Observed == nil || len(check.Observed.Addresses) == 0 {
				return ProbeResult{}, errors.New("an answer comparison is present on a row that recorded no answers to compare")
			}
		}
		switch check.Derived.AnswerComparison {
		case snapshot.AnswerComparisonAgree:
			result.answerComparison = comparisonAgree
		case snapshot.AnswerComparisonDisagree:
			result.answerComparison = comparisonDisagree
		}
	}
	if check.Observed == nil {
		return result, nil
	}

	observed := check.Observed
	var err error
	if result.Addrs, err = replayIPs("address", observed.Addresses); err != nil {
		return ProbeResult{}, err
	}
	if result.SelectedIP, err = replayIP("selected IP", observed.SelectedIP); err != nil {
		return ProbeResult{}, err
	}
	if result.Source, err = replayIP("source IP", observed.SourceIP); err != nil {
		return ProbeResult{}, err
	}
	result.DNSNotFound = observed.DNSNotFound
	result.resolver = observed.Resolver
	result.ResolverTargets = append([]string(nil), observed.ResolverTargets...)
	result.Iface = observed.Interface
	result.Network = observed.SSID
	result.timedOut = observed.Timeout
	result.ifaceAmbiguous = observed.InterfaceAmbiguous
	if observed.Families != nil {
		if err := replayFamilies(observed.Families); err != nil {
			return ProbeResult{}, err
		}
		result.Families = &FamilyConnectivity{IPv4: observed.Families.IPv4, IPv6: observed.Families.IPv6}
	}
	if observed.Portal != nil {
		result.Portal = &Portal{RedirectURL: observed.Portal.RedirectURL}
	}
	if observed.ClockOffsetMs != nil {
		if *observed.ClockOffsetMs > math.MaxInt64/int64(time.Millisecond) ||
			*observed.ClockOffsetMs < math.MinInt64/int64(time.Millisecond) {
			return ProbeResult{}, fmt.Errorf("clock offset %dms is out of range", *observed.ClockOffsetMs)
		}
		result.clockOffset = time.Duration(*observed.ClockOffsetMs) * time.Millisecond
	}
	for _, attempt := range observed.Attempts {
		item := Attempt{Cause: attempt.Cause, Aborted: attempt.Aborted}
		if item.IP, err = replayRequiredIP("attempt IP", attempt.IP); err != nil {
			return ProbeResult{}, err
		}
		if attempt.Cause != "" {
			item.Err = errReplayedAttempt
		} else if id == ProbeTargetTCP && attempt.Error != "" {
			return ProbeResult{}, errors.New("target attempt has human error text but no typed cause")
		}
		result.Attempts = append(result.Attempts, item)
	}
	for _, route := range observed.Routes {
		destination, err := replayRequiredIP("route destination", route.Destination)
		if err != nil {
			return ProbeResult{}, err
		}
		if route.Family != "" && route.Family != counterfactualIPv4 && route.Family != counterfactualIPv6 {
			return ProbeResult{}, fmt.Errorf("unsupported route family %q", route.Family)
		}
		tunnel := TunnelState(route.Tunnel)
		if tunnel != TunnelUnknown && tunnel != TunnelDirect && tunnel != TunnelLikely && tunnel != TunnelKnown {
			return ProbeResult{}, fmt.Errorf("unsupported route tunnel state %q", route.Tunnel)
		}
		// The next hop and the routing table are restored because the
		// comparison that reads them is part of the reasoning replay
		// recomputes: a stored path whose gateway was dropped here would come
		// back looking on-link, and two flows the run recorded as routed apart
		// would replay as taking one path. Table knowledge is restored beside
		// the name for the same reason, since an artifact that named no table
		// is unknown rather than the main one.
		gateway, err := replayIP("route gateway", route.Gateway)
		if err != nil {
			return ProbeResult{}, err
		}
		source, err := replayIP("route source", route.Source)
		if err != nil {
			return ProbeResult{}, err
		}
		result.Routes = append(result.Routes, RouteDecision{
			Destination: destination,
			Family:      route.Family,
			Iface:       route.Interface,
			Gateway:     gateway,
			Source:      source,
			Table:       route.Table,
			TableKnown:  route.TableKnown,
			MTU:         route.InterfaceMTU,
			Tunnel:      tunnel,
			Unreachable: route.Unreachable,
		})
	}
	return result, nil
}

func replayIP(field, value string) (net.IP, error) {
	if value == "" {
		return nil, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("invalid %s %q", field, value)
	}
	return ip, nil
}

func replayIPs(field string, values []string) ([]net.IP, error) {
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		ip, err := replayRequiredIP(field, value)
		if err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, nil
}

func replayRequiredIP(field, value string) (net.IP, error) {
	if value == "" {
		return nil, fmt.Errorf("missing %s", field)
	}
	return replayIP(field, value)
}

func replayFamilies(families *snapshot.Families) error {
	for _, family := range []struct{ name, value string }{{"IPv4", families.IPv4}, {"IPv6", families.IPv6}} {
		if family.value != "" && family.value != FamilyReachable && family.value != FamilyUnreachable {
			return fmt.Errorf("unsupported %s family state %q", family.name, family.value)
		}
	}
	return nil
}

func replayProbeID(id ProbeID) bool {
	switch id {
	case ProbeIface, ProbeSSID, ProbeInternet, ProbeQUIC, ProbeProxy, ProbeDNS, ProbeDNSPublic,
		ProbeDNSEncrypted, ProbeTargetTCP, ProbePMTU, ProbeTLS, ProbeHTTP, ProbeHTTPS, ProbeSSH, ProbeSMTP:
		return true
	}
	return false
}
