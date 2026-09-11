package compare

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// EvidenceComparison compares one explicitly named dimension, never whole
// checks or root causes. Missing dimensions mean unknown, not equivalence.
// Values are recorded facts from A and B, including partial evidence when the
// relation is unknown. The derived.* dimensions retain recorded reconciliation,
// not new measurements. These optional fields extend netdoc.twosided.v1 without
// changing status comparability, placement, finding IDs, or exit codes.
type EvidenceComparison struct {
	Dimension string         `json:"dimension"`
	Relation  string         `json:"relation"` // equivalent, different, unknown
	A         []EvidenceFact `json:"a,omitempty"`
	B         []EvidenceFact `json:"b,omitempty"`
	Reason    string         `json:"reason,omitempty"` // missing_evidence, redacted_identity
}

// EvidenceFact is a stable value, optionally scoped to an address or family.
// An aborted attempt describes the enclosing budget/cancellation, not an
// independently failed address. No human error text is copied or compared.
type EvidenceFact struct {
	Address string `json:"address,omitempty"`
	Family  string `json:"family,omitempty"`
	Value   string `json:"value"`
	Aborted bool   `json:"aborted,omitempty"`
}

type evidenceValues struct {
	facts []EvidenceFact
	known bool
}

func evidenceScalar(value string) evidenceValues {
	if value == "" {
		return evidenceValues{}
	}
	return evidenceValues{[]EvidenceFact{{Value: value}}, true}
}

func derivedOf(c snapshot.Check) snapshot.Derived {
	if c.Derived == nil {
		return snapshot.Derived{}
	}
	return *c.Derived
}

// checkEvidence is deliberately a projection, not a deep comparison of the
// artifact. Host-local names, route-table IDs, metrics, prose, durations and
// historical findings cannot establish shared infrastructure across machines.
// Positive-only optional booleans never become observations of their negation.
//
// Equivalence means equality of a known dimension's canonical projection:
// address/resolver sets ignore order and duplicates; address strings normalize
// IP spelling; attempts preserve multiplicity but ignore completion/array
// order, including repeated-address verification; routes ignore destination order.
// The *_states and attempt_outcomes multisets retain family, value and count,
// not address association. Their equivalence says nothing about identities.
// Any missing member's optional value makes that dimension unknown. Other
// dimensions remain independently comparable. Neither equivalence nor
// difference changes localization. There is deliberately no whole-row equality.
func checkEvidence(a, b snapshot.Check, redacted bool) []EvidenceComparison {
	var out []EvidenceComparison
	add := func(dimension string, x, y evidenceValues, identity bool) {
		if len(x.facts) == 0 && len(y.facts) == 0 {
			return
		}
		c := EvidenceComparison{Dimension: dimension, A: x.facts, B: y.facts, Relation: "unknown"}
		switch {
		case identity && redacted:
			c.Reason = "redacted_identity"
		case !x.known || !y.known:
			c.Reason = "missing_evidence"
		case slices.Equal(x.facts, y.facts):
			c.Relation = "equivalent"
		default:
			c.Relation = "different"
		}
		out = append(out, c)
	}
	x, y := observedOf(a), observedOf(b)
	xf, yf := familiesOf(x), familiesOf(y)
	add("cause", evidenceScalar(a.Cause), evidenceScalar(b.Cause), false)
	add("cause_family", evidenceScalar(a.CauseFamily), evidenceScalar(b.CauseFamily), false)
	add("address_families.ipv4", evidenceScalar(xf.IPv4), evidenceScalar(yf.IPv4), false)
	add("address_families.ipv6", evidenceScalar(xf.IPv6), evidenceScalar(yf.IPv6), false)
	add("dns_outcome", evidenceScalar(dnsOutcome(a)), evidenceScalar(dnsOutcome(b)), false)
	add("addresses", evidenceAddresses(x.Addresses), evidenceAddresses(y.Addresses), true)
	add("selected_ip", evidenceAddresses(nonempty(x.SelectedIP)), evidenceAddresses(nonempty(y.SelectedIP)), true)
	add("resolver", evidenceAddresses(nonempty(x.Resolver)), evidenceAddresses(nonempty(y.Resolver)), true)
	add("resolver_targets", evidenceResolverTargets(x.ResolverTargets), evidenceResolverTargets(y.ResolverTargets), true)
	// Attempt outcomes retain multiplicity, not completion/array order. The
	// artifact has no chronological attempt IDs or timestamps. Even canceled
	// attempts and their verification are compared as unordered observations.
	// The family-only multiset remains usable after support redaction, without
	// pretending that it identifies which address had each outcome.
	add("attempt_outcomes", evidenceAttempts(x.Attempts, false), evidenceAttempts(y.Attempts, false), false)
	add("attempts", evidenceAttempts(x.Attempts, true), evidenceAttempts(y.Attempts, true), true)
	for _, field := range []struct {
		name  string
		value func(snapshot.Route) string
	}{
		{"tunnel", func(r snapshot.Route) string { return r.Tunnel }},
		{"selection", func(r snapshot.Route) string {
			if r.Unreachable {
				return "unreachable"
			}
			if r.Interface != "" {
				return "selected"
			}
			return ""
		}},
		{"link_mtu", func(r snapshot.Route) string {
			if r.InterfaceMTU > 0 {
				return strconv.Itoa(r.InterfaceMTU)
			}
			return ""
		}},
	} {
		add("route_"+field.name+"_states", evidenceRoutes(x.Routes, false, field.value), evidenceRoutes(y.Routes, false, field.value), false)
		add("route_"+field.name, evidenceRoutes(x.Routes, true, field.value), evidenceRoutes(y.Routes, true, field.value), true)
	}
	add("protocol_timeout", evidencePositive(x.Timeout), evidencePositive(y.Timeout), false)
	add("clock_offset_seconds", evidenceClockOffset(x.ClockOffsetMs), evidenceClockOffset(y.ClockOffsetMs), false)
	add("portal", evidenceScalar(portalWord(x.Portal)), evidenceScalar(portalWord(y.Portal)), false)
	add("connect_cleartext", evidencePositive(x.ConnectCleartext), evidencePositive(y.ConnectCleartext), false)
	xd, yd := derivedOf(a), derivedOf(b)
	add("derived.status_downgraded", evidencePositive(xd.StatusDowngraded), evidencePositive(yd.StatusDowngraded), false)
	add("derived.answer_comparison", evidenceScalar(string(xd.AnswerComparison)), evidenceScalar(string(yd.AnswerComparison)), false)
	return out
}

func nonempty(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func evidencePositive(value bool) evidenceValues {
	if !value {
		return evidenceValues{}
	}
	return evidenceScalar("observed")
}

// Clock offset is evidence for certificate-date failures, not probe duration.
// Match the existing snapshot comparison's whole-second resolution, without
// converting arbitrary artifact milliseconds to nanoseconds (which can overflow).
func evidenceClockOffset(ms *int64) evidenceValues {
	if ms == nil {
		return evidenceValues{}
	}
	seconds := *ms / 1000
	if *ms%1000 >= 500 {
		seconds++
	}
	if *ms%1000 <= -500 {
		seconds--
	}
	return evidenceScalar(strconv.FormatInt(seconds, 10))
}

func dnsOutcome(c snapshot.Check) string {
	if c.ID != "dns" && c.ID != "dns_public" {
		return ""
	}
	o := observedOf(c)
	switch {
	case o.DNSNotFound:
		return "negative_answer"
	case len(o.Addresses) > 0:
		return "addresses_returned"
	case c.Cause == "dns_timeout":
		return "timeout"
	case c.Cause == "dns_temporary_failure":
		return "temporary_failure"
	}
	return ""
}

func evidenceStrings(values []string) evidenceValues {
	values = slices.Clone(values)
	slices.Sort(values)
	var out []EvidenceFact
	for _, value := range slices.Compact(values) {
		out = append(out, EvidenceFact{Value: value})
	}
	return evidenceValues{out, len(out) > 0}
}

func evidenceAddresses(values []string) evidenceValues {
	var addresses []string
	for _, value := range values {
		ip, err := netip.ParseAddr(value)
		if err != nil {
			return evidenceValues{}
		}
		addresses = append(addresses, ip.Unmap().String())
	}
	return evidenceStrings(addresses)
}

func evidenceResolverTargets(values []string) evidenceValues {
	var targets []string
	for _, value := range values {
		endpoint, err := netip.ParseAddrPort(value)
		if err != nil {
			return evidenceValues{}
		}
		targets = append(targets, netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()).String())
	}
	return evidenceStrings(targets)
}

func evidenceAttempts(attempts []snapshot.Attempt, identities bool) evidenceValues {
	out := evidenceValues{known: len(attempts) > 0}
	for _, a := range attempts {
		ip, err := netip.ParseAddr(a.IP)
		if err != nil {
			out.known = false
			continue
		}
		ip = ip.Unmap()
		f := EvidenceFact{Family: "ipv6", Value: a.Cause, Aborted: a.Aborted}
		if ip.Is4() {
			f.Family = "ipv4"
		}
		if identities {
			f.Address = ip.String()
		}
		if a.Cause == "" {
			if a.Error != "" || a.Aborted {
				f.Value, out.known = "unknown", false
			} else {
				f.Value = "succeeded"
			}
		}
		out.facts = append(out.facts, f)
	}
	sortEvidenceFacts(out.facts)
	return out
}

func evidenceRoutes(routes []snapshot.Route, identities bool, value func(snapshot.Route) string) evidenceValues {
	out := evidenceValues{known: len(routes) > 0}
	anyKnown := false
	for _, r := range routes {
		ip, err := netip.ParseAddr(r.Destination)
		if err != nil {
			out.known = false
			continue
		}
		ip = ip.Unmap()
		f := EvidenceFact{Family: "ipv6", Value: value(r)}
		if ip.Is4() {
			f.Family = "ipv4"
		}
		if identities {
			f.Address = ip.String()
		}
		if f.Value == "" {
			f.Value, out.known = "unknown", false
		} else {
			anyKnown = true
		}
		out.facts = append(out.facts, f)
	}
	if !anyKnown {
		return evidenceValues{}
	}
	sortEvidenceFacts(out.facts)
	return out
}

func sortEvidenceFacts(facts []EvidenceFact) {
	slices.SortFunc(facts, func(a, b EvidenceFact) int {
		for _, pair := range [][2]string{{a.Address, b.Address}, {a.Family, b.Family}, {a.Value, b.Value}, {strconv.FormatBool(a.Aborted), strconv.FormatBool(b.Aborted)}} {
			if c := strings.Compare(pair[0], pair[1]); c != 0 {
				return c
			}
		}
		return 0
	})
}

func evidenceWord(facts []EvidenceFact) string {
	if len(facts) == 0 {
		return "unknown"
	}
	var words []string
	for _, f := range facts {
		word := strings.TrimSpace(f.Address + " " + f.Family + " " + f.Value)
		if f.Aborted {
			word += " (aborted)"
		}
		words = append(words, word)
	}
	return strings.Join(words, "; ")
}
