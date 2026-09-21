package snapshot

import (
	"net/netip"
	"testing"
)

// sanitizeValid sanitizes one artifact that has to be valid before and after,
// and holds the pass to the two promises every case below rests on: the
// original is untouched, and the result is a file netdoc will still encode.
func sanitizeValid(t *testing.T, s Snapshot) Snapshot {
	t.Helper()
	pinLocalIdentity(t)
	before, err := Encode(s)
	if err != nil {
		t.Fatalf("the fixture is not a valid artifact to begin with: %v", err)
	}
	sanitized := SanitizeForSupport(s)
	// The bytes rather than the struct: this is the whole artifact as the
	// format writes it, so a mutation anywhere under the snapshot shows up.
	after, err := Encode(s)
	if err != nil {
		t.Fatalf("the full-fidelity snapshot stopped encoding after sanitization: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("SanitizeForSupport modified the full-fidelity snapshot")
	}
	if _, err := Encode(sanitized); err != nil {
		t.Fatalf("the sanitized artifact no longer holds together: %v", err)
	}
	return sanitized
}

// isAddress reports whether a sanitized value landed in the address namespace.
// Every address pseudonym parses as an address and no interface alias does,
// which is exactly the distinction the reported bug erased.
func isAddress(value string) bool {
	_, err := netip.ParseAddr(value)
	return err == nil
}

// routeEvidenceSnapshot is one valid artifact whose finding rests on an
// interface-valued observation about the route row beside it. cited is the
// interface the evidence names, which for route_path_differs is deliberately
// not the one the row selected.
func routeEvidenceSnapshot(observation, iface, cited string) Snapshot {
	route := Route{
		Destination: "2001:db8::7", Family: "ipv6", Interface: iface,
		Gateway: "2001:db8::1", Tunnel: TunnelStateDirect,
	}
	switch observation {
	case ObservationRouteTunneled:
		route.Tunnel, route.TunnelKind = TunnelStateTunnel, "wireguard"
	case ObservationRouteInterfaceMTU:
		route.InterfaceMTU = 1420
	}
	return Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Checks: []Check{{ID: "target_tcp", Name: "target_tcp", Status: StatusFail, Ran: true, DurationMs: 1,
			Cause: "timeout", CauseFamily: "ipv6", Observed: &Observed{Routes: []Route{route}}}},
		Diagnosis: Diagnosis{Verdict: "network", Summary: "unreachable", Blamed: "target_tcp", FailedStage: "target_tcp",
			Findings: []Finding{{
				ID: "target_unreachable", Verdict: "network", Summary: "unreachable", Focus: "target_tcp",
				Evidence: []string{"target_tcp"},
				CausalEvidence: []CausalEvidence{{
					Kind: EvidenceSupport, Check: "target_tcp", Observation: observation, Value: cited,
				}},
			}}},
	}
}

// The reported bug. An interface is whatever name the operating system gave a
// device, and a device can be named "192.0.2.1". Redaction that read that name
// as an address gave the evidence a pseudonym out of the address namespace
// while the route it cites got an interface alias, and the artifact stopped
// being one netdoc would encode:
//
//	causal evidence references route_tunneled on check "dns", but that
//	observation is absent
//
// The name's shape is not its meaning, so every interface-valued observation
// is checked with both an ordinary device name and one shaped like an address.
func TestInterfaceValuedEvidenceKeepsTheInterfaceAliasOfItsRoute(t *testing.T) {
	for _, observation := range []string{
		ObservationRouteTunneled, ObservationRouteDirect, ObservationRouteInterfaceMTU,
	} {
		for _, iface := range []string{"192.0.2.1", "2001:db8::1", "wg0"} {
			t.Run(observation+" on "+iface, func(t *testing.T) {
				sanitized := sanitizeValid(t, routeEvidenceSnapshot(observation, iface, iface))
				named := sanitized.Diagnosis.Findings[0].CausalEvidence[0].Value
				recorded := sanitized.Checks[0].Observed.Routes[0].Interface
				if named != recorded {
					t.Errorf("evidence named interface %q, want the route's sanitized %q", named, recorded)
				}
				if named == iface {
					t.Errorf("the original interface name %q survived sanitization", iface)
				}
				if isAddress(named) {
					t.Errorf("interface %q was sanitized into the address namespace as %q", iface, named)
				}
			})
		}
	}
}

// route_path_differs names the other path's interface rather than this row's,
// so the relationship it has to keep is the opposite one: the two names stay
// two, and neither of them becomes an address.
func TestRoutePathDiffersKeepsTwoInterfacesApart(t *testing.T) {
	for _, other := range []string{"192.0.2.1", "eth1"} {
		t.Run(other, func(t *testing.T) {
			sanitized := sanitizeValid(t, routeEvidenceSnapshot(ObservationRoutePathDiffers, "wg0", other))
			named := sanitized.Diagnosis.Findings[0].CausalEvidence[0].Value
			recorded := sanitized.Checks[0].Observed.Routes[0].Interface
			if named == recorded {
				t.Errorf("two interfaces collapsed onto one alias %q", named)
			}
			if named == other || isAddress(named) {
				t.Errorf("the other path's interface %q sanitized to %q", other, named)
			}
		})
	}
}

// One interface named in two places is one interface, which is the property
// the address namespace broke: the route row and the evidence have to end up
// on the same alias, and a second device on a second one.
func TestRepeatedInterfaceNamesShareOneAlias(t *testing.T) {
	s := routeEvidenceSnapshot(ObservationRouteTunneled, "wg0", "wg0")
	s.Options.Source = &Source{Interface: "wg0", IPv4: "192.0.2.10"}
	s.Checks[0].Observed.Interface = "wg0"
	s.Checks[0].Observed.Routes[0].Competing = []CompetingRoute{{Interface: "eth0", Metric: 20}}
	sanitized := sanitizeValid(t, s)
	observed := sanitized.Checks[0].Observed
	alias := sanitized.Diagnosis.Findings[0].CausalEvidence[0].Value
	for name, got := range map[string]string{
		"the route's interface":  observed.Routes[0].Interface,
		"the row's interface":    observed.Interface,
		"the source binding":     sanitized.Options.Source.Interface,
		"the evidence's own one": alias,
	} {
		if got != alias {
			t.Errorf("%s sanitized to %q, want the one alias %q", name, got, alias)
		}
	}
	if competing := observed.Routes[0].Competing[0].Interface; competing == alias {
		t.Errorf("a second device shares the first one's alias %q", competing)
	}
}

// addressEvidenceRowSnapshot is one valid artifact carrying every
// address-valued observation against the row that recorded it.
func addressEvidenceRowSnapshot(answer, otherNextHop string) Snapshot {
	const (
		succeeded   = "2001:db8::9"
		unreachable = "2001:db8::5"
		gateway     = "2001:db8::1"
	)
	return Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Checks: []Check{{ID: "target_tcp", Name: "target_tcp", Status: StatusFail, Ran: true, DurationMs: 1,
			Cause: "timeout", CauseFamily: "ipv6",
			Observed: &Observed{
				Addresses: []string{answer},
				Attempts: []Attempt{
					{IP: answer, Error: "deadline exceeded", Cause: "timeout"},
					{IP: succeeded},
				},
				Routes: []Route{
					{Destination: answer, Family: "ipv6", Interface: "eth0", Gateway: gateway, Tunnel: TunnelStateDirect},
					{Destination: unreachable, Family: "ipv6", Unreachable: true},
				},
			}}},
		Diagnosis: Diagnosis{Verdict: "network", Summary: "unreachable", Blamed: "target_tcp", FailedStage: "target_tcp",
			Findings: []Finding{{
				ID: "target_unreachable", Verdict: "network", Summary: "unreachable", Focus: "target_tcp",
				Evidence: []string{"target_tcp"},
				CausalEvidence: []CausalEvidence{
					{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationDNSAnswers, Value: answer},
					{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationAddressFailed, Value: answer},
					{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationAddressSucceeded, Value: succeeded},
					{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationRouteUnreachable, Value: unreachable},
					{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationRouteNextHopDiffers, Value: otherNextHop},
				},
			}}},
	}
}

// The other half of the classification has to keep working. All five
// address-valued observations stay in the address namespace and land on the
// same pseudonym as the recording each one cites.
func TestAddressValuedEvidenceKeepsThePseudonymOfWhatItCites(t *testing.T) {
	const answer = "2001:db8::7"
	// A next hop this artifact records nowhere else, in a range the pseudonym
	// generator does not draw from, so it cannot be confused with an alias.
	const otherNextHop = "2606:2800:220:1::2"
	sanitized := sanitizeValid(t, addressEvidenceRowSnapshot(answer, otherNextHop))
	observed := sanitized.Checks[0].Observed
	evidence := sanitized.Diagnosis.Findings[0].CausalEvidence
	for i, want := range []string{
		observed.Addresses[0],
		observed.Attempts[0].IP,
		observed.Attempts[1].IP,
		observed.Routes[1].Destination,
	} {
		if evidence[i].Value != want {
			t.Errorf("%s named %q, want the recording's pseudonym %q", evidence[i].Observation, evidence[i].Value, want)
		}
	}
	named := evidence[4].Value
	if !isAddress(named) {
		t.Errorf("route_next_hop_differs named %q, which is not an address", named)
	}
	if named == otherNextHop {
		t.Errorf("the original next hop %q survived sanitization", named)
	}
	// The claim is that this row went somewhere else, so the two next hops
	// have to stay two.
	if named == observed.Routes[0].Gateway {
		t.Errorf("the two next hops collapsed onto one pseudonym %q", named)
	}
}

// Address identity is not spelling, so an artifact whose evidence spells one
// address differently from the row still names one address after redaction.
func TestAddressValuedEvidenceKeepsOnePseudonymAcrossSpellings(t *testing.T) {
	s := addressEvidenceRowSnapshot("2001:db8::7", "2606:2800:220:1::2")
	s.Diagnosis.Findings[0].CausalEvidence[0].Value = "2001:0db8:0000:0000:0000:0000:0000:0007"
	sanitized := sanitizeValid(t, s)
	named := sanitized.Diagnosis.Findings[0].CausalEvidence[0].Value
	if recorded := sanitized.Checks[0].Observed.Addresses[0]; named != recorded {
		t.Errorf("an answer spelled two ways sanitized to %q and %q, want one pseudonym", named, recorded)
	}
}

// familyEvidenceSnapshot is one valid artifact whose finding rests on the two
// address-family readings of a row.
func familyEvidenceSnapshot() Snapshot {
	return Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Checks: []Check{{ID: "target_tcp", Name: "target_tcp", Status: StatusWarn, Ran: true, DurationMs: 1,
			Cause: "timeout", CauseFamily: "ipv6",
			Observed: &Observed{Families: &Families{IPv4: "reachable", IPv6: "unreachable"}}}},
		Diagnosis: Diagnosis{Verdict: "degraded", Summary: "one family fails", Blamed: "target_tcp",
			Findings: []Finding{{
				ID: "ipv6_target_unreachable", Verdict: "degraded", Summary: "one family fails", Focus: "target_tcp",
				Evidence: []string{"target_tcp"},
				CausalEvidence: []CausalEvidence{
					{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationFamilyFailed, Value: "ipv6"},
					{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationFamilyReachable, Value: "ipv4"},
					{Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationCause, Value: "ipv6"},
				},
			}}},
		OK: true,
	}
}

// An address family is one of two words, and both are as public as the format
// that defines them. They stay themselves: a pseudonym there would erase the
// whole content of the claim and leave a file that no longer checks.
func TestFamilyValuedEvidenceKeepsItsVocabulary(t *testing.T) {
	sanitized := sanitizeValid(t, familyEvidenceSnapshot())
	for i, want := range []string{"ipv6", "ipv4", "ipv6"} {
		evidence := sanitized.Diagnosis.Findings[0].CausalEvidence[i]
		if evidence.Value != want {
			t.Errorf("%s named %q, want %q", evidence.Observation, evidence.Value, want)
		}
	}
}

// resolvedAddressCounterfactualSnapshot is the artifact the address
// counterfactual produces: one answer connected and another did not, and each
// alternative is named by the address it is about.
func resolvedAddressCounterfactualSnapshot(failed, succeeded string) Snapshot {
	evidence := func(observation, value string) []CausalEvidence {
		return []CausalEvidence{
			{Kind: EvidenceSupport, Check: "target_tcp", Observation: observation, Value: value},
			{Kind: EvidenceSupport, Check: "dns", Observation: ObservationDNSAnswers, Value: value},
		}
	}
	failure, success := evidence(ObservationAddressFailed, failed), evidence(ObservationAddressSucceeded, succeeded)
	return Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Checks: []Check{
			{ID: "target_tcp", Name: "target_tcp", Status: StatusWarn, Ran: true, DurationMs: 1,
				Observed: &Observed{Attempts: []Attempt{
					{IP: failed, Error: "deadline exceeded", Cause: "timeout"},
					{IP: succeeded},
				}}},
			{ID: "dns", Name: "dns", Status: StatusPass, Ran: true, DurationMs: 1,
				Observed: &Observed{Addresses: []string{failed, succeeded}}},
		},
		Diagnosis: Diagnosis{Verdict: "degraded", Summary: "one address fails", Blamed: "target_tcp",
			Findings: []Finding{{
				ID: "partial_reachability", Verdict: "degraded", Summary: "one address fails", Focus: "target_tcp",
				Evidence:       []string{"target_tcp", "dns"},
				CausalEvidence: append(append([]CausalEvidence{}, failure...), success...),
				Counterfactual: &Counterfactual{Variable: CounterfactualResolvedAddress, Alternatives: []CounterfactualAlternative{
					{Value: failed, Outcome: "failed", Evidence: failure},
					{Value: succeeded, Outcome: "succeeded", Evidence: success},
				}},
			}}},
		OK: true,
	}
}

// A resolved_address alternative is named by an address, so it takes the same
// pseudonym as the recordings it is about, including the evidence nested
// inside it. That nested evidence is also what the alternative's reference
// resolves through, so a value out of step with the finding's own copy is an
// artifact whose counterfactual references nothing.
func TestResolvedAddressAlternativesShareThePseudonymOfTheirEvidence(t *testing.T) {
	const failed, succeeded = "2001:db8::7", "2001:db8::9"
	sanitized := sanitizeValid(t, resolvedAddressCounterfactualSnapshot(failed, succeeded))
	finding := sanitized.Diagnosis.Findings[0]
	answers := sanitized.Checks[1].Observed.Addresses
	for i, alternative := range finding.Counterfactual.Alternatives {
		if !isAddress(alternative.Value) {
			t.Errorf("alternative %q is not an address", alternative.Value)
		}
		if alternative.Value != answers[i] {
			t.Errorf("alternative named %q, want the recorded answer's pseudonym %q", alternative.Value, answers[i])
		}
		for _, evidence := range alternative.Evidence {
			if evidence.Value != alternative.Value {
				t.Errorf("%s nested under alternative %q named %q", evidence.Observation, alternative.Value, evidence.Value)
			}
		}
		if carried := finding.CausalEvidence[2*i].Value; carried != alternative.Value {
			t.Errorf("the finding carries %q where its alternative names %q", carried, alternative.Value)
		}
	}
	if finding.Counterfactual.Alternatives[0].Value == finding.Counterfactual.Alternatives[1].Value {
		t.Error("two addresses collapsed onto one alternative")
	}
}

// wordCounterfactualSnapshot is a counterfactual whose alternatives are named
// by words rather than by an address: which resolver answered, or which
// address family was tried.
func wordCounterfactualSnapshot(variable, first, second string) Snapshot {
	row := func(id string) Check {
		return Check{ID: id, Name: id, Status: StatusFail, Ran: true, DurationMs: 1,
			Cause: "dns_not_found", CauseFamily: "ipv4", Observed: &Observed{DNSNotFound: true}}
	}
	alternative := func(value, check string) CounterfactualAlternative {
		return CounterfactualAlternative{Value: value, Outcome: "not_found", Evidence: []CausalEvidence{
			{Kind: EvidenceSupport, Check: check, Observation: ObservationDNSNotFound},
		}}
	}
	first0, second0 := alternative(first, "dns"), alternative(second, "dns_public")
	return Snapshot{CreatedAt: "2026-01-02T03:04:05Z", Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Checks: []Check{row("dns"), row("dns_public")},
		Diagnosis: Diagnosis{Verdict: "dns", Summary: "no records", Blamed: "dns", FailedStage: "dns",
			Findings: []Finding{{
				ID: "dns_name_not_found", Verdict: "dns", Summary: "no records", Focus: "dns",
				Evidence:       []string{"dns", "dns_public"},
				CausalEvidence: append(append([]CausalEvidence{}, first0.Evidence...), second0.Evidence...),
				Counterfactual: &Counterfactual{Variable: variable,
					Alternatives: []CounterfactualAlternative{first0, second0}},
			}}},
	}
}

// The resolver and family vocabularies are closed sets of words the format
// defines, so they stay themselves. Nothing here comes from the local machine
// or its network, and an alias would say nothing about what was compared.
func TestWordValuedCounterfactualAlternativesKeepTheirVocabulary(t *testing.T) {
	for _, tc := range []struct{ variable, first, second string }{
		{CounterfactualDNSResolver, "system", "independent"},
		{CounterfactualAddressFamily, "ipv4", "ipv6"},
	} {
		t.Run(tc.variable, func(t *testing.T) {
			sanitized := sanitizeValid(t, wordCounterfactualSnapshot(tc.variable, tc.first, tc.second))
			alternatives := sanitized.Diagnosis.Findings[0].Counterfactual.Alternatives
			for i, want := range []string{tc.first, tc.second} {
				if alternatives[i].Value != want {
					t.Errorf("%s alternative sanitized to %q, want %q", tc.variable, alternatives[i].Value, want)
				}
			}
		})
	}
}

// A word-valued variable whose value is shaped like an address is still a
// word-valued variable. Nothing about the spelling moves it into the address
// namespace, and because the value is outside the variable's own vocabulary it
// is not kept either: this build cannot say what that string is, so it is
// aliased rather than published.
func TestWordValuedCounterfactualDoesNotBecomeAnAddressByItsShape(t *testing.T) {
	const shaped = "192.0.2.1"
	sanitized := sanitizeValid(t, wordCounterfactualSnapshot(CounterfactualDNSResolver, shaped, "independent"))
	named := sanitized.Diagnosis.Findings[0].Counterfactual.Alternatives[0].Value
	if isAddress(named) {
		t.Errorf("an address-shaped resolver name sanitized into the address namespace as %q", named)
	}
	if named == shaped {
		t.Errorf("a value outside the resolver vocabulary survived verbatim as %q", named)
	}
}

// An observation a later netdoc names and this one does not says nothing about
// what its value is, and "unknown" is not a reason to publish a string. The
// artifact is not one this build can validate either way, so the only thing
// under test is that the value does not leave verbatim and does not take on a
// meaning nothing declared.
func TestUnknownObservationValueIsNotPublished(t *testing.T) {
	pinLocalIdentity(t)
	const unknownValue = "vpn-gateway.corp.example"
	s := routeEvidenceSnapshot(ObservationRouteTunneled, "wg0", "wg0")
	evidence := &s.Diagnosis.Findings[0].CausalEvidence[0]
	evidence.Observation, evidence.Value = "route_moon_phase", unknownValue
	named := SanitizeForSupport(s).Diagnosis.Findings[0].CausalEvidence[0]
	if named.Value == unknownValue {
		t.Errorf("an unknown observation published its value verbatim as %q", named.Value)
	}
	if isAddress(named.Value) {
		t.Errorf("an unknown observation's value was given address semantics as %q", named.Value)
	}
	// Forward compatibility is about the observation id, which a later build
	// still has to be able to read back.
	if named.Observation != "route_moon_phase" {
		t.Errorf("the unknown observation id became %q", named.Observation)
	}
}

// An observation whose evidence names no value gets none invented for it. A
// support artifact that filled one would be refused by its own encoder, since
// naming a value is the one thing those observations may not do.
func TestValuelessObservationsStayValueless(t *testing.T) {
	s := routeEvidenceSnapshot(ObservationRouteTunneled, "wg0", "wg0")
	s.Diagnosis.Findings[0].CausalEvidence[0] = CausalEvidence{
		Kind: EvidenceSupport, Check: "target_tcp", Observation: ObservationStatusFail,
	}
	if named := sanitizeValid(t, s).Diagnosis.Findings[0].CausalEvidence[0].Value; named != "" {
		t.Errorf("status_fail evidence gained the value %q", named)
	}
}

// pseudonymOf sanitizes an artifact once and reads one field's pseudonym back
// out, so a collision case can name an alias this build really hands out
// instead of hard-coding the arithmetic of one generator.
func pseudonymOf(t *testing.T, s Snapshot, read func(Snapshot) string) string {
	t.Helper()
	pinLocalIdentity(t)
	return read(SanitizeForSupport(s))
}

// A diagnosis can be the only place an address appears. Pseudonyms are
// allocated against the addresses the artifact already holds, so an original
// the collection pass never saw can be handed out as another address's alias.
// Redaction then meets that original again in the evidence, reads it as an
// alias of its own making, and returns it exactly as written: the original
// leaks, and the two next hops the finding was telling apart become one, which
// is a claim the file can no longer support.
func TestEvidenceOnlyAddressIsNotHandedBackAsAnotherAddressPseudonym(t *testing.T) {
	const answer = "2001:db8::7"
	collision := pseudonymOf(t, addressEvidenceRowSnapshot(answer, "2606:2800:220:1::2"), func(s Snapshot) string {
		return s.Checks[0].Observed.Routes[0].Gateway
	})
	sanitized := sanitizeValid(t, addressEvidenceRowSnapshot(answer, collision))
	named := sanitized.Diagnosis.Findings[0].CausalEvidence[4].Value
	gateway := sanitized.Checks[0].Observed.Routes[0].Gateway
	if named == collision {
		t.Errorf("the evidence's own next hop %q survived sanitization", collision)
	}
	if named == gateway {
		t.Errorf("the two next hops collapsed onto one pseudonym %q", named)
	}
	if !isAddress(named) {
		t.Errorf("route_next_hop_differs named %q, which is not an address", named)
	}
}

// The same hole through the counterfactual. An alternative names the address
// it is about, and nothing requires that address to appear in an observed row,
// so the collection pass has to reach the counterfactual as well.
func TestCounterfactualOnlyAddressIsNotHandedBackAsAnotherAddressPseudonym(t *testing.T) {
	const failed, succeeded = "2001:db8::7", "2001:db8::9"
	collision := pseudonymOf(t, resolvedAddressCounterfactualSnapshot(failed, succeeded), func(s Snapshot) string {
		return s.Checks[0].Observed.Attempts[0].IP
	})
	s := resolvedAddressCounterfactualSnapshot(failed, succeeded)
	s.Diagnosis.Findings[0].Counterfactual.Alternatives[0].Value = collision
	sanitized := sanitizeValid(t, s)
	named := sanitized.Diagnosis.Findings[0].Counterfactual.Alternatives[0].Value
	if named == collision {
		t.Errorf("the alternative's own address %q survived sanitization", collision)
	}
	if recorded := sanitized.Checks[0].Observed.Attempts[0].IP; named == recorded {
		t.Errorf("the alternative took the pseudonym %q of a different address", recorded)
	}
	if !isAddress(named) {
		t.Errorf("resolved_address named %q, which is not an address", named)
	}
}
