package diagnostic

import (
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// Start with the same real builder as the published golden, plus a kernel
// route decision. Each case changes only the observation it names.
func observationArtifact(t *testing.T) snapshot.Snapshot {
	t.Helper()
	target, probes, results := fixtureRun()
	r := results[ProbeTargetTCP]
	r.Routes = []RouteDecision{{Destination: net.ParseIP("93.184.216.34"), Family: "ipv4", Iface: "wg0",
		Gateway: net.ParseIP("192.0.2.1"), Source: net.ParseIP("192.0.2.10"),
		Prefix: netip.MustParsePrefix("0.0.0.0/0"), MTU: 1500, Tunnel: TunnelKnown, TunnelKind: "wireguard"}}
	results[ProbeTargetTCP] = r
	s := withSnapshotProvenance(BuildSnapshot(target, probes, results))
	assertObservationBoundaries(t, s, "")
	return s
}

func observationCheck(s *snapshot.Snapshot, id string) *snapshot.Check {
	for i := range s.Checks {
		if s.Checks[i].ID == id {
			return &s.Checks[i]
		}
	}
	panic("missing check " + id)
}

// The profile wrapper changes no component evidence or execution state.
func observationProfile(s snapshot.Snapshot) snapshot.ProfileSnapshot {
	return snapshot.ProfileSnapshot{Schema: snapshot.ProfileSchema, CreatedAt: s.CreatedAt, Tool: s.Tool,
		Redaction:  s.Redaction,
		Profile:    snapshot.ProfileIdentity{Name: "audit", Version: 1, Title: "Observation audit"},
		Components: []snapshot.ProfileComponent{{ID: "target", Label: "Target", Focus: "target_tcp", Status: snapshot.StatusFail, Snapshot: s}},
		Aggregate: snapshot.ProfileAggregate{Status: snapshot.StatusFail, Summary: "Target failed.", Finding: &snapshot.ProfileFinding{
			ID: "audit_unreachable", AffectedComponents: []string{"target"}}}}
}

func assertObservationBoundaries(t *testing.T, s snapshot.Snapshot, want string) {
	t.Helper()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	p := observationProfile(s)
	profileData, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	_, encodeErr := snapshot.Encode(s)
	_, decodeErr := snapshot.Decode(data)
	_, profileEncodeErr := snapshot.EncodeProfile(p)
	_, profileDecodeErr := snapshot.DecodeProfile(profileData)
	for _, boundary := range []struct {
		name string
		err  error
	}{
		{"Validate", snapshot.Validate(s)}, {"Encode", encodeErr}, {"Decode", decodeErr},
		{"EncodeProfile", profileEncodeErr}, {"DecodeProfile", profileDecodeErr},
	} {
		if want == "" && boundary.err != nil {
			t.Fatalf("valid seed: %s: %v", boundary.name, boundary.err)
		}
		if want != "" && (boundary.err == nil || !strings.Contains(boundary.err.Error(), want)) {
			t.Errorf("%s: got %v, want rejection containing %q", boundary.name, boundary.err, want)
		}
	}
}

func TestObservationValidationBoundaries(t *testing.T) {
	cases := []struct {
		name, field string
		mutate      func(*snapshot.Snapshot)
	}{
		{"check duration", "duration_ms", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").DurationMs = -1 }},
		{"attempt duration", "duration_ms", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").Observed.Attempts[0].DurationMs = -1 }},
		{"cause family", "cause_family", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").CauseFamily = "ipv5" }},
		{"address", "addresses", func(s *snapshot.Snapshot) { observationCheck(s, "dns").Observed.Addresses[0] = "not-an-ip" }},
		{"empty address", "addresses", func(s *snapshot.Snapshot) { observationCheck(s, "dns").Observed.Addresses[0] = "" }},
		{"selected IP", "selected_ip", func(s *snapshot.Snapshot) { observationCheck(s, "internet_tcp").Observed.SelectedIP = "not-an-ip" }},
		{"source IP", "source_ip", func(s *snapshot.Snapshot) { observationCheck(s, "iface").Observed.SourceIP = "not-an-ip" }},
		{"resolver", "resolver", func(s *snapshot.Snapshot) { observationCheck(s, "dns_public").Observed.Resolver = "not-an-ip" }},
		{"attempt IP", "ip", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").Observed.Attempts[0].IP = "not-an-ip" }},
		{"empty attempt IP", "ip", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").Observed.Attempts[0].IP = "" }},
		{"IPv4 reachability", "ipv4", func(s *snapshot.Snapshot) { observationCheck(s, "internet_tcp").Observed.Families.IPv4 = "maybe" }},
		{"IPv6 reachability", "ipv6", func(s *snapshot.Snapshot) { observationCheck(s, "internet_tcp").Observed.Families.IPv6 = "maybe" }},
	}
	for _, routeCase := range []struct {
		name, field string
		mutate      func(*snapshot.Route)
	}{
		{"destination", "destination", func(r *snapshot.Route) { r.Destination = "not-an-ip" }},
		{"empty destination", "destination", func(r *snapshot.Route) { r.Destination = "" }},
		{"gateway", "gateway", func(r *snapshot.Route) { r.Gateway = "not-an-ip" }},
		{"source", "source", func(r *snapshot.Route) { r.Source = "not-an-ip" }},
		{"prefix", "prefix", func(r *snapshot.Route) { r.Prefix = "192.0.2.0/33" }},
		{"family", "family", func(r *snapshot.Route) { r.Family = "ipv5" }},
		{"family mismatch", "family", func(r *snapshot.Route) { r.Family = "ipv6" }},
		{"tunnel", "tunnel", func(r *snapshot.Route) { r.Tunnel = "maybe" }},
		{"kind without tunnel", "tunnel_kind", func(r *snapshot.Route) { r.Tunnel = "" }},
		{"kind with likely tunnel", "tunnel_kind", func(r *snapshot.Route) { r.Tunnel = "likely" }},
		{"kind with direct route", "tunnel_kind", func(r *snapshot.Route) { r.Tunnel = "direct" }},
		{"MTU", "interface_mtu", func(r *snapshot.Route) { r.InterfaceMTU = -1 }},
	} {
		cases = append(cases, struct {
			name, field string
			mutate      func(*snapshot.Snapshot)
		}{"route " + routeCase.name, routeCase.field,
			func(s *snapshot.Snapshot) { routeCase.mutate(&observationCheck(s, "target_tcp").Observed.Routes[0]) }})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sanitized := range []bool{false, true} {
				s := observationArtifact(t)
				if sanitized {
					s = snapshot.SanitizeForSupport(s)
					assertObservationBoundaries(t, s, "")
				}
				tc.mutate(&s)
				assertObservationBoundaries(t, s, tc.field)
			}
		})
	}
}

func TestObservationValidationPreservesV1(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*snapshot.Snapshot)
	}{
		{"zero timings", func(s *snapshot.Snapshot) {
			c := observationCheck(s, "target_tcp")
			c.DurationMs = 0
			c.Observed.Attempts[0].DurationMs = 0
		}},
		{"unknown readings", func(s *snapshot.Snapshot) {
			o := observationCheck(s, "internet_tcp").Observed
			o.SelectedIP, o.SourceIP = "", ""
			o.Families = &snapshot.Families{}
			r := &observationCheck(s, "target_tcp").Observed.Routes[0]
			*r = snapshot.Route{Destination: r.Destination}
			observationCheck(s, "dns_public").Observed.Resolver = ""
		}},
		{"both family causes", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").CauseFamily = "ipv4" }},
		{"IPv6 cause", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").CauseFamily = "ipv6" }},
		{"reachability vocabulary", func(s *snapshot.Snapshot) {
			observationCheck(s, "internet_tcp").Observed.Families = &snapshot.Families{IPv4: "unreachable", IPv6: "reachable"}
		}},
		{"IPv6 readings", func(s *snapshot.Snapshot) {
			observationCheck(s, "iface").Observed.SourceIP = "::1"
			observationCheck(s, "dns_public").Observed.Resolver = "2001:db8::53"
			o := observationCheck(s, "target_tcp").Observed
			o.Attempts[0].IP = "2001:db8::1"
			o.Routes[0] = snapshot.Route{Destination: "2001:db8::1", Family: "ipv6", Source: "::1", Gateway: "fe80::1", Prefix: "::/0"}
		}},
		{"mapped IPv4", func(s *snapshot.Snapshot) {
			observationCheck(s, "target_tcp").Observed.Routes[0].Destination = "::ffff:93.184.216.34"
		}},
		{"mapped prefix", func(s *snapshot.Snapshot) {
			observationCheck(s, "target_tcp").Observed.Routes[0].Prefix = "::ffff:93.184.216.34/128"
		}},
		{"minimum MTU and host prefix", func(s *snapshot.Snapshot) {
			r := &observationCheck(s, "target_tcp").Observed.Routes[0]
			r.InterfaceMTU = 1
			r.Prefix = "93.184.216.34/32"
		}},
		{"large MTU and unknown metric", func(s *snapshot.Snapshot) {
			r := &observationCheck(s, "target_tcp").Observed.Routes[0]
			r.InterfaceMTU = 65536
			r.Metric = nil
		}},
		{"known zero metric and main table", func(s *snapshot.Snapshot) {
			r := &observationCheck(s, "target_tcp").Observed.Routes[0]
			metric := 0
			r.Metric = &metric
			r.TableKnown = true
			r.Table = ""
			r.Competing = []snapshot.CompetingRoute{{Metric: 0}}
		}},
		{"legacy table without knowledge", func(s *snapshot.Snapshot) {
			r := &observationCheck(s, "target_tcp").Observed.Routes[0]
			r.Table = "table 100"
			r.TableKnown = false
		}},
		{"cross family next hop", func(s *snapshot.Snapshot) {
			observationCheck(s, "target_tcp").Observed.Routes[0].Gateway = "fe80::1"
		}},
		{"direct", func(s *snapshot.Snapshot) {
			r := &observationCheck(s, "target_tcp").Observed.Routes[0]
			r.Tunnel = "direct"
			r.TunnelKind = ""
		}},
		{"likely", func(s *snapshot.Snapshot) {
			r := &observationCheck(s, "target_tcp").Observed.Routes[0]
			r.Tunnel = "likely"
			r.TunnelKind = ""
		}},
		{"tunnel without kind", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").Observed.Routes[0].TunnelKind = "" }},
		{"extensible machine values", func(s *snapshot.Snapshot) {
			c := observationCheck(s, "target_tcp")
			c.Cause = "future_cause"
			c.Observed.Attempts[0].Cause = "future_attempt_cause"
			c.Observed.Routes[0].TunnelKind = "future_device"
			c.Observed.Routes[0].Reason = "future_reason"
			s.Checks = append(s.Checks, snapshot.Check{ID: "future_check", Status: snapshot.StatusPass, Ran: true})
			s.Diagnosis.Findings = append(s.Diagnosis.Findings, snapshot.Finding{ID: "future_finding"})
		}},
		{"signed clock offset", func(s *snapshot.Snapshot) {
			offset := int64(-1)
			observationCheck(s, "internet_tcp").Observed.ClockOffsetMs = &offset
		}},
		{"legacy untyped attempt error", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").Observed.Attempts[0].Cause = "" }},
		{"aborted failure need not be canceled", func(s *snapshot.Snapshot) { observationCheck(s, "target_tcp").Observed.Attempts[0].Aborted = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := observationArtifact(t)
			tc.mutate(&s)
			assertObservationBoundaries(t, s, "")
			assertObservationBoundaries(t, snapshot.SanitizeForSupport(s), "")
		})
	}
}

func TestObservationValidationAcceptsAdditiveJSON(t *testing.T) {
	s := observationArtifact(t)
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	// Unknown keys inside every observation object remain additive, including
	// an entire unfamiliar nested object rather than only a scalar value.
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	var extend func(any)
	extend = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for _, child := range v {
				extend(child)
			}
			v["future_observation"] = map[string]any{"version": 2}
		case []any:
			for _, child := range v {
				extend(child)
			}
		}
	}
	extend(value)
	data, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	assertObservationBoundaries(t, decoded, "")
	p := observationProfile(s)
	profileData, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(profileData, &value); err != nil {
		t.Fatal(err)
	}
	extend(value)
	profileData, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.DecodeProfile(profileData); err != nil {
		t.Fatal(err)
	}
}

func TestObservationValidationPreservesSupportErasure(t *testing.T) {
	s := observationArtifact(t)
	// support-v1 documents this exact placeholder for an address it erased.
	// It is unknown evidence, not a newly invented endpoint or IPv6 address.
	marker := "<address-redacted>"
	observationCheck(&s, "dns").Observed.Addresses[0] = marker
	observationCheck(&s, "internet_tcp").Observed.SelectedIP = marker
	observationCheck(&s, "iface").Observed.SourceIP = marker
	observationCheck(&s, "dns_public").Observed.Resolver = marker
	o := observationCheck(&s, "target_tcp").Observed
	o.Attempts[0].IP = marker
	o.Routes[0].Destination, o.Routes[0].Gateway, o.Routes[0].Source = marker, marker, marker
	assertObservationBoundaries(t, s, "IP address")
	assertObservationBoundaries(t, snapshot.SanitizeForSupport(s), "")
}
