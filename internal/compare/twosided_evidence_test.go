package compare

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

func evidenceArtifact(t *testing.T, check snapshot.Check) snapshot.Snapshot {
	t.Helper()
	// ran follows the status the caller asked for, because the format holds
	// the two together: only a probe body that executed reports an outcome,
	// and a skipped or unreported row was never called.
	check.Ran = !snapshot.ExecutionContradicts(snapshot.Check{Status: check.Status, Ran: true})
	if check.Ran && check.DurationMs == 0 {
		check.DurationMs = 1
	}
	s := snapshot.Snapshot{Schema: snapshot.Schema, Checks: []snapshot.Check{check}, OK: check.Status != snapshot.StatusFail && check.Status != snapshot.StatusIncomplete}
	if check.Status == snapshot.StatusFail {
		s.Diagnosis.FailedStage = check.ID
	}
	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	s, err = snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dimension(t *testing.T, row SideRow, name string) EvidenceComparison {
	t.Helper()
	for _, e := range row.Evidence {
		if e.Dimension == name {
			return e
		}
	}
	t.Fatalf("missing dimension %s: %+v", name, row)
	return EvidenceComparison{}
}

func TestTwoSidedEvidenceUnknownAndSettings(t *testing.T) {
	a := evidenceArtifact(t, snapshot.Check{ID: "tls", Status: snapshot.StatusFail, Cause: "timeout", Observed: &snapshot.Observed{SelectedIP: "192.0.2.1"}})
	for _, status := range []string{snapshot.StatusPass, snapshot.StatusWarn, snapshot.StatusFail, snapshot.StatusSkip, snapshot.StatusNA, snapshot.StatusIncomplete} {
		t.Run(status, func(t *testing.T) {
			b := evidenceArtifact(t, snapshot.Check{ID: "tls", Status: status}) // pre-optional-evidence v1
			b.Options.ProbeTimeoutMs = 123
			b.Options.Check = []string{"tls"}
			a.CreatedAt, b.CreatedAt = "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z"
			got := twoSided(t, a, b)
			row := got.Checks[0]
			if measured(status) {
				for _, e := range row.Evidence {
					if e.Relation != "unknown" || e.Reason != "missing_evidence" {
						t.Fatalf("invented missing evidence: %+v", e)
					}
				}
			} else if row.Comparable || len(row.Evidence) != 0 {
				t.Fatalf("unmeasured evidence read: %+v", row)
			}
			if !hasCaveat(got, "timeouts differ") || !hasCaveat(got, "selected different probes") || !hasCaveat(got, "1 day apart") {
				t.Fatal(got.Caveats)
			}
		})
	}
	// Different budgets and capture times qualify causation, not the recorded
	// outcome. Identical explicit causes remain equivalent in that dimension.
	b := a
	b.Options.ProbeTimeoutMs = 1
	if e := dimension(t, twoSided(t, a, b).Checks[0], "cause"); e.Relation != "equivalent" {
		t.Fatal(e)
	}
}

func TestTwoSidedEvidenceOrderAndHistory(t *testing.T) {
	a := snapshot.Check{ID: "target_tcp", Status: snapshot.StatusWarn, Observed: &snapshot.Observed{
		Attempts:   []snapshot.Attempt{{IP: "192.0.2.1", Cause: "canceled", Error: "context canceled", Aborted: true}, {IP: "192.0.2.2"}, {IP: "192.0.2.1", Cause: "timeout", Error: "deadline exceeded"}},
		SelectedIP: "192.0.2.2",
		Routes:     []snapshot.Route{{Destination: "192.0.2.1", Tunnel: "direct"}, {Destination: "192.0.2.2", Tunnel: "tunnel"}},
	}}
	s := evidenceArtifact(t, a)
	b := evidenceArtifact(t, a)
	b.Checks[0].Observed.Attempts[0], b.Checks[0].Observed.Attempts[1] = b.Checks[0].Observed.Attempts[1], b.Checks[0].Observed.Attempts[0]
	slices.Reverse(b.Checks[0].Observed.Routes)
	b.Checks[0].Observed.Attempts[1].Error = "different untrusted prose"
	b.Checks[0].Observed.Attempts[1].DurationMs = 99999
	b.Checks[0].Detail, b.Checks[0].Fix = "untrusted detail", "untrusted fix"
	base, got := twoSided(t, s, s), twoSided(t, s, b)
	if !reflect.DeepEqual(base.Checks, got.Checks) {
		t.Fatalf("harmless order/prose changed evidence: %+v", got.Checks)
	}
	// Same-address retry order is not a chronology promised by the artifact,
	// either. This matches TestRepeatedAddressAttemptsRetainVerificationEvidence.
	b.Checks[0].Observed.Attempts[1], b.Checks[0].Observed.Attempts[2] = b.Checks[0].Observed.Attempts[2], b.Checks[0].Observed.Attempts[1]
	got = twoSided(t, s, b)
	if dimension(t, got.Checks[0], "attempts").Relation != "equivalent" || dimension(t, got.Checks[0], "attempt_outcomes").Relation != "equivalent" {
		t.Fatal(got.Checks)
	}
	// Multiplicity is still recorded evidence. Do not turn one recorded attempt
	// into two, or treat an enclosing cancellation as an address timeout.
	b.Checks[0].Observed.Attempts = append(b.Checks[0].Observed.Attempts, b.Checks[0].Observed.Attempts[2])
	got = twoSided(t, s, b)
	if dimension(t, got.Checks[0], "attempts").Relation != "different" {
		t.Fatal(got.Checks)
	}
	if !reflect.DeepEqual(base.Diagnosis, got.Diagnosis) {
		t.Fatal("history became causal localization")
	}
}

func TestTwoSidedDNSAddressSets(t *testing.T) {
	a := evidenceArtifact(t, snapshot.Check{ID: "dns", Status: snapshot.StatusPass, Observed: &snapshot.Observed{Addresses: []string{"2001:db8::1", "192.0.2.1"}}})
	b := evidenceArtifact(t, snapshot.Check{ID: "dns", Status: snapshot.StatusPass, Observed: &snapshot.Observed{Addresses: []string{"192.0.2.1", "2001:0db8:0:0:0:0:0:1", "192.0.2.1"}}})
	if dimension(t, twoSided(t, a, b).Checks[0], "addresses").Relation != "equivalent" {
		t.Fatal("address set order, duplication or spelling read as semantic")
	}
	b.Checks[0].Observed.Addresses = []string{"192.0.2.1", "192.0.2.2"}
	got := twoSided(t, a, b)
	if dimension(t, got.Checks[0], "addresses").Relation != "different" || got.Diagnosis.Side != SideNone {
		t.Fatal(got)
	}
}

func TestTwoSidedFamilyAndRouteDimensionsStayIndependent(t *testing.T) {
	// These fragments describe partial target reachability: the same IPv4
	// winner, with independent IPv6 success on A and failure on B. A common
	// selected address is not evidence that the other family worked.
	a := snapshot.Check{ID: "target_tcp", Status: snapshot.StatusWarn, Observed: &snapshot.Observed{
		SelectedIP: "192.0.2.1", Families: &snapshot.Families{IPv4: "reachable", IPv6: "reachable"},
	}}
	b := a
	b.Observed = &snapshot.Observed{SelectedIP: "192.0.2.1", Families: &snapshot.Families{IPv4: "reachable", IPv6: "unreachable"}}
	row := SideRow{Evidence: checkEvidence(a, b, false)}
	if dimension(t, row, "selected_ip").Relation != "equivalent" || dimension(t, row, "address_families.ipv6").Relation != "different" {
		t.Fatal(row)
	}
	// Kernel selection and link MTU are independent of transport success.
	// Missing MTU on an older/platform-limited record never means zero.
	a.Observed.Routes = []snapshot.Route{{Destination: "192.0.2.1", Interface: "eth0", Tunnel: "direct", InterfaceMTU: 1500}}
	b.Observed.Routes = []snapshot.Route{{Destination: "192.0.2.1", Interface: "tun0", Tunnel: "tunnel", InterfaceMTU: 1280}}
	row.Evidence = checkEvidence(a, b, false)
	if dimension(t, row, "route_link_mtu").Relation != "different" || dimension(t, row, "route_selection").Relation != "equivalent" {
		t.Fatal(row)
	}
	b.Observed.Routes[0].InterfaceMTU = 0
	if e := dimension(t, SideRow{Evidence: checkEvidence(a, b, false)}, "route_link_mtu"); e.Relation != "unknown" {
		t.Fatal(e)
	}
	// Compare a failed target's recorded kernel decisions. Do not construct a
	// successful socket with an unreachable route to explain it.
	a.Status, b.Status = snapshot.StatusFail, snapshot.StatusFail
	a.Observed.SelectedIP, b.Observed.SelectedIP = "", ""
	a.Observed.Families, b.Observed.Families = nil, nil
	b.Observed.Routes = []snapshot.Route{{Destination: "192.0.2.1", Unreachable: true}}
	if e := dimension(t, SideRow{Evidence: checkEvidence(a, b, false)}, "route_selection"); e.Relation != "different" {
		t.Fatal(e)
	}
}

func TestTwoSidedSupportEvidenceDoesNotComparePseudonyms(t *testing.T) {
	makeSide := func(ip, cause, tunnel string) snapshot.Snapshot {
		rowCause := ""
		if cause == "connection_refused" {
			rowCause = cause
		}
		return evidenceArtifact(t, snapshot.Check{ID: "target_tcp", Status: snapshot.StatusFail, Cause: rowCause, Observed: &snapshot.Observed{
			Attempts: []snapshot.Attempt{{IP: ip, Cause: cause, Error: "failed"}},
			Routes:   []snapshot.Route{{Destination: ip, Tunnel: tunnel}},
		}})
	}
	a, b := makeSide("10.23.0.1", "connection_refused", "direct"), makeSide("10.23.0.2", "timeout", "tunnel")
	for _, mixed := range []bool{false, true} {
		x, y := snapshot.SanitizeForSupport(a), snapshot.SanitizeForSupport(b)
		if mixed {
			x = a
		}
		got := twoSided(t, x, y)
		for _, name := range []string{"attempts", "route_tunnel"} {
			e := dimension(t, got.Checks[0], name)
			if e.Relation != "unknown" || e.Reason != "redacted_identity" {
				t.Fatal(e)
			}
		}
		for _, name := range []string{"attempt_outcomes", "route_tunnel_states"} {
			if e := dimension(t, got.Checks[0], name); e.Relation != "different" {
				t.Fatal(e)
			}
		}
		if !got.Diagnosis.Ambiguous || !hasCaveat(got, "pseudonyms are local") {
			t.Fatal(got)
		}
	}
	// Separate original endpoints can get exactly the same support pseudonym.
	b = makeSide("10.23.0.2", "connection_refused", "direct")
	x, y := snapshot.SanitizeForSupport(a), snapshot.SanitizeForSupport(b)
	if x.Checks[0].Observed.Attempts[0].IP != y.Checks[0].Observed.Attempts[0].IP {
		t.Fatal("fixture did not produce pseudonym collision")
	}
	if e := dimension(t, twoSided(t, x, y).Checks[0], "attempts"); e.Relation != "unknown" {
		t.Fatal(e)
	}
	// Nor do different spellings prove different originals: another address
	// encountered first shifts the per-artifact mapping.
	b = makeSide("10.23.0.1", "connection_refused", "direct")
	b.Checks[0].Observed.Addresses = []string{"10.23.0.9"}
	y = snapshot.SanitizeForSupport(b)
	if x.Checks[0].Observed.Attempts[0].IP == y.Checks[0].Observed.Attempts[0].IP {
		t.Fatal("fixture did not shift pseudonym")
	}
	if e := dimension(t, twoSided(t, x, y).Checks[0], "attempts"); e.Relation != "unknown" {
		t.Fatal(e)
	}
}

func TestTwoSidedOptionalEvidenceNeverInventsNegation(t *testing.T) {
	a := evidenceArtifact(t, snapshot.Check{ID: "https", Status: snapshot.StatusFail, Observed: &snapshot.Observed{Timeout: true, SelectedIP: "192.0.2.1"}})
	b := evidenceArtifact(t, snapshot.Check{ID: "https", Status: snapshot.StatusFail, Observed: &snapshot.Observed{SelectedIP: "192.0.2.1"}})
	if e := dimension(t, twoSided(t, a, b).Checks[0], "protocol_timeout"); e.Relation != "unknown" {
		t.Fatal(e)
	}
	// Old attempts with error prose but no stable cause cannot be promoted to
	// success, or classified by reading that prose.
	b.Checks[0].Observed.Attempts = []snapshot.Attempt{{IP: "192.0.2.1", Error: "timeout"}}
	a.Checks[0].Observed.Attempts = []snapshot.Attempt{{IP: "192.0.2.1", Error: "timeout", Cause: "timeout"}}
	if e := dimension(t, twoSided(t, a, b).Checks[0], "attempts"); e.Relation != "unknown" {
		t.Fatal(e)
	}
}

func TestTwoSidedClockAndResolverNormalization(t *testing.T) {
	nearZero, jitter, skew := int64(12), int64(90), int64(-600000)
	a := snapshot.Check{ID: "internet_tcp", Status: snapshot.StatusPass, Observed: &snapshot.Observed{ClockOffsetMs: &nearZero}}
	b := snapshot.Check{ID: "internet_tcp", Status: snapshot.StatusPass, Observed: &snapshot.Observed{ClockOffsetMs: &jitter}}
	if e := dimension(t, SideRow{Evidence: checkEvidence(a, b, false)}, "clock_offset_seconds"); e.Relation != "equivalent" {
		t.Fatal(e)
	}
	b.Observed.ClockOffsetMs = &skew
	if e := dimension(t, SideRow{Evidence: checkEvidence(a, b, false)}, "clock_offset_seconds"); e.Relation != "different" || e.B[0].Value != "-600" {
		t.Fatal(e)
	}
	b.Observed.ClockOffsetMs = nil
	if e := dimension(t, SideRow{Evidence: checkEvidence(a, b, false)}, "clock_offset_seconds"); e.Relation != "unknown" {
		t.Fatal(e)
	}
	a.ID, b.ID = "dns", "dns"
	a.Observed, b.Observed = &snapshot.Observed{ResolverTargets: []string{"[2001:db8::1]:53", "192.0.2.1:53"}}, &snapshot.Observed{ResolverTargets: []string{"192.0.2.1:53", "[2001:0db8::1]:53", "192.0.2.1:53"}}
	if e := dimension(t, SideRow{Evidence: checkEvidence(a, b, false)}, "resolver_targets"); e.Relation != "equivalent" {
		t.Fatal(e)
	}
}

func TestTwoSidedEvidenceRenderingAndHistory(t *testing.T) {
	a := evidenceArtifact(t, snapshot.Check{ID: "tls", Status: snapshot.StatusFail, Cause: "timeout"})
	b := evidenceArtifact(t, snapshot.Check{ID: "tls", Status: snapshot.StatusFail, Cause: "hostname_mismatch"})
	got := twoSided(t, a, b)
	before := got
	b.Diagnosis = snapshot.Diagnosis{Verdict: "historical", Findings: []snapshot.Finding{{ID: "invented"}}}
	got = twoSided(t, a, b)
	if !reflect.DeepEqual(before.Checks, got.Checks) || !reflect.DeepEqual(before.Diagnosis, got.Diagnosis) {
		t.Fatal("historical diagnosis became authoritative")
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`"schema":"netdoc.twosided.v1"`, `"dimension":"cause"`, `"relation":"different"`, `"side":"shared"`} {
		if !strings.Contains(string(data), fragment) {
			t.Fatalf("JSON missing %s", fragment)
		}
	}
	for _, fragment := range []string{"Recorded evidence", "timeout", "hostname_mismatch", "different", "not different root causes"} {
		if !strings.Contains(got.Text(), fragment) {
			t.Fatalf("text missing %s", fragment)
		}
	}
	// An old consumer can still decode exactly the original row fields.
	var old struct {
		Checks []struct {
			ID, A, B   string
			Comparable bool
		}
	}
	if err := json.Unmarshal(data, &old); err != nil || len(old.Checks) != 1 || old.Checks[0].A != "FAIL" || !old.Checks[0].Comparable {
		t.Fatalf("old consumer: %+v %v", old, err)
	}
}
