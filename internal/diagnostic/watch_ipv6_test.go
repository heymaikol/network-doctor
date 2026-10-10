package diagnostic

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"
)

// ipv6Pass runs one published Watch pass the way watchPass does. It also reports
// the executions of that pass, whether it measured every row itself, and how many
// attempts it took.
func ipv6Pass(t *testing.T, s *WatchSession, n *watchNet) (res map[ProbeID]ProbeResult, runs map[ProbeID]int, fresh bool, attempts int) {
	t.Helper()
	for attempt := 1; attempt <= 2; attempt++ {
		n.resetRuns()
		pass := s.Begin(n.graph(), time.Second)
		results := RunAll(context.Background(), pass.Probes(), time.Second)
		if pass.Publish(results) {
			return results, n.snapshotRuns(), pass.Fresh(), attempt
		}
	}
	t.Fatal("a fresh pass was not published")
	return nil, nil, false, 0
}

// checkIPv6Outage takes one IPv6 path down while IPv4 keeps working, holds it for a
// second pass, and brings it back. Each published pass must match a fresh pass, and
// the diagnosis must carry the finding want. Recovery must return the healthy
// diagnosis exactly. Both changes move a row verdict, so the verdict gate refuses the
// reused pass and the onset and the recovery are measured whole, on attempt 2.
func checkIPv6Outage(t *testing.T, set func(n *watchNet, down bool), want DiagnosisID) {
	t.Helper()
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	ipv6Pass(t, s, n) // settles the session, so later passes may reuse rows

	clock.Advance(5 * time.Second)
	healthy, _, _, _ := ipv6Pass(t, s, n)
	if !reusedAny(healthy) {
		t.Fatal("the healthy pass reused no row, so the outage would not test reuse")
	}
	probes := ProbeOrder(n.graph())
	healthyDiagnosis := Interpret(watchTarget(), probes, healthy)
	if healthyDiagnosis.Verdict != VerdictOK {
		t.Fatalf("healthy verdict %q, want ok", healthyDiagnosis.Verdict)
	}

	set(n, true)
	var outage Diagnosis
	for pass := range 2 {
		clock.Advance(5 * time.Second)
		res, _, fresh, attempts := ipv6Pass(t, s, n)
		assertFreshDiagnosis(t, n, res)
		// IPv4 evidence stays correct: both rows still report IPv4 reachable.
		if f := res[ProbeTargetTCP].Families; f == nil || f.IPv4 != FamilyReachable {
			t.Fatalf("pass %d: target IPv4 family %+v, want reachable", pass, f)
		}
		if f := res[ProbeInternet].Families; f == nil || f.IPv4 != FamilyReachable {
			t.Fatalf("pass %d: egress IPv4 family %+v, want reachable", pass, f)
		}
		if pass == 0 {
			checkWhole(t, fresh, attempts)
		}
		outage = Interpret(watchTarget(), probes, res)
		finding := diagnosisFinding(outage, want)
		if finding == nil {
			t.Fatalf("pass %d: diagnosis %+v has no %s finding", pass, outage, want)
		}
		if !slices.ContainsFunc(finding.Evidence, func(e CausalEvidence) bool { return e.Value == counterfactualIPv6 }) {
			t.Errorf("pass %d: finding %s carries no ipv6 evidence: %+v", pass, want, finding.Evidence)
		}
	}
	if reflect.DeepEqual(outage, healthyDiagnosis) {
		t.Fatal("the outage diagnosis equals the healthy one, so the fault did not reach the diagnosis")
	}

	set(n, false)
	clock.Advance(5 * time.Second)
	recovered, _, fresh, attempts := ipv6Pass(t, s, n)
	assertFreshDiagnosis(t, n, recovered)
	checkWhole(t, fresh, attempts)
	if got := Interpret(watchTarget(), probes, recovered); !reflect.DeepEqual(got, healthyDiagnosis) {
		t.Errorf("recovered diagnosis differs from the healthy one:\n got  %+v\n want %+v", got, healthyDiagnosis)
	}
}

// checkWhole asserts that a pass which changed a verdict was measured whole, on the
// attempt the verdict gate lets through.
func checkWhole(t *testing.T, fresh bool, attempts int) {
	t.Helper()
	if !fresh || attempts != 2 {
		t.Errorf("fresh=%v attempts=%d, want a whole measurement on attempt 2: the verdict changed, so the reused pass is refused", fresh, attempts)
	}
}

// diagnosisFinding returns the finding with id, or nil when the diagnosis has none.
func diagnosisFinding(d Diagnosis, id DiagnosisID) *DiagnosisFinding {
	for i := range d.Findings {
		if d.Findings[i].ID == id {
			return &d.Findings[i]
		}
	}
	return nil
}

// TestWatchIPv6EgressOutageAndRecoveryMatchFreshPasses takes IPv6 egress down. The
// egress row warns and names the IPv6 cause, while IPv4 egress is unchanged.
func TestWatchIPv6EgressOutageAndRecoveryMatchFreshPasses(t *testing.T) {
	checkIPv6Outage(t, func(n *watchNet, down bool) { n.egressIPv6Down = down }, DiagnosisDirectEgressDegraded)
}

// TestWatchIPv6TargetOutageAndRecoveryMatchFreshPasses takes only the target's IPv6
// address down. IPv6 egress and the IPv4 target still work, so the diagnosis names the
// IPv6 target family, as a fresh pass does.
func TestWatchIPv6TargetOutageAndRecoveryMatchFreshPasses(t *testing.T) {
	checkIPv6Outage(t, func(n *watchNet, down bool) { n.targetIPv6Down = down }, DiagnosisIPv6TargetUnreachable)
}
