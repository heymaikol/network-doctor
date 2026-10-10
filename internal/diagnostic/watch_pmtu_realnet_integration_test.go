//go:build integration

package diagnostic

// A path-MTU black hole injected into a Watch session over real loopback
// sockets. The fault uses the two seams the production probes read: the send
// queue the path MTU row measures, and the TLS handshake the target holds open.
// Together they are the client-side signature of a black hole, a connect that
// works, a bulk write that never drains, and a handshake that stalls. The
// kernel-level black hole, a narrowed hop with ICMP suppressed, is the
// simulator's pmtu-blackhole scenario, and its netns tests prove that scenario
// makes path_mtu WARN.
//
// Run with: go test -tags integration -run TestRealWatchPathMTU ./internal/diagnostic

import (
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/incident"
)

func TestRealWatchPathMTUFaultAndRecovery(t *testing.T) {
	// The path MTU row reads the send queue, and only Linux and macOS report it.
	// Elsewhere the row is N/A on every pass, so there is no fault to watch.
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("path MTU is not measured on %s: the send queue is not reported", runtime.GOOS)
	}
	n := newRealNet(t)
	clock := newWatchClock()
	s := NewWatchSession(clock.Now)
	var sessionTL, oracleTL incident.Timeline
	// The black hole is on from onset through degraded. The handshake stalls only
	// from onset through sustained, so degraded is a pass where the handshake works
	// and the bulk write does not.
	const onset, sustained, degraded, recovered, steps = 3, 4, 5, 6, 9
	var injectedAt time.Time
	for i := 0; i < steps; i++ {
		if i > 0 {
			clock.Advance(5 * time.Second)
		}
		switch i {
		case onset:
			injectedAt = time.Now()
			n.blackHole.Store(true)
			n.target.stall.Store(true)
		case degraded:
			n.target.stall.Store(false)
		case recovered:
			n.blackHole.Store(false)
		}
		inc := n.watchStep(s)
		if i == onset {
			t.Logf("onset: published on attempt %d, fresh=%v, after %v of wall time", inc.attempts, inc.fresh, time.Since(injectedAt))
		}
		want := n.freshStep()
		if masked, differs := n.checkEquivalent(i, clock.Now(), inc, want); len(masked) != 0 || differs {
			t.Errorf("step %d: masked %v, diagnosis differs %v; a path-MTU fault must never be masked", i, masked, differs)
		}

		faulted := i >= onset && i < recovered
		wantPMTU := StatusPass
		if faulted {
			wantPMTU = StatusWarn
		}
		if got := inc.res[ProbePMTU].Status; got != wantPMTU {
			t.Errorf("step %d: path MTU = %s, want %s", i, got, wantPMTU)
		}
		if _, reused := inc.res[ProbePMTU].ReusedFrom(); reused {
			t.Errorf("step %d: path MTU was reused; it must measure on every pass", i)
		}
		if got := want.res[ProbePMTU].Status; got != wantPMTU {
			t.Errorf("step %d: fresh oracle path MTU = %s, want %s", i, got, wantPMTU)
		}

		d := n.diagnosisOf(inc)
		blamesPMTU := len(d.Findings) > 0 && d.Findings[0].ID == DiagnosisProbablePathMTU
		switch i {
		case onset, sustained:
			if !blamesPMTU {
				t.Errorf("step %d: diagnosis %+v, want %s", i, d.Findings, DiagnosisProbablePathMTU)
			}
			if !blamesPMTU || !citesObservation(d.Findings[0], ProbePMTU, ObservationStatusWarn) || !citesObservation(d.Findings[0], ProbeTLS, ObservationCause) {
				t.Errorf("step %d: %s evidence %+v, want the path MTU warning and the TLS cause", i, DiagnosisProbablePathMTU, d.Findings)
			}
		default:
			if blamesPMTU {
				t.Errorf("step %d: diagnosis blames a path MTU black hole, want none: the fault is not present", i)
			}
		}

		wantAttempts := map[int]int{onset: 2, sustained: 1, degraded: 1, recovered: 2}[i]
		if wantAttempts == 0 {
			wantAttempts = 1
		}
		if inc.attempts != wantAttempts {
			t.Errorf("step %d: published on attempt %d, want %d", i, inc.attempts, wantAttempts)
		}
		if i == recovered+1 && (inc.attempts != 1 || inc.traffic.clientHellos != 0) {
			t.Errorf("step %d: after recovery attempts=%d clientHellos=%d, want reuse to resume: 1 attempt and no handshake", i, inc.attempts, inc.traffic.clientHellos)
		}

		// The incident timeline is fed only fresh passes, and the oracle at every
		// step. Degraded is the Failing-to-Degraded transition: a working pass closes
		// the incident.
		wantT := n.observe(&oracleTL, clock.Now(), want)
		var gotT incident.Transition
		if inc.fresh {
			gotT = n.observe(&sessionTL, clock.Now(), inc)
			if gotT != wantT {
				t.Errorf("step %d: incident transition %q, fresh oracle %q", i, gotT, wantT)
			}
		}
		switch i {
		case onset:
			if wantT != incident.TransitionBegan {
				t.Errorf("step %d: oracle transition %q, want %q", i, wantT, incident.TransitionBegan)
			}
		case sustained:
			if wantT != incident.TransitionFailing && wantT != incident.TransitionChanged {
				t.Errorf("step %d: oracle transition %q, want a failing pass of the open incident", i, wantT)
			}
		case degraded:
			if wantT != incident.TransitionRecovered {
				t.Errorf("step %d: oracle transition %q, want %q: a degraded pass closes the incident", i, wantT, incident.TransitionRecovered)
			}
			if h := healthOf(n, want); h != incident.Degraded {
				t.Errorf("step %d: health %s, want %s: the handshake works and only the bulk write fails", i, h, incident.Degraded)
			}
		case recovered:
			if h := healthOf(n, want); h != incident.Healthy {
				t.Errorf("step %d: health %s, want %s", i, h, incident.Healthy)
			}
		}
		t.Logf("step %d: attempts=%d fresh=%v path_mtu=%s tls=%s/%s transition=%q oracle=%q",
			i, inc.attempts, inc.fresh, inc.res[ProbePMTU].Status, inc.res[ProbeTLS].Status, inc.res[ProbeTLS].Cause, gotT, wantT)
	}

	sessionIncidents, oracleIncidents := sessionTL.Incidents(), oracleTL.Incidents()
	if len(sessionIncidents) != 1 || len(oracleIncidents) != 1 {
		t.Fatalf("incidents: session %d, oracle %d, want one each", len(sessionIncidents), len(oracleIncidents))
	}
	if got, want := incidentFacts(sessionIncidents[0]), incidentFacts(oracleIncidents[0]); !reflect.DeepEqual(got, want) {
		t.Errorf("incident differs from the fresh oracle:\n session %q\n oracle  %q", got, want)
	}
	if passes := oracleIncidents[0].Passes; passes != sustained-onset+1 {
		t.Errorf("oracle incident counts %d failing passes, want %d: the degraded pass is recovery, not a failure", passes, sustained-onset+1)
	}
}

// citesObservation reports whether a finding cites observation of row.
func citesObservation(f DiagnosisFinding, row ProbeID, obs ObservationID) bool {
	for _, e := range f.Evidence {
		if e.Check == row && e.Observation == obs {
			return true
		}
	}
	return false
}

// healthOf is the health a pass gives the incident timeline, read off the
// snapshot the TUI and headless loops build from it.
func healthOf(n *realNet, p passRun) incident.Health {
	return incident.Classify(BuildSnapshotWithDiagnosis(n.tg, p.probes, p.res, n.diagnosisOf(p)))
}
