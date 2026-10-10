package diagnostic

import (
	"testing"
	"time"
)

// A resolver row is never reused, and a failing pass leaves the session unsettled,
// so every row runs fresh until a clean pass. The one case that reuses a row beside
// a changed resolver verdict is the first failing pass after a settled one: attempt
// 1 reuses encrypted DNS, Publish refuses it, and the fresh attempt 2 is published
// with no reused row in it.
//
// The two resolvers differ in what else changes. A failing system resolver also
// skips the target row, which depends on it, so the route key moves and Publish
// refuses on the path. A failing public resolver changes only its own verdict, so
// the verdict check is the only guard.
func TestWatchResolverFlipPublishesNoReusedRow(t *testing.T) {
	resolvers := []struct {
		name string
		id   ProbeID
		set  func(n *watchNet, broken bool)
	}{
		{"system", ProbeDNS, func(n *watchNet, b bool) { n.dnsBroken = b }},
		{"public", ProbeDNSPublic, func(n *watchNet, b bool) { n.publicBroken = b }},
	}
	steps := []struct {
		broken bool
		// attempts is the attempt that is published. reuse says whether encrypted
		// DNS is reused on the published pass.
		attempts int
		reuse    bool
	}{
		{true, 2, false},  // settled session sees the failure: attempt 1 refused, attempt 2 published
		{true, 1, false},  // unsettled while the resolver fails: every row runs fresh
		{true, 1, false},  // still unsettled
		{false, 1, false}, // recovery on an unsettled session: every row runs fresh, and the pass settles
		{false, 1, true},  // settled again: reuse resumes
	}
	for _, r := range resolvers {
		t.Run(r.name, func(t *testing.T) {
			clock := newWatchClock()
			n := newWatchNet()
			s := NewWatchSession(clock.Now)
			watchPass(t, s, n)

			for i, st := range steps {
				r.set(n, st.broken)
				clock.Advance(5 * time.Second)
				res, runs, attempts := watchPass(t, s, n)

				wantStatus := StatusPass
				if st.broken {
					wantStatus = StatusFail
				}
				if got := res[r.id].Status; got != wantStatus {
					t.Fatalf("step %d: %s resolver %v, want %v", i, r.id, got, wantStatus)
				}
				if runs[r.id] != 1 {
					t.Errorf("step %d: %s resolver ran %d times, want 1: it is never reused", i, r.id, runs[r.id])
				}
				if attempts != st.attempts {
					t.Errorf("step %d: published on attempt %d, want %d", i, attempts, st.attempts)
				}
				if st.attempts == 2 && reusedAny(res) {
					t.Errorf("step %d: resolver flip published a reused row beside the changed verdict", i)
				}
				if _, reused := res[ProbeDNSEncrypted].ReusedFrom(); reused != st.reuse {
					t.Errorf("step %d: encrypted DNS reused=%v, want %v", i, reused, st.reuse)
				}
				assertFreshDiagnosis(t, n, res)
			}
		})
	}
}

// Encrypted DNS fails with nothing else changed, so its reused PASS stands until
// watchMaxAge. Then the row runs, and the failure is published on the first pass
// that does not reuse it. The masked passes are the bound that reuse accepts.
func TestWatchEncryptedDNSFailureSurfacesAtMaxAge(t *testing.T) {
	const cadence = 5 * time.Second
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	n.encryptedBroken = true
	changedAt := clock.now
	masked := 0
	for {
		clock.Advance(cadence)
		res, runs, attempts := watchPass(t, s, n)
		if runs[ProbeDNS] != 1 {
			t.Fatalf("pass at +%v: system DNS ran %d times, want 1", clock.now.Sub(changedAt), runs[ProbeDNS])
		}
		if res[ProbeDNSEncrypted].Status == StatusPass {
			masked++
			if masked > int(watchMaxAge/cadence) {
				t.Fatalf("encrypted DNS still PASS %d passes after the change, past max age", masked)
			}
			if _, reused := res[ProbeDNSEncrypted].ReusedFrom(); !reused || runs[ProbeDNSEncrypted] != 0 {
				t.Errorf("masked pass %d did not reuse encrypted DNS (runs=%d)", masked, runs[ProbeDNSEncrypted])
			}
			if attempts != 1 {
				t.Errorf("masked pass %d took %d attempts, want 1", masked, attempts)
			}
			continue
		}
		if res[ProbeDNSEncrypted].Status != StatusFail {
			t.Fatalf("detecting pass: encrypted DNS %v, want fail", res[ProbeDNSEncrypted].Status)
		}
		if runs[ProbeDNSEncrypted] != 1 || attempts != 1 {
			t.Errorf("detecting pass: encrypted DNS runs=%d attempts=%d, want 1 run, 1 attempt", runs[ProbeDNSEncrypted], attempts)
		}
		latency := clock.now.Sub(changedAt)
		t.Logf("detection: masked=%d latency=%v (watchMaxAge=%v)", masked, latency, watchMaxAge)
		if latency != watchMaxAge {
			t.Errorf("detection latency %v, want exactly watchMaxAge %v: encrypted DNS is reused until max age", latency, watchMaxAge)
		}
		assertFreshDiagnosis(t, n, res)
		break
	}
	if masked == 0 {
		t.Fatal("encrypted DNS failure was seen at once; reuse did not happen")
	}
}
