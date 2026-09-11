package diagnostic

import (
	"net"
	"slices"
	"strings"
	"testing"
)

// The overclaim tests. Each one is about a sentence, an identity, or a verdict
// the run's own observations do not support, and each names the reachable
// probe state that produced it. They are kept together because they share one
// standard: a conclusion has to be true of everything the run looked at, not
// only of the rung the branch that reached it was reading.

// planOrder is the production probe order for a run, with no host operations
// and no probe bodies. Using the real graph is what keeps the states below
// reachable: a fixture that invents a row order, or a dependency, proves
// nothing about what netdoc can actually be asked to interpret.
func planOrder(t *testing.T, target *Target, skip ...ProbeID) []ProbeID {
	t.Helper()
	var order []ProbeID
	for _, p := range ProbePlan(target, DefaultPublicDNS, true) {
		if slices.Contains(skip, p.ID) {
			continue
		}
		order = append(order, p.ID)
	}
	return order
}

// settle fills every row the plan names, defaulting to Pass, then propagates
// the skip a failed or skipped prerequisite forces. That is the scheduler's own
// rule (DepsState), so a state built this way is one a run can reach.
func settle(t *testing.T, target *Target, order []ProbeID, given map[ProbeID]ProbeResult) map[ProbeID]ProbeResult {
	t.Helper()
	res := make(map[ProbeID]ProbeResult, len(order))
	for _, p := range ProbePlan(target, DefaultPublicDNS, true) {
		if !slices.Contains(order, p.ID) {
			continue
		}
		if r, ok := given[p.ID]; ok {
			r.ID = p.ID
			res[p.ID] = r
			continue
		}
		blocked := false
		for _, dep := range p.Deps {
			if r, ok := res[dep]; ok && (r.Status == StatusFail || r.Status == StatusSkip) {
				blocked = true
			}
		}
		if blocked {
			res[p.ID] = SkipPrereq(p.ID)
			continue
		}
		res[p.ID] = ProbeResult{ID: p.ID, Status: StatusPass}
	}
	Finalize(res)
	return res
}

func failedRows(order []ProbeID, res map[ProbeID]ProbeResult) []ProbeID {
	var out []ProbeID
	for _, id := range order {
		if r, ok := res[id]; ok && r.Status == StatusFail {
			out = append(out, id)
		}
	}
	return out
}

// A sentence about every check passing has to be true of every check. The two
// states below reach it with a row that failed, and neither needs an unusual
// probe result: an address for a target, and a supported --skip.
func TestNoRunCallsItselfHealthyWithAFailedRow(t *testing.T) {
	literal, err := ParseTarget("93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	named := mustTarget(t, "github.com")
	ip := net.ParseIP("93.184.216.34")
	pub := net.ParseIP("140.82.121.4")

	cases := []struct {
		name   string
		target *Target
		order  []ProbeID
		given  map[ProbeID]ProbeResult
	}{{
		// An address target takes both plaintext resolver rows out of the run
		// as not applicable, which is the state encryptedDNSBlocked reads as
		// "no plaintext resolution to compare against". The encrypted row
		// still ran, and still failed.
		name:   "encrypted DNS blocked behind an address target",
		target: literal, order: planOrder(t, literal),
		given: map[ProbeID]ProbeResult{
			ProbeDNS:          {Status: StatusNA, Addrs: []net.IP{ip}, SelectedIP: ip},
			ProbeDNSPublic:    {Status: StatusNA},
			ProbeDNSEncrypted: {Status: StatusFail, Detail: "no verified DoH/DoT exchange"},
			ProbeTargetTCP:    {Status: StatusPass, SelectedIP: ip},
		},
	}, {
		// Without the egress row there is no directOK() for the QUIC and
		// proxy cases to test, so neither is about this failure any more.
		name:   "QUIC blocked with the egress row skipped",
		target: named, order: planOrder(t, named, ProbeInternet),
		given: map[ProbeID]ProbeResult{
			ProbeQUIC:      {Status: StatusFail, Cause: QUICCauseTimeout},
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{pub}},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{pub}},
			ProbeTargetTCP: {Status: StatusPass, SelectedIP: pub},
		},
	}, {
		name:   "environment proxy failed with the egress row skipped",
		target: named, order: planOrder(t, named, ProbeInternet),
		given: map[ProbeID]ProbeResult{
			ProbeProxy:     {Status: StatusFail, Detail: "proxy CONNECT refused"},
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{pub}},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{pub}},
			ProbeTargetTCP: {Status: StatusPass, SelectedIP: pub},
		},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := settle(t, c.target, c.order, c.given)
			failed := failedRows(c.order, res)
			if len(failed) == 0 {
				t.Fatal("the state under test has no failed row, so it tests nothing")
			}
			d := Interpret(c.target, c.order, res)
			if d.Verdict == VerdictOK {
				t.Errorf("verdict = %q with %v failed: %q", d.Verdict, failed, d.Summary)
			}
			for _, phrase := range []string{"All checks passed", "looks healthy"} {
				if strings.Contains(d.Summary, phrase) {
					t.Errorf("summary %q says %q with %v failed", d.Summary, phrase, failed)
				}
			}
			// The row a caller is pointed at has to be one the sentence is
			// about. Blaming a row the summary has just called healthy is the
			// shape this defect took.
			if d.Blamed != "" && d.Focus() == "" {
				t.Errorf("blamed %q while the diagnosis names no row: %q", d.Blamed, d.Summary)
			}
		})
	}
}

// A resolver that failed with nothing to explain it outranks the rungs that
// run beside it. Those sentences all describe a network that resolves names,
// so reaching one on a run that cannot resolve reports the half that still
// works and drops the half that does not.
func TestDegradedSiblingsDoNotOutrankAnUnexplainedResolverFailure(t *testing.T) {
	order := planOrder(t, nil)
	// The system resolver fails and the second opinion could not be reached,
	// so no row narrows the failure: a network that blocks outbound 53 to
	// anything but its own broken resolver is exactly this state.
	base := map[ProbeID]ProbeResult{
		ProbeDNS:       {Status: StatusFail, Cause: DNSCauseTimeout},
		ProbeDNSPublic: {Status: StatusNA, Detail: "public DNS unavailable"},
	}
	alone := Interpret(nil, order, settle(t, nil, order, base))
	if alone.Verdict != VerdictDNS {
		t.Fatalf("the resolver failure alone gives %q, want %q", alone.Verdict, VerdictDNS)
	}

	for _, sibling := range []struct {
		name string
		id   ProbeID
		res  ProbeResult
	}{
		{"UDP/443 blocked", ProbeQUIC, ProbeResult{Status: StatusFail, Cause: QUICCauseTimeout}},
		{"DoH/DoT blocked", ProbeDNSEncrypted, ProbeResult{Status: StatusFail}},
	} {
		t.Run(sibling.name, func(t *testing.T) {
			with := map[ProbeID]ProbeResult{sibling.id: sibling.res}
			for id, r := range base {
				with[id] = r
			}
			// The second opinion answering with a negative is the other way
			// into the same hole: it is functional, so it reads as plaintext
			// resolution working, while it resolved nothing.
			if sibling.id == ProbeDNSEncrypted {
				with[ProbeDNSPublic] = ProbeResult{Status: StatusPass, DNSNotFound: true}
			}
			d := Interpret(nil, order, settle(t, nil, order, with))
			if d.Verdict != VerdictDNS {
				t.Errorf("verdict = %q, want %q: %q", d.Verdict, VerdictDNS, d.Summary)
			}
			if got := d.Focus(); got != ProbeDNS {
				t.Errorf("focus = %q, want the resolver row: %q", got, d.Summary)
			}
		})
	}
}

// A run that says nothing failed has to be a run where nothing failed. This is
// the general form of the defect the first test above reproduces, and it holds
// over the whole reachable state space rather than over the two states that
// happened to expose it.
func TestAVerdictOfOKNeverCoversAFailedRow(t *testing.T) {
	forEachReachableState(t, func(t *testing.T, target *Target, order []ProbeID, res map[ProbeID]ProbeResult) {
		d := Interpret(target, order, res)
		failed := failedRows(order, res)
		if d.Verdict == VerdictOK && len(failed) > 0 {
			t.Errorf("verdict %q with %v failed: %q", d.Verdict, failed, d.Summary)
		}
	})
}

// Adding a failure never softens the answer. A run cannot learn that a check
// it had not yet seen fail is broken and conclude that less is wrong, and a
// sentence that gets less severe as evidence gets worse is a branch reading
// one rung while another one speaks for the run.
func TestAddingAFailureNeverSoftensTheVerdict(t *testing.T) {
	severity := map[string]int{VerdictOK: 0, VerdictDegraded: 1}
	rank := func(verdict string) int {
		if s, ok := severity[verdict]; ok {
			return s
		}
		return 2
	}
	forEachReachableState(t, func(t *testing.T, target *Target, order []ProbeID, res map[ProbeID]ProbeResult) {
		before := Interpret(target, order, res)
		for _, id := range order {
			r, ok := res[id]
			// Only a row that ran and did not fail can newly fail, and only
			// one whose prerequisites held: a row behind a failure is skipped
			// rather than failed, which is a different state entirely. The
			// two rows excluded here are the ones whose probes never report a
			// failure at all, so turning one to Fail would be inventing an
			// observation rather than varying one.
			switch {
			case !ok, r.Status == StatusFail, r.Status == StatusSkip,
				id == ProbeDNSPublic, id == ProbePMTU, !depsHeld(target, id, res):
				continue
			}
			worse := make(map[ProbeID]ProbeResult, len(res))
			for k, v := range res {
				worse[k] = v
			}
			worse[id] = ProbeResult{ID: id, Status: StatusFail}
			after := Interpret(target, order, settleFrom(t, target, order, worse))
			if rank(after.Verdict) < rank(before.Verdict) {
				t.Errorf("%s failing moved the verdict %q -> %q\n  before: %q\n  after:  %q",
					id, before.Verdict, after.Verdict, before.Summary, after.Summary)
			}
		}
	})
}

// depsHeld reports whether every prerequisite of a row is functional, which is
// the scheduler's condition for running it at all. A row behind a failure is
// skipped, so a fixture that fails it is not describing a run.
func depsHeld(target *Target, id ProbeID, res map[ProbeID]ProbeResult) bool {
	for _, p := range ProbePlan(target, DefaultPublicDNS, true) {
		if p.ID != id {
			continue
		}
		for _, dep := range p.Deps {
			if r, ok := res[dep]; ok && !functional(r.Status) {
				return false
			}
		}
	}
	return true
}

// settleFrom re-propagates skips over a state that was already settled once,
// so a row turned to Fail takes its dependents with it.
func settleFrom(t *testing.T, target *Target, order []ProbeID, given map[ProbeID]ProbeResult) map[ProbeID]ProbeResult {
	t.Helper()
	res := make(map[ProbeID]ProbeResult, len(given))
	for _, p := range ProbePlan(target, DefaultPublicDNS, true) {
		r, ok := given[p.ID]
		if !ok {
			continue
		}
		for _, dep := range p.Deps {
			if d, ran := res[dep]; ran && (d.Status == StatusFail || d.Status == StatusSkip) {
				r = SkipPrereq(p.ID)
				break
			}
		}
		res[p.ID] = r
	}
	Finalize(res)
	return res
}

// forEachReachableState walks a bounded space of probe states built from the
// production graph, in both generic and targeted mode. Every state is settled
// through the scheduler's own skip rule and Finalize, so nothing here is a
// combination a run could not produce. Only statuses a probe actually reports
// are used: the second-opinion resolver never fails, and the path-MTU row
// never does either.
func forEachReachableState(t *testing.T, check func(*testing.T, *Target, []ProbeID, map[ProbeID]ProbeResult)) {
	t.Helper()
	pub := net.ParseIP("140.82.121.4")
	answers := ProbeResult{Status: StatusPass, Addrs: []net.IP{pub}}
	target := mustTarget(t, "github.com")

	states := map[ProbeID][]ProbeResult{
		ProbeInternet: {{Status: StatusPass}, {Status: StatusWarn, Detail: "one family down"},
			{Status: StatusFail, Cause: RouteCauseNoDefaultRoute}, {Status: StatusFail, Cause: RouteCauseSelectedPathFailed}},
		ProbeProxy: {{Status: StatusNA}, {Status: StatusPass}, {Status: StatusFail}},
		ProbeQUIC:  {{Status: StatusPass}, {Status: StatusNA}, {Status: StatusFail, Cause: QUICCauseTimeout}},
		ProbeDNS: {answers, {Status: StatusFail, Cause: DNSCauseTimeout},
			{Status: StatusFail, DNSNotFound: true}},
		ProbeDNSPublic:    {answers, {Status: StatusNA}, {Status: StatusPass, DNSNotFound: true}},
		ProbeDNSEncrypted: {{Status: StatusPass}, {Status: StatusFail}, {Status: StatusNA}},
		ProbeTargetTCP: {{Status: StatusPass, SelectedIP: pub}, {Status: StatusWarn, SelectedIP: pub},
			{Status: StatusFail, Cause: ConnectionCauseTimeout}, {Status: StatusFail, Cause: ConnectionCauseRefused}},
		ProbeTLS:  {{Status: StatusPass}, {Status: StatusFail, Cause: TLSCauseTimeout}, {Status: StatusFail, Cause: TLSCauseCertificateExpired}},
		ProbePMTU: {{Status: StatusPass}, {Status: StatusWarn}, {Status: StatusNA}},
	}

	for _, run := range []struct {
		name   string
		target *Target
		vary   []ProbeID
	}{
		{"generic", nil, []ProbeID{ProbeInternet, ProbeProxy, ProbeQUIC, ProbeDNS, ProbeDNSPublic, ProbeDNSEncrypted}},
		{"targeted", target, []ProbeID{ProbeInternet, ProbeProxy, ProbeDNS, ProbeDNSPublic, ProbeTargetTCP, ProbeTLS, ProbePMTU}},
		{"targeted without the egress row", target, []ProbeID{ProbeQUIC, ProbeProxy, ProbeDNS, ProbeTargetTCP, ProbeDNSEncrypted}},
	} {
		order := planOrder(t, run.target)
		if run.name == "targeted without the egress row" {
			order = planOrder(t, run.target, ProbeInternet)
		}
		total := 1
		for _, id := range run.vary {
			total *= len(states[id])
		}
		for code := 0; code < total; code++ {
			given := map[ProbeID]ProbeResult{}
			c := code
			for _, id := range run.vary {
				given[id] = states[id][c%len(states[id])]
				c /= len(states[id])
			}
			res := settle(t, run.target, order, given)
			t.Run(run.name+"/"+stateName(order, res), func(t *testing.T) {
				check(t, run.target, order, res)
			})
		}
	}
}

// stateName labels a case by the rows that are not passing, which is what a
// failure message needs to reproduce it.
func stateName(order []ProbeID, res map[ProbeID]ProbeResult) string {
	var parts []string
	for _, id := range order {
		if r, ok := res[id]; ok && r.Status != StatusPass {
			parts = append(parts, string(id)+"="+r.Status.String())
		}
	}
	if len(parts) == 0 {
		return "all pass"
	}
	return strings.Join(parts, ",")
}
