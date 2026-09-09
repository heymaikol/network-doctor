package diagnostic

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The first dial cannot finish before the sibling wins. No external socket or
// scheduler timing supplies its outcome: cancellation is its only exit.
func TestTargetEvidenceVerifiesCanceledSibling(t *testing.T) {
	for _, pair := range [][2]string{{"192.0.2.1", "192.0.2.2"}, {"2001:db8::1", "2001:db8::2"}} {
		t.Run(pair[0], func(t *testing.T) {
			ips := []net.IP{net.ParseIP(pair[0]), net.ParseIP(pair[1])}
			o := &netops{interfaces: func() ([]net.Interface, error) { return nil, nil }}
			o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(addr)
				if host == pair[0] {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return fakeConn{local: &net.TCPAddr{IP: ips[1]}}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
			defer cancel()
			r := o.targetTCPProbe(80)(ctx, map[ProbeID]ProbeResult{ProbeDNS: {Addrs: ips}})
			res := map[ProbeID]ProbeResult{ProbeDNS: {Status: StatusPass, Addrs: ips}, ProbeTargetTCP: r}
			Finalize(res)
			d := Interpret(&Target{Host: "failover.test", Port: 80}, []ProbeID{ProbeDNS, ProbeTargetTCP}, res)
			t.Logf("resolved=%v selected=%v families=%+v attempts=%+v diagnosis=%+v", ips, r.SelectedIP, r.Families, r.Attempts, d)
			if !r.SelectedIP.Equal(ips[1]) {
				t.Fatalf("winner=%v", r.SelectedIP)
			}
			if len(r.Attempts) != 3 || r.Attempts[0].Cause != ConnectionCauseCanceled || !r.Attempts[0].Aborted || r.Attempts[2].Aborted || r.Attempts[2].Cause != ConnectionCauseTimeout {
				t.Fatalf("attempts=%+v", r.Attempts)
			}
			if _, found := findingByID(d, DiagnosisPartialReachability); !found {
				t.Fatal("independent address timeout missing")
			}
			_, artifact := sanitizedReplayInput(t, &Target{Raw: "failover.test:80", Host: "failover.test", Port: 80}, []ProbeID{ProbeDNS, ProbeTargetTCP}, res)
			replayed, err := ReplaySnapshot(artifact)
			if err != nil {
				t.Fatal(err)
			}
			if finding, ok := findingByID(replayed, DiagnosisPartialReachability); !ok || len(finding.Counterfactual.Alternatives) != 2 {
				t.Fatalf("support replay=%+v", replayed)
			}
			for _, check := range artifact.Checks {
				if check.ID == string(ProbeTargetTCP) {
					ats := check.Observed.Attempts
					if len(ats) != 3 || !ats[0].Aborted || ats[2].Aborted || ats[2].Cause != ConnectionCauseTimeout {
						t.Fatalf("support attempts=%+v", ats)
					}
				}
			}
		})
	}
}

func TestTargetSiblingVerificationEligibility(t *testing.T) {
	a, b, c := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("2001:db8::1")
	canceled := Attempt{IP: a, Err: context.Canceled, Cause: ConnectionCauseCanceled, Aborted: true}
	for _, tc := range []struct {
		name     string
		resolved []net.IP
		attempts []Attempt
		sources  *SourceAddresses
		budget   time.Duration
		want     bool
	}{
		{"canceled by winner", []net.IP{a, b}, []Attempt{canceled, {IP: b}}, nil, DefaultProbeTimeout, true},
		{"resolved never started", []net.IP{a, b}, []Attempt{{IP: b}}, nil, DefaultProbeTimeout, false},
		{"not resolved", []net.IP{b, c}, []Attempt{canceled, {IP: b}}, nil, DefaultProbeTimeout, false},
		{"cross family", []net.IP{b, c}, []Attempt{{IP: c, Err: context.Canceled, Cause: ConnectionCauseCanceled}, {IP: b}}, nil, DefaultProbeTimeout, false},
		{"probe already canceled", []net.IP{a, b}, []Attempt{canceled, {IP: b}}, nil, -1, false},
		{"no enclosing deadline", []net.IP{a, b}, []Attempt{canceled, {IP: b}}, nil, 0, false},
		{"insufficient remaining budget", []net.IP{a, b}, []Attempt{canceled, {IP: b}}, nil, targetSiblingTimeout / 2, false},
		{"max attempts reserved", append(make([]net.IP, maxAttempts-2), a, b), []Attempt{canceled, {IP: b}}, nil, DefaultProbeTimeout, false},
		{"interface lacks family", []net.IP{a, b}, []Attempt{canceled, {IP: b}}, &SourceAddresses{IPv6: c}, DefaultProbeTimeout, false},
		{"bound IPv4", []net.IP{a, b}, []Attempt{canceled, {IP: b}}, &SourceAddresses{IPv4: b}, DefaultProbeTimeout, true},
		{"duplicate canceled addresses", []net.IP{a, a, b}, []Attempt{canceled, canceled, {IP: b}}, nil, DefaultProbeTimeout, true},
		{"malformed canceled address", []net.IP{nil, b}, []Attempt{{Err: context.Canceled, Cause: ConnectionCauseCanceled}, {IP: b}}, nil, DefaultProbeTimeout, false},
		{"winner duplicate", []net.IP{b, b}, []Attempt{{IP: b, Err: context.Canceled, Cause: ConnectionCauseCanceled}, {IP: b}}, nil, DefaultProbeTimeout, false},
		{"explicit failure already sufficient", []net.IP{a, b, c}, []Attempt{canceled, {IP: a, Err: syscall.ECONNREFUSED, Cause: ConnectionCauseRefused}, {IP: b}}, nil, DefaultProbeTimeout, false},
		{"successful race loser", []net.IP{a, b}, []Attempt{{IP: a}, {IP: b}}, nil, DefaultProbeTimeout, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.budget != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.budget)
				defer cancel()
			}
			calls := 0
			o := &netops{sources: tc.sources, dialContext: func(vctx context.Context, network, addr string) (net.Conn, error) {
				calls++
				if network != "tcp4" || addr != "192.0.2.1:80" {
					t.Errorf("out of scope %s %s", network, addr)
				}
				vd, _ := vctx.Deadline()
				pd, _ := ctx.Deadline()
				if vd.After(pd) || time.Until(vd) > targetSiblingTimeout {
					t.Error("verification extended budget")
				}
				return nil, syscall.ECONNREFUSED
			}}
			got, ran := o.verifyTargetSibling(ctx, tc.resolved, b, tc.attempts, 80)
			if ran != tc.want || calls > 1 || (ran && (got.Aborted || got.Cause != ConnectionCauseRefused)) {
				t.Fatalf("calls=%d ran=%t attempt=%+v", calls, ran, got)
			}
		})
	}
}

func TestTargetEvidenceOrdinaryOutcomes(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, outcome := range []string{"healthy first", "refused first", "timed out first", "whole family fails", "probe expires", "healthy verification", "cancel verification"} {
			t.Run(family+"/"+outcome, func(t *testing.T) {
				a, b := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
				if family == "ipv6" {
					a, b = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
				}
				ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
				defer cancel()
				var firstCalls, allCalls atomic.Int32
				o := &netops{interfaces: func() ([]net.Interface, error) { return nil, nil }}
				o.dialContext = func(dctx context.Context, network, addr string) (net.Conn, error) {
					if network == "udp" {
						return nil, errors.New("no source")
					}
					allCalls.Add(1)
					host, _, _ := net.SplitHostPort(addr)
					if outcome == "whole family fails" {
						return nil, syscall.EHOSTUNREACH
					}
					if outcome == "probe expires" {
						cancel()
						<-dctx.Done()
						return nil, dctx.Err()
					}
					if host == a.String() {
						n := firstCalls.Add(1)
						switch outcome {
						case "refused first":
							return nil, syscall.ECONNREFUSED
						case "timed out first":
							return nil, context.DeadlineExceeded
						case "healthy verification", "cancel verification":
							if n == 1 {
								<-dctx.Done()
								return nil, dctx.Err()
							}
							if outcome == "cancel verification" {
								cancel()
								<-dctx.Done()
								return nil, dctx.Err()
							}
						}
					}
					return fakeConn{local: &net.TCPAddr{IP: b}}, nil
				}
				r := o.targetTCPProbe(80)(ctx, map[ProbeID]ProbeResult{ProbeDNS: {Addrs: []net.IP{a, b}}})
				res := map[ProbeID]ProbeResult{ProbeDNS: {Status: StatusPass, Addrs: []net.IP{a, b}}, ProbeTargetTCP: cleanResult(r)}
				Finalize(res)
				_, found := addressCounterfactual(&Target{Host: "example.test", Port: 80}, res)
				want := outcome == "refused first" || outcome == "timed out first"
				if found != want {
					t.Fatalf("partial=%t want=%t result=%+v", found, want, r)
				}
				if outcome == "healthy first" && (allCalls.Load() != 1 || r.Status != StatusPass) {
					t.Fatalf("healthy target sampled: %+v calls=%d", r, allCalls.Load())
				}
				if outcome == "cancel verification" && (len(r.Attempts) != 3 || !r.Attempts[2].Aborted || r.Status != StatusPass) {
					t.Fatalf("canceled verification=%+v", r)
				}
				if outcome == "healthy verification" && (len(r.Attempts) != 3 || r.Attempts[2].Err != nil || r.Status != StatusPass) {
					t.Fatalf("healthy verification=%+v", r)
				}
				if outcome == "probe expires" && slices.ContainsFunc(r.Attempts, func(a Attempt) bool { return !isCanceledAttempt(a) }) {
					t.Fatalf("parent expiration supplied evidence: %+v", r.Attempts)
				}
			})
		}
	}
}

func TestAddressEvidenceRequiresSameFamilySuccess(t *testing.T) {
	a, b, c := net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	for _, sameFamilySuccess := range []bool{false, true} {
		r := ProbeResult{SelectedIP: a, Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyReachable}, Attempts: []Attempt{{IP: a}, {IP: b, Err: syscall.EHOSTUNREACH, Cause: ConnectionCauseUnreachable}}}
		if sameFamilySuccess {
			r.Attempts = append(r.Attempts, Attempt{IP: c})
		}
		f, found := addressCounterfactual(&Target{Host: "example.test"}, map[ProbeID]ProbeResult{ProbeDNS: {Addrs: []net.IP{a, b, c}}, ProbeTargetTCP: r})
		if found != sameFamilySuccess {
			t.Fatalf("found=%t success=%t", found, sameFamilySuccess)
		}
		if found && f.Counterfactual.Alternatives[1].Value != c.String() {
			t.Fatalf("cross-family comparison: %+v", f.Counterfactual)
		}
	}
}

func TestTargetAttemptLimitLeavesResolvedAddressesUnknown(t *testing.T) {
	var ips []net.IP
	for i := 0; i < maxAttempts+2; i++ {
		ips = append(ips, net.IPv4(192, 0, 2, byte(i+1)))
	}
	var calls atomic.Int32
	o := &netops{interfaces: func() ([]net.Interface, error) { return nil, nil }, dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
		if network != "udp" {
			calls.Add(1)
		}
		return nil, syscall.ECONNREFUSED
	}}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
	defer cancel()
	r := o.targetTCPProbe(80)(ctx, map[ProbeID]ProbeResult{ProbeDNS: {Addrs: ips}})
	if calls.Load() != maxAttempts || len(r.Attempts) != maxAttempts {
		t.Fatalf("calls=%d attempts=%d", calls.Load(), len(r.Attempts))
	}
	if r.Families.IPv4 != "" {
		t.Fatalf("unattempted siblings became whole-family failure: %+v", r.Families)
	}
	for _, ip := range ips[maxAttempts:] {
		if slices.ContainsFunc(r.Attempts, func(a Attempt) bool { return a.IP.Equal(ip) }) {
			t.Fatal("unstarted address recorded")
		}
	}
	if _, found := addressCounterfactual(&Target{Host: "example.test"}, map[ProbeID]ProbeResult{ProbeDNS: {Addrs: ips}, ProbeTargetTCP: r}); found {
		t.Fatal("whole-family failure became partial")
	}
}

func TestTargetProbeDeadlineIsNotAddressFailure(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	o := &netops{interfaces: func() ([]net.Interface, error) { return nil, nil }, dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "udp" {
			<-ctx.Done()
		}
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	r := o.targetTCPProbe(80)(ctx, map[ProbeID]ProbeResult{ProbeDNS: {Addrs: []net.IP{ip}}})
	if len(r.Attempts) != 1 || !r.Attempts[0].Aborted || r.Attempts[0].Cause != ConnectionCauseTimeout {
		t.Fatalf("deadline evidence=%+v", r.Attempts)
	}
}

func TestTargetSuccessfulRaceLoserIsClosedWithoutFailure(t *testing.T) {
	a, b := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	loser := &closeTrackingConn{closed: make(chan struct{})}
	winner := &closeTrackingConn{closed: make(chan struct{})}
	var calls atomic.Int32
	o := &netops{interfaces: func() ([]net.Interface, error) { return nil, nil }, dialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		calls.Add(1)
		host, _, _ := net.SplitHostPort(addr)
		if host == a.String() {
			<-ctx.Done()
			return loser, nil
		}
		return winner, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
	defer cancel()
	r := o.targetTCPProbe(80)(ctx, map[ProbeID]ProbeResult{ProbeDNS: {Addrs: []net.IP{a, b}}})
	if calls.Load() != 2 || r.Status != StatusPass || len(r.Attempts) != 1 || r.Attempts[0].Err != nil {
		t.Fatalf("result=%+v calls=%d", r, calls.Load())
	}
	for _, conn := range []*closeTrackingConn{loser, winner} {
		select {
		case <-conn.closed:
		default:
			t.Fatal("connection leaked")
		}
	}
}
