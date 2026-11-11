package diagnostic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// The ways a QUIC attempt ends, as the dialer records them.
func quicSilent(ip string) Attempt {
	return Attempt{IP: net.ParseIP(ip), Err: context.DeadlineExceeded, Cause: ConnectionCauseTimeout, Aborted: true}
}
func quicNoRoute(ip string) Attempt {
	return Attempt{IP: net.ParseIP(ip), Err: errors.New("connect: network is unreachable"), Cause: ConnectionCauseUnreachable}
}
func quicRefused(ip string) Attempt {
	return Attempt{IP: net.ParseIP(ip), Err: errors.New("read: connection refused"), Cause: ConnectionCauseRefused}
}
func quicCanceled(ip string) Attempt {
	return Attempt{IP: net.ParseIP(ip), Err: context.Canceled, Cause: ConnectionCauseCanceled, Aborted: true}
}

// "TCP works and QUIC does not" is a comparison, and the TCP half is the
// egress row. These runs fail the QUIC row beside working egress, and what
// changes between them is whether that egress was measured in a family QUIC
// was tried in.
func TestQUICIsNotCalledUnavailableWithoutAReferenceInItsFamily(t *testing.T) {
	const (
		q4, q4b, q6 = "192.0.2.10", "192.0.2.11", "2001:db8::10"
		t4, t6      = "203.0.113.20", "2001:db8:1::20"
	)
	v4Dead := ProbeResult{Status: StatusWarn, Cause: FamilyCauseIPv4Unreachable, causeFamily: counterfactualIPv4, Families: &FamilyConnectivity{IPv4: FamilyUnreachable, IPv6: FamilyReachable}}
	v6Absent := egress(FamilyReachable, FamilyUnreachable)
	bothUp := egress(FamilyReachable, FamilyReachable)
	v4Untested := egress("", FamilyReachable)

	tls443 := &Target{Raw: "app.example:443", Host: "app.example", Port: 443, Proto: ProtoTLSHTTP}
	cases := []struct {
		name     string
		target   *Target
		reached  string // the address the target row connected to, with a target
		internet ProbeResult
		attempts []Attempt
		want     DiagnosisID
		family   string // the family the summary must name, when it must
	}{
		{"generic, QUIC silent over IPv4 only, IPv4 egress black-holed", nil, "", v4Dead, []Attempt{quicSilent(q4), quicSilent(q4b)}, DiagnosisFamilyReachabilityUnlocalized, "IPv4"},
		{"generic, QUIC with no route over IPv6 only, network without IPv6", nil, "", v6Absent, []Attempt{quicNoRoute(q6)}, DiagnosisFamilyReachabilityUnlocalized, "IPv6"},
		{"generic, a canceled IPv6 attempt is not a second family tried", nil, "", v4Dead, []Attempt{quicSilent(q4), quicCanceled(q6)}, DiagnosisFamilyReachabilityUnlocalized, "IPv4"},
		{"targeted, target answered over IPv6, QUIC silent over IPv4 only", tls443, t6, v4Dead, []Attempt{quicSilent(q4)}, DiagnosisFamilyReachabilityUnlocalized, "IPv4"},
		// The egress row and the target row disagree about IPv4 here. The
		// target is another host, reached perhaps by a route of its own, and
		// is no reference for the endpoint the QUIC row dials.
		{"targeted, target answered over IPv4 while the IPv4 reference endpoints were silent", tls443, t4, v4Dead, []Attempt{quicSilent(q4)}, DiagnosisFamilyReachabilityUnlocalized, "IPv4"},
		{"targeted, target answered over IPv4, QUIC had no route over IPv4", tls443, t4, v4Dead, []Attempt{quicNoRoute(q4)}, DiagnosisFamilyReachabilityUnlocalized, "IPv4"},

		// The comparison was made in each of these, so the conclusion stays.
		// The first is the ordinary one: an IPv4-only network that blocks
		// UDP/443, where the IPv6 attempt has no route and the IPv4 one is
		// silent.
		{"generic, both families tried on an IPv4-only network", nil, "", v6Absent, []Attempt{quicNoRoute(q6), quicSilent(q4)}, DiagnosisQUICUnavailable, ""},
		{"generic, both families tried, IPv4 egress black-holed", nil, "", v4Dead, []Attempt{quicSilent(q6), quicSilent(q4)}, DiagnosisQUICUnavailable, ""},
		{"generic, QUIC silent over IPv4, egress up in both families", nil, "", bothUp, []Attempt{quicSilent(q4)}, DiagnosisQUICUnavailable, ""},
		{"generic, QUIC silent over IPv4, IPv6 egress absent", nil, "", v6Absent, []Attempt{quicSilent(q4)}, DiagnosisQUICUnavailable, ""},
		// A refusal is the endpoint answering in that family.
		{"generic, one IPv4 address refused and one silent, IPv4 egress black-holed", nil, "", v4Dead, []Attempt{quicRefused(q4), quicSilent(q4b)}, DiagnosisQUICUnavailable, ""},
		{"targeted, target answered over IPv4, QUIC silent over IPv4, egress up in both families", tls443, t4, bothUp, []Attempt{quicSilent(q4)}, DiagnosisQUICUnavailable, ""},
		// Nothing recorded about the family, in either row, changes nothing.
		{"generic, no attempts recorded", nil, "", v4Dead, nil, DiagnosisQUICUnavailable, ""},
		{"generic, the egress row never tested IPv4", nil, "", v4Untested, []Attempt{quicSilent(q4)}, DiagnosisQUICUnavailable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			order := planOrder(t, tc.target)
			given := map[ProbeID]ProbeResult{
				ProbeInternet: tc.internet,
				ProbeQUIC:     {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: tc.attempts},
			}
			if tc.target != nil {
				given[ProbeDNS] = ProbeResult{Status: StatusPass, Addrs: []net.IP{net.ParseIP(tc.reached)}}
				given[ProbeTargetTCP] = ProbeResult{Status: StatusPass, SelectedIP: net.ParseIP(tc.reached)}
			}
			res := settle(t, tc.target, order, given)
			d := Interpret(tc.target, order, res)
			if got := findingIDs(d); len(got) == 0 || got[0] != tc.want {
				t.Fatalf("findings = %v, want %q first (summary: %s)", got, tc.want, d.Summary)
			}
			// Whatever is said about a failed QUIC row, it is never nothing.
			if d.Verdict != VerdictDegraded || d.Blamed != ProbeQUIC || d.Findings[0].Focus != ProbeQUIC {
				t.Errorf("verdict = %s, blamed = %s, focus = %s; want a degraded run blaming the QUIC row", d.Verdict, d.Blamed, d.Findings[0].Focus)
			}
			if tc.want == DiagnosisFamilyReachabilityUnlocalized {
				f := d.Findings[0]
				if f.Confidence != ConfidenceInsufficientEvidence || !strings.Contains(d.Summary, "only over "+tc.family) {
					t.Errorf("confidence = %s, summary = %s", f.Confidence, d.Summary)
				}
				for _, e := range f.Evidence {
					if e.Check == ProbeInternet && e.Observation != ObservationFamilyFailed && e.Observation != ObservationFamilyReachable {
						t.Errorf("the egress row is cited as a whole: %+v", e)
					}
				}
				if e := d.Explain(tc.target, order, res); !strings.Contains(e.Headline, "faster connection method") || strings.Contains(e.Meaning, "did not answer") {
					t.Errorf("plain-language text is not the QUIC one: %q / %q", e.Headline, e.Meaning)
				}
				if r, ok := Remediate(d, res, "linux"); !ok || strings.Contains(r.Why+r.Action, "target") {
					t.Errorf("remediation = %+v, ok = %v; want advice that does not speak of a target", r, ok)
				}
			}
			// The same evidence read back from an artifact reaches the same answer.
			var probes []Probe
			for _, p := range ProbePlan(tc.target, DefaultPublicDNS, true) {
				if slices.Contains(order, p.ID) {
					probes = append(probes, p)
				}
			}
			replayed, err := ReplaySnapshot(BuildSnapshot(tc.target, probes, res))
			if err != nil {
				t.Fatal(err)
			}
			if got := findingIDs(replayed); replayed.Verdict != d.Verdict || replayed.Blamed != d.Blamed || len(got) == 0 || got[0] != tc.want {
				t.Errorf("replay = %s %s %v, live = %s %s %v", replayed.Verdict, replayed.Blamed, got, d.Verdict, d.Blamed, findingIDs(d))
			}
		})
	}
}

// The production probes, runner and Finalize over the in-memory network. The
// hand-built rows above record attempts however they like; these are the
// records a real run leaves.
func TestQUICFamilyReadingThroughTheRealProbes(t *testing.T) {
	const v4, v6 = "203.0.113.10", "2001:db8::10"
	for _, tc := range []struct {
		name        string
		quicAnswers []string
		dead        string // dials in this network family block until the probe gives up
		noRoute     string // dials in this network family fail at once
		want        DiagnosisID
	}{
		// IPv4 is black-holed and the QUIC endpoint was answered in IPv4 only.
		{"QUIC tried only over a black-holed family", []string{v4}, "4", "", DiagnosisFamilyReachabilityUnlocalized},
		// An IPv4-only network that blocks UDP/443. QUIC is tried in both
		// families: IPv6 has no route and fails at once, IPv4 is silent.
		{"both families tried on an IPv4-only network that blocks UDP/443", []string{v6, v4}, "udp4", "6", DiagnosisQUICUnavailable},
		// A dual-stack network that blocks UDP/443 and nothing else: TCP works
		// in both families and QUIC is silent in both.
		{"both families silent on a dual-stack network that blocks UDP/443", []string{v6, v4}, "udp", "", DiagnosisQUICUnavailable},
		// The same block with the endpoint answered in one family, which has
		// a working reference.
		{"one family silent on a dual-stack network that blocks UDP/443", []string{v4}, "udp", "", DiagnosisQUICUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newBudgetFixture(t)
			o := f.ops()
			o.lookupIP = func(_ context.Context, host string) ([]net.IP, []string, error) {
				answers := []string{v4}
				if host == ConnectivityProbeHost {
					answers = tc.quicAnswers
				}
				var ips []net.IP
				for _, a := range answers {
					ips = append(ips, net.ParseIP(a))
				}
				return ips, []string{"192.0.2.53:53"}, nil
			}
			o.lookupPublicIP = func(ctx context.Context, host, _ string) ([]net.IP, []string, error) {
				ips, _, err := o.lookupIP(ctx, host)
				return ips, []string{"8.8.8.8:53"}, err
			}
			dial := o.dialContext
			o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				switch {
				case tc.noRoute != "" && strings.HasSuffix(network, tc.noRoute):
					return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connect: network is unreachable")}
				case strings.HasSuffix(network, tc.dead) && strings.HasPrefix(network, "tcp"):
					<-ctx.Done()
					return nil, &net.OpError{Op: "dial", Net: network, Err: context.DeadlineExceeded}
				}
				return dial(ctx, network, addr)
			}
			// UDP/443 in the dead family is silence: the handshake never returns
			// by itself.
			handshake := o.quicHandshake
			o.quicHandshake = func(ctx context.Context, conn net.Conn, cfg *tls.Config) (quicState, error) {
				<-ctx.Done()
				_ = handshake
				return quicState{}, ctx.Err()
			}
			probes := o.buildProbes(nil, DefaultPublicDNS, true)
			res := RunAll(context.Background(), probes, time.Second)
			order := make([]ProbeID, len(probes))
			for i, p := range probes {
				order[i] = p.ID
			}
			d := Interpret(nil, order, res)
			if got := findingIDs(d); len(got) == 0 || got[0] != tc.want || d.Blamed != ProbeQUIC || d.Verdict != VerdictDegraded {
				t.Fatalf("verdict = %s, blamed = %s, findings = %v, want %q on the QUIC row\negress: %+v %s\nQUIC attempts: %+v\nsummary: %s",
					d.Verdict, d.Blamed, got, tc.want, res[ProbeInternet].Families, res[ProbeInternet].Detail, res[ProbeQUIC].Attempts, d.Summary)
			}
			if len(res[ProbeQUIC].Attempts) != len(tc.quicAnswers) {
				t.Errorf("QUIC attempts = %+v, want one per address tried", res[ProbeQUIC].Attempts)
			}
		})
	}
}

// The dialer used to record nothing for a silent QUIC endpoint, so these runs
// are the first that carry such attempts into the two arms that read QUIC
// attempts against the DNS rows. Both arms need the resolvers' answers to be
// comparable, and for the generic test name they never are: the public row
// asks for the rooted name while the system lookup may apply search suffixes.
// A real generic run therefore reaches neither arm, with or without recorded
// attempts, and the QUIC conclusion is what it was.
func TestRecordedSilentQUICAttemptsDoNotMoveAGenericRun(t *testing.T) {
	f := newBudgetFixture(t)
	o := f.ops()
	// The resolvers return addresses in different allocations.
	o.lookupIP = func(context.Context, string) ([]net.IP, []string, error) {
		return []net.IP{net.ParseIP("192.0.2.123")}, []string{"192.0.2.53:53"}, nil
	}
	o.lookupPublicIP = func(context.Context, string, string) ([]net.IP, []string, error) {
		return []net.IP{net.ParseIP("142.250.9.94")}, []string{"8.8.8.8:53"}, nil
	}
	o.quicHandshake = func(ctx context.Context, _ net.Conn, _ *tls.Config) (quicState, error) {
		<-ctx.Done()
		return quicState{}, ctx.Err()
	}
	probes := o.buildProbes(nil, DefaultPublicDNS, true)
	res := RunAll(context.Background(), probes, time.Second)
	order := make([]ProbeID, len(probes))
	for i, p := range probes {
		order[i] = p.ID
	}
	attempts := res[ProbeQUIC].Attempts
	if len(attempts) != 1 || !attempts[0].Aborted || attempts[0].Cause != ConnectionCauseTimeout {
		t.Fatalf("QUIC attempts = %+v, want the one silent attempt the deadline ended", attempts)
	}
	if dnsNamesComparable(res) || res[ProbeDNSPublic].answerComparison != comparisonUnrecorded {
		t.Fatalf("public DNS row = scope %q, comparison %v; the generic name is not comparable", res[ProbeDNSPublic].DNSNameScope, res[ProbeDNSPublic].answerComparison)
	}
	d := Interpret(nil, order, res)
	if got := findingIDs(d); len(got) != 1 || got[0] != DiagnosisQUICUnavailable || d.Blamed != ProbeQUIC || d.Findings[0].Confidence != ConfidenceHigh {
		t.Fatalf("findings = %v, blamed = %s, confidence = %s (summary: %s)", got, d.Blamed, d.Findings[0].Confidence, d.Summary)
	}
	if r, ok := Remediate(d, res, "linux"); !ok || r.ID != RemedyExpectTCPFallback {
		t.Errorf("remediation = %+v, ok = %v", r, ok)
	}
}

// Where the answers are comparable, which an artifact or a hand-built state can
// carry, a silent attempt is read like any other attempt by the arm that asks
// which address QUIC used: the address is what that arm is about, not how the
// attempt ended. The verdict, the blamed row, the confidence and the advice are
// the ones that arm has always given.
func TestSilentQUICAttemptAtADisputedAddressIsTheDisagreement(t *testing.T) {
	poison4, real4 := net.ParseIP("192.0.2.123"), net.ParseIP("142.250.9.94")
	for _, tc := range []struct {
		name    string
		attempt Attempt
		want    DiagnosisID
		blamed  ProbeID
	}{
		{"silent at the address only the system resolver gave", quicSilent(poison4.String()), DiagnosisDNSDisagreement, ProbeDNSPublic},
		{"silent at an address both resolvers gave", quicSilent(real4.String()), DiagnosisQUICUnavailable, ProbeQUIC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			order := planOrder(t, nil)
			res := settle(t, nil, order, map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poison4, real4}},
				ProbeDNSPublic: {DNSNameScope: "absolute", Status: StatusPass, Addrs: []net.IP{real4}, resolver: "8.8.8.8"},
				ProbeQUIC:      {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{tc.attempt}},
			})
			// Stamped, as the existing disagreement tests stamp it: a shared
			// address is a shared prefix, so the live comparison cannot reach
			// a disagreement that also has an address in common.
			public := res[ProbeDNSPublic]
			public.Status, public.answerComparison = StatusWarn, comparisonDisagree
			res[ProbeDNSPublic] = public
			d := Interpret(nil, order, res)
			if got := findingIDs(d); len(got) == 0 || got[0] != tc.want || d.Blamed != tc.blamed || d.Verdict != VerdictDegraded {
				t.Fatalf("verdict = %s, blamed = %s, findings = %v, want %q blaming %s (summary: %s)", d.Verdict, d.Blamed, got, tc.want, tc.blamed, d.Summary)
			}
			if _, ok := Remediate(d, res, "linux"); !ok {
				t.Error("no remediation")
			}
		})
	}
}

// A QUIC row written before the dialer typed its attempts is not a record of
// which families were tried. That dialer dropped every attempt the probe
// deadline ended and kept only the ones that failed at once, so on an
// IPv4-only network that blocks UDP/443 it recorded the IPv6 attempt with no
// route and nothing for the silent IPv4 one. Such rows reach this engine from
// stored artifacts and from a --via host running an earlier netdoc, and they
// keep the conclusion they were given.
func TestQUICFamilyReadingNeedsATypedRecord(t *testing.T) {
	untyped := Attempt{IP: net.ParseIP("2001:db8::10"), Err: errors.New("dial udp6 [2001:db8::10]:443: connect: network is unreachable")}
	order := planOrder(t, nil)
	res := settle(t, nil, order, map[ProbeID]ProbeResult{
		ProbeInternet: egress(FamilyReachable, FamilyUnreachable),
		ProbeQUIC:     {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{untyped}},
	})
	d := Interpret(nil, order, res)
	if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisQUICUnavailable {
		t.Fatalf("live: findings = %v, want %q (summary: %s)", got, DiagnosisQUICUnavailable, d.Summary)
	}
	// The same row as an artifact holds it: error text and no cause.
	snap := BuildSnapshot(nil, ProbePlan(nil, DefaultPublicDNS, true), res)
	for _, c := range snap.Checks {
		if c.ID == string(ProbeQUIC) && (c.Observed == nil || len(c.Observed.Attempts) != 1 || c.Observed.Attempts[0].Cause != "" || c.Observed.Attempts[0].Error == "") {
			t.Fatalf("stored QUIC row = %+v, want one attempt with error text and no cause", c.Observed)
		}
	}
	replayed, err := ReplaySnapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	if got := findingIDs(replayed); len(got) == 0 || got[0] != DiagnosisQUICUnavailable {
		t.Fatalf("replay: findings = %v, want %q (summary: %s)", got, DiagnosisQUICUnavailable, replayed.Summary)
	}
}
