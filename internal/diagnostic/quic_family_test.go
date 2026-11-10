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
