package diagnostic

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// A reference dial is a control only for the address family it was made in.
// These runs fail a public target while direct egress works in some family, and
// what changes between them is whether that family is one the target was tried
// in.
func referenceFamilyRun(attempts []Attempt, internet ProbeResult) (*Target, []ProbeID, map[ProbeID]ProbeResult) {
	target := &Target{Raw: "app.example:443", Host: "app.example", Port: 443, Proto: ProtoTLSHTTP}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeTLS, ProbeHTTP, ProbeHTTPS}
	tcp := ProbeResult{Status: StatusFail, Cause: attempts[0].Cause, Attempts: attempts, Families: &FamilyConnectivity{}}
	if tcp.Cause != ConnectionCauseRefused {
		tcp.Cause = ""
	}
	var addrs []net.IP
	for _, attempt := range attempts {
		addrs = append(addrs, attempt.IP)
		if attempt.IP.To4() != nil {
			tcp.Families.IPv4 = FamilyUnreachable
		} else {
			tcp.Families.IPv6 = FamilyUnreachable
		}
	}
	res := map[ProbeID]ProbeResult{
		ProbeIface:     {Status: StatusPass},
		ProbeInternet:  internet,
		ProbeDNS:       {Status: StatusPass, Addrs: addrs},
		ProbeTargetTCP: tcp,
		ProbeTLS:       SkipPrereq(ProbeTLS),
		ProbeHTTP:      {Status: StatusFail},
		ProbeHTTPS:     SkipPrereq(ProbeHTTPS),
	}
	Finalize(res)
	return target, order, res
}

func failedAttempts(cause string, addrs ...string) []Attempt {
	var out []Attempt
	for _, addr := range addrs {
		out = append(out, Attempt{IP: net.ParseIP(addr), Err: errors.New(cause), Cause: cause})
	}
	return out
}

func TestSilentTargetIsNotBlamedWithoutAReferenceInItsFamily(t *testing.T) {
	const v4, v6 = "203.0.113.10", "2001:db8::10"
	families := func(ipv4, ipv6 string) *FamilyConnectivity { return &FamilyConnectivity{IPv4: ipv4, IPv6: ipv6} }
	// The three ways direct egress can be up while one family is not: the
	// family is configured and black-holed, which the egress row warns about,
	// or this network simply does not have it, which it does not.
	v4BlackHoled := ProbeResult{Status: StatusWarn, Cause: FamilyCauseIPv4Unreachable, causeFamily: counterfactualIPv4, Families: families(FamilyUnreachable, FamilyReachable)}
	v6BlackHoled := ProbeResult{Status: StatusWarn, Cause: FamilyCauseIPv6Unreachable, causeFamily: counterfactualIPv6, Families: families(FamilyReachable, FamilyUnreachable)}
	v6Absent := ProbeResult{Status: StatusPass, Families: families(FamilyReachable, FamilyUnreachable)}
	bothUp := ProbeResult{Status: StatusPass, Families: families(FamilyReachable, FamilyReachable)}
	bothDown := ProbeResult{Status: StatusFail, Families: families(FamilyUnreachable, FamilyUnreachable)}

	cases := []struct {
		name     string
		addrs    []string
		refused  bool
		internet ProbeResult
		verdict  string
		finding  DiagnosisID
		family   string // the family the summary must name, when it must
	}{
		{"IPv4-only target, IPv4 egress black-holed", []string{v4}, false, v4BlackHoled, VerdictNetwork, DiagnosisFamilyReachabilityUnlocalized, "IPv4"},
		{"IPv6-only target, IPv6 egress black-holed", []string{v6}, false, v6BlackHoled, VerdictNetwork, DiagnosisFamilyReachabilityUnlocalized, "IPv6"},
		{"IPv6-only target, network without IPv6", []string{v6}, false, v6Absent, VerdictNetwork, DiagnosisFamilyReachabilityUnlocalized, "IPv6"},
		// A silent address as the dialer records it: ended by the probe
		// deadline, not by an answer of its own.
		{"IPv4-only target cut off at the probe deadline, IPv4 egress black-holed", []string{v4}, false, v4BlackHoled, VerdictNetwork, DiagnosisFamilyReachabilityUnlocalized, "IPv4"},
		{"IPv6-only target cut off at the probe deadline, IPv6 egress black-holed", []string{v6}, false, v6BlackHoled, VerdictNetwork, DiagnosisFamilyReachabilityUnlocalized, "IPv6"},
		// The control holds in each of these, so the conclusion it supports stays.
		{"IPv4-only target, both families up", []string{v4}, false, bothUp, VerdictService, DiagnosisTargetUnreachable, ""},
		{"IPv4-only target, IPv6 egress black-holed", []string{v4}, false, v6BlackHoled, VerdictService, DiagnosisTargetUnreachable, ""},
		{"dual-stack target, IPv4 egress black-holed", []string{v4, v6}, false, v4BlackHoled, VerdictService, DiagnosisTargetUnreachable, ""},
		// A refusal is a peer answering in that family, whatever the reference did.
		{"IPv4-only target refused, IPv4 egress black-holed", []string{v4}, true, v4BlackHoled, VerdictService, DiagnosisTCPConnectionRefused, ""},
		// No egress at all was already unlocalized, and stays so.
		{"IPv4-only target, no egress", []string{v4}, false, bothDown, VerdictNetwork, DiagnosisReachabilityUnlocalized, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cause := ConnectionCauseTimeout
			if tc.refused {
				cause = ConnectionCauseRefused
			}
			attempts := failedAttempts(cause, tc.addrs...)
			if strings.Contains(tc.name, "probe deadline") {
				for i := range attempts {
					attempts[i].Err, attempts[i].Aborted = context.DeadlineExceeded, true
				}
			}
			target, order, res := referenceFamilyRun(attempts, tc.internet)
			d := Interpret(target, order, res)
			var got DiagnosisID
			if len(d.Findings) > 0 {
				got = d.Findings[0].ID
			}
			if d.Verdict != tc.verdict || got != tc.finding {
				t.Fatalf("verdict = %s, finding = %q, want %s and %q (summary: %s)", d.Verdict, got, tc.verdict, tc.finding, d.Summary)
			}
			if tc.family != "" && !strings.Contains(d.Summary, "only over "+tc.family) {
				t.Errorf("summary does not name the untested-control family %s: %s", tc.family, d.Summary)
			}
			if tc.finding == DiagnosisFamilyReachabilityUnlocalized {
				f := d.Findings[0]
				if f.Focus != ProbeTargetTCP || d.Blamed != ProbeTargetTCP || f.Confidence != ConfidenceInsufficientEvidence {
					t.Errorf("focus = %s, blamed = %s, confidence = %s", f.Focus, d.Blamed, f.Confidence)
				}
				// The working family must not be cited as a control for the other one.
				for _, e := range f.Evidence {
					if e.Check == ProbeInternet && (e.Kind == EvidenceRuledOut || e.Observation == ObservationStatusPass) {
						t.Errorf("the egress row is cited as a control: %+v", e)
					}
				}
				if e := d.Explain(target, order, res); strings.Contains(e.Meaning, "not tested") || strings.Contains(e.Meaning, "Your internet connection works") {
					t.Errorf("plain-language meaning does not fit this run: %s", e.Meaning)
				}
				if _, ok := Remediate(d, res, "linux"); !ok {
					t.Error("no remediation")
				}
			}
			// The same evidence read back from an artifact reaches the same answer.
			probes := make([]Probe, len(order))
			for i, id := range order {
				probes[i] = Probe{ID: id}
			}
			replayed, err := ReplaySnapshot(BuildSnapshot(target, probes, res))
			if err != nil {
				t.Fatal(err)
			}
			if replayed.Verdict != d.Verdict || replayed.Summary != d.Summary || len(replayed.Findings) != len(d.Findings) {
				t.Errorf("replay = %s %q, live = %s %q", replayed.Verdict, replayed.Summary, d.Verdict, d.Summary)
			}
		})
	}
}

// Reference egress in a family the target was never tried in is not evidence
// about the target, so learning that it works must not move a silent target
// from an unlocalized failure to the target's own fault.
func TestReferenceEgressInAnotherFamilyDoesNotLocalizeASilentTarget(t *testing.T) {
	for _, addr := range []string{"203.0.113.10", "2001:db8::10"} {
		neither := FamilyConnectivity{IPv4: FamilyUnreachable, IPv6: FamilyUnreachable}
		otherOnly := neither
		if net.ParseIP(addr).To4() != nil {
			otherOnly.IPv6 = FamilyReachable
		} else {
			otherOnly.IPv4 = FamilyReachable
		}
		var verdicts []string
		for _, internet := range []ProbeResult{
			{Status: StatusFail, Families: &neither},
			{Status: StatusPass, Families: &otherOnly},
		} {
			target, order, res := referenceFamilyRun(failedAttempts(ConnectionCauseTimeout, addr), internet)
			verdicts = append(verdicts, Interpret(target, order, res).Verdict)
		}
		if slices.Contains(verdicts, VerdictService) {
			t.Errorf("%s: verdicts without and with the other family's egress = %v; neither may blame the service", addr, verdicts)
		}
	}
}

// Which families the target was tried in is a fact about the run. The order the
// attempts were recorded in, the byte length an address is held in, an attempt
// that was abandoned before it concluded, and whether the target was named or
// given as an address are not, and none of them may change the reading.
func TestReferenceFamilyReadingIgnoresOrderAndEncoding(t *testing.T) {
	internet := func() ProbeResult {
		return ProbeResult{Status: StatusWarn, Cause: FamilyCauseIPv4Unreachable, causeFamily: counterfactualIPv4, Families: &FamilyConnectivity{IPv4: FamilyUnreachable, IPv6: FamilyReachable}}
	}
	base := func() []Attempt { return failedAttempts(ConnectionCauseTimeout, "203.0.113.10", "203.0.113.11") }
	target, order, res := referenceFamilyRun(base(), internet())
	want := Interpret(target, order, res)
	if want.Verdict != VerdictNetwork || len(want.Findings) != 1 || want.Findings[0].ID != DiagnosisFamilyReachabilityUnlocalized {
		t.Fatalf("baseline verdict = %s, findings = %v (summary: %s)", want.Verdict, want.Findings, want.Summary)
	}

	reversed := base()
	slices.Reverse(reversed)
	fourByte := base()
	for i := range fourByte {
		fourByte[i].IP = fourByte[i].IP.To4()
	}
	abandoned := append(base(), Attempt{IP: net.ParseIP("2001:db8::10"), Err: context.Canceled, Aborted: true})
	for name, attempts := range map[string][]Attempt{"reversed": reversed, "four-byte addresses": fourByte, "abandoned IPv6 attempt": abandoned} {
		target, order, res := referenceFamilyRun(attempts, internet())
		if got := Interpret(target, order, res); got.Verdict != want.Verdict || got.Summary != want.Summary || got.Blamed != want.Blamed || len(got.Findings) != 1 {
			t.Errorf("%s: %s %q, want %s %q", name, got.Verdict, got.Summary, want.Verdict, want.Summary)
		}
	}

	// An address typed as the target has no DNS rows to lean on, and the same
	// one family to be wrong about.
	_, order, res = referenceFamilyRun(base()[:1], internet())
	res[ProbeDNS] = ProbeResult{Status: StatusNA}
	literal := &Target{Raw: "203.0.113.10:443", Host: "203.0.113.10", IP: net.ParseIP("203.0.113.10"), Port: 443, Proto: ProtoTLSHTTP}
	if got := Interpret(literal, order, res); got.Verdict != VerdictNetwork || got.Blamed != ProbeTargetTCP || !strings.Contains(got.Summary, "only over IPv4") {
		t.Errorf("address target: %s, findings = %v (summary: %s)", got.Verdict, got.Findings, got.Summary)
	}
}

// The sibling probes fail early in probe order in exactly this outage, so the
// row a reader is sent to has to be the one the sentence is about and not the
// first failure: a QUIC row that died with the same family is not what made
// the target silent, and no later row is its consequence.
func TestFamilyUnlocalizedTargetIsTheRowBlamed(t *testing.T) {
	internet := ProbeResult{Status: StatusWarn, Cause: FamilyCauseIPv4Unreachable, causeFamily: counterfactualIPv4, Families: &FamilyConnectivity{IPv4: FamilyUnreachable, IPv6: FamilyReachable}}
	target, order, res := referenceFamilyRun(failedAttempts(ConnectionCauseTimeout, "203.0.113.10"), internet)
	res[ProbeQUIC] = ProbeResult{Status: StatusFail}
	order = slices.Insert(order, 2, ProbeQUIC)
	d := Interpret(target, order, res)
	if d.Blamed != ProbeTargetTCP {
		t.Fatalf("blamed = %s, want %s (summary: %s)", d.Blamed, ProbeTargetTCP, d.Summary)
	}
	if collateral := d.Collateral(order, res); !collateral[ProbeHTTP] || collateral[ProbeQUIC] {
		t.Errorf("collateral = %v: the HTTP row follows from the target row, and the QUIC row from neither", collateral)
	}
}

// The production probes, runner and Finalize over the in-memory network, with
// one family turned into a black hole: its dials block until the probe gives
// up, which is what a silent address does. The hand-built rows above can
// record a timeout however they like, and the lab models one as an answer of
// its own; this is the shape a real run produces.
func TestBlackHoledFamilyIsNotBlamedOnTheTarget(t *testing.T) {
	for _, tc := range []struct{ name, dead, addr, family string }{
		{"IPv4", "tcp4", "203.0.113.10", "IPv4"},
		{"IPv6", "tcp6", "2001:db8::10", "IPv6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newBudgetFixture(t)
			f.loopbacks = []net.IP{net.ParseIP(tc.addr)}
			o := f.ops()
			dial := o.dialContext
			o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network == tc.dead {
					<-ctx.Done()
					return nil, &net.OpError{Op: "dial", Net: network, Err: context.DeadlineExceeded}
				}
				return dial(ctx, network, addr)
			}
			target, err := ParseTarget(budgetTargetHost + ":443")
			if err != nil {
				t.Fatal(err)
			}
			probes := o.buildProbes(target, DefaultPublicDNS, true)
			res := RunAll(context.Background(), probes, time.Second)
			order := make([]ProbeID, len(probes))
			for i, p := range probes {
				order[i] = p.ID
			}
			attempts := res[ProbeTargetTCP].Attempts
			if len(attempts) != 1 || !attempts[0].Aborted || attempts[0].Cause != ConnectionCauseTimeout {
				t.Fatalf("target attempts = %+v, want one timeout ended by the probe deadline", attempts)
			}
			d := Interpret(target, order, res)
			if d.Verdict != VerdictNetwork || d.Focus() != ProbeTargetTCP || len(d.Findings) == 0 || d.Findings[0].ID != DiagnosisFamilyReachabilityUnlocalized {
				t.Fatalf("verdict = %s, findings = %+v (egress row: %s, summary: %s)", d.Verdict, d.Findings, res[ProbeInternet].Detail, d.Summary)
			}
			if !strings.Contains(d.Summary, "only over "+tc.family) {
				t.Errorf("summary does not name %s: %s", tc.family, d.Summary)
			}
		})
	}
}

// One address refused and the rest silent is not the all-silent picture. The
// refusal came back in the family that was tried, so that family carried a
// round trip whatever the reference endpoints did, and the run keeps the
// reading it has always given a target that is partly refused. Silence alone,
// in the same run shape, stays unlocalized.
func TestARefusedAddressIsAReferenceInItsFamily(t *testing.T) {
	for _, tc := range []struct {
		name            string
		silent, refused string
		reference       FamilyConnectivity
	}{
		{"IPv4", "203.0.113.11", "203.0.113.10", FamilyConnectivity{IPv4: FamilyUnreachable, IPv6: FamilyReachable}},
		{"IPv6", "2001:db8::11", "2001:db8::10", FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyUnreachable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			silent := failedAttempts(ConnectionCauseTimeout, tc.silent)
			silent[0].Err, silent[0].Aborted = context.DeadlineExceeded, true
			for _, withRefusal := range []bool{true, false} {
				attempts := silent
				want, wantVerdict := DiagnosisFamilyReachabilityUnlocalized, VerdictNetwork
				if withRefusal {
					attempts = append(slices.Clone(silent), failedAttempts(ConnectionCauseRefused, tc.refused)...)
					want, wantVerdict = DiagnosisTargetUnreachable, VerdictService
				}
				reference := tc.reference
				target, order, res := referenceFamilyRun(attempts, ProbeResult{Status: StatusPass, Families: &reference})
				d := Interpret(target, order, res)
				if d.Verdict != wantVerdict || len(d.Findings) == 0 || d.Findings[0].ID != want {
					t.Errorf("refusal present = %v: verdict = %s, findings = %+v, want %s and %s", withRefusal, d.Verdict, d.Findings, wantVerdict, want)
				}
			}
		})
	}
}

// A secure target's plain-HTTP row dials the same host on port 80. When that
// answered at a public address in the family the TCP row failed in, the host
// was reached over that family, and its silence on the other port is the
// target's. An answer at a local address is not the internet path, and an
// HTTP row that failed too leaves the picture unlocalized.
func TestTheTargetAnsweringOnAnotherPortIsAReference(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addr      string
		reference FamilyConnectivity
	}{
		{"IPv4", "203.0.113.10", FamilyConnectivity{IPv4: FamilyUnreachable, IPv6: FamilyReachable}},
		{"IPv6", "2001:db8::10", FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyUnreachable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, http := range []struct {
				name string
				row  ProbeResult
				want DiagnosisID
			}{
				{"answered in the family", ProbeResult{Status: StatusPass, SelectedIP: net.ParseIP(tc.addr)}, DiagnosisTargetUnreachable},
				{"answered at a local address", ProbeResult{Status: StatusPass, SelectedIP: net.ParseIP("192.168.1.5")}, DiagnosisFamilyReachabilityUnlocalized},
				{"failed too", ProbeResult{Status: StatusFail, SelectedIP: net.ParseIP(tc.addr)}, DiagnosisFamilyReachabilityUnlocalized},
			} {
				if tc.name == "IPv6" && http.name == "answered at a local address" {
					http.row.SelectedIP = net.ParseIP("fd00::5")
				}
				attempts := failedAttempts(ConnectionCauseTimeout, tc.addr)
				attempts[0].Err, attempts[0].Aborted = context.DeadlineExceeded, true
				reference := tc.reference
				target, order, res := referenceFamilyRun(attempts, ProbeResult{Status: StatusPass, Families: &reference})
				res[ProbeHTTP] = http.row
				d := Interpret(target, order, res)
				if len(d.Findings) == 0 || d.Findings[0].ID != http.want {
					t.Errorf("HTTP row %s: verdict = %s, findings = %+v, want %s", http.name, d.Verdict, d.Findings, http.want)
				}
			}
		})
	}
}
