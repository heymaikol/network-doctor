// Interpret branches the main tables miss: targeted failure rungs, banner
// failures, and generic egress without DNS.

package diagnostic

import (
	"crypto/x509"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// targetOrder is the full https probe order used to exercise the target-mode
// verdict branches.
var targetOrder = []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeTLS, ProbeHTTP, ProbeHTTPS}

func TestDiagnoseTargetBranches(t *testing.T) {
	tg := mustTarget(t, "github.com")
	pass := ProbeResult{Status: StatusPass}
	warn := ProbeResult{Status: StatusWarn}
	skip := ProbeResult{Status: StatusSkip}
	fail := ProbeResult{Status: StatusFail}

	cases := []struct {
		name string
		res  map[ProbeID]ProbeResult
		want string
	}{
		{
			name: "iface down short-circuits",
			res: map[ProbeID]ProbeResult{
				ProbeIface: fail, ProbeInternet: skip, ProbeDNS: skip,
				ProbeTargetTCP: skip, ProbeTLS: skip, ProbeHTTP: skip, ProbeHTTPS: skip,
			},
			want: "link is down",
		},
		{
			// The portal makes every lower rung pass; the verdict must still
			// name the portal rather than the first rung that looks broken.
			name: "captive portal outranks the rungs below it",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: {Status: StatusFail, Portal: &Portal{}}, ProbeDNS: pass,
				ProbeTargetTCP: pass, ProbeTLS: fail, ProbeHTTP: skip, ProbeHTTPS: skip,
			},
			want: "captive portal",
		},
		{
			name: "dns fails but general internet is up",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: fail,
				ProbeTargetTCP: skip, ProbeTLS: skip, ProbeHTTP: skip, ProbeHTTPS: skip,
			},
			want: "general internet is reachable",
		},
		{
			name: "dns fails but general internet is degraded",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: warn, ProbeDNS: fail,
				ProbeTargetTCP: skip, ProbeTLS: skip, ProbeHTTP: skip, ProbeHTTPS: skip,
			},
			want: "general internet is reachable",
		},
		{
			name: "target unreachable but internet up",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: pass,
				ProbeTargetTCP: fail, ProbeTLS: skip, ProbeHTTP: pass, ProbeHTTPS: skip,
			},
			want: "unreachable though DNS and reference egress work",
		},
		{
			name: "target unreachable but internet is degraded",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: warn, ProbeDNS: pass,
				ProbeTargetTCP: fail, ProbeTLS: skip, ProbeHTTP: pass, ProbeHTTPS: skip,
			},
			want: "unreachable though DNS and reference egress work",
		},
		{
			// Both silent, and nothing looked at where: the run may say what
			// did not answer and may not say whose fault it is.
			name: "target and reference endpoints both unreachable",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: fail, ProbeDNS: pass,
				ProbeTargetTCP: fail, ProbeTLS: skip, ProbeHTTP: fail, ProbeHTTPS: skip,
			},
			want: "nothing this run observed says where the path breaks",
		},
		{
			// The same two failures with the routing table's own verdict
			// beside them, which is what earns the located conclusion.
			name: "target and reference endpoints unreachable with a routing cause",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: {Status: StatusFail, Cause: RouteCauseNoDefaultRoute}, ProbeDNS: pass,
				ProbeTargetTCP: fail, ProbeTLS: skip, ProbeHTTP: fail, ProbeHTTPS: skip,
			},
			want: "local egress problem",
		},
		{
			name: "tls handshake fails",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: pass,
				ProbeTargetTCP: pass, ProbeTLS: fail, ProbeHTTP: pass, ProbeHTTPS: skip,
			},
			want: "TLS handshake fails",
		},
		{
			name: "https blocked",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: pass,
				ProbeTargetTCP: pass, ProbeTLS: pass, ProbeHTTP: pass, ProbeHTTPS: fail,
			},
			want: "no HTTPS response",
		},
		{
			name: "http blocked",
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: pass,
				ProbeTargetTCP: pass, ProbeTLS: pass, ProbeHTTP: fail, ProbeHTTPS: pass,
			},
			want: "HTTPS works but no HTTP response",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if v := Interpret(tg, targetOrder, c.res).Summary; !strings.Contains(v, c.want) {
				t.Errorf("got %q, want substring %q", v, c.want)
			}
		})
	}
}

func TestDiagnoseNamesRefusalOnlyWithWorkingEgressControl(t *testing.T) {
	tg := mustTarget(t, "example.com:443")
	base := map[ProbeID]ProbeResult{
		ProbeIface:     {Status: StatusPass},
		ProbeDNS:       {Status: StatusPass},
		ProbeTargetTCP: {Status: StatusFail, Cause: ConnectionCauseRefused},
		ProbeTLS:       {Status: StatusSkip},
		ProbeHTTP:      {Status: StatusSkip},
		ProbeHTTPS:     {Status: StatusSkip},
	}
	for _, tt := range []struct {
		name        string
		internet    Status
		wantSummary string
		wantVerdict string
	}{
		{"working egress isolates refusal", StatusPass, "explicitly refused", VerdictService},
		{"failed egress keeps broader diagnosis", StatusFail, "nothing this run observed says where the path breaks", VerdictNetwork},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := make(map[ProbeID]ProbeResult, len(base)+1)
			for id, result := range base {
				res[id] = result
			}
			res[ProbeInternet] = ProbeResult{Status: tt.internet}
			d := Interpret(tg, targetOrder, res)
			if !strings.Contains(d.Summary, tt.wantSummary) || d.Verdict != tt.wantVerdict {
				t.Errorf("diagnosis = %q (%s), want %q (%s)", d.Summary, d.Verdict, tt.wantSummary, tt.wantVerdict)
			}
		})
	}
}

// The banner-check verdict covers the SSH/SMTP protocol path.
func TestDiagnoseBannerFail(t *testing.T) {
	tg := mustTarget(t, "host:22")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeSSH}
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
		ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass},
		ProbeSSH: {Status: StatusFail},
	}
	if v := Interpret(tg, order, res).Summary; !strings.Contains(v, "banner check failed") {
		t.Errorf("got %q, want 'banner check failed'", v)
	}
}

// Generic mode: egress up but DNS down is a distinct, diagnosable state.
func TestDiagnoseGenericEgressNoDNS(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusFail},
		ProbeDNS: {Status: StatusPass},
	}
	if v := Interpret(nil, order, res).Summary; !strings.Contains(v, "no direct TCP egress") {
		t.Errorf("got %q, want 'no direct TCP egress'", v)
	}
}

// A Warn planted by downgradeEgress isn't a degraded route, it's a dead one:
// with no proxy to carry traffic the prose has to say so, and match the verdict.
//
// The row is assembled rather than produced here. This pass no longer plants a
// Warn on a generic run with no proxy, since a resolver answering is not
// egress, but an artifact written before that reaches replay carrying exactly
// this state and still has to read the same way.
func TestDiagnoseGenericDowngradedNoProxy(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusWarn, downgraded: true},
		ProbeDNS: {Status: StatusPass},
	}
	d := Interpret(nil, order, res)
	if !strings.Contains(d.Summary, "no direct TCP egress") {
		t.Errorf("got %q, want 'no direct TCP egress'", d.Summary)
	}
	if d.Verdict != VerdictNetwork {
		t.Errorf("got verdict %q, want %q", d.Verdict, VerdictNetwork)
	}
}

// The threshold is a boundary the prose depends on, so it is tested at the
// boundary rather than near it: exactly at the threshold counts as material.
func TestClockSkewThresholdBoundary(t *testing.T) {
	cases := []struct {
		name     string
		offset   time.Duration
		material bool
	}{
		{"correct clock", 0, false},
		// Written out rather than derived from clockSkewThreshold: the point
		// is to pin the boundary itself, which a test phrased in terms of the
		// constant would follow silently if the constant moved.
		{"just below, fast", 4*time.Minute + 59*time.Second, false},
		{"just below, slow", -(4*time.Minute + 59*time.Second), false},
		{"exactly at, fast", 5 * time.Minute, true},
		{"exactly at, slow", -5 * time.Minute, true},
		{"just above, fast", 5*time.Minute + time.Second, true},
		{"just above, slow", -(5*time.Minute + time.Second), true},
		{"materially slow", -72 * time.Hour, true},
		{"materially fast", 5 * time.Hour, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{ProbeInternet: {Status: StatusPass, clockOffset: c.offset}}
			d, ok := clockSkew(res)
			if ok != c.material {
				t.Errorf("clockSkew(%v) material = %v, want %v", c.offset, ok, c.material)
			}
			if d != c.offset {
				t.Errorf("clockSkew(%v) offset = %v, want the signed value back", c.offset, d)
			}
		})
	}
	// A run with no egress result at all has nothing to read, and must not
	// invent a reading out of the zero ProbeResult.
	if _, ok := clockSkew(map[ProbeID]ProbeResult{}); ok {
		t.Error("clockSkew reported material skew with no egress result")
	}
}

// Direction and unit are the two halves the user acts on, so both are pinned.
func TestClockSkewWording(t *testing.T) {
	cases := []struct {
		offset time.Duration
		phrase string
		effect string
	}{
		{-72 * time.Hour, "this machine's clock is about 3 days slow", "certificates that are already valid look not yet valid"},
		{5 * time.Hour, "this machine's clock is about 5 hours fast", "certificates that are still valid look expired"},
		{-7 * time.Minute, "this machine's clock is about 7 minutes slow", "certificates that are already valid look not yet valid"},
		{100 * time.Minute, "this machine's clock is about 2 hours fast", "certificates that are still valid look expired"},
	}
	for _, c := range cases {
		if got := clockSkewPhrase(c.offset); got != c.phrase {
			t.Errorf("clockSkewPhrase(%v) = %q, want %q", c.offset, got, c.phrase)
		}
		if got := clockSkewEffect(c.offset); got != c.effect {
			t.Errorf("clockSkewEffect(%v) = %q, want %q", c.offset, got, c.effect)
		}
	}
}

// A wrong clock only explains a certificate-date rejection when it points the
// same way as the rejection. The mismatched pairings are a genuinely bad
// certificate next to an unrelated bad clock.
func TestSkewExplainsTLS(t *testing.T) {
	cases := []struct {
		cause  string
		offset time.Duration
		want   bool
	}{
		{TLSCauseCertificateNotYet, -72 * time.Hour, true},
		{TLSCauseCertificateNotYet, 72 * time.Hour, false},
		{TLSCauseCertificateExpired, 72 * time.Hour, true},
		{TLSCauseCertificateExpired, -72 * time.Hour, false},
		{TLSCauseHostnameMismatch, 72 * time.Hour, false},
		{TLSCauseUntrustedIssuer, -72 * time.Hour, false},
		{TLSCauseHandshake, 72 * time.Hour, false},
		{TLSCauseTimeout, 72 * time.Hour, false},
	}
	for _, c := range cases {
		if got := skewExplainsTLS(c.cause, c.offset); got != c.want {
			t.Errorf("skewExplainsTLS(%q, %v) = %v, want %v", c.cause, c.offset, got, c.want)
		}
	}
}

// The fix hint stops guessing about the clock once the egress probe has
// actually measured it, and keeps guessing when it has not.
func TestReconcileClockSkewFixHints(t *testing.T) {
	const guess = "TLS broken: clock skew, bad/expired cert, or MITM proxy?"
	cases := []struct {
		name    string
		offset  time.Duration
		cause   string
		status  Status
		fix     string
		want    string
		wantNot string
	}{
		{
			name: "expired cert with a fast clock", offset: 5 * time.Hour,
			cause: TLSCauseCertificateExpired, status: StatusFail, fix: "renew the cert" + clockHedgeSuffix,
			want: "about 5 hours fast",
		},
		{
			name: "not yet valid cert with a slow clock", offset: -72 * time.Hour,
			cause: TLSCauseCertificateNotYet, status: StatusFail, fix: "renew the cert" + clockHedgeSuffix,
			want: "about 3 days slow",
		},
		{
			name: "unclassified handshake failure", offset: 5 * time.Hour,
			cause: TLSCauseHandshake, status: StatusFail, fix: guess,
			want: "separately this machine's clock is about 5 hours fast", wantNot: guess,
		},
		{
			name: "hostname mismatch keeps its own answer", offset: 5 * time.Hour,
			cause: TLSCauseHostnameMismatch, status: StatusFail, fix: "cert is for other.example, not host",
			want: "cert is for other.example, not host", wantNot: "clock",
		},
		{
			name: "expired cert with a slow clock drops the clock maybe", offset: -5 * time.Hour,
			cause: TLSCauseCertificateExpired, status: StatusFail, fix: "renew the cert" + clockHedgeSuffix,
			want: "renew the cert", wantNot: "clock",
		},
		{
			name: "not yet valid cert with a fast clock drops the clock maybe", offset: 5 * time.Hour,
			cause: TLSCauseCertificateNotYet, status: StatusFail, fix: "renew the cert" + clockHedgeSuffix,
			want: "renew the cert", wantNot: "clock",
		},
		{
			name: "no measurable skew keeps the fallback", offset: 0,
			cause: TLSCauseHandshake, status: StatusFail, fix: guess,
			want: guess,
		},
		{
			name: "skew below the threshold keeps the fallback", offset: clockSkewThreshold - time.Second,
			cause: TLSCauseHandshake, status: StatusFail, fix: guess,
			want: guess,
		},
		{
			name: "healthy TLS is left alone", offset: 72 * time.Hour,
			cause: "", status: StatusPass, fix: "",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				ProbeInternet: {Status: StatusPass, clockOffset: c.offset},
				ProbeTLS:      {Status: c.status, Cause: c.cause, Fix: c.fix},
			}
			reconcileClockSkew(res)
			got := res[ProbeTLS].Fix
			if !strings.Contains(got, c.want) {
				t.Errorf("fix = %q, want substring %q", got, c.want)
			}
			if c.wantNot != "" && strings.Contains(got, c.wantNot) {
				t.Errorf("fix = %q, want it to drop %q", got, c.wantNot)
			}
		})
	}
}

// The headline stops hedging only when the measurement explains the failure.
func TestDiagnoseTLSClockSkew(t *testing.T) {
	const hedge = "bad/expired cert, clock skew, or MITM proxy"
	tg := mustTarget(t, "https://host")
	cases := []struct {
		name    string
		offset  time.Duration
		cause   string
		want    string
		wantNot string
	}{
		{
			name: "slow clock explains a not-yet-valid cert", offset: -72 * time.Hour, cause: TLSCauseCertificateNotYet,
			want: "fails because this machine's clock is about 3 days slow, so certificates that are already valid look not yet valid.", wantNot: hedge,
		},
		{
			name: "fast clock explains an expired cert", offset: 5 * time.Hour, cause: TLSCauseCertificateExpired,
			want: "fails because this machine's clock is about 5 hours fast, so certificates that are still valid look expired.", wantNot: hedge,
		},
		{name: "no reading keeps the hedge", offset: 0, cause: TLSCauseCertificateExpired, want: hedge},
		{name: "sub-threshold skew keeps the hedge", offset: clockSkewThreshold - time.Second, cause: TLSCauseCertificateExpired, want: hedge},
		{
			name: "slow clock cannot have expired the cert", offset: -5 * time.Hour, cause: TLSCauseCertificateExpired,
			want: "fails: bad/expired cert or MITM proxy.", wantNot: "clock",
		},
		{
			name: "fast clock cannot have made the cert not yet valid", offset: 5 * time.Hour, cause: TLSCauseCertificateNotYet,
			want: "fails: bad/expired cert or MITM proxy.", wantNot: "clock",
		},
		{name: "hostname mismatch keeps the hedge", offset: 5 * time.Hour, cause: TLSCauseHostnameMismatch, want: hedge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass, clockOffset: c.offset},
				ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass},
				ProbeTLS: {Status: StatusFail, Cause: c.cause}, ProbeHTTP: {Status: StatusPass}, ProbeHTTPS: {Status: StatusSkip},
			}
			d := Interpret(tg, targetOrder, res)
			if !strings.Contains(d.Summary, c.want) {
				t.Errorf("got %q, want substring %q", d.Summary, c.want)
			}
			if c.wantNot != "" && strings.Contains(d.Summary, c.wantNot) {
				t.Errorf("got %q, want it to drop %q", d.Summary, c.wantNot)
			}
			if d.Verdict != VerdictService {
				t.Errorf("verdict = %q, want %q", d.Verdict, VerdictService)
			}
		})
	}
}

// The clock evidence has to survive contact with the strings tlsFix actually
// produces, not test-local copies of them: the hint is rewritten by trimming a
// suffix, so a table that spells the suffix out itself would keep passing after
// the real hint stopped ending in it. Both directions of both certificate-date
// rejections are checked end to end, from the x509 error to the finished row.
func TestClockSkewRewritesRealTLSHint(t *testing.T) {
	now := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	expired := x509.CertificateInvalidError{
		Cert:   &x509.Certificate{NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour)},
		Reason: x509.Expired,
	}
	notYet := x509.CertificateInvalidError{
		Cert:   &x509.Certificate{NotBefore: now.Add(24 * time.Hour), NotAfter: now.Add(48 * time.Hour)},
		Reason: x509.Expired,
	}
	cases := []struct {
		name   string
		err    error
		offset time.Duration
		want   string
	}{
		{
			"expired cert, fast clock", expired, 5 * time.Hour,
			"this machine's clock is about 5 hours fast, so certificates that are still valid look expired: set the clock (enable network time) and retry",
		},
		{
			"expired cert, slow clock", expired, -5 * time.Hour,
			"cert is only valid 2030-05-30 → 2030-05-31: renew the cert",
		},
		{
			"not yet valid cert, slow clock", notYet, -5 * time.Hour,
			"this machine's clock is about 5 hours slow, so certificates that are already valid look not yet valid: set the clock (enable network time) and retry",
		},
		{
			"not yet valid cert, fast clock", notYet, 5 * time.Hour,
			"cert is only valid 2030-06-02 → 2030-06-03: renew the cert",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				ProbeInternet: {Status: StatusPass, clockOffset: c.offset},
				ProbeTLS:      {Status: StatusFail, Cause: tlsFailureCause(c.err, now), Fix: tlsFix(c.err)},
			}
			reconcileClockSkew(res)
			if got := res[ProbeTLS].Fix; got != c.want {
				t.Errorf("fix = %q, want %q", got, c.want)
			}
		})
	}
}

// genericOrder is the no-target probe order the Checks panel renders, which is
// the run the offline case is reported against.
var genericOrder = []ProbeID{ProbeIface, ProbeInternet, ProbeQUIC, ProbeProxy, ProbeDNS, ProbeDNSPublic, ProbeDNSEncrypted}

// TestCollateralNamesOnlyExplainedFailures is the causal half of the Checks
// panel: which failed rows the diagnosis has already accounted for as
// downstream of another failure, and which ones it has not. The negative rows
// matter as much as the positive ones, because a failure the diagnosis really
// does blame must never be dimmed for merely following another one down the
// list.
func TestCollateralNamesOnlyExplainedFailures(t *testing.T) {
	pass := ProbeResult{Status: StatusPass}
	fail := ProbeResult{Status: StatusFail}
	na := ProbeResult{Status: StatusNA}
	resolved := ProbeResult{Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}}

	cases := []struct {
		name   string
		target *Target
		order  []ProbeID
		res    map[ProbeID]ProbeResult
		want   []ProbeID
	}{
		{
			name:  "offline: egress is the failure, the rest is what it looks like",
			order: genericOrder,
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: fail, ProbeQUIC: fail, ProbeProxy: na,
				ProbeDNS: fail, ProbeDNSPublic: na, ProbeDNSEncrypted: fail,
			},
			want: []ProbeID{ProbeQUIC, ProbeDNS, ProbeDNSEncrypted},
		},
		{
			name:  "DNS alone, with egress working",
			order: genericOrder,
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeQUIC: pass, ProbeProxy: na,
				ProbeDNS: fail, ProbeDNSPublic: na, ProbeDNSEncrypted: pass,
			},
		},
		{
			name:  "encrypted DNS blocked while plain DNS resolves",
			order: genericOrder,
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeQUIC: pass, ProbeProxy: na,
				ProbeDNS: resolved, ProbeDNSPublic: na, ProbeDNSEncrypted: fail,
			},
		},
		{
			name:  "QUIC blocked while TCP carries traffic",
			order: genericOrder,
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeQUIC: fail, ProbeProxy: na,
				ProbeDNS: pass, ProbeDNSPublic: na, ProbeDNSEncrypted: pass,
			},
		},
		{
			name:  "three failures the working path leaves independently actionable",
			order: genericOrder,
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeQUIC: fail, ProbeProxy: fail,
				ProbeDNS: resolved, ProbeDNSPublic: pass, ProbeDNSEncrypted: fail,
			},
		},
		{
			// The proxy carries traffic, so a resolver failing on top of it is
			// its own problem and keeps its red. The two rows that go direct by
			// construction do not: with the direct path down, their failures
			// are what that one dead path looks like from two more probes.
			name:  "proxy-only: the resolver is its own problem, the direct rows are not",
			order: genericOrder,
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: {Status: StatusWarn, downgraded: true},
				ProbeQUIC: fail, ProbeProxy: pass,
				ProbeDNS: fail, ProbeDNSPublic: na, ProbeDNSEncrypted: fail,
			},
			want: []ProbeID{ProbeQUIC, ProbeDNSEncrypted},
		},
		{
			name:   "target service failure with every rung under it working",
			target: mustTarget(t, "github.com"),
			order:  targetOrder,
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: pass, ProbeDNS: resolved,
				ProbeTargetTCP: pass, ProbeTLS: fail, ProbeHTTP: fail, ProbeHTTPS: fail,
			},
		},
		{
			name:   "offline with a target: the verdict names DNS, so DNS keeps its red",
			target: mustTarget(t, "github.com"),
			order:  genericOrder,
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: fail, ProbeQUIC: fail, ProbeProxy: na,
				ProbeDNS: fail, ProbeDNSPublic: na, ProbeDNSEncrypted: fail,
			},
			want: []ProbeID{ProbeQUIC, ProbeDNSEncrypted},
		},
		{
			name:  "a run with no egress row has nothing to call a failure a consequence of",
			order: []ProbeID{ProbeIface, ProbeQUIC, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeQUIC: fail, ProbeDNS: fail,
			},
		},
		{
			name:  "unfinished run",
			order: genericOrder,
			res: map[ProbeID]ProbeResult{
				ProbeIface: pass, ProbeInternet: fail, ProbeQUIC: fail,
			},
		},
		{name: "no checks at all"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Collateral(c.target, c.order, c.res)
			for _, id := range c.want {
				if !got[id] {
					t.Errorf("%s is not marked a consequence; got %v", id, sortedIDs(got))
				}
			}
			for id := range got {
				if !slices.Contains(c.want, id) {
					t.Errorf("%s marked a consequence, want only %v", id, c.want)
				}
			}
			// Whatever the presentation decided, the evidence is untouched.
			for id, r := range c.res {
				if got[id] && r.Status != StatusFail {
					t.Errorf("%s is %s, so it cannot be a failed row's consequence", id, r.Status)
				}
			}
		})
	}
}

// sortedIDs is a stable rendering of the collateral set for failure messages.
func sortedIDs(set map[ProbeID]bool) []ProbeID {
	ids := make([]ProbeID, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
