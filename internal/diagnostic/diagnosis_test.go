// Table tests for Diagnose verdicts: generic and targeted runs, proxy-only
// networks, and the in-progress placeholder.

package diagnostic

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
)

func TestDiagnoseGeneric(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}
	cases := []struct {
		name          string
		internet, dns Status
		want          string
	}{
		{"online", StatusPass, StatusPass, "Online"},
		{"dns down", StatusPass, StatusFail, "DNS resolution is failing"},
		{"no egress", StatusFail, StatusPass, "no direct TCP egress"},
		{"offline", StatusFail, StatusFail, "Offline"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				ProbeIface:    {Status: StatusPass},
				ProbeInternet: {Status: c.internet},
				ProbeDNS:      {Status: c.dns},
			}
			if v, _ := Diagnose(nil, order, res); !strings.Contains(v, c.want) {
				t.Errorf("got %q, want substring %q", v, c.want)
			}
		})
	}
}

// Direct and proxied egress are diagnosed separately: a proxy-only network
// reads as online-via-proxy, and a dead configured proxy is called out even
// when direct connectivity works.
func TestDiagnoseProxy(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS}
	cases := []struct {
		name                 string
		internet, proxy, dns Status
		downgraded           bool
		want                 string
	}{
		{"proxy-only network", StatusWarn, StatusWarn, StatusPass, true, "Online via the environment proxy"},
		{"degraded direct with proxy", StatusWarn, StatusPass, StatusPass, false, "Online but degraded"},
		{"proxy failed, direct fine", StatusPass, StatusFail, StatusPass, false, "proxy check failed"},
		{"no proxy configured", StatusPass, StatusNA, StatusPass, false, "Online: direct TCP egress"},
		// A downgraded egress row is a dead direct route wearing a Warn, so a
		// resolver failure beside it cannot be prefaced with working egress.
		{"proxy-only network with broken DNS", StatusWarn, StatusPass, StatusFail, true, "Direct egress is blocked and DNS resolution is failing"},
		// The probe's own Warn, with no proxy in the picture: direct egress
		// genuinely carries traffic, so the older wording still holds.
		{"degraded direct, no proxy, broken DNS", StatusWarn, StatusNA, StatusFail, false, "Internet egress works (degraded)"},
		// Nothing carries traffic, so nothing may be described as carrying it.
		{"everything down", StatusFail, StatusFail, StatusFail, false, "Offline"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				ProbeIface:    {Status: StatusPass},
				ProbeInternet: {Status: c.internet, downgraded: c.downgraded},
				ProbeProxy:    {Status: c.proxy},
				ProbeDNS:      {Status: c.dns},
			}
			if v, _ := Diagnose(nil, order, res); !strings.Contains(v, c.want) {
				t.Errorf("got %q, want substring %q", v, c.want)
			}
		})
	}
}

// A proxy-only network whose resolver is also gone, assembled the way a real
// run assembles it: raw probe results in, Finalize, then Diagnose. The direct
// dial failed outright and only the environment proxy carries traffic, so the
// summary may not open by saying internet egress works.
func TestDiagnoseProxyOnlyBrokenDNS(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS}
	res := map[ProbeID]ProbeResult{
		ProbeIface:    {Status: StatusPass},
		ProbeInternet: {Status: StatusFail, Detail: "no direct TCP egress to 1.1.1.1, 8.8.8.8 (port 443)"},
		ProbeProxy:    {Status: StatusPass, Detail: "proxy proxy.corp:3128 tunnels to connectivitycheck.gstatic.com:443"},
		ProbeDNS:      {Status: StatusFail, Detail: "cannot resolve connectivitycheck.gstatic.com: i/o timeout"},
	}
	Finalize(res)

	// The state transition the diagnosis has to read correctly: the working
	// proxy turned an egress Fail into a Warn, and the Warn is flagged as one
	// Finalize planted rather than one the probe raised.
	internet := res[ProbeInternet]
	if internet.Status != StatusWarn || !internet.downgraded {
		t.Fatalf("egress after Finalize = %v (downgraded %t), want a downgraded WARN", internet.Status, internet.downgraded)
	}
	if !strings.Contains(internet.Detail, "but the environment proxy works") {
		t.Errorf("egress detail = %q, want the proxy named as the surviving path", internet.Detail)
	}
	if directEgressOK(res) {
		t.Error("directEgressOK is true for an egress row that only the proxy rescued")
	}
	if res[ProbeDNS].Status != StatusFail {
		t.Fatalf("DNS after Finalize = %v, want FAIL", res[ProbeDNS].Status)
	}

	summary, verdict := Diagnose(nil, order, res)
	want := "Direct egress is blocked and DNS resolution is failing; only the environment proxy is carrying traffic."
	if summary != want {
		t.Errorf("summary = %q, want %q", summary, want)
	}
	for _, claim := range []string{"Internet egress works", "Online"} {
		if strings.Contains(summary, claim) {
			t.Errorf("summary %q claims %q on a network with no direct egress", summary, claim)
		}
	}
	if verdict != VerdictNetwork {
		t.Errorf("verdict = %q, want %q", verdict, VerdictNetwork)
	}
}

func TestDiagnoseTargetProxyOnly(t *testing.T) {
	tg := mustTarget(t, "host:9999")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeTargetTCP}
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusFail},
		ProbeProxy: {Status: StatusPass}, ProbeDNS: {Status: StatusPass},
		ProbeTargetTCP: {Status: StatusFail},
	}
	downgradeEgress(res)
	if v, _ := Diagnose(tg, order, res); !strings.Contains(v, "proxy-only network") {
		t.Errorf("got %q, want a proxy-only verdict", v)
	}
	res[ProbeInternet] = ProbeResult{Status: StatusWarn}
	res[ProbeTargetTCP] = ProbeResult{Status: StatusPass}
	if v, _ := Diagnose(tg, order, res); !strings.Contains(v, "direct egress to the egress check's reference endpoints is degraded") {
		t.Errorf("got %q, want a degraded direct-egress verdict", v)
	}
}

func TestDiagnoseIncomplete(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}
	res := map[ProbeID]ProbeResult{ProbeIface: {Status: StatusPass}}
	if v, _ := Diagnose(nil, order, res); !strings.Contains(v, "Running") {
		t.Errorf("incomplete should report running, got %q", v)
	}
}

func TestDiagnoseSelectionPreservesSupportedDiagnosis(t *testing.T) {
	tg := mustTarget(t, "github.com")
	order := []ProbeID{
		ProbeIface, ProbeInternet, ProbeQUIC, ProbeProxy, ProbeDNS,
		ProbeDNSPublic, ProbeDNSEncrypted, ProbeTargetTCP, ProbePMTU,
		ProbeSSID, ProbeTLS, ProbeHTTP, ProbeHTTPS,
	}
	cases := []struct {
		name      string
		overrides map[ProbeID]ProbeResult
		omit      []ProbeID
		verdict   string
	}{
		{"healthy", nil, []ProbeID{ProbeSSID, ProbeDNSPublic}, VerdictOK},
		{"degraded", map[ProbeID]ProbeResult{ProbeQUIC: {Status: StatusFail}}, []ProbeID{ProbeSSID, ProbeDNSPublic}, VerdictDegraded},
		{"dns", map[ProbeID]ProbeResult{ProbeDNS: {Status: StatusFail}}, []ProbeID{ProbeSSID}, VerdictDNS},
		{"network", map[ProbeID]ProbeResult{ProbeInternet: {Status: StatusFail}, ProbeTargetTCP: {Status: StatusFail}}, []ProbeID{ProbeSSID, ProbeDNSPublic}, VerdictNetwork},
		{"service", map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusFail}}, []ProbeID{ProbeSSID, ProbeDNSPublic}, VerdictService},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := make(map[ProbeID]ProbeResult, len(order))
			for _, id := range order {
				results[id] = ProbeResult{Status: StatusPass}
			}
			for id, result := range tc.overrides {
				results[id] = result
			}
			wantSummary, wantVerdict := Diagnose(tg, order, results)
			if wantVerdict != tc.verdict {
				t.Fatalf("fixture verdict = %q, want %q (summary: %s)", wantVerdict, tc.verdict, wantSummary)
			}

			omit := make(map[ProbeID]bool, len(tc.omit))
			for _, id := range tc.omit {
				omit[id] = true
				delete(results, id)
			}
			selected := make([]ProbeID, 0, len(order)-len(omit))
			for _, id := range order {
				if !omit[id] {
					selected = append(selected, id)
				}
			}
			if summary, verdict := Diagnose(tg, selected, results); summary != wantSummary || verdict != wantVerdict {
				t.Errorf("omitting %v changed diagnosis from %q/%q to %q/%q", tc.omit, wantSummary, wantVerdict, summary, verdict)
			}
		})
	}
}

func TestDiagnoseDoesNotInferMissingEvidence(t *testing.T) {
	tg := mustTarget(t, "github.com")
	t.Run("target failure needs general internet evidence", func(t *testing.T) {
		order := []ProbeID{ProbeIface, ProbeDNS, ProbeTargetTCP}
		results := map[ProbeID]ProbeResult{
			ProbeIface:     {Status: StatusPass},
			ProbeDNS:       {Status: StatusPass},
			ProbeTargetTCP: {Status: StatusFail},
		}
		summary, verdict := Diagnose(tg, order, results)
		if verdict != VerdictNetwork || !strings.Contains(summary, "general internet reachability was not checked") {
			t.Fatalf("Diagnose without internet evidence = %q/%q", summary, verdict)
		}
		results[ProbeInternet] = ProbeResult{Status: StatusPass}
		order = append(order[:1], append([]ProbeID{ProbeInternet}, order[1:]...)...)
		if _, verdict := Diagnose(tg, order, results); verdict != VerdictService {
			t.Fatalf("Diagnose with internet evidence = %q, want %q", verdict, VerdictService)
		}
	})

	t.Run("missing PMTU warning cannot imply a path black hole", func(t *testing.T) {
		order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeTLS}
		results := map[ProbeID]ProbeResult{
			ProbeIface:     {Status: StatusPass},
			ProbeInternet:  {Status: StatusPass},
			ProbeDNS:       {Status: StatusPass},
			ProbeTargetTCP: {Status: StatusPass},
			ProbeTLS:       {Status: StatusFail, Cause: TLSCauseTimeout},
		}
		if summary, verdict := Diagnose(tg, order, results); verdict != VerdictService || strings.Contains(summary, "MTU") {
			t.Fatalf("Diagnose without PMTU evidence = %q/%q", summary, verdict)
		}
	})

	t.Run("finalization cannot turn an isolated egress failure into a warning", func(t *testing.T) {
		results := map[ProbeID]ProbeResult{ProbeInternet: {Status: StatusFail}}
		Finalize(results)
		if results[ProbeInternet].Status != StatusFail {
			t.Fatalf("isolated egress status = %v, want FAIL", results[ProbeInternet].Status)
		}
	})
}

func TestDiagnoseTarget(t *testing.T) {
	tg := mustTarget(t, "github.com")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeTLS, ProbeHTTP, ProbeHTTPS}

	// DNS + internet OK, Target TCP fails → remote port/firewall verdict.
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
		ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusFail},
		ProbeTLS: {Status: StatusSkip}, ProbeHTTP: {Status: StatusPass}, ProbeHTTPS: {Status: StatusSkip},
	}
	if v, _ := Diagnose(tg, order, res); !strings.Contains(v, "unreachable") {
		t.Errorf("got %q, want 'unreachable'", v)
	}

	// Everything passes → Diagnose owns the shared all-clear verdict.
	for _, id := range order {
		res[id] = ProbeResult{Status: StatusPass}
	}
	if v, _ := Diagnose(tg, order, res); !strings.Contains(v, "github.com:443 looks healthy") {
		t.Errorf("got %q, want target healthy verdict", v)
	}

	// A raw egress failure must never fall through to the all-clear verdict,
	// and with the target answering directly it must not be called an egress
	// outage either.
	res[ProbeInternet] = ProbeResult{Status: StatusFail}
	if v, _ := Diagnose(tg, order, res); !strings.Contains(v, "reference endpoints are what did not answer") {
		t.Errorf("got %q, want the reference-endpoint verdict", v)
	}
}

func TestDiagnoseTargetWarnings(t *testing.T) {
	tg := mustTarget(t, "github.com")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeTargetTCP, ProbeTLS, ProbeHTTP, ProbeHTTPS}
	for _, warning := range []ProbeID{ProbeProxy, ProbeTargetTCP} {
		res := make(map[ProbeID]ProbeResult, len(order))
		for _, id := range order {
			res[id] = ProbeResult{Status: StatusPass}
		}
		res[warning] = ProbeResult{Status: StatusWarn}
		if v, _ := Diagnose(tg, order, res); !strings.Contains(v, "some checks are degraded") {
			t.Errorf("%s warning: got %q, want degraded verdict", warning, v)
		}
	}
}

// FocusProbe is what lets the UI park the cursor, the remediation and the
// evidence on the row the prose points at. It has to stay tied to the verdict
// that was actually reached: a black hole preempted by a broken resolver
// blames the resolver, or the cursor would land on Path MTU while the banner
// talks about DNS.
func TestFocusProbe(t *testing.T) {
	tg := mustTarget(t, "github.com")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeTargetTCP, ProbePMTU, ProbeTLS, ProbeHTTP, ProbeHTTPS}
	blackHole := map[ProbeID]ProbeResult{
		ProbePMTU:  {Status: StatusWarn},
		ProbeTLS:   {Status: StatusFail, Cause: TLSCauseTimeout},
		ProbeHTTP:  {Status: StatusFail, timedOut: true},
		ProbeHTTPS: {Status: StatusFail, timedOut: true},
	}
	withDNSDown := map[ProbeID]ProbeResult{ProbeDNS: {Status: StatusFail}}
	for id, r := range blackHole {
		withDNSDown[id] = r
	}

	cases := []struct {
		name string
		res  map[ProbeID]ProbeResult
		want ProbeID
	}{
		{"path MTU black hole", blackHole, ProbePMTU},
		// No black hole to redirect the reader: the handshake failure is its
		// own answer, so the TLS row is the row the sentence is about.
		{"immediate TLS failure", map[ProbeID]ProbeResult{ProbeTLS: {Status: StatusFail}}, ProbeTLS},
		{"a stall with no PMTU warning", map[ProbeID]ProbeResult{ProbeTLS: {Status: StatusFail, Cause: TLSCauseTimeout}}, ProbeTLS},
		// TLS reaching the far end while the bulk rows do not is the same
		// black hole seen through the other half of the correlation.
		{"the stall shows only on the HTTP rows", map[ProbeID]ProbeResult{
			ProbePMTU: {Status: StatusWarn},
			ProbeHTTP: {Status: StatusFail, timedOut: true},
		}, ProbePMTU},
		// Nothing failed and nothing is degraded, so there is no row to send
		// the reader to and none is invented.
		{"everything passes", nil, ""},
		// The resolver preempts the black hole, so the row follows the prose
		// down to DNS rather than staying on the stall the verdict dropped.
		{"resolver failure outranks the stall", withDNSDown, ProbeDNS},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := make(map[ProbeID]ProbeResult, len(order))
			for _, id := range order {
				res[id] = ProbeResult{Status: StatusPass}
			}
			for id, r := range c.res {
				res[id] = r
			}
			if got := FocusProbe(tg, order, res); got != c.want {
				t.Errorf("FocusProbe = %q, want %q", got, c.want)
			}
		})
	}
}

// A row that measured nothing is not half of the path-MTU correlation. On a
// platform with no send-queue accounting an unverified Path MTU row is the
// ordinary shape of a run, so it has to reach the same answer as no Path MTU
// row at all: the protocol stall keeps its own service verdict rather than
// being promoted to a black hole nothing observed.
func TestUnverifiedPathMTUIsNotBlackHoleEvidence(t *testing.T) {
	tg := mustTarget(t, "github.com")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeTargetTCP, ProbePMTU, ProbeTLS, ProbeHTTP, ProbeHTTPS}
	stall := ProbeResult{Status: StatusFail, Cause: TLSCauseTimeout}
	unverified := map[ProbeID]ProbeResult{
		ProbeTLS: stall,
		ProbePMTU: {Status: StatusNA,
			Detail: "24 KiB accepted by the local TCP stack, but path-MTU delivery could not be verified: no TCP send-queue accounting on windows"},
	}
	summary, verdict := Diagnose(tg, order, unverified)
	if strings.Contains(summary, "path MTU black hole") {
		t.Errorf("summary = %q, want no black hole named: nothing measured one", summary)
	}
	// The comparison is the invariant: an unverified row is worth exactly as
	// much as a row that never ran.
	wantSummary, wantVerdict := Diagnose(tg, order, map[ProbeID]ProbeResult{ProbeTLS: stall})
	if summary != wantSummary || verdict != wantVerdict {
		t.Errorf("unverified Path MTU changed the answer to (%q, %q), want (%q, %q)", summary, verdict, wantSummary, wantVerdict)
	}
	if focus := FocusProbe(tg, order, unverified); focus == ProbePMTU {
		t.Error("focus landed on a Path MTU row that established nothing")
	}
}

// The service/network split is the whole point of the machine-readable
// verdict: the same target failure classifies differently depending on
// whether anything else proved the path usable.
func TestVerdict(t *testing.T) {
	tg := mustTarget(t, "github.com")
	targetOrder := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeTargetTCP, ProbePMTU, ProbeTLS, ProbeHTTP, ProbeHTTPS}
	genericOrder := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS}

	cases := []struct {
		name   string
		target *Target
		order  []ProbeID
		res    map[ProbeID]ProbeResult
		want   string
	}{
		{"all clear", tg, targetOrder, nil, VerdictOK},
		{"link down", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbeIface: {Status: StatusFail},
		}, VerdictNetwork},
		{"dns failure", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbeDNS: {Status: StatusFail},
		}, VerdictDNS},
		{"port closed, internet fine", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbeTargetTCP: {Status: StatusFail},
		}, VerdictService},
		{"target unreachable, no egress", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbeInternet:  {Status: StatusFail},
			ProbeTargetTCP: {Status: StatusFail},
		}, VerdictNetwork},
		{"tls broken", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbeTLS: {Status: StatusFail},
		}, VerdictService},
		{"http broken", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbeHTTPS: {Status: StatusFail},
		}, VerdictService},
		// A bulk stall correlated with a protocol timeout reclassifies the rung
		// it broke; an immediate protocol error does not.
		{"tls broken by a black hole", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbePMTU: {Status: StatusWarn},
			ProbeTLS:  {Status: StatusFail, Cause: TLSCauseTimeout},
		}, VerdictNetwork},
		{"certificate failure alongside a bulk stall", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbePMTU: {Status: StatusWarn},
			ProbeTLS:  {Status: StatusFail},
		}, VerdictService},
		// On its own it's only a warning, since nothing the caller asked for broke,
		// and a stalled write has innocent explanations.
		{"black hole evidence alone", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbePMTU: {Status: StatusWarn},
		}, VerdictDegraded},
		{"target fine, egress blocked", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail},
		}, VerdictDegraded},
		{"slow but working", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbeTargetTCP: {Status: StatusWarn},
		}, VerdictDegraded},
		// The target and direct egress both work; only the configured proxy
		// check failed. Apps that use the proxy will still fail, so
		// this can't be a clean pass.
		{"target fine, configured proxy broken", tg, targetOrder, map[ProbeID]ProbeResult{
			ProbeProxy: {Status: StatusFail},
		}, VerdictDegraded},
		{"generic online", nil, genericOrder, nil, VerdictOK},
		{"generic dns down", nil, genericOrder, map[ProbeID]ProbeResult{
			ProbeDNS: {Status: StatusFail},
		}, VerdictDNS},
		{"generic offline", nil, genericOrder, map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail},
			ProbeDNS:      {Status: StatusFail},
		}, VerdictNetwork},
		{"generic no egress", nil, genericOrder, map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail},
			ProbeProxy:    {Status: StatusNA},
		}, VerdictNetwork},
		{"generic proxy-only", nil, genericOrder, map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusWarn, downgraded: true},
			ProbeProxy:    {Status: StatusPass},
		}, VerdictDegraded},
		// Same network, resolver gone: the direct route is dead and no name
		// resolves, which is a broken path rather than a degraded one.
		{"generic proxy-only with broken DNS", nil, genericOrder, map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusWarn, downgraded: true},
			ProbeProxy:    {Status: StatusPass},
			ProbeDNS:      {Status: StatusFail},
		}, VerdictNetwork},
		// Direct internet and DNS both work; only the configured proxy check
		// failed. The summary already warns proxy-aware apps will fail, so
		// the verdict can't say ok.
		{"generic direct fine, configured proxy broken", nil, genericOrder, map[ProbeID]ProbeResult{
			ProbeProxy: {Status: StatusFail},
		}, VerdictDegraded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := make(map[ProbeID]ProbeResult, len(c.order))
			for _, id := range c.order {
				res[id] = ProbeResult{Status: StatusPass}
			}
			for id, r := range c.res {
				res[id] = r
			}
			if summary, got := Diagnose(c.target, c.order, res); got != c.want {
				t.Errorf("Verdict = %q, want %q (summary: %s)", got, c.want, summary)
			}
		})
	}

	// An unfinished run must not claim health.
	if _, got := Diagnose(tg, targetOrder, map[ProbeID]ProbeResult{ProbeIface: {Status: StatusPass}}); got != VerdictIncomplete {
		t.Errorf("Verdict on partial results = %q, want %q", got, VerdictIncomplete)
	}
}

func TestReconcileDNS(t *testing.T) {
	ip1, ip2 := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	elsewhere := net.ParseIP("198.51.100.7")
	t.Run("public resolver works", func(t *testing.T) {
		res := map[ProbeID]ProbeResult{
			ProbeDNS:       {Status: StatusFail, Detail: "SERVFAIL"},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{ip1}},
		}
		reconcileDNS(res)
		if !strings.Contains(res[ProbeDNS].Detail, "public DNS resolves it") || res[ProbeDNSPublic].Status != StatusPass {
			t.Fatalf("results = %+v, want public success to explain system failure", res)
		}
	})
	t.Run("both say name is absent", func(t *testing.T) {
		res := map[ProbeID]ProbeResult{
			ProbeDNS:       {Status: StatusFail, DNSNotFound: true, Detail: "not found"},
			ProbeDNSPublic: {Status: StatusPass, DNSNotFound: true},
		}
		reconcileDNS(res)
		if !strings.Contains(res[ProbeDNS].Detail, "agrees") || res[ProbeDNSPublic].Status != StatusPass {
			t.Fatalf("results = %+v, want corroborated not-found", res)
		}
	})
	t.Run("unrelated answers warn", func(t *testing.T) {
		res := map[ProbeID]ProbeResult{
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{ip1}},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{elsewhere}, resolver: "8.8.8.8"},
		}
		reconcileDNS(res)
		if !strings.Contains(res[ProbeDNSPublic].Detail, "public 8.8.8.8:") {
			t.Errorf("detail = %q, want it to name the resolver", res[ProbeDNSPublic].Detail)
		}
		if res[ProbeDNSPublic].Status != StatusWarn || !strings.Contains(res[ProbeDNSPublic].Detail, "split DNS") {
			t.Fatalf("public result = %+v, want explanatory warning", res[ProbeDNSPublic])
		}
		// The warning should name the comparison prefix on each side, so a
		// reader can see that these answers really did mask to different
		// prefixes rather than to two /24s inside one /16 (ordinary anycast).
		for _, want := range []string{"192.0.0.0/16", "198.51.0.0/16"} {
			if !strings.Contains(res[ProbeDNSPublic].Detail, want) {
				t.Fatalf("detail = %q, want it to name comparison prefix %s", res[ProbeDNSPublic].Detail, want)
			}
		}
	})
	t.Run("same answers in different order pass", func(t *testing.T) {
		res := map[ProbeID]ProbeResult{
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{ip1, ip2}},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{ip2, ip1}},
		}
		reconcileDNS(res)
		if res[ProbeDNSPublic].Status != StatusPass {
			t.Fatalf("public result = %+v, want matching set to pass", res[ProbeDNSPublic])
		}
	})
	// Round-robin and GeoDNS: the everyday case a healthy run must not warn on.
	t.Run("rotating answers in one block pass", func(t *testing.T) {
		for _, tc := range []struct {
			name           string
			system, public []net.IP
		}{
			// The v4 floor is the /16 allocation, not the announced /24:
			// comparing at /24 would split one operator's block in two.
			{
				"same v4 allocation, different /24",
				[]net.IP{net.ParseIP("142.250.9.94")},
				[]net.IP{net.ParseIP("142.250.189.99")},
			},
			{"same block, different hosts", []net.IP{ip1}, []net.IP{ip2}},
			{
				// The default probe host: Google anycast, observed answering
				// from a different /24 and /48 per resolver on every run.
				"gstatic anycast answers per resolver",
				[]net.IP{net.ParseIP("142.250.9.94"), net.ParseIP("2607:f8b0:4002:c00::5e")},
				[]net.IP{net.ParseIP("142.250.189.99"), net.ParseIP("2607:f8b0:4009:80c::2003")},
			},
			{
				"github round-robin within one /24",
				[]net.IP{net.ParseIP("140.82.114.3")},
				[]net.IP{net.ParseIP("140.82.114.4")},
			},
			{
				"v4 differs, v6 allocation shared",
				[]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8:1::5e")},
				[]net.IP{net.ParseIP("198.51.100.9"), net.ParseIP("2001:db8:9::2003")},
			},
			{
				"one of several addresses overlaps",
				[]net.IP{net.ParseIP("198.51.100.1"), ip1},
				[]net.IP{ip2},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				res := map[ProbeID]ProbeResult{
					ProbeDNS:       {Status: StatusPass, Addrs: tc.system},
					ProbeDNSPublic: {Status: StatusPass, Addrs: tc.public},
				}
				reconcileDNS(res)
				if res[ProbeDNSPublic].Status != StatusPass {
					t.Fatalf("public result = %+v, want shared routing prefix to pass", res[ProbeDNSPublic])
				}
			})
		}
	})
	// Split DNS proper: an internal answer against a public one.
	t.Run("disjoint allocations warn", func(t *testing.T) {
		for _, tc := range []struct {
			name           string
			system, public []net.IP
		}{
			{"private against public", []net.IP{net.ParseIP("10.1.2.3")}, []net.IP{ip1}},
			{
				// Both sides sit in 172.0.0.0/8, so only a comparison no
				// coarser than /16 sees an RFC 1918 answer standing against
				// a Google one.
				"same v4 /8, different allocation",
				[]net.IP{net.ParseIP("172.16.5.10")},
				[]net.IP{net.ParseIP("172.217.14.206")},
			},
			{
				// Both sides sit in 2001::/16, so only a comparison no
				// coarser than /32 separates the documentation block from
				// Google's allocation.
				"same v6 /16, different allocation",
				[]net.IP{net.ParseIP("2001:db8:1::5e")},
				[]net.IP{net.ParseIP("2001:4860:4860::8888")},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				res := map[ProbeID]ProbeResult{
					ProbeDNS:       {Status: StatusPass, Addrs: tc.system},
					ProbeDNSPublic: {Status: StatusPass, Addrs: tc.public},
				}
				reconcileDNS(res)
				if res[ProbeDNSPublic].Status != StatusWarn {
					t.Fatalf("public result = %+v, want disjoint allocations to warn", res[ProbeDNSPublic])
				}
			})
		}
	})
	t.Run("unavailable public resolver is neutral", func(t *testing.T) {
		res := map[ProbeID]ProbeResult{
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{ip1}},
			ProbeDNSPublic: {Status: StatusNA},
		}
		reconcileDNS(res)
		order := []ProbeID{ProbeDNS, ProbeDNSPublic}
		if _, verdict := Diagnose(nil, order, res); verdict != VerdictOK {
			t.Fatalf("verdict = %q, want public N/A to be neutral", verdict)
		}
	})
	t.Run("comparison prefixes describe what answersAgree compared", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			ips  []net.IP
			want string
		}{
			{"single v4", []net.IP{net.ParseIP("172.217.14.206")}, "172.217.0.0/16"},
			{"several v4 share one /16", []net.IP{net.ParseIP("142.250.9.94"), net.ParseIP("142.250.189.99")}, "142.250.0.0/16"},
			{"sorted across v4 and v6", []net.IP{net.ParseIP("2607:f8b0:4009::1"), net.ParseIP("142.250.9.94")}, "142.250.0.0/16, 2607:f8b0::/32"},
			{"mixed v6 prefixes", []net.IP{net.ParseIP("2001:4860:4860::8888"), net.ParseIP("2001:db8:1::5e")}, "2001:4860::/32, 2001:db8::/32"},
			{"empty input", nil, "no comparison prefix"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := comparisonPrefixes(tc.ips); got != tc.want {
					t.Fatalf("comparisonPrefixes = %q, want %q", got, tc.want)
				}
			})
		}
	})
}

func TestDiagnoseSecondOpinionDNS(t *testing.T) {
	tg := mustTarget(t, "example.com")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic, ProbeTargetTCP, ProbeTLS, ProbeHTTP, ProbeHTTPS}
	base := map[ProbeID]ProbeResult{
		ProbeIface:     {Status: StatusPass},
		ProbeInternet:  {Status: StatusPass},
		ProbeTargetTCP: {Status: StatusPass},
		ProbeTLS:       {Status: StatusPass},
		ProbeHTTP:      {Status: StatusPass},
		ProbeHTTPS:     {Status: StatusPass},
	}
	for _, tc := range []struct {
		name    string
		system  ProbeResult
		public  ProbeResult
		want    string
		verdict string
	}{
		{
			"system resolver broken",
			ProbeResult{Status: StatusFail},
			ProbeResult{Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.1")}},
			"public DNS can",
			VerdictDNS,
		},
		{
			"name does not exist",
			ProbeResult{Status: StatusFail, DNSNotFound: true},
			ProbeResult{Status: StatusPass, DNSNotFound: true},
			"no A/AAAA records according to either",
			VerdictDNS,
		},
		{
			"split DNS warning",
			ProbeResult{Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.1")}},
			ProbeResult{Status: StatusPass, Addrs: []net.IP{net.ParseIP("198.51.100.2")}},
			"system DNS and public DNS disagree",
			VerdictDegraded,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := make(map[ProbeID]ProbeResult, len(base)+2)
			for id, r := range base {
				res[id] = r
			}
			res[ProbeDNS], res[ProbeDNSPublic] = tc.system, tc.public
			reconcileDNS(res)
			summary, verdict := Diagnose(tg, order, res)
			if verdict != tc.verdict || !strings.Contains(summary, tc.want) {
				t.Fatalf("Diagnose = (%q, %q), want %q and %q", summary, verdict, tc.want, tc.verdict)
			}
		})
	}
}

// A device on the same network is not reached through the internet, so the
// egress rung must not be what explains a failure to reach it. Each case is a
// state a person hits with a printer or a NAS that stopped answering.
func TestDiagnoseLocalDeviceTargetTCPFailure(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS, ProbeTargetTCP}
	cases := []struct {
		name        string
		target      string
		internet    Status
		cause       string
		omit        []ProbeID
		want        string
		wantVerdict string
	}{
		{
			// The device answered with a reset, so it is demonstrably there.
			name: "refused with the internet up", target: "192.168.1.23:631",
			internet: StatusPass, cause: ConnectionCauseRefused,
			want: "the device is on the network, but nothing is listening on that port", wantVerdict: VerdictService,
		},
		{
			// Still a complete answer with no internet at all: reaching the
			// device never needed egress in the first place.
			name: "refused with the internet down", target: "192.168.1.23:631",
			internet: StatusFail, cause: ConnectionCauseRefused,
			want: "the device is on the network, but nothing is listening on that port", wantVerdict: VerdictService,
		},
		{
			name: "silent with the internet up", target: "192.168.1.23:9100",
			internet: StatusPass,
			want:     "did not answer, though this machine's network is working", wantVerdict: VerdictService,
		},
		{
			// The device and the egress check's reference endpoints were both
			// silent, and nothing observed which end of the path is at fault.
			name: "silent with the reference endpoints down", target: "192.168.1.23:9100",
			internet: StatusFail,
			want:     "nothing this run observed says whether the break is on this machine", wantVerdict: VerdictNetwork,
		},
		{
			name: "silent with egress unchecked", target: "192.168.1.23:9100",
			omit: []ProbeID{ProbeInternet},
			want: "this machine's own network was not checked", wantVerdict: VerdictNetwork,
		},
		{
			name: "loopback counts as local", target: "127.0.0.1:8080",
			internet: StatusFail, cause: ConnectionCauseRefused,
			want: "the device is on the network, but nothing is listening on that port", wantVerdict: VerdictService,
		},
		{
			// A public literal keeps the internet-facing reading it always had.
			name: "a public address is not a local device", target: "93.184.216.34:443",
			internet: StatusPass, cause: ConnectionCauseRefused,
			want: "the service may not be listening", wantVerdict: VerdictService,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tg := mustTarget(t, c.target)
			res := map[ProbeID]ProbeResult{
				ProbeIface:     {Status: StatusPass},
				ProbeInternet:  {Status: c.internet},
				ProbeProxy:     {Status: StatusNA},
				ProbeDNS:       {Status: StatusNA, Addrs: []net.IP{tg.IP}},
				ProbeTargetTCP: {Status: StatusFail, Cause: c.cause},
			}
			ids := order
			for _, drop := range c.omit {
				delete(res, drop)
				ids = slices.DeleteFunc(slices.Clone(ids), func(id ProbeID) bool { return id == drop })
			}
			summary, verdict := Diagnose(tg, ids, res)
			if !strings.Contains(summary, c.want) {
				t.Errorf("summary = %q, want substring %q", summary, c.want)
			}
			if verdict != c.wantVerdict {
				t.Errorf("verdict = %q, want %q", verdict, c.wantVerdict)
			}
			// Whatever else it says, a local device's failure is never
			// explained by the state of the route to the internet.
			if strings.Contains(summary, "general internet") || strings.Contains(summary, "proxy-only") {
				t.Errorf("summary = %q, which explains a local device by the internet path", summary)
			}
		})
	}
}

// A name resolves the question the same way a literal does, so the CLI target
// nas.lan:445 gets the local reading its address earns.
func TestDiagnoseLocalTargetFollowsResolvedAddresses(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}
	cases := []struct {
		name  string
		addrs []net.IP
		want  string
	}{
		{"every address is local", []net.IP{net.ParseIP("192.168.1.9")}, "did not answer, though this machine's network is working"},
		{"a public address among them keeps the internet reading", []net.IP{net.ParseIP("192.168.1.9"), net.ParseIP("93.184.216.34")}, "unreachable though DNS and the general internet work"},
		{"no addresses at all", nil, "unreachable though DNS and the general internet work"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				ProbeIface:     {Status: StatusPass},
				ProbeInternet:  {Status: StatusPass},
				ProbeDNS:       {Status: StatusPass, Addrs: c.addrs},
				ProbeTargetTCP: {Status: StatusFail},
			}
			if v, _ := Diagnose(mustTarget(t, "nas.lan:445"), order, res); !strings.Contains(v, c.want) {
				t.Errorf("summary = %q, want substring %q", v, c.want)
			}
		})
	}
}

// A default second opinion that had to change address family is still a second
// opinion, and the run has to spend it as one. The IPv4 candidate being
// unreachable is a fact about that resolver, not about DNS: the row that
// answered agrees with the system resolver, so nothing here is degraded and
// nothing blames DNS. Before the default could change family this run had no
// public row at all and reached the same verdict for a worse reason.
func TestIPv6OnlyDefaultSecondOpinionDoesNotReadAsDNSTrouble(t *testing.T) {
	tg := mustTarget(t, "example.com")
	answer := net.ParseIP("192.0.2.9")
	ops := &netops{lookupPublicIP: func(_ context.Context, _, server string) ([]net.IP, []string, error) {
		if server == publicDNSServer("8.8.8.8") {
			return nil, []string{server}, errors.New("connect: network is unreachable")
		}
		return []net.IP{answer}, []string{server}, nil
	}}
	public := ops.publicDNSProbe("example.com", nil, PublicDNSCandidates(DefaultPublicDNS, true))(context.Background(), nil)

	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic, ProbeTargetTCP}
	res := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{answer}},
		ProbeDNSPublic: public,
		ProbeTargetTCP: {Status: StatusPass},
	}
	reconcileDNS(res)
	if got := res[ProbeDNSPublic]; got.Status != StatusPass || got.resolver != "2001:4860:4860::8888" {
		t.Fatalf("public row = %+v, want a pass credited to the resolver that answered", got)
	}
	summary, verdict := Diagnose(tg, order, res)
	if verdict != VerdictOK {
		t.Errorf("verdict = %q (%q), want %q: one unreachable resolver is not a DNS problem", verdict, summary, VerdictOK)
	}
	if strings.Contains(summary, "DNS") {
		t.Errorf("summary = %q, want no DNS claim", summary)
	}
}
