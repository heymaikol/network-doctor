// The failure banner's remediation block: the verdict line, the "Fix:" line,
// and the "Next: press ..." drill-down hint, plus the rule that all of them
// describe one row: the first failing probe in probe order, unless the
// diagnosis blames a row of its own.

package ui

import (
	"maps"
	"net"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// TestBannerFailureGuidance pins the whole failure banner for several result
// maps. It is deliberately an exact comparison of a three-line block, not a
// full-screen snapshot: these three lines are the entire remediation contract,
// and a substring check for "Fix:" would let the wrong advice through.
//
// Ordering matters because several rungs fail together in every real outage:
// the first failing probe is the cause and the ones below it are symptoms, so
// remediation taken from the last failure contradicts the verdict above it.
//
// The one exception to "everything follows the first failure" is a verdict that
// names a row of its own: the path MTU black hole fails TLS first but blames
// the Path MTU row, so both remediation lines come from there instead. They
// move together, because a "Fix:" about one row above a "Next:" about another
// sends the reader two ways at once. Cases 4 and 5 are the same rows with and
// without the TLS timeout that turns the first into the second.
func TestBannerFailureGuidance(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(bin string) (string, error) { return bin, nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	fail := func(fix string) diagnostic.ProbeResult {
		return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Fix: fix}
	}
	// A handshake that ran out of time rather than failing outright. It is the
	// half of the black-hole correlation the protocol rows contribute.
	stalled := func(fix string) diagnostic.ProbeResult {
		return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Fix: fix, Cause: diagnostic.TLSCauseTimeout}
	}
	// Fix strings are the real ones the probes emit, so a case reads like a
	// screen a user would actually see.
	const (
		egressFix = "no default route: nothing in the routing table leads off this network, check DHCP, the VPN, or a static route"
		proxyFix  = "proxy configured but unreachable: check HTTPS_PROXY/HTTP_PROXY/ALL_PROXY and the proxy host"
		dnsFix    = "name resolution failing: check /etc/resolv.conf / DNS"
		tcpFix    = "port 443 blocked/refused: firewall, wrong network, or VPN routing?"
		tlsFix    = "TLS timed out after TCP connected; read the Path MTU row: it says whether full-size packets are reaching the far end (VPN, PPPoE, or tunnel)"
		httpFix   = "HTTP blocked: proxy or firewall?"
		httpsFix  = "HTTPS blocked: proxy or firewall?"
		pmtuFix   = "bulk TCP stalled after the handshake; if lowering MTU makes it drain, lower the interface MTU"
	)

	tests := []struct {
		name string
		// results overrides the all-pass baseline; every other probe passes.
		results map[diagnostic.ProbeID]diagnostic.ProbeResult
		want    string
	}{
		{
			name: "egress alone fails",
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeInternet: fail(egressFix),
				// The address that answered is what makes the sentence below
				// true: the endpoint check left this network and arrived.
				diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusPass, SelectedIP: net.ParseIP("93.184.216.34")},
			},
			// Degraded: the target works, so the banner warns rather than
			// painting a red failure over a sentence that says so. The
			// remediation block is unchanged by that.
			want: "! The target answered a direct connection, so direct egress works; the egress check's own fixed reference endpoints are what did not answer.\n" +
				"  Fix: " + egressFix + "\n" +
				"  Next: press p for ping the host (ping)",
		},
		{
			name: "egress fails and every rung below it fails too",
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeInternet:  {Status: diagnostic.StatusFail, Fix: egressFix, Cause: diagnostic.RouteCauseNoDefaultRoute},
				diagnostic.ProbeProxy:     fail(proxyFix),
				diagnostic.ProbeTargetTCP: fail(tcpFix),
				diagnostic.ProbeTLS:       fail(tlsFix),
				diagnostic.ProbeHTTP:      fail(httpFix),
				diagnostic.ProbeHTTPS:     fail(httpsFix),
			},
			want: "✗ example.com resolves but neither it nor the egress check's reference endpoints are reachable, and this machine's own routing state says why: local egress problem.\n" +
				"  Fix: " + egressFix + "\n" +
				"  Next: press p for ping the host (ping)",
		},
		{
			name: "resolver fails and the target rungs fail behind it",
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeDNS:       fail(dnsFix),
				diagnostic.ProbeTargetTCP: fail(tcpFix),
				diagnostic.ProbeTLS:       fail(tlsFix),
				diagnostic.ProbeHTTP:      fail(httpFix),
				diagnostic.ProbeHTTPS:     fail(httpsFix),
			},
			want: "✗ Cannot resolve example.com: DNS failure. (The general internet is reachable.)\n" +
				"  Fix: " + dnsFix + "\n" +
				"  Next: press d for DNS lookup (dig)",
		},
		{
			name: "protocol rows stall behind a path MTU warning",
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbePMTU:  {Status: diagnostic.StatusWarn, Fix: pmtuFix},
				diagnostic.ProbeTLS:   fail(tlsFix),
				diagnostic.ProbeHTTP:  fail(httpFix),
				diagnostic.ProbeHTTPS: fail(httpsFix),
			},
			want: "✗ TCP reaches example.com:443 but the TLS handshake fails: bad/expired cert, clock skew, or MITM proxy.\n" +
				"  Fix: " + tlsFix + "\n" +
				"  Next: press c for web check (curl)",
		},
		{
			name: "protocol rows stall behind a path MTU warning and TLS times out",
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbePMTU:  {Status: diagnostic.StatusWarn, Fix: pmtuFix},
				diagnostic.ProbeTLS:   stalled(tlsFix),
				diagnostic.ProbeHTTP:  fail(httpFix),
				diagnostic.ProbeHTTPS: fail(httpsFix),
			},
			want: "✗ TCP reaches example.com:443 but the protocol and bulk-transfer checks both stall, which is evidence of a path MTU black hole rather than a broken service (see the Path MTU row).\n" +
				"  Fix: " + pmtuFix + "\n" +
				"  Next: press t for trace the path (traceroute)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tgt := mustTarget(t, "example.com:443")
			m := newModel(tgt, false)
			// One fixed GOOS table keeps the "Next:" label identical wherever
			// the suite runs; the per-GOOS tables themselves are pinned by
			// TestToolsForDefinitions.
			m.tools = toolsFor(tgt, "linux", toolBind{})
			for _, p := range m.probes {
				r, ok := tt.results[p.ID]
				if !ok {
					r = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
				}
				r.ID = p.ID
				m.results[p.ID] = r
			}
			if got := m.banner(); got != tt.want {
				t.Errorf("banner() =\n%s\n\nwant\n%s", got, tt.want)
			}
		})
	}
}

// TestProbeNextTool pins the whole failure-to-hotkey table. The keys are frozen
// user-visible bindings, and Path MTU in particular must reach for the path
// tools rather than curl, which stalls for the same reason the probe rows did.
func TestProbeNextTool(t *testing.T) {
	want := map[diagnostic.ProbeID]string{
		diagnostic.ProbeInternet:  "p",
		diagnostic.ProbeDNS:       "d",
		diagnostic.ProbeTargetTCP: "t",
		diagnostic.ProbePMTU:      "t",
		diagnostic.ProbeTLS:       "c",
		diagnostic.ProbeHTTP:      "c",
		diagnostic.ProbeHTTPS:     "c",
		diagnostic.ProbeSSH:       "t",
		diagnostic.ProbeSMTP:      "t",
	}
	if !maps.Equal(probeNextTool, want) {
		t.Errorf("probeNextTool = %v, want %v", probeNextTool, want)
	}
}

// TestBannerSeverityFollowsVerdict pins the cross-component invariant the
// banner and the report verdict line share: the diagnosis verdict decides the
// severity, not the presence of a failed probe row. Degraded diagnoses that
// carry a FAIL row are shipped behavior, asserted by the
// quic-udp-443-blocked and encrypted-dns-blocked scenarios, and the two
// presentations must not contradict the sentence they print.
//
// The exit code is asserted alongside them because it deliberately does NOT
// follow the verdict: README documents "any failed row" as exit 1, and
// separating presentation severity from exit status is the point, not an
// oversight.
func TestBannerSeverityFollowsVerdict(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(bin string) (string, error) { return bin, nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	const quicFix = "UDP/443 blocked: applications fall back to TCP"

	tests := []struct {
		name    string
		results map[diagnostic.ProbeID]diagnostic.ProbeResult
		// failRow is the probe that must still read FAIL in its own row.
		failRow     diagnostic.ProbeID
		wantVerdict string
		wantGlyph   string
		wantPrefix  string
		wantFix     string
		wantExit    int
	}{
		{
			name:        "everything passes",
			wantVerdict: diagnostic.VerdictOK,
			wantGlyph:   "✓",
			wantPrefix:  "PASS: ",
			wantExit:    0,
		},
		{
			name: "quic blocked with usable TCP fallback",
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeQUIC: {Status: diagnostic.StatusFail, Fix: quicFix},
			},
			failRow:     diagnostic.ProbeQUIC,
			wantVerdict: diagnostic.VerdictDegraded,
			wantGlyph:   "!",
			wantPrefix:  "WARN: ",
			wantFix:     quicFix,
			wantExit:    1,
		},
		{
			name: "encrypted DNS blocked while plain DNS resolves",
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeDNSEncrypted: {Status: diagnostic.StatusFail},
			},
			failRow:     diagnostic.ProbeDNSEncrypted,
			wantVerdict: diagnostic.VerdictDegraded,
			wantGlyph:   "!",
			wantPrefix:  "WARN: ",
			wantExit:    1,
		},
		{
			name: "the name does not resolve",
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeDNS: {Status: diagnostic.StatusFail},
			},
			failRow:     diagnostic.ProbeDNS,
			wantVerdict: diagnostic.VerdictDNS,
			wantGlyph:   "✗",
			wantPrefix:  "FAIL: ",
			wantExit:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tgt := mustTarget(t, "example.com:443")
			m := newModel(tgt, false)
			m.tools = toolsFor(tgt, "linux", toolBind{})
			order := make([]diagnostic.ProbeID, len(m.probes))
			for i, p := range m.probes {
				order[i] = p.ID
				r, ok := tt.results[p.ID]
				if !ok {
					r = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
				}
				r.ID = p.ID
				m.results[p.ID] = r
			}
			summary, verdict := m.diagnose(order)
			if verdict != tt.wantVerdict {
				t.Fatalf("verdict = %q, want %q (summary %q)", verdict, tt.wantVerdict, summary)
			}
			if tt.failRow != "" && m.results[tt.failRow].Status != diagnostic.StatusFail {
				t.Fatalf("%s row = %v, want FAIL", tt.failRow, m.results[tt.failRow].Status)
			}
			banner := m.banner()
			if want := tt.wantGlyph + " " + summary; !strings.HasPrefix(banner, want) {
				t.Errorf("banner =\n%s\nwant it to start with\n%s", banner, want)
			}
			if line := m.verdictLine(); line != tt.wantPrefix+summary {
				t.Errorf("verdictLine = %q, want %q", line, tt.wantPrefix+summary)
			}
			// A degraded diagnosis must not cost the reader the remediation
			// the failing row carries.
			if tt.wantFix != "" && !strings.Contains(banner, "Fix: "+tt.wantFix) {
				t.Errorf("banner lost the fix for the failing row:\n%s", banner)
			}
			if got := ExitCode(m); got != tt.wantExit {
				t.Errorf("ExitCode = %d, want %d", got, tt.wantExit)
			}
		})
	}
}

// Fix strings the probes really emit. The black hole is the case where the
// diagnosis blames a row other than the first failing one: TCP connects, the
// Path MTU row warns about a bulk stall, and TLS, HTTP and HTTPS all time out
// behind it. TLS is the first FAIL in probe order; Path MTU is what the
// verdict names.
const (
	blackHolePMTUFix = "bulk TCP stalled after the handshake; if lowering MTU makes it drain, lower the interface MTU"
	blackHoleTLSFix  = "TLS timed out after TCP connected; read the Path MTU row: it says whether full-size packets are reaching the far end (VPN, PPPoE, or tunnel)"
	blackHoleHTTPFix = "HTTP blocked: proxy or firewall?"
)

// blackHoleModel is a finished run whose verdict blames the Path MTU row.
func blackHoleModel(t *testing.T) model {
	t.Helper()
	oldLookPath := toolLookPath
	toolLookPath = func(bin string) (string, error) { return bin, nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	tgt := mustTarget(t, "example.com:443")
	m := newModel(tgt, false)
	// One fixed GOOS table keeps the "Next:" label identical wherever the
	// suite runs.
	m.tools = toolsFor(tgt, "linux", toolBind{})
	stalls := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbePMTU:  {Status: diagnostic.StatusWarn, Fix: blackHolePMTUFix},
		diagnostic.ProbeTLS:   {Status: diagnostic.StatusFail, Fix: blackHoleTLSFix, Cause: diagnostic.TLSCauseTimeout},
		diagnostic.ProbeHTTP:  {Status: diagnostic.StatusFail, Fix: blackHoleHTTPFix},
		diagnostic.ProbeHTTPS: {Status: diagnostic.StatusFail, Fix: blackHoleHTTPFix},
	}
	for _, p := range m.probes {
		r, ok := stalls[p.ID]
		if !ok {
			r = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
		}
		r.ID = p.ID
		m.results[p.ID] = r
	}
	return m
}

// TestBannerActionFollowsBlamedRowNotFirstFailure is the contract the two
// remediation lines share. The first failing row is TLS and its own hint just
// forwards the reader to the Path MTU row, so taking "Fix:" from it costs the
// reader the one line that says what to actually change.
func TestBannerActionFollowsBlamedRowNotFirstFailure(t *testing.T) {
	m := blackHoleModel(t)

	firstFail := diagnostic.ProbeID("")
	for _, p := range m.probes {
		if m.results[p.ID].Status == diagnostic.StatusFail {
			firstFail = p.ID
			break
		}
	}
	if firstFail != diagnostic.ProbeTLS {
		t.Fatalf("first failing row = %q, want the TLS row: the case no longer separates the two candidates", firstFail)
	}
	blamed := m.diagnosis().Focus()
	if blamed != diagnostic.ProbePMTU {
		t.Fatalf("diagnosis blames %q, want the Path MTU row", blamed)
	}

	banner := m.banner()
	if !strings.Contains(banner, "Fix: "+blackHolePMTUFix) {
		t.Errorf("Fix: must come from the blamed row:\n%s", banner)
	}
	if strings.Contains(banner, blackHoleTLSFix) {
		t.Errorf("Fix: still follows the first failing row:\n%s", banner)
	}
	if !strings.Contains(banner, "Next: press t for trace the path (traceroute)") {
		t.Errorf("Next: must come from the blamed row:\n%s", banner)
	}
}
