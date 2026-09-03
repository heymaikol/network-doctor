// The whole diagnosis matrix in one table: every arm the interpretation pass
// can return, with the exact sentence, the broad verdict, and the row it
// blames. Existing diagnosis tests assert substrings of individual branches;
// this one pins the complete set of outcomes byte for byte, so a refactor of
// the pass cannot quietly reword, reclassify, or reblame any of them.
//
// It is also the coverage list for the stable diagnosis IDs: every ID declared
// in the package has to be produced by at least one row here, which is what
// stops an ID from being added without a condition that reaches it.

package diagnostic

import (
	"errors"
	"go/ast"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// matrixCase is one complete run handed to the pass: the probes the run asked
// for, what each of them reported, and everything the pass must say about it.
type matrixCase struct {
	name    string
	target  *Target
	order   []ProbeID
	res     map[ProbeID]ProbeResult
	summary string
	verdict string
	focus   ProbeID
	// id is the stable diagnosis identity the arm must produce, pinned as the
	// published string rather than the constant so a renamed value fails here.
	// Empty for the arms that deliberately produce no finding.
	id DiagnosisID
	// evidence is the supporting rows, focus first.
	evidence []ProbeID
}

// ok is a probe row that reported nothing but its status, which is most rows
// in most of these runs: the arm under test is the one or two that carry more.
func ok(s Status) ProbeResult { return ProbeResult{Status: s} }

// disagreed is the independent DNS row as reconcileDNS leaves it when the two
// resolvers answered from different allocations: warned, carrying the answers
// it compared, and carrying the outcome of that comparison. The recorded
// outcome is part of the state, not decoration: it is the only form of the
// comparison that survives into a sanitized artifact.
func disagreed(addrs ...net.IP) ProbeResult {
	return ProbeResult{Status: StatusWarn, Addrs: addrs, answerComparison: comparisonDisagree}
}

func diagnosisMatrix() []matrixCase {
	tls := &Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	local := &Target{Host: "192.168.1.10", IP: net.ParseIP("192.168.1.10"), Port: 9100, Proto: ProtoNone}
	httpOnly := &Target{Host: "example.com", Port: 80, Proto: ProtoHTTP}
	ssh := &Target{Host: "example.com", Port: 22, Proto: ProtoSSH}
	tcp := &Target{Host: "example.com", Port: 443, Proto: ProtoNone}

	webOrder := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbePMTU, ProbeTLS, ProbeHTTP, ProbeHTTPS}
	webHealthy := func() map[ProbeID]ProbeResult {
		return map[ProbeID]ProbeResult{
			ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusPass),
			ProbeTargetTCP: ok(StatusPass), ProbePMTU: ok(StatusPass), ProbeTLS: ok(StatusPass),
			ProbeHTTP: ok(StatusPass), ProbeHTTPS: ok(StatusPass),
		}
	}
	// with returns the healthy web run with some rows replaced, which is how
	// every targeted arm below is built.
	with := func(over map[ProbeID]ProbeResult) map[ProbeID]ProbeResult {
		res := webHealthy()
		for id, r := range over {
			res[id] = r
		}
		return res
	}

	return []matrixCase{
		{
			name: "no checks selected", order: nil, res: map[ProbeID]ProbeResult{},
			summary: "No checks selected.", verdict: VerdictOK,
		},
		{
			name: "still running", order: []ProbeID{ProbeIface, ProbeInternet}, res: map[ProbeID]ProbeResult{ProbeIface: ok(StatusPass)},
			summary: "Running diagnostics…", verdict: VerdictIncomplete,
		},
		{
			name: "link down", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusFail), ProbeInternet: ok(StatusFail), ProbeDNS: ok(StatusFail),
			},
			summary: "No usable network interface: the link is down.", verdict: VerdictNetwork, focus: ProbeIface,
			id: "no_usable_interface", evidence: []ProbeID{ProbeIface},
		},

		// ---- generic mode ----
		{
			name: "generic captive portal", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: {Status: StatusFail, Portal: &Portal{}}, ProbeDNS: ok(StatusPass),
			},
			summary: "Behind a captive portal: traffic is intercepted until you sign in to the network.",
			verdict: VerdictNetwork, focus: ProbeInternet,
			id: "captive_portal", evidence: []ProbeID{ProbeInternet},
		},
		{
			name: "generic system resolver failing", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusFail),
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}},
			},
			summary: "System DNS is failing, but public DNS resolves the name. Check the configured resolver, VPN, or DNS filter.",
			verdict: VerdictDNS, focus: ProbeDNS,
			id: "system_dns_failure", evidence: []ProbeID{ProbeDNS, ProbeDNSPublic, ProbeInternet},
		},
		{
			name: "generic name has no records", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass),
				ProbeDNS:       {Status: StatusFail, DNSNotFound: true},
				ProbeDNSPublic: {Status: StatusPass, DNSNotFound: true},
			},
			summary: "Internet egress works, but the DNS test name has no A/AAAA records according to either resolver.",
			verdict: VerdictDNS, focus: ProbeDNS,
			id: "dns_name_not_found", evidence: []ProbeID{ProbeDNS, ProbeDNSPublic, ProbeInternet},
		},
		{
			name: "generic QUIC blocked", order: []ProbeID{ProbeIface, ProbeInternet, ProbeQUIC, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeQUIC: ok(StatusFail), ProbeDNS: ok(StatusPass),
			},
			summary: "Direct TCP/443 works, but the QUIC handshake over UDP/443 failed. Applications can fall back to TCP, which may feel slower.",
			verdict: VerdictDegraded, focus: ProbeQUIC,
			id: "quic_unavailable", evidence: []ProbeID{ProbeQUIC, ProbeInternet},
		},
		{
			name: "generic encrypted DNS blocked", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSEncrypted},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusPass), ProbeDNSEncrypted: ok(StatusFail),
			},
			summary: encryptedDNSSummary, verdict: VerdictDegraded, focus: ProbeDNSEncrypted,
			id: "encrypted_dns_unavailable", evidence: []ProbeID{ProbeDNSEncrypted, ProbeDNS, ProbeInternet},
		},
		{
			name: "generic resolvers disagree", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic},
			// The rows a run reaches this arm with: reconcileDNS warned the
			// public row because two real answer sets landed in different
			// allocations, and recorded that conclusion on the row it warned.
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("203.0.113.9")}},
				ProbeDNSPublic: disagreed(net.ParseIP("198.51.100.20")),
			},
			summary: "Online, but system DNS and public DNS disagree; split DNS or filtering may be intentional (see the DNS rows).",
			verdict: VerdictDegraded, focus: ProbeDNSPublic,
			id: "dns_disagreement", evidence: []ProbeID{ProbeDNSPublic, ProbeDNS},
		},
		{
			name: "generic proxy failed", order: []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeProxy: ok(StatusFail), ProbeDNS: ok(StatusPass),
			},
			summary: "Online directly, but the configured environment proxy check failed, so apps that use the proxy will fail (see the proxy row).",
			verdict: VerdictDegraded, focus: ProbeProxy,
			id: "proxy_failure", evidence: []ProbeID{ProbeProxy, ProbeInternet, ProbeDNS},
		},
		{
			name: "generic online", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusPass),
			},
			summary: "Online: direct TCP egress and DNS both work.", verdict: VerdictOK,
		},
		{
			// Degraded with nothing specific to blame: the warning is on a row
			// no case is about, so the run is degraded and names no finding.
			name: "generic online with an unrelated warning", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusWarn), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusPass),
			},
			summary: "Online: direct TCP egress and DNS both work.", verdict: VerdictDegraded,
		},
		{
			name: "generic proxy-only network", order: []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: {Status: StatusWarn, downgraded: true},
				ProbeProxy: ok(StatusPass), ProbeDNS: ok(StatusPass),
			},
			summary: "Online via the environment proxy: direct egress is blocked (proxy-only network).",
			verdict: VerdictDegraded, focus: ProbeInternet,
			id: "proxy_only_network", evidence: []ProbeID{ProbeInternet, ProbeProxy, ProbeDNS},
		},
		{
			name: "generic proxy-only network with broken DNS", order: []ProbeID{ProbeIface, ProbeInternet, ProbeProxy, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: {Status: StatusWarn, downgraded: true},
				ProbeProxy: ok(StatusPass), ProbeDNS: ok(StatusFail),
			},
			summary: "Direct egress is blocked and DNS resolution is failing; only the environment proxy is carrying traffic.",
			verdict: VerdictNetwork, focus: ProbeDNS,
			id: "dns_failure", evidence: []ProbeID{ProbeDNS, ProbeInternet, ProbeProxy},
		},
		{
			name: "generic direct egress impaired", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusWarn), ProbeDNS: ok(StatusPass),
			},
			summary: "Online but degraded: direct egress is impaired (see the ! row for details).",
			verdict: VerdictDegraded, focus: ProbeInternet,
			id: "direct_egress_degraded", evidence: []ProbeID{ProbeInternet, ProbeDNS},
		},
		{
			name: "generic impaired egress with broken DNS", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusWarn), ProbeDNS: ok(StatusFail),
			},
			summary: "Internet egress works (degraded) but DNS resolution is failing.",
			verdict: VerdictDNS, focus: ProbeDNS,
			id: "dns_failure", evidence: []ProbeID{ProbeDNS, ProbeInternet},
		},
		{
			name: "generic egress works, DNS broken", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusFail),
			},
			summary: "Internet egress works but DNS resolution is failing.",
			verdict: VerdictDNS, focus: ProbeDNS,
			id: "dns_failure", evidence: []ProbeID{ProbeDNS, ProbeInternet},
		},
		{
			name: "generic no direct egress", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusFail), ProbeDNS: ok(StatusPass),
			},
			summary: "DNS resolves but there's no direct TCP egress to the egress check's reference endpoints (proxy-only or filtered network?).",
			verdict: VerdictNetwork, focus: ProbeInternet,
			id: "direct_egress_blocked", evidence: []ProbeID{ProbeInternet, ProbeDNS},
		},
		{
			name: "generic offline", order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusFail), ProbeDNS: ok(StatusFail),
			},
			summary: "Offline: neither DNS nor direct TCP to the egress check's reference endpoints is working.",
			verdict: VerdictNetwork, focus: ProbeInternet,
			id: "offline", evidence: []ProbeID{ProbeInternet, ProbeDNS},
		},

		// ---- selected-check fallbacks ----
		{
			name: "selected DNS check failed", order: []ProbeID{ProbeIface, ProbeDNS},
			res:     map[ProbeID]ProbeResult{ProbeIface: ok(StatusPass), ProbeDNS: ok(StatusFail)},
			summary: "A selected DNS check failed.", verdict: VerdictDNS, focus: ProbeDNS,
			id: "selected_dns_check_failed", evidence: []ProbeID{ProbeDNS},
		},
		{
			name: "selected service check failed", order: []ProbeID{ProbeIface, ProbeTLS},
			res:     map[ProbeID]ProbeResult{ProbeIface: ok(StatusPass), ProbeTLS: ok(StatusFail)},
			summary: "A selected service check failed.", verdict: VerdictService, focus: ProbeTLS,
			id: "selected_service_check_failed", evidence: []ProbeID{ProbeTLS},
		},
		{
			name: "selected network check failed", order: []ProbeID{ProbeIface, ProbeProxy},
			res:     map[ProbeID]ProbeResult{ProbeIface: ok(StatusPass), ProbeProxy: ok(StatusFail)},
			summary: "A selected network check failed.", verdict: VerdictNetwork, focus: ProbeProxy,
			id: "selected_network_check_failed", evidence: []ProbeID{ProbeProxy},
		},
		{
			name: "selected checks warned", order: []ProbeID{ProbeIface, ProbeProxy},
			res:     map[ProbeID]ProbeResult{ProbeIface: ok(StatusPass), ProbeProxy: ok(StatusWarn)},
			summary: "Selected checks completed with warnings.", verdict: VerdictDegraded,
		},
		{
			name: "selected checks passed", order: []ProbeID{ProbeIface, ProbeProxy},
			res:     map[ProbeID]ProbeResult{ProbeIface: ok(StatusPass), ProbeProxy: ok(StatusPass)},
			summary: "Selected checks passed.", verdict: VerdictOK,
		},

		// ---- targeted mode ----
		{
			name: "targeted captive portal", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeInternet: {Status: StatusFail, Portal: &Portal{}}}),
			summary: "Behind a captive portal: sign in to the network before trusting anything about example.com.",
			verdict: VerdictNetwork, focus: ProbeInternet,
			id: "captive_portal", evidence: []ProbeID{ProbeInternet},
		},
		{
			name: "targeted DNS failure", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeInternet: ok(StatusFail), ProbeDNS: ok(StatusFail)}),
			summary: "Cannot resolve example.com: DNS failure.",
			verdict: VerdictDNS, focus: ProbeDNS,
			id: "dns_failure", evidence: []ProbeID{ProbeDNS, ProbeInternet},
		},
		{
			name: "targeted DNS failure with working egress", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeDNS: ok(StatusFail)}),
			summary: "Cannot resolve example.com: DNS failure. (The general internet is reachable.)",
			verdict: VerdictDNS, focus: ProbeDNS,
			id: "dns_failure", evidence: []ProbeID{ProbeDNS, ProbeInternet},
		},
		{
			name: "targeted system resolver failing", target: tls, order: append(append([]ProbeID{}, webOrder...), ProbeDNSPublic),
			res: with(map[ProbeID]ProbeResult{
				ProbeDNS:       ok(StatusFail),
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}},
			}),
			summary: "System DNS cannot resolve example.com, but public DNS can, so the configured resolver is failing or filtering the name. (The general internet is reachable.)",
			verdict: VerdictDNS, focus: ProbeDNS,
			id: "system_dns_failure", evidence: []ProbeID{ProbeDNS, ProbeDNSPublic, ProbeInternet},
		},
		{
			name: "targeted name has no records", target: tls, order: append(append([]ProbeID{}, webOrder...), ProbeDNSPublic),
			res: with(map[ProbeID]ProbeResult{
				ProbeDNS:       {Status: StatusFail, DNSNotFound: true},
				ProbeDNSPublic: {Status: StatusPass, DNSNotFound: true},
			}),
			summary: "example.com has no A/AAAA records according to either system or public DNS. (The general internet is reachable.)",
			verdict: VerdictDNS, focus: ProbeDNS,
			id: "dns_name_not_found", evidence: []ProbeID{ProbeDNS, ProbeDNSPublic, ProbeInternet},
		},
		{
			name: "target reachable over IPv4 only", target: tcp,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface:    ok(StatusPass),
				ProbeInternet: {Status: StatusPass, Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyReachable}},
				ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}},
				ProbeTargetTCP: {Status: StatusWarn, SelectedIP: net.ParseIP("192.0.2.1"),
					Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyUnreachable}},
			},
			summary: "IPv6 connectivity to example.com is failing, but IPv4 works.",
			verdict: VerdictDegraded, focus: ProbeTargetTCP,
			id: "ipv6_target_unreachable", evidence: []ProbeID{ProbeTargetTCP, ProbeInternet},
		},
		{
			name: "target reachable over IPv6 only", target: tcp,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface:    ok(StatusPass),
				ProbeInternet: {Status: StatusPass, Families: &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyReachable}},
				ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}},
				ProbeTargetTCP: {Status: StatusWarn, SelectedIP: net.ParseIP("2001:db8::1"),
					Families: &FamilyConnectivity{IPv4: FamilyUnreachable, IPv6: FamilyReachable}},
			},
			summary: "IPv4 connectivity to example.com is failing, but IPv6 works.",
			verdict: VerdictDegraded, focus: ProbeTargetTCP,
			id: "ipv4_target_unreachable", evidence: []ProbeID{ProbeTargetTCP, ProbeInternet},
		},
		{
			name: "one target address fails before another succeeds", target: tcp,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass),
				ProbeDNS: {Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}},
				ProbeTargetTCP: {Status: StatusWarn, SelectedIP: net.ParseIP("192.0.2.2"),
					Families: &FamilyConnectivity{IPv4: FamilyReachable}, Attempts: []Attempt{
						{IP: net.ParseIP("192.0.2.1"), Err: errors.New("unreachable"), Cause: ConnectionCauseUnreachable},
						{IP: net.ParseIP("192.0.2.2")},
					}},
			},
			summary: "A connection to one address for example.com fails, but another succeeds.",
			verdict: VerdictDegraded, focus: ProbeTargetTCP,
			id: "partial_endpoint_reachability", evidence: []ProbeID{ProbeTargetTCP, ProbeDNS},
		},
		{
			name: "local device refuses the port", target: local,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusNA),
				ProbeTargetTCP: {Status: StatusFail, Cause: ConnectionCauseRefused},
			},
			summary: "Every TCP connection attempt to 192.168.1.10:9100 was explicitly refused: the device is on the network, but nothing is listening on that port.",
			verdict: VerdictService, focus: ProbeTargetTCP,
			id: "tcp_connection_refused", evidence: []ProbeID{ProbeTargetTCP},
		},
		{
			name: "local device silent while this machine works", target: local,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusNA), ProbeTargetTCP: ok(StatusFail),
			},
			summary: "192.168.1.10:9100 did not answer, though this machine's network is working: the device may be powered off or asleep, may have a different address now, or may be dropping the connection.",
			verdict: VerdictService, focus: ProbeTargetTCP,
			id: "local_device_unreachable", evidence: []ProbeID{ProbeTargetTCP, ProbeInternet},
		},
		{
			name: "local device silent with egress unchecked", target: local,
			order: []ProbeID{ProbeIface, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeDNS: ok(StatusNA), ProbeTargetTCP: ok(StatusFail),
			},
			summary: "192.168.1.10:9100 did not answer, and this machine's own network was not checked, so a problem here cannot be told apart from one on the device.",
			verdict: VerdictNetwork, focus: ProbeTargetTCP,
			id: "reachability_untested", evidence: []ProbeID{ProbeTargetTCP},
		},
		{
			name: "local device and reference endpoints both silent", target: local,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusFail), ProbeDNS: ok(StatusNA), ProbeTargetTCP: ok(StatusFail),
			},
			summary: "192.168.1.10:9100 did not answer, and neither did the egress check's reference endpoints; nothing this run observed says whether the break is on this machine, on the device, or between them.",
			verdict: VerdictNetwork, focus: ProbeInternet,
			id: "reachability_unlocalized", evidence: []ProbeID{ProbeInternet, ProbeTargetTCP},
		},
		{
			name: "local device silent and the routing table names the break", target: local,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: {Status: StatusFail, Cause: RouteCauseNoDefaultRoute},
				ProbeDNS: ok(StatusNA), ProbeTargetTCP: ok(StatusFail),
			},
			summary: "192.168.1.10:9100 did not answer, and neither did the egress check's reference endpoints; this machine's own routing state says why: fix this machine's own connection first.",
			verdict: VerdictNetwork, focus: ProbeInternet,
			id: "local_egress_failure", evidence: []ProbeID{ProbeInternet, ProbeTargetTCP},
		},
		{
			name: "target refuses the connection", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusFail, Cause: ConnectionCauseRefused}}),
			summary: "Every TCP connection attempt to example.com:443 was explicitly refused: the service may not be listening, or a firewall may be actively rejecting it.",
			verdict: VerdictService, focus: ProbeTargetTCP,
			id: "tcp_connection_refused", evidence: []ProbeID{ProbeTargetTCP, ProbeInternet},
		},
		{
			name: "target unreachable while the internet works", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeTargetTCP: ok(StatusFail)}),
			summary: "example.com:443 is unreachable though DNS and the general internet work: remote port closed, firewall, or VPN routing.",
			verdict: VerdictService, focus: ProbeTargetTCP,
			id: "target_unreachable", evidence: []ProbeID{ProbeTargetTCP, ProbeInternet, ProbeDNS},
		},
		{
			name: "target reachable only through the proxy", target: tls,
			order: append([]ProbeID{ProbeProxy}, webOrder...),
			res: with(map[ProbeID]ProbeResult{
				ProbeInternet: ok(StatusFail), ProbeProxy: ok(StatusPass), ProbeTargetTCP: ok(StatusFail),
			}),
			summary: "example.com:443 is unreachable directly, but the environment proxy has egress: this is a proxy-only network, so route traffic through the proxy.",
			verdict: VerdictNetwork, focus: ProbeTargetTCP,
			id: "proxy_only_network", evidence: []ProbeID{ProbeTargetTCP, ProbeProxy, ProbeInternet},
		},
		{
			name: "target unreachable with egress unchecked", target: tls,
			order: []ProbeID{ProbeIface, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeDNS: ok(StatusPass), ProbeTargetTCP: ok(StatusFail),
			},
			summary: "example.com:443 is unreachable, but general internet reachability was not checked, so a local path problem cannot be told apart from a remote service failure.",
			verdict: VerdictNetwork, focus: ProbeTargetTCP,
			id: "reachability_untested", evidence: []ProbeID{ProbeTargetTCP},
		},
		{
			name: "target and reference endpoints both unreachable", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeInternet: ok(StatusFail), ProbeTargetTCP: ok(StatusFail)}),
			summary: "example.com resolves but neither it nor the egress check's reference endpoints answered, and nothing this run observed says where the path breaks.",
			verdict: VerdictNetwork, focus: ProbeInternet,
			id: "reachability_unlocalized", evidence: []ProbeID{ProbeInternet, ProbeTargetTCP, ProbeDNS},
		},
		{
			name: "target unreachable and the routing table names the break", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeInternet:  {Status: StatusFail, Cause: RouteCauseNoDefaultRoute},
				ProbeTargetTCP: ok(StatusFail),
			}),
			summary: "example.com resolves but neither it nor the egress check's reference endpoints are reachable, and this machine's own routing state says why: local egress problem.",
			verdict: VerdictNetwork, focus: ProbeInternet,
			id: "local_egress_failure", evidence: []ProbeID{ProbeInternet, ProbeTargetTCP, ProbeDNS},
		},
		{
			name: "path MTU black hole", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbePMTU:  ok(StatusWarn),
				ProbeTLS:   {Status: StatusFail, Cause: TLSCauseTimeout},
				ProbeHTTPS: {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the protocol and bulk-transfer checks both stall, which is evidence of a path MTU black hole rather than a broken service (see the Path MTU row).",
			verdict: VerdictNetwork, focus: ProbePMTU,
			id: "probable_path_mtu_problem", evidence: []ProbeID{ProbePMTU, ProbeTargetTCP, ProbeTLS},
		},
		{
			name: "TLS handshake failure", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeTLS: {Status: StatusFail, Cause: TLSCauseHandshake}, ProbeHTTPS: {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the TLS handshake fails: bad/expired cert, clock skew, or MITM proxy.",
			verdict: VerdictService, focus: ProbeTLS,
			id: "tls_handshake_failure", evidence: []ProbeID{ProbeTLS, ProbeTargetTCP},
		},
		{
			name: "TLS expiry explained by a fast clock", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeInternet: {Status: StatusPass, clockOffset: 2 * 60 * 60 * 1e9},
				ProbeTLS:      {Status: StatusFail, Cause: TLSCauseCertificateExpired},
				ProbeHTTPS:    {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the TLS handshake fails because this machine's clock is about 2 hours fast, so certificates that are still valid look expired.",
			verdict: VerdictService, focus: ProbeTLS,
			id: "tls_clock_skew", evidence: []ProbeID{ProbeTLS, ProbeInternet, ProbeTargetTCP},
		},
		{
			name: "TLS expiry with the clock ruled out", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeInternet: {Status: StatusPass, clockOffset: -2 * 60 * 60 * 1e9},
				ProbeTLS:      {Status: StatusFail, Cause: TLSCauseCertificateExpired},
				ProbeHTTPS:    {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the TLS handshake fails: bad/expired cert or MITM proxy.",
			verdict: VerdictService, focus: ProbeTLS,
			id: "tls_certificate_expired", evidence: []ProbeID{ProbeTLS, ProbeInternet, ProbeTargetTCP},
		},
		{
			name: "TLS hostname mismatch", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeTLS: {Status: StatusFail, Cause: TLSCauseHostnameMismatch}, ProbeHTTPS: {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the TLS handshake fails: bad/expired cert, clock skew, or MITM proxy.",
			verdict: VerdictService, focus: ProbeTLS,
			id: "tls_hostname_mismatch", evidence: []ProbeID{ProbeTLS, ProbeTargetTCP},
		},
		{
			// The remaining handshake causes keep the same hedged sentence and
			// separate only by identity, which is the whole point of having
			// one: the prose cannot promise what the handshake did not prove,
			// and the ID can say what it did.
			name: "TLS certificate not yet valid", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeTLS: {Status: StatusFail, Cause: TLSCauseCertificateNotYet}, ProbeHTTPS: {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the TLS handshake fails: bad/expired cert, clock skew, or MITM proxy.",
			verdict: VerdictService, focus: ProbeTLS,
			id: "tls_certificate_not_yet_valid", evidence: []ProbeID{ProbeTLS, ProbeTargetTCP},
		},
		{
			name: "TLS untrusted issuer", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeTLS: {Status: StatusFail, Cause: TLSCauseUntrustedIssuer}, ProbeHTTPS: {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the TLS handshake fails: bad/expired cert, clock skew, or MITM proxy.",
			verdict: VerdictService, focus: ProbeTLS,
			id: "tls_untrusted_issuer", evidence: []ProbeID{ProbeTLS, ProbeTargetTCP},
		},
		{
			// A handshake timeout with the bulk-write row healthy: the path
			// carried a full-size write, so this is not the path MTU case one
			// rung above and stays a service answer.
			name: "TLS timed out with a healthy path", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeTLS: {Status: StatusFail, Cause: TLSCauseTimeout}, ProbeHTTPS: {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the TLS handshake fails: bad/expired cert, clock skew, or MITM proxy.",
			verdict: VerdictService, focus: ProbeTLS,
			id: "tls_timeout", evidence: []ProbeID{ProbeTLS, ProbeTargetTCP},
		},
		{
			name: "TLS connection closed", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeTLS: {Status: StatusFail, Cause: TLSCauseConnectionClosed}, ProbeHTTPS: {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the TLS handshake fails: bad/expired cert, clock skew, or MITM proxy.",
			verdict: VerdictService, focus: ProbeTLS,
			id: "tls_connection_closed", evidence: []ProbeID{ProbeTLS, ProbeTargetTCP},
		},
		{
			// The TLS row dials the pinned address itself, so the port can
			// stop answering between the TCP rung and this one.
			name: "TLS dial refused", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeTLS: {Status: StatusFail, Cause: TLSCauseTCPUnreachable}, ProbeHTTPS: {Status: StatusSkip},
			}),
			summary: "TCP reaches example.com:443 but the TLS handshake fails: bad/expired cert, clock skew, or MITM proxy.",
			verdict: VerdictService, focus: ProbeTLS,
			id: "tls_tcp_unreachable", evidence: []ProbeID{ProbeTLS, ProbeTargetTCP},
		},
		{
			name: "no HTTPS response", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeHTTPS: ok(StatusFail)}),
			summary: "TLS is fine but no HTTPS response from example.com:443: application-layer or proxy block.",
			verdict: VerdictService, focus: ProbeHTTPS,
			id: "https_no_response", evidence: []ProbeID{ProbeHTTPS, ProbeTLS},
		},
		{
			name: "no plain HTTP response beside working HTTPS", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeHTTP: ok(StatusFail)}),
			summary: "HTTPS works but no HTTP response from example.com:80: the redirect/plain-HTTP endpoint may be blocked.",
			verdict: VerdictService, focus: ProbeHTTP,
			id: "http_no_response", evidence: []ProbeID{ProbeHTTP, ProbeHTTPS},
		},
		{
			name: "no HTTP response", target: httpOnly,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeHTTP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusPass),
				ProbeTargetTCP: ok(StatusPass), ProbeHTTP: ok(StatusFail),
			},
			summary: "No HTTP response from example.com:80: application-layer or proxy block.",
			verdict: VerdictService, focus: ProbeHTTP,
			id: "http_no_response", evidence: []ProbeID{ProbeHTTP, ProbeTargetTCP},
		},
		{
			name: "service banner check failed", target: ssh,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeSSH},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusPass),
				ProbeTargetTCP: ok(StatusPass), ProbeSSH: ok(StatusFail),
			},
			summary: "example.com:22 accepts TCP but the service banner check failed.",
			verdict: VerdictService, focus: ProbeSSH,
			id: "service_banner_failure", evidence: []ProbeID{ProbeSSH, ProbeTargetTCP},
		},
		{
			name: "service sent no banner", target: ssh,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeSSH},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusPass), ProbeDNS: ok(StatusPass),
				ProbeTargetTCP: ok(StatusPass), ProbeSSH: ok(StatusWarn),
			},
			summary: "example.com:22 accepts TCP but sent no service banner.",
			verdict: VerdictDegraded, focus: ProbeSSH,
			id: "service_banner_missing", evidence: []ProbeID{ProbeSSH, ProbeTargetTCP},
		},
		{
			name: "targeted QUIC blocked", target: tls, order: append([]ProbeID{ProbeQUIC}, webOrder...),
			res:     with(map[ProbeID]ProbeResult{ProbeQUIC: ok(StatusFail)}),
			summary: "The target and direct TCP/443 work, but the QUIC handshake over UDP/443 failed. Applications can fall back to TCP, which may feel slower.",
			verdict: VerdictDegraded, focus: ProbeQUIC,
			id: "quic_unavailable", evidence: []ProbeID{ProbeQUIC, ProbeInternet},
		},
		{
			name: "targeted encrypted DNS blocked", target: tls, order: append([]ProbeID{ProbeDNSEncrypted}, webOrder...),
			res:     with(map[ProbeID]ProbeResult{ProbeDNSEncrypted: ok(StatusFail)}),
			summary: encryptedDNSSummary, verdict: VerdictDegraded, focus: ProbeDNSEncrypted,
			id: "encrypted_dns_unavailable", evidence: []ProbeID{ProbeDNSEncrypted, ProbeDNS, ProbeInternet},
		},
		{
			// The endpoint under test answered a direct connection, so the
			// reference endpoints failing is a fact about those addresses.
			name: "target works, reference endpoints unreachable", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeInternet: ok(StatusFail)}),
			summary: "The target answered a direct connection, so direct egress works; the egress check's own fixed reference endpoints are what did not answer.",
			verdict: VerdictDegraded, focus: ProbeInternet,
			id: "reference_egress_unreachable", evidence: []ProbeID{ProbeInternet, ProbeTargetTCP, ProbeHTTP, ProbeHTTPS},
		},
		{
			// The same egress failure with a device on the local network as
			// the target: reaching it never leaves the network, so it
			// contradicts nothing and the blocked reading stands.
			name: "local device works, direct egress blocked", target: local,
			order: []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP},
			res: map[ProbeID]ProbeResult{
				ProbeIface: ok(StatusPass), ProbeInternet: ok(StatusFail),
				ProbeDNS: ok(StatusNA), ProbeTargetTCP: ok(StatusPass),
			},
			summary: "The target works but direct TCP egress to the egress check's reference endpoints is blocked (proxy-only or filtered network?).",
			verdict: VerdictDegraded, focus: ProbeInternet,
			id: "direct_egress_blocked", evidence: []ProbeID{ProbeInternet, ProbeTargetTCP},
		},
		{
			name: "target works, proxy failed", target: tls, order: append([]ProbeID{ProbeProxy}, webOrder...),
			res:     with(map[ProbeID]ProbeResult{ProbeProxy: ok(StatusFail)}),
			summary: "The target and direct egress work, but the configured environment proxy check failed, so apps that use the proxy will fail (see the proxy row).",
			verdict: VerdictDegraded, focus: ProbeProxy,
			id: "proxy_failure", evidence: []ProbeID{ProbeProxy, ProbeInternet},
		},
		{
			name: "target works, direct egress degraded", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeInternet: ok(StatusWarn)}),
			summary: "The target works but direct egress to the egress check's reference endpoints is degraded (see the ! row for details).",
			verdict: VerdictDegraded, focus: ProbeInternet,
			id: "direct_egress_degraded", evidence: []ProbeID{ProbeInternet, ProbeHTTP, ProbeHTTPS},
		},
		{
			name: "target works, resolvers disagree", target: tls, order: append([]ProbeID{ProbeDNSPublic}, webOrder...),
			res: with(map[ProbeID]ProbeResult{
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("203.0.113.9")}},
				ProbeDNSPublic: disagreed(net.ParseIP("198.51.100.20")),
			}),
			summary: "The target works, but system DNS and public DNS disagree; split DNS or filtering may be intentional (see the DNS rows).",
			verdict: VerdictDegraded, focus: ProbeDNSPublic,
			id: "dns_disagreement", evidence: []ProbeID{ProbeDNSPublic, ProbeDNS},
		},
		{
			name: "target works, something else degraded", target: tls, order: webOrder,
			res:     with(map[ProbeID]ProbeResult{ProbeIface: ok(StatusWarn)}),
			summary: "The target works, but some checks are degraded (see the ! rows for details).",
			verdict: VerdictDegraded,
		},
		{
			name: "target healthy", target: tls, order: webOrder, res: webHealthy(),
			summary: "All checks passed. example.com:443 looks healthy.", verdict: VerdictOK,
		},
		{
			// The target rungs never ran, so nothing above TCP is evidence and
			// no case is about any of them: the run falls through to the
			// selected-check answer.
			name: "targeted run whose target rungs were skipped", target: tls, order: webOrder,
			res: with(map[ProbeID]ProbeResult{
				ProbeTargetTCP: {Status: StatusSkip}, ProbePMTU: {Status: StatusSkip},
				ProbeTLS: {Status: StatusSkip}, ProbeHTTP: {Status: StatusSkip}, ProbeHTTPS: {Status: StatusSkip},
			}),
			summary: "Selected checks passed.", verdict: VerdictOK,
		},
	}
}

// TestDiagnosisMatrix pins the sentence, the verdict, the blamed row and the
// stable identity of every arm at once. Diagnose and FocusProbe are read
// through their public signatures, because those are what the JSON report and
// the TUI use, and the structured result is read beside them so the two can be
// shown to agree rather than assumed to.
func TestDiagnosisMatrix(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			summary, verdict := Diagnose(c.target, c.order, c.res)
			if summary != c.summary {
				t.Errorf("summary:\n got %q\nwant %q", summary, c.summary)
			}
			if verdict != c.verdict {
				t.Errorf("verdict: got %q, want %q", verdict, c.verdict)
			}
			if focus := FocusProbe(c.target, c.order, c.res); focus != c.focus {
				t.Errorf("focus probe: got %q, want %q", focus, c.focus)
			}

			d := Interpret(c.target, c.order, c.res)
			// The compatibility accessors are views onto this one result, so
			// anything they report that the structure does not is a second
			// source of truth returning.
			if d.Summary != summary || d.Verdict != verdict {
				t.Errorf("Diagnose disagrees with Interpret: %q/%q vs %q/%q", summary, verdict, d.Summary, d.Verdict)
			}
			if c.id == "" {
				if len(d.Findings) != 0 {
					t.Fatalf("expected no finding, got %+v", d.Findings)
				}
				return
			}
			if len(d.Findings) != 1 {
				t.Fatalf("expected exactly one finding, got %d", len(d.Findings))
			}
			f := d.Findings[0]
			if f.ID != c.id {
				t.Errorf("diagnosis id: got %q, want %q", f.ID, c.id)
			}
			if f.Focus != c.focus {
				t.Errorf("finding focus: got %q, want %q", f.Focus, c.focus)
			}
			if f.Summary != c.summary || f.Verdict != c.verdict {
				t.Errorf("finding restates the run differently: %q/%q", f.Summary, f.Verdict)
			}
			if rows := f.EvidenceRows(); !slices.Equal(rows, c.evidence) {
				t.Errorf("evidence rows: got %v, want %v", rows, c.evidence)
			}
		})
	}
}

// TestDiagnosisEvidenceIsRealProbeState guards the property that makes evidence
// worth publishing: every row a finding cites was part of that run and reported
// something, the row the finding blames leads the list, and nothing repeats.
// Citing a check nobody made would be a claim about evidence that does not
// exist.
func TestDiagnosisEvidenceIsRealProbeState(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			for _, f := range Interpret(c.target, c.order, c.res).Findings {
				rows := f.EvidenceRows()
				if f.Focus != "" && (len(rows) == 0 || rows[0] != f.Focus) {
					t.Errorf("evidence %v does not lead with the blamed row %q", f.Evidence, f.Focus)
				}
				seen := map[CausalEvidence]bool{}
				for _, evidence := range f.Evidence {
					if seen[evidence] {
						t.Errorf("evidence repeats %+v", evidence)
					}
					seen[evidence] = true
					if evidence.Kind == EvidenceNotEvaluated && evidence.Reason == NotEvaluatedNotSelected {
						if slices.Contains(c.order, evidence.Check) {
							t.Errorf("not-selected evidence names %q, which the run did ask for", evidence.Check)
						}
						if _, exists := c.res[evidence.Check]; exists {
							t.Errorf("not-selected evidence names %q, which produced a result", evidence.Check)
						}
						continue
					}
					if !slices.Contains(c.order, evidence.Check) {
						t.Errorf("evidence names %q, which the run did not ask for", evidence.Check)
					}
					if _, ran := c.res[evidence.Check]; !ran {
						t.Errorf("evidence names %q, which produced no result", evidence.Check)
					}
				}
			}
		})
	}
}

// TestBlamedRowFallsBackOnlyWhenTheDiagnosisNamesNone pins the difference
// between the two rows a caller can ask for. Focus is what the diagnosis
// proved; Blamed is where to put a cursor, so it falls back to the first
// failure rather than leaving the reader nowhere to look.
func TestBlamedRowFallsBackOnlyWhenTheDiagnosisNamesNone(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			d := Interpret(c.target, c.order, c.res)
			if c.focus != "" {
				if d.Blamed != c.focus {
					t.Errorf("blamed row: got %q, want the focus row %q", d.Blamed, c.focus)
				}
				return
			}
			want := ProbeID("")
			for _, id := range c.order {
				if r, ok := c.res[id]; ok && r.Status == StatusFail {
					want = id
					break
				}
			}
			if d.Blamed != want {
				t.Errorf("blamed row: got %q, want the first failed row %q", d.Blamed, want)
			}
		})
	}
}

// TestDiagnosisIDInventory reads every DiagnosisID declared in the package,
// because Go has no runtime enum, and holds the vocabulary to its contract:
// values are unique, spelled in the stable lower_snake_case the JSON report
// publishes, and reachable, since an identity no condition produces is a
// promise the engine does not keep. The matrix above is the reachability
// proof.
func TestDiagnosisIDInventory(t *testing.T) {
	declared := map[DiagnosisID]string{}
	for _, spec := range declaredConstants(t, "finding.go", "DiagnosisID") {
		for i, name := range spec.Names {
			if i >= len(spec.Values) {
				t.Fatalf("%s has no explicit stable diagnosis ID", name.Name)
			}
			literal, ok := spec.Values[i].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatalf("%s is not a string literal", name.Name)
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(name.Name, "Diagnosis") {
				t.Errorf("%s does not read as a diagnosis identity", name.Name)
			}
			if !stableIDRe.MatchString(value) {
				t.Errorf("%s = %q is not stable lower_snake_case", name.Name, value)
			}
			if other, dup := declared[DiagnosisID(value)]; dup {
				t.Errorf("%s duplicates the value of %s", name.Name, other)
			}
			declared[DiagnosisID(value)] = name.Name
		}
	}

	produced := map[DiagnosisID]bool{}
	for _, c := range diagnosisMatrix() {
		for _, f := range Interpret(c.target, c.order, c.res).Findings {
			if _, known := declared[f.ID]; !known {
				t.Errorf("case %q produced undeclared diagnosis ID %q", c.name, f.ID)
			}
			produced[f.ID] = true
		}
	}
	for id, name := range declared {
		if !produced[id] {
			t.Errorf("%s (%q) is declared but no case in the matrix reaches it", name, id)
		}
	}
}

var stableIDRe = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// TestDiagnosisIDsAreDocumented keeps the published vocabulary and its
// documentation in step. The IDs are a JSON contract, and a contract nobody
// wrote down is one users discover by reading source.
func TestDiagnosisIDsAreDocumented(t *testing.T) {
	docs, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range declaredConstants(t, "finding.go", "DiagnosisID") {
		for i, name := range spec.Names {
			value, err := strconv.Unquote(spec.Values[i].(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(docs), "`"+value+"`") {
				t.Errorf("%s (%q) is not documented in docs/reference.md", name.Name, value)
			}
		}
	}
}

// TestObservationVocabulariesAreDocumented keeps the rest of the published
// vocabulary in step with its documentation, for the same reason the diagnosis
// IDs are: an observation, a route reason, and a tunnel state all reach a
// consumer through the JSON report and the .ndoc file. The empty value in each
// is skipped, since absence is documented as a state rather than as a word.
func TestObservationVocabulariesAreDocumented(t *testing.T) {
	docs, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, vocabulary := range []struct{ file, typeName string }{
		{"finding.go", "ObservationID"},
		{"route.go", "RouteReason"},
		{"route.go", "TunnelState"},
	} {
		for _, spec := range declaredConstants(t, vocabulary.file, vocabulary.typeName) {
			for i, name := range spec.Names {
				value, err := strconv.Unquote(spec.Values[i].(*ast.BasicLit).Value)
				if err != nil {
					t.Fatal(err)
				}
				if value == "" {
					continue
				}
				if !strings.Contains(string(docs), "`"+value+"`") {
					t.Errorf("%s (%q) is not documented in docs/reference.md", name.Name, value)
				}
			}
		}
	}
}

// TestCollateralFollowsTheSameInterpretation checks the property that makes
// Collateral a view rather than a second opinion: it never dims the row the
// diagnosis blames, and it says nothing at all about a run that has not
// finished.
func TestCollateralFollowsTheSameInterpretation(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			d := Interpret(c.target, c.order, c.res)
			collateral := Collateral(c.target, c.order, c.res)
			if d.Verdict == VerdictIncomplete {
				if collateral != nil {
					t.Errorf("unfinished run reported collateral %v", collateral)
				}
				return
			}
			if d.Blamed != "" && collateral[d.Blamed] {
				t.Errorf("the blamed row %q was called collateral to itself", d.Blamed)
			}
			for id := range collateral {
				if r, ok := c.res[id]; !ok || r.Status != StatusFail {
					t.Errorf("collateral names %q, which did not fail", id)
				}
			}
		})
	}
}
