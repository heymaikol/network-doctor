package diagnostic

import (
	"slices"
	"strings"
)

// Remediation is what to do about a diagnosis: the next action, why that
// action is the right one, the steps it breaks down into, an optional
// read-only command for looking at the local state the conclusion is about,
// and what a reader should see once it worked.
//
// It is typed data, not prose to be parsed back. Nothing recovers a
// remediation from Detail, Fix, or a rendered screen: callers read the fields.
//
// It sits one level above ProbeResult.Fix and does not replace it. Fix is the
// one-line hint the row that failed wrote about itself, at probe time, with
// the certificate dates and measurements only that probe held. A Remediation
// is the finished diagnosis's answer, chosen from the stable conclusion the
// interpretation pass reached rather than from any single row, which is why
// the two can say different things without contradicting each other: the row
// reports what it saw, the diagnosis says what to do about the run.
type Remediation struct {
	// ID is the stable machine-readable identity of this advice. Scripts
	// branch on it; the English beside it can be reworded freely.
	ID RemediationID
	// Action is the imperative next step, short enough for one line.
	Action string
	// Why is what makes that action the appropriate one, in the evidence the
	// run actually collected.
	Why string
	// Steps break the action down, in the order worth trying. Empty when the
	// action says the whole of it.
	Steps []string
	// Command is a safe read-only command as an argv, never a shell string and
	// never executed by netdoc: it is offered for the user to run and read.
	// Empty where prose is clearer or nothing local is worth inspecting.
	Command []string
	// Expect is what a successful remedy looks like, so a reader knows whether
	// the retest is worth running yet.
	Expect string
}

// CommandLine renders Command as the one line a reader would type, and "" when
// there is no command. It is display text only: the argv is the contract, and
// nothing parses this back. Joining on spaces stays unambiguous because no
// argument in the table contains one, which TestRemediationCommandsAreSafe
// pins.
func (r Remediation) CommandLine() string { return strings.Join(r.Command, " ") }

// RemediationID is the stable identity of one piece of advice. It is a second
// vocabulary rather than a reuse of DiagnosisID because one conclusion can
// have several remedies: a dead direct path is a missing default route, an
// unreachable gateway, or a working link with a broken uplink beyond it, and
// those are three different things to go and do.
type RemediationID string

// The remediation vocabulary. Values are lower_snake_case and permanent;
// renaming one is a breaking change to the JSON report. docs/reference.md
// tabulates the whole set, and TestRemediationIDsAreDocumented keeps that
// table honest.
const (
	RemedyBringUpLink          RemediationID = "bring_up_link"
	RemedySignInToPortal       RemediationID = "sign_in_to_portal"
	RemedyCheckLocalPath       RemediationID = "check_local_path"
	RemedyRestoreDefaultRoute  RemediationID = "restore_default_route"
	RemedyReachGateway         RemediationID = "reach_gateway"
	RemedyCheckUpstream        RemediationID = "check_router_uplink"
	RemedyFixPreferredRoute    RemediationID = "fix_preferred_route"
	RemedyFixLocalEgressFirst  RemediationID = "fix_local_egress_first"
	RemedyUseProxyPath         RemediationID = "use_proxy_path"
	RemedyCheckProxyConfig     RemediationID = "check_proxy_config"
	RemedyCheckProxyReachable  RemediationID = "check_proxy_reachable"
	RemedyCheckProxyResolution RemediationID = "check_proxy_resolution"
	RemedyCheckProxyEgress     RemediationID = "check_proxy_egress"
	RemedyRestoreIPv4          RemediationID = "restore_ipv4_egress"
	RemedyRestoreIPv6          RemediationID = "restore_ipv6_egress"
	RemedyReadEgressWarning    RemediationID = "read_egress_warning"
	RemedyFixSystemResolver    RemediationID = "fix_system_resolver"
	RemedyCheckTheName         RemediationID = "check_the_name"
	RemedyCheckResolution      RemediationID = "check_name_resolution"
	RemedyConfirmSplitDNS      RemediationID = "confirm_split_dns"
	RemedyEncryptedDNSChoice   RemediationID = "choose_encrypted_dns"
	RemedyExpectTCPFallback    RemediationID = "expect_tcp_fallback"
	RemedyStartTheService      RemediationID = "start_the_service"
	RemedyTracePath            RemediationID = "trace_the_path"
	RemedyCheckTheDevice       RemediationID = "check_the_device"
	RemedyRerunWithEgress      RemediationID = "rerun_with_egress_check"
	RemedyLowerMTU             RemediationID = "lower_path_mtu"
	RemedyRenewCertificate     RemediationID = "renew_certificate"
	RemedyAwaitCertificate     RemediationID = "await_certificate_validity"
	RemedySetClock             RemediationID = "set_the_clock"
	RemedyMatchCertName        RemediationID = "match_certificate_name"
	RemedyTrustIssuer          RemediationID = "resolve_untrusted_issuer"
	RemedyCheckTLSPath         RemediationID = "check_tls_path"
	RemedyCheckTLSTermination  RemediationID = "check_tls_termination"
	RemedyRetryTLSDial         RemediationID = "retry_tls_dial"
	RemedyNarrowTLSFailure     RemediationID = "narrow_tls_failure"
	RemedyCheckApplication     RemediationID = "check_application_layer"
	RemedyCheckBannerService   RemediationID = "check_banner_service"
	RemedyIdentifyListener     RemediationID = "identify_listener"
	RemedyRerunFullChain       RemediationID = "rerun_full_chain"
)

// Remediate is the advice a finished diagnosis supports, and false when it
// supports none: an unfinished run, a healthy one, or a verdict about no
// single conclusion. It reads the interpretation the caller already has rather
// than diagnosing the run a second time, so the advice, the sentence and the
// blamed row cannot disagree.
//
// The choice is made from typed inputs alone: the finding's stable ID, and
// where a probe classified its failure further, the stable Cause on the row
// the finding focuses. No prose is parsed to get here.
//
// goos is a parameter rather than runtime.GOOS so every platform's advice is
// reachable from one test run.
func Remediate(d Diagnosis, res map[ProbeID]ProbeResult, goos string) (Remediation, bool) {
	if len(d.Findings) == 0 {
		return Remediation{}, false
	}
	f := d.Findings[0]
	// A cause refines the advice only where the table has an entry for it.
	// Anything else keeps the conclusion's general answer, which is what stops
	// an unrecognized cause from silently losing the remediation.
	r, ok := remedies[remedyKey{id: f.ID, cause: res[f.Focus].Cause}]
	if !ok {
		if r, ok = remedies[remedyKey{id: f.ID}]; !ok {
			return Remediation{}, false
		}
	}
	out := Remediation{
		ID:      r.id,
		Action:  r.action,
		Why:     r.why,
		Steps:   slices.Clone(r.steps),
		Command: commandFor(r.command, goos),
		Expect:  r.expect,
	}
	if out.ID == RemedyReachGateway {
		for _, route := range res[ProbeIface].Routes {
			if len(route.Competing) > 0 && (res[f.Focus].causeFamily == "" || route.Family == res[f.Focus].causeFamily) {
				out.Steps = append(out.Steps, "Another default route is configured for this family. Test that path before changing preference; its presence does not prove it works.")
				break
			}
		}
	}
	return out, true
}

// remedyKey is what a piece of advice answers: a stable conclusion, optionally
// narrowed by the stable cause the focused row reported. The empty cause is
// the conclusion's general answer and the fallback for every cause with no
// entry of its own.
type remedyKey struct {
	id    DiagnosisID
	cause string
}

// remedy is one table row. Several keys may share one of these, which is how
// the same advice reaches two conclusions without being written twice.
type remedy struct {
	id          RemediationID
	action, why string
	steps       []string
	command     map[string][]string
	expect      string
}

// commandFor picks a table's command for one OS. The empty key is the default
// every OS without an entry of its own falls back to, matching how the fix
// hints in fixhints.go treat their default branch.
func commandFor(byOS map[string][]string, goos string) []string {
	if args, ok := byOS[goos]; ok {
		return slices.Clone(args)
	}
	return slices.Clone(byOS[""])
}

// The read-only commands the table offers, named once and shared, so two
// remedies that want the routing table cannot drift into asking for it
// differently. Each is an argv: netdoc never runs these, never wraps them in a
// shell, and never puts the target inside one. Investigating the target itself
// is what the drill-down tools are for, and they build their own arguments.
var (
	showLinks = map[string][]string{
		"":        {"ip", "link"},
		"darwin":  {"ifconfig", "-a"},
		"windows": {"netsh", "interface", "show", "interface"},
	}
	showRoutes = map[string][]string{
		"":        {"ip", "route"},
		"darwin":  {"netstat", "-rn"},
		"windows": {"route", "print", "-4"},
	}
	showNeighbors = map[string][]string{
		"":        {"ip", "neigh"},
		"darwin":  {"arp", "-an"},
		"windows": {"arp", "-a"},
	}
	showResolvers = map[string][]string{
		"":        {"cat", "/etc/resolv.conf"},
		"darwin":  {"scutil", "--dns"},
		"windows": {"ipconfig", "/all"},
	}
	showClock = map[string][]string{
		"":        {"timedatectl", "status"},
		"darwin":  {"date"},
		"windows": {"w32tm", "/query", "/status"},
	}
	showMTU = map[string][]string{
		"":        {"ip", "link"},
		"darwin":  {"ifconfig", "-a"},
		"windows": {"netsh", "interface", "ipv4", "show", "subinterfaces"},
	}
)

// Advice that answers more than one conclusion, held in a variable so the two
// keys share one truth rather than two copies that can drift apart.
var (
	routeMissing = remedy{
		id:     RemedyRestoreDefaultRoute,
		action: "Restore a default route",
		why:    "Nothing in the routing table leads off this network, so traffic for the internet has nowhere to go. That is usually DHCP not completing, a VPN that dropped its route, or a static configuration with no gateway.",
		steps: []string{
			"Renew the DHCP lease, or reconnect the VPN that installs the route.",
			"On a static configuration, check that the gateway is set and sits on this machine's own subnet.",
		},
		command: showRoutes,
		expect:  "A default route (0.0.0.0/0 or ::/0) pointing at the gateway.",
	}
	gatewaySilent = remedy{
		id:     RemedyReachGateway,
		action: "Get the default gateway answering",
		why:    "After the reference connections failed, the gateway was unresolved in the neighbor table. A loose cable, a dropped Wi-Fi association, or an address on the wrong subnet all look like this.",
		steps: []string{
			"Reseat the cable, or leave and rejoin the Wi-Fi network.",
			"Check that this machine's address and mask put the gateway on the same subnet.",
			"Power-cycle the router if no device on the network can reach it either.",
		},
		command: showNeighbors,
		expect:  "The gateway resolving to a hardware address instead of staying incomplete.",
	}
	uplinkBroken = remedy{
		id:     RemedyCheckUpstream,
		action: "Check the router's own uplink",
		why:    "A default route exists, but failed reference connections do not establish whether the gateway or upstream path works. The location of the break remains unknown.",
		steps: []string{
			"Check whether other devices on the same network are offline too.",
			"Look at the router's WAN status, or ask whoever runs the network about a filter.",
		},
		expect: "A measured gateway or upstream result that narrows where connectivity fails.",
	}
	preferredRouteDead = remedy{
		id:     RemedyFixPreferredRoute,
		action: "Check the interface holding the preferred default route",
		why:    "This machine has multiple default routes with a metric preference. Failed reference connections do not prove that the preferred route caused the failure or that another route works.",
		steps: []string{
			"Test connectivity through each interface before changing route preference.",
			"Confirm the preferred interface really has upstream connectivity of its own.",
		},
		command: showRoutes,
		expect:  "A measured comparison showing whether either route carries traffic.",
	}
	noHTTPResponse = remedy{
		id:     RemedyCheckApplication,
		action: "Check the service on top of the connection",
		why:    "The connection completed and no HTTP response came back, so the path is not the problem: the service, or something in front of it, is holding the request.",
		steps: []string{
			"Check the service's own status or logs for the request.",
			"Look for a proxy, load balancer, or WAF that accepts connections and then holds them.",
		},
		expect: "An HTTP status line back from the endpoint.",
	}
	selectionTooNarrow = remedy{
		id:     RemedyRerunFullChain,
		action: "Rerun without the check selection",
		why:    "A check failed in a run whose other rungs were selected out, so the checks that would explain the failure were never made. What is left is the failed row itself.",
		steps: []string{
			"Rerun without --check or --skip, or add back the rungs underneath the failing one.",
		},
		expect: "A run that can name the cause instead of only the failed row.",
	}
)

// remedies is the whole remediation table: the one place advice is written.
//
// Conservative on purpose. Where netdoc cannot tell two causes apart, the
// entry says what to investigate instead of presenting one of them as fact,
// and no entry suggests a destructive configuration change, a privilege
// escalation, or turning a security check off to make a symptom go away.
var remedies = map[remedyKey]remedy{
	{id: DiagnosisNoUsableInterface}: {
		id:     RemedyBringUpLink,
		action: "Bring a network interface up",
		why:    "No interface is up, so nothing this machine sends can leave it. Every other check is untestable until the link is back.",
		steps: []string{
			"Plug the cable back in, or turn Wi-Fi on and join a network.",
			"If a VPN or virtual interface is the only one configured, connect it, or fall back to the physical link.",
		},
		command: showLinks,
		expect:  "At least one interface besides loopback listed as up with an address.",
	},
	{id: DiagnosisCaptivePortal}: {
		id:     RemedySignInToPortal,
		action: "Sign in to the network",
		why:    "Something on this network answered a request addressed elsewhere, which is how a sign-in portal announces itself. Nothing below that point means what it says until the sign-in is done.",
		steps: []string{
			"Open a browser, load any plain http:// page, and complete the portal's sign-in.",
			"Where the interception advertised a sign-in URL, the egress row carries it.",
		},
		expect: "Checks that reach the real internet rather than the portal.",
	},

	// Direct egress. The route causes come from the local routing and neighbor
	// tables, and each one is a different thing to go and do.
	{id: DiagnosisOffline}: {
		id:     RemedyCheckLocalPath,
		action: "Check this machine's own path off the network",
		why:    "Neither DNS nor a direct connection to the egress check's reference endpoints is getting through, and the routing table offered no specific cause. This machine's own path is the first thing to rule out rather than something the run established.",
		steps: []string{
			"Confirm the link is up and this machine has an address from DHCP.",
			"Restart the router or modem if other devices are offline too.",
		},
		command: showRoutes,
		expect:  "A default route, and a gateway that answers.",
	},
	{id: DiagnosisOffline, cause: RouteCauseNoDefaultRoute}:                routeMissing,
	{id: DiagnosisOffline, cause: RouteCauseGatewayUnreachable}:            gatewaySilent,
	{id: DiagnosisOffline, cause: RouteCauseSelectedPathFailed}:            uplinkBroken,
	{id: DiagnosisOffline, cause: RouteCausePreferredPathFailed}:           preferredRouteDead,
	{id: DiagnosisLocalEgressFailure, cause: RouteCauseNoDefaultRoute}:     routeMissing,
	{id: DiagnosisLocalEgressFailure, cause: RouteCauseGatewayUnreachable}: gatewaySilent,
	{id: DiagnosisLocalEgressFailure}: {
		id:     RemedyFixLocalEgressFirst,
		action: "Fix this machine's own connection first",
		why:    "The local routing state classified this machine's path off the network as broken, so the far end has not been given a fair test yet. Anything concluded about it now would be a claim about a test that never really ran.",
		steps: []string{
			"Work down the local rungs in order: link up, address from DHCP, default route, gateway answering.",
			"Retest the target once the general checks pass, so its result means something.",
		},
		command: showRoutes,
		expect:  "The general connectivity checks passing, with the target retested afterwards.",
	},
	{id: DiagnosisReferenceEgressUnreachable}: {
		id:     RemedyReadEgressWarning,
		action: "Read which reference endpoints the egress row could not reach",
		why:    "The endpoint under test answered a direct connection, so traffic does leave this machine without a proxy. What failed is the fixed set of reference addresses the egress check dials, which a filter, a policy route, or an outage at those addresses can take out on their own without touching anything else.",
		steps: []string{
			"Read the egress row's attempts for the addresses that did not answer.",
			"Treat general connectivity as proved by this run: retest anything else against the destination you actually care about.",
		},
		expect: "Either those addresses answering again, or a confirmed filter that leaves the rest of this machine's egress working.",
	},
	{id: DiagnosisReachabilityUnlocalized}: {
		id:     RemedyCheckLocalPath,
		action: "Check this machine's own path off the network",
		why:    "Every destination this run tried was silent, and nothing it observed says where the path breaks. This machine's own path is the cheapest half to rule out, which is why it comes first, not because the run located the fault there.",
		steps: []string{
			"Confirm the link is up and this machine has an address from DHCP.",
			"Check whether another device on the same network reaches the same destinations, which is what separates this machine from the network around it.",
		},
		command: showRoutes,
		expect:  "A default route and a gateway that answers, or a second device failing the same way and moving the question off this machine.",
	},
	{id: DiagnosisDirectEgressBlocked}: {
		id:     RemedyUseProxyPath,
		action: "Send this traffic the way this network allows",
		why:    "Something else on this machine is carrying traffic while direct TCP egress is not, which is what a proxy-only or filtered network looks like from here. netdoc cannot tell an intended policy from an outage, so both are still open.",
		steps: []string{
			"Set HTTPS_PROXY, HTTP_PROXY and NO_PROXY for the tools that need the internet, if this network runs a proxy.",
			"If direct egress is meant to work, ask whoever runs the network which destinations are filtered.",
		},
		expect: "Traffic leaving through the path this network intends, or a confirmed filter.",
	},
	{id: DiagnosisProxyOnlyNetwork}: {
		id:     RemedyUseProxyPath,
		action: "Use the environment proxy for this traffic",
		why:    "Direct connections do not leave this network, but the configured proxy does carry traffic, so the proxy is the path that works.",
		steps: []string{
			"Point the failing application at the same proxy the environment variables name.",
			"Check NO_PROXY for an entry that sends this destination direct.",
		},
		expect: "The destination reachable through the proxy.",
	},
	{id: DiagnosisDirectEgressDegraded}: {
		id:     RemedyReadEgressWarning,
		action: "Read what the egress row is warning about",
		why:    "Direct egress carries traffic but is impaired. Nothing is broken here, so this is worth acting on only when the impairment matches the symptom you are chasing.",
		steps: []string{
			"Open the warned row for the measurement behind it, such as latency or one address family failing.",
		},
		expect: "Either a measurement that explains the symptom, or one that rules this out.",
	},
	{id: DiagnosisDirectEgressDegraded, cause: FamilyCauseIPv4Unreachable}: {
		id:     RemedyRestoreIPv4,
		action: "Restore IPv4 egress, or accept an IPv6-only path",
		why:    "IPv6 carried traffic while IPv4 did not, so this machine reaches the internet over one family only. Ordinary browsing looks fine while anything IPv4-only quietly fails.",
		steps: []string{
			"Check whether this machine still has a usable IPv4 address and default route.",
			"Check whether a VPN or tunnel captured IPv4 without carrying it.",
		},
		command: showRoutes,
		expect:  "Both families reachable, or a network that is IPv6-only on purpose.",
	},
	{id: DiagnosisDirectEgressDegraded, cause: FamilyCauseIPv6Unreachable}: {
		id:     RemedyRestoreIPv6,
		action: "Restore IPv6 egress, or accept an IPv4-only path",
		why:    "IPv4 carried traffic while IPv6 did not, so this machine reaches the internet over one family only. Destinations that publish only AAAA records fail while everything else looks fine.",
		steps: []string{
			"Check whether this machine has a global IPv6 address and a default route for it.",
			"Check whether a VPN, tunnel, or firewall is dropping IPv6 while leaving IPv4 alone.",
		},
		command: showRoutes,
		expect:  "Both families reachable, or a network that is IPv4-only on purpose.",
	},

	// The proxy path beside the direct one.
	{id: DiagnosisProxyFailure}: {
		id:     RemedyCheckProxyConfig,
		action: "Check the configured proxy",
		why:    "Direct egress works while the proxy the environment names does not, so applications that honor those variables fail on a machine that is otherwise online.",
		steps: []string{
			"Check HTTPS_PROXY, HTTP_PROXY and NO_PROXY for a stale address or a wrong port.",
			"Unset them for tools that do not need the proxy, since direct egress works here.",
		},
		expect: "Either a proxy that tunnels traffic, or variables that no longer point at a dead one.",
	},
	{id: DiagnosisProxyFailure, cause: ProxyCauseUnreachable}: {
		id:     RemedyCheckProxyReachable,
		action: "Check that the proxy itself is up",
		why:    "The connection to the proxy never completed, so this is about reaching the proxy rather than anything it was asked to fetch.",
		steps: []string{
			"Check the proxy's address and port in the environment variables.",
			"Confirm the proxy is running, and reachable from this network rather than only from the office or VPN.",
		},
		expect: "A proxy that accepts a connection.",
	},
	{id: DiagnosisProxyFailure, cause: ProxyCauseProxyDNS}: {
		id:     RemedyCheckProxyResolution,
		action: "Check name resolution on the proxy",
		why:    "The proxy answered and said it could not resolve the destination, so the failing resolver is the proxy's, not this machine's.",
		steps: []string{
			"Confirm the destination name is spelled the way the proxy expects.",
			"Ask whoever runs the proxy about its resolver, since this machine cannot see it.",
		},
		expect: "The proxy resolving the destination and opening the tunnel.",
	},
	{id: DiagnosisProxyFailure, cause: ProxyCauseDestinationUnreachable}: {
		id:     RemedyCheckProxyEgress,
		action: "Check what the proxy is allowed to reach",
		why:    "The proxy answered and refused to reach the destination, which is what a policy denial and a dead path beyond the proxy both look like from a client.",
		steps: []string{
			"Check whether the destination or its port is on the proxy's allow list.",
			"Try a known-allowed destination through the same proxy to tell policy from an outage.",
		},
		expect: "A tunnel the proxy is willing to open.",
	},

	// Name resolution.
	{id: DiagnosisSystemDNSFailure}: {
		id:     RemedyFixSystemResolver,
		action: "Fix or replace the configured resolver",
		why:    "Public DNS resolves the same name this machine's resolver could not, so the path is fine and the configured resolver is the part that is failing or filtering.",
		steps: []string{
			"Check which resolvers this machine uses, and whether a VPN or filtering service installed them.",
			"Point at another resolver temporarily to confirm, then fix the configured one rather than leaving the override in place.",
		},
		command: showResolvers,
		expect:  "The name resolving through the configured resolver, not only through public DNS.",
	},
	{id: DiagnosisDNSNameNotFound}: {
		id:     RemedyCheckTheName,
		action: "Check the name itself",
		why:    "Both resolvers answered, and both say the name has no A or AAAA records. That is an answer rather than a failure to answer, so nothing here is broken.",
		steps: []string{
			"Check the spelling, and whether the record was ever published.",
			"For an internal name, check that you are on the network or VPN that serves it.",
		},
		expect: "An address for the name once the record exists, or the right name if it was a typo.",
	},
	{id: DiagnosisDNSFailure}: {
		id:     RemedyCheckResolution,
		action: "Check name resolution on this machine",
		why:    "Resolution is failing with no second opinion to separate a broken resolver from a name that does not exist, so both are still possible.",
		steps: []string{
			"Check which resolvers are configured, and whether they answer anything at all.",
			"Rerun with the public DNS check enabled to get the second opinion that tells those two apart.",
		},
		command: showResolvers,
		expect:  "Either a resolver that answers, or a second opinion showing the name itself is missing.",
	},
	{id: DiagnosisDNSDisagreement}: {
		id:     RemedyConfirmSplitDNS,
		action: "Confirm which of the two answers is the right one",
		why:    "The configured resolver and public DNS point at different networks. Split DNS and filtering both do this deliberately, so this is only a problem when the answer you got is the wrong one.",
		steps: []string{
			"Compare both answers on the DNS rows against the address the service should have.",
			"On a VPN or corporate network the internal answer is usually the intended one.",
		},
		expect: "No change at all when split DNS is intended.",
	},
	{id: DiagnosisEncryptedDNSUnavailable}: {
		id:     RemedyEncryptedDNSChoice,
		action: "Decide whether encrypted DNS has to work here",
		why:    "Ordinary DNS resolves while DoH or DoT cannot complete a verified exchange. The resolver may be down, or this network may block or intercept encrypted DNS, and nothing observable from a client proves which.",
		steps: []string{
			"Try another DoH or DoT provider, which tells a broken resolver from a blocked transport.",
			"Where the network requires its own resolver, expect encrypted DNS to keep failing here.",
		},
		expect: "Either a verified exchange with another provider, or a confirmed policy on this network.",
	},

	// Paths beside the direct one.
	{id: DiagnosisQUICUnavailable}: {
		id:     RemedyExpectTCPFallback,
		action: "Expect the TCP fallback, and open UDP/443 if the speed matters",
		why:    "TCP/443 works while the QUIC handshake over UDP/443 does not. Applications fall back to TCP on their own, so this costs speed rather than connectivity.",
		steps: []string{
			"Where a firewall, VPN, or tunnel drops UDP/443, allowing it restores QUIC.",
			"No action is needed for applications that are happy on TCP.",
		},
		expect: "Traffic continuing over TCP, and QUIC returning once UDP/443 is allowed.",
	},

	// Reaching the endpoint under test.
	{id: DiagnosisTCPConnectionRefused}: {
		id:     RemedyStartTheService,
		action: "Start the service, or check the port",
		why:    "Every attempt was refused rather than ignored, so something answered for that address. The path works and nothing is listening on that port.",
		steps: []string{
			"Check that the service is running, and bound to an address reachable from here rather than only to localhost.",
			"Confirm the port number, and whether a firewall is rejecting rather than dropping.",
		},
		expect: "The port accepting a connection once the service listens on it.",
	},
	{id: DiagnosisTargetUnreachable}: {
		id:     RemedyTracePath,
		action: "Work out where the packets stop",
		why:    "DNS and the general internet both work from here, so this machine's path is fine and the silence is specific to that endpoint. A closed port, a firewall that drops, and VPN routing all look the same from a client.",
		steps: []string{
			"Trace the path to see how far the packets get before they stop.",
			"Check whether the endpoint needs a VPN, and whether it is up for anyone else.",
		},
		expect: "Either a trace that stops at an identifiable hop, or confirmation that the endpoint is down.",
	},
	{id: DiagnosisIPv4TargetUnreachable}: {
		id:     RemedyTracePath,
		action: "Check the target's IPv4 path",
		why:    "The same target and port work over IPv6 while every tested IPv4 alternative fails. Independent IPv4 egress or explicit peer replies prove the family was testable, narrowing the impairment to this target's IPv4 path or listener.",
		steps:  []string{"Check the target's IPv4 listener, firewall policy, and route."},
		expect: "The target accepting the same connection over IPv4.",
	},
	{id: DiagnosisIPv6TargetUnreachable}: {
		id:     RemedyTracePath,
		action: "Check the target's IPv6 path",
		why:    "The same target and port work over IPv4 while every tested IPv6 alternative fails. Independent IPv6 egress or explicit peer replies prove the family was testable, narrowing the impairment to this target's IPv6 path or listener.",
		steps:  []string{"Check the target's IPv6 listener, firewall policy, and route."},
		expect: "The target accepting the same connection over IPv6.",
	},
	{id: DiagnosisPartialReachability}: {
		id:     RemedyTracePath,
		action: "Check the failed endpoint addresses",
		why:    "At least one resolved address failed an actual connection attempt while another address for the same target and port succeeded.",
		steps:  []string{"Compare the failed addresses in Details with the target's current backends, listeners, and firewall policy."},
		expect: "Every published address accepting the connection, or stale addresses removed from DNS.",
	},
	{id: DiagnosisLocalDeviceUnreachable}: {
		id:     RemedyCheckTheDevice,
		action: "Check the device itself",
		why:    "This machine's own network is working, so the device on the local network is the part not answering. It may be off or asleep, may have a different address now, or may be dropping the connection.",
		steps: []string{
			"Wake the device, or check that it is powered on.",
			"Scan the local network for its current address, since DHCP may have moved it.",
			"Confirm the port, because a device that answers a ping can still refuse this one.",
		},
		expect: "The device answering on the address and port it is meant to use.",
	},
	{id: DiagnosisReachabilityUntested}: {
		id:     RemedyRerunWithEgress,
		action: "Rerun with the general connectivity check included",
		why:    "The target did not answer, and the check that would say whether this machine's own network works was not part of this run, so a local problem cannot be told apart from one on the far end.",
		steps: []string{
			"Rerun without the --check or --skip selection that left the egress check out.",
		},
		expect: "A run that can attribute the silence to one end or the other.",
	},
	{id: DiagnosisProbablePathMTU}: {
		id:     RemedyLowerMTU,
		action: "Try a lower MTU on the path",
		why:    "TCP connects and then stalls on a full-size write, which is what a path MTU black hole looks like: small packets get through, large ones are dropped, and no ICMP message comes back to say so. An ordinary socket cannot measure the real path MTU, so this stays evidence rather than proof.",
		steps: []string{
			"Lower the MTU on the tunnel or interface carrying this traffic, 1400 being a safe first try, then retest.",
			"On a router you control, clamping MSS to the path MTU fixes it for every client at once.",
		},
		command: showMTU,
		expect:  "The stalled transfer draining once the MTU is lower, which is what confirms the black hole.",
	},

	// TLS, at the precision the handshake itself reached.
	{id: DiagnosisTLSCertificateExpired}: {
		id:     RemedyRenewCertificate,
		action: "Renew the certificate, or check this machine's clock",
		why:    "The handshake was rejected because the certificate is outside its validity window. Either it really has expired, or this machine's clock runs far enough ahead to make a valid one look expired.",
		steps: []string{
			"Compare the validity dates on the TLS row with today's date.",
			"Confirm this machine's clock before blaming the certificate.",
		},
		command: showClock,
		expect:  "A certificate whose validity window covers now, on a machine whose clock is right.",
	},
	{id: DiagnosisTLSCertificateNotYetValid}: {
		id:     RemedyAwaitCertificate,
		action: "Check this machine's clock, then the certificate's start date",
		why:    "The certificate was rejected as not yet valid. A clock running slow makes a perfectly good certificate look that way, which is the more common of the two explanations.",
		steps: []string{
			"Confirm this machine's clock and time zone.",
			"If the clock is right, the certificate was issued with a start date in the future and has to be reissued or waited out.",
		},
		command: showClock,
		expect:  "A certificate whose validity window has started, on a machine whose clock is right.",
	},
	{id: DiagnosisTLSClockSkew}: {
		id:     RemedySetClock,
		action: "Set this machine's clock",
		why:    "The measured offset between this machine and the network points the same way as the certificate rejection, which is enough to name the clock rather than list it as one possibility among several.",
		steps: []string{
			"Turn on automatic network time and let it resync.",
			"Check the time zone as well as the time.",
		},
		command: showClock,
		expect:  "Certificate validation succeeding once the clock is right.",
	},
	{id: DiagnosisTLSHostnameMismatch}: {
		id:     RemedyMatchCertName,
		action: "Connect with the name the certificate is for",
		why:    "The certificate is valid but issued for a different name, so either this connection reached a different service than intended, or the server needs the right SNI to answer with the right certificate.",
		steps: []string{
			"Compare the names on the TLS row with the name you asked for.",
			"Check whether the address belongs to a shared host or CDN serving several names.",
		},
		expect: "A certificate whose names include the one you connect with.",
	},
	{id: DiagnosisTLSUntrustedIssuer}: {
		id:     RemedyTrustIssuer,
		action: "Find out who signed the certificate",
		why:    "The chain ends in a CA this machine does not trust. An intercepting proxy, a self-signed certificate, and a missing root store are indistinguishable from here, and one of those is worth stopping for.",
		steps: []string{
			"Check the issuer on the TLS row: a name you do not recognize on a public site is a reason to stop.",
			"On a corporate network, install the organization's root certificate through the normal channel rather than turning verification off.",
		},
		expect: "A chain ending in a CA this machine already trusts.",
	},
	{id: DiagnosisTLSTimeout}: {
		id:     RemedyCheckTLSPath,
		action: "Check the path before blaming the service",
		why:    "TCP connected and then the handshake spent its whole budget without an answer. That is more often a path dropping large packets than a broken service, since a handshake is the first thing on a connection big enough to hit a black hole.",
		steps: []string{
			"Read the Path MTU row: it says whether full-size packets are reaching the far end.",
			"Retest over another network, or without the VPN or tunnel, to see whether the stall follows the path.",
		},
		command: showMTU,
		expect:  "Either a handshake that completes on another path, or a confirmed MTU problem.",
	},
	{id: DiagnosisTLSConnectionClosed}: {
		id:     RemedyCheckTLSTermination,
		action: "Check what is terminating the handshake",
		why:    "The peer accepted the connection and then closed or reset it mid-handshake. A plaintext service on a TLS port, a protocol version the server refuses, and a middlebox cutting the connection all do this.",
		steps: []string{
			"Confirm the port is meant to speak TLS at all.",
			"Check whether an inspecting firewall or proxy sits in front of it.",
		},
		expect: "A completed handshake, or a confirmed plaintext service on that port.",
	},
	{id: DiagnosisTLSTCPUnreachable}: {
		id:     RemedyRetryTLSDial,
		action: "Retest, since the TLS check could not open its own connection",
		why:    "The handshake never started because its connection to the port failed, which points at an intermittent path or an endpoint dropping connections rather than at anything about TLS.",
		steps: []string{
			"Retest to see whether the failure is intermittent.",
			"Check the endpoint's own health if it keeps happening.",
		},
		expect: "A connection that stays open long enough to attempt a handshake.",
	},
	{id: DiagnosisTLSHandshakeFailure}: {
		id:     RemedyNarrowTLSFailure,
		action: "Narrow the handshake failure down by hand",
		why:    "The handshake failed in a way this client could not classify, so netdoc will not name a cause. A bad or expired certificate, an intercepting proxy, and a wrong clock are all still on the table.",
		steps: []string{
			"Check this machine's clock, since a wrong one breaks validation on its own.",
			"Compare the result from another network, which is what separates an interception from a server-side problem.",
		},
		command: showClock,
		expect:  "Enough evidence to tell an interception from a certificate problem.",
	},

	// The application on top of a working connection.
	{id: DiagnosisHTTPSNoResponse}: noHTTPResponse,
	{id: DiagnosisHTTPNoResponse}:  noHTTPResponse,
	{id: DiagnosisServiceBannerFailure}: {
		id:     RemedyCheckBannerService,
		action: "Check the service behind the open port",
		why:    "The connection was accepted and the banner exchange failed, so the port is open and the service behind it is not answering the way that protocol expects.",
		steps: []string{
			"Confirm the port really carries this protocol, since a different service on it fails the same way.",
			"Check the service's own logs for the connection.",
		},
		expect: "A protocol banner from the service on connect.",
	},
	{id: DiagnosisServiceBannerMissing}: {
		id:     RemedyIdentifyListener,
		action: "Confirm which service is on that port",
		why:    "SSH and SMTP both speak first, so a connection that is accepted and then stays silent suggests something else is listening, or something in front accepted the connection on the service's behalf.",
		steps: []string{
			"Check what is bound to that port on the far end.",
			"Look for a load balancer or port forward that accepts connections before the service does.",
		},
		expect: "The protocol's own banner arriving right after the connect.",
	},

	// What a --check or --skip selection can leave behind.
	{id: DiagnosisSelectedDNSCheckFailed}:     selectionTooNarrow,
	{id: DiagnosisSelectedServiceCheckFailed}: selectionTooNarrow,
	{id: DiagnosisSelectedNetworkCheckFailed}: selectionTooNarrow,
}
