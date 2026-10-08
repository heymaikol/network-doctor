package diagnostic

import (
	"slices"
	"strings"
)

// Explanation is the diagnosis retold for a reader with no networking
// vocabulary: what is wrong, what that means, and the one low-risk thing worth
// trying first. It is a view of Interpret's answer, never a second opinion, so
// the plain sentence and the technical one below it are always about the same
// finding.
//
// It is presentation text for the interactive answer block. Nothing
// machine-readable carries it, and nothing should branch on it: scripts keep
// reading the verdict and the finding IDs.
type Explanation struct {
	// Headline says whether something is wrong and which part, in words a
	// reader without networking vocabulary already has.
	Headline string
	// Meaning is what the headline means for the reader, one or two
	// sentences. It says so when the run could not establish a cause.
	Meaning string
	// TryFirst is the lowest-risk first step the evidence supports, and empty
	// where none is warranted: a working connection, or a fault on someone
	// else's side that the reader cannot act on.
	TryFirst string
	// Unexplained counts failed checks this conclusion does not account for,
	// so a reader is not told about one problem when the run saw several.
	Unexplained int
}

// plainText is one row of the table below. {host} is replaced with the target
// host, which is only ever used by identities a targeted run can produce.
type plainText struct{ headline, meaning, try string }

// Shared rows, for identities that differ only in the technical detail a
// beginner cannot act on.
var (
	plainOffline = plainText{
		"This computer cannot reach the internet",
		"It is on a network, but nothing Network Doctor tried outside that network answered.",
		plainTryOffline,
	}
	plainTLS = plainText{
		"The secure connection to {host} failed",
		"Network Doctor reached {host}, but setting up the encrypted connection that websites and apps use did not complete. The site, a filter on this network, or security software on this computer could each cause this.",
		"Try {host} from a different network, such as a phone hotspot, to see whether the problem follows the site or this network.",
	}
	plainCertDistrust = "Do not click past security warnings for {host}. Try it from a different network, such as a phone hotspot, to see whether the problem follows the site or this network."
	plainNoReply      = plainText{
		"{host} connected but did not reply",
		"The connection worked, but the service at {host} did not send back an answer. That points to the service itself, or to a filter between you and it, rather than to your internet connection.",
		"Try again in a few minutes, and check whether {host} is down for other people too.",
	}
	plainSelected = plainText{
		"A check you selected failed",
		"Only some checks ran, so the ones that would explain this failure were never made.",
		"Run Network Doctor again without --check or --skip for a full diagnosis.",
	}
)

const (
	plainTryOffline = "Check whether other devices on this network can get online. If they cannot either, restarting the router or modem is a reasonable first step."
	plainDNSMeaning = "This computer's name lookup service (DNS), which turns names like example.com into the addresses computers connect to, could not find an address for {host}."
	plainTryDNSName = "Check that the name is spelled correctly. If it is, restarting the router is a reasonable next step if it provides name lookups for this network, as most home routers do."
	plainTryDNS     = "Restarting the router is a reasonable first step if it provides name lookups for this network, as most home routers do. If a VPN is on, try disconnecting it briefly."
)

// plainTexts is the whole table, one entry per diagnosis identity.
// TestEveryDiagnosisIDHasAnExplanation keeps it total.
var plainTexts = map[DiagnosisID]plainText{
	DiagnosisNoUsableInterface: {
		"This computer is not connected to a network",
		"No network connection is active, so nothing can reach the internet or other devices.",
		"Turn Wi-Fi on and join your network, or check that the network cable is plugged in at both ends.",
	},
	DiagnosisCaptivePortal: {
		"This network wants you to sign in first",
		"Something on this network is intercepting web traffic, the way hotel, airport, and cafe Wi-Fi does until you accept its terms or log in. Nothing else can be tested until then.",
		"Open a web browser, visit any website, and complete the sign-in page that appears.",
	},
	DiagnosisOffline:                 plainOffline,
	DiagnosisReachabilityUnlocalized: plainOffline,
	DiagnosisLocalEgressFailure: {
		"This computer cannot reach the internet",
		"Nothing outside this network answered, and this computer's own network settings show a problem with its route out.",
		"Disconnect and reconnect this computer's Wi-Fi or cable. If a VPN is on, reconnect it or turn it off briefly.",
	},
	DiagnosisDirectEgressBlocked: {
		"Direct internet connections are blocked",
		"Website names can be looked up, but Network Doctor's test connections to the internet were blocked. Some work and school networks only allow internet access through a proxy (a go-between server) or a filter.",
		"If this is a work or school network, ask its IT staff whether internet access needs a proxy.",
	},
	DiagnosisDirectEgressDegraded: {
		"The internet connection works, with a warning",
		"Connections get through, but one of Network Doctor's internet tests reported a problem, such as slowness or one of the two kinds of internet address (IPv4 and IPv6) not working. It matters only if it matches what you are experiencing.",
		"",
	},
	DiagnosisReferenceEgressUnreachable: {
		"The internet works, but Network Doctor's own test sites did not answer",
		"What you asked Network Doctor to test was reachable, so your connection works. Only the fixed test sites it uses for its general internet check did not answer, which may be a filter on this network.",
		"",
	},
	DiagnosisProxyOnlyNetwork: {
		"This network allows internet access only through a proxy",
		"A proxy is a go-between server that some work and school networks require. Direct connections are blocked, but the proxy this computer is set to use works, so apps that use it should work.",
		"If an app cannot connect, check that it is set to use the system's proxy settings.",
	},
	DiagnosisProbablePathMTU: {
		"Larger transfers are getting stuck on the way to {host}",
		"Network Doctor can connect, but bigger pieces of data stall, which makes pages and downloads hang. A VPN or a router setting (the packet size, called MTU) is a common cause.",
		"If a VPN is on, disconnect it briefly and see whether the problem goes away.",
	},

	DiagnosisSystemDNSFailure: {
		"Website names are not being found",
		"This computer's name lookup service (DNS), which turns names like example.com into the addresses computers connect to, is failing, while a public lookup service found the name. The problem is the lookup service this computer is set to use.",
		plainTryDNS,
	},
	DiagnosisDNSFailure:             {"Website names are not being found", plainDNSMeaning, plainTryDNSName},
	DiagnosisSelectedDNSCheckFailed: plainSelected,
	DiagnosisDNSNameNotFound: {
		"That name does not exist",
		"Both this computer's name lookup service and a public one say there is no such name, so the name itself is the problem, not your connection.",
		"Check the spelling of the name.",
	},
	DiagnosisDNSDisagreement: {
		"Name lookups give different answers",
		"This computer's name lookup service and a public one returned different addresses for the same name. That is normal on some work networks and VPNs, but lookups can also be filtered or redirected.",
		"If you are not on a VPN or a work network, try the same site from a different network, such as a phone hotspot.",
	},
	DiagnosisEncryptedDNSUnavailable: {
		"Private name lookups are not available",
		"Ordinary name lookups work. The encrypted kind, which some browsers and apps prefer for privacy, could not be completed, and those apps normally fall back to the ordinary kind on their own.",
		"",
	},
	DiagnosisQUICUnavailable: {
		"A faster connection method is blocked",
		"Normal connections work. A newer method that some browsers and apps prefer (QUIC) is blocked, so they fall back to the older one, which may feel a little slower.",
		"",
	},
	DiagnosisProxyFailure: {
		"The proxy this computer is set to use is not working",
		"Direct connections work, but the proxy (a go-between server) configured on this computer failed, so apps that send their traffic through it will not connect.",
		"If you do not know why a proxy is set, ask whoever set up this computer. At work or school, ask IT.",
	},

	DiagnosisTCPConnectionRefused: {
		"{host} is turning connections away",
		"Network Doctor reached {host}, but it refused the connection. The service may not be running there, or it may use a different port (the number after the colon).",
		"If you run this service, check that it is started. Otherwise the problem is on its side, not with your connection.",
	},
	DiagnosisTargetUnreachable: {
		"{host} did not answer",
		"Your internet connection works and the name was found, but {host} did not respond. The problem may be on its side or somewhere along the way.",
		"Try again in a few minutes, and check whether {host} is down for other people too.",
	},
	DiagnosisLocalDeviceUnreachable: {
		"The device at {host} did not answer",
		"Your internet connection works, but this device on your local network did not respond. It may be off, asleep, disconnected, or now using a different address.",
		"Check that the device is turned on and connected to the same network as this computer.",
	},
	DiagnosisReachabilityUntested: {
		"{host} did not answer",
		"The general internet connection was not tested in this run, and that is what would show whether the problem is on this side or on {host}'s side.",
		"Run Network Doctor again with all checks enabled so it can tell the two apart.",
	},
	DiagnosisIPv4TargetUnreachable: {
		"{host} works one way but not the other",
		"Computers connect using two kinds of internet address, the older IPv4 and the newer IPv6. {host} answered over IPv6 but not over IPv4. Most apps switch to the working kind on their own, though some may connect slowly.",
		"",
	},
	DiagnosisIPv6TargetUnreachable: {
		"{host} works one way but not the other",
		"Computers connect using two kinds of internet address, the older IPv4 and the newer IPv6. {host} answered over IPv4 but not over IPv6. Most apps switch to the working kind on their own, though some may connect slowly.",
		"",
	},
	DiagnosisPartialReachability: {
		"{host} only partly answered",
		"Some of the addresses behind this name answered and others did not. Apps usually try another address, but connections may be slow or fail now and then.",
		"",
	},
	DiagnosisUncorroboratedEndpointFailure: {
		"The addresses this computer was given did not answer",
		"This computer's name lookup service gave addresses that did not answer, while a public lookup service gave different ones that this run did not try.",
		"",
	},

	DiagnosisTLSCertificateExpired: {
		"{host}'s security certificate looks expired",
		"A certificate is how a site proves it is genuine. This computer judged this one to be expired according to its current date and time. If this computer's clock is correct, the certificate needs to be renewed by whoever runs {host}.",
		"Check that this computer's date and time are correct. If they are, do not click past security warnings for {host}, and let whoever runs it know its certificate has expired.",
	},
	DiagnosisTLSCertificateNotYetValid: {
		"{host}'s security certificate is not valid yet",
		"A certificate is how a site proves it is genuine. This one is dated in the future, which usually means a setup mistake on {host}, or a wrong clock on this computer.",
		"Check that this computer's date and time are correct.",
	},
	DiagnosisTLSHostnameMismatch: {
		"{host}'s security certificate is for a different name",
		"A certificate is how a site proves it is genuine. This one belongs to a different name, so this computer cannot confirm it is talking to the real {host}. That can be a setup mistake on the site, or something on this network intercepting the connection.",
		plainCertDistrust,
	},
	DiagnosisTLSUntrustedIssuer: {
		"This computer does not trust {host}'s security certificate",
		"A certificate is how a site proves it is genuine. This one was not issued by anyone this computer trusts. Some work networks inspect secure traffic this way, but it can also mean the connection is being intercepted.",
		plainCertDistrust,
	},
	DiagnosisTLSClockSkew: {
		"This computer's clock is wrong",
		"Secure connections check the date, and this computer's clock is far enough off that the secure connection to {host} fails.",
		"Set this computer's date and time to update automatically, then try again.",
	},
	DiagnosisTLSTimeout:          plainTLS,
	DiagnosisTLSConnectionClosed: plainTLS,
	DiagnosisTLSTCPUnreachable:   plainTLS,
	DiagnosisTLSHandshakeFailure: plainTLS,

	DiagnosisHTTPSNoResponse: plainNoReply,
	DiagnosisHTTPNoResponse:  plainNoReply,
	DiagnosisHTTPConnectionClosed: {
		"{host} hung up without replying",
		"The connection worked, but the service at {host} ended it before sending a web response. That points to the service itself, or to something in front of it, rather than to your internet connection.",
		"Check that the address and port are the right ones for this website.",
	},
	DiagnosisInvalidHTTPResponse: {
		"{host} replied, but not in a form this computer understands",
		"The connection worked and the service at {host} sent something back, but it was not a proper web response. That points to the service itself, or to something in front of it, rather than to your internet connection.",
		"Check that the address and port are the right ones for this website.",
	},
	DiagnosisServiceBannerFailure:       plainNoReply,
	DiagnosisServiceBannerMissing:       plainNoReply,
	DiagnosisSelectedServiceCheckFailed: plainSelected,
	DiagnosisSelectedNetworkCheckFailed: plainSelected,
}

// Explain retells the run's diagnosis in plain language. It reads Interpret's
// answer and adds only what that answer already establishes: whether the
// internet was reachable beside a name lookup failure, how certain the finding
// is, and how many failures it leaves unexplained.
func Explain(t *Target, order []ProbeID, res map[ProbeID]ProbeResult) Explanation {
	if len(order) == 0 {
		return Explanation{Headline: "No checks were run"}
	}
	return Interpret(t, order, res).Explain(t, order, res)
}

// Explain retells this diagnosis without interpreting the same inputs again.
func (d Diagnosis) Explain(t *Target, order []ProbeID, res map[ProbeID]ProbeResult) Explanation {
	if len(order) == 0 {
		return Explanation{Headline: "No checks were run"}
	}
	if len(d.Findings) == 0 {
		switch d.Verdict {
		case VerdictIncomplete:
			return Explanation{Headline: "The checks have not finished"}
		case VerdictDegraded:
			return Explanation{
				Headline: "Working, with some warnings",
				Meaning:  "Nothing failed, but some checks reported a problem. It matters only if it matches what you are experiencing.",
			}
		case VerdictNetwork:
			return Explanation{
				Headline: "Target reachability is unknown",
				Meaning:  "The connection check failed, but some addresses for this target were not tested. This run cannot tell whether the target can be reached.",
			}
		}
		// No failure, warning or unfinished check remains.
		return Explanation{
			Headline: "No obvious problem found",
			Meaning:  "Network Doctor did not find a problem with this connection. That does not guarantee every app or website will work.",
		}
	}
	f := d.Findings[0]
	text := plainTexts[f.ID]
	e := Explanation{Headline: text.headline, Meaning: text.meaning, TryFirst: text.try}
	// Uncorroborated findings about the QUIC row are about a sibling path,
	// not the target, and the connection itself works.
	if f.ID == DiagnosisUncorroboratedEndpointFailure && f.Focus == ProbeQUIC {
		e = Explanation{
			Headline: "A faster connection method may be blocked",
			Meaning:  "Normal connections work. A newer method some apps prefer (QUIC) failed, but only against addresses this computer's name lookup service gave, not the different ones a public lookup service gave.",
		}
	}
	// Plain HTTP failing beside working HTTPS is the old address alone.
	if f.ID == DiagnosisHTTPNoResponse && res[ProbeHTTPS].Status == StatusPass {
		e = Explanation{
			Headline: "{host} works, but its unencrypted web address does not reply",
			Meaning:  "Secure (https://) connections to {host} work. Only the older, unencrypted http:// address did not reply, which matters only for links or apps that still use it.",
			TryFirst: "Use the https:// address.",
		}
	}
	// Without a target the name is Network Doctor's own test name, which the
	// reader neither typed nor can respell.
	if f.ID == DiagnosisDNSNameNotFound && t == nil {
		e = Explanation{
			Headline: "Name lookups are not finding a name that should exist",
			Meaning:  "Both this computer's name lookup service and a public one say Network Doctor's test name does not exist. Lookups may be filtered on this network.",
		}
	}
	// The name lookup identities say nothing about the path under them, and
	// what to try first depends on it: a resolver on a working connection is
	// its own problem, one on a dead connection is probably a symptom.
	if f.ID == DiagnosisDNSFailure || f.ID == DiagnosisSystemDNSFailure || f.ID == DiagnosisDNSNameNotFound {
		switch r, ok := res[ProbeInternet]; {
		case directEgressOK(res):
			if f.ID != DiagnosisDNSNameNotFound {
				e.Meaning += " Your internet connection itself works."
			}
		case ok && r.Status == StatusFail:
			e.Meaning += " Network Doctor's test connections to the internet failed too, so the connection itself may be down."
			e.TryFirst = plainTryOffline
		case ok && r.downgraded:
			// A proxy-only network: the direct path is closed by design and
			// the proxy carries traffic, so the router is not the suspect.
			e.Meaning += " This network allows internet access only through a proxy (a go-between server)."
			e.TryFirst = "If this is a work or school network, ask its IT staff."
		}
	}
	switch f.Confidence {
	case ConfidenceLow:
		e.Meaning += " Network Doctor could not pin down the exact cause."
	case ConfidenceInsufficientEvidence:
		e.Meaning += " Network Doctor does not have enough evidence to say why."
	}
	// Without a target the only name looked up is Network Doctor's own test
	// name, so there is nothing for the reader to respell either.
	host := "the name it tested"
	if t != nil {
		host = t.Host
	} else if e.TryFirst == plainTryDNSName {
		e.TryFirst = plainTryDNS
	}
	for _, s := range []*string{&e.Headline, &e.Meaning, &e.TryFirst} {
		*s = strings.ReplaceAll(*s, "{host}", host)
	}
	collateral := d.Collateral(order, res)
	explained := f.EvidenceRows()
	for _, id := range order {
		if r, ok := res[id]; ok && r.Status == StatusFail && id != d.Blamed && !collateral[id] && !slices.Contains(explained, id) {
			e.Unexplained++
		}
	}
	return e
}
