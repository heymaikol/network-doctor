package simulation

import (
	"slices"
	"strconv"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// The name the player is asked about.
//
// A challenge base names its target in its own YAML (example.test,
// secure-target.test, subnet-target.test) which made the hostname a fingerprint
// of the base rather than a property of the challenge. Seeing secure-target.test
// told a returning player they were on tls-valid, which is most of the way to
// the answer for two of the conditions, and the base is precisely what the
// briefing is not allowed to disclose.
//
// So the target gets a name of its own, derived from the id and nothing else:
// deterministic, unique to the challenge, identical on replay, and carrying no
// information about the base, the case or the fault. It is a real part of the
// simulated network: the rename goes through the DNS zone the node's resolver
// serves, through the certificates that have to cover it, and through the target
// the graded netdoc run is handed, so nothing about it can disagree with the
// evidence.

// challengeHostSuffix is the reserved TLD RFC 6761 set aside for exactly this:
// a name that no public resolver may ever answer, so the zone is answerable
// inside the simulation and nowhere else. It is also what every base scenario
// already uses, so a challenge host is the same kind of name as the rest of the
// simulated network rather than a new convention beside it.
//
// Deliberately not a `.challenge.test` label, tempting as it is to say so out
// loud. The primary target is passed to the graded netdoc run as its argument,
// and TestRunChallengeOrderAndNetdocArguments exists to keep the simulator from
// handing that process any token telling it a challenge is happening. What marks
// the name as this challenge's is the id in it, which the player is holding
// anyway.
const challengeHostSuffix = ".test"

// challengeHostWords are the service-ish names a challenge target is drawn
// from, so the thing under investigation reads like something an organisation
// would run. Ordered API: the word is picked by index, so reordering this list
// renames every existing challenge's host.
//
// Deliberately none of them names a network layer, a protocol or a failure
// mode. A host called `dns-gateway` would be a hint, and a host called
// `broken-thing` would be two.
var challengeHostWords = []string{
	"ledger", "invoices", "payroll", "intranet",
	"wiki", "tickets", "inventory", "timesheets",
	"dashboard", "registry", "backups", "metrics",
	"reports", "orders", "catalog", "helpdesk",
}

// challengeHostname is the name this challenge's target answers to. The id is
// the only input, and the id is already in the briefing, so the name discloses
// nothing the player was not handed anyway.
func challengeHostname(id string) string {
	_, digits, _ := strings.Cut(id, "-")
	digits = strings.ToLower(digits)
	value, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		// Unreachable through BuildChallenge: NormalizeChallengeID has already
		// rejected anything that is not hex. Falling back to the first word keeps
		// this total rather than panicking on a caller that skipped it.
		value = 0
	}
	return challengeHostWords[value%uint64(len(challengeHostWords))] + "-" + digits + challengeHostSuffix
}

// challengeFixtureHosts are the names netdoc's own connectivity probes dial.
// They belong to the probe fixtures rather than to the challenge target, and
// renaming one would break the measurement every scenario depends on.
var challengeFixtureHosts = []string{proxyCONNECTTarget, diagnostic.EncryptedDNSHost}

// nameChallengeTarget renames the primary test's host to this challenge's own
// name, everywhere the simulated network spells it. It reports the new host, or
// "" when the primary test has no hostname to rename, such as a test pointed at an IP
// literal, or one with no target at all, which is the client's own connectivity
// and names nothing.
//
// Every occurrence moves together. A rename that reached the zone but not the
// certificate would invent a hostname mismatch, and one that reached the zone
// but not the test target would point both contestants at a name nothing serves.
func nameChallengeTarget(s *Scenario, id string) string {
	primary, ok := primaryTest(s)
	if !ok || primary.Target == "" {
		return ""
	}
	parsed, err := diagnostic.ParseTarget(primary.Target)
	if err != nil || parsed.IP != nil {
		return ""
	}
	from := parsed.Host
	if slices.Contains(challengeFixtureHosts, dnsKey(from)) {
		return ""
	}
	to := challengeHostname(id)
	renameScenarioHost(s, from, to)
	return to
}

// challengeTargetHost is the bare name out of a briefed target, for the tools
// that want a host rather than a URL: dig, ping, host. It falls back to the
// whole target rather than to nothing, because a target this cannot parse is
// still the string the player was shown.
func challengeTargetHost(target string) string {
	parsed, err := diagnostic.ParseTarget(target)
	if err != nil {
		return target
	}
	return parsed.Host
}

// renameScenarioHost rewrites one hostname through every place a scenario can
// spell it: the zones and records a simulated resolver answers from, the
// certificates a TLS or QUIC service presents, and the targets the tests dial.
func renameScenarioHost(s *Scenario, from, to string) {
	key := dnsKey(from)
	for ni := range s.Topology.Nodes {
		node := &s.Topology.Nodes[ni]
		for si := range node.Services {
			service := &node.Services[si]
			for name, address := range service.Zone {
				if dnsKey(name) == key {
					delete(service.Zone, name)
					service.Zone[to] = address
				}
			}
			for ri := range service.Records {
				if dnsKey(service.Records[ri].Name) == key {
					service.Records[ri].Name = to
				}
			}
			if service.Certificate == nil {
				continue
			}
			for di, name := range service.Certificate.DNSNames {
				if dnsKey(name) == key {
					service.Certificate.DNSNames[di] = to
				}
			}
		}
	}
	for ti := range s.Tests {
		test := &s.Tests[ti]
		parsed, err := diagnostic.ParseTarget(test.Target)
		if err != nil || parsed.IP != nil || dnsKey(parsed.Host) != key {
			continue
		}
		test.Target = strings.Replace(test.Target, parsed.Host, to, 1)
		// A name Validate generated from the target still spells the old host, and
		// the report prints it. Clearing it has Validate derive it again; an
		// authored name is left alone, because it describes the test rather than
		// repeating the target.
		if strings.Contains(dnsKey(test.Name), key) {
			test.Name = ""
		}
	}
}
