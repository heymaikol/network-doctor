package simulation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// Challenge Mode is the human-facing counterpart to the hunt. The simulator
// breaks a network, a person investigates it with ordinary tools and commits to
// a structured diagnosis, and only then does the real netdoc get its turn at
// the same live network. Both answers are graded against the same independently
// observed simulator truth, so neither contestant can move the answer key.
//
// This file is the domain model: identity, generation, truth and scoring. It
// knows nothing about terminals; challenge_run.go runs one against a backend,
// and cmd/netdoc-sim/challenge.go is the interaction.

const (
	// ChallengeIDVersion is the version new ids are minted with. It is part of
	// the id itself, not a note about it: an id names the generation rules that
	// resolve it, so a future change to selection adds a version instead of
	// quietly repointing every id that has already been shared.
	ChallengeIDVersion = "V4"
	challengeIDDomain  = "netdoc-sim-challenge"
	// challengeIDDigits is the width of a shareable challenge id, in hex digits.
	challengeIDDigits = 6
	// challengeSearchLimit bounds the deterministic scan an id makes for a
	// case whose single mutation is challenge-capable.
	challengeSearchLimit = 200
	// challengeIDSearchLimit bounds the scan for an id of a requested
	// difficulty. Difficulty is a property of the case behind an id, so the only
	// way to honour a request is to look at ids until one carries it.
	challengeIDSearchLimit = 500
	// challengeHealthyOdds gives one challenge in this many no injected fault at
	// all. "Nothing is wrong with this network" has to be a real possibility, or
	// the game teaches people to always find something.
	challengeHealthyOdds = 6
)

// Difficulty levels. A level is reviewed metadata on a challenge family, not a
// score computed from the topology: it says how directly the symptoms expose
// the fault, whether the families differ, and how many plausible competing
// diagnoses the evidence leaves open.
const (
	DifficultyEasy   = "easy"
	DifficultyMedium = "medium"
	DifficultyHard   = "hard"
)

// ChallengeDifficulties is ordered API.
var ChallengeDifficulties = []string{DifficultyEasy, DifficultyMedium, DifficultyHard}

// ChallengeAnswer is one entry in the structured diagnosis vocabulary both
// contestants are graded against. Scoring never reads free text.
type ChallengeAnswer string

const (
	AnswerHealthy           ChallengeAnswer = "healthy"
	AnswerDNSFailure        ChallengeAnswer = "dns_failure"
	AnswerNoDefaultRoute    ChallengeAnswer = "no_default_route"
	AnswerWrongDefaultRoute ChallengeAnswer = "wrong_default_route"
	AnswerMissingRoute      ChallengeAnswer = "missing_subnet_route"
	AnswerPreferredRoute    ChallengeAnswer = "preferred_route_failure"
	AnswerIPv4Failure       ChallengeAnswer = "ipv4_failure"
	AnswerIPv6Failure       ChallengeAnswer = "ipv6_failure"
	AnswerPortBlocked       ChallengeAnswer = "tcp_port_blocked"
	AnswerRefused           ChallengeAnswer = "connection_refused"
	AnswerReset             ChallengeAnswer = "connection_reset"
	AnswerTLSCertificate    ChallengeAnswer = "tls_certificate"
	AnswerTLSHostname       ChallengeAnswer = "tls_hostname_mismatch"
	AnswerHTTPService       ChallengeAnswer = "http_service"
	AnswerProxy             ChallengeAnswer = "proxy_failure"
	AnswerQUICBlocked       ChallengeAnswer = "quic_udp_blocked"
	AnswerPacketLoss        ChallengeAnswer = "packet_loss"
)

// ChallengeAnswerInfo is one menu entry: the internal identity, the name a
// person reads, and the words a person is allowed to type for it.
//
// ID and Label are deliberately separate. ID is what a saved result, a
// recognizer table and a script are keyed by, so it may never change; Label is
// prose aimed at whoever is reading the menu, so it may be reworded whenever it
// reads badly. Using the label as the key would make every wording improvement a
// breaking change to the JSON.
type ChallengeAnswerInfo struct {
	ID    ChallengeAnswer `json:"id"`
	Label string          `json:"label"`
	Help  string          `json:"help,omitempty"`
	// Aliases are the extra spellings ChallengeAnswerByName accepts. Each one is
	// a deliberate choice, not a fuzzy match: the shorthand a person types at a
	// terminal, and the term they would have used if this taxonomy had split the
	// condition more finely than it does. They are matched whole, never as a
	// prefix or a substring, because an answer selected by resemblance is a
	// diagnosis nobody committed to.
	Aliases []string `json:"aliases,omitempty"`
}

// ChallengeAnswerMenu is ordered API. Every entry but the last three is a fault
// a challenge can be set on; those three stay listed because a menu of only the
// possible faults would be most of the answer, and each one is excluded for a
// reason written down next to challengeConditions.
//
// The help text is the part a player actually reads, so where two answers sit
// next to each other it says what separates them rather than what they have in
// common: refused against blocked, no default route against a wrong one,
// expired against a name mismatch.
var ChallengeAnswerMenu = []ChallengeAnswerInfo{
	{ID: AnswerHealthy, Label: "Nothing is wrong with this network",
		Help: "every layer works; the reported problem is elsewhere", Aliases: []string{"ok", "none", "nothing"}},
	{ID: AnswerDNSFailure, Label: "DNS resolution",
		Help: "names do not resolve, or the resolver refuses",
		// One answer covers a refusing resolver and a silent one, because
		// challengeRecognition asks netdoc one question about both; see the note
		// there. A player who reasoned their way to either specific spelling has
		// named this condition, so both spellings are accepted for it rather than
		// rejected for being more precise than the taxonomy.
		Aliases: []string{"dns", "nxdomain", "dns_timeout", "servfail"}},
	{ID: AnswerNoDefaultRoute, Label: "No default route",
		Help:    "the routing table has no default at all, so nothing off-link can be reached",
		Aliases: []string{"no_route"}},
	{ID: AnswerWrongDefaultRoute, Label: "Wrong default route",
		Help:    "there is exactly one default route, its gateway answers, and it goes somewhere that cannot reach the internet",
		Aliases: []string{"bad_gateway", "wrong_gateway"}},
	{ID: AnswerMissingRoute, Label: "Missing route to the target's subnet",
		Help:    "the internet is fine; what is missing is the specific route the target's network needs",
		Aliases: []string{"missing_route"}},
	{ID: AnswerPreferredRoute, Label: "Failed preferred route",
		Help:    "two defaults exist and the lower-metric one is selected, but only the other one's path works",
		Aliases: []string{"preferred_route"}},
	{ID: AnswerIPv4Failure, Label: "IPv4 connectivity",
		Help: "the IPv4 path is down while IPv6 works", Aliases: []string{"ipv4"}},
	{ID: AnswerIPv6Failure, Label: "IPv6 connectivity",
		Help: "the IPv6 path is down while IPv4 works", Aliases: []string{"ipv6"}},
	{ID: AnswerPortBlocked, Label: "TCP port blocked",
		Help:    "connections to the target port are silently discarded, so they time out",
		Aliases: []string{"port_blocked", "blocked", "filtered"}},
	{ID: AnswerRefused, Label: "Connection refused",
		Help:    "the host answers the connection immediately with a refusal, because nothing is listening",
		Aliases: []string{"refused"}},
	{ID: AnswerReset, Label: "Connection reset by the service",
		Help: "the target accepts the connection and then tears it down", Aliases: []string{"reset"}},
	{ID: AnswerTLSCertificate, Label: "Expired TLS certificate",
		Help:    "the handshake fails because the certificate is outside its validity dates",
		Aliases: []string{"tls_expired", "expired_certificate"}},
	{ID: AnswerTLSHostname, Label: "TLS certificate name mismatch",
		Help:    "the certificate is valid and trusted, but not for the name that was requested",
		Aliases: []string{"tls_hostname", "hostname_mismatch"}},
	{ID: AnswerHTTPService, Label: "HTTP service error",
		Help: "the server answers, with an error status", Aliases: []string{"http_error"}},
	{ID: AnswerProxy, Label: "Proxy", Help: "the configured proxy is the thing that fails",
		Aliases: []string{"proxy"}},
	{ID: AnswerQUICBlocked, Label: "QUIC / UDP 443",
		Help: "UDP/443 is filtered while TCP/443 is not", Aliases: []string{"quic"}},
	{ID: AnswerPacketLoss, Label: "Packet loss or latency",
		Help: "the path works but drops or delays traffic", Aliases: []string{"loss", "packet_loss"}},
}

// ChallengeAnswerByID resolves an answer by its internal identity, and only
// that. It is the lookup for a stored answer (a result being reread, a
// recognizer being consulted) where accepting a display name or a shorthand
// would let one answer arrive under two spellings.
func ChallengeAnswerByID(raw string) (ChallengeAnswerInfo, bool) {
	want := ChallengeAnswer(strings.ToLower(strings.TrimSpace(raw)))
	for _, item := range ChallengeAnswerMenu {
		if item.ID == want {
			return item, true
		}
	}
	return ChallengeAnswerInfo{}, false
}

// ChallengeAnswerByName resolves what a person typed: the id, one of the
// deliberate aliases, or the display name itself. Every comparison is on the
// whole string after case and separator normalization, so `dns` selects the DNS
// answer and `dns thing` selects nothing. There is no prefix or substring
// matching on purpose: a diagnosis chosen by resemblance is one the player
// never made, and silently scoring it would be worse than asking again.
func ChallengeAnswerByName(raw string) (ChallengeAnswerInfo, bool) {
	want := normalizeAnswerName(raw)
	if want == "" {
		return ChallengeAnswerInfo{}, false
	}
	for _, item := range ChallengeAnswerMenu {
		if normalizeAnswerName(string(item.ID)) == want || normalizeAnswerName(item.Label) == want {
			return item, true
		}
		for _, alias := range item.Aliases {
			if normalizeAnswerName(alias) == want {
				return item, true
			}
		}
	}
	return ChallengeAnswerInfo{}, false
}

// normalizeAnswerName folds the differences nobody means: case, surrounding
// space, and whether the words were joined with spaces, hyphens or underscores.
// `tcp_port_blocked`, `TCP port blocked` and `tcp-port-blocked` are one answer.
func normalizeAnswerName(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		switch r {
		case ' ', '-', '_':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ChallengeAnswerNames lists every accepted answer id, for a usage message. The
// ids rather than the labels: a message telling somebody what to pass to a flag
// has to name the things that flag accepts unquoted.
func ChallengeAnswerNames() []string {
	out := make([]string, 0, len(ChallengeAnswerMenu))
	for _, item := range ChallengeAnswerMenu {
		out = append(out, string(item.ID))
	}
	return out
}

func challengeAnswerLabel(answer ChallengeAnswer) string {
	if info, ok := ChallengeAnswerByID(string(answer)); ok {
		return info.Label
	}
	return string(answer)
}

// challengeCondition is one condition the simulator can create and then prove,
// from its own observations, that it created. It is eligibility metadata and
// nothing else: every field is a fact about the simulated network, about what
// evidence settles it, or about fairness between the two contestants. Network
// Doctor does not appear here.
//
// Whether netdoc has any way to state this condition lives in a separate table,
// challengeRecognition, which this side never reads. That separation is the
// point. When eligibility and recognition were one struct, a condition could
// not be set as a challenge until somebody had first decided what netdoc ought
// to say about it, which made the game a quiz written from the answer sheet.
type challengeCondition struct {
	// mutation is the hunt mutation id, empty for the healthy challenge.
	mutation    string
	answer      ChallengeAnswer
	difficulty  string
	explanation string
	// requires is the independent observation this condition needs on top of
	// the shared per-mutation evidence check in mutationObserved. nil means that
	// check is the whole requirement. It may only ever narrow: a challenge may
	// demand more evidence than the hunt does, never less, so nothing here can
	// manufacture a fault the hunt would not also have seen.
	requires func(Evidence, GeneratedMutation) bool
	// briefed, when set, is the extra condition that makes a generated case a
	// fair puzzle rather than merely a possible one: it is handed the unmutated
	// base and the mutation, and reports whether the fault sits where the player
	// was pointed. A base with more than one client test can place a service
	// fault on a target the briefing never names: a clue nobody was shown, and a
	// question the graded netdoc run was never asked.
	briefed func(*Scenario, GeneratedMutation) bool
	// signature is this condition's unscoped evidence trace: does the run show a
	// fault of this class anywhere, with no mutation to scope it by. It is
	// required on every condition but the healthy one, and it is what the healthy
	// verdict is derived from; see challenge_truth.go, and
	// TestEveryChallengeConditionCarriesASignature.
	//
	// It is deliberately not the thing that establishes a fault challenge's
	// answer. That stays the scoped pair, mutationObserved plus requires, which
	// knows which node and port were mutated. A signature only has to be
	// sensitive enough that no run carrying this fault can pass for healthy.
	signature challengeSignature
}

// challengeConditions is the challenge contract: the hunt mutations Challenge
// Mode is willing to set as puzzles. A mutation qualifies on four
// simulator-side tests, none of which mentions a diagnosis:
//
//  1. independently observable: the executed run leaves evidence, read back
//     off the wire or off the kernel, that the fault reached live traffic.
//     mutationObserved is that check, narrowed further by requires.
//  2. deterministic and replayable: the same id sets the same puzzle, and the
//     condition either holds for the whole run or does not hold at all.
//  3. same network for both contestants: a person in the shell and the netdoc
//     process must be able to see the same thing.
//  4. inside the diagnostic scope: the condition is a fault of the network
//     itself, the thing Network Doctor exists to name, rather than a fault of
//     an application that the network delivered correctly.
//
// Nothing in that list is "netdoc already recognizes it". A condition netdoc
// has no vocabulary for is deliberately still eligible, and is a loss for
// netdoc rather than a challenge that could never be set; see
// challengeRecognition and docs/simulation-challenge.md#the-challenge-contract.
//
// Ids select through this list, so adding or removing an entry changes what ids
// already in circulation resolve to. That is a new id version, not an edit;
// see challengeGenerators and challengeV1Mutations.
//
// Deliberately absent, and which test each one fails:
//   - every timed family (timeline.*, link.transient_down) fails (2) and (3): a
//     scheduled fault is measured from the instant the first netdoc process
//     starts, so it would be over, or not yet started, while the person was
//     investigating.
//   - netem.latency and netem.jitter fail (1): delay leaves no counter of its
//     own, so the only thing that could establish them is a round-trip sample
//     read back after the run, which is not evidence that the shaper delayed
//     anybody's traffic. netem.loss is in, because the qdisc's own drop counter
//     is exactly that evidence.
//   - http.status_503 and encrypted_dns.doh_invalid fail (4): the network
//     carried the request and carried the answer back. What the answer said is
//     the application's business, and the `http-error` control pins down that
//     netdoc reports the network as working there on purpose.
//   - proxy.connect_refused fails (3): the netdoc process is handed the proxy
//     through its environment and a shell is not.
//   - quic.udp_443_block fails (3): a filtered UDP port and a silent one look
//     identical to the tools in the shell, so the person is left with nothing
//     to reason from while netdoc's QUIC probe measures it directly.
var challengeConditions = []challengeCondition{
	{
		mutation: "", answer: AnswerHealthy, difficulty: "",
		explanation: "Nothing was injected. Every layer the simulator measured (the link, the gateway, name resolution and the path to the controlled endpoints) was working.",
	},
	{
		mutation: "dns.servfail", answer: AnswerDNSFailure, difficulty: DifficultyEasy,
		signature:   signatureDNSFailing,
		explanation: "The client's resolver answered queries with SERVFAIL. Nothing below DNS was touched: the link, the gateway and the path to the target's address kept working.",
	},
	{
		mutation: "dns.drop", answer: AnswerDNSFailure, difficulty: DifficultyEasy,
		signature:   signatureDNSFailing,
		explanation: "The client's resolver silently discarded queries, so name resolution timed out rather than failing fast. Nothing below DNS was touched.",
	},
	{
		mutation: "service.tcp_reset", answer: AnswerReset, difficulty: DifficultyEasy,
		signature:   signatureTCPReset,
		explanation: "The target's service accepted the TCP connection and then reset it. The path to the target is intact: the connection completes before it is torn down.",
		briefed:     resetTargetIsBriefed,
	},
	{
		mutation: "service.tls_expired", answer: AnswerTLSCertificate, difficulty: DifficultyMedium,
		signature:   signatureExpiredCertificate,
		explanation: "The target served an expired certificate and the client refused it. TCP to the port succeeds, so everything below TLS is healthy.",
	},
	{
		mutation: "family.ipv4_drop", answer: AnswerIPv4Failure, difficulty: DifficultyMedium,
		signature:   signatureFamilyUnreachable("ipv4"),
		explanation: "IPv4 forwarding was dropped at the gateway while IPv6 kept working. The client still has an IPv4 address and an IPv4 route. What it does not have is an IPv4 path.",
	},
	{
		mutation: "family.ipv6_drop", answer: AnswerIPv6Failure, difficulty: DifficultyHard,
		signature:   signatureFamilyUnreachable("ipv6"),
		explanation: "IPv6 forwarding was dropped at the gateway while IPv4 kept working. Most traffic still succeeds by falling back to IPv4, which is what makes this one quiet.",
	},
	{
		mutation: "routing.preferred_path_failure", answer: AnswerPreferredRoute, difficulty: DifficultyHard,
		signature:   signatureControlledTargetUnreachable,
		explanation: "The client's lower-metric default route is still selected and its gateway still answers, but that router's own upstream link is down. The higher-metric alternate default remains healthy, which a controlled target on that path proves.",
	},
	{
		mutation: "netem.loss", answer: AnswerPacketLoss, difficulty: DifficultyMedium,
		signature:   signaturePacketDrops,
		explanation: "A shaper on the path to the internet discarded a percentage of the packets crossing it. Nothing is misconfigured, since addresses, routes, name resolution and every service are intact, and connections that survive the loss still work, which is what makes it read as flaky rather than broken.",
		// The qdisc's own drop counter, not the qdisc being installed with the
		// requested parameters. A shaper that matched no traffic impaired
		// nobody, and this is the only reading that separates the two.
		requires: func(evidence Evidence, m GeneratedMutation) bool {
			return shapedPacketsDroppedAt(evidence, m.Node, m.Segment)
		},
	},
	{
		mutation: "service.connection_refused", answer: AnswerRefused, difficulty: DifficultyEasy,
		signature: signatureControlledTargetRefused,
		explanation: "The target host is up and its port is closed, so it answers the connection with a refusal rather than swallowing it. " +
			"The path is intact: a refusal is something only a reachable host can send.",
	},
	{
		mutation: "service.tcp_port_blocked", answer: AnswerPortBlocked, difficulty: DifficultyMedium,
		signature: signatureInboundTCPDropped,
		explanation: "A filter at the target discarded inbound connections to the port, so they timed out instead of being refused. " +
			"The host itself is up and every other port on it kept working, which is what separates a filtered port from a dead one.",
	},
	{
		mutation: "service.tls_hostname_mismatch", answer: AnswerTLSHostname, difficulty: DifficultyMedium,
		signature: signatureMismatchedCertificate,
		explanation: "The target served a certificate that is currently valid and signed by a trusted issuer, but issued for a different name than the one requested. " +
			"TCP and the handshake up to certificate verification both succeed.",
	},
	{
		mutation: "routing.no_default_route", answer: AnswerNoDefaultRoute, difficulty: DifficultyEasy,
		signature: signatureNoDefaultRoute,
		explanation: "The client's default route was deleted. Its link, its address and anything on its own segment still work; " +
			"what it has lost is any way to a destination that is not on-link.",
	},
	{
		mutation: "routing.wrong_default_route", answer: AnswerWrongDefaultRoute, difficulty: DifficultyHard,
		signature: signatureFamilyUnreachable(""),
		explanation: "The default route was repointed at a second router on the same LAN. That router answers, so the gateway is not unreachable, " +
			"but it has no path to the internet. The original gateway is still up and still forwarding, which a controlled target reached over its own specific route proves.",
	},
	{
		mutation: "routing.missing_subnet_route", answer: AnswerMissingRoute, difficulty: DifficultyHard,
		signature: signatureControlledTargetUnreachable,
		explanation: "The specific route to the target's subnet is gone, so traffic for it falls back to a default route that has no way there. " +
			"Everything the default does cover (the internet, name resolution) kept working, which is what makes this a route-shaped hole rather than an outage.",
	},
}

// challengeRecognition is the contestant's half: what Network Doctor's own
// report has to say for it to have named a condition. It reads one diagnosis
// and nothing else, exactly as the hunt oracle's half does: netdoc is never
// told which condition it is looking at, and never graded on prose.
//
// The map is deliberately partial, and nothing that decides what may be
// generated is allowed to consult it. A condition with no entry is one netdoc's
// vocabulary has no way to express, which scores ChallengeUnrecognized: a loss,
// stated as the distinct thing it is rather than folded into "wrong answer".
//
// Keyed by answer rather than by mutation because recognition is about the
// condition, not about how the simulator produced it: dns.servfail and dns.drop
// are one question to netdoc.
var challengeRecognition = map[ChallengeAnswer]func(*Diagnosis) bool{
	AnswerHealthy:        func(d *Diagnosis) bool { return d.Verdict == diagnostic.VerdictOK },
	AnswerDNSFailure:     flaggedRow(diagnostic.ProbeDNS),
	AnswerRefused:        causeRecognizer(diagnostic.ConnectionCauseRefused),
	AnswerReset:          causeRecognizer(diagnostic.ConnectionCauseReset),
	AnswerTLSCertificate: conditionRecognizer(ConditionTLSCertificateExpired),
	AnswerIPv4Failure:    conditionRecognizer(ConditionIPv4InternetUnreachable),
	AnswerIPv6Failure:    conditionRecognizer(ConditionIPv6InternetUnreachable),
	AnswerTLSHostname:    conditionRecognizer(ConditionTLSHostnameMismatch),
	AnswerNoDefaultRoute: causeRecognizer(diagnostic.RouteCauseNoDefaultRoute),
	// AnswerWrongDefaultRoute and AnswerPreferredRoute have no recognition
	// rule: the report's legacy route-selection causes do not establish either
	// fault, and the simulator's private alternate-path evidence cannot do so
	// on the report's behalf.
	// AnswerPortBlocked and AnswerMissingRoute have no entries. netdoc's target
	// row fails both the same way and carries no cause: a filtered port and a
	// target with no route to it are one sentence to it, and there is no report
	// it could produce that would name either one. Two challenges it is going to
	// lose, stated as the vocabulary gap it is.
	//
	// AnswerPacketLoss has no entry on purpose. netdoc's cause vocabulary
	// carries no impairment verdict at all, so there is no report it could
	// produce that would name observed packet loss, and the `packet-loss` control
	// scenario expects a clean `ok`. A challenge on it is netdoc's to lose.
}

// flaggedRow recognizes a diagnosis by the row it raised its hand on. Used only
// where the row is the whole message: a failing DNS row is netdoc telling the
// user the name did not resolve, and there is no narrower cause to match. The
// probe id comes from the diagnostic constant so a rename stays in step.
func flaggedRow(ids ...diagnostic.ProbeID) func(*Diagnosis) bool {
	return func(d *Diagnosis) bool {
		for _, check := range d.Checks {
			if flagged(check.Status) && slices.Contains(ids, diagnostic.ProbeID(check.ID)) {
				return true
			}
		}
		return false
	}
}

// causeRecognizer recognizes a diagnosis by netdoc's own cause vocabulary,
// which is what the report says about the network rather than which row
// noticed. A cause on a passing row is context, not recognition.
func causeRecognizer(causes ...string) func(*Diagnosis) bool {
	return func(d *Diagnosis) bool { return flaggedCause(d, nil, causes...) }
}

// conditionRecognizer reuses the hunt oracle's recognition half verbatim, so a
// condition the hunt already knows how to grade cannot be graded two ways.
func conditionRecognizer(condition NetworkCondition) func(*Diagnosis) bool {
	for _, rule := range conditionOracle {
		if rule.condition == condition {
			return rule.recognized
		}
	}
	panic("challenge: no oracle rule for condition " + string(condition))
}

// resetTargetIsBriefed reports whether the HTTP target the reset was installed
// on is the one the player is asked about. The generator picks the first test
// with an HTTP target, which on a base with several client tests is not
// necessarily the primary one, and a reset on a target the briefing never
// names is a puzzle with no findable clue whose graded netdoc run never dials
// it.
func resetTargetIsBriefed(base *Scenario, m GeneratedMutation) bool {
	// The same canonical form the generator worked from, so the two are looking
	// at one scenario.
	base = cloneScenario(base)
	canonicalScenarioInput(base)
	primary, ok := primaryTest(base)
	if !ok {
		return false
	}
	target, ok := findHTTPTestTarget(base, []Test{primary})
	return ok && target.node == m.Node && target.port == m.TargetPort
}

func challengeConditionFor(mutation string) (challengeCondition, bool) {
	for _, condition := range challengeConditions {
		if condition.mutation != "" && condition.mutation == mutation {
			return condition, true
		}
	}
	return challengeCondition{}, false
}

func healthyChallengeCondition() challengeCondition {
	for _, condition := range challengeConditions {
		if condition.mutation == "" {
			return condition
		}
	}
	panic("challenge: no healthy condition")
}

// challengeBases are the known-good controls a challenge may be generated from.
// Every one is already a hunt base, so the generator, the mutation registry and
// the observation rules are shared rather than reimplemented.
//
// socks5h-remote-dns-succeeds is left out: its netdoc run is handed a proxy
// through the environment and an investigator's shell is not, so the two
// contestants would not be looking at the same network.
//
// V1 and V2 ids select through this list. Reordering or changing it is a new id
// version; see challengeGenerators.
var challengeBases = []string{"dual-stack-healthy", "healthy", "healthy-routed-network",
	"tls-valid", "two-path-healthy", "two-path-ipv6-healthy"}

// challengeBasesV3 adds the two-router control. V4 and the authored challenges
// draw from it too, so it is the current control set rather than V3's alone. Its client LAN carries a second
// router that answers but goes nowhere, and a target subnet that only a
// specific route reaches, which is what a wrong default route and a missing
// subnet route need to exist at all, since no earlier base could express either.
var challengeBasesV3 = []string{"dual-stack-healthy", "healthy", "healthy-routed-network",
	"tls-valid", "two-path-healthy", "two-path-ipv6-healthy", "two-router-healthy"}

// Challenge is one reproducible puzzle. Everything the player may see before
// they answer is above the line; Base, Seed, Case and Manifest name the case
// and are therefore the answer, so nothing prints them before the reveal.
type Challenge struct {
	ID         string `json:"id"`
	Difficulty string `json:"difficulty"`
	// Node is the node the player investigates from, and Target is what they
	// were asked about. Both come from the scenario's own primary test, so
	// neither is a hint the netdoc run does not also get.
	Node   string `json:"node"`
	Target string `json:"target,omitempty"`
	// Daily is the UTC calendar date this challenge is the daily for, set only
	// when it was selected that way. It is a label on how the player arrived,
	// never an input to generation: the id alone decides the puzzle, and the same
	// id played without -daily is the same network.
	Daily string `json:"daily,omitempty"`

	Base     string                `json:"base_scenario"`
	Seed     int64                 `json:"seed"`
	Case     int                   `json:"case"`
	Manifest GeneratedCaseManifest `json:"manifest"`

	Scenario  *Scenario          `json:"-"`
	condition challengeCondition `json:"-"`
}

// Replay is the command that reproduces this exact challenge.
func (c *Challenge) Replay() string { return challengeCommand() + " -id " + c.ID }

// challengeCommandEnv lets the packaging around this binary say how someone
// should run a challenge. Only the printed invitation changes; nothing here is
// ever executed, and the id, the puzzle and the scoring are untouched by it.
//
// The container image sets it, because a result posted from the image is read
// by people who may have no netdoc-sim and no Linux, so telling them to run
// `netdoc-sim challenge` would be telling them to go install one.
const challengeCommandEnv = "NETDOC_SIM_CHALLENGE_COMMAND"

const defaultChallengeCommand = "netdoc-sim challenge"

// challengeCommandLimit keeps the invitation a one-line command. It is external
// input printed to a terminal and pasted into forums, so it is sanitized and
// bounded like every other untrusted string this package prints.
const challengeCommandLimit = 200

func challengeCommand() string {
	custom := textsafe.Clean(strings.TrimSpace(os.Getenv(challengeCommandEnv)))
	if custom == "" || len(custom) > challengeCommandLimit {
		return defaultChallengeCommand
	}
	return custom
}

// challengeGenerators maps an id version to the selection rules that version
// means. An entry is frozen the moment ids carrying it have been shared:
// changing how a version picks a base, a case or a family repoints every id
// ever published with it, so such a change adds a version here rather than
// editing one. Resolution of an old id then keeps working unchanged.
//
// A version covers the whole chain an id resolves through (this file's
// selection, the hunt generator behind it and the base scenarios it draws
// from) because all three decide what a shared id means.
// TestChallengeIDsResolveToTheSameCaseForever pins that chain.
//
// When a version is justified, and when it is not. A version is the cost of
// keeping a promise, never a place to put new content, so it is added only when
// keeping an existing id pointing where it points leaves no alternative:
//
//   - a new playable diagnosis does NOT need one. A row in challengeConditions
//     reaches V4 generation immediately, and earlier versions skip it through
//     their own frozen lists. See "Adding a new playable diagnosis" in
//     docs/simulation-challenge.md.
//   - a new hand-picked case does NOT need one. Append to authoredChallenges:
//     A1 digits derive from the slug, so the table is append-safe forever and
//     costs no frozen code at all.
//   - bumping HuntGeneratorVersion does NOT force one and does not reach
//     Challenge Mode at all. V3, V4 and A1 name the hunt version they shipped
//     with as a literal, so a bump leaves every published id where it is.
//     Putting a newer hunt generator in front of players is therefore a choice
//     rather than a consequence, and making that choice is what needs a version.
//   - changing how selection itself behaves DOES force one. V4 exists for that
//     reason and no other: V1 to V3 let the search decide the distribution of
//     answers, and fixing that had to repoint ids, so it became a version.
//
// A version copied from the one above it to carry content that the current
// contract already expresses is pure permanent cost. There is no V5 pending,
// and the absence of one is the design working rather than a gap to fill.
var challengeGenerators = map[string]func(id, digits string) (*Challenge, error){
	"V1": buildChallengeV1,
	"V2": buildChallengeV2,
	"V3": buildChallengeV3,
	"V4": buildChallengeV4,
	// Authored ids are a version like any other, so they parse, resolve, replay
	// and share through exactly the same path. Their digits name a case somebody
	// wrote rather than a seed to search from; see challenge_authored.go.
	AuthoredIDVersion: buildChallengeAuthored,
}

// challengeV1Mutations freezes the conditions V1 ids select through. V1 ids are
// in circulation, so this list can never change: a condition added to
// challengeConditions afterwards would repoint every V1 id whose scan used to
// skip that mutation's case. Conditions added later are reachable from V2
// onwards, which is what the version in an id is for.
var challengeV1Mutations = []string{"dns.drop", "dns.servfail", "family.ipv4_drop", "family.ipv6_drop",
	"routing.preferred_path_failure", "service.tcp_reset", "service.tls_expired"}

// challengeV2Mutations is the same freeze one version on: V1 plus netem.loss,
// which is what V2 was published for. It is belt as well as braces, since V2
// also resolves through the v3 hunt generator, which cannot produce a later
// family at all, but the freeze is written down rather than inferred, so a future
// change to either list fails loudly instead of quietly repointing ids.
var challengeV2Mutations = append([]string{"netem.loss"}, challengeV1Mutations...)

func challengeIDVersions() []string {
	out := make([]string, 0, len(challengeGenerators))
	for version := range challengeGenerators {
		out = append(out, version)
	}
	slices.Sort(out)
	return out
}

// NormalizeChallengeID accepts the id in the form a person would type or paste
// it and returns the canonical one, `V1-8F42C1`. It is deliberately strict: an
// id is the whole reproduction contract, so a near miss has to be a rejection
// rather than a different challenge.
//
// A bare `8F42C1` means V1 and always will. Bare was the only form the first
// release published, so re-pointing it at whatever version is current would be
// exactly the silent drift the version prefix exists to prevent.
func NormalizeChallengeID(raw string) (string, error) {
	id := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(raw)), "#")
	version, digits := "V1", id
	if before, after, found := strings.Cut(id, "-"); found {
		version, digits = before, after
	}
	if len(digits) != challengeIDDigits || strings.TrimLeft(digits, "0123456789ABCDEF") != "" {
		return "", fmt.Errorf("a challenge id is %d hex characters after an optional version, like %s-8F42C1, got %q",
			challengeIDDigits, ChallengeIDVersion, id)
	}
	if _, ok := challengeGenerators[version]; !ok {
		return "", fmt.Errorf("challenge id version %q is not one this build can resolve (have: %s)",
			version, strings.Join(challengeIDVersions(), ", "))
	}
	return version + "-" + digits, nil
}

// RandomChallengeID draws a fresh id, at the current version.
func RandomChallengeID() (string, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	value := binary.BigEndian.Uint32(raw[:]) & 0xFFFFFF
	return fmt.Sprintf("%s-%0*X", ChallengeIDVersion, challengeIDDigits, value), nil
}

// challengeSeed derives this id's independent PRNG stream. Every generation
// decision behind an id comes out of this one seed, which is what makes an id
// the whole reproduction contract. The version is in the domain, so the same
// digits under a future version are a different challenge rather than a
// coincidence.
func challengeSeed(version, digits string) int64 {
	h := sha256.New()
	h.Write([]byte(challengeIDDomain))
	h.Write([]byte{0})
	h.Write([]byte(version))
	h.Write([]byte{0})
	h.Write([]byte(digits))
	// #nosec G115 -- all 64 hash bits are intentionally preserved in the signed seed.
	return int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
}

// BuildChallenge resolves an id into the case behind it. It is pure and
// deterministic: the same id builds the same challenge on any machine whose
// build knows that id's version, with no state on disk and no network.
func BuildChallenge(raw string) (*Challenge, error) {
	id, err := NormalizeChallengeID(raw)
	if err != nil {
		return nil, err
	}
	version, digits, _ := strings.Cut(id, "-")
	return challengeGenerators[version](id, digits)
}

// challengeSelection is everything one id version means: which controls it may
// draw from, which hunt generator materializes the case, and which conditions
// it is allowed to set. All three decide what a shared id resolves to, so all
// three are frozen together per version rather than read from whatever the
// current build happens to have.
type challengeSelection struct {
	bases            []string
	generatorVersion string
	selectable       func(string) bool
}

// buildChallengeV1 is the V1 selection. Frozen; see challengeGenerators. It
// sees only the conditions that existed when V1 ids were first published.
func buildChallengeV1(id, digits string) (*Challenge, error) {
	return buildChallengeCase(id, "V1", digits, challengeSelection{
		bases: challengeBases, generatorVersion: "v3",
		selectable: func(mutation string) bool { return slices.Contains(challengeV1Mutations, mutation) },
	})
}

// buildChallengeV2 is V1 plus netem.loss, on the same controls and the same
// hunt generator. Frozen for the same reason.
func buildChallengeV2(id, digits string) (*Challenge, error) {
	return buildChallengeCase(id, "V2", digits, challengeSelection{
		bases: challengeBases, generatorVersion: "v3",
		selectable: func(mutation string) bool { return slices.Contains(challengeV2Mutations, mutation) },
	})
}

// buildChallengeV3 selects from the two-router control and every condition the
// challenge contract admits, including the ones netdoc has no vocabulary for,
// through the v4 hunt generator. Frozen for the same reason, and note that the
// hunt version is the literal V3 shipped with rather than HuntGeneratorVersion:
// the generator behind a published id is part of what that id means, so it has
// to stay where it was even after the hunt generator moves on.
func buildChallengeV3(id, digits string) (*Challenge, error) {
	return buildChallengeCase(id, "V3", digits, challengeSelection{
		bases: challengeBasesV3, generatorVersion: "v4",
		selectable: func(string) bool { return true },
	})
}

// buildChallengeV4 is the current selection, and the first one that chooses what
// the challenge is about before it goes looking for a case to express it.
//
// V1 to V3 draw a base and a case number and accept whatever single mutation
// the hunt generator produces, retrying until one is challenge-capable. That
// makes the distribution of diagnoses an accident of three unrelated things:
// how many mutation variants a family has, how many bases the operator applies
// to, and how often the case scan reaches it first. Measured over V3, it puts
// DNS at roughly 23% and a missing subnet route at under 2%, a sixteenfold
// spread nobody chose, in a game whose whole point is practising the rare ones.
//
// V4 picks the answer first, uniformly over the playable vocabulary, and only
// then looks for a case that sets it. The search is still a search, but it can
// no longer decide what the game is about: it chooses which base and which case
// number express an answer that was already fixed. Rejection affects how long
// resolution takes, never the distribution.
//
// Uniform over answers rather than over mutations, deliberately. dns.servfail
// and dns.drop are one diagnosis to a player, and weighting by mutation is
// exactly the accident this version exists to remove.
//
// The "v4" literals below are the hunt generator V4 ids were minted under, held
// as a literal for the reason given on buildChallengeV3.
func buildChallengeV4(id, digits string) (*Challenge, error) {
	seed := challengeSeed("V4", digits)
	// #nosec G404 -- deterministic challenge selection must reproduce from its public ID.
	rng := mathrand.New(mathrand.NewSource(seed))
	if rng.Intn(challengeHealthyOdds) == 0 {
		base := challengeBasesV3[rng.Intn(len(challengeBasesV3))]
		return healthyChallenge(id, base, seed, "v4",
			ChallengeDifficulties[rng.Intn(len(ChallengeDifficulties))])
	}
	answers := challengePlayableAnswers()
	answer := answers[rng.Intn(len(answers))]
	conditions := challengeConditionsFor(answer)
	condition := conditions[rng.Intn(len(conditions))]
	// Only the bases this condition's operator applies to. Drawing from all of
	// them would spend the search budget on combinations that can never produce
	// the wanted mutation, and would make resolution failure depend on how many
	// unrelated bases happen to exist.
	bases, err := challengeBasesForMutation(condition.mutation)
	if err != nil {
		return nil, fmt.Errorf("challenge %s: %w", id, err)
	}
	if len(bases) == 0 {
		return nil, fmt.Errorf("challenge %s: no challenge base scenario can express %s", id, condition.mutation)
	}
	for attempt := 0; attempt < challengeSearchLimit; attempt++ {
		base := bases[rng.Intn(len(bases))]
		caseNumber := rng.Intn(HuntMaxCaseNumber + 1)
		scenario, err := LibraryScenario(base)
		if err != nil {
			return nil, err
		}
		generated, err := generateHuntCase("v4", base, scenario, seed, caseNumber, 1)
		if err != nil || len(generated.Manifest.Mutations) != 1 {
			continue
		}
		if generated.Manifest.Mutations[0].ID != condition.mutation {
			continue
		}
		if condition.briefed != nil && !condition.briefed(scenario, generated.Manifest.Mutations[0]) {
			continue
		}
		return newChallenge(id, base, seed, caseNumber, condition.difficulty,
			generated.Manifest, generated.Scenario, condition)
	}
	return nil, fmt.Errorf("challenge %s: no case setting %s within %d candidates",
		id, condition.mutation, challengeSearchLimit)
}

// challengeBasesForMutation lists the challenge controls this mutation's
// operator applies to, in challengeBasesV3 order. Derived by asking the
// operator itself, so it cannot fall out of step with the hunt registry the way
// a written-down compatibility list would.
func challengeBasesForMutation(mutation string) ([]string, error) {
	operator, ok := huntOperatorByID("v4", mutation)
	if !ok {
		return nil, fmt.Errorf("hunt generator v4 has no %q operator", mutation)
	}
	var out []string
	for _, name := range challengeBasesV3 {
		scenario, err := LibraryScenario(name)
		if err != nil {
			return nil, err
		}
		canonicalScenarioInput(scenario)
		if operator.applicable(scenario) {
			out = append(out, name)
		}
	}
	return out, nil
}

// buildChallengeCase is the selection every version shares. The selection is
// the only thing a version varies, and every part of it is a question about
// bases and mutation ids. Nothing in this function, or in anything it calls,
// can reach a diagnosis or challengeRecognition. Eligibility is settled before
// Network Doctor exists.
func buildChallengeCase(id, version, digits string, selection challengeSelection) (*Challenge, error) {
	seed := challengeSeed(version, digits)
	// #nosec G404 -- deterministic challenge selection must reproduce from its public ID.
	rng := mathrand.New(mathrand.NewSource(seed))
	if rng.Intn(challengeHealthyOdds) == 0 {
		base := selection.bases[rng.Intn(len(selection.bases))]
		return healthyChallenge(id, base, seed, selection.generatorVersion,
			ChallengeDifficulties[rng.Intn(len(ChallengeDifficulties))])
	}
	for attempt := 0; attempt < challengeSearchLimit; attempt++ {
		base := selection.bases[rng.Intn(len(selection.bases))]
		caseNumber := rng.Intn(HuntMaxCaseNumber + 1)
		scenario, err := LibraryScenario(base)
		if err != nil {
			return nil, err
		}
		// One mutation, always: a challenge with two faults would have two
		// defensible answers and no honest way to score either.
		generated, err := generateHuntCase(selection.generatorVersion, base, scenario, seed, caseNumber, 1)
		if err != nil || len(generated.Manifest.Mutations) != 1 {
			continue
		}
		condition, ok := challengeConditionFor(generated.Manifest.Mutations[0].ID)
		if !ok || !selection.selectable(condition.mutation) {
			continue
		}
		// Asked of the unmutated base, which is where the target the fault
		// replaced is still readable.
		if condition.briefed != nil && !condition.briefed(scenario, generated.Manifest.Mutations[0]) {
			continue
		}
		return newChallenge(id, base, seed, caseNumber, condition.difficulty, generated.Manifest, generated.Scenario, condition)
	}
	return nil, fmt.Errorf("challenge %s: no challenge-capable case within %d candidates", id, challengeSearchLimit)
}

// healthyChallenge is the base scenario with nothing done to it. It carries an
// ordinary manifest with an empty mutation list so the reproduction artifact,
// the fingerprint and the truth rules stay one shape.
func healthyChallenge(id, base string, seed int64, generatorVersion, difficulty string) (*Challenge, error) {
	scenario, err := LibraryScenario(base)
	if err != nil {
		return nil, err
	}
	canonicalScenarioInput(scenario)
	if err := scenario.Validate(); err != nil {
		return nil, fmt.Errorf("challenge base %s: %w", base, err)
	}
	manifest := GeneratedCaseManifest{GeneratorVersion: generatorVersion, BaseScenario: base,
		HuntSeed: seed, Case: -1, CaseSeed: seed, Mutations: []GeneratedMutation{}}
	manifest.CaseFingerprint = huntCaseFingerprint(manifest)
	return newChallenge(id, base, seed, -1, difficulty, manifest, scenario, healthyChallengeCondition())
}

func newChallenge(id, base string, seed int64, caseNumber int, difficulty string,
	manifest GeneratedCaseManifest, scenario *Scenario, condition challengeCondition) (*Challenge, error) {
	// The target gets this challenge's own name before anybody is told what it
	// is. Derived from the id alone, so a replay renames it identically, and
	// applied to the executing scenario rather than to the briefing, so the name
	// the player is given is the name the network answers to.
	if nameChallengeTarget(scenario, id) != "" {
		canonicalScenarioInput(scenario)
		if err := scenario.Validate(); err != nil {
			return nil, fmt.Errorf("challenge %s: naming the target broke the scenario: %w", id, err)
		}
	}
	primary, ok := primaryTest(scenario)
	if !ok {
		return nil, fmt.Errorf("challenge base %s has no client test", base)
	}
	return &Challenge{ID: id, Difficulty: difficulty, Node: primary.Node, Target: primary.Target,
		Base: base, Seed: seed, Case: caseNumber, Manifest: manifest, Scenario: scenario, condition: condition}, nil
}

// primaryTest is the run the player is asked about: the first test on the
// client node. It is also the netdoc run scoring reads, so both contestants are
// answering the same question about the same target.
func primaryTest(s *Scenario) (Test, bool) {
	client := clientNode(s)
	for _, test := range s.Tests {
		if test.Node == client {
			return test, true
		}
	}
	return Test{}, false
}

// FindChallenge draws a fresh challenge, optionally of a requested difficulty.
// Difficulty is a property of the case an id resolves to, so honouring a
// request means looking at ids until one carries it.
func FindChallenge(difficulty string) (*Challenge, error) {
	if difficulty != "" && !slices.Contains(ChallengeDifficulties, difficulty) {
		return nil, fmt.Errorf("unknown difficulty %q (have: %s)", difficulty, strings.Join(ChallengeDifficulties, ", "))
	}
	for attempt := 0; attempt < challengeIDSearchLimit; attempt++ {
		id, err := RandomChallengeID()
		if err != nil {
			return nil, err
		}
		challenge, err := BuildChallenge(id)
		if err != nil {
			continue
		}
		if difficulty == "" || challenge.Difficulty == difficulty {
			return challenge, nil
		}
	}
	return nil, fmt.Errorf("no %s challenge found in %d attempts", difficulty, challengeIDSearchLimit)
}

// Scores one contestant can earn. There is deliberately no partial credit: the
// diagnosis model can say whether an answer names what the simulator observed,
// and inventing degrees of nearly-right would be scoring on resemblance.
//
// ChallengeUnrecognized is not a softer ChallengeIncorrect. Both lose the
// round; they say different things about why, and the difference is the whole
// point of the contract. Incorrect means netdoc had the words for this
// condition and reached for different ones. Unrecognized means its vocabulary
// has no way to state the condition at all, so no report it could have written
// would have won, which is the finding worth acting on.
const (
	ChallengeCorrect      = "correct"
	ChallengeIncorrect    = "incorrect"
	ChallengeUnrecognized = "unrecognized"
	ChallengeGaveUp       = "gave_up"
	ChallengeUnscoreable  = "unscoreable"
)

// Matchups.
const (
	ChallengeHumanWins  = "human_wins"
	ChallengeNetdocWins = "network_doctor_wins"
	ChallengeDraw       = "draw"
	ChallengeNobodyWins = "nobody_wins"
	ChallengeNoResult   = "no_result"
)

// ChallengeSubmission is what the person committed to, before any netdoc
// process ran.
type ChallengeSubmission struct {
	Answer  ChallengeAnswer
	GaveUp  bool
	Note    string
	Elapsed time.Duration
}

// ChallengeTruth is what the simulator independently established. It is derived
// from evidence and the mutation manifest only, never from a diagnosis, never
// from the player's answer, and never from a mutation having merely been
// scheduled.
type ChallengeTruth struct {
	Answer      ChallengeAnswer `json:"answer,omitempty"`
	Label       string          `json:"label,omitempty"`
	Scoreable   bool            `json:"scoreable"`
	Reason      string          `json:"reason,omitempty"`
	Explanation string          `json:"explanation,omitempty"`
	// Injected is what the generator asked for. It is intent rather than truth,
	// is never what a score is computed from, and is printed only after both
	// answers are in.
	Injected       string   `json:"injected,omitempty"`
	ObservedFaults []string `json:"observed_faults"`
	Evidence       []string `json:"evidence"`
}

// ChallengeContestant is one graded answer.
type ChallengeContestant struct {
	Answer ChallengeAnswer `json:"answer,omitempty"`
	Label  string          `json:"label,omitempty"`
	Score  string          `json:"score"`
	Detail string          `json:"detail,omitempty"`
	Note   string          `json:"note,omitempty"`
}

// ChallengeTiming is every field of a result that a replay will not reproduce.
// It is one object rather than two loose fields so a consumer diffing two runs
// of the same id knows exactly what it has to ignore: everything else in a
// ChallengeResult is determined by the id and the network.
type ChallengeTiming struct {
	HumanMS  int64 `json:"human_ms"`
	NetdocMS int64 `json:"network_doctor_ms"`
}

// NetdocIdentity is which Network Doctor executable produced a result: the
// absolute path the run launched, and the line that same executable printed for
// -version. It is what makes a saved result reproducible: `netdoc` on the next
// machine, or in the next month, is not necessarily this build.
//
// The version is recorded as the binary reported it. A local build says `dev`,
// and that is the honest answer; nothing here infers a version from the
// checkout, the filename, or the simulator's own build.
type NetdocIdentity struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// ChallengeResult is the whole matchup, and the machine-readable artifact.
type ChallengeResult struct {
	ChallengeID string `json:"challenge_id"`
	Difficulty  string `json:"difficulty"`
	// Daily is the UTC date this was played as the daily for, and is what makes
	// two people's results comparable as the same day's puzzle. Like netdoc and
	// timing, it records the session rather than the challenge: a replay by id
	// reproduces the network and not the way somebody arrived at it.
	Daily            string              `json:"daily,omitempty"`
	IDVersion        string              `json:"id_version"`
	GeneratorVersion string              `json:"generator_version"`
	BaseScenario     string              `json:"base_scenario"`
	Seed             int64               `json:"seed"`
	Case             int                 `json:"case"`
	CaseFingerprint  string              `json:"case_fingerprint"`
	Node             string              `json:"node"`
	Target           string              `json:"target,omitempty"`
	Netdoc           NetdocIdentity      `json:"netdoc"`
	Truth            ChallengeTruth      `json:"truth"`
	Human            ChallengeContestant `json:"human"`
	NetworkDoctor    ChallengeContestant `json:"network_doctor"`
	Result           string              `json:"result"`
	Timing           ChallengeTiming     `json:"timing"`
	Replay           string              `json:"replay"`
	// Error is the simulator falling over, which is not a matchup.
	Error string `json:"error,omitempty"`
}

// ScoreChallenge grades both contestants against one truth.
//
// The order here is the invariant: truth is established first, from simulator
// evidence and the manifest alone, and only then is either answer looked at.
// Neither contestant appears in challengeTruth's inputs, and neither grading
// function can reach the other's answer.
func ScoreChallenge(c *Challenge, report *Report, submission ChallengeSubmission) *ChallengeResult {
	result := &ChallengeResult{
		// The version this id carries, not the one this build mints: a V1 id
		// resolved by a later build is still a V1 challenge.
		ChallengeID: c.ID, Difficulty: c.Difficulty, Daily: c.Daily, IDVersion: challengeIDVersionOf(c.ID),
		GeneratorVersion: c.Manifest.GeneratorVersion, BaseScenario: c.Base, Seed: c.Seed, Case: c.Case,
		CaseFingerprint: c.Manifest.CaseFingerprint, Node: c.Node, Target: c.Target,
		Timing: ChallengeTiming{HumanMS: submission.Elapsed.Milliseconds()}, Replay: c.Replay(),
	}
	result.Truth = challengeTruth(c, report)
	diagnosis := primaryClientDiagnosis(c, report)
	if report != nil {
		result.Error = report.Error
		result.Timing.NetdocMS = netdocDuration(c, report).Milliseconds()
	}

	result.Human = ChallengeContestant{Answer: submission.Answer, Note: submission.Note,
		Label: challengeAnswerLabel(submission.Answer)}
	result.NetworkDoctor = ChallengeContestant{}
	if diagnosis != nil {
		result.NetworkDoctor.Detail = diagnosis.Summary
	}

	if !result.Truth.Scoreable {
		result.Human.Score, result.NetworkDoctor.Score = ChallengeUnscoreable, ChallengeUnscoreable
		result.Result = ChallengeNoResult
		return result
	}

	switch {
	case submission.GaveUp:
		result.Human.Answer, result.Human.Label, result.Human.Score = "", "", ChallengeGaveUp
	case submission.Answer == result.Truth.Answer:
		result.Human.Score = ChallengeCorrect
	default:
		result.Human.Score = ChallengeIncorrect
	}

	// Recognition is looked up by the condition the simulator established, never
	// by the condition the generator asked for, and the lookup can fail: a
	// condition netdoc's vocabulary cannot state is a loss it was always going
	// to take, and the result says so in those words.
	switch recognized, known := challengeRecognition[result.Truth.Answer]; {
	case !known:
		result.NetworkDoctor.Score = ChallengeUnrecognized
		result.NetworkDoctor.Note = "Network Doctor's report has no verdict that states this condition."
	case recognized(diagnosis):
		result.NetworkDoctor.Score = ChallengeCorrect
		result.NetworkDoctor.Answer = result.Truth.Answer
		result.NetworkDoctor.Label = result.Truth.Label
	default:
		result.NetworkDoctor.Score = ChallengeIncorrect
	}

	humanRight := result.Human.Score == ChallengeCorrect
	netdocRight := result.NetworkDoctor.Score == ChallengeCorrect
	switch {
	case humanRight && !netdocRight:
		result.Result = ChallengeHumanWins
	case !humanRight && netdocRight:
		result.Result = ChallengeNetdocWins
	case humanRight && netdocRight:
		result.Result = ChallengeDraw
	default:
		result.Result = ChallengeNobodyWins
	}
	return result
}

// challengeTruth establishes what actually happened. It reads the report's
// evidence and the manifest; it never reads report.Tests, so no diagnosis can
// reach it.
//
// The manifest is used for one thing: knowing which mutation to demand
// independent evidence for. A mutation that was generated, applied, or expected
// to break something establishes nothing on its own; collectObservedTruth only
// lists it under ObservedFaults once service, event, kernel-fault or
// reachability evidence from the executed run supports it.
func challengeTruth(c *Challenge, report *Report) ChallengeTruth {
	truth := ChallengeTruth{Explanation: c.condition.explanation, ObservedFaults: []string{}, Evidence: []string{}}
	if len(c.Manifest.Mutations) == 1 {
		truth.Injected = c.Manifest.Mutations[0].Description
	}
	switch {
	case report == nil:
		truth.Reason = "the simulation produced no report"
		return truth
	case report.Error != "":
		truth.Reason = "the simulation did not complete: " + report.Error
		return truth
	case !report.Cleanup.Done && !report.Cleanup.Kept:
		truth.Reason = "the simulation did not clean up, so its final state is not trustworthy"
		return truth
	}
	// Network Doctor not having produced a diagnosis is not a win for anybody:
	// there is no matchup to score, and voiding the round is the honest outcome.
	if primaryClientDiagnosis(c, report) == nil {
		truth.Reason = "Network Doctor produced no diagnosis for this challenge, so there is nothing to compare"
		return truth
	}

	observed := collectObservedTruth(c.Manifest, report)
	truth.ObservedFaults = observed.ObservedFaults
	truth.Evidence = challengeEvidence(c, report, observed)

	if c.condition.mutation == "" {
		if reason, ok := healthyObserved(c, report, observed); !ok {
			truth.Reason = reason
			return truth
		}
		truth.Answer, truth.Scoreable = AnswerHealthy, true
		truth.Label = challengeAnswerLabel(AnswerHealthy)
		return truth
	}
	if !slices.Contains(observed.ObservedFaults, c.condition.mutation) {
		truth.Reason = "the injected fault left no independent evidence that it took effect, so this challenge has no answer to grade against"
		return truth
	}
	// The condition's own narrower demand, where the shared per-mutation check
	// would settle for less than proof that live traffic met the fault.
	if c.condition.requires != nil && !c.condition.requires(report.Evidence, c.Manifest.Mutations[0]) {
		truth.Reason = "the injected fault was in place but no independent evidence shows it reached live traffic, so this challenge has no answer to grade against"
		return truth
	}
	truth.Answer, truth.Scoreable = c.condition.answer, true
	truth.Label = challengeAnswerLabel(c.condition.answer)
	return truth
}

// challengeEvidence is the reveal's evidence block: what the simulator measured
// for itself, in a fixed order, with no diagnosis in it.
func challengeEvidence(c *Challenge, report *Report, observed ObservedTruth) []string {
	var out []string
	for _, family := range []struct{ key, label string }{{"ipv4", "IPv4"}, {"ipv6", "IPv6"}} {
		for _, item := range report.Evidence.FamilyReachability {
			if item.Node != c.Node || item.Family != family.key {
				continue
			}
			out = append(out, "internet path over "+family.label+": "+item.State+viaSuffix(item.Via))
		}
	}
	for _, item := range report.Evidence.ControlledTargets {
		if item.From != c.Node {
			continue
		}
		// The dial's own word, not the bool: "refused" and "unreachable" are the
		// two answers this block exists to keep apart, and collapsing them here
		// would hide the difference the scoring turned on.
		out = append(out, "controlled target "+item.To+": "+item.Outcome+viaSuffix(item.Via))
	}
	// The client's real routing table, which is the only line that can show an
	// absence: no default at all, or no specific route to where the target is.
	for _, table := range report.Evidence.RouteTables {
		if table.Node != c.Node {
			continue
		}
		defaults := defaultRoutesIn(table.Routes)
		line := table.Family + " default routes in the client's own table: none"
		if len(defaults) > 0 {
			var vias []string
			for _, route := range defaults {
				vias = append(vias, route.Via)
			}
			line = table.Family + " default routes in the client's own table: " + strings.Join(vias, ", ")
		}
		out = append(out, line, fmt.Sprintf("%s routes in the client's own table: %d", table.Family, len(table.Routes)))
	}
	// One line per gateway, not per destination: the client selects the same
	// route for every controlled endpoint, and repeating it reads as two
	// measurements when it is one.
	for _, route := range report.Evidence.Routes {
		if route.Node != c.Node || !route.Selected || route.GatewayReachable == nil {
			continue
		}
		line := "selected " + route.Family + " gateway " + route.Via + ": " + reachableWord(*route.GatewayReachable)
		if !slices.Contains(out, line) {
			out = append(out, line)
		}
	}
	if observed.DNS != "unknown" {
		out = append(out, "DNS answers observed by the resolver: "+observed.DNS)
	}
	if observed.TLS != "unknown" {
		out = append(out, "TLS handshakes observed by the target: "+observed.TLS)
	}
	if observed.TCP != "unknown" {
		out = append(out, "TCP service behaviour: "+observed.TCP)
	}
	if observed.Link != "unknown" {
		out = append(out, "simulated links: "+observed.Link)
	}
	if observed.Packet != "unknown" {
		out = append(out, "path shaping counted by the kernel: "+observed.Packet)
	}
	return out
}

func viaSuffix(via []string) string {
	if len(via) == 0 {
		return ""
	}
	return " (via " + strings.Join(via, " ") + ")"
}

func reachableWord(reachable bool) string {
	if reachable {
		return FamilyStateReachable
	}
	return FamilyStateUnreachable
}

// primaryClientDiagnosis returns the diagnosis from the run the player was
// asked about, the first one on the challenge node. Later runs in a multi-test
// base describe a different target and would answer a different question.
func primaryClientDiagnosis(c *Challenge, report *Report) *Diagnosis {
	if report == nil {
		return nil
	}
	for i := range report.Tests {
		if report.Tests[i].Node == c.Node {
			return report.Tests[i].Diagnosis
		}
	}
	return nil
}

func netdocDuration(c *Challenge, report *Report) time.Duration {
	for i := range report.Tests {
		if report.Tests[i].Node == c.Node {
			return report.Tests[i].Duration
		}
	}
	return 0
}

func challengeIDVersionOf(id string) string {
	version, _, _ := strings.Cut(id, "-")
	return version
}

func msDuration(ms int64) time.Duration { return time.Duration(ms) * time.Millisecond }

// formatElapsed renders an investigation time the way a person reads one.
func formatElapsed(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return strconv.Itoa(int(d/time.Second)) + "s"
	}
	return fmt.Sprintf("%dm %02ds", int(d/time.Minute), int((d%time.Minute)/time.Second))
}
