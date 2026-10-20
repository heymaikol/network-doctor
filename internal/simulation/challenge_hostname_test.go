package simulation

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// renderScenario is the whole scenario as one searchable string, so a test can
// assert an old name is gone from all of it rather than from the places it
// remembered to look.
func renderScenario(t *testing.T, s *Scenario) string {
	t.Helper()
	blob, err := yaml.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}

// The name the player is asked about has to be the name the network answers to.
// A cosmetic hostname sitting beside the real topology would be worse than no
// hostname at all: the player would dig it, get nothing, and be investigating
// the game instead of the fault.
func TestChallengeHostnameIsRealInTheSimulation(t *testing.T) {
	named := 0
	for _, id := range challengeIDs(120) {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		if challenge.Target == "" {
			// A base whose primary test names no target asks about the client's own
			// connectivity. There is nothing to name, and inventing a host for it
			// would change the question netdoc is graded on.
			continue
		}
		parsed, err := diagnostic.ParseTarget(challenge.Target)
		if err != nil {
			t.Fatalf("challenge %s target %q does not parse: %v", id, challenge.Target, err)
		}
		if parsed.IP != nil {
			continue
		}
		named++
		if want := challengeHostname(id); parsed.Host != want {
			t.Fatalf("challenge %s is presented as %q, want the id's own name %q", id, parsed.Host, want)
		}
		// The scenario's own zone, not a resolver: the address has to be one a node
		// in this simulation owns, or the name resolves to somewhere nothing serves.
		if addrs := scenarioTargetAddresses(challenge.Scenario, parsed); len(addrs) == 0 {
			t.Fatalf("challenge %s: nothing in the simulation resolves %q", id, parsed.Host)
		}
		// And whatever presents a certificate for it has to present one for this
		// name. A rename that reached the zone but not the certificate would have
		// invented a hostname mismatch on every TLS challenge.
		assertCertificatesCoverOrIgnore(t, id, challenge.Scenario, parsed.Host)
	}
	if named < 40 {
		t.Fatalf("only %d of 120 sampled challenges named a host; the rename is barely reached", named)
	}
}

// assertCertificatesCoverOrIgnore checks that no service still advertises the
// base scenario's old name for the renamed host. The mismatch family reissues
// its certificate for a name on purpose, so a certificate covering neither the
// new host nor anything else is what this is looking for: a stale name from the
// base YAML surviving the rename.
func assertCertificatesCoverOrIgnore(t *testing.T, id string, s *Scenario, host string) {
	t.Helper()
	for _, node := range s.Topology.Nodes {
		for _, service := range node.Services {
			if service.Certificate == nil {
				continue
			}
			for _, name := range service.Certificate.DNSNames {
				if strings.HasSuffix(dnsKey(name), "-target.test") || dnsKey(name) == "example.test" {
					t.Fatalf("challenge %s: %s/%s still presents the base scenario's name %q instead of %q",
						id, node.Name, service.Name, name, host)
				}
			}
		}
	}
}

// The hostname is part of the reproduction contract: the same id has to present
// the same name, and two ids must not collide into one.
func TestChallengeHostnameIsDeterministicAndDistinct(t *testing.T) {
	ids := challengeIDs(200)
	seen := map[string]string{}
	for _, id := range ids {
		first, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		second, err := BuildChallenge(strings.ToLower(id))
		if err != nil {
			t.Fatalf("rebuild %s: %v", id, err)
		}
		if first.Target != second.Target {
			t.Fatalf("challenge %s presented %q then %q", id, first.Target, second.Target)
		}
		if first.Target == "" {
			continue
		}
		if other, ok := seen[first.Target]; ok {
			t.Fatalf("challenges %s and %s are both presented as %q", other, id, first.Target)
		}
		seen[first.Target] = id
	}
}

// The zone is answerable inside the simulation and nowhere else. `.test` is
// reserved by RFC 6761 precisely so that no public resolver may answer it, which
// is what keeps a challenge from depending on the host's DNS or on the internet.
func TestChallengeHostnameCannotResolvePublicly(t *testing.T) {
	for _, id := range challengeIDs(40) {
		host := challengeHostname(id)
		if !strings.HasSuffix(host, ".test") {
			t.Fatalf("challenge %s host %q is outside the reserved .test namespace", id, host)
		}
		if !isSafeHostname(host) {
			t.Fatalf("challenge %s host %q is not a name the simulator will serve", id, host)
		}
		// One label before the TLD, so nothing about the name can be read as a
		// delegation to a real zone.
		if labels := strings.Split(host, "."); len(labels) != 2 {
			t.Fatalf("challenge %s host %q has %d labels, want 2", id, host, len(labels))
		}
	}
}

// The name is derived from the id and nothing else. The base scenario is the
// answer's neighbourhood, and seeing the same host on every tls-valid challenge
// would tell a returning player which two conditions it can be, so the name may
// not be a fingerprint of the base, the case, or the fault.
func TestChallengeHostnameLeaksNothingAboutTheCase(t *testing.T) {
	hostsPerBase := map[string]map[string]bool{}
	for _, id := range challengeIDs(200) {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		if challenge.Target == "" {
			continue
		}
		host := challengeTargetHost(challenge.Target)
		for _, secret := range []string{challenge.Base, challenge.condition.mutation,
			string(challenge.condition.answer), challenge.Difficulty, challenge.Manifest.CaseFingerprint} {
			if secret == "" {
				continue
			}
			if strings.Contains(host, secret) {
				t.Fatalf("challenge %s host %q spells out %q", id, host, secret)
			}
		}
		word, _, _ := strings.Cut(host, "-")
		if hostsPerBase[word] == nil {
			hostsPerBase[word] = map[string]bool{}
		}
		hostsPerBase[word][challenge.Base] = true
	}
	// The readable half of the name is the word, so the word is what a player
	// could learn to recognize. Every word has to appear on more than one base,
	// or it would be one.
	for word, bases := range hostsPerBase {
		if len(bases) < 2 {
			t.Errorf("host word %q only ever appears on base %v, which makes it a tell", word, bases)
		}
	}
}

// The probe fixtures are what netdoc's own connectivity checks dial. They are
// not the challenge's target and renaming one would break the measurement every
// scenario depends on.
func TestChallengeRenameLeavesTheProbeFixturesAlone(t *testing.T) {
	for _, id := range challengeIDs(60) {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		// Compared against the base rather than asserted absolutely: not every base
		// has every fixture, and the invariant is that renaming the target changed
		// nothing about the ones it has. The predicates are the generator's own, so
		// this asks the question the generator asks.
		base, err := LibraryScenario(challenge.Base)
		if err != nil {
			t.Fatal(err)
		}
		for _, fixture := range []struct {
			name string
			has  func(*Scenario) bool
		}{
			{"QUIC", hasWorkingQUICFixture},
			{"DoH", hasWorkingDoHFixture},
			{proxyCONNECTTarget, func(s *Scenario) bool { return dnsAddress(s, proxyCONNECTTarget) != "" }},
		} {
			if fixture.has(challenge.Scenario) != fixture.has(base) {
				t.Fatalf("challenge %s changed the %s fixture of base %s", id, fixture.name, challenge.Base)
			}
		}
	}
}

// A base whose primary test is an IP literal or has no target at all is left
// exactly as it was. There is no name to rename, and inventing one would put a
// hostname in front of a question that was never about a name.
func TestChallengeRenameSkipsWhatHasNoName(t *testing.T) {
	for _, base := range []string{"two-path-healthy", "two-path-ipv6-healthy"} {
		// Already validated: LibraryScenario parses and validates, and Validate
		// normalizes shorthands it cannot be handed twice.
		scenario, err := LibraryScenario(base)
		if err != nil {
			t.Fatal(err)
		}
		if got := nameChallengeTarget(scenario, "V3-8F42C1"); got != "" {
			t.Fatalf("base %s has no briefed hostname, but the rename produced %q", base, got)
		}
	}
}

// renameScenarioHost has to move every spelling together. The unit-level proof,
// because the case that would break it, a zone renamed while a certificate is
// not, is exactly the one a whole-challenge test would report as a TLS
// mismatch rather than as a rename bug.
func TestRenameScenarioHostMovesEverySpelling(t *testing.T) {
	scenario, err := LibraryScenario("tls-valid")
	if err != nil {
		t.Fatal(err)
	}
	renameScenarioHost(scenario, "secure-target.test", "ledger-8f42c1.test")
	blob := renderScenario(t, scenario)
	if strings.Contains(blob, "secure-target.test") {
		t.Fatalf("the old name survives the rename:\n%s", blob)
	}
	if got := dnsAddress(scenario, "ledger-8f42c1.test"); got != "10.77.0.20" {
		t.Fatalf("the renamed zone resolves to %q, want 10.77.0.20", got)
	}
	target, ok := findValidTLSTestTarget(scenario)
	if !ok {
		t.Fatal("the renamed scenario no longer has a valid TLS test target")
	}
	for _, node := range scenario.Topology.Nodes {
		for _, service := range node.Services {
			if service.Name != target.service {
				continue
			}
			if !certificateCoversHost(service.Certificate, "ledger-8f42c1.test") {
				t.Fatalf("%s presents %v, which does not cover the renamed host",
					service.Name, service.Certificate.DNSNames)
			}
		}
	}
	// And the fixtures are untouched, so netdoc's own probes still have somewhere
	// to go.
	if dnsAddress(scenario, proxyCONNECTTarget) == "" {
		t.Fatal("the rename took the connectivity fixture with it")
	}
}
