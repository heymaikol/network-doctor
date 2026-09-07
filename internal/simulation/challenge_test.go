package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// challengeIDs walks a deterministic spread of ids at the version this build
// mints, so these tests follow the current generator rather than a frozen one.
// Tests that only need "a challenge of condition X" search it rather than
// pinning constants, so ordinary changes to the mutation registry do not break
// them. The ids that must never move are pinned once, in
// TestChallengeIDsResolveToTheSameCaseForever.
func challengeIDs(count int) []string {
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, fmt.Sprintf("%s-%06X", ChallengeIDVersion, i*7919%0xFFFFFF))
	}
	return out
}

// challengeWithMutation finds a challenge whose single mutation is the named
// one. An empty name finds the healthy challenge.
func challengeWithMutation(t *testing.T, mutation string) *Challenge {
	t.Helper()
	for _, id := range challengeIDs(400) {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build challenge %s: %v", id, err)
		}
		if challenge.condition.mutation == mutation {
			return challenge
		}
	}
	t.Fatalf("no challenge generated the %q condition in the sampled ids", mutation)
	return nil
}

// A published challenge id is a promise: whoever types it gets the puzzle the
// person who shared it played. That promise spans this file's selection, the
// hunt generator behind it and the base scenario YAML it draws from, so this
// table pins the whole chain.
//
// A failure here is not a broken test. It means a change repointed ids that may
// already be in circulation, and the fix is to leave V1 alone and add a V2
// entry to challengeGenerators, never to update these rows.
func TestChallengeIDsResolveToTheSameCaseForever(t *testing.T) {
	pinned := map[string]int{}
	pinnedIDs := map[string]bool{}
	for _, tt := range []struct {
		id, base    string
		caseNumber  int
		mutation    string
		difficulty  string
		fingerprint string
	}{
		{"V1-000000", "two-path-healthy", 949668, "routing.preferred_path_failure", "hard", "7bd2f4bbb737c782"},
		{"V1-001EEF", "tls-valid", 619652, "dns.servfail", "easy", "ebe836dc0861aa5b"},
		{"V1-003DDE", "tls-valid", -1, "", "medium", "09e369387b93f6db"},
		{"V1-005CCD", "tls-valid", 492100, "dns.drop", "easy", "639903dfbc7956f1"},
		{"V1-013556", "tls-valid", 391463, "service.tls_expired", "medium", "46d2b0f2b4af38d5"},
		{"V1-01B112", "dual-stack-healthy", 715611, "service.tcp_reset", "easy", "059f3d44d5c36606"},
		{"V1-04977A", "dual-stack-healthy", 476967, "family.ipv4_drop", "medium", "3faa09b3c67c5370"},
		{"V1-04B669", "dual-stack-healthy", 538431, "family.ipv6_drop", "hard", "2e5c19bb54c29117"},
		// V2 added netem.loss, which V1 must never start selecting. The two
		// blocks below are one table on purpose, so a change that repoints either
		// version fails in the same place.
		{"V2-000000", "dual-stack-healthy", 167361, "family.ipv6_drop", "hard", "2e5c19bb54c29117"},
		{"V2-001EEF", "two-path-ipv6-healthy", 272552, "dns.drop", "easy", "5e1e565d238fb948"},
		{"V2-003DDE", "dual-stack-healthy", 765464, "family.ipv4_drop", "medium", "3faa09b3c67c5370"},
		{"V2-007BBC", "two-path-ipv6-healthy", -1, "", "easy", "08824fd8c8781c79"},
		{"V2-009AAB", "dual-stack-healthy", 678197, "netem.loss", "medium", "fd4ebcf823a96a62"},
		{"V2-00D889", "two-path-healthy", 548214, "routing.preferred_path_failure", "hard", "7bd2f4bbb737c782"},
		{"V2-00F778", "tls-valid", 342609, "dns.servfail", "easy", "ebe836dc0861aa5b"},
		{"V2-017334", "dual-stack-healthy", 589641, "service.tcp_reset", "easy", "059f3d44d5c36606"},
		{"V2-04F447", "tls-valid", 992337, "service.tls_expired", "medium", "46d2b0f2b4af38d5"},
		// V3 ids are published too: the starter packs are written in them and the
		// daily epoch table resolves through V3. Every starter entry is pinned
		// here, so a change that repoints one fails as an id change rather than
		// as a pack quietly teaching a different lesson.
		{"V3-000000", "dual-stack-healthy", 47865, "family.ipv4_drop", "medium", "231095f63e19ed50"},
		{"V3-001EEF", "healthy-routed-network", 113244, "service.tcp_port_blocked", "medium", "34d875982cc4a92c"},
		{"V3-005CCD", "healthy-routed-network", 823920, "service.tcp_reset", "easy", "6831d5c06db1a57a"},
		{"V3-009AAB", "two-router-healthy", 506479, "routing.no_default_route", "easy", "4ac68ae4c8186287"},
		{"V3-00B99A", "two-path-healthy", 342407, "dns.servfail", "easy", "7fc47de5d4b4b7ce"},
		{"V3-00D889", "dual-stack-healthy", 226736, "service.connection_refused", "easy", "ba11b14d2cba16f9"},
		{"V3-011667", "two-router-healthy", 735550, "routing.wrong_default_route", "hard", "aa3ac7ef97ab1bd4"},
		{"V3-019223", "healthy", 698901, "routing.no_default_route", "easy", "4215c4009595e7c5"},
		{"V3-01B112", "healthy", 493581, "service.connection_refused", "easy", "d4b7091d411a156f"},
		{"V3-01EEF0", "tls-valid", -1, "", "easy", "f20e7492fcfcb216"},
		{"V3-020DDF", "two-router-healthy", 678808, "routing.missing_subnet_route", "hard", "a4417bcf09ae330d"},
		{"V3-022CCE", "two-router-healthy", -1, "", "easy", "c9d19d64d6021c04"},
		{"V3-024BBD", "two-path-healthy", -1, "", "medium", "f8ca077177422bd0"},
		{"V3-02E668", "healthy-routed-network", 712638, "dns.servfail", "easy", "9f7d85c4ce3a63bd"},
		{"V3-032446", "two-path-healthy", 523512, "dns.drop", "easy", "f0ad4fec76868ce3"},
		{"V3-034335", "healthy-routed-network", 920724, "netem.loss", "medium", "0418beda7947c876"},
		{"V3-04599C", "two-path-healthy", 624898, "routing.preferred_path_failure", "hard", "c9d15493189fc1b8"},
		{"V3-058EF2", "tls-valid", 424504, "service.tls_expired", "medium", "d43e003da7792e6f"},
		{"V3-05EBBF", "tls-valid", 855224, "service.tls_hostname_mismatch", "medium", "eb280cd235bfcadc"},
		{"V3-07F99E", "dual-stack-healthy", 457722, "family.ipv6_drop", "hard", "7716ddb93d3c01c6"},
		// V4 is the version this build mints, so it is frozen from its first
		// release rather than after somebody notices an id has moved.
		{"V4-000000", "healthy-routed-network", -1, "", "hard", "5ce33998b441f040"},
		{"V4-001EEF", "two-path-ipv6-healthy", -1, "", "easy", "06ee298e2e9c6d81"},
		{"V4-003DDE", "tls-valid", 844771, "routing.no_default_route", "easy", "a5b4405fa620ba15"},
		{"V4-005CCD", "healthy", 393985, "service.tcp_port_blocked", "medium", "e501938e58f8e4b8"},
		{"V4-007BBC", "dual-stack-healthy", 858566, "dns.drop", "easy", "22bc3963a5306280"},
		{"V4-009AAB", "tls-valid", 422849, "service.tls_expired", "medium", "d43e003da7792e6f"},
		{"V4-00B99A", "tls-valid", 830741, "service.tls_hostname_mismatch", "medium", "eb280cd235bfcadc"},
		{"V4-00D889", "tls-valid", 809946, "service.tls_expired", "medium", "d43e003da7792e6f"},
		{"V4-00F778", "two-path-ipv6-healthy", 751460, "routing.preferred_path_failure", "hard", "cea184054ba16e4d"},
		{"V4-011667", "dual-stack-healthy", 584555, "family.ipv4_drop", "medium", "231095f63e19ed50"},
	} {
		version, _, _ := strings.Cut(tt.id, "-")
		pinned[version]++
		pinnedIDs[tt.id] = true
		t.Run(tt.id, func(t *testing.T) {
			challenge, err := BuildChallenge(tt.id)
			if err != nil {
				t.Fatalf("build %s: %v", tt.id, err)
			}
			mutation := ""
			if len(challenge.Manifest.Mutations) == 1 {
				mutation = challenge.Manifest.Mutations[0].ID
			}
			if challenge.ID != tt.id || challenge.Base != tt.base || challenge.Case != tt.caseNumber ||
				mutation != tt.mutation || challenge.Difficulty != tt.difficulty ||
				challenge.Manifest.CaseFingerprint != tt.fingerprint {
				t.Fatalf("%s now resolves to base %s case %d mutation %q %s fingerprint %s;"+
					" it was shared as base %s case %d mutation %q %s fingerprint %s."+
					" Add a new generator version instead of changing what an existing one means.",
					tt.id, challenge.Base, challenge.Case, mutation, challenge.Difficulty,
					challenge.Manifest.CaseFingerprint, tt.base, tt.caseNumber, tt.mutation,
					tt.difficulty, tt.fingerprint)
			}
		})
	}
	// The version an id carries is the version it is resolved by, whatever this
	// build happens to mint.
	for _, version := range []string{"V1", "V2", "V3", "V4"} {
		if _, ok := challengeGenerators[version]; !ok {
			t.Fatalf("%s ids have been published; this build can no longer resolve them", version)
		}
	}
	// The other half: a version cannot be added without rows either. A version's
	// meaning is the whole chain it resolves through, so it can be repointed by a
	// change that never mentions it, and bumping HuntGeneratorVersion moves every
	// V3 and V4 id exactly that way. The rows above are what catches that, so a
	// version carrying none is unprotected from the release it ships in, which is
	// the window in which nobody is yet looking.
	for version := range challengeGenerators {
		// Authored ids name a case rather than search for one, so they are pinned
		// by slug in TestAuthoredChallengeIDsAreFrozen instead.
		if version == AuthoredIDVersion {
			continue
		}
		if pinned[version] == 0 {
			t.Errorf("challenge version %s resolves ids but no row above pins one."+
				" Add golden rows for it before it ships: without them a change to the hunt"+
				" generator, the control scenarios or the condition table repoints every %s id"+
				" silently.", version, version)
		}
	}
	// The rows above claim to pin every starter entry, and a claim nothing checks
	// is a wish. A pack entry that is not pinned still resolves, so the omission
	// stays invisible until a generator change moves it and a beginner is taught
	// something the pack never promised.
	for _, pack := range starterPacks {
		for _, entry := range pack.entries {
			if !pinnedIDs[entry.id] {
				t.Errorf("starter pack %s plays %s but no row above pins it;"+
					" add one so a change that repoints it fails here instead of in a pack",
					pack.id, entry.id)
			}
		}
	}
	// V1 is frozen at the conditions it was published with. Its list may only
	// shrink relative to what a later version selects, never grow.
	for _, mutation := range challengeV1Mutations {
		if _, ok := challengeConditionFor(mutation); !ok {
			t.Fatalf("V1 ids select %s, which is no longer a challenge condition", mutation)
		}
	}
}

func TestChallengeIDReproducesTheSameCase(t *testing.T) {
	for _, id := range challengeIDs(40) {
		first, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		second, err := BuildChallenge(strings.ToLower(id))
		if err != nil {
			t.Fatalf("rebuild %s: %v", id, err)
		}
		if first.Base != second.Base || first.Case != second.Case || first.Seed != second.Seed ||
			first.Difficulty != second.Difficulty || first.condition.answer != second.condition.answer {
			t.Fatalf("challenge %s is not reproducible: %+v vs %+v", id, first, second)
		}
		if first.Manifest.CaseFingerprint != second.Manifest.CaseFingerprint {
			t.Fatalf("challenge %s: case fingerprint %s then %s", id,
				first.Manifest.CaseFingerprint, second.Manifest.CaseFingerprint)
		}
		one, err := yaml.Marshal(first.Scenario)
		if err != nil {
			t.Fatal(err)
		}
		two, err := yaml.Marshal(second.Scenario)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(one, two) {
			t.Fatalf("challenge %s built two different scenarios", id)
		}
	}
}

func TestChallengeIDsVaryAndStayChallengeCapable(t *testing.T) {
	cases := map[string]int{}
	answers := map[ChallengeAnswer]int{}
	for _, id := range challengeIDs(200) {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		if len(challenge.Manifest.Mutations) > 1 {
			t.Fatalf("challenge %s carries %d mutations; a challenge is a single primary fault",
				id, len(challenge.Manifest.Mutations))
		}
		if len(challenge.Manifest.Mutations) == 1 {
			if _, ok := challengeConditionFor(challenge.Manifest.Mutations[0].ID); !ok {
				t.Fatalf("challenge %s generated %q, which is not challenge-capable",
					id, challenge.Manifest.Mutations[0].ID)
			}
		}
		if challenge.Node == "" {
			t.Fatalf("challenge %s has no client node", id)
		}
		cases[challenge.Base+"/"+fmt.Sprint(challenge.Case)]++
		answers[challenge.condition.answer]++
	}
	if len(cases) < 100 {
		t.Fatalf("200 ids produced only %d distinct cases", len(cases))
	}
	if len(answers) < 5 {
		t.Fatalf("200 ids produced only %d distinct answers: %v", len(answers), answers)
	}
}

// A fault on a target the briefing never names is a puzzle with no findable
// clue, and the netdoc run scoring reads was never asked about it. Both
// contestants would be guaranteed to lose.
func TestChallengeFaultsSitOnTheTargetThePlayerIsPointedAt(t *testing.T) {
	for _, id := range challengeIDs(300) {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		if challenge.condition.briefed == nil || len(challenge.Manifest.Mutations) != 1 {
			continue
		}
		base, err := LibraryScenario(challenge.Base)
		if err != nil {
			t.Fatal(err)
		}
		if !challenge.condition.briefed(base, challenge.Manifest.Mutations[0]) {
			t.Fatalf("challenge %s puts %s on a target the briefing (%s → %q) never names",
				id, challenge.Manifest.Mutations[0].ID, challenge.Node, challenge.Target)
		}
	}
	// The rule has to actually exclude something, or it is decoration: the
	// two-path bases run a second client test whose target the briefing omits,
	// and that is where the generator places the reset.
	base, err := LibraryScenario("two-path-healthy")
	if err != nil {
		t.Fatal(err)
	}
	excluded := 0
	for caseNumber := range 200 {
		generated, err := generateHuntCase(HuntGeneratorVersion, "two-path-healthy", base, 1234, caseNumber, 1)
		if err != nil || len(generated.Manifest.Mutations) != 1 ||
			generated.Manifest.Mutations[0].ID != "service.tcp_reset" {
			continue
		}
		if resetTargetIsBriefed(base, generated.Manifest.Mutations[0]) {
			t.Fatalf("case %d puts a reset on the second client test's target and it was accepted as briefed",
				caseNumber)
		}
		excluded++
	}
	if excluded == 0 {
		t.Fatal("no two-path reset case was found, so this rule was never exercised")
	}
}

func TestChallengeDifficultyComesFromTheCondition(t *testing.T) {
	for _, condition := range challengeConditions {
		if condition.mutation == "" {
			continue
		}
		if condition.difficulty == "" {
			t.Fatalf("condition %s has no reviewed difficulty", condition.mutation)
		}
	}
	for _, id := range challengeIDs(60) {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		if challenge.condition.mutation != "" && challenge.Difficulty != challenge.condition.difficulty {
			t.Fatalf("challenge %s says %s, condition %s is %s", id, challenge.Difficulty,
				challenge.condition.mutation, challenge.condition.difficulty)
		}
	}
}

func TestChallengeBriefingHidesTheAnswer(t *testing.T) {
	for _, id := range challengeIDs(120) {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		var out bytes.Buffer
		challenge.WriteBriefing(&out)
		text := strings.ToLower(out.String())
		forbidden := []string{challenge.Base, fmt.Sprint(challenge.Seed), challenge.Manifest.CaseFingerprint,
			string(challenge.condition.answer), strings.ToLower(challenge.condition.explanation)}
		for _, mutation := range challenge.Manifest.Mutations {
			forbidden = append(forbidden, mutation.ID, strings.ToLower(mutation.Description))
		}
		for _, secret := range forbidden {
			if secret == "" {
				continue
			}
			if strings.Contains(text, secret) {
				t.Fatalf("challenge %s briefing leaks %q:\n%s", id, secret, out.String())
			}
		}
		if !strings.Contains(out.String(), id) || !strings.Contains(text, challenge.Difficulty) {
			t.Fatalf("challenge %s briefing must still name the id and difficulty:\n%s", id, out.String())
		}
	}
}

func TestChallengeAnswerMenuIsWiderThanTheGeneratableFaults(t *testing.T) {
	generatable := map[ChallengeAnswer]bool{}
	for _, condition := range challengeConditions {
		generatable[condition.answer] = true
	}
	if len(ChallengeAnswerMenu) <= len(generatable) {
		t.Fatalf("the menu (%d) must offer more answers than a challenge can inject (%d), or it is the answer key",
			len(ChallengeAnswerMenu), len(generatable))
	}
	seen := map[ChallengeAnswer]bool{}
	for _, item := range ChallengeAnswerMenu {
		if seen[item.ID] {
			t.Fatalf("duplicate answer %s", item.ID)
		}
		seen[item.ID] = true
	}
	for answer := range generatable {
		if !seen[answer] {
			t.Fatalf("condition answer %s is not offered in the menu", answer)
		}
	}
}

// resetChallengeReport is a report for a tcp_reset challenge: the target's
// service recorded a reset, which is what makes that fault observed.
func resetChallengeReport(t *testing.T, challenge *Challenge, cause string) *Report {
	t.Helper()
	mutation := challenge.Manifest.Mutations[0]
	check := DiagnosisCheck{ID: "http", Status: "FAIL", Cause: cause, Detail: "no HTTP response"}
	return &Report{
		Cleanup:  CleanupInfo{Done: true},
		Topology: []NodeInfo{{Name: challenge.Node, Role: "client"}},
		Tests: []TestOutcome{{Node: challenge.Node, Duration: 3 * time.Second, Diagnosis: &Diagnosis{
			Checks: []DiagnosisCheck{check}, Summary: "the target did not answer", Verdict: "service"}}},
		Evidence: Evidence{
			TCPResets: []TCPResetEvidence{{Node: mutation.Node, Event: "reset", Result: "connection_reset", Count: 1}},
			FamilyReachability: []FamilyReachabilityEvidence{
				{Node: challenge.Node, Family: "ipv4", State: FamilyStateReachable},
			},
		},
	}
}

func TestChallengeScoringMatchup(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	right, wrong := AnswerReset, AnswerDNSFailure
	if challenge.condition.answer != right {
		t.Fatalf("tcp_reset condition answers %s", challenge.condition.answer)
	}
	for _, tt := range []struct {
		name     string
		answer   ChallengeAnswer
		gaveUp   bool
		cause    string
		human    string
		netdoc   string
		expected string
	}{
		{"human right, netdoc wrong", right, false, "", ChallengeCorrect, ChallengeIncorrect, ChallengeHumanWins},
		{"human wrong, netdoc right", wrong, false, "connection_reset", ChallengeIncorrect, ChallengeCorrect, ChallengeNetdocWins},
		{"both right", right, false, "connection_reset", ChallengeCorrect, ChallengeCorrect, ChallengeDraw},
		{"both wrong", wrong, false, "", ChallengeIncorrect, ChallengeIncorrect, ChallengeNobodyWins},
		{"gave up, netdoc right", "", true, "connection_reset", ChallengeGaveUp, ChallengeCorrect, ChallengeNetdocWins},
		{"gave up, netdoc wrong", "", true, "", ChallengeGaveUp, ChallengeIncorrect, ChallengeNobodyWins},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := resetChallengeReport(t, challenge, tt.cause)
			result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: tt.answer, GaveUp: tt.gaveUp})
			if !result.Truth.Scoreable || result.Truth.Answer != right {
				t.Fatalf("truth = %+v", result.Truth)
			}
			if result.Human.Score != tt.human || result.NetworkDoctor.Score != tt.netdoc {
				t.Fatalf("scores = %s/%s, want %s/%s", result.Human.Score, result.NetworkDoctor.Score, tt.human, tt.netdoc)
			}
			if result.Result != tt.expected {
				t.Fatalf("result = %s, want %s", result.Result, tt.expected)
			}
		})
	}
}

// The human's answer is an input to one grading function and to nothing else.
// Changing it must not move the truth or Network Doctor's score by so much as a
// field.
func TestChallengeHumanAnswerCannotMoveTruthOrNetdoc(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	report := resetChallengeReport(t, challenge, "connection_reset")
	baseline := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: AnswerReset})
	for _, item := range ChallengeAnswerMenu {
		result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: item.ID})
		if !reflectEqualJSON(t, result.Truth, baseline.Truth) {
			t.Fatalf("answering %s changed the truth", item.ID)
		}
		if !reflectEqualJSON(t, result.NetworkDoctor, baseline.NetworkDoctor) {
			t.Fatalf("answering %s changed Network Doctor's score", item.ID)
		}
		want := ChallengeIncorrect
		if item.ID == AnswerReset {
			want = ChallengeCorrect
		}
		if result.Human.Score != want {
			t.Fatalf("answering %s scored %s, want %s", item.ID, result.Human.Score, want)
		}
	}
}

// A mutation that was generated and applied but left no independent evidence is
// not an answer. Scoring it would tell the player the simulator knows something
// it does not.
func TestChallengeWithoutObservedFaultIsNotScored(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	report := resetChallengeReport(t, challenge, "connection_reset")
	report.Evidence.TCPResets = nil
	result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: challenge.condition.answer})
	if result.Truth.Scoreable || result.Truth.Answer != "" {
		t.Fatalf("truth = %+v, want unscoreable with no answer", result.Truth)
	}
	if result.Result != ChallengeNoResult {
		t.Fatalf("result = %s, want %s", result.Result, ChallengeNoResult)
	}
	if result.Human.Score != ChallengeUnscoreable || result.NetworkDoctor.Score != ChallengeUnscoreable {
		t.Fatalf("scores = %s/%s, want both unscoreable", result.Human.Score, result.NetworkDoctor.Score)
	}
	if result.Truth.Reason == "" {
		t.Fatal("an unscoreable challenge has to say why")
	}
}

// A service reset the mutation did not install cannot answer for it either: the
// evidence has to name the node the mutation aimed at.
func TestChallengeFaultObservedElsewhereIsNotScored(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	report := resetChallengeReport(t, challenge, "connection_reset")
	report.Evidence.TCPResets[0].Node = "some-other-node"
	result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: challenge.condition.answer})
	if result.Truth.Scoreable {
		t.Fatalf("a reset on another node scored the challenge: %+v", result.Truth)
	}
}

func TestChallengeWithoutADiagnosisIsNotScored(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	report := resetChallengeReport(t, challenge, "connection_reset")
	report.Tests[0].Diagnosis = nil
	result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: challenge.condition.answer})
	if result.Truth.Scoreable || result.Result != ChallengeNoResult {
		t.Fatalf("no diagnosis must be no matchup: %+v", result)
	}
}

func TestChallengeSimulatorFailureIsNotScored(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	for _, tt := range []struct {
		name    string
		mutate  func(*Report)
		wantHas string
	}{
		{"setup failed", func(r *Report) { r.Error = "setup failed: no namespaces" }, "did not complete"},
		{"cleanup failed", func(r *Report) { r.Cleanup = CleanupInfo{Done: false} }, "clean up"},
		{"no report", nil, "no report"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var report *Report
			if tt.mutate != nil {
				report = resetChallengeReport(t, challenge, "connection_reset")
				tt.mutate(report)
			}
			result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: challenge.condition.answer})
			if result.Truth.Scoreable || result.Result != ChallengeNoResult {
				t.Fatalf("result = %+v, want no result", result)
			}
			if !strings.Contains(result.Truth.Reason, tt.wantHas) {
				t.Fatalf("reason = %q, want it to mention %q", result.Truth.Reason, tt.wantHas)
			}
		})
	}
}

// The healthy challenge needs positive evidence that the network worked. The
// absence of a measurement is not a healthy network.
func TestHealthyChallengeNeedsMeasuredHealth(t *testing.T) {
	challenge := challengeWithMutation(t, "")
	healthy := func() *Report {
		return &Report{
			Cleanup:  CleanupInfo{Done: true},
			Topology: []NodeInfo{{Name: challenge.Node, Role: "client"}},
			Tests: []TestOutcome{{Node: challenge.Node, Diagnosis: &Diagnosis{
				Checks: []DiagnosisCheck{{ID: "dns", Status: "PASS"}}, Verdict: "ok", OK: true}}},
			Evidence: Evidence{FamilyReachability: []FamilyReachabilityEvidence{
				{Node: challenge.Node, Family: "ipv4", State: FamilyStateReachable},
				{Node: challenge.Node, Family: "ipv6", State: FamilyStateUnavailable},
			}},
		}
	}
	result := ScoreChallenge(challenge, healthy(), ChallengeSubmission{Answer: AnswerHealthy})
	if !result.Truth.Scoreable || result.Truth.Answer != AnswerHealthy {
		t.Fatalf("truth = %+v", result.Truth)
	}
	if result.Human.Score != ChallengeCorrect || result.NetworkDoctor.Score != ChallengeCorrect {
		t.Fatalf("both named a healthy network: %+v", result)
	}

	for _, tt := range []struct {
		name   string
		mutate func(*Report)
	}{
		{"nothing measured", func(r *Report) { r.Evidence.FamilyReachability = nil }},
		{"a condition was unreachable", func(r *Report) {
			r.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
		}},
		{"a link was down", func(r *Report) {
			r.Evidence.Links = []LinkEvidence{{Node: challenge.Node, Segment: "lan", Up: false}}
		}},
		{"DNS was failing", func(r *Report) {
			r.Evidence.DNSQueries = []DNSQueryEvidence{{Node: "resolver", Service: "r", ActualOutcome: "SERVFAIL"}}
		}},
		{"a controlled target was unreachable", func(r *Report) {
			r.Evidence.ControlledTargets = []ControlledTargetEvidence{
				{From: challenge.Node, To: "controlled.test", Family: "ipv4", Reachable: false}}
		}},
		{"the gateway did not answer", func(r *Report) {
			no := false
			r.Evidence.Routes = []RouteEvidence{{Node: challenge.Node, Family: "ipv4", Destination: "default",
				Via: "10.0.0.1", Selected: true, GatewayReachable: &no}}
		}},
		{"a service reset connections", func(r *Report) {
			r.Evidence.TCPResets = []TCPResetEvidence{
				{Node: "target", Event: "reset", Result: "connection_reset", Count: 1}}
		}},
		{"a TLS handshake was refused", func(r *Report) {
			r.Evidence.TLS = []TLSEvidence{{Node: "target", Service: "tls-target",
				CertificateMode: TLSCertificateExpired, CertificatePresented: true,
				Result: "client_rejected_certificate", Count: 1}}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := healthy()
			tt.mutate(report)
			result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: AnswerHealthy})
			if result.Truth.Scoreable {
				t.Fatalf("scored a healthy challenge on a network that was not measured healthy: %+v", result.Truth)
			}
		})
	}
}

// Every fault a challenge can inject has to be a fault the healthy oracle would
// have caught, or "healthy" means "we did not look" for that condition. The
// mapping is spelled out in healthyObserved's comment; this keeps it honest by
// requiring a rejecting check to exist for each one.
func TestHealthyChallengeCoversEveryCondition(t *testing.T) {
	challenge := challengeWithMutation(t, "")
	// Each entry is the evidence the named condition leaves behind, dropped into an
	// otherwise-healthy report. It must stop the healthy verdict.
	contradictions := map[string]func(*Report){
		"dns.servfail": func(r *Report) {
			r.Evidence.DNSQueries = []DNSQueryEvidence{{Node: "resolver", Service: "r", ActualOutcome: "SERVFAIL"}}
		},
		"dns.drop": func(r *Report) {
			r.Evidence.DNSQueries = []DNSQueryEvidence{{Node: "resolver", Service: "r", ActualOutcome: "DROPPED"}}
		},
		"service.tcp_reset": func(r *Report) {
			r.Evidence.TCPResets = []TCPResetEvidence{
				{Node: "target", Event: "reset", Result: "connection_reset", Count: 1}}
		},
		"service.tls_expired": func(r *Report) {
			r.Evidence.TLS = []TLSEvidence{{Node: "target", Service: "tls-target",
				CertificateMode: TLSCertificateExpired, CertificatePresented: true,
				Result: "client_rejected_certificate", Count: 1}}
		},
		"family.ipv4_drop": func(r *Report) {
			r.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
		},
		"family.ipv6_drop": func(r *Report) {
			r.Evidence.FamilyReachability[1] = FamilyReachabilityEvidence{
				Node: challenge.Node, Family: "ipv6", State: FamilyStateUnreachable}
		},
		"routing.preferred_path_failure": func(r *Report) {
			r.Evidence.ControlledTargets = []ControlledTargetEvidence{
				{From: challenge.Node, To: "controlled.test", Family: "ipv4", Reachable: false}}
		},
		"netem.loss": func(r *Report) {
			r.Evidence.PacketConditions = []PacketConditionEvidence{{Node: "gateway", Segment: "upstream",
				LossPercent: 12, Active: true, DroppedPackets: 7}}
		},
		"service.connection_refused": func(r *Report) {
			r.Evidence.ControlledTargets = []ControlledTargetEvidence{
				{From: challenge.Node, To: "10.77.0.20:80", Family: "ipv4", Outcome: TargetStateRefused}}
		},
		"service.tcp_port_blocked": func(r *Report) {
			r.Evidence.PacketDrops = []PacketDropEvidence{{Node: "target", Protocol: "tcp", Port: 80,
				Direction: DirectionInbound, Packets: 3}}
		},
		"service.tls_hostname_mismatch": func(r *Report) {
			r.Evidence.TLS = []TLSEvidence{{Node: "target", Service: "tls-target",
				CertificateMode: TLSCertificateHostnameMismatch, RequestedServer: "secure-target.test",
				CertificateDNS: []string{"somewhere-else.test"}, CertificatePresented: true,
				Result: "client_rejected_certificate", Count: 1}}
		},
		"routing.no_default_route": func(r *Report) {
			r.Evidence.RouteTables = []RouteTableEvidence{{Node: challenge.Node, Family: "ipv4",
				Routes: []KernelRoute{{Destination: "10.77.0.0/24", Segment: "client-lan"}}}}
		},
		"routing.wrong_default_route": func(r *Report) {
			r.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
		},
		"routing.missing_subnet_route": func(r *Report) {
			r.Evidence.ControlledTargets = []ControlledTargetEvidence{
				{From: challenge.Node, To: "10.77.3.20:80", Family: "ipv4", Outcome: FamilyStateUnreachable}}
		},
	}
	for _, condition := range challengeConditions {
		if condition.mutation == "" {
			continue
		}
		contradict, ok := contradictions[condition.mutation]
		if !ok {
			t.Fatalf("%s can be injected, but nothing here proves the healthy oracle would notice it",
				condition.mutation)
		}
		t.Run(condition.mutation, func(t *testing.T) {
			report := &Report{
				Cleanup:  CleanupInfo{Done: true},
				Topology: []NodeInfo{{Name: challenge.Node, Role: "client"}},
				Tests: []TestOutcome{{Node: challenge.Node, Diagnosis: &Diagnosis{
					Checks: []DiagnosisCheck{{ID: "dns", Status: "PASS"}}, Verdict: "ok", OK: true}}},
				Evidence: Evidence{FamilyReachability: []FamilyReachabilityEvidence{
					{Node: challenge.Node, Family: "ipv4", State: FamilyStateReachable},
					{Node: challenge.Node, Family: "ipv6", State: FamilyStateReachable},
				}},
			}
			contradict(report)
			result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: AnswerHealthy})
			if result.Truth.Scoreable {
				t.Fatalf("evidence of %s left a healthy challenge scoreable as healthy: %+v",
					condition.mutation, result.Truth)
			}
		})
	}
}

// The recognition half of every condition, as a table. Network Doctor is graded on
// what its own report says about the network, never on a Challenge-only
// expected label. For the three conditions the hunt oracle already grades, the
// rule here is that oracle's, reused rather than restated.
func TestChallengeRecognizesNetdocsOwnVocabulary(t *testing.T) {
	fail := func(id, cause string) *Diagnosis {
		return &Diagnosis{Verdict: "service", Checks: []DiagnosisCheck{{ID: id, Status: "FAIL", Cause: cause}}}
	}
	healthy := &Diagnosis{Verdict: diagnostic.VerdictOK, OK: true,
		Checks: []DiagnosisCheck{{ID: "dns", Status: "PASS"}, {ID: "http", Status: "PASS"}}}
	for _, tt := range []struct {
		mutation  string
		recognize []*Diagnosis
		reject    []*Diagnosis
	}{
		{"dns.servfail",
			[]*Diagnosis{fail("dns", "dns_temporary_failure"), fail("dns", "dns_timeout"), fail("dns", "")},
			[]*Diagnosis{healthy, fail("http", "dns_temporary_failure")}},
		{"dns.drop",
			[]*Diagnosis{fail("dns", "dns_timeout")},
			[]*Diagnosis{healthy}},
		{"service.tcp_reset",
			[]*Diagnosis{fail("http", "connection_reset"), fail("ssh_banner", "connection_reset")},
			[]*Diagnosis{healthy, fail("http", ""), fail("http", "timeout")}},
		{"service.connection_refused",
			[]*Diagnosis{fail("target_tcp", diagnostic.ConnectionCauseRefused)},
			[]*Diagnosis{healthy, fail("target_tcp", ""), fail("target_tcp", diagnostic.ConnectionCauseReset),
				fail("proxy_connect", diagnostic.ProxyCauseDestinationUnreachable)}},
		{"service.tls_expired",
			[]*Diagnosis{fail("tls", "certificate_expired"), fail("https", "certificate_expired")},
			[]*Diagnosis{healthy, fail("tls", "tls_handshake_failure")}},
		{"family.ipv4_drop",
			[]*Diagnosis{fail("internet_tcp", "ipv4_unreachable"),
				{Checks: []DiagnosisCheck{{ID: "internet_tcp", Status: "WARN",
					Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable, IPv6: FamilyStateReachable}}}}},
			[]*Diagnosis{healthy, fail("internet_tcp", "ipv6_unreachable")}},
		{"family.ipv6_drop",
			[]*Diagnosis{fail("internet_tcp", "ipv6_unreachable")},
			[]*Diagnosis{healthy, fail("internet_tcp", "ipv4_unreachable")}},
		// The name half of a certificate failure, and deliberately not the date
		// half: an expired-certificate verdict sends the user to check a clock
		// for a certificate whose dates are fine.
		{"service.tls_hostname_mismatch",
			[]*Diagnosis{fail("tls", "hostname_mismatch"), fail("https", "hostname_mismatch")},
			[]*Diagnosis{healthy, fail("tls", "certificate_expired"), fail("tls", "untrusted_issuer"),
				fail("tls", "tls_handshake_failure"), fail("tls", "tcp_unreachable")}},
		// Missing-default evidence is distinct from gateway state or ordinary
		// route selection metadata.
		{"routing.no_default_route",
			[]*Diagnosis{fail("internet_tcp", "no_default_route"), fail("route", "no_default_route")},
			[]*Diagnosis{healthy, fail("internet_tcp", "selected_path_failed"),
				fail("internet_tcp", "preferred_route_failed"), fail("internet_tcp", "gateway_unreachable"),
				fail("internet_tcp", "")}},
	} {
		condition, ok := challengeConditionFor(tt.mutation)
		if !ok {
			t.Fatalf("%s is no longer a challenge condition; drop it here too", tt.mutation)
		}
		recognized, known := challengeRecognition[condition.answer]
		if !known {
			t.Fatalf("%s answers %s, which no longer has a recognition rule; drop it here too",
				tt.mutation, condition.answer)
		}
		t.Run(tt.mutation, func(t *testing.T) {
			for _, d := range tt.recognize {
				if !recognized(d) {
					t.Errorf("%s was not recognized as %s: %+v", tt.mutation, condition.answer, d.Checks)
				}
			}
			for _, d := range tt.reject {
				if recognized(d) {
					t.Errorf("%s was scored correct on a diagnosis that does not name it: %+v", tt.mutation, d.Checks)
				}
			}
		})
	}
	// The healthy condition is the same question asked of a whole report.
	recognizedHealthy := challengeRecognition[AnswerHealthy]
	if !recognizedHealthy(healthy) || recognizedHealthy(fail("dns", "dns_timeout")) {
		t.Fatal("the healthy condition does not follow netdoc's own verdict")
	}
}

// ---- the challenge contract ----
//
// The seven tests below are the architecture, not one regression each. Together
// they say: what the simulator can prove decides which challenges exist, what
// netdoc says decides only who wins, and nothing may cross between the two.

// lossChallengeReport is a report for a netem.loss challenge. The packet
// condition carries the shaper's own kernel drop counter, which is what makes
// the impairment observed; verdict is the `ok` netdoc really returns for the
// `packet-loss` control scenario.
func lossChallengeReport(t *testing.T, challenge *Challenge) *Report {
	t.Helper()
	m := challenge.Manifest.Mutations[0]
	return &Report{
		Cleanup:  CleanupInfo{Done: true},
		Topology: []NodeInfo{{Name: challenge.Node, Role: "client"}},
		Tests: []TestOutcome{{Node: challenge.Node, Duration: 3 * time.Second, Diagnosis: &Diagnosis{
			Checks:  []DiagnosisCheck{{ID: "internet_tcp", Status: "PASS"}, {ID: "dns", Status: "PASS"}},
			Summary: "every check passed", Verdict: diagnostic.VerdictOK, OK: true}}},
		Evidence: Evidence{
			PacketConditions: []PacketConditionEvidence{{Node: m.Node, Segment: m.Segment,
				Latency: msDuration(m.LatencyMS), Jitter: msDuration(m.JitterMS),
				LossPercent: m.LossPercent, Seed: m.NetemSeed, Active: true, DroppedPackets: 9}},
			FamilyReachability: []FamilyReachabilityEvidence{
				{Node: challenge.Node, Family: "ipv4", State: FamilyStateReachable},
			},
		},
	}
}

// 1. The TCP reset diagnosis, end to end. The simulator proves the target
// reset the connection and netdoc identifies the same condition.
func TestChallengeTCPResetIsDiagnosed(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	report := resetChallengeReport(t, challenge, diagnostic.ConnectionCauseReset)
	report.Tests[0].Diagnosis.Summary = "No HTTP response from the target: application-layer or proxy block."
	result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: AnswerReset})

	if !result.Truth.Scoreable || result.Truth.Answer != AnswerReset {
		t.Fatalf("an observed reset did not become gradeable truth: %+v", result.Truth)
	}
	if !slices.Contains(result.Truth.ObservedFaults, "service.tcp_reset") {
		t.Fatalf("truth does not rest on the observed reset: %+v", result.Truth.ObservedFaults)
	}
	if result.NetworkDoctor.Score != ChallengeCorrect {
		t.Fatalf("netdoc scored %s on a reset it classified", result.NetworkDoctor.Score)
	}
	if result.Result != ChallengeDraw {
		t.Fatalf("result = %s, want %s", result.Result, ChallengeDraw)
	}
}

// 2. The other direction. A condition netdoc does state in its own vocabulary
// is netdoc's round, and the contract has to keep working there or it has only
// been rigged the other way.
func TestChallengeRecognizedConditionIsANetdocWin(t *testing.T) {
	challenge := challengeWithMutation(t, "family.ipv4_drop")
	report := &Report{
		Cleanup:  CleanupInfo{Done: true},
		Topology: []NodeInfo{{Name: challenge.Node, Role: "client"}},
		Tests: []TestOutcome{{Node: challenge.Node, Diagnosis: &Diagnosis{Verdict: "network",
			Checks: []DiagnosisCheck{{ID: "internet_tcp", Status: "FAIL",
				Cause: diagnostic.FamilyCauseIPv4Unreachable}}}}},
		Evidence: Evidence{FamilyReachability: []FamilyReachabilityEvidence{
			{Node: challenge.Node, Family: "ipv4", State: FamilyStateUnreachable},
			{Node: challenge.Node, Family: "ipv6", State: FamilyStateReachable},
		}},
	}
	result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: AnswerDNSFailure})
	if result.NetworkDoctor.Score != ChallengeCorrect || result.Result != ChallengeNetdocWins {
		t.Fatalf("netdoc named the condition and did not win: %s / %s",
			result.NetworkDoctor.Score, result.Result)
	}
}

// 3. Eligibility does not need a diagnosis mapping to exist. netem.loss is a
// real condition the simulator can prove and netdoc's cause vocabulary has no
// verdict for at all. It is generated anyway, and netdoc loses it as
// unrecognized rather than as a wrong answer.
func TestChallengeAdmitsAConditionNetdocCannotState(t *testing.T) {
	challenge := challengeWithMutation(t, "netem.loss")
	if _, known := challengeRecognition[challenge.condition.answer]; known {
		t.Fatalf("%s now has a recognition rule; this test needs a condition that has none",
			challenge.condition.mutation)
	}
	result := ScoreChallenge(challenge, lossChallengeReport(t, challenge),
		ChallengeSubmission{Answer: AnswerPacketLoss})
	if !result.Truth.Scoreable || result.Truth.Answer != AnswerPacketLoss {
		t.Fatalf("observed packet loss did not become gradeable truth: %+v", result.Truth)
	}
	if result.NetworkDoctor.Score != ChallengeUnrecognized {
		t.Fatalf("netdoc scored %s on a condition it has no verdict for", result.NetworkDoctor.Score)
	}
	if result.NetworkDoctor.Note == "" {
		t.Fatal("an unrecognized condition has to say that is what happened")
	}
	if result.Result != ChallengeHumanWins {
		t.Fatalf("result = %s, want %s", result.Result, ChallengeHumanWins)
	}
	// A clean netdoc report is not evidence of anything either way. The score
	// above came from the recognition table being empty for this answer, and it
	// must not move when netdoc says more.
	loud := lossChallengeReport(t, challenge)
	loud.Tests[0].Diagnosis = &Diagnosis{Verdict: "network", Checks: []DiagnosisCheck{
		{ID: "internet_tcp", Status: "WARN", Cause: "", Detail: "high latency (900ms)"}}}
	if ScoreChallenge(challenge, loud, ChallengeSubmission{Answer: AnswerPacketLoss}).NetworkDoctor.Score !=
		ChallengeUnrecognized {
		t.Fatal("a noisier report changed an unrecognized condition's score")
	}
}

// 4. A mutation that was generated, applied, and read back off the kernel with
// exactly the parameters that were asked for still proves nothing. Only the
// drop counter says traffic met it, and without that there is no challenger
// victory to take.
func TestChallengeConfiguredButUnmetFaultCannotWin(t *testing.T) {
	challenge := challengeWithMutation(t, "netem.loss")
	report := lossChallengeReport(t, challenge)
	// The shaper is installed and active with the manifest's own parameters.
	// The only thing missing is a packet.
	report.Evidence.PacketConditions[0].DroppedPackets = 0
	result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: AnswerPacketLoss})
	if result.Truth.Scoreable {
		t.Fatalf("a shaper that dropped nothing was scored as an observed fault: %+v", result.Truth)
	}
	if result.Result != ChallengeNoResult || result.Human.Score != ChallengeUnscoreable {
		t.Fatalf("result = %s, human = %s; a configured fault must not beat netdoc",
			result.Result, result.Human.Score)
	}
	if result.NetworkDoctor.Score != ChallengeUnscoreable {
		t.Fatalf("netdoc scored %s on a challenge with no established truth", result.NetworkDoctor.Score)
	}
	// The manifest still says exactly what was asked for. Truth read it for the
	// mutation id to demand evidence of, and for nothing else.
	if result.Truth.Injected == "" {
		t.Fatal("the reveal should still say what the generator asked for")
	}
}

// 5. No evidence at all is inconclusive, not a win. This is the case a
// challenger would most like to be scored generously on: they named the
// condition, and the simulator simply cannot say whether it happened.
func TestChallengeWithoutEvidenceIsInconclusiveNotAWin(t *testing.T) {
	for _, tt := range []struct {
		name     string
		mutation string
		strip    func(*Report)
		report   func(*testing.T, *Challenge) *Report
	}{
		{"no packet conditions were collected", "netem.loss",
			func(r *Report) { r.Evidence.PacketConditions = nil }, lossChallengeReport},
		{"no reset was recorded", "service.tcp_reset",
			func(r *Report) { r.Evidence.TCPResets = nil },
			func(t *testing.T, c *Challenge) *Report { return resetChallengeReport(t, c, "") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			challenge := challengeWithMutation(t, tt.mutation)
			report := tt.report(t, challenge)
			tt.strip(report)
			result := ScoreChallenge(challenge, report,
				ChallengeSubmission{Answer: challenge.condition.answer})
			if result.Result != ChallengeNoResult {
				t.Fatalf("result = %s, want %s", result.Result, ChallengeNoResult)
			}
			if result.Human.Score == ChallengeCorrect {
				t.Fatal("a challenger was credited for naming a condition nothing established")
			}
			if result.Truth.Reason == "" {
				t.Fatal("an inconclusive challenge has to say why")
			}
		})
	}
}

// The packaging around this binary decides how a reader of a result should run
// it: the container image sets its own `docker run …` line, because whoever
// reads a posted result may have no netdoc-sim and no Linux. Only the printed
// invitation moves, the id and therefore the puzzle is untouched, and the
// value is external input on its way to a terminal and a forum post, so it is
// sanitized and bounded like everything else this package prints.
func TestChallengeCommandComesFromTheEnvironment(t *testing.T) {
	challenge, err := BuildChallenge("V3-8F42C1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := challenge.Replay(), "netdoc-sim challenge -id V3-8F42C1"; got != want {
		t.Fatalf("default replay = %q, want %q", got, want)
	}
	for _, tt := range []struct {
		name, env, want string
	}{
		{"a container invocation", "docker run --rm -it netdoc-sim challenge",
			"docker run --rm -it netdoc-sim challenge -id V3-8F42C1"},
		{"unset falls back", "", "netdoc-sim challenge -id V3-8F42C1"},
		{"terminal escapes are stripped", "docker \x1b]0;pwned\x07run",
			"docker run -id V3-8F42C1"},
		{"an overlong value falls back", strings.Repeat("x", challengeCommandLimit+1),
			"netdoc-sim challenge -id V3-8F42C1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(challengeCommandEnv, tt.env)
			if got := challenge.Replay(); got != tt.want {
				t.Errorf("replay = %q, want %q", got, tt.want)
			}
		})
	}
}

// 6. A netdoc loss is worth nothing if it cannot be handed to somebody else.
// The id is the whole reproduction contract, so rebuilding from the result's
// own identity fields has to produce the same case and the same verdict.
func TestChallengeLossReplaysFromItsOwnIdentity(t *testing.T) {
	for _, mutation := range []string{"service.tcp_reset", "netem.loss"} {
		t.Run(mutation, func(t *testing.T) {
			challenge := challengeWithMutation(t, mutation)
			build := func(c *Challenge) *ChallengeResult {
				report := lossChallengeReport(t, c)
				if mutation == "service.tcp_reset" {
					report = resetChallengeReport(t, c, "")
				}
				return ScoreChallenge(c, report, ChallengeSubmission{Answer: c.condition.answer,
					Elapsed: 42 * time.Second})
			}
			first := build(challenge)
			if first.Result != ChallengeHumanWins {
				t.Fatalf("this case is not a netdoc loss: %s", first.Result)
			}

			// Everything a replay is given: the id in the result, and the command
			// the result prints. Nothing else is carried over.
			if first.Replay != "netdoc-sim challenge -id "+first.ChallengeID {
				t.Fatalf("replay line = %q", first.Replay)
			}
			replayed, err := BuildChallenge(first.ChallengeID)
			if err != nil {
				t.Fatalf("replay %s: %v", first.ChallengeID, err)
			}
			if replayed.Base != challenge.Base || replayed.Case != challenge.Case ||
				replayed.Manifest.CaseFingerprint != first.CaseFingerprint {
				t.Fatalf("replay resolved to %s/%d/%s, want %s/%d/%s", replayed.Base, replayed.Case,
					replayed.Manifest.CaseFingerprint, challenge.Base, challenge.Case, first.CaseFingerprint)
			}
			second := build(replayed)
			first.Timing, second.Timing = ChallengeTiming{}, ChallengeTiming{}
			if !reflectEqualJSON(t, first, second) {
				t.Fatal("a replayed loss did not reproduce the same result")
			}
		})
	}
}

// 7. The selection-bias regression. Challenge Mode's universe is defined by
// what the simulator can prove, so it must be strictly wider than the set of
// conditions Network Doctor already has a rule for. If these two sets ever
// coincide again, the game has quietly gone back to grading netdoc on questions
// written from its own answer sheet.
func TestChallengeEligibilityIsNotTheRecognizedSet(t *testing.T) {
	var unrecognized []string
	for _, condition := range challengeConditions {
		if _, known := challengeRecognition[condition.answer]; !known {
			unrecognized = append(unrecognized, condition.mutation)
		}
	}
	if len(unrecognized) == 0 {
		t.Fatal("every challengeable condition has a netdoc recognition rule, so challenge" +
			" eligibility is once again the set of faults netdoc already handles")
	}
	// Every recognition rule must belong to a condition that can be set, or the
	// table has grown a half nothing grades against.
	answers := map[ChallengeAnswer]bool{}
	for _, condition := range challengeConditions {
		answers[condition.answer] = true
	}
	for answer := range challengeRecognition {
		if !answers[answer] {
			t.Errorf("recognition rule for %s grades a condition no challenge can set", answer)
		}
	}

	// And the wider set is reachable, not just declared: generation really
	// resolves ids to a condition with no recognition rule.
	generated := map[string]bool{}
	for _, id := range challengeIDs(400) {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		if _, known := challengeRecognition[challenge.condition.answer]; !known {
			generated[challenge.condition.mutation] = true
		}
	}
	for _, mutation := range unrecognized {
		if !generated[mutation] {
			t.Errorf("%s is eligible but no sampled id generates it, so the wider universe is"+
				" declared and not reachable", mutation)
		}
	}
}

// Network Doctor is graded on the run the player was asked about, and on its
// own structured output alone.
func TestNetdocIsGradedOnThePrimaryClientRun(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	report := resetChallengeReport(t, challenge, "")
	// A later run against a different target that does classify a reset must not
	// be borrowed as an answer to the question the player was asked.
	report.Tests = append(report.Tests, TestOutcome{Node: challenge.Node, Target: "10.0.0.9:80",
		Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "http", Status: "FAIL", Cause: "connection_reset"}}}})
	result := ScoreChallenge(challenge, report, ChallengeSubmission{GaveUp: true})
	if result.NetworkDoctor.Score != ChallengeIncorrect {
		t.Fatalf("netdoc scored %s from a run the challenge did not ask about", result.NetworkDoctor.Score)
	}
}

func TestChallengeJSONIsDeterministicExceptTiming(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	render := func(elapsed, netdocRun time.Duration) string {
		report := resetChallengeReport(t, challenge, "connection_reset")
		report.Tests[0].Duration = netdocRun
		result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: AnswerReset, Elapsed: elapsed})
		result.Timing = ChallengeTiming{}
		var out bytes.Buffer
		if err := result.WriteJSON(&out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	first := render(90*time.Second, 3*time.Second)
	second := render(4*time.Second, 900*time.Millisecond)
	if first != second {
		t.Fatalf("challenge JSON is not deterministic:\n%s\n%s", first, second)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(first), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"challenge_id", "difficulty", "truth", "human", "network_doctor", "netdoc", "result", "replay"} {
		if _, ok := decoded[field]; !ok {
			t.Fatalf("challenge JSON has no %q field", field)
		}
	}
}

// A challenge result is only reproducible if it says which Network Doctor
// produced it. The path is not carried alongside the run; it is read back off
// the argv the run was built from, so a result cannot name a binary other than
// the one that executed.
func TestChallengeResultRecordsTheNetdocThatRan(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	env := &fakeEnv{stdout: `{"checks":[{"id":"http","status":"FAIL"}],"verdict":"service"}`}
	backend := &fakeBackend{caps: Capabilities{Supported: true, Backend: "fake"}, env: env}
	result, err := RunChallenge(context.Background(), challenge, backend, ChallengeOptions{
		Run:           Options{Netdoc: "/opt/builds/netdoc"},
		NetdocVersion: "netdoc v1.2.3",
		Play: func(context.Context, *ChallengeSession) (ChallengeSubmission, error) {
			return ChallengeSubmission{Answer: AnswerReset}, nil
		},
	})
	if err != nil {
		t.Fatalf("run challenge: %v", err)
	}
	if result.Netdoc.Path != "/opt/builds/netdoc" || result.Netdoc.Version != "netdoc v1.2.3" {
		t.Fatalf("result records %+v", result.Netdoc)
	}
	if len(env.lastArgv) == 0 || env.lastArgv[0] != result.Netdoc.Path {
		t.Fatalf("netdoc ran as %v, but the result names %q", env.lastArgv, result.Netdoc.Path)
	}

	var out bytes.Buffer
	if err := result.WriteJSON(&out); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Netdoc NetdocIdentity `json:"netdoc"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Netdoc != result.Netdoc {
		t.Fatalf("challenge JSON carries %+v, want %+v", decoded.Netdoc, result.Netdoc)
	}

	// The reveal is the one place a person sees it; per-test output stays clean.
	var text bytes.Buffer
	result.WriteText(&text)
	for _, want := range []string{"/opt/builds/netdoc", "netdoc v1.2.3"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("the reveal does not show %q:\n%s", want, text.String())
		}
	}
}

// A development build reports `dev`, and that is the honest identity of the
// thing that ran. Nothing may substitute a release-looking version for it.
func TestChallengeResultKeepsADevelopmentVersion(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	report := resetChallengeReport(t, challenge, "connection_reset")
	result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: AnswerReset})
	result.Netdoc = NetdocIdentity{Path: "/home/dev/network-doctor/netdoc", Version: "netdoc dev"}
	var out bytes.Buffer
	if err := result.WriteJSON(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"version": "netdoc dev"`) {
		t.Fatalf("challenge JSON did not preserve a development version:\n%s", out.String())
	}
}

// The share block is the thing people paste in public. It must not name the
// fault, or the first person to post one spoils the challenge for everybody who
// reads it.
func TestChallengeShareBlockNamesNoFault(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	report := resetChallengeReport(t, challenge, "connection_reset")
	result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: AnswerReset, Note: "the service resets"})
	share := strings.ToLower(result.Share())
	for _, secret := range []string{string(result.Truth.Answer), strings.ToLower(result.Truth.Label),
		strings.ToLower(result.Truth.Explanation), strings.ToLower(result.Truth.Injected),
		"connection_reset", challenge.Base, "the service resets"} {
		if secret != "" && strings.Contains(share, secret) {
			t.Fatalf("share block leaks %q:\n%s", secret, result.Share())
		}
	}
	if !strings.Contains(result.Share(), challenge.ID) {
		t.Fatalf("share block has to carry the id:\n%s", result.Share())
	}
}

func TestNormalizeChallengeID(t *testing.T) {
	// Bare, prefixed, lowercase and hash-prefixed are all one id, and a bare id
	// means V1 permanently, since it was the only form the first release printed.
	for _, raw := range []string{"8f42c1", " #8F42C1 ", "8F42C1", "v1-8f42c1", "#V1-8F42C1"} {
		got, err := NormalizeChallengeID(raw)
		if err != nil || got != "V1-8F42C1" {
			t.Fatalf("NormalizeChallengeID(%q) = %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"", "8F42C", "8F42C11", "8G42C1", "../../etc", "8F 42C1",
		"V9-8F42C1", "V1-", "-8F42C1", "V1-8F42C1-extra"} {
		if _, err := NormalizeChallengeID(raw); err == nil {
			t.Fatalf("NormalizeChallengeID(%q) was accepted", raw)
		}
	}
	if _, err := BuildChallenge("V9-8F42C1"); err == nil {
		t.Fatal("an id whose version this build cannot resolve must be rejected, not guessed at")
	}
	// A future version reusing the same digits must be a different challenge.
	if challengeSeed("V1", "8F42C1") == challengeSeed("V2", "8F42C1") {
		t.Fatal("the id version is not part of the seed domain")
	}
}

func TestFindChallengeHonoursDifficulty(t *testing.T) {
	for _, difficulty := range ChallengeDifficulties {
		challenge, err := FindChallenge(difficulty)
		if err != nil {
			t.Fatalf("find %s: %v", difficulty, err)
		}
		if challenge.Difficulty != difficulty {
			t.Fatalf("asked for %s, got %s", difficulty, challenge.Difficulty)
		}
	}
	if _, err := FindChallenge("impossible"); err == nil {
		t.Fatal("an unknown difficulty must be rejected")
	}
}

// RunChallenge hands the player the network before netdoc has run, and hands
// netdoc nothing about the challenge.
func TestRunChallengeOrderAndNetdocArguments(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	env := &fakeEnv{stdout: `{"checks":[{"id":"http","status":"FAIL"}],"verdict":"service"}`}
	backend := &fakeBackend{caps: Capabilities{Supported: true, Backend: "fake"}, env: env}
	execsWhenPlayed := -1
	_, err := RunChallenge(context.Background(), challenge, backend, ChallengeOptions{
		Run: Options{Netdoc: "/bin/netdoc"},
		Play: func(_ context.Context, session *ChallengeSession) (ChallengeSubmission, error) {
			execsWhenPlayed = env.execs
			if session.Challenge.ID != challenge.ID {
				t.Errorf("session carries challenge %s", session.Challenge.ID)
			}
			return ChallengeSubmission{Answer: AnswerReset}, nil
		},
	})
	if err != nil {
		t.Fatalf("run challenge: %v", err)
	}
	if execsWhenPlayed != 0 {
		t.Fatalf("netdoc ran %d times before the player answered", execsWhenPlayed)
	}
	if env.execs == 0 {
		t.Fatal("netdoc never ran")
	}
	if env.cleanups == 0 {
		t.Fatal("the challenge network was not cleaned up")
	}
	for _, arg := range env.lastArgv {
		for _, secret := range []string{challenge.ID, challenge.Base, "service.tcp_reset", "challenge", "mutation"} {
			if strings.Contains(arg, secret) {
				t.Fatalf("netdoc was told %q: %v", secret, env.lastArgv)
			}
		}
	}
	for _, kv := range env.lastEnv {
		if strings.Contains(strings.ToUpper(kv), "CHALLENGE") {
			t.Fatalf("netdoc's environment carries %q", kv)
		}
	}
}

type interactiveFakeEnv struct {
	*fakeEnv
	argv []string
	env  []string
}

func (e *interactiveFakeEnv) ExecInteractive(_ context.Context, _ string, argv, env []string,
	_ io.Reader, _, _ io.Writer) error {
	e.argv = slices.Clone(argv)
	e.env = slices.Clone(env)
	return nil
}

func TestChallengeSessionShell(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	unsupported := &ChallengeSession{Challenge: challenge, env: &fakeEnv{}}
	if unsupported.ShellAvailable() {
		t.Fatal("fake backend unexpectedly offers a shell")
	}
	if err := unsupported.Shell(context.Background(), nil, io.Discard, io.Discard); err == nil {
		t.Fatal("shell opened on a backend without interactive execution")
	}

	shell := filepath.Join(t.TempDir(), "player-shell")
	t.Setenv("SHELL", shell)
	env := &interactiveFakeEnv{fakeEnv: &fakeEnv{}}
	session := &ChallengeSession{Challenge: challenge, env: env, shellEnv: []string{"SSL_CERT_FILE=/sim/ca.pem"}}
	if !session.ShellAvailable() {
		t.Fatal("interactive backend does not offer a shell")
	}
	if err := session.Shell(context.Background(), nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(env.argv, []string{shell, "-i"}) {
		t.Errorf("shell argv = %q", env.argv)
	}
	wantEnv := []string{"NETDOC_CHALLENGE=" + challenge.ID,
		"NETDOC_CHALLENGE_TARGET=" + challenge.Target,
		"NETDOC_CHALLENGE_HOST=" + challengeTargetHost(challenge.Target),
		"SSL_CERT_FILE=/sim/ca.pem"}
	if !slices.Equal(env.env, wantEnv) {
		t.Errorf("shell env = %q, want %q", env.env, wantEnv)
	}

	t.Setenv("SHELL", "relative-shell")
	if got := loginShell(); got != "/bin/sh" {
		t.Errorf("relative login shell = %q, want /bin/sh", got)
	}
}

func TestRunChallengeStopsBeforePlayWhenTrustEnvironmentFails(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tls_expired")
	want := errors.New("trust anchor unavailable")
	env := &fakeEnv{trustErr: want}
	backend := &fakeBackend{caps: Capabilities{Supported: true, Backend: "fake"}, env: env}
	played := false
	result, err := RunChallenge(context.Background(), challenge, backend, ChallengeOptions{
		Run: Options{Netdoc: "/bin/netdoc"},
		Play: func(context.Context, *ChallengeSession) (ChallengeSubmission, error) {
			played = true
			return ChallengeSubmission{}, nil
		},
	})
	if err == nil || !errors.Is(err, want) || result != nil {
		t.Fatalf("trust failure returned result %+v, error %v", result, err)
	}
	if !strings.Contains(err.Error(), "challenge shell") {
		t.Fatalf("error does not explain the failed player environment: %v", err)
	}
	if played {
		t.Fatal("the player was handed a shell without the graded run's trust anchors")
	}
	if env.execs != 0 {
		t.Fatalf("netdoc ran %d times after trust setup failed", env.execs)
	}
	if env.cleanups == 0 {
		t.Fatal("trust setup failure did not clean up")
	}
}

// A player who walks out has not been scored, and the network still goes away.
func TestRunChallengeAbandonedRunsNoTestsAndCleansUp(t *testing.T) {
	challenge := challengeWithMutation(t, "service.tcp_reset")
	env := &fakeEnv{}
	backend := &fakeBackend{caps: Capabilities{Supported: true, Backend: "fake"}, env: env}
	result, err := RunChallenge(context.Background(), challenge, backend, ChallengeOptions{
		Run: Options{Netdoc: "/bin/netdoc"},
		Play: func(context.Context, *ChallengeSession) (ChallengeSubmission, error) {
			return ChallengeSubmission{}, errors.New("challenge abandoned")
		},
	})
	if err == nil || result != nil {
		t.Fatalf("an abandoned challenge is not a result: %v, %+v", err, result)
	}
	if env.execs != 0 {
		t.Fatalf("netdoc ran %d times after the challenge was abandoned", env.execs)
	}
	if env.cleanups == 0 {
		t.Fatal("an abandoned challenge did not clean up")
	}
}

func reflectEqualJSON(t *testing.T, a, b any) bool {
	t.Helper()
	one, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	two, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(one, two)
}

func TestSelectionMetadataCannotRecognizeRouteChallenges(t *testing.T) {
	for _, answer := range []ChallengeAnswer{AnswerWrongDefaultRoute, AnswerPreferredRoute} {
		if _, ok := challengeRecognition[answer]; ok {
			t.Fatalf("selection-only condition %s has a recognition rule", answer)
		}
	}
}
