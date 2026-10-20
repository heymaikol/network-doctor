package simulation

import (
	"fmt"
	"io"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// The three screens of a challenge: the briefing, which must not narrow the
// answer; the menu, which is the structured vocabulary; and the reveal, which
// may say everything.

// WriteBriefing prints what the player is told before they start, and prints it
// again whenever they ask for it mid-session. It is the only briefing renderer
// there is, deliberately: a separate "recall" format would be a second thing to
// keep truthful, and the one that drifted would be the one nobody reread.
//
// Everything here is either the id, the difficulty, or something the netdoc run
// is also given: the node it stands in and the target it is asked about. The
// base scenario, the seed, the case and the mutation stay out of it.
func (c *Challenge) WriteBriefing(w io.Writer) {
	fmt.Fprintf(w, "\nNETWORK DOCTOR CHALLENGE\nChallenge %s   Difficulty: %s\n", c.ID, c.Difficulty)
	if c.Daily != "" {
		// The date is what makes a daily comparable, so it is stated where the
		// player will read it rather than only in the result.
		fmt.Fprintf(w, "Daily challenge for %s (UTC)\n", c.Daily)
	}
	fmt.Fprintln(w, "\nSomething may be wrong with this network. Your job is to say what.")
	fmt.Fprintf(w, "\nYou are on:   %s\n", textsafe.Clean(c.Node))
	if c.Target == "" {
		fmt.Fprintln(w, "Investigate:  this machine's own connectivity, with no specific target")
	} else {
		fmt.Fprintf(w, "Investigate:  %s\n", textsafe.Clean(c.Target))
	}
	fmt.Fprintln(w, "\nInvestigate with whatever you would normally reach for: ping, dig, curl,")
	fmt.Fprintln(w, "ip route, ss, traceroute, nc. Commit to a diagnosis when you are ready.")
	fmt.Fprintln(w, "Network Doctor then gets the same network, and has not seen the answer either.")
}

// WriteAnswerMenu prints the structured diagnosis vocabulary. It lists more
// faults than a challenge can inject on purpose: a menu of only the possible
// answers would be most of the answer.
func WriteAnswerMenu(w io.Writer) {
	fmt.Fprintln(w, "\nWhat is the primary problem?")
	for i, item := range ChallengeAnswerMenu {
		fmt.Fprintf(w, "%3d. %-38s %s\n", i+1, item.Label, item.Help)
	}
	fmt.Fprintln(w, "\n  s. back to the shell   b. read the briefing again   q. give up and reveal")
}

func (r *ChallengeResult) WriteJSON(w io.Writer) error { return writeJSON(w, r) }

// WriteText is the reveal. It runs only after both answers are in.
func (r *ChallengeResult) WriteText(w io.Writer) {
	fmt.Fprintf(w, "\nRESULT: CHALLENGE %s\n", r.ChallengeID)
	if r.Daily != "" {
		fmt.Fprintf(w, "Daily challenge for %s (UTC)\n", r.Daily)
	}

	fmt.Fprintln(w, "\nGround truth")
	if r.Truth.Scoreable {
		fmt.Fprintf(w, "  %s\n", r.Truth.Label)
	} else {
		fmt.Fprintln(w, "  No result: this challenge cannot be scored.")
		fmt.Fprintf(w, "  %s\n", textsafe.Clean(r.Truth.Reason))
	}
	if r.Truth.Explanation != "" {
		fmt.Fprintf(w, "  %s\n", wrapChallengeText(r.Truth.Explanation, "  "))
	}

	if len(r.Truth.Evidence) > 0 {
		fmt.Fprintln(w, "\nWhat the simulator measured for itself")
		for _, line := range r.Truth.Evidence {
			fmt.Fprintf(w, "  %s\n", textsafe.Clean(line))
		}
	}
	if r.Truth.Injected != "" {
		fmt.Fprintf(w, "\nInjected (what the generator asked for, not what scored it)\n  %s\n",
			textsafe.Clean(r.Truth.Injected))
	}
	if len(r.Truth.ObservedFaults) > 0 {
		fmt.Fprintf(w, "  independently observed: %s\n", strings.Join(r.Truth.ObservedFaults, ", "))
	}

	fmt.Fprintln(w, "\nYour diagnosis")
	writeContestant(w, r.Human)
	if r.Human.Note != "" {
		fmt.Fprintf(w, "  note: %s\n", textsafe.Clean(r.Human.Note))
	}

	fmt.Fprintln(w, "\nNetwork Doctor")
	writeContestant(w, r.NetworkDoctor)
	if r.NetworkDoctor.Note != "" {
		fmt.Fprintf(w, "  %s\n", textsafe.Clean(r.NetworkDoctor.Note))
	}

	fmt.Fprintf(w, "\nResult\n  %s\n", challengeResultLine(r.Result))
	fmt.Fprintf(w, "\nHuman investigation: %s\nNetwork Doctor run:  %s\n",
		formatElapsed(msDuration(r.Timing.HumanMS)), formatElapsed(msDuration(r.Timing.NetdocMS)))
	fmt.Fprintf(w, "\nCase\n  base %s  seed %d  case %d  fingerprint %s  generator %s\n",
		textsafe.Clean(r.BaseScenario), r.Seed, r.Case, r.CaseFingerprint, r.GeneratorVersion)
	if r.Netdoc.Path != "" {
		// Provenance, once, next to the case: the id says which puzzle this was,
		// and this says which build answered it.
		fmt.Fprintf(w, "\nNetwork Doctor under test\n  %s\n  %s\n",
			textsafe.Clean(r.Netdoc.Path), textsafe.Clean(r.Netdoc.Version))
	}
	if r.Error != "" {
		fmt.Fprintf(w, "\nSimulator error: %s\n", textsafe.Clean(r.Error))
	}
	fmt.Fprintf(w, "\nReplay:\n  %s\n", r.Replay)

	fmt.Fprintln(w, "\nShare this (it names no fault, so it spoils nothing):")
	fmt.Fprint(w, indentBlock(r.Share(), "  "))
}

func writeContestant(w io.Writer, contestant ChallengeContestant) {
	switch contestant.Score {
	case ChallengeCorrect:
		fmt.Fprintf(w, "  %s\n  ✓ correct\n", contestant.Label)
	case ChallengeIncorrect:
		if contestant.Label == "" {
			fmt.Fprintln(w, "  did not name it\n  ✗ incorrect")
		} else {
			fmt.Fprintf(w, "  %s\n  ✗ incorrect\n", contestant.Label)
		}
	case ChallengeUnrecognized:
		fmt.Fprintln(w, "  no verdict for this condition\n  ✗ not recognized")
	case ChallengeGaveUp:
		fmt.Fprintln(w, "  gave up")
	default:
		fmt.Fprintln(w, "  not scored")
	}
	if contestant.Detail != "" {
		fmt.Fprintf(w, "  \"%s\"\n", textsafe.Clean(contestant.Detail))
	}
}

func challengeResultLine(result string) string {
	switch result {
	case ChallengeHumanWins:
		return "YOU BEAT NETWORK DOCTOR"
	case ChallengeNetdocWins:
		return "NETWORK DOCTOR WINS"
	case ChallengeDraw:
		return "DRAW: you both got it"
	case ChallengeNobodyWins:
		return "NOBODY WINS: neither of you got it"
	default:
		return "NO RESULT"
	}
}

func indentBlock(text, prefix string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		b.WriteString(prefix + line + "\n")
	}
	return b.String()
}

// wrapChallengeText keeps the reveal readable in a terminal without pulling in
// a layout dependency for the one paragraph that needs it.
func wrapChallengeText(text, prefix string) string {
	const width = 74
	var b strings.Builder
	column := 0
	for _, word := range strings.Fields(textsafe.Clean(text)) {
		if column > 0 && column+1+len(word) > width {
			b.WriteString("\n" + prefix)
			column = 0
		} else if column > 0 {
			b.WriteString(" ")
			column++
		}
		b.WriteString(word)
		column += len(word)
	}
	return b.String()
}
