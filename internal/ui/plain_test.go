// The plain-language layer of the answer block: what reaches the screen for a
// reader with no networking vocabulary, and how it yields on a short terminal.
// What the explanation says is pinned in internal/diagnostic/plain_test.go.

package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// plainHeadline is the headline the answer block leads with.
func plainHeadline(m model) string {
	return diagnostic.Explain(m.target, m.probeOrder(), m.results).Headline
}

// TestPlainAnswerLeadsAFinishedRun: on an ordinary terminal a finished failing
// run answers the five questions a reader without networking vocabulary has,
// in order, above the checks: is something wrong and where, what it means,
// what to try, and how to hand the evidence to someone else. The technical
// sentence stays under them.
func TestPlainAnswerLeadsAFinishedRun(t *testing.T) {
	m := answerScenarios(t)[1].build(t) // printer.local does not resolve
	_, v := renderAt(t, m)
	lines := viewLines(v)
	plain := diagnostic.Explain(m.target, m.probeOrder(), m.results)
	summary, _ := m.diagnose(m.probeOrder())
	want := []string{
		"✗ " + plain.Headline,
		answerLead(plain.Meaning),
		"Try first: ",
		"Technical: " + answerLead(summary),
		"Need help? Press w to save a report",
	}
	prev := -1
	for _, w := range want {
		at := lineWith(lines, w)
		switch {
		case at < 0:
			t.Fatalf("%q never reaches the screen:\n%s", w, v)
		case at <= prev:
			t.Errorf("%q is at row %d, out of order after row %d:\n%s", w, at, prev, v)
		case at >= firstBodyLine(lines):
			t.Errorf("%q is below the checks:\n%s", w, v)
		}
		prev = at
	}
	if lines[0] != "✗ "+plain.Headline {
		t.Errorf("the first row is %q, want the plain headline:\n%s", lines[0], v)
	}
}

// TestHealthyAnswerHasNothingToTry: a clean run says so without claiming more
// than it proved, and offers no remedy and no help to ask for.
func TestHealthyAnswerHasNothingToTry(t *testing.T) {
	m := answerScenarios(t)[0].build(t)
	_, v := renderAt(t, m)
	text := ansi.Strip(v)
	for _, want := range []string{"✓ No obvious problem found", "does not guarantee"} {
		if !strings.Contains(text, want) {
			t.Errorf("a healthy run does not say %q:\n%s", want, v)
		}
	}
	for _, unwanted := range []string{"Try first:", "Need help?"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a healthy run offers %q:\n%s", unwanted, v)
		}
	}
}

// TestUnfinishedRunClaimsNoPlainAnswer: nothing plain is said before every
// probe has reported, any more than anything technical is.
func TestUnfinishedRunClaimsNoPlainAnswer(t *testing.T) {
	s := answerScenarios(t)[1]
	m := s.build(t)
	delete(m.results, s.blamed)
	_, v := renderAt(t, m)
	text := ansi.Strip(v)
	for _, unwanted := range []string{"Website names", "Try first:", "Technical:", "Need help?"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("an unfinished run already says %q:\n%s", unwanted, v)
		}
	}
}

// TestPlainElaborationYieldsBeforeTheChecks: on a terminal too short for both,
// the meaning and the first step give way before the results block does, and
// the headline and the technical answer stay either way. The elaboration is
// never shed while the screen has room for it and the results block.
func TestPlainElaborationYieldsBeforeTheChecks(t *testing.T) {
	m := answerScenarios(t)[1].build(t)
	plain := diagnostic.Explain(m.target, m.probeOrder(), m.results)
	sawYield := false
	for h := 40; h >= 8; h-- {
		sm, lines := sized(t, m, 100, h)
		elaborated := lineWith(lines, "Try first:") >= 0
		checks := firstBodyLine(lines) >= 0
		if !elaborated && !checks {
			// A terminal this short keeps only the answer, and the headline is
			// the part of it that goes first.
			if lineWith(lines, plain.Headline) != 0 {
				t.Fatalf("100x%d: the headline is not the first row:\n%s", h, strings.Join(lines, "\n"))
			}
			continue
		}
		if !elaborated {
			sawYield = true
			// The layout only drops the elaboration when keeping it would
			// have cost the checks, so the elaborated view must not fit.
			full, _ := sm.layout(true)
			if len(viewLines(full)) <= h && firstBodyLine(viewLines(full)) >= 0 {
				t.Errorf("100x%d: the elaboration was dropped though it fit beside the checks:\n%s", h, strings.Join(lines, "\n"))
			}
		}
		if lineWith(lines, plain.Headline) != 0 {
			t.Errorf("100x%d: the headline is not the first row:\n%s", h, strings.Join(lines, "\n"))
		}
	}
	if !sawYield {
		t.Error("the elaboration never yielded, so nothing was under pressure")
	}
}
