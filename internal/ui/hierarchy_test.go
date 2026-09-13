// The main screen's information hierarchy: the answer block (what is wrong and
// what to do about it) is one visually separated group that outranks every
// other region, and the evidence under it yields rows before any of it does.
// These tests read the rendered view rather than the helpers that build it,
// because the claim under test is about what a reader sees and in what order.

package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// hierarchySizes is the range the hierarchy has to hold across: a roomy
// terminal, the two common ones, a cramped one, and heights short enough that
// something has to be shed on every render.
var hierarchySizes = []struct{ w, h int }{
	{120, 40}, {100, 30}, {80, 24}, {70, 20}, {100, 16}, {100, 12}, {100, 10},
}

// sized renders m at one terminal size through the real resize path.
func sized(t *testing.T, m model, w, h int) (model, []string) {
	t.Helper()
	u, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	nm := asModel(t, u)
	return nm, viewLines(nm.View())
}

// blackHoleFocused is the representative failed run with an actionable
// diagnosis, with the cursor where a finished run puts it.
func blackHoleFocused(t *testing.T) model {
	t.Helper()
	m := blackHoleModel(t)
	m.selected = m.focusTarget()
	return m
}

// TestNextActionRidesWithTheAnswer is the point of the split: the thing to do
// is in the answer block at the top of the screen, not in a section beside the
// probe table that a reader reaches only by moving the cursor. A first-time
// reader must be able to answer "what do I do" without touching a key.
func TestNextActionRidesWithTheAnswer(t *testing.T) {
	m := blackHoleFocused(t)
	rem, ok := m.remediation()
	if !ok {
		t.Fatal("this case no longer carries a remediation, so the split is not under test")
	}
	for _, size := range hierarchySizes {
		t.Run(fmt.Sprintf("%dx%d", size.w, size.h), func(t *testing.T) {
			_, lines := sized(t, m, size.w, size.h)
			action := lineWith(lines, answerLead(rem.Action))
			if action < 0 {
				t.Fatalf("the next action was shed:\n%s", strings.Join(lines, "\n"))
			}
			// Above every piece of probe machinery, and above the context that
			// only qualifies it.
			if body := firstBodyLine(lines); body >= 0 && action > body {
				t.Errorf("the next action is at row %d, under the results block at row %d:\n%s",
					action, body, strings.Join(lines, "\n"))
			}
		})
	}
}

// TestEvidenceYieldsBeforeTheAnswer walks one terminal down a row at a time.
// Every line of the answer block survives every height at which anything is on
// screen at all, and the evidence regions are what disappear on the way.
func TestEvidenceYieldsBeforeTheAnswer(t *testing.T) {
	m := blackHoleFocused(t)
	full, _ := sized(t, m, 100, 40)
	answer := viewLines(full.answerBlock())

	sawBodyGo := false
	for h := 30; h >= 10; h-- {
		_, lines := sized(t, m, 100, h)
		if n := len(lines); n > h {
			t.Fatalf("100x%d: the view is %d rows, so the renderer eats the top:\n%s", h, n, strings.Join(lines, "\n"))
		}
		for _, want := range answer {
			if strings.TrimSpace(want) == "" {
				continue
			}
			if lineWith(lines, strings.TrimSpace(want)) < 0 {
				t.Fatalf("100x%d: the answer line %q was shed while evidence was still on screen:\n%s",
					h, want, strings.Join(lines, "\n"))
			}
		}
		if firstBodyLine(lines) < 0 {
			sawBodyGo = true
		}
	}
	if !sawBodyGo {
		t.Error("the results block never yielded, so nothing was actually under pressure")
	}
}

// TestAnswerIsSeparatedFromItsSupport: a multi-line answer is held off the
// context strip and the sections under it by a blank row. That gap is the only
// thing marking where the conclusion stops and the supporting material starts,
// and it is carried by position rather than by colour, so it survives a
// monochrome terminal. A one-line answer has no parts to group and pays for no
// separator.
func TestAnswerIsSeparatedFromItsSupport(t *testing.T) {
	m, lines := sized(t, blackHoleFocused(t), 100, 40)
	answerHeight := len(viewLines(m.answerBlock()))
	if answerHeight < 2 {
		t.Fatalf("this case renders a %d line answer, so the grouping is not under test", answerHeight)
	}
	if got := strings.TrimSpace(lines[answerHeight]); got != "" {
		t.Errorf("row %d under the answer is %q, want the blank that separates it from its support:\n%s",
			answerHeight, got, strings.Join(lines, "\n"))
	}
	// Nothing inside the answer breaks the group apart.
	for i, line := range lines[:answerHeight] {
		if strings.TrimSpace(line) == "" {
			t.Errorf("the answer block is split by a blank row at %d:\n%s", i, strings.Join(lines, "\n"))
		}
	}

	healthy := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&healthy, "")
	_, hl := sized(t, healthy, 100, 40)
	if strings.TrimSpace(hl[1]) == "" {
		t.Errorf("a one-line answer paid for a separator it has nothing to separate:\n%s", strings.Join(hl, "\n"))
	}
}

// TestAnswerKeepsItsIndentWhenItWraps: the answer's hierarchy is carried by
// indentation, which is the one signal a monochrome terminal with no attribute
// support still renders. A wrapped continuation that restarts at column 0
// reads as a new top-level statement rather than as the rest of the line above
// it, which is exactly the distinction the indent exists to make.
func TestAnswerKeepsItsIndentWhenItWraps(t *testing.T) {
	m := blackHoleFocused(t)
	logical := append(strings.Split(m.banner(), "\n"), m.answerRemediation()...)
	indented := 0
	for _, width := range []int{120, 100, 80, 70, 60, 50, 40} {
		t.Run(fmt.Sprintf("w%d", width), func(t *testing.T) {
			nm, _ := sized(t, m, width, 40)
			for _, line := range logical {
				plain := ansi.Strip(line)
				rows := viewLines(nm.answerWrap(line))
				for _, row := range rows {
					if ansi.StringWidth(row) > width {
						t.Errorf("an answer row is %d columns wide on a %d column terminal:\n%q",
							ansi.StringWidth(row), width, row)
					}
				}
				if !strings.HasPrefix(plain, "  ") {
					continue // the verdict sentence, which is the one line at column 0
				}
				if len(rows) > 1 {
					indented++
				}
				for _, row := range rows {
					if !strings.HasPrefix(row, "  ") {
						t.Errorf("a continuation of %q restarts at column 0, losing the indent:\n%s",
							strings.TrimSpace(plain), strings.Join(rows, "\n"))
						break
					}
				}
			}
		})
	}
	if indented == 0 {
		t.Error("no indented answer line ever wrapped, so the hanging indent is not under test")
	}
}

// TestDetailsDoesNotRepeatTheAnswer: the evidence section is subordinate, so
// it adds what the answer left out and never restates it. Two copies of the
// same advice a few rows apart read as two competing answers, and the second
// one is in the region the reader was meant to skip.
func TestDetailsDoesNotRepeatTheAnswer(t *testing.T) {
	m, v := renderAt(t, blackHoleFocused(t))
	rem, ok := m.remediation()
	if !ok {
		t.Fatal("this case no longer carries a remediation")
	}
	details := detailsRows(v)
	if len(details) == 0 {
		t.Fatal("no Details section on screen, so the overlap is not under test")
	}
	for _, repeated := range []string{rem.Action, rem.CommandLine(), "Then press"} {
		if repeated == "" {
			continue
		}
		if containsRow(details, repeated) {
			t.Errorf("Details repeats %q, which the answer block is already showing:\n%s",
				repeated, strings.Join(details, "\n"))
		}
	}
	// The elaboration it is responsible for is still there: nothing was
	// dropped on the way, only moved.
	for _, want := range []string{rem.Why, rem.Expect} {
		if want == "" {
			continue
		}
		if reflowed := strings.Join(strings.Fields(strings.Join(details, " ")), " "); !strings.Contains(reflowed, strings.Join(strings.Fields(want), " ")) {
			t.Errorf("Details lost %q:\n%s", want, strings.Join(details, "\n"))
		}
	}
}

// TestJobOutputDoesNotOutrankTheAnswer: a running tool is unrelated to the
// diagnosis, so however much it prints it stays under the answer and never
// pushes it off the top. The pane takes the rows the rest of the screen did
// not want, which is the opposite of the priority a scrolling tail would
// otherwise claim for itself.
func TestJobOutputDoesNotOutrankTheAnswer(t *testing.T) {
	m := blackHoleFocused(t)
	m.cur = jobState{status: JobRunning, name: "traceroute", display: "traceroute example.com"}
	for i := range 200 {
		m.cur.lines = append(m.cur.lines, fmt.Sprintf("%2d  10.0.0.%d  1.234 ms", i+1, i+1))
	}
	for _, size := range hierarchySizes {
		t.Run(fmt.Sprintf("%dx%d", size.w, size.h), func(t *testing.T) {
			nm, lines := sized(t, m, size.w, size.h)
			if n := len(lines); n > size.h {
				t.Fatalf("the view is %d rows on a %d row terminal:\n%s", n, size.h, strings.Join(lines, "\n"))
			}
			answer := viewLines(nm.answerBlock())
			if lineWith(lines, strings.TrimSpace(answer[0])) != 0 {
				t.Errorf("the job pane moved the verdict off the first row:\n%s", strings.Join(lines, "\n"))
			}
			// Every job line sits below every answer line.
			job := lineWith(lines, "10.0.0.")
			if job < 0 {
				return // too short for a pane at all, which is the pane yielding correctly
			}
			for _, want := range answer {
				if strings.TrimSpace(want) == "" {
					continue
				}
				at := lineWith(lines, strings.TrimSpace(want))
				if at < 0 {
					t.Errorf("the job pane shed the answer line %q:\n%s", want, strings.Join(lines, "\n"))
					continue
				}
				if at > job {
					t.Errorf("the answer line %q is at row %d, under the job output at row %d:\n%s",
						want, at, job, strings.Join(lines, "\n"))
				}
			}
		})
	}
}

// TestWatchStateStaysWithTheContext: watch is context for the answer, not part
// of it. It belongs on the context strip below the answer block, where it
// qualifies the verdict without competing with it, and it must still be
// legible there.
func TestWatchStateStaysWithTheContext(t *testing.T) {
	m := blackHoleFocused(t)
	m.watch = true
	for _, p := range m.probes {
		m.runHistory[p.ID] = []diagnostic.Status{diagnostic.StatusPass, m.results[p.ID].Status}
	}
	nm, lines := sized(t, m, 100, 40)
	answerHeight := len(viewLines(nm.answerBlock()))
	watch := lineWith(lines, "watch")
	if watch < 0 {
		t.Fatalf("watch mode is not stated anywhere:\n%s", strings.Join(lines, "\n"))
	}
	if watch <= answerHeight {
		t.Errorf("the watch state is at row %d, inside the %d row answer block:\n%s",
			watch, answerHeight, strings.Join(lines, "\n"))
	}
	if !hasLine(lines2str(lines), ansi.Strip(nm.headerView())) {
		t.Errorf("the context strip is not on screen intact:\n%s", strings.Join(lines, "\n"))
	}
}

func lines2str(lines []string) string { return strings.Join(lines, "\n") }

// TestAnswerStatesOneRemedy: the primary answer says what to do once. The row
// hint and the diagnosis's action are the same instruction one level apart
// ("lower the interface MTU" against "Try a lower MTU on the path"), so
// printing both makes the answer longer without making it say more. Which of
// the two is shown is not a judgement about particular wordings: every
// diagnosis that blames a row also reaches an action about it, so the answer
// prints the action, and every run that reaches no action keeps the row's hint
// as the only advice it has.
func TestAnswerStatesOneRemedy(t *testing.T) {
	advised := 0
	for _, s := range answerScenarios(t) {
		if s.blamed == "" {
			continue
		}
		t.Run(s.name, func(t *testing.T) {
			m := s.build(t)
			m.width = 120
			block := ansi.Strip(m.answerBlock())
			rem, ok := m.remediation()
			if !ok {
				if fix := m.results[s.blamed].Fix; fix != "" && !strings.Contains(block, "Fix: "+fix) {
					t.Errorf("a run with no action of its own dropped the row's hint too:\n%s", block)
				}
				return
			}
			advised++
			if strings.Contains(block, "Fix: ") {
				t.Errorf("the answer states the remedy twice:\n%s", block)
			}
			if !strings.Contains(block, "Do: "+rem.Action) {
				t.Errorf("the answer lost the action %q:\n%s", rem.Action, block)
			}
			// Not lost, moved: the wording that carries the dates, names and
			// commands only the probe held waits on that row, which is the row
			// the cursor is already parked on.
			if fix := m.results[s.blamed].Fix; fix != "" {
				if details := reflowed(answerRowDetails(m)); !strings.Contains(details, reflowed("Fix: "+fix)) {
					t.Errorf("the blamed row's hint is nowhere:\n%s", details)
				}
			}
		})
	}
	if advised == 0 {
		t.Fatal("no scenario reached a remediation, so the rule is not under test")
	}
}

// TestAnswerKeepsTheWorkflowLines: dropping the row hint must not take the two
// lines that make the action a workflow with it. The command is what the reader
// runs to look at the state the conclusion is about, and the key is how they
// ask the same question again once they have changed something.
func TestAnswerKeepsTheWorkflowLines(t *testing.T) {
	m := blackHoleFocused(t)
	m.width = 120
	rem, ok := m.remediation()
	if !ok || rem.CommandLine() == "" {
		t.Fatal("this case carries no command, so the rule is not under test")
	}
	block := ansi.Strip(m.answerBlock())
	for _, want := range []string{"Run: " + rem.CommandLine(), "Then press " + m.keys.label(ctxList, actRetest) + " to retest"} {
		if !strings.Contains(block, want) {
			t.Errorf("the answer lost %q:\n%s", want, block)
		}
	}
	// And the elaboration is still a section away rather than up here.
	details := reflowed(answerRowDetails(m))
	for _, want := range []string{rem.Why, rem.Expect} {
		if want != "" && !strings.Contains(details, reflowed(want)) {
			t.Errorf("Details lost %q:\n%s", want, details)
		}
	}
}

// TestOneRemedyHoldsOnEveryTerminal: the rule is about what is on screen, so it
// is checked on screen, at every size the hierarchy has to survive. A layout
// that sheds the action and leaves the hint behind would read as the answer
// changing its mind as the window narrows.
func TestOneRemedyHoldsOnEveryTerminal(t *testing.T) {
	m := blackHoleFocused(t)
	rem, ok := m.remediation()
	if !ok {
		t.Fatal("this case no longer carries a remediation, so the rule is not under test")
	}
	for _, size := range hierarchySizes {
		t.Run(fmt.Sprintf("%dx%d", size.w, size.h), func(t *testing.T) {
			nm, lines := sized(t, m, size.w, size.h)
			block := ansi.Strip(nm.answerBlock())
			if strings.Contains(block, "Fix: ") {
				t.Errorf("the answer states the remedy twice:\n%s", block)
			}
			if lineWith(lines, answerLead(rem.Action)) < 0 {
				t.Errorf("the action was shed:\n%s", lines2str(lines))
			}
		})
	}
}
