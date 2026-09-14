// The reading order inside a selected check's evidence: what happened, what it
// means in this run, what to do about it, and only then what was measured.
// These tests fail if the mechanics climb back above the interpretation, if a
// downstream failure goes back to reading like an independent one, or if the
// inline section and the full-screen viewer drift into two renderers.

package ui

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// plainDetails is the selected row's evidence as text, its heading dropped and
// its styling stripped, one entry per logical row.
func plainDetails(m model) []string {
	rows := m.detailRows(false, max(m.width, 1))
	if len(rows) > 0 {
		rows = rows[1:]
	}
	out := make([]string, len(rows))
	for i, row := range rows {
		out[i] = ansi.Strip(row)
	}
	return out
}

// rowIndex is where want first appears in rows, and -1 when it never does.
func rowIndex(rows []string, want string) int {
	for i, row := range rows {
		if strings.Contains(row, want) {
			return i
		}
	}
	return -1
}

// downstreamRun is the offline shape with measurements on one of the rows the
// diagnosis has already explained: the egress row is the failure to act on,
// and QUIC is that dead path reported a second time. The cursor sits on the
// downstream row, which is the case the consequence line exists for.
func downstreamRun(t *testing.T) model {
	t.Helper()
	m := offlineRun(t, mustTarget(t, "example.com:443"))
	m.width, m.height = 100, 40
	r := m.results[diagnostic.ProbeQUIC]
	r.Source, r.Iface = net.ParseIP("192.0.2.7"), "eth0"
	r.Attempts = []diagnostic.Attempt{{
		IP: net.ParseIP("198.51.100.4"), Dur: time.Millisecond,
		Err: errors.New("network is unreachable"),
	}}
	m.results[diagnostic.ProbeQUIC] = r
	m.selected, m.selMoved = probeIndex(t, m, diagnostic.ProbeQUIC), true
	return m
}

// TestSelectedCheckLeadsWithItsOutcome: the status word and the finding are
// the first thing under the heading on every row, including the one the
// diagnosis focuses, where the section used to open on "Fix:" or on the
// remediation's reasoning with no statement of what had happened at all.
func TestSelectedCheckLeadsWithItsOutcome(t *testing.T) {
	m := blackHoleFocused(t)
	m.width, m.height = 100, 40
	r := m.results[diagnostic.ProbePMTU]
	r.Detail = "bulk transfer stalled after the handshake"
	m.results[diagnostic.ProbePMTU] = r
	if m.selected != m.answerRow() {
		t.Fatal("the cursor is not on the blamed row, so the case is not under test")
	}
	rows := plainDetails(m)
	if len(rows) == 0 {
		t.Fatal("the blamed row has no evidence at all")
	}
	if want := "WARN: " + r.Detail; rows[0] != want {
		t.Errorf("the evidence opens on %q, want %q:\n%s", rows[0], want, strings.Join(rows, "\n"))
	}
	// And the interpretation is above the mechanics, not mixed into them.
	if fix, observed := rowIndex(rows, "Fix: "), rowIndex(rows, observedTitle); observed >= 0 && fix >= 0 && fix > observed {
		t.Errorf("the measurements come before the guidance:\n%s", strings.Join(rows, "\n"))
	}
}

// TestWarningReadsAsAWarningNotAFailure: the blamed row of the black-hole run
// is a WARN carrying the longest elaboration in the program. Status leads, so
// the size of the block under it never decides what the reader thinks it says.
func TestWarningReadsAsAWarningNotAFailure(t *testing.T) {
	m := blackHoleFocused(t)
	m.width, m.height = 100, 40
	if m.results[diagnostic.ProbePMTU].Status != diagnostic.StatusWarn {
		t.Fatal("the blamed row is no longer a warning, so the case is not under test")
	}
	rows := plainDetails(m)
	if !strings.HasPrefix(rows[0], "WARN") {
		t.Errorf("a warning row opens on %q:\n%s", rows[0], strings.Join(rows, "\n"))
	}
	if strings.Contains(rows[0], "FAIL") {
		t.Errorf("a warning row states a failure:\n%s", strings.Join(rows, "\n"))
	}
}

// TestConsequenceSaysItIsDownstream: a failure the diagnosis has already
// explained under another row says so in words, and names the row it is
// downstream of. Without it the section reads as an independent problem, since
// the Checks marker is in the other section and the viewer has no marker.
func TestConsequenceSaysItIsDownstream(t *testing.T) {
	m := downstreamRun(t)
	collateral := diagnostic.Collateral(m.target, m.probeOrder(), m.results)
	if !collateral[diagnostic.ProbeQUIC] {
		t.Fatal("the QUIC row is not collateral in this run, so the case is not under test")
	}
	blamed := m.probeLabel(m.diagnosis().Blamed)
	rows := plainDetails(m)
	at := rowIndex(rows, "Consequence of ")
	if at < 0 {
		t.Fatalf("a downstream failure does not say it is one:\n%s", strings.Join(rows, "\n"))
	}
	if !strings.Contains(rows[at], blamed) {
		t.Errorf("the consequence line does not name %q:\n%s", blamed, rows[at])
	}
	if at != 1 {
		t.Errorf("the consequence line is row %d, want it directly under the outcome:\n%s",
			at, strings.Join(rows, "\n"))
	}
	// It explains the relation and nothing more: the action is the answer
	// block's, and a second copy of it here would be a second diagnosis.
	if rem, ok := m.remediation(); ok && strings.Contains(rows[at], rem.Action) {
		t.Errorf("the consequence line restates the diagnosis's action:\n%s", rows[at])
	}

	// The blamed row itself is never described as a consequence of anything.
	m.selected = probeIndex(t, m, m.diagnosis().Blamed)
	if got := plainDetails(m); rowIndex(got, "Consequence of ") >= 0 {
		t.Errorf("the blamed row calls itself downstream:\n%s", strings.Join(got, "\n"))
	}
}

// TestHealthyCheckStaysInspectableAndShort: a passing row keeps every
// measurement it took and spends nothing on saying that all is well.
func TestHealthyCheckStaysInspectableAndShort(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.width, m.height = 100, 40
	doneResults(&m, "")
	r := m.results[diagnostic.ProbeTargetTCP]
	r.Detail = "connected in 23ms"
	r.Source, r.Iface = net.ParseIP("192.0.2.7"), "eth0"
	r.Attempts = []diagnostic.Attempt{{IP: net.ParseIP("93.184.216.34"), Dur: 23 * time.Millisecond}}
	m.results[diagnostic.ProbeTargetTCP] = r
	m.selected = probeIndex(t, m, diagnostic.ProbeTargetTCP)
	rows := plainDetails(m)
	if rows[0] != "PASS: connected in 23ms" {
		t.Errorf("a passing row opens on %q:\n%s", rows[0], strings.Join(rows, "\n"))
	}
	for _, want := range []string{observedTitle, "src 192.0.2.7 eth0", "93.184.216.34 23ms ok"} {
		if rowIndex(rows, want) < 0 {
			t.Errorf("a passing row lost %q:\n%s", want, strings.Join(rows, "\n"))
		}
	}
	if len(rows) > 4 {
		t.Errorf("a passing row with one address costs %d rows:\n%s", len(rows), strings.Join(rows, "\n"))
	}
}

// TestMeasurementsAreLabelledAndComeLast: every raw line a probe recorded is
// still there, grouped under one word, after the interpretation rather than
// interleaved with it.
func TestMeasurementsAreLabelledAndComeLast(t *testing.T) {
	m := evidenceModel(t)
	m.width, m.height = 100, 40
	rows := plainDetails(m)
	observed := rowIndex(rows, observedTitle)
	if observed < 0 {
		t.Fatalf("the measurements are unlabelled:\n%s", strings.Join(rows, "\n"))
	}
	raw := []string{"src 192.0.2.7 eth0", "198.51.100.9 12ms ok", "198.51.100.10 34ms connection refused"}
	for _, want := range raw {
		at := rowIndex(rows, want)
		if at < 0 {
			t.Fatalf("the measurement %q was dropped:\n%s", want, strings.Join(rows, "\n"))
		}
		if at < observed {
			t.Errorf("the measurement %q is above its own label:\n%s", want, strings.Join(rows, "\n"))
		}
	}
	// The label is not drawn over an empty group.
	bare := m
	r := bare.results[diagnostic.ProbeDNS]
	r.Source, r.Attempts, r.Routes, r.Portal = nil, nil, nil, nil
	bare.results[diagnostic.ProbeDNS] = r
	if got := plainDetails(bare); rowIndex(got, observedTitle) >= 0 {
		t.Errorf("a probe with no measurements still draws the label:\n%s", strings.Join(got, "\n"))
	}
}

// TestProbeFixSurvivesOnRowsTheDiagnosisIsNotAbout: the per-probe remedy is
// still where it was, between the outcome and the measurements.
func TestProbeFixSurvivesOnRowsTheDiagnosisIsNotAbout(t *testing.T) {
	m := downstreamRun(t)
	rows := plainDetails(m)
	fix := rowIndex(rows, "Fix: "+m.results[diagnostic.ProbeQUIC].Fix)
	if fix < 0 {
		t.Fatalf("the row lost its own remedy:\n%s", strings.Join(rows, "\n"))
	}
	if observed := rowIndex(rows, observedTitle); observed >= 0 && fix > observed {
		t.Errorf("the remedy is below the measurements:\n%s", strings.Join(rows, "\n"))
	}
}

// TestCheckDetailsViewerMatchesTheInlineSection: one renderer. The viewer is
// the inline rows without the heading its own header already carries, so a
// reader pressing D cannot be shown a different reading of the check they were
// just looking at.
func TestCheckDetailsViewerMatchesTheInlineSection(t *testing.T) {
	cases := map[string]func(t *testing.T) model{
		"blamed warning":      func(t *testing.T) model { m := blackHoleFocused(t); m.width, m.height = 100, 40; return m },
		"downstream failure":  downstreamRun,
		"independent failure": func(t *testing.T) model { return evidenceModel(t) },
		"routine success": func(t *testing.T) model {
			m := downstreamRun(t)
			m.selected = probeIndex(t, m, diagnostic.ProbeIface)
			return m
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			m := build(t)
			m.width, m.height = 100, 40
			// The viewer wraps to the terminal rather than to a section, so
			// the two are compared as text: same words, same order, and the
			// heading is the only thing the viewer leaves out.
			inline := reflowed(ansi.Strip(strings.Join(plainDetails(m), " ")))
			viewer := reflowed(ansi.Strip(m.detailsContent()))
			if inline != viewer {
				t.Errorf("the viewer and the section disagree about the same check:\n viewer: %s\n inline: %s", viewer, inline)
			}
		})
	}
}

// TestEvidenceHierarchySurvivesMonochromeAndNarrowTerminals: the order is
// carried by words, so it holds with every colour taken away and at the
// narrowest section the layout allows. Nothing may exceed the terminal.
func TestEvidenceHierarchySurvivesMonochromeAndNarrowTerminals(t *testing.T) {
	sizes := []struct{ w, h int }{{120, 40}, {100, 30}, {80, 24}, {70, 20}, {80, 16}, {80, 12}, {80, 10}}
	for _, size := range sizes {
		for _, theme := range []string{"terminal", "monochrome"} {
			t.Run(fmt.Sprintf("%dx%d/%s", size.w, size.h, theme), func(t *testing.T) {
				m := downstreamRun(t)
				m.setTheme(resolveTheme(theme))
				nm, lines := sized(t, m, size.w, size.h)
				for _, line := range lines {
					if w := ansi.StringWidth(line); w > size.w {
						t.Fatalf("%dx%d: a line is %d columns wide:\n%q", size.w, size.h, w, line)
					}
				}
				// Whatever the terminal, the full evidence is reachable, and
				// there it still reads outcome, meaning, then measurements.
				nm.detailsViewing = true
				nm.refreshDetailsViewport(true)
				text := strings.Join(strings.Fields(ansi.Strip(nm.detailsContent())), " ")
				outcome := strings.Index(text, "FAIL:")
				cause := strings.Index(text, "Consequence of")
				observed := strings.Index(text, observedTitle)
				if outcome != 0 {
					t.Fatalf("%dx%d %s: the viewer does not open on the outcome:\n%s", size.w, size.h, theme, text)
				}
				if cause < outcome || observed < cause {
					t.Errorf("%dx%d %s: the reading order is scrambled:\n%s", size.w, size.h, theme, text)
				}
			})
		}
	}
}

// TestSelectedEvidenceDoesNotRestateTheDiagnosis: the section explains its own
// check. The action, the command and the retest key belong to the answer block
// at the top of the screen and appear in exactly one place.
func TestSelectedEvidenceDoesNotRestateTheDiagnosis(t *testing.T) {
	for _, m := range []model{blackHoleFocused(t), downstreamRun(t)} {
		m.width, m.height = 100, 40
		rem, ok := m.remediation()
		if !ok {
			continue
		}
		text := strings.Join(plainDetails(m), "\n")
		for _, unwanted := range []string{"Do: " + rem.Action, "Run: " + rem.CommandLine(), "Then press"} {
			if strings.TrimPrefix(unwanted, "Run: ") == "" {
				continue
			}
			if strings.Contains(text, unwanted) {
				t.Errorf("the evidence restates %q:\n%s", unwanted, text)
			}
		}
	}
}

// TestWatchChangeStaysVisibleInTheEvidence: the retained history line is a
// measurement like any other, and the reordering must not have dropped it.
func TestWatchChangeStaysVisibleInTheEvidence(t *testing.T) {
	m := downstreamRun(t)
	m.watch = true
	for _, p := range m.probes {
		m.runHistory[p.ID] = []diagnostic.Status{diagnostic.StatusPass, diagnostic.StatusPass, diagnostic.StatusFail}
	}
	rows := plainDetails(m)
	if rowIndex(rows, "History: ") < 0 {
		t.Errorf("the watch history is gone from the evidence:\n%s", strings.Join(rows, "\n"))
	}
	if !m.changedRow(diagnostic.ProbeQUIC) {
		t.Fatal("this row did not change, so the changed marker is not under test")
	}
	_, v := renderAt(t, m)
	if !strings.Contains(ansi.Strip(v), changedLabel) {
		t.Errorf("the changed marker is gone from the screen:\n%s", v)
	}
}
