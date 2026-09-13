// The Checks section's width: it is decided by the rows the section actually
// draws, marker, glyph, probe name and watch sparkline included, rather than
// by whether one of those rows happens to carry a label. A terminal with
// columns to spare must spend them rather than wrap a target name beside a
// Details section that is not using its own.

package ui

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// bodyWidths are the terminal widths the body is held to: the two-column
// layout from its 80-column floor up to a terminal with far more room than the
// rows need, and the stacked widths under it.
var bodyWidths = []int{40, 60, 80, 100, 110, 160, 300}

// longHost is a target name no Checks section fits in its usual 36 columns,
// and mediumHost is the ordinary one that has to keep behaving as it did.
const (
	longHost   = "a-very-long-hostname-that-nobody-has.invalid:443"
	mediumHost = "mail.google.com:443"
	// sparkHost is the name that makes the sparkline the deciding half of the
	// row: its probe row fits the section's usual width on its own and does
	// not once eight passes of history are drawn beside it.
	sparkHost = "smtp.mail.example.com:587"
)

// checksLines is the Checks section's rows as rendered, with their leading
// spaces kept: the indent is what says a wrapped line is a continuation of the
// row above rather than a row of its own. sectionCell trims it away, so this
// reads the column itself.
func checksLines(v string) []string {
	lines := strings.Split(v, "\n")
	for i, line := range lines {
		spans := ruleSpans(line)
		if len(spans) == 0 || i == 0 || sectionCell(lines[i-1], spans[0]) != "Checks" {
			continue
		}
		sp := spans[0]
		var out []string
		for j := i + 1; j < len(lines); j++ {
			plain := ansi.Strip(lines[j])
			if strings.TrimSpace(plain) == "" || ruleSpans(lines[j]) != nil {
				break
			}
			// The Details section beside it is usually the taller of the two,
			// so the lines past the last Checks row carry nothing in this
			// column. They are not rows.
			if cell := strings.TrimRight(ansi.Cut(plain, sp.col, sp.col+sp.width), " "); cell != "" {
				out = append(out, cell)
			}
		}
		return out
	}
	return nil
}

// sectionRuleWidth is the columns a section was laid out in, read off the rule
// under its heading. That rule is as wide as the section, so it is the
// rendered output's own account of the width the layout settled on. The
// heading is matched by prefix, because the Details heading names the probe it
// is describing and is cut to its own column when that will not fit.
func sectionRuleWidth(v, title string) int {
	lines := strings.Split(v, "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		for _, sp := range ruleSpans(line) {
			if strings.HasPrefix(sectionCell(lines[i-1], sp), title) {
				return sp.width
			}
		}
	}
	return 0
}

// targetModel is a finished run against host with the failing check selected,
// which is the row a long target name is longest on.
func targetModel(t *testing.T, host string) model {
	t.Helper()
	m := newModel(mustTarget(t, host), false)
	doneResults(&m, diagnostic.ProbeDNS)
	m.selected = probeIndex(t, m, diagnostic.ProbeDNS)
	return m
}

// watchTarget is a watched run against host, so its rows carry sparklines.
func watchTarget(t *testing.T, host string) model {
	t.Helper()
	return NewWithSelection(mustTarget(t, host), nil, false, true, "", "test",
		diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)
}

// dnsOut is the one failing probe the watch passes below report, so every pass
// draws the same failing glyph into the sparkline.
var dnsOut = map[diagnostic.ProbeID]diagnostic.Status{diagnostic.ProbeDNS: diagnostic.StatusFail}

// widthStates are the runs whose Checks rows have to fit: an ordinary target
// name, one long enough to push the section past its usual width, and the
// watched pair of them, whose rows carry a sparkline as well.
func widthStates(t *testing.T) []struct {
	name  string
	build func(t *testing.T) model
} {
	t.Helper()
	return []struct {
		name  string
		build func(t *testing.T) model
	}{
		{"medium name", func(t *testing.T) model { return targetModel(t, mediumHost) }},
		{"long name", func(t *testing.T) model { return targetModel(t, longHost) }},
		{"medium name watched", func(t *testing.T) model {
			m := watchTarget(t, mediumHost)
			for range 8 {
				m = watchRun(t, m, dnsOut)
			}
			return m
		}},
		{"long name watched", func(t *testing.T) model {
			m := watchTarget(t, longHost)
			for range 8 {
				m = watchRun(t, m, dnsOut)
			}
			return m
		}},
	}
}

// render lays the body out at width and returns the block.
func render(m model, width int) string {
	m.width, m.height = width, 40
	return m.bodyView(false, 0)
}

// TestChecksWidthSpendsAvailableColumns is the bug this file exists for: at a
// width the two-column layout can serve, the Checks rows are the rows a very
// wide terminal draws, unwrapped, rather than the same rows broken over two
// display lines beside a Details section sitting on unused columns.
func TestChecksWidthSpendsAvailableColumns(t *testing.T) {
	for _, s := range widthStates(t) {
		t.Run(s.name, func(t *testing.T) {
			// What the rows come to, read off a terminal wide enough that
			// nothing in the section can have been wrapped or truncated.
			want := checksLines(render(s.build(t), 400))
			widest := 0
			for _, row := range want {
				widest = max(widest, lipgloss.Width(row))
			}
			for _, width := range bodyWidths {
				// The columns the layout can give Checks without taking any
				// from what Details is guaranteed. Below that the rows have to
				// wrap, and this test has nothing to say about them.
				if max(width-detailsMinWidth-bodyGutter, checksWidth) < widest || width < 80 {
					continue
				}
				got := checksLines(render(s.build(t), width))
				for i := range got {
					got[i] = strings.TrimRight(got[i], " ")
				}
				if strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Errorf("%d columns: the rows fit in %d columns and still wrapped:\nwant %q\ngot  %q",
						width, widest, want, got)
				}
			}
		})
	}
}

// TestChecksWidthHoldsTheWholeTargetName is the reported symptom stated
// directly: a 300-column terminal draws the whole name on its row.
func TestChecksWidthHoldsTheWholeTargetName(t *testing.T) {
	for _, host := range []string{mediumHost, longHost} {
		m := targetModel(t, host)
		name := m.probes[m.selected].Name
		for _, width := range []int{100, 110, 160, 300} {
			v := render(m, width)
			if !strings.Contains(v, name) {
				t.Errorf("%s at %d columns: %q is wrapped or cut:\n%s", host, width, name, v)
			}
		}
	}
}

// TestChecksWidthCountsTheWatchSparkline holds the half of the row a width
// taken from the labels alone never saw: history glyphs are part of the row,
// so the section has to widen as they accumulate rather than wrap the name out
// from under them.
func TestChecksWidthCountsTheWatchSparkline(t *testing.T) {
	m := watchTarget(t, sparkHost)
	name := m.probes[probeIndex(t, m, diagnostic.ProbeDNS)].Name
	prev := 0
	grew := false
	for pass := 1; pass <= 8; pass++ {
		m = watchRun(t, m, dnsOut)
		v := render(m, 160)
		row := watchRow(t, m, v, diagnostic.ProbeDNS)
		spark := m.statusSparkline(diagnostic.ProbeDNS, 8)
		if !strings.Contains(ansi.Strip(row), ansi.Strip(spark)) {
			t.Fatalf("pass %d: the row lost its sparkline:\nrow %q\nspark %q", pass, row, spark)
		}
		sect := sectionRuleWidth(v, "Checks")
		// The whole row, name and sparkline together, inside the columns the
		// section was laid out in.
		if w := lipgloss.Width(row); w > sect {
			t.Errorf("pass %d: the row is %d columns in a %d-column section:\n%s", pass, w, sect, v)
		}
		if !strings.Contains(v, name) {
			t.Errorf("pass %d: %q wrapped at 160 columns:\n%s", pass, name, v)
		}
		if sect < prev {
			t.Errorf("pass %d: the section narrowed from %d to %d as history grew", pass, prev, sect)
		}
		grew = grew || sect > checksWidth
		prev = sect
	}
	if !grew {
		t.Fatalf("eight passes of history left the section at %d columns, so nothing here was measured", prev)
	}
	// Without the sparkline the same row fits the usual width, so it is the
	// history and nothing else that widened the section.
	plain := targetModel(t, sparkHost)
	if got := sectionRuleWidth(render(plain, 160), "Checks"); got != checksWidth {
		t.Fatalf("unwatched, the same target lays out in %d columns, want %d", got, checksWidth)
	}
}

// TestChecksWidthLeavesDetailsUsable is the other side of the trade: the
// Checks section takes the columns its rows ask for and never the ones Details
// is promised, and the two of them plus the gutter stay inside the terminal.
func TestChecksWidthLeavesDetailsUsable(t *testing.T) {
	for _, s := range widthStates(t) {
		t.Run(s.name, func(t *testing.T) {
			for _, width := range bodyWidths {
				if width < 80 { // stacked, where each section is the terminal
					continue
				}
				v := render(s.build(t), width)
				left, right := sectionRuleWidth(v, "Checks"), sectionRuleWidth(v, "Details")
				if right == 0 {
					t.Fatalf("%d columns: no Details section to measure:\n%s", width, v)
				}
				if right < detailsMinWidth {
					t.Errorf("%d columns: Details is %d columns, under the %d it is guaranteed:\n%s",
						width, right, detailsMinWidth, v)
				}
				if left+bodyGutter+right > width {
					t.Errorf("%d columns: %d + %d gutter + %d overruns the terminal:\n%s",
						width, left, bodyGutter, right, v)
				}
			}
		})
	}
}

// TestChecksRowsFitNarrowTerminals is the degradation half: a terminal with no
// columns to spare still renders, still stays inside itself, and a row it has
// to wrap keeps its continuation under the probe name rather than back in the
// marker column, where it would read as a second probe.
func TestChecksRowsFitNarrowTerminals(t *testing.T) {
	// A row opens with its marker, its cursor or the collapsed row's bullet.
	// Anything else at the left edge of the column is a continuation that
	// escaped its indent.
	stray := regexp.MustCompile(`^[^\s·]`)
	for _, s := range widthStates(t) {
		t.Run(s.name, func(t *testing.T) {
			for _, width := range append([]int{20, 24, 30, 36, 79}, bodyWidths...) {
				v := render(s.build(t), width)
				where := fmt.Sprintf("%d columns", width)
				for _, line := range strings.Split(v, "\n") {
					if w := lipgloss.Width(line); w > width {
						t.Errorf("%s: a line is %d columns wide:\n%s", where, w, v)
						break
					}
				}
				rows := checksLines(v)
				if len(rows) == 0 {
					t.Fatalf("%s: no Checks rows rendered:\n%s", where, v)
				}
				for i, row := range rows {
					if i > 0 && strings.HasPrefix(row, "›") {
						continue // the cursor row opens in the marker column
					}
					if i > 0 && stray.MatchString(row) {
						t.Errorf("%s: row %d starts at the left edge, so a wrapped name reads as its own row: %q\n%s",
							where, i, row, v)
					}
				}
			}
		})
	}
}

// TestChecksWidthUnchangedForShortNames pins the layout everyone already sees:
// a run whose rows fit is laid out in the section's usual width, not widened
// because the terminal happens to be large.
func TestChecksWidthUnchangedForShortNames(t *testing.T) {
	for _, width := range []int{80, 100, 160, 300} {
		v := render(wifiModel(t), width)
		if got := sectionRuleWidth(v, "Checks"); got != checksWidth {
			t.Errorf("%d columns: short rows laid out in %d columns, want %d:\n%s", width, got, checksWidth, v)
		}
	}
}
