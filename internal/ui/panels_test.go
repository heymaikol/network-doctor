// The two sections of the results block: which probes earn a Checks row, when
// Details is worth drawing at all, and the rule that neither section is padded
// out to the other's height.

package ui

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// onWireless gives a finished run the interface and Wi-Fi results of a
// wireless machine, so the network name is there for whatever reads it.
func onWireless(m model) model {
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass,
		Iface: "wlan0", Detail: "interface wlan0 is up",
	}
	m.results[diagnostic.ProbeSSID] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeSSID, Status: diagnostic.StatusPass,
		Network: "homewifi", Detail: "connected to homewifi",
	}
	return m
}

// wifiModel is a finished healthy run on a wireless machine: the interface
// probe names the link and the Wi-Fi probe carries the network name.
func wifiModel(t *testing.T) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, "")
	return onWireless(m)
}

// rowLabel is one rendered Checks row with its cursor marker and status glyph
// taken off, which leaves the probe name the row is carrying.
func rowLabel(row string) string {
	// The status glyph is one rune followed by a space, so the name is what
	// is left of an un-marked row after its first space.
	if _, name, ok := strings.Cut(strings.TrimPrefix(row, "› "), " "); ok {
		return name
	}
	return row
}

// TestNetworkNameIsToldOnceOnTheContextStrip: the context strip under the
// banner already prints "Wi-Fi: homewifi" from the Wi-Fi probe's result, so a
// Checks row saying the same thing is the same fact twice. Collapsed or
// expanded, the panel does not draw one.
func TestNetworkNameIsToldOnceOnTheContextStrip(t *testing.T) {
	m, compact := renderAt(t, wifiModel(t))
	strip := m.headerView()
	if !strings.Contains(ansi.Strip(strip), "Wi-Fi: homewifi") {
		t.Fatalf("the context strip lost the network name: %q", ansi.Strip(strip))
	}
	if !hasLine(compact, strip) {
		t.Errorf("the context strip is not on screen:\n%s", compact)
	}
	// Expanded, so every row the Checks panel has to offer is on screen and a
	// missing row cannot be blamed on the compact view collapsing it.
	expanded, ev := renderAt(t, press(t, m, "a"))
	if collapsedRow(ev) != "" {
		t.Fatalf("the expanded view is still collapsing rows:\n%s", ev)
	}
	name := probeName(t, m, diagnostic.ProbeSSID)
	for _, tc := range []struct{ where, v string }{{"compact", compact}, {"expanded", ev}} {
		if hasRow(tc.v, name) {
			t.Errorf("%s: the Checks panel still draws the %q row:\n%s", tc.where, name, tc.v)
		}
		for _, row := range checksRows(tc.v) {
			if strings.Contains(row, "homewifi") {
				t.Errorf("%s: a Checks row repeats the network name: %q\n%s", tc.where, row, tc.v)
			}
		}
	}
	// The probe itself is untouched: everything else still reads its result.
	if got := expanded.results[diagnostic.ProbeSSID].Network; got != "homewifi" {
		t.Errorf("the Wi-Fi probe result was dropped along with its row: Network = %q", got)
	}
	if rep := expanded.report(); !strings.Contains(rep, "homewifi") {
		t.Errorf("the report lost the network name:\n%s", rep)
	}
}

// TestChecksPanelReadsBottomUp pins the rendered Checks order as literal row
// names, for both run shapes. The panel is a protocol stack read from the link
// upward, and the probe slice is not that order: the Wi-Fi probe sits between
// Path MTU and TLS in a targeted run and last in a generic one, so a panel
// that simply drew every probe would break the progression in one mode and
// disagree with the other. Deriving the expected order from the model, as the
// order tests around it do, cannot catch that.
func TestChecksPanelReadsBottomUp(t *testing.T) {
	public := "DNS (public)"
	for _, tc := range []struct {
		name, target string
		want         []string
	}{
		{
			name:   "targeted TLS",
			target: "example.com:443",
			want: []string{
				"Interface",
				"Internet (TCP egress)",
				"QUIC / UDP 443",
				"Internet (env proxy)",
				"DNS example.com",
				public,
				"DNS (encrypted DoH/DoT)",
				"TCP example.com:443",
				"Path MTU example.com:443",
				"TLS example.com",
				"HTTP example.com",
				"HTTPS example.com",
			},
		},
		{
			name: "generic",
			want: []string{
				"Interface",
				"Internet (TCP egress)",
				"QUIC / UDP 443",
				"Internet (env proxy)",
				"DNS",
				public,
				"DNS (encrypted DoH/DoT)",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target *diagnostic.Target
			if tc.target != "" {
				target = mustTarget(t, tc.target)
			}
			m := newModel(target, false)
			doneResults(&m, "")
			// Expanded, so every row the panel has is on screen and a missing
			// one cannot be blamed on the compact view collapsing it.
			m, v := renderAt(t, press(t, onWireless(m), "a"))
			if collapsedRow(v) != "" {
				t.Fatalf("the expanded view is still collapsing rows:\n%s", v)
			}
			var got []string
			for _, row := range checksRows(v) {
				got = append(got, rowLabel(row))
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Checks rows = %v, want %v:\n%s", got, tc.want, v)
			}
			// The Wi-Fi probe still ran, and its name is on the context strip
			// rather than in the list above.
			if got := m.results[diagnostic.ProbeSSID].Network; got != "homewifi" {
				t.Errorf("the Wi-Fi probe result is gone: Network = %q", got)
			}
			if strip := ansi.Strip(m.headerView()); !strings.Contains(strip, "Wi-Fi: homewifi") {
				t.Errorf("the context strip lost the network name: %q", strip)
			}
		})
	}
}

// TestCursorNeverStopsOnARowlessProbe: hiding a row without taking it out of
// the cursor's path would leave the reader on a position with no row under it
// and a Details panel describing something they cannot see.
func TestCursorNeverStopsOnARowlessProbe(t *testing.T) {
	m := press(t, wifiModel(t), "a")
	m.width, m.height = 100, 40
	ssid := probeIndex(t, m, diagnostic.ProbeSSID)
	rows := m.checkRows()
	if slices.Contains(rows, ssid) {
		t.Fatalf("the Wi-Fi probe still has a row, so there is nothing to skip over")
	}

	seen := map[int]bool{}
	walk := func(key string) {
		for range len(m.probes) + 2 {
			if m.selected == ssid {
				t.Fatalf("%q parked the cursor on the rowless Wi-Fi probe", key)
			}
			seen[m.selected] = true
			m = press(t, m, key)
		}
	}
	walk("j")
	walk("k")
	for _, key := range []string{"G", "g"} { // bottom, then top on the default map
		m = press(t, m, key)
		if m.selected == ssid {
			t.Fatalf("%q parked the cursor on the rowless Wi-Fi probe", key)
		}
	}
	if len(seen) != len(rows) {
		t.Errorf("the cursor reached %d of the %d rows the panel offers", len(seen), len(rows))
	}
	// Every stop the cursor made is a row the panel is actually showing.
	for i := range seen {
		if v := m.View(); !strings.Contains(v, "Details: "+m.probes[i].Name) && m.selected == i {
			t.Errorf("Details is not describing the cursor row %q:\n%s", m.probes[i].Name, v)
		}
	}
}

// TestCollapsedCountIsWhatExpandBringsBack: the summary line stands in for
// rows, so it must count rows. A probe with no row of its own is not one of
// them, and counting it would promise the reader a row expand cannot deliver.
func TestCollapsedCountIsWhatExpandBringsBack(t *testing.T) {
	m, compact := renderAt(t, wifiModel(t))
	summary := collapsedRow(compact)
	if summary == "" {
		t.Fatalf("nothing collapsed, so there is no count to check:\n%s", compact)
	}
	_, ev := renderAt(t, press(t, m, "a"))
	gained := len(checksRows(ev)) - (len(checksRows(compact)) - 1) // the summary is not a row
	if !strings.Contains(summary, fmt.Sprintf("%d other checks passed", gained)) {
		t.Errorf("summary = %q, but expand brought back %d rows:\n%s", summary, gained, ev)
	}
}

// noChecksModel is the run that selects nothing: every probe hangs off the
// interface row, so skipping that one leaves an empty DAG. The run is finished
// and healthy the moment it starts, and there is no row to describe.
func noChecksModel(t *testing.T) model {
	t.Helper()
	selection := diagnostic.ProbeSelection{
		Skip: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeIface: {}},
	}
	m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "test",
		diagnostic.DefaultPublicDNS, true, selection).(model)
	if len(m.probes) != 0 {
		t.Fatalf("this selection still runs %d probes, so it has details to show", len(m.probes))
	}
	return m
}

// TestDetailsPanelIsDroppedWhenItHasNothingToSay: a bordered box of whitespace
// under a title is worse than no panel. The block is the Checks panel alone,
// with no orphaned title and no rows reserved for the panel that is not there.
//
// This is also the run that used to panic. With no probes selected there is no
// cursor row to describe, and the Details panel indexed the empty slice to look
// for one, so rendering it at all is half of what this test proves.
func TestDetailsPanelIsDroppedWhenItHasNothingToSay(t *testing.T) {
	m, v := renderAt(t, noChecksModel(t))
	if strings.Contains(ansi.Strip(v), "Details") {
		t.Errorf("an empty Details panel (or its title) is still drawn:\n%s", v)
	}
	if sections := bodySections(v); len(sections) != 1 || sections["Checks"] == nil {
		t.Errorf("the block drew %v, want the Checks section alone:\n%s", sections, v)
	}
	if n := unclosedPanels(v); n != 0 {
		t.Errorf("%d panel border(s) left unclosed:\n%s", n, v)
	}
	// No blank rows kept back for the section that is not drawn: the block is
	// exactly the Checks heading over its rule, with no rows under it.
	if h := lipgloss.Height(m.bodyView(false, 0)); h != 2 {
		t.Errorf("the results block is %d rows tall, want 2 (heading, rule):\n%s",
			h, m.bodyView(false, 0))
	}
	// There is no row to move onto and none to blame, so every movement key has
	// to leave the cursor alone rather than walk off the end of an empty row set.
	if rows := m.checkRows(); len(rows) != 0 {
		t.Fatalf("this run offers %d rows, so the empty row set is not under test", len(rows))
	}
	for _, key := range []string{"j", "k", "G", "g"} {
		m = press(t, m, key)
		if m.selected != 0 {
			t.Fatalf("%q moved the cursor to %d on a run with no rows", key, m.selected)
		}
		if i := m.focusRow(); i >= 0 {
			t.Fatalf("after %q the view blames row %d of a run with no rows", key, i)
		}
		if v := m.View(); strings.Contains(ansi.Strip(v), "Details") || unclosedPanels(v) != 0 {
			t.Errorf("%q left the view malformed:\n%s", key, v)
		}
	}
}

// TestDetailsPanelComesBackWithContent is the other half of that rule: the
// panel is decided by what it would contain, not by the verdict. A healthy run
// still has a cursor row with evidence, and the panel is there to carry it.
// The failing row is the case where the answer block has taken the finding and
// the remedy: what the panel is left holding is the raw probe evidence, and
// that is enough to keep it on screen.
func TestDetailsPanelComesBackWithContent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) model
		want  string
	}{
		{"healthy run", wifiModel, "interface wlan0 is up"},
		{"failing row", evidenceModel, "198.51.100.10"},
		{"checks not run yet", func(t *testing.T) model { return newModel(mustTarget(t, "example.com:443"), true) },
			"the checks haven't run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, v := renderAt(t, tc.build(t))
			if !strings.Contains(ansi.Strip(v), "Details") {
				t.Fatalf("the Details panel is missing:\n%s", v)
			}
			if !containsRow(detailsRows(v), tc.want) {
				t.Errorf("Details lost %q:\n%s", tc.want, v)
			}
		})
	}
}

// TestSectionBodyDropsWhitespaceOnlyContent: emptiness is measured on the text
// with its styling stripped, so a body that is only spaces, or only escape
// sequences, still counts as nothing to draw.
func TestSectionBodyDropsWhitespaceOnlyContent(t *testing.T) {
	title := defaultStyles.panelTitle.Render("Details: DNS")
	for _, tc := range []struct {
		name string
		rows []string
		want bool
	}{
		{"title alone", []string{title}, false},
		{"blank body", []string{title, ""}, false},
		{"spaces", []string{title, "   ", "\t"}, false},
		{"styling only", []string{title, defaultStyles.faint.Render("")}, false},
		{"nothing at all", nil, false},
		{"real content", []string{title, defaultStyles.faint.Render("src 192.0.2.7 eth0")}, true},
		{"blank row above content", []string{title, "  ", "PASS: up"}, true},
	} {
		if got := sectionBody(tc.rows) != nil; got != tc.want {
			t.Errorf("%s: sectionBody kept the section = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestSectionsTakeTheirOwnHeights: neither section is padded out to match the
// other. Whichever has more to say is taller, and the block is as tall as that
// one rather than as tall as both.
func TestSectionsTakeTheirOwnHeights(t *testing.T) {
	for _, tc := range []struct {
		name   string
		build  func(t *testing.T) model
		taller string
	}{
		// One collapsed row of checks beside a failing row's source identity
		// and its two per-address attempts.
		{"details taller", evidenceModel, "details"},
		// Every passing row expanded beside a one-line PASS.
		{"checks taller", func(t *testing.T) model { return press(t, wifiModel(t), "a") }, "checks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, v := renderAt(t, tc.build(t))
			details := len(detailsRows(v))
			if details == 0 {
				t.Fatalf("no Details section to compare heights against:\n%s", v)
			}
			checks := len(checksRows(v))
			if checks == details {
				t.Fatalf("both sections are %d rows tall, so one is still padded to the other:\n%s",
					checks, v)
			}
			if (details > checks) != (tc.taller == "details") {
				t.Fatalf("checks = %d rows, details = %d, want %s taller:\n%s",
					checks, details, tc.taller, v)
			}
			if got, want := lipgloss.Height(v), 40; got > want {
				t.Errorf("the view is %d rows on a %d-row terminal:\n%s", got, want, v)
			}
		})
	}
}

// TestUnevenSectionsStayInsideAShortTerminal: the sections do not share a
// height, so the taller one is what the row budget has to answer for. The
// block still yields rather than overflow, at every size.
func TestUnevenSectionsStayInsideAShortTerminal(t *testing.T) {
	for _, width := range []int{100, 60} {
		for _, h := range []int{40, 24, 20, 16, 12, 10, 8, 6} {
			u, _ := evidenceModel(t).Update(tea.WindowSizeMsg{Width: width, Height: h})
			v := asModel(t, u).View()
			if rows := lipgloss.Height(v); rows > h {
				t.Errorf("%dx%d: view is %d display rows tall:\n%s", width, h, rows, v)
			}
			if n := unclosedPanels(v); n != 0 {
				t.Errorf("%dx%d: %d panel border(s) left unclosed:\n%s", width, h, n, v)
			}
		}
	}
}
