// The Observed block's grouping: what a probe measured, said once per outcome
// rather than once per measurement. These tests fail if a grouped block stops
// being the whole record, if it reorders what a probe measured, if a lone
// measurement grows chrome it never needed, or if the count that says how much
// of the record a group covers stops surviving a monochrome terminal.

package ui

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// refusedRun is the shape the grouping exists for: one address answered and
// the fifteen behind it were refused, which is one fact about fifteen
// addresses and used to be fifteen copies of one sentence. The errors carry
// their own address the way Go's dialer writes them, so the run is only one
// group if the address has been taken back off the front of each.
func refusedRun(t *testing.T) model {
	t.Helper()
	m := offlineRun(t, mustTarget(t, "example.com:443"))
	m.width, m.height = 100, 40
	r := m.results[diagnostic.ProbeQUIC]
	r.Source, r.Iface = net.ParseIP("192.0.2.7"), "eth0"
	r.Attempts = refusedAttempts(16)
	m.results[diagnostic.ProbeQUIC] = r
	m.selected, m.selMoved = probeIndex(t, m, diagnostic.ProbeQUIC), true
	return m
}

// refusedAttempts is n recorded attempts: the first answered, the rest were
// refused, each error naming its own address the way net.OpError spells one.
func refusedAttempts(n int) []diagnostic.Attempt {
	out := make([]diagnostic.Attempt, 0, n)
	for i := range n {
		ip := net.ParseIP(fmt.Sprintf("203.0.113.%d", i+1))
		a := diagnostic.Attempt{IP: ip, Dur: time.Duration(20+i) * time.Millisecond}
		if i > 0 {
			a.Err = errors.New("dial tcp4 " + ip.String() + ":443: connect: connection refused")
			a.Cause = diagnostic.ConnectionCauseRefused
		}
		out = append(out, a)
	}
	return out
}

// observedBlock is the Observed rows of the selected check's evidence, styling
// stripped: everything under the label and above whatever follows it.
func observedBlock(m model) []string {
	rows := plainDetails(m)
	start := rowIndex(rows, observedTitle)
	if start < 0 {
		return nil
	}
	var out []string
	for _, row := range rows[start+1:] {
		if !strings.HasPrefix(row, " ") {
			break
		}
		out = append(out, row)
	}
	return out
}

// TestSingleObservationStaysOneLine: one address is not a repetition, so it
// keeps the plain line it has always had. No count, no list, no group heading
// over a group of one.
func TestSingleObservationStaysOneLine(t *testing.T) {
	m := refusedRun(t)
	r := m.results[diagnostic.ProbeQUIC]
	r.Attempts = refusedAttempts(1)
	m.results[diagnostic.ProbeQUIC] = r

	block := observedBlock(m)
	line := ""
	for _, row := range block {
		if strings.Contains(row, "203.0.113.1") {
			line = strings.TrimSpace(row)
		}
	}
	if want := "203.0.113.1 20ms ok"; line != want {
		t.Errorf("a lone attempt renders as %q, want %q:\n%s", line, want, strings.Join(block, "\n"))
	}
	for _, row := range block {
		if strings.Contains(row, "addresses)") {
			t.Errorf("a lone attempt grew a group count:\n%s", strings.Join(block, "\n"))
		}
	}
}

// TestRepeatedOutcomeIsSaidOnceWithACount: fifteen addresses refused for the
// same reason state that reason once. The point of the change: the sixteenth
// line, the one that is not a copy, is no longer buried under fifteen copies.
func TestRepeatedOutcomeIsSaidOnceWithACount(t *testing.T) {
	block := observedBlock(refusedRun(t))
	text := strings.Join(block, "\n")
	if got := strings.Count(text, "connection refused"); got != 1 {
		t.Errorf("the refusal is stated %d times, want once:\n%s", got, text)
	}
	if !strings.Contains(text, "connect: connection refused (15 of 16 addresses)") {
		t.Errorf("the group does not say how much of the record it covers:\n%s", text)
	}
	// The one address that behaved differently is still its own line.
	if !strings.Contains(text, "203.0.113.1 20ms ok") {
		t.Errorf("the address that answered lost its own line:\n%s", text)
	}
	// And the block is now short enough to read as a summary.
	if len(block) > 8 {
		t.Errorf("sixteen attempts still draw %d rows:\n%s", len(block), text)
	}
}

// TestGroupedObservationsKeepEveryMeasurement is the invariant the grouping
// has to earn: it is a rearrangement of the record, not a summary standing in
// for one. Every address and every timing a probe recorded is still in the
// block, so nothing needs an expansion mechanism to be reachable.
func TestGroupedObservationsKeepEveryMeasurement(t *testing.T) {
	m := refusedRun(t)
	attempts := m.results[diagnostic.ProbeQUIC].Attempts
	text := strings.Join(observedBlock(m), "\n")
	for _, a := range attempts {
		entry := fmt.Sprintf("%s %dms", a.IP, diagnostic.Ms(a.Dur))
		if !strings.Contains(text, entry) {
			t.Errorf("%q is not in the evidence:\n%s", entry, text)
		}
	}
	// Counted, not just spot-checked: an address rendered twice or a timing
	// quietly shared between two addresses would pass the loop above.
	addresses := regexp.MustCompile(`203\.0\.113\.\d+ \d+ms`).FindAllString(text, -1)
	if len(addresses) != len(attempts) {
		t.Errorf("the evidence carries %d measurements, want %d:\n%s",
			len(addresses), len(attempts), text)
	}
}

// TestMateriallyDifferentObservationsStayApart: grouping is by what came back,
// so results that differ are never folded together. Four different failures
// are four lines, and none of them acquires a count.
func TestMateriallyDifferentObservationsStayApart(t *testing.T) {
	m := refusedRun(t)
	reasons := []string{"connection refused", "network is unreachable", "i/o timeout", "connection reset by peer"}
	var attempts []diagnostic.Attempt
	for i, reason := range reasons {
		ip := net.ParseIP(fmt.Sprintf("203.0.113.%d", i+1))
		attempts = append(attempts, diagnostic.Attempt{
			IP: ip, Dur: time.Duration(10+i) * time.Millisecond,
			Err: errors.New("dial tcp4 " + ip.String() + ":443: connect: " + reason),
		})
	}
	r := m.results[diagnostic.ProbeQUIC]
	r.Attempts = attempts
	m.results[diagnostic.ProbeQUIC] = r

	block := observedBlock(m)
	text := strings.Join(block, "\n")
	for _, reason := range reasons {
		if got := strings.Count(text, reason); got != 1 {
			t.Errorf("%q appears %d times, want once:\n%s", reason, got, text)
		}
	}
	if strings.Contains(text, "addresses)") {
		t.Errorf("four different failures were grouped:\n%s", text)
	}
}

// TestObservedKeepsChronology: only neighbours are grouped, so a result that
// changed part-way through the run stays two groups. Folding every equal
// outcome together regardless of position would report "2 of 3" once and lose
// the order the probe actually measured them in, which for connection
// attempts is the order the addresses were tried.
func TestObservedKeepsChronology(t *testing.T) {
	m := refusedRun(t)
	ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	var attempts []diagnostic.Attempt
	for i, ip := range ips {
		a := diagnostic.Attempt{IP: net.ParseIP(ip), Dur: time.Duration(i+1) * time.Millisecond}
		if i != 1 { // refused, answered, refused: the middle one is the change
			a.Err = errors.New("dial tcp4 " + ip + ":443: connect: connection refused")
		}
		attempts = append(attempts, a)
	}
	r := m.results[diagnostic.ProbeQUIC]
	r.Attempts = attempts
	m.results[diagnostic.ProbeQUIC] = r

	text := strings.Join(observedBlock(m), "\n")
	if got := strings.Count(text, "connection refused"); got != 2 {
		t.Errorf("a refusal either side of a success collapsed into %d group(s), want 2:\n%s", got, text)
	}
	// And the measurements are still in the order they were taken.
	var seen []string
	for _, at := range regexp.MustCompile(`203\.0\.113\.\d+`).FindAllString(text, -1) {
		seen = append(seen, at)
	}
	if strings.Join(seen, ",") != strings.Join(ips, ",") {
		t.Errorf("the evidence reads %v, want the measured order %v:\n%s", seen, ips, text)
	}
}

// TestGroupedObservationsStayWithinTheirColumn: the member list is packed to
// the column it was handed, so a grouped block never widens the section that
// draws it. The whole view is checked too, since a row that overflows is a row
// the layout's own budget never saw coming.
func TestGroupedObservationsStayWithinTheirColumn(t *testing.T) {
	m := refusedRun(t)
	for _, width := range []int{36, 40, 62, 80, 100, 120} {
		t.Run(strconv.Itoa(width), func(t *testing.T) {
			for _, row := range observedLines(m.results[diagnostic.ProbeQUIC], width) {
				if got := len(row); got > width && strings.HasPrefix(row, "    ") {
					t.Errorf("a packed list row is %d columns wide in a %d-column section: %q",
						got, width, row)
				}
			}
		})
	}
	for _, size := range shortSizes {
		t.Run(fmt.Sprintf("view-%dx%d", size[0], size[1]), func(t *testing.T) {
			sm, _ := sized(t, m, size[0], size[1])
			assertViewFits(t, sm)
		})
	}
}

// TestObservedCountSurvivesMonochrome: the count is what says a group stands
// for more than one measurement, so it has to be words and digits rather than
// a colour or a glyph. Read back with every style stripped, which is what a
// NO_COLOR terminal and a screen reader both get.
func TestObservedCountSurvivesMonochrome(t *testing.T) {
	m := refusedRun(t)
	m.st = newStyles(resolveTheme("monochrome"))
	text := ansi.Strip(strings.Join(observedBlock(m), "\n"))
	if !strings.Contains(text, "(15 of 16 addresses)") {
		t.Errorf("the group count is not readable without colour:\n%s", text)
	}
}

// TestObservedStaysUnderTheInterpretation: grouping changes the shape of the
// mechanics and nothing above them. The status word, the consequence and the
// guidance are all still read before the measurements.
func TestObservedStaysUnderTheInterpretation(t *testing.T) {
	m := refusedRun(t)
	rows := plainDetails(m)
	observed := rowIndex(rows, observedTitle)
	if observed < 0 {
		t.Fatalf("the grouped row has no Observed block:\n%s", strings.Join(rows, "\n"))
	}
	if observed == 0 {
		t.Errorf("the evidence opens on the measurements:\n%s", strings.Join(rows, "\n"))
	}
	if !strings.HasPrefix(rows[0], "FAIL") {
		t.Errorf("the evidence no longer opens on its outcome, got %q", rows[0])
	}
	for _, above := range []string{"Consequence of ", "Fix: "} {
		if at := rowIndex(rows, above); at >= 0 && at > observed {
			t.Errorf("%q is under the measurements:\n%s", above, strings.Join(rows, "\n"))
		}
	}
}

// TestInlineAndViewerGroupTheSameWay: D opens the same reading of the same
// check, grouped the same way. The viewer needs no expansion of its own
// because the inline block already carries every measurement.
func TestInlineAndViewerGroupTheSameWay(t *testing.T) {
	m := refusedRun(t)
	sm, _ := sized(t, m, 100, 40)
	viewer := openCheckDetails(t, sm)
	text := ansi.Strip(viewer.detailsContent())
	for _, a := range m.results[diagnostic.ProbeQUIC].Attempts {
		entry := fmt.Sprintf("%s %dms", a.IP, diagnostic.Ms(a.Dur))
		if !strings.Contains(text, entry) {
			t.Errorf("the viewer is missing %q:\n%s", entry, text)
		}
	}
	if got := strings.Count(text, "connection refused"); got != 1 {
		t.Errorf("the viewer states the refusal %d times, want once:\n%s", got, text)
	}
}

// TestShortTerminalsStillReachEveryMeasurement: the inline section sheds rows
// on a short terminal, and D is the route back to the whole record. Every
// address the probe tried is in the viewer at every size, including the ones
// where the inline block was cut to a couple of rows.
func TestShortTerminalsStillReachEveryMeasurement(t *testing.T) {
	m := refusedRun(t)
	attempts := m.results[diagnostic.ProbeQUIC].Attempts
	for _, size := range shortSizes {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			sm, _ := sized(t, m, size[0], size[1])
			viewer := openCheckDetails(t, sm)
			text := ansi.Strip(viewer.detailsContent())
			for _, a := range attempts {
				if !strings.Contains(text, a.IP.String()) {
					t.Errorf("%s is unreachable through D at %dx%d:\n%s",
						a.IP, size[0], size[1], text)
				}
			}
		})
	}
}

// TestWatchHistoryStaysOutOfObserved: History is the run before this one and
// Observed is this one. Grouping works inside a single pass, so a watched row
// can never fold what it measured now into what it measured last time.
func TestWatchHistoryStaysOutOfObserved(t *testing.T) {
	m := refusedRun(t)
	m.watch = true
	m.runHistory = map[diagnostic.ProbeID][]diagnostic.Status{
		diagnostic.ProbeQUIC: {diagnostic.StatusFail, diagnostic.StatusPass, diagnostic.StatusFail},
	}
	rows := plainDetails(m)
	history := rowIndex(rows, "History: ")
	observed := rowIndex(rows, observedTitle)
	if history < 0 || observed < 0 {
		t.Fatalf("want both an Observed block and a History line:\n%s", strings.Join(rows, "\n"))
	}
	if history < observed {
		t.Errorf("History is above the measurements it is not part of:\n%s", strings.Join(rows, "\n"))
	}
	for _, row := range observedBlock(m) {
		if strings.Contains(row, "History") || strings.Contains(row, "runs") {
			t.Errorf("a past pass is inside this pass's measurements: %q", row)
		}
	}
}

// TestObservedGroupsRoutesTheSameWay: the grouping is one representation, not
// a formatter per probe. Destinations the operating system routed the same way
// are one answer about several addresses, and a destination it answered
// differently keeps its own line.
func TestObservedGroupsRoutesTheSameWay(t *testing.T) {
	r := diagnostic.ProbeResult{Routes: []diagnostic.RouteDecision{
		{Destination: net.ParseIP("198.18.0.1"), Family: "ipv4", Iface: "eth0", Gateway: net.ParseIP("10.0.1.1")},
		{Destination: net.ParseIP("198.18.0.2"), Family: "ipv4", Iface: "eth0", Gateway: net.ParseIP("10.0.1.1")},
		{Destination: net.ParseIP("2001:db8::2"), Family: "ipv6", Unreachable: true},
	}}
	text := strings.Join(observedLines(r, 80), "\n")
	if !strings.Contains(text, "dev eth0 via 10.0.1.1 (2 of 3 destinations)") {
		t.Errorf("two identical route decisions were not grouped:\n%s", text)
	}
	if !strings.Contains(text, "route 2001:db8::2: no route") {
		t.Errorf("the destination with no route lost its own line:\n%s", text)
	}
	for _, want := range []string{"198.18.0.1", "198.18.0.2", "2001:db8::2"} {
		if !strings.Contains(text, want) {
			t.Errorf("%s is not in the evidence:\n%s", want, text)
		}
	}
}

// TestAttemptOutcomeOnlyDropsTheAddressItRestates: the normalisation is what
// lets two addresses that failed for the same reason read as one fact, and it
// is also the one place this block rewrites a probe's own text. It cuts the
// dialler's "dial tcp4 addr:port: " opener and nothing else.
func TestAttemptOutcomeOnlyDropsTheAddressItRestates(t *testing.T) {
	ip := net.ParseIP("203.0.113.9")
	for _, tc := range []struct{ name, err, want string }{
		{"ipv4 dial", "dial tcp4 203.0.113.9:443: connect: connection refused", "connect: connection refused"},
		{"ipv6 dial", "dial tcp6 [2001:db8::2]:443: connect: network is unreachable", "connect: network is unreachable"},
		{"no address in the text", "recorded connection attempt failed", "recorded connection attempt failed"},
		{"address only later in the sentence", "lookup failed: no route to 203.0.113.9", "lookup failed: no route to 203.0.113.9"},
		{"nothing left after the cut", "203.0.113.9: ", "203.0.113.9: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := diagnostic.Attempt{IP: ip, Err: errors.New(tc.err)}
			if tc.name == "ipv6 dial" {
				at.IP = net.ParseIP("2001:db8::2")
			}
			if got := attemptOutcome(at); got != tc.want {
				t.Errorf("attemptOutcome(%q) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
	if got := attemptOutcome(diagnostic.Attempt{IP: ip}); got != "ok" {
		t.Errorf("a successful attempt reports %q, want %q", got, "ok")
	}
}
