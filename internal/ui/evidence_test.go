// The split between the two panels: Checks answers what needs attention,
// Details answers what evidence produced that answer. These tests fail if
// per-address attempts, source and interface identity, or the retained watch
// history drift back into the Checks panel.

package ui

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// detailsRows is the Details section's rows as rendered, its heading and rule
// left out. The heading is contextual, so the section is found by what its
// heading starts with rather than by an exact title: it names the cursor row,
// or the diagnosis when the reader has opened the "why".
func detailsRows(v string) []string {
	for title, rows := range bodySections(v) {
		if strings.HasPrefix(title, "Details") || strings.HasPrefix(title, "Why:") {
			return rows
		}
	}
	return nil
}

// containsRow reports whether any of rows carries want.
func containsRow(rows []string, want string) bool {
	for _, row := range rows {
		if strings.Contains(row, want) {
			return true
		}
	}
	return false
}

// glyphCount is how many status glyphs a rendered row carries. A probe row
// carries one for its own status, plus one per tick of history beside it.
func glyphCount(row string) int {
	n := 0
	for _, r := range row {
		if strings.ContainsRune("✓!✗⊘–", r) {
			n++
		}
	}
	return n
}

// rowFor is the Checks panel's row for one probe, "" when it drew none.
func rowFor(v, name string) string {
	for _, row := range checksRows(v) {
		if strings.Contains(row, name) {
			return row
		}
	}
	return ""
}

// evidenceModel is a finished run whose failing DNS row carries every kind of
// evidence a probe can attach, with the cursor on it so Details describes it.
func evidenceModel(t *testing.T) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, diagnostic.ProbeDNS)
	r := m.results[diagnostic.ProbeDNS]
	r.Detail = "no A or AAAA record"
	r.Source, r.Iface = net.ParseIP("192.0.2.7"), "eth0"
	r.Attempts = []diagnostic.Attempt{
		{IP: net.ParseIP("198.51.100.9"), Dur: 12 * time.Millisecond},
		{IP: net.ParseIP("198.51.100.10"), Dur: 34 * time.Millisecond, Err: errors.New("connection refused")},
	}
	m.results[diagnostic.ProbeDNS] = r
	m.selected = probeIndex(t, m, diagnostic.ProbeDNS)
	return m
}

// TestSourceIdentityIsDetailsOnly: which local address and interface a probe
// went out of is evidence for the result, not the result. It belongs beside
// the probe in Details, never on the Checks row.
func TestSourceIdentityIsDetailsOnly(t *testing.T) {
	_, v := renderAt(t, evidenceModel(t))
	for _, row := range checksRows(v) {
		if strings.Contains(row, "src ") || strings.Contains(row, "192.0.2.7") || strings.Contains(row, "eth0") {
			t.Errorf("source evidence is on a Checks row: %q\n%s", row, v)
		}
	}
	if !containsRow(detailsRows(v), "src 192.0.2.7 eth0") {
		t.Errorf("Details lost the source and interface identity:\n%s", v)
	}
}

// TestPerAddressAttemptsAreDetailsOnly: the attempt list is the longest piece
// of evidence a probe produces and the least useful at a glance.
func TestPerAddressAttemptsAreDetailsOnly(t *testing.T) {
	_, v := renderAt(t, evidenceModel(t))
	for _, row := range checksRows(v) {
		if strings.Contains(row, "198.51.100.") || strings.Contains(row, "connection refused") {
			t.Errorf("an attempt leaked into a Checks row: %q\n%s", row, v)
		}
	}
	details := detailsRows(v)
	for _, want := range []string{"198.51.100.9 12ms ok", "198.51.100.10 34ms connection refused"} {
		if !containsRow(details, want) {
			t.Errorf("Details lost the attempt %q:\n%s", want, v)
		}
	}
}

func TestCounterfactualEvidenceUsesTheExistingWhyView(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	m.results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{}
	for _, tt := range []struct {
		evidence diagnostic.CausalEvidence
		want     string
	}{
		{diagnostic.CausalEvidence{Kind: diagnostic.EvidenceSupport, Check: diagnostic.ProbeTargetTCP,
			Observation: diagnostic.ObservationFamilyFailed, Value: "ipv6"}, "could not reach the target over IPv6"},
		{diagnostic.CausalEvidence{Kind: diagnostic.EvidenceSupport, Check: diagnostic.ProbeTargetTCP,
			Observation: diagnostic.ObservationAddressSucceeded, Value: "192.0.2.2"}, "reached 192.0.2.2"},
	} {
		if got := m.causalEvidenceLine(tt.evidence); !strings.Contains(got, tt.want) {
			t.Errorf("line = %q, want %q", got, tt.want)
		}
	}
}

// watchHistoryModel is a finished watch pass with runs recorded ticks long for
// the failing DNS row, which is also the row the cursor is on.
func watchHistoryModel(t *testing.T, ticks int) model {
	t.Helper()
	m := evidenceModel(t)
	m.watch = true
	history := make([]diagnostic.Status, 0, ticks)
	for i := range ticks {
		status := diagnostic.StatusPass
		if i%3 == 0 {
			status = diagnostic.StatusFail
		}
		history = append(history, status)
	}
	m.runHistory[diagnostic.ProbeDNS] = history
	return m
}

// TestChecksHaveNoHistoryStripOutsideWatch: a single run has no pass-by-pass
// story to tell, so the Checks row spends no columns implying it has one.
func TestChecksHaveNoHistoryStripOutsideWatch(t *testing.T) {
	m := watchHistoryModel(t, 12)
	m.watch = false
	m, v := renderAt(t, m)
	row := rowFor(v, probeName(t, m, diagnostic.ProbeDNS))
	if row == "" {
		t.Fatalf("the failing row is missing:\n%s", v)
	}
	if n := glyphCount(row); n != 1 {
		t.Errorf("row = %q carries %d status glyphs, want only its own", row, n)
	}
}

// TestWatchChecksShowTheCompactEightTickStrip: watch mode earns the strip, but
// only the last eight passes of it. The full retained history is Details' job.
func TestWatchChecksShowTheCompactEightTickStrip(t *testing.T) {
	for _, ticks := range []int{1, 8, 12, watchRuns} {
		m, v := renderAt(t, watchHistoryModel(t, ticks))
		row := rowFor(v, probeName(t, m, diagnostic.ProbeDNS))
		if row == "" {
			t.Fatalf("the failing row is missing at %d ticks:\n%s", ticks, v)
		}
		want := min(ticks, 8) + 1 // the strip, plus the row's own status glyph
		if n := glyphCount(row); n != want {
			t.Errorf("at %d ticks the row = %q carries %d glyphs, want %d", ticks, row, n, want)
		}
	}
}

// TestDetailsKeepsTheFullRetainedHistory: Details is the evidence surface, so
// it shows every pass the model still holds, not the compact eight.
func TestDetailsKeepsTheFullRetainedHistory(t *testing.T) {
	const ticks = 12
	m, v := renderAt(t, watchHistoryModel(t, ticks))
	var history string
	for _, row := range detailsRows(v) {
		if strings.Contains(row, "History:") {
			history = row
		}
	}
	if history == "" {
		t.Fatalf("Details drew no history line:\n%s", v)
	}
	if n := glyphCount(history); n != ticks {
		t.Errorf("Details history = %q carries %d ticks, want all %d", history, n, ticks)
	}
	failed := 0
	for _, status := range m.runHistory[diagnostic.ProbeDNS] {
		if status == diagnostic.StatusFail {
			failed++
		}
	}
	if want := "failed 4 of 12 runs"; !strings.Contains(history, want) || failed != 4 {
		t.Errorf("Details history = %q, want %q over the full retained run count", history, want)
	}
}

// TestWatchStripFollowsTheRowThroughAChange: the strip is presentation, so a
// row that flipped keeps every recorded state, including the earlier failure a
// currently passing row is hiding.
func TestWatchStripFollowsTheRowThroughAChange(t *testing.T) {
	m := evidenceModel(t)
	m.watch = true
	r := m.results[diagnostic.ProbeDNS]
	r.Status = diagnostic.StatusPass
	m.results[diagnostic.ProbeDNS] = r
	m.runHistory[diagnostic.ProbeDNS] = []diagnostic.Status{diagnostic.StatusFail, diagnostic.StatusPass}
	m, v := renderAt(t, m)

	row := rowFor(v, probeName(t, m, diagnostic.ProbeDNS))
	if n := glyphCount(row); n != 3 {
		t.Errorf("row = %q carries %d glyphs, want the status plus both recorded passes", row, n)
	}
	if !containsRow(detailsRows(v), "failed 1 of 2 runs") {
		t.Errorf("Details lost the earlier failure of a now-passing row:\n%s", v)
	}
}

// TestWatchStripIsAbsentBeforeTheFirstRecordedPass: the first pass has nothing
// to draw, and an empty strip is two columns of nothing.
func TestWatchStripIsAbsentBeforeTheFirstRecordedPass(t *testing.T) {
	m := evidenceModel(t)
	m.watch = true
	m, v := renderAt(t, m)
	row := rowFor(v, probeName(t, m, diagnostic.ProbeDNS))
	if n := glyphCount(row); n != 1 {
		t.Errorf("row = %q carries %d glyphs before any pass was recorded, want only its own", row, n)
	}
	if containsRow(detailsRows(v), "History:") {
		t.Errorf("Details drew a history line with no history:\n%s", v)
	}
}

// Every route observation renders as a sentence about the path, and none of
// them renders as a failure of the row that recorded it: a tunnel is not a
// fault, and a split path is a difference rather than a verdict.
func TestRouteObservationsRenderAsPathSentences(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:443"), false)
	// The row records the kernel having named wg0 a wireguard device, which is
	// what lets the sentence about it be stated rather than suggested.
	m.results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{Routes: []diagnostic.RouteDecision{{
		Destination: net.ParseIP("198.51.100.7"), Iface: "wg0",
		Tunnel: diagnostic.TunnelKnown, TunnelKind: "wireguard",
	}}}
	m.results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{}
	for _, tt := range []struct {
		evidence diagnostic.CausalEvidence
		want     string
		// glyph: only a destination with no route is a failure. A tunnel, a
		// split path, and a narrow link are readings about the path, and the
		// panel must not present them as things that went wrong.
		glyph string
	}{
		{diagnostic.CausalEvidence{Kind: diagnostic.EvidenceSupport, Check: diagnostic.ProbeTargetTCP,
			Observation: diagnostic.ObservationRouteTunneled, Value: "wg0"}, "through the tunnel wg0", "!"},
		{diagnostic.CausalEvidence{Kind: diagnostic.EvidenceSupport, Check: diagnostic.ProbeTargetTCP,
			Observation: diagnostic.ObservationRouteDirect, Value: "eth0"}, "eth0, which is not reported as a tunnel", "✓"},
		{diagnostic.CausalEvidence{Kind: diagnostic.EvidenceSupport, Check: diagnostic.ProbeTargetTCP,
			Observation: diagnostic.ObservationRouteUnreachable, Value: "198.51.100.7"}, "no route to 198.51.100.7", "✗"},
		{diagnostic.CausalEvidence{Kind: diagnostic.EvidenceSupport, Check: diagnostic.ProbeDNS,
			Observation: diagnostic.ObservationRoutePathDiffers, Value: "wg0"}, "different path from the target traffic on wg0", "!"},
		{diagnostic.CausalEvidence{Kind: diagnostic.EvidenceSupport, Check: diagnostic.ProbeTargetTCP,
			Observation: diagnostic.ObservationRouteFamilySplit}, "IPv4 and IPv6 over materially different routes", "!"},
		{diagnostic.CausalEvidence{Kind: diagnostic.EvidenceSupport, Check: diagnostic.ProbeTargetTCP,
			Observation: diagnostic.ObservationRouteInterfaceMTU, Value: "wg0"}, "link MTU is smaller than the general path's", "!"},
	} {
		got := m.causalEvidenceLine(tt.evidence)
		if !strings.Contains(got, tt.want) {
			t.Errorf("line = %q, want %q", got, tt.want)
		}
		if !strings.HasPrefix(got, tt.glyph) {
			t.Errorf("line = %q, want it to start with %q", got, tt.glyph)
		}
	}
}

// The tunnel sentence is only as strong as the evidence behind the row's
// tunnel state. A kind the operating system named is a fact to repeat; a link
// that merely has the shape of a tunnel is a guess, and a mobile broadband
// modem has the same shape, so the app must not tell the user they are on a
// VPN because an interface is point-to-point.
func TestShapeOnlyTunnelsAreNotStatedAsFact(t *testing.T) {
	tunneled := diagnostic.CausalEvidence{Kind: diagnostic.EvidenceSupport,
		Check: diagnostic.ProbeTargetTCP, Observation: diagnostic.ObservationRouteTunneled, Value: "utun3"}
	route := diagnostic.RouteDecision{Destination: net.ParseIP("198.51.100.7"), Iface: "utun3"}

	for _, tt := range []struct {
		name  string
		state diagnostic.TunnelState
		want  string
		deny  string
	}{
		{"named by the operating system", diagnostic.TunnelKnown, "left through the tunnel utun3", "shape"},
		{"shape only", diagnostic.TunnelLikely, "which has the shape of a tunnel", "through the tunnel"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := newModel(mustTarget(t, "example.com:443"), false)
			route.Tunnel = tt.state
			m.results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{Routes: []diagnostic.RouteDecision{route}}
			got := m.causalEvidenceLine(tunneled)
			if !strings.Contains(got, tt.want) {
				t.Errorf("line = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, tt.deny) {
				t.Errorf("line = %q, must not contain %q", got, tt.deny)
			}
		})
	}
}

// A tunnel a probe took shows up in the Details panel for that row, and never
// on the Checks row: it is evidence about the path, not the outcome.
func TestRouteDecisionsAreDetailsOnly(t *testing.T) {
	m := evidenceModel(t)
	r := m.results[diagnostic.ProbeDNS]
	r.Routes = []diagnostic.RouteDecision{{
		Destination: net.ParseIP("192.0.2.53"), Family: "ipv4", Iface: "wg0",
		Prefix: netip.MustParsePrefix("10.20.0.0/16"), Tunnel: diagnostic.TunnelKnown, TunnelKind: "wireguard",
	}}
	m.results[diagnostic.ProbeDNS] = r
	_, v := renderAt(t, m)
	if !containsRow(detailsRows(v), "route 192.0.2.53: 10.20.0.0/16 dev wg0 (wireguard)") {
		t.Errorf("Details lost the route decision:\n%s", v)
	}
	for _, row := range checksRows(v) {
		if strings.Contains(row, "wg0") || strings.Contains(row, "10.20.0.0/16") {
			t.Errorf("a route decision leaked into a Checks row: %q\n%s", row, v)
		}
	}
}
