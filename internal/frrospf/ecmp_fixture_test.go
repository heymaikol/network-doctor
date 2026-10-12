package frrospf

import (
	"strings"
	"testing"
	"time"
)

// ecmpCapture loads one bracket capture of the committed ECMP run. role is A,
// B, E, or D, as in lsdbCapture.
func ecmpCapture(tb testing.TB, node, role string) Capture {
	tb.Helper()
	var command string
	switch role {
	case "A", "D":
		command = CommandProcessState
	case "B":
		command = CommandLSDB
	case "E":
		command = CommandRoute
	default:
		tb.Fatalf("unknown role %q", role)
	}
	stem := node + "-" + role + "-" + strings.ReplaceAll(command, " ", "_")
	return loadCapture(tb, "ecmp", stem, node, command, "ecmp "+node+" "+role)
}

// Gate B2. In each committed ECMP bracket, the A to D window exceeds the
// holdtime maximum plus SPF delay read from the captures, and the 1000 ms AS
// external calculation interval that the guard also uses. A window at or below
// the bound would fail the guard, so this test fails first on a shorter bracket.
func TestECMPBracketWindowExceedsTheBound(t *testing.T) {
	for _, node := range []string{"r1", "r2"} {
		a, d := ecmpCapture(t, node, "A"), ecmpCapture(t, node, "D")
		pa, reason := decodeProcessState(a.Data)
		if reason != "" {
			t.Fatalf("%s A: %s", node, reason)
		}
		pd, reason := decodeProcessState(d.Data)
		if reason != "" {
			t.Fatalf("%s D: %s", node, reason)
		}
		// #nosec G115 -- the timers in these captures are a few seconds, far below the int64 range.
		bound := max(int64(pa.HoldtimeMaxMs)+int64(pa.SPFDelayMs), int64(pd.HoldtimeMaxMs)+int64(pd.SPFDelayMs), 1000)
		window := d.CollectedAt.Sub(a.CollectedAt)
		if window <= time.Duration(bound)*time.Millisecond {
			t.Fatalf("%s window %s does not exceed the %d ms bound", node, window, bound)
		}
	}
}
