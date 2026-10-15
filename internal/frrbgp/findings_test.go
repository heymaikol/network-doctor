package frrbgp

import (
	"strings"
	"testing"
)

// Each RFC 4271 state has its own limit. Only those other than Established carry
// the not-down wording, every state says that it does not show reachability and
// that the far end is not identified, and a state FRR prints with a qualifier is
// not read as the bare state.
func TestStateLimit(t *testing.T) {
	seen := map[string]string{}
	for _, state := range []string{"Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established", "Idle (Admin)", "Clearing", "Down"} {
		limit := StateLimit(state)
		if !strings.HasSuffix(limit, "The state alone does not show whether the peer is reachable. The far end is not identified; the summary maps no address to a node.") {
			t.Errorf("%s: limit does not end with the reachability and far-end caveats: %q", state, limit)
		}
		_, known := stateLimits[state]
		if notDown := strings.Contains(limit, "The session is not reported as down."); notDown != (known && state != StateEstablished) {
			t.Errorf("%s: not-down wording present = %v", state, notDown)
		}
		if strings.Contains(limit, "is down") || strings.Contains(limit, "unreachable") {
			t.Errorf("%s: limit calls the session down or the peer unreachable: %q", state, limit)
		}
		if known == strings.Contains(limit, "does not interpret") {
			t.Errorf("%s: known = %v, but the limit is %q", state, known, limit)
		}
		if other, dup := seen[limit]; dup && known {
			t.Errorf("%s and %s share one limit", state, other)
		}
		seen[limit] = state
	}
}

// A state outside the six is matched exactly, so FRR's text is never read as a
// known state, and its limit uses no word that could contradict it. "Down" is
// not a state RFC 4271 names, so the limit neither denies it nor reads a cause
// into it.
func TestStateLimitClaimsNothingForAnUnfamiliarState(t *testing.T) {
	generic := StateLimit("Down")
	for _, state := range []string{"Down", "down", "established", "Established ", "Idle (Admin)"} {
		if got := StateLimit(state); got != generic {
			t.Errorf("%q: limit = %q, want the generic limit %q", state, got, generic)
		}
	}
	lower := strings.ToLower(generic)
	for _, word := range []string{"down", "up", "established", "unreachable", "because"} {
		if strings.Contains(lower, word) {
			t.Errorf("generic limit uses %q, which a state such as Down could contradict: %q", word, generic)
		}
	}
	if !strings.Contains(generic, "no meaning or cause is claimed") {
		t.Errorf("generic limit does not disclaim meaning and cause: %q", generic)
	}
}
