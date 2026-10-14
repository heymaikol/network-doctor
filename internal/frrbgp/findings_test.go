package frrbgp

import (
	"strings"
	"testing"
)

// Each RFC 4271 state has its own limit. Only Established leaves out the
// not-down wording, every state says the far end is not identified, and a state
// FRR prints with a qualifier is not read as the bare state.
func TestStateLimit(t *testing.T) {
	seen := map[string]string{}
	for _, state := range []string{"Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established", "Idle (Admin)", "Clearing"} {
		limit := StateLimit(state)
		if !strings.HasSuffix(limit, "The far end is not identified; the summary maps no address to a node.") {
			t.Errorf("%s: limit does not end with the far-end caveat: %q", state, limit)
		}
		if notDown := strings.Contains(limit, "The session is not reported as down."); notDown == (state == StateEstablished) {
			t.Errorf("%s: not-down wording present = %v", state, notDown)
		}
		if strings.Contains(limit, "is down") {
			t.Errorf("%s: limit calls the session down: %q", state, limit)
		}
		if _, known := stateLimits[state]; known && strings.Contains(limit, "does not interpret") {
			t.Errorf("%s: an RFC 4271 state got the generic limit", state)
		}
		if _, known := stateLimits[state]; !known && !strings.Contains(limit, "does not interpret") {
			t.Errorf("%s: an uninterpreted state got a specific limit: %q", state, limit)
		}
		if other, dup := seen[limit]; dup && stateLimits[state] != "" {
			t.Errorf("%s and %s share one limit", state, other)
		}
		seen[limit] = state
	}
}
