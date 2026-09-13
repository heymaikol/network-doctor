package ui

import (
	"slices"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func referenceSelection(hasTarget bool) diagnostic.ProbeSelection {
	skip := map[diagnostic.ProbeID]struct{}{}
	for _, id := range diagnostic.ReferenceEgressProbes(hasTarget, false) {
		skip[id] = struct{}{}
	}
	return diagnostic.ProbeSelection{Skip: skip}
}

// The command line resolves -no-reference-egress against the run it was given.
// Here that run has a target, so the DNS rows ask about example.com and are the
// user's own traffic rather than netdoc's. Retest with an empty line makes the
// session targetless, and those same rows would go back to resolving a
// compiled-in hostname purely to manufacture a DNS answer. The DAG is rebuilt
// for the new shape, so the mode has to be decided against that DAG instead of
// replayed from the IDs the command line worked out for the old one.
func TestNoReferenceEgressSurvivesATargetSwitchToAGenericRun(t *testing.T) {
	selection := referenceSelection(true)
	selection.NoReferenceEgress = true
	m := NewWithSelection(mustTarget(t, "example.com"), nil, false, false, "", "test",
		diagnostic.DefaultPublicDNS, true, selection).(model)
	if !slices.Contains(probeIDs(m), diagnostic.ProbeDNS) {
		t.Fatalf("the target's own DNS row was dropped; rows were %v", probeIDs(m))
	}

	m.applyTarget(nil, true)
	after := probeIDs(m)
	for _, id := range diagnostic.ReferenceEgressProbes(false, false) {
		if slices.Contains(after, id) {
			t.Errorf("the targetless run reintroduced row %q; rows were %v", id, after)
		}
	}
}

// Why that is a flag on the selection and not the resolved list of IDs: the
// list alone is a snapshot of one run's shape, and the switch above is exactly
// where it goes stale.
func TestTheResolvedSkipListAloneWouldNotSurviveTheSwitch(t *testing.T) {
	m := NewWithSelection(mustTarget(t, "example.com"), nil, false, false, "", "test",
		diagnostic.DefaultPublicDNS, true, referenceSelection(true)).(model)
	m.applyTarget(nil, true)
	if !slices.Contains(probeIDs(m), diagnostic.ProbeDNS) {
		t.Fatal("the stale list no longer leaks the compiled-in DNS row, so ProbeSelection.NoReferenceEgress may have become redundant; confirm that before removing it")
	}
}

// And with the mode off, a target switch changes nothing about which rows run.
func TestATargetSwitchWithoutTheModeKeepsTheReferenceRows(t *testing.T) {
	m := NewWithSelection(mustTarget(t, "example.com"), nil, false, false, "", "test",
		diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)
	m.applyTarget(nil, true)
	after := probeIDs(m)
	for _, id := range diagnostic.ReferenceEgressProbes(false, false) {
		if !slices.Contains(after, id) {
			t.Errorf("an ordinary targetless run is missing row %q; rows were %v", id, after)
		}
	}
}
