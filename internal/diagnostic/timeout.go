package diagnostic

import (
	"fmt"
	"math"
	"time"
)

// The probe timeout's canonical representation is a time.Duration that is a
// whole number of milliseconds, and this file is the only place that decides
// what that means.
//
// It is one representation because the setting has to survive every boundary
// one invocation crosses. A probe consumes a time.Duration, but every durable
// and remote spelling of the same setting is an integer millisecond field:
// options.probe_timeout_ms in netdoc.snapshot.v1, and timeout_ms in remote
// protocol 1. Both are published contracts that existing readers and existing
// remote builds already interpret, so neither can widen. Accepting a finer
// local value than those fields can carry is what makes the setting change
// meaning on the way through: a sub-millisecond timeout becomes zero, which a
// remote worker rejects and an artifact cannot tell from an absent field, and a
// fractional one silently shrinks to the millisecond below it.
//
// So the restriction lives at the invocation instead, where a person can still
// be told about it, and every conversion below is exact by construction.

// MaxProbeTimeoutMs is the largest millisecond timeout that converts to a
// time.Duration without overflowing its int64 nanoseconds. A whole-millisecond
// Duration can never exceed it, so it bounds only values that arrived as a
// number from somewhere else.
const MaxProbeTimeoutMs = int64(math.MaxInt64) / int64(time.Millisecond)

// ValidateProbeTimeout reports whether d can be a probe timeout.
//
// Whole milliseconds is the accepted precision, checked here rather than
// rounded, because rounding is the silent change this contract exists to
// prevent: a run told to spend 1.9ms and given 1ms was answered with a budget
// it did not ask for. A rejection before any probe or SSH connection starts is
// the honest answer, and it is the ordinary bad-argument outcome.
//
// No upper bound is needed: a positive whole-millisecond Duration is always
// within MaxProbeTimeoutMs, since Duration itself runs out first.
func ValidateProbeTimeout(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("-timeout must be positive")
	}
	if d%time.Millisecond != 0 {
		return fmt.Errorf("-timeout must be a whole number of milliseconds, not %s", d)
	}
	return nil
}

// ProbeTimeoutFromMs rebuilds the canonical timeout from a millisecond count
// that arrived as untrusted data: a remote request, or any other producer's
// integer field.
//
// The range check happens before the multiplication, not after. Converting
// first overflows int64 silently, and the wrap is not always negative: a wire
// value of 18446744073710 comes back as a plausible 448.384us, which a
// positive-only check accepts as a timeout nobody asked for.
func ProbeTimeoutFromMs(ms int64) (time.Duration, error) {
	if ms <= 0 {
		return 0, fmt.Errorf("-timeout must be positive")
	}
	if ms > MaxProbeTimeoutMs {
		return 0, fmt.Errorf("-timeout must not exceed %dms", MaxProbeTimeoutMs)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

// ProbeTimeoutMs projects an accepted probe timeout onto the integer
// millisecond field every wire and artifact form uses.
//
// It is exact for anything ValidateProbeTimeout or ProbeTimeoutFromMs returned,
// which is every timeout a run can reach, so no producer loses precision by
// calling it. Callers route through this rather than Milliseconds() so that the
// projection and the rule that makes it lossless cannot drift apart.
func ProbeTimeoutMs(d time.Duration) int64 {
	return d.Milliseconds()
}
