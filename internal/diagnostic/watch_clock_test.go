package diagnostic

import "time"

// Sessions in these tests run on fake clocks, which do not move the real unbiased
// counter. On Windows that counter advances in real time, so a fake minute would
// read as a suspend. The package therefore runs with the real counter off, and the
// tests that exercise the count set their own reader on the session.
func init() {
	SystemUnbiasedClock = nil
}

// unbiasedTicks converts awake time to counter ticks. Fake awake time never runs
// backward, so a negative duration reads as zero.
func unbiasedTicks(d time.Duration) uint64 {
	if d < 0 {
		return 0
	}
	return uint64(d / unbiasedTick) //nolint:gosec // G115: d is non-negative here
}
