//go:build !windows

package diagnostic

// SystemUnbiasedClock is nil where no second reader is wired, so a pass keeps the
// monotonic check alone. Linux CLOCK_MONOTONIC does not count a suspend
// (clock_gettime(2)). Go's darwin monotonic reads mach_absolute_time, and whether
// that counts a sleep is not verified on hardware, so macOS keeps this behavior.
var SystemUnbiasedClock func() (uint64, bool)
