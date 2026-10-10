package app

import "github.com/heymaikol/network-doctor/internal/diagnostic"

// These tests run Watch on fake clocks. On Windows the session would otherwise
// read the real unbiased counter, which advances in real time and would show a
// fake minute as a suspend. The counter is off for the package's tests.
func init() {
	diagnostic.SystemUnbiasedClock = nil
}
