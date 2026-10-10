//go:build windows

package diagnostic

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// realUnbiasedClock is the platform reader as the package found it. Package
// variables initialize before init runs, and watch_clock_test.go clears the
// exported var in init, so this keeps the value the platform file set.
var realUnbiasedClock = SystemUnbiasedClock

// The real counter with real clocks. The sleep is short and does not suspend the
// machine, so both clocks advance over it and must agree. This shows the counter
// is readable and moves with time. It does not show a suspend is caught: that needs
// a real suspend, which an ordinary test run never does.
func TestWindowsUnbiasedCounterAgreesWithMonotonicWithoutSuspend(t *testing.T) {
	if realUnbiasedClock == nil {
		t.Fatal("the platform file did not set the unbiased reader")
	}
	v := windows.RtlGetVersion()
	t.Logf("windows %d.%d build %d", v.MajorVersion, v.MinorVersion, v.BuildNumber)

	start, ok := realUnbiasedClock()
	if !ok {
		t.Fatal("the unbiased interrupt time is unavailable")
	}
	mono := time.Now()
	time.Sleep(200 * time.Millisecond)
	end, ok := realUnbiasedClock()
	if !ok {
		t.Fatal("the unbiased interrupt time became unavailable")
	}
	working := ticksElapsed(start, end)
	awake := time.Since(mono)
	t.Logf("monotonic %v, unbiased %v", awake, working)
	if working < 100*time.Millisecond {
		t.Errorf("the unbiased count advanced %v over a 200ms sleep", working)
	}
	if !unbiasedCurrent(awake, working, time.Hour) {
		t.Errorf("the unbiased count %v disagrees with the monotonic clock %v", working, awake)
	}
}

// A session on the real clocks reads the counter at Begin and checks it at
// publication. Without a suspend the pass stays current.
func TestWindowsWatchPassStaysCurrentOnRealClocks(t *testing.T) {
	if realUnbiasedClock == nil {
		t.Fatal("the platform file did not set the unbiased reader")
	}
	s := NewWatchSession(time.Now)
	s.unbiased = realUnbiasedClock
	pass := s.Begin(nil, time.Second)
	if !pass.hasUnbiased {
		t.Fatal("a session on Windows did not read the unbiased count at Begin")
	}
	time.Sleep(200 * time.Millisecond)
	if !pass.current(time.Now()) {
		t.Error("a pass without a suspend was refused on the real clocks")
	}
}
