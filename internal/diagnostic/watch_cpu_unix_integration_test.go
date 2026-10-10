//go:build integration && unix

package diagnostic

import (
	"syscall"
	"time"
)

// processCPU returns the user and system CPU time this process has used so far.
// It counts every goroutine, so the loopback servers' work is included with the
// client's. A benchmark reads it before and after its timed region.
func processCPU() (user, sys time.Duration, ok bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, 0, false
	}
	return timevalDuration(ru.Utime), timevalDuration(ru.Stime), true
}

// timevalDuration converts a Timeval whose field widths differ between platforms.
func timevalDuration(tv syscall.Timeval) time.Duration {
	return time.Duration(int64(tv.Sec))*time.Second + time.Duration(int64(tv.Usec))*time.Microsecond
}
