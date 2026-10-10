//go:build windows

package diagnostic

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// SystemUnbiasedClock reads the unbiased interrupt-time count, in 100 ns units. It
// reports false when the count cannot be read. Go's monotonic clock on Windows
// reads the biased count, which keeps running through a suspend, so the unbiased
// count is the reading that shows one. The export is loaded through the realtime
// API set rather than kernel32.dll: on Windows 11 build 26200 kernel32.dll does not
// export it, although the documentation lists that DLL.
var SystemUnbiasedClock = unbiasedInterruptTime

var queryUnbiasedInterruptTimePrecise = windows.NewLazySystemDLL("api-ms-win-core-realtime-l1-1-1.dll").NewProc("QueryUnbiasedInterruptTimePrecise")

// unbiasedInterruptTime calls QueryUnbiasedInterruptTimePrecise. The function has
// no return value, so its only failure is a missing export, which Find detects
// before the call.
func unbiasedInterruptTime() (uint64, bool) {
	if queryUnbiasedInterruptTimePrecise.Find() != nil {
		return 0, false
	}
	var ticks uint64
	// The call has no return value, so the last-error result it would give is not read.
	_, _, _ = queryUnbiasedInterruptTimePrecise.Call(uintptr(unsafe.Pointer(&ticks)))
	return ticks, true
}
