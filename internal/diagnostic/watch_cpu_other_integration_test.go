//go:build integration && !unix

package diagnostic

import "time"

// processCPU reports no CPU time where getrusage is unavailable. The benchmark
// then omits its CPU metrics rather than report zero.
func processCPU() (user, sys time.Duration, ok bool) {
	return 0, 0, false
}
