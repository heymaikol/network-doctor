package diagnostic

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// The kernel reports dropped notifications as ENOBUFS on the read, wrapped by
// os.File. Only that is an overflow: the reader keeps going after it and stops
// on anything else.
func TestRouteReadErrorMapsOnlyENOBUFSToOverflow(t *testing.T) {
	dropped := &os.PathError{Op: "read", Path: "netlink route events", Err: unix.ENOBUFS}
	if got := routeReadError(dropped); !errors.Is(got, errRouteEventsOverflow) {
		t.Errorf("ENOBUFS read = %v, want the overflow error", got)
	}
	ended := &os.PathError{Op: "read", Path: "netlink route events", Err: unix.EINVAL}
	if got := routeReadError(ended); !errors.Is(got, ended) {
		t.Errorf("EINVAL read = %v, want it passed through", got)
	}
	if got := routeReadError(nil); got != nil {
		t.Errorf("successful read = %v, want nil", got)
	}
}
