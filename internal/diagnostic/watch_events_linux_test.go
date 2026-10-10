package diagnostic

import (
	"errors"
	"os"
	"slices"
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

// membershipBits returns the groups the kernel reports for fd, with bit g-1 set
// for group g. It reads the kernel's list, so a join is checked where it took effect.
func membershipBits(fd int) (uint32, error) {
	bits, err := unix.GetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_LIST_MEMBERSHIPS)
	// #nosec G115 -- the kernel's 32-bit membership word, read into an int
	return uint32(bits), err
}

// The optional groups are rtnetlink group numbers. RTMGRP_IPV4_RULE is the bit for
// group 8, not group 128, so a join by mask would name a group that does not exist.
func TestOptionalRouteGroupsAreRtnetlinkGroupNumbers(t *testing.T) {
	if want := []int{8, 19, 32}; !slices.Equal(optionalRouteGroups, want) {
		t.Errorf("optional route groups = %v, want %v", optionalRouteGroups, want)
	}
}

// A group the kernel does not have refuses its join, and the joins after it still
// stand. Group 99 is past every rtnetlink group, so the kernel refuses it everywhere.
func TestRefusedOptionalJoinLeavesTheOthers(t *testing.T) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: routeGroups}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, 99); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("join of group 99 = %v, want EINVAL", err)
	}

	joinOptionalRouteGroups(fd, []int{99, unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_NEXTHOP})
	bits, err := membershipBits(fd)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []int{8, 32} {
		if bits&(1<<(g-1)) == 0 {
			t.Errorf("group %d not joined after group 99 was refused", g)
		}
	}
	for _, g := range []int{1, 5, 7, 9, 11} {
		if bits&(1<<(g-1)) == 0 {
			t.Errorf("bound group %d lost after a refused join", g)
		}
	}
}
