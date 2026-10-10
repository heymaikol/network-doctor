//go:build linux

package diagnostic

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// routeGroups are the kernel multicast groups a route source binds: link,
// address and route changes, for both families. Joining them takes no privilege.
const routeGroups = unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
	unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE

// optionalRouteGroups are rtnetlink group numbers joined after the bind: IPv4
// policy rules (8), IPv6 policy rules (19) and nexthop objects (32). A change to
// any of them can alter a route lookup without a link, address or route
// notification. They are group numbers, not bit masks, and each join reports its
// own error: a kernel without a group refuses that join, and the rest stand.
var optionalRouteGroups = []int{unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE, unix.RTNLGRP_NEXTHOP}

// joinOptionalRouteGroups joins each group in turn. A refused join leaves that
// group out and does not stop the others, and the bound groups are unaffected.
func joinOptionalRouteGroups(fd int, groups []int) {
	for _, g := range groups {
		_ = unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, g)
	}
}

// netlinkRouteEvents reads the route groups from a non-blocking netlink socket.
// The socket is non-blocking and wrapped by os.File, so closing the file from
// another goroutine wakes a pending read. A blocking descriptor would not wake,
// and its number could be reused under the reader.
type netlinkRouteEvents struct {
	f   *os.File
	buf []byte
}

func openRouteEvents() (routeEvents, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: routeGroups}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	joinOptionalRouteGroups(fd, optionalRouteGroups)
	// #nosec G115 -- a valid descriptor just returned by the kernel
	return &netlinkRouteEvents{f: os.NewFile(uintptr(fd), "netlink route events"), buf: make([]byte, 8<<10)}, nil
}

// next blocks until the kernel sends a notification. The content is not read:
// every message on these groups is a link, address, route, rule or nexthop
// change, and the reader only has to know that one happened.
func (r *netlinkRouteEvents) next() error {
	_, err := r.f.Read(r.buf)
	return routeReadError(err)
}

// routeReadError maps the kernel's dropped-notification error to an overflow.
// Any other error ends the subscription.
func routeReadError(err error) error {
	if errors.Is(err, unix.ENOBUFS) {
		return errRouteEventsOverflow
	}
	return err
}

func (r *netlinkRouteEvents) close() error {
	return r.f.Close()
}
