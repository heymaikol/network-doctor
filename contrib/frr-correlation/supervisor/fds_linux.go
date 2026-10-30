//go:build linux

package supervisor

import (
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// checkInheritance refuses when this process holds a descriptor above 2 that a
// child would inherit. Go closes only close-on-exec descriptors at exec, so an
// inherited plain descriptor would reach FRR. It is a point-in-time check.
func checkInheritance() error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrFDLeak
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= 2 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err == unix.EBADF {
			continue // the directory descriptor used for this listing
		}
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			return ErrFDLeak
		}
	}
	return nil
}

// cloexecFD wraps an ioctl that returns a new descriptor so the descriptor is
// close-on-exec before any concurrent fork can inherit it.
func cloexecFD(get func() (int, error)) (int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := get()
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}
