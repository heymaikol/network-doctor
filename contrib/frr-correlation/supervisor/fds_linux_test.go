//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// markInheritedCloseOnExec makes every descriptor above 2 that whatever started
// this process left open close-on-exec, and names each one on stderr. The
// supervisor refuses to work while it holds an inheritable descriptor, so a
// runner that leaks one into the test binary (the hosted GitHub runner does) would
// fail every test for a reason that has nothing to do with them. Tests that need
// a leaked descriptor open their own after this runs.
func markInheritedCloseOnExec() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= 2 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC != 0 { // an error is the listing's own, already closed descriptor
			continue
		}
		target, _ := os.Readlink("/proc/self/fd/" + e.Name())
		fmt.Fprintf(os.Stderr, "supervisor tests: descriptor %d (%s) was left inheritable, marking it close-on-exec\n", fd, target)
		unix.CloseOnExec(fd)
	}
}

func TestCheckInheritanceRefusesPlainDescriptor(t *testing.T) {
	markInheritedCloseOnExec()
	if err := checkInheritance(); err != nil {
		t.Fatalf("still inheritable after marking the runner's descriptors: %v", err)
	}
	fd, err := unix.Open(os.DevNull, unix.O_RDONLY, 0) // no O_CLOEXEC on purpose
	if err != nil {
		t.Fatal(err)
	}
	if err := checkInheritance(); !errors.Is(err, ErrFDLeak) {
		t.Fatalf("plain descriptor %d: got %v", fd, err)
	}
	unix.CloseOnExec(fd)
	if err := checkInheritance(); err != nil {
		t.Fatalf("close-on-exec descriptor refused: %v", err)
	}
	_ = unix.Close(fd)
}
