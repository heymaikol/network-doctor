//go:build linux

package supervisor

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheckInheritanceRefusesPlainDescriptor(t *testing.T) {
	if err := checkInheritance(); err != nil {
		t.Skipf("test process already holds an inheritable descriptor: %v", err)
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
	unix.Close(fd)
}
