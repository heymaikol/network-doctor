//go:build linux

package supervisor

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"
)

// Only a failure that says the host cannot make the namespaces may read as
// unsupported, because that is the one class a test or CI probe turns into a
// skip. A resource limit, a failed exec or an error nobody listed must stay a
// failure, and the cause must survive in both classes.
func TestHolderStartErrorSeparatesUnsupportedFromGenuineFailures(t *testing.T) {
	start := func(e error) error { return &fs.PathError{Op: "fork/exec", Path: "/usr/bin/sleep", Err: e} }
	for _, tc := range []struct {
		name        string
		err         error
		unsupported bool
	}{
		{"clone refused", start(syscall.EPERM), true},
		{"denied by a security module or seccomp", start(syscall.EACCES), true},
		{"kernel without user namespaces", start(syscall.EINVAL), true},
		{"namespace limit is zero", start(syscall.ENOSPC), true},
		{"clone not implemented", start(syscall.ENOSYS), true},
		{"bare errno", syscall.EPERM, true},
		{"process limit", start(syscall.EAGAIN), false},
		{"out of memory", start(syscall.ENOMEM), false},
		{"descriptor limit", start(syscall.EMFILE), false},
		{"system descriptor limit", start(syscall.ENFILE), false},
		{"holder binary gone", start(syscall.ENOENT), false},
		{"holder not executable", start(syscall.ENOEXEC), false},
		{"error nobody listed", errors.New("something else"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := holderStartError(tc.err)
			if gotUnsupported := errors.Is(got, ErrUnsupported); gotUnsupported != tc.unsupported {
				t.Fatalf("unsupported = %v, want %v: %v", gotUnsupported, tc.unsupported, got)
			}
			if errors.Is(got, ErrLaunchFailed) == tc.unsupported {
				t.Fatalf("an error must be in exactly one class: %v", got)
			}
			if !errors.Is(got, tc.err) {
				t.Fatalf("the cause was dropped: %v", got)
			}
		})
	}
}
