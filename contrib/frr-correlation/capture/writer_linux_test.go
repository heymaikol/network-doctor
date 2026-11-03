//go:build linux

package capture

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These helpers and tests cover the test processes this package starts: the
// detached writer a producer helper leaves behind, and the helper programs
// themselves. They make no claim about the supervisor or its process lifetime.

// pinnedWriter is a process held by a pidfd. A signal sent through it reaches
// that process or nobody: once the process is gone its number may be reused, but
// the pidfd never follows the number, and the kernel answers ESRCH.
type pinnedWriter struct {
	fd  int
	pid int // for diagnostics only; never used to signal
}

// pinWriter pins the process a PID file names, and accepts it only if it holds
// the stream open. The pidfd is opened first and the check made second. If the
// number was reused before the open, the process behind the pidfd does not hold
// the stream and is refused. If the process was reaped between the open and the
// check, the check may read whichever process took the number next. The signal 0
// after the check settles that. It fails once the process is reaped, and reaping
// cannot be undone, so a success means the process was unreaped at the check. The
// check therefore read that process, and the pin names the writer.
func pinWriter(pid int, stream string) (*pinnedWriter, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open: %w", err)
	}
	if !holdsStream(pid, stream) || unix.PidfdSendSignal(fd, 0, nil, 0) != nil {
		_ = unix.Close(fd)
		return nil, errors.New("the process does not hold the stream")
	}
	return &pinnedWriter{fd: fd, pid: pid}, nil
}

func (w *pinnedWriter) kill() error { return unix.PidfdSendSignal(w.fd, unix.SIGKILL, nil, 0) }

func (w *pinnedWriter) close() { _ = unix.Close(w.fd) }

// holdsStream reports whether the process has the stream open for writing under
// any descriptor. It compares the inode that following each /proc link reaches, so
// it does not depend on how the path reads from the process's own mount namespace.
// A read-only descriptor does not count: a pin is a kill capability, and only a
// writer may receive it.
func holdsStream(pid int, stream string) bool {
	want, err := os.Stat(stream)
	if err != nil {
		return false
	}
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if got, err := os.Stat(filepath.Join(dir, e.Name())); err == nil && os.SameFile(got, want) && fdWritable(pid, e.Name()) {
			return true
		}
	}
	return false
}

// fdWritable reports whether descriptor fd of pid was opened for writing. The
// access mode is the low two bits of the octal "flags:" field in fdinfo.
func fdWritable(pid int, fd string) bool {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/fdinfo/" + fd) //nolint:gosec // G304: a /proc path built from a PID and descriptor number.
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "flags:") {
			continue
		}
		flags, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "flags:")), 8, 64)
		return err == nil && flags&unix.O_ACCMODE != unix.O_RDONLY
	}
	return false
}

// requirePidfd skips the test as unavailable when the host cannot open a pidfd.
// Call it before any detached writer starts, so a skip leaves no process behind.
// Any other failure fails the test.
func requirePidfd(t *testing.T) {
	t.Helper()
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err == nil {
		_ = unix.Close(fd)
		return
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		unavailable(t, "pidfd_open: %v", err)
	}
	t.Fatalf("pidfd_open: %v", err)
}

// holders lists the processes that have the stream open.
func holders(stream string) []int {
	entries, _ := os.ReadDir("/proc")
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && holdsStream(pid, stream) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// adoptWriter pins the detached writer a producer helper recorded in pidfile. A
// writer that cannot be pinned fails the test: there is no fallback to signaling
// the number. Cleanup kills the writer through the pin.
func adoptWriter(t *testing.T, pidfile, stream string) *pinnedWriter {
	t.Helper()
	raw, err := os.ReadFile(pidfile) //nolint:gosec // G304: the path is this test's own TempDir.
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil {
		t.Fatalf("pid file: %v", err)
	}
	w, err := pinWriter(pid, stream)
	if err != nil {
		t.Fatalf("detached writer %d: %v", pid, err)
	}
	t.Cleanup(func() { _ = w.kill(); w.close() })
	return w
}

// startHold starts the sleeping helper as a direct child. stream, if not empty,
// is passed to it as descriptor 3, which is how a producer helper hands a
// descendant the writable stream.
func startHold(t *testing.T, stream string) (*exec.Cmd, <-chan error) {
	t.Helper()
	cmd := exec.Command(os.Args[0]) //nolint:gosec // G204: re-executes this test binary.
	cmd.Env = []string{"CAPTURE_HELPER=hold"}
	if stream != "" {
		f, err := os.OpenFile(stream, os.O_WRONLY|os.O_CREATE, 0o600) //nolint:gosec // G304: a path in this test's own TempDir.
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		cmd.ExtraFiles = []*os.File{f}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait(); close(exited) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-exited })
	return cmd, exited
}

// A PID file can name a process that is not the writer, for instance one that
// took the number after the writer was reaped. Pinning must refuse it, and
// nothing may be signaled.
func TestPinWriterRefusesAProcessThatDoesNotHoldTheStream(t *testing.T) {
	stream := filepath.Join(t.TempDir(), "stream")
	if err := os.WriteFile(stream, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bystander, exited := startHold(t, "")
	w, err := pinWriter(bystander.Process.Pid, stream)
	if err == nil {
		_ = w.kill() // what the cleanup does with a pin it was given
		w.close()
		t.Error("pinned a process that does not hold the stream")
	}
	select {
	case <-exited:
		t.Fatal("the bystander was signaled")
	case <-time.After(300 * time.Millisecond):
	}
}

// A read-only descriptor on the stream does not make a process the writer. The
// test process stands in for a producer, and nothing is signaled.
func TestPinWriterRefusesAReadOnlyHolder(t *testing.T) {
	stream := filepath.Join(t.TempDir(), "stream")
	if err := os.WriteFile(stream, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ro, err := os.Open(stream) //nolint:gosec // G304: a path in this test's own TempDir.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if w, err := pinWriter(os.Getpid(), stream); err == nil {
		w.close()
		t.Fatal("pinned a process whose only descriptor is read-only")
	}
	rw, err := os.OpenFile(stream, os.O_WRONLY, 0) //nolint:gosec // G304: a path in this test's own TempDir.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rw.Close() }()
	w, err := pinWriter(os.Getpid(), stream)
	if err != nil {
		t.Fatalf("refused a process holding the stream for writing: %v", err)
	}
	w.close()
}

// Once the writer is gone a pin signals nobody. A number that was reused cannot
// be reached through it, because the pidfd names the process and not the number.
// Real number reuse is not simulated here: it takes a PID namespace with its own
// procfs, and this shows the kernel's answer for a process that exited.
func TestPinnedWriterSignalsNobodyOnceTheWriterIsGone(t *testing.T) {
	stream := filepath.Join(t.TempDir(), "stream")
	writer, exited := startHold(t, stream)
	w, err := pinWriter(writer.Process.Pid, stream)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if err := w.kill(); err != nil {
		t.Fatalf("kill through the pin: %v", err)
	}
	<-exited
	if err := w.kill(); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("kill after the writer was reaped: %v, want ESRCH", err)
	}
}

// If the helper cannot record the PID of the descendant it started, it must not
// leave that descendant behind, sleeping with the writable stream open.
func TestDetachHelperLeavesNoWriterWhenItCannotRecordItsPID(t *testing.T) {
	stream := filepath.Join(t.TempDir(), "stream")
	cmd := exec.Command(os.Args[0]) //nolint:gosec // G204: re-executes this test binary.
	cmd.Env = []string{"CAPTURE_HELPER=detach", "CAPTURE_FILE=" + stream, "CAPTURE_PIDFILE=" + filepath.Join(t.TempDir(), "missing", "pid")}
	var ee *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &ee) || ee.ExitCode() != 6 {
		t.Fatalf("helper exit: %v, want status 6", err)
	}
	left := holders(stream)
	for _, pid := range left { // a failing run must not leave an hour-long sleeper
		if w, err := pinWriter(pid, stream); err == nil {
			_ = w.kill()
			w.close()
		}
	}
	if len(left) != 0 {
		t.Fatalf("%d process(es) still hold the stream after the helper failed: %v", len(left), left)
	}
}

// A helper name that no case handles must not skip the suite and pass.
func TestMainRefusesAnUnknownHelper(t *testing.T) {
	const marker = "no-such-helper-9c1e"
	cmd := exec.Command(os.Args[0]) //nolint:gosec // G204: re-executes this test binary.
	cmd.Env = []string{"CAPTURE_HELPER=" + marker}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("unknown helper: %v, want status 7: %q", err, out)
	}
	if bytes.Contains(out, []byte(marker)) {
		t.Fatalf("the helper name was echoed: %q", out)
	}
}
