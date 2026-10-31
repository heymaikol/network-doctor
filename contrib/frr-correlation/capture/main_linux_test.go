//go:build linux

package capture

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestMain doubles as the producer program. Tests launch this binary with
// CAPTURE_HELPER set, so the processes that write, detach and probe are real.
func TestMain(m *testing.M) {
	switch os.Getenv("CAPTURE_HELPER") {
	case "":
		markInheritedCloseOnExec()
		os.Exit(m.Run())
	case "detach":
		helperDetach()
	case "hold":
		time.Sleep(time.Hour)
	case "peerwrite":
		helperPeerWrite()
	case "probe":
		helperProbe()
	case "report":
		helperReport()
	}
	os.Exit(0)
}

// markInheritedCloseOnExec keeps a leaky runner from failing the supervisor's
// descriptor check in the integration tests for a reason that is not theirs.
func markInheritedCloseOnExec() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		if fd, err := strconv.Atoi(e.Name()); err == nil && fd > 2 {
			unix.CloseOnExec(fd)
		}
	}
}

// helperDetach is a producer that writes its stream, leaves a session-leading
// descendant holding the writable descriptor, records that descendant's PID and
// exits cleanly. The leader's exit and process group say nothing about the
// descendant.
func helperDetach() {
	f, err := os.OpenFile(os.Getenv("CAPTURE_FILE"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the path is this test's own TempDir, passed through the helper environment.
	if err != nil {
		os.Exit(3)
	}
	if _, err := f.WriteString(streamBody); err != nil {
		os.Exit(4)
	}
	cmd := exec.Command(os.Args[0]) //nolint:gosec // G204: re-executes this test binary.
	cmd.Env = []string{"CAPTURE_HELPER=hold"}
	cmd.ExtraFiles = []*os.File{f}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		os.Exit(5)
	}
	if err := os.WriteFile(os.Getenv("CAPTURE_PIDFILE"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil { //nolint:gosec // G703: the path is this test's own TempDir, passed through the helper environment.
		os.Exit(6)
	}
	_ = f.Close()
	os.Exit(0)
}

// helperPeerWrite is the other producer: it replaces the file named in
// CAPTURE_FILE with forged bytes using nothing but the path it was given.
func helperPeerWrite() {
	target := os.Getenv("CAPTURE_FILE")
	tmp := target + ".forged"
	if err := os.WriteFile(tmp, []byte(forgedBody), 0o600); err != nil { //nolint:gosec // G703: the path is this test's own TempDir, passed through the helper environment.
		os.Exit(3)
	}
	if err := os.Rename(tmp, target); err != nil { //nolint:gosec // G703: as above.
		os.Exit(4)
	}
	os.Exit(0)
}

// helperProbe tries to reach the supervisor's memory and its sealed snapshot with
// the PID and descriptor number handed to it, and reports each errno. The control
// row reads its own memory, so a denial elsewhere cannot be a broken probe.
func helperProbe() {
	pid, fd := os.Getenv("SUP_PID"), os.Getenv("SUP_FD")
	var b strings.Builder
	try := func(name, path string, flags int) {
		f, err := unix.Open(path, flags|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(f)
		}
		fmt.Fprintf(&b, "%s %d\n", name, errnoOf(err))
	}
	try("visible", "/proc/"+pid+"/status", unix.O_RDONLY) // the denials below are not a missing /proc entry
	try("mem-write", "/proc/"+pid+"/mem", unix.O_RDWR)
	try("mem-read", "/proc/"+pid+"/mem", unix.O_RDONLY)
	try("snapshot-write", "/proc/"+pid+"/fd/"+fd, unix.O_RDWR)
	try("snapshot-read", "/proc/"+pid+"/fd/"+fd, unix.O_RDONLY)
	try("control-own-mem", "/proc/self/mem", unix.O_RDWR)
	p, _ := strconv.Atoi(pid)
	fmt.Fprintf(&b, "ptrace %d\n", errnoOf(unix.PtraceSeize(p)))
	_ = os.WriteFile(os.Getenv("CAPTURE_OUT"), []byte(b.String()), 0o600) //nolint:gosec // G703: the path is this test's own TempDir, passed through the helper environment.
}

// helperReport lists the descriptors above 2 that this process inherited. It
// probes by number before opening anything, because the runtime's first file
// open creates a descriptor of its own.
func helperReport() {
	var open []string
	for fd := 3; fd < 256; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			open = append(open, strconv.Itoa(fd))
		}
	}
	_ = os.WriteFile(os.Getenv("CAPTURE_OUT"), []byte("fds "+strings.Join(open, ",")+"\n"), 0o600) //nolint:gosec // G703: the path is this test's own TempDir, passed through the helper environment.
}

func errnoOf(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := err.(syscall.Errno); ok { //nolint:errorlint // unix calls return a bare Errno.
		return int(e)
	}
	return -1
}
