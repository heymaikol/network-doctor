//go:build linux && netns_integration

package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestMain doubles as the child program: Start launches the test binary itself
// with SUPERVISOR_HELPER set, so the namespaces are exercised by a real exec.
func TestMain(m *testing.M) {
	out := os.Getenv("SUPERVISOR_OUT")
	switch os.Getenv("SUPERVISOR_HELPER") {
	case "":
		markInheritedCloseOnExec()
		os.Exit(m.Run())
	case "sleep":
		time.Sleep(time.Hour)
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		if ready := os.Getenv("SUPERVISOR_READY"); ready != "" {
			_ = os.WriteFile(ready, []byte("ready"), 0o600) //nolint:gosec // G703: the path is this test's own TempDir, passed through the helper environment.
		}
		time.Sleep(time.Hour)
	case "report":
		fds := rawInheritedFDs() // before anything else can open a descriptor
		var b strings.Builder
		for _, l := range []string{"net", "user"} {
			target, _ := os.Readlink("/proc/self/ns/" + l)
			fmt.Fprintf(&b, "%s %s\n", l, target)
		}
		status, _ := os.ReadFile("/proc/self/status")
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "CapEff:") || strings.HasPrefix(line, "NoNewPrivs:") {
				fmt.Fprintln(&b, line)
			}
		}
		fmt.Fprintf(&b, "uid %d\nfds %s\n", os.Getuid(), fds)
		_ = os.WriteFile(out, []byte(b.String()), 0o600) //nolint:gosec // G703: the path is this test's own TempDir, passed through the helper environment.
	case "supervise":
		// A supervisor that dies abruptly: it reports its holder and child, then kills itself.
		n, err := NewNamespace(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "supervise:", err)
			os.Exit(2)
		}
		self, _ := os.Executable()
		c, err := n.Start(context.Background(), Options{Argv: []string{self}, Env: []string{"SUPERVISOR_HELPER=sleep"}})
		if err != nil {
			fmt.Fprintln(os.Stderr, "supervise:", err)
			os.Exit(3)
		}
		_ = os.WriteFile(out, []byte(fmt.Sprintf("%d %d", n.holder.Process.Pid, c.PID())), 0o600) //nolint:gosec // G703: the path is this test's own TempDir, passed through the helper environment.
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		time.Sleep(time.Hour)
	case "daemonize":
		g := exec.Command(os.Args[0]) //nolint:gosec // G204: re-executes this test binary as the grandchild.
		// The grandchild ignores SIGTERM, so only the SIGKILL sweep removes it.
		g.Env = []string{"SUPERVISOR_HELPER=ignore-term", "SUPERVISOR_READY=" + out + ".ready"}
		if err := g.Start(); err != nil {
			os.Exit(2)
		}
		_ = os.WriteFile(out, []byte(strconv.Itoa(g.Process.Pid)), 0o600) //nolint:gosec // G703: the path is this test's own TempDir, passed through the helper environment.
	}
	os.Exit(0)
}

// rawInheritedFDs lists descriptors above 2 with raw syscalls, so the Go
// runtime has not yet opened any of its own.
func rawInheritedFDs() string {
	dir, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "error"
	}
	defer func() { _ = unix.Close(dir) }()
	buf := make([]byte, 4096)
	var names []string
	for {
		n, err := unix.ReadDirent(dir, buf)
		if err != nil || n == 0 {
			break
		}
		_, _, names = parseNames(buf[:n], dir, names)
	}
	return strings.Join(names, ",")
}

func parseNames(buf []byte, dir int, names []string) (int, int, []string) {
	consumed, count, parsed := unix.ParseDirent(buf, -1, nil)
	for _, name := range parsed {
		if fd, err := strconv.Atoi(name); err == nil && fd > 2 && fd != dir {
			names = append(names, name)
		}
	}
	return consumed, count, names
}

func helperOptions(t *testing.T, mode string) (Options, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	return Options{
		Argv: []string{self},
		Env:  []string{"SUPERVISOR_HELPER=" + mode, "SUPERVISOR_OUT=" + out, "SUPERVISOR_READY=" + out + ".ready"},
	}, out
}

func startHelper(t *testing.T, n *Namespace, mode string) (*Child, string) {
	t.Helper()
	o, out := helperOptions(t, mode)
	c, err := n.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("start %s: %v", mode, err)
	}
	return c, out
}

func waitFile(t *testing.T, path string) string {
	t.Helper()
	for range 500 {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 { //nolint:gosec // G304: a file in this test's own TempDir.
			return string(b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
	return ""
}

func field(report, key string) string {
	for _, l := range strings.Split(report, "\n") {
		if k, v, ok := strings.Cut(l, " "); ok && strings.TrimSuffix(k, ":") == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func TestChildRunsInTheRetainedNamespaces(t *testing.T) {
	n := newNamespace(t)
	c, out := startHelper(t, n, "report")
	report := waitFile(t, out)
	id, _ := n.Identity()
	if got, want := field(report, "net"), fmt.Sprintf("net:[%d]", id.NetIno); got != want {
		t.Fatalf("child net namespace %q, want %q", got, want)
	}
	if got, want := field(report, "user"), fmt.Sprintf("user:[%d]", id.UserIno); got != want {
		t.Fatalf("child user namespace %q, want %q", got, want)
	}
	self, _ := selfIdentity()
	if id.NetIno == self.NetIno {
		t.Fatal("child shares the supervisor's network namespace")
	}
	if field(report, "uid") != "0" {
		t.Fatalf("uid %s, want 0 inside the user namespace", field(report, "uid"))
	}
	<-c.Done() // the helper exits by itself after reporting
	st, err := c.Stop(context.Background())
	if err != nil || st.Code != 0 || st.Signal != 0 || st.Escalated {
		t.Fatalf("status %+v err %v", st, err)
	}
}

// fdProbe prints the number of every descriptor the shell holds, with no upper
// bound. The glob lists /proc/<pid>/fd, which includes the directory descriptor
// the glob itself opens; that one is closed before the loop starts, so the
// builtin test -L, an lstat of the entry, drops it. Only builtins run, so the
// shell opens nothing else and the result does not depend on which ls the host
// ships. The glob sorts as text, so callers sort the numbers.
const fdProbe = `for f in /proc/$$/fd/*; do if [ -L "$f" ]; then echo "${f##*/}"; fi; done`

func fdList(t *testing.T, out string) []int {
	t.Helper()
	var fds []int
	for _, f := range strings.Fields(out) {
		n, err := strconv.Atoi(f)
		if err != nil {
			t.Fatalf("descriptor probe printed %q", f)
		}
		fds = append(fds, n)
	}
	slices.Sort(fds)
	return fds
}

// The probe must see a descriptor far above the old ceiling of 1023, or a
// descriptor leaked to that number would pass TestChildInheritsNoDescriptors
// unseen. Go maps ExtraFiles entry i to descriptor 3+i and leaves a nil entry
// closed, so a long slice with one file at the end puts it at 1100.
func TestDescriptorProbeSeesDescriptorsAbove1023(t *testing.T) {
	const leaked = 1100
	sh := lookPath(t, "sh")
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil || lim.Cur <= leaked {
		unavailable(t, "the descriptor limit %d is too low to hold descriptor %d (%v)", lim.Cur, leaked, err)
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	extra := make([]*os.File, leaked-3+1)
	extra[leaked-3] = null
	var out bytes.Buffer
	cmd := exec.Command(sh, "-c", fdProbe) //nolint:gosec // G204: sh comes from LookPath and the script is a constant.
	cmd.ExtraFiles, cmd.Stdout = extra, &out
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if got := fdList(t, out.String()); fmt.Sprint(got) != "[0 1 2 1100]" {
		t.Fatalf("descriptor table %v, want [0 1 2 1100]", got)
	}
}

// The Go runtime holds descriptors of its own (a cgroup file and the poller),
// so inheritance is measured with a shell that never opens one: its table is
// exactly what nsenter left.
func TestChildInheritsNoDescriptors(t *testing.T) {
	n := newNamespace(t)
	sh, err := exec.LookPath("sh")
	if err != nil {
		unavailable(t, "no sh")
	}
	out, err := os.Create(filepath.Join(t.TempDir(), "fds"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	c, err := n.Start(context.Background(), Options{
		Argv:   []string{sh, "-c", fdProbe},
		Stdout: out,
	})
	if err != nil {
		t.Fatal(err)
	}
	<-c.Done()
	if _, err := c.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out.Name())
	if got := fdList(t, string(b)); fmt.Sprint(got) != "[0 1 2]" {
		t.Fatalf("child descriptor table %v, want [0 1 2]", got)
	}
}

func TestLeakedDescriptorRefusesStart(t *testing.T) {
	n := newNamespace(t)
	if checkInheritance() != nil {
		unavailable(t, "test process already holds an inheritable descriptor")
	}
	fd, err := unix.Open(os.DevNull, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	o, _ := helperOptions(t, "sleep")
	if _, err := n.Start(context.Background(), o); !errors.Is(err, ErrFDLeak) {
		t.Fatalf("got %v", err)
	}
	_ = n.Close()
	if !reaped() {
		t.Fatal("a child was launched anyway")
	}
}

func TestStopEscalatesOnlyWhenTermIsIgnored(t *testing.T) {
	n := newNamespace(t)
	c, _ := startHelper(t, n, "sleep")
	st, err := c.Stop(context.Background())
	if err != nil || st.Signal != syscall.SIGTERM || st.Escalated {
		t.Fatalf("graceful stop: %+v %v", st, err)
	}
	o, out := helperOptions(t, "ignore-term")
	o.StopGrace = 300 * time.Millisecond
	c, err = n.Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	waitFile(t, out+".ready") // the handler is installed
	begin := time.Now()
	st, err = c.Stop(context.Background())
	if err != nil || st.Signal != syscall.SIGKILL || !st.Escalated || time.Since(begin) < o.StopGrace {
		t.Fatalf("escalation: %+v %v after %v", st, err, time.Since(begin))
	}
	again, err2 := c.Stop(context.Background())
	if again != st || err2 != nil {
		t.Fatalf("second Stop changed the result: %+v %v", again, err2)
	}
}

func TestDaemonizedGrandchildDiesWithTheGroup(t *testing.T) {
	n := newNamespace(t)
	c, out := startHelper(t, n, "daemonize")
	pid, err := strconv.Atoi(waitFile(t, out))
	if err != nil {
		t.Fatal(err)
	}
	waitFile(t, out+".ready")
	<-c.Done() // the owned leader is gone and unreaped; the grandchild lives on
	if alive(pid) == false {
		t.Fatal("fixture grandchild was not running")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	for range 200 {
		if !alive(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("grandchild survived Close")
}

// alive reports whether pid is a running (not zombie) process.
// procState returns the one-letter state from /proc/<pid>/stat, or 0 when the
// PID is not in use.
func procState(pid int) byte {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) //nolint:gosec // G304: a /proc path built from a PID this test launched.
	if err != nil {
		return 0
	}
	s := string(b)
	return s[strings.LastIndex(s, ")")+2]
}

func alive(pid int) bool {
	st := procState(pid)
	return st != 0 && st != 'Z'
}

func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		unavailable(t, "no %s", name)
	}
	return p
}

// thirdNamespaceUnshare returns the unshare binary a test uses as its stand-in
// for a child that lands in a third user and network namespace. If this host
// refuses to let unshare create that pair, the test could only end in
// ErrLaunchFailed, which says nothing about the supervisor, so it ends through
// unavailable instead: a skip with the reason, or a failure in a job that must
// run the namespace tests. Where unshare can create the pair, the test runs.
func thirdNamespaceUnshare(t *testing.T) string {
	t.Helper()
	unshare, noop := lookPath(t, "unshare"), lookPath(t, "true")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, unshare, "--user", "--map-root-user", "--net", "--", noop).CombinedOutput(); err != nil { //nolint:gosec // G204: both binaries come from LookPath and the arguments are constant.
		unavailable(t, "unshare cannot create a user and network namespace here: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return unshare
}

// A child that creates its own user and network namespaces is in neither the
// supervisor's nor the retained pair, so it is refused and reaped.
func TestChildInAThirdNamespaceIsRefusedAndReaped(t *testing.T) {
	n := newNamespace(t)
	unshare, sleep := thirdNamespaceUnshare(t), lookPath(t, "sleep")
	testNsenterArgs = func(int) []string { return []string{unshare, "--user", "--map-root-user", "--net", "--"} }
	defer func() { testNsenterArgs = nil }()
	_, err := n.Start(context.Background(), Options{Argv: []string{sleep, "3600"}})
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("got %v", err)
	}
	_ = n.Close()
	if !reaped() {
		t.Fatal("refused child was not reaped")
	}
}

// A child left in the supervisor's own namespaces is never accepted. Here it
// stays running, so only the deadline stops the wait, and the child is killed
// and reaped on the way out.
func TestCancelWhileChildIsInTheSupervisorsNamespaces(t *testing.T) {
	n := newNamespace(t)
	env := lookPath(t, "env")
	testNsenterArgs = func(int) []string { return []string{env} }
	defer func() { testNsenterArgs = nil }()
	o, _ := helperOptions(t, "sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := n.Start(ctx, o); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	_ = n.Close()
	if !reaped() {
		t.Fatal("cancelled child was not reaped")
	}
}

// A child that exits before it ever reaches the retained namespaces is refused
// and reaped. It is launched without nsenter, so it is only ever in the
// supervisor's namespaces and the outcome does not depend on timing.
func TestChildThatExitsDuringStartIsRefused(t *testing.T) {
	n := newNamespace(t)
	env, truePath := lookPath(t, "env"), lookPath(t, "true")
	testNsenterArgs = func(int) []string { return []string{env} }
	defer func() { testNsenterArgs = nil }()
	if _, err := n.Start(context.Background(), Options{Argv: []string{truePath}}); !errors.Is(err, ErrLaunchFailed) {
		t.Fatalf("got %v", err)
	}
	if got := registered(n); got != 0 {
		t.Fatalf("%d children registered after the refusal", got)
	}
	_ = n.Close()
	if !reaped() {
		t.Fatal("failed child was not reaped")
	}
}

// nsenter enters the namespaces and only then execs, so a program it cannot run
// leaves a window in which the child already holds the retained pair. Start may
// refuse the child (it exited first) or return it (the identity matched first),
// and either is correct: verification is point in time. What must hold in both
// cases is that the failure is visible and nothing is left behind.
func TestChildThatFailsToExecAfterEnteringTheNamespaces(t *testing.T) {
	n := newNamespace(t)
	c, err := n.Start(context.Background(), Options{Argv: []string{"/nonexistent/frr"}})
	switch {
	case errors.Is(err, ErrLaunchFailed):
	case err == nil:
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("Done is still open for a child whose exec failed")
		}
		if st, err := c.Stop(context.Background()); err != nil || st.Code == 0 {
			t.Fatalf("Stop: %+v %v, want the nsenter failure status", st, err)
		}
	default:
		t.Fatalf("got %v", err)
	}
	_ = n.Close()
	if !reaped() {
		t.Fatal("failed child was not reaped")
	}
}

func TestRelativeProgramIsRefused(t *testing.T) {
	n := newNamespace(t)
	if _, err := n.Start(context.Background(), Options{Argv: []string{"sleep"}}); !errors.Is(err, ErrLaunchFailed) {
		t.Fatalf("got %v", err)
	}
}

func TestCloseStopsRunningChildrenAndRefusesNewOnes(t *testing.T) {
	base := openFDs(t)
	n := newNamespace(t)
	c, _ := startHelper(t, n, "sleep")
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("child still running after Close")
	}
	o, _ := helperOptions(t, "sleep")
	if _, err := n.Start(context.Background(), o); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
	if got := openFDs(t); got != base || !reaped() {
		t.Fatalf("left state: %d descriptors (base %d), reaped=%v", got, base, reaped())
	}
}

func TestConcurrentStartStopAndClose(t *testing.T) {
	base := openFDs(t)
	n := newNamespace(t)
	o, _ := helperOptions(t, "sleep")
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, err := n.Start(context.Background(), o); err == nil {
				_, _ = c.Stop(context.Background())
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); time.Sleep(20 * time.Millisecond); _ = n.Close() }()
	wg.Wait()
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if got := openFDs(t); got != base || !reaped() {
		t.Fatalf("left state: %d descriptors (base %d), reaped=%v", got, base, reaped())
	}
}

// Pdeathsig ties the holder and every child to the supervisor's lifetime. It
// fires when the creating thread exits, so this proves only the whole-process
// kill case, not a supervisor that retires one thread.
func TestSupervisorKilledTakesHolderAndChildWithIt(t *testing.T) {
	_ = newNamespace(t).Close() // skip when namespaces are unavailable
	o, out := helperOptions(t, "supervise")
	cmd := exec.Command(o.Argv[0])                     //nolint:gosec // G204: re-executes this test binary as the supervisor.
	cmd.Env = append(o.Env, "PATH="+os.Getenv("PATH")) // the helper resolves sleep and nsenter
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pids := strings.Fields(waitFile(t, out))
	if len(pids) != 2 {
		t.Fatalf("report %q", pids)
	}
	_ = cmd.Wait() // killed by its own SIGKILL
	for _, p := range pids {
		pid, _ := strconv.Atoi(p)
		for i := 0; alive(pid); i++ {
			if i > 200 {
				t.Fatalf("process %d outlived its supervisor", pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// An exited leader or holder stays a zombie, so the kernel cannot give its PID
// or process group ID to another process until the supervisor reaps it. This
// checks that hold. It does not force PID wraparound.
func TestExitedProcessesKeepTheirPIDUntilReaped(t *testing.T) {
	n := newNamespace(t)
	c, _ := startHelper(t, n, "report")
	<-c.Done()
	pid := c.PID()
	if st := procState(pid); st != 'Z' {
		t.Fatalf("exited child is in state %q, want a zombie", st)
	}
	if _, err := c.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := procState(pid); st != 0 {
		t.Fatalf("reaped child still holds its PID in state %q", st)
	}

	holder := n.holder.Process.Pid
	if err := syscall.Kill(holder, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for i := 0; n.sys.probe(n.holderFD) != leaderZombie; i++ {
		if i > 200 {
			t.Fatal("holder did not exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := procState(holder); st != 'Z' {
		t.Fatalf("exited holder is in state %q, want a zombie", st)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if st := procState(holder); st != 0 {
		t.Fatalf("closed namespace still holds the holder PID in state %q", st)
	}
}
