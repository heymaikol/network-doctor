//go:build linux

package supervisor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// DefaultStopGrace is how long Stop waits after SIGTERM before SIGKILL.
	DefaultStopGrace = 5 * time.Second
)

// Options describes one child. Argv[0] must be an absolute path. Env is used
// as given; nothing is inherited. Stdout and Stderr, when set, are the only
// descriptors beyond stdin that the child receives, and stdin is /dev/null.
type Options struct {
	Argv           []string
	Env            []string
	Stdout, Stderr *os.File
	StopGrace      time.Duration // zero means DefaultStopGrace
}

// ExitStatus describes how a reaped child ended.
type ExitStatus struct {
	Code      int            // exit code, or -1 when killed by a signal
	Signal    syscall.Signal // terminating signal, or 0
	Escalated bool           // SIGKILL was needed after SIGTERM
}

// Child is a process the supervisor launched into the retained namespaces. It
// is identified by its pidfd and by process group membership, never by a PID
// looked up later. Its process group is signalled only while the leader is
// unreaped, so the group ID cannot belong to anyone else.
type Child struct {
	ns    *Namespace
	cmd   *exec.Cmd
	pidfd int
	pgid  int
	grace time.Duration
	done  chan struct{} // closed when the leader has exited, still unreaped

	stopMu  sync.Mutex
	stopped bool
	status  ExitStatus
	err     error
}

// testNsenterArgs lets tests launch without nsenter to model a child that lands
// in the wrong namespaces.
var testNsenterArgs func(holderPID int) []string

// Start launches Argv through nsenter against the unreaped holder, so the
// target process is the child's own PID after exec, and accepts it only after
// its own pidfd shows both retained namespaces. A child that exits, or sits in
// any other namespace, is killed, reaped and refused.
func (n *Namespace) Start(ctx context.Context, o Options) (*Child, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing || n.closed || n.unclean {
		return nil, ErrClosed
	}
	if len(o.Argv) == 0 || !filepath.IsAbs(o.Argv[0]) {
		return nil, ErrLaunchFailed
	}
	if n.sys.exited(n.holderFD) {
		return nil, ErrIdentityMismatch
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkInheritance(); err != nil {
		return nil, err
	}
	enter, err := exec.LookPath("nsenter")
	if err != nil {
		return nil, ErrUnsupported
	}
	args := []string{enter, "--target", strconv.Itoa(n.holder.Process.Pid), "--user", "--net", "--preserve-credentials", "--"}
	if testNsenterArgs != nil {
		args = testNsenterArgs(n.holder.Process.Pid)
	}
	c := &Child{ns: n, pidfd: -1, grace: o.StopGrace, done: make(chan struct{})}
	if c.grace == 0 {
		c.grace = DefaultStopGrace
	}
	c.cmd = &exec.Cmd{Path: args[0], Args: append(args, o.Argv...)}
	c.cmd.Env = append([]string{}, o.Env...)
	c.cmd.Stdout, c.cmd.Stderr = o.Stdout, o.Stderr
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &c.pidfd}
	if err := c.cmd.Start(); err != nil {
		return nil, ErrLaunchFailed
	}
	if c.pidfd < 0 { // kernel without CLONE_PIDFD
		_ = c.cmd.Process.Kill()
		_, _ = c.cmd.Process.Wait()
		return nil, ErrUnsupported
	}
	c.pgid = c.cmd.Process.Pid
	go c.watch()
	if err := c.verify(ctx, n.id); err != nil {
		if _, serr := c.Stop(context.Background()); serr != nil {
			err = errors.Join(err, serr)
		}
		return nil, err
	}
	n.cmu.Lock()
	n.children[c] = struct{}{}
	n.cmu.Unlock()
	return c, nil
}

// watch closes done when the leader exits, without reaping it.
func (c *Child) watch() {
	var info unix.Siginfo
	_ = c.ns.sys.waitid(c.pidfd, &info, unix.WEXITED|unix.WNOWAIT)
	close(c.done)
}

// verify polls the child's own pidfd until both of its namespaces are the
// retained ones. nsenter only execs after setns succeeds, so the only
// intermediate state is the supervisor's own namespaces.
func (c *Child) verify(ctx context.Context, want Identity) error {
	self, err := selfIdentity()
	if err != nil {
		return ErrIdentityMismatch
	}
	deadline := time.NewTimer(c.ns.sys.startDeadline)
	defer deadline.Stop()
	for {
		select {
		case <-c.done:
			return ErrLaunchFailed
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrIdentityMismatch
		default:
		}
		got, err := pidfdIdentity(c.pidfd)
		if err != nil {
			if c.ns.sys.exited(c.pidfd) {
				return ErrLaunchFailed
			}
			return ErrIdentityMismatch
		}
		if got == want {
			return nil
		}
		// nsenter enters the namespaces one at a time, so a component may still
		// be the supervisor's. Any component that is neither is a third namespace.
		netOK := got.NetDev == want.NetDev && got.NetIno == want.NetIno || got.NetDev == self.NetDev && got.NetIno == self.NetIno
		userOK := got.UserDev == want.UserDev && got.UserIno == want.UserIno || got.UserDev == self.UserDev && got.UserIno == self.UserIno
		if !netOK || !userOK {
			return ErrIdentityMismatch
		}
		time.Sleep(time.Millisecond)
	}
}

// pidfdIdentity reads a process's namespaces through its pidfd.
func pidfdIdentity(pidfd int) (Identity, error) {
	net, err := pidfdNamespace(pidfd, pidfdGetNetNamespace)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = unix.Close(net) }()
	user, err := pidfdNamespace(pidfd, pidfdGetUserNamespace)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = unix.Close(user) }()
	return identityOf(net, user)
}

// Done is closed when the child's leader process has exited.
func (c *Child) Done() <-chan struct{} { return c.done }

// PID is an observation for reading /proc while Done is open. It is never
// authentication and is meaningless after Stop returns.
func (c *Child) PID() int { return c.pgid }

// Stop terminates the child's process group with SIGTERM, escalates to SIGKILL
// after the grace period, sweeps the group once the leader has exited, and
// reaps last. It is idempotent: later calls return the first result. If the
// leader cannot be shown exited it is left unreaped and Stop returns
// ErrCleanupIncomplete.
func (c *Child) Stop(ctx context.Context) (ExitStatus, error) {
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	if c.stopped {
		return c.status, c.err
	}
	_ = c.ns.sys.killGroup(c.pgid, unix.SIGTERM)
	if !c.waitDone(ctx, c.grace) {
		c.status.Escalated = true
		_ = c.ns.sys.killGroup(c.pgid, unix.SIGKILL)
		if !c.waitDone(context.Background(), c.ns.sys.killDeadline) {
			c.stopped, c.err = true, ErrCleanupIncomplete
			return c.status, c.err
		}
	}
	_ = c.ns.sys.killGroup(c.pgid, unix.SIGKILL) // leader is a zombie, so the group ID is still held
	ps, werr := c.ns.sys.reap(c.cmd.Process)
	_ = unix.Close(c.pidfd)
	c.pidfd, c.stopped = -1, true
	ws, ok := ps.Sys().(syscall.WaitStatus)
	if !ok || werr != nil {
		c.err = ErrCleanupIncomplete
		return c.status, c.err
	}
	c.status.Code = ws.ExitStatus()
	if ws.Signaled() {
		c.status.Code, c.status.Signal = -1, ws.Signal()
	}
	c.ns.cmu.Lock()
	delete(c.ns.children, c)
	c.ns.cmu.Unlock()
	return c.status, nil
}

func (c *Child) waitDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-c.done:
		return true
	case <-t.C:
	case <-ctx.Done():
	}
	select { // a final look so a cancelled context does not hide an exit
	case <-c.done:
		return true
	default:
		return false
	}
}
