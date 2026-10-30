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
// descriptors beyond stdin that the child receives, and stdin is /dev/null. An
// unset Stdout or Stderr is /dev/null too, never a closed descriptor.
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
	done  chan struct{} // closed only when the leader is proven exited, still unreaped
	lost  chan struct{} // closed if the watcher failed to observe, with the exit unproven

	stopMu sync.Mutex // serializes Stop, which can be retried
	reaped bool       // the leader was reaped; status is final
	status ExitStatus
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
	if n.closing || n.closed || n.unclean.Load() {
		return nil, ErrClosed
	}
	if len(o.Argv) == 0 || !filepath.IsAbs(o.Argv[0]) {
		return nil, ErrLaunchFailed
	}
	if n.sys.probe(n.holderFD) != leaderRunning {
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
	c := &Child{ns: n, pidfd: -1, grace: o.StopGrace, done: make(chan struct{}), lost: make(chan struct{})}
	if c.grace == 0 {
		c.grace = DefaultStopGrace
	}
	c.cmd = &exec.Cmd{Path: args[0], Args: append(args, o.Argv...)}
	c.cmd.Env = append([]string{}, o.Env...)
	// A nil *os.File stored in the io.Writer fields would count as set and leave
	// that descriptor closed in the child. Unset must stay a nil interface so Go
	// connects the null device.
	if o.Stdout != nil {
		c.cmd.Stdout = o.Stdout
	}
	if o.Stderr != nil {
		c.cmd.Stderr = o.Stderr
	}
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &c.pidfd}
	if err := c.cmd.Start(); err != nil {
		return nil, ErrLaunchFailed
	}
	if c.pidfd < 0 { // kernel without CLONE_PIDFD
		_ = c.cmd.Process.Kill()
		if _, err := n.sys.reap(c.cmd.Process); err != nil {
			// Only a process that is not ours to reap fails here, and no handle
			// could help with that, so the namespace just stops accepting children.
			n.unclean.Store(true)
			return nil, errors.Join(ErrUnsupported, ErrCleanupIncomplete, err)
		}
		return nil, ErrUnsupported
	}
	c.pgid = c.cmd.Process.Pid
	// The process is the supervisor's responsibility from here. It stays
	// registered until Stop proves it reaped, so a failed cleanup is never an
	// orphan that Close cannot see.
	n.cmu.Lock()
	n.children[c] = struct{}{}
	n.cmu.Unlock()
	go c.watch()
	if err := c.verify(ctx, n.id); err != nil {
		if _, serr := c.Stop(context.Background()); serr != nil {
			err = errors.Join(err, serr)
		}
		return nil, err
	}
	return c, nil
}

// watch closes done when the leader is proven to have exited, without reaping
// it. A waitid that fails proves nothing about the child, so done stays open and
// lost is closed instead. Exactly one of the two is closed, and watch touches
// the pidfd no more after that.
func (c *Child) watch() {
	var info unix.Siginfo
	if err := c.ns.sys.waitid(c.pidfd, &info, unix.WEXITED|unix.WNOWAIT); err != nil || info.Signo == 0 {
		close(c.lost)
		return
	}
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
		case <-c.lost:
			return ErrObservationLost
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrIdentityMismatch
		default:
		}
		got, err := c.ns.sys.identity(c.pidfd)
		if err != nil {
			return c.unreadable()
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

// unreadable classifies a child whose namespaces cannot be read. A process that
// is exiting loses its namespaces a moment before it becomes a zombie, so a
// leader that still looks running gets a short, bounded chance to show its exit
// before the failure is blamed on the namespaces.
func (c *Child) unreadable() error {
	for end := time.Now().Add(c.ns.sys.exitSettle); ; time.Sleep(time.Millisecond) {
		switch c.ns.sys.probe(c.pidfd) {
		case leaderZombie, leaderGone:
			return ErrLaunchFailed
		case leaderUnknown:
			return ErrObservationLost
		}
		if !time.Now().Before(end) {
			return ErrIdentityMismatch
		}
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

// Done is closed when the supervisor has observed the child's leader exit. A
// failed observation is not an exit, so Done stays open then and Lost is closed
// instead. Done is closed at most once and never by an error.
func (c *Child) Done() <-chan struct{} { return c.done }

// Lost is closed if the supervisor could no longer observe the child, so Done may
// never close although the child has exited. Stop still works: it reads the
// pidfd itself.
func (c *Child) Lost() <-chan struct{} { return c.lost }

// PID is an observation for reading /proc while Done is open. It is never
// authentication and is meaningless after Stop returns.
func (c *Child) PID() int { return c.pgid }

// Stop terminates the child's process group with SIGTERM, escalates to SIGKILL
// after the grace period, sweeps the group once the leader has exited, and
// reaps last. The group is signalled only while the pidfd shows the leader
// unreaped. After a success Stop returns the same status on every call.
//
// Success means the leader is reaped and the sweep SIGKILL went to the group. It
// does not mean the group's other members have exited or been reaped: delivery is
// asynchronous, their reaper is init or a subreaper, and the kernel reports
// success as long as one member, the zombie leader included, accepted the signal.
// A member the supervisor may not signal is therefore not detected when another
// accepted it.
//
// If the sweep fails, or the leader cannot be shown reaped, Stop returns an error
// wrapping ErrCleanupIncomplete, marks the namespace unusable for new children,
// and keeps the pidfd and the child registered: a later Stop or Namespace.Close
// retries. A failed sweep leaves the leader unreaped on purpose, because the
// zombie is what keeps its group ID from being reissued.
func (c *Child) Stop(ctx context.Context) (ExitStatus, error) {
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	if c.reaped {
		return c.status, nil
	}
	s := c.ns.sys
	// The first two signals are requests; the sweep below repeats the SIGKILL and
	// its result is the one that decides.
	_ = c.signalGroup(unix.SIGTERM)
	if !c.waitDone(ctx, c.grace) {
		c.status.Escalated = true
		_ = c.signalGroup(unix.SIGKILL)
		if !c.waitDone(context.Background(), s.killDeadline) {
			return c.incomplete(c.unobservable())
		}
	}
	// The sweep needs the leader proven unreaped, and reaping first would make it
	// impossible, so without the proof, or without a sweep, the child is left for a
	// later attempt with its group ID still held by the zombie leader.
	if err := c.signalGroup(unix.SIGKILL); err != nil {
		return c.incomplete(err)
	}
	ps, err := s.reap(c.cmd.Process)
	if err != nil || ps == nil {
		return c.incomplete(err)
	}
	select { // the watcher ends once the child is reaped; only then is the pidfd number safe to reuse
	case <-c.done:
	case <-c.lost:
	}
	_ = unix.Close(c.pidfd)
	c.pidfd, c.reaped = -1, true
	ws := ps.Sys().(syscall.WaitStatus) // always a WaitStatus on Linux
	c.status.Code = ws.ExitStatus()
	if ws.Signaled() {
		c.status.Code, c.status.Signal = -1, ws.Signal()
	}
	c.ns.cmu.Lock()
	delete(c.ns.children, c)
	c.ns.cmu.Unlock()
	return c.status, nil
}

// signalGroup signals the child's process group, but only while the pidfd proves
// the leader is still an unreaped child, so the group ID cannot belong to anyone
// else. Otherwise it signals the leader alone through the pidfd, which can only
// ever name that process, and returns ErrObservationLost. The proof rests on the
// supervisor being the only reaper of its children.
//
// ESRCH means the group has no member, so there is nothing left to signal. EPERM
// means no member could be signalled. Both come from kill(2) and neither is a
// partial result: a signal that reached at least one member returns nil.
func (c *Child) signalGroup(sig unix.Signal) error {
	s := c.ns.sys
	if !s.probe(c.pidfd).unreaped() {
		_ = s.signalLeader(c.pidfd, sig)
		return ErrObservationLost
	}
	if err := s.killGroup(c.pgid, sig); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

// incomplete records that the leader is not proven reaped. It keeps the pidfd and
// the registry entry, and stops the namespace from launching more children.
func (c *Child) incomplete(cause error) (ExitStatus, error) {
	c.ns.unclean.Store(true)
	return c.status, errors.Join(ErrCleanupIncomplete, cause)
}

// exitPoll is how often waitDone reads the pidfd itself as well as waiting for
// the watcher, so a watcher that lost its observation cannot hide an exit.
const exitPoll = 10 * time.Millisecond

// waitDone reports whether the leader is proven exited within d: the watcher saw
// it, or the pidfd shows a zombie. A leader that is gone or cannot be read is not
// an exit. Once it is gone, no exit can ever be proven, so the wait ends at once.
func (c *Child) waitDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	poll := time.NewTicker(exitPoll)
	defer poll.Stop()
	for {
		select {
		case <-c.done:
			return true
		case <-poll.C:
			switch c.ns.sys.probe(c.pidfd) {
			case leaderZombie:
				return true
			case leaderGone:
				return false
			}
		case <-t.C:
			return c.exitSeen()
		case <-ctx.Done():
			return c.exitSeen() // a final look so a cancelled context does not hide an exit
		}
	}
}

func (c *Child) exitSeen() bool {
	select {
	case <-c.done:
		return true
	default:
		return c.ns.sys.probe(c.pidfd) == leaderZombie
	}
}

// unobservable explains a leader that never showed as exited: ErrObservationLost
// when its pidfd cannot be read as a live child, and nothing when it is simply
// still running.
func (c *Child) unobservable() error {
	if c.ns.sys.probe(c.pidfd).unreaped() {
		return nil
	}
	return ErrObservationLost
}
