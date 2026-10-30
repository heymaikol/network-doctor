//go:build linux

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// pidfd namespace ioctls, from linux/pidfd.h: _IO(PIDFS_IOCTL_MAGIC 0xFF, n).
// They return a descriptor for the process's own namespace without a /proc
// lookup, so no PID is resolved a second time. Linux 6.11 or later.
const (
	pidfdGetNetNamespace  = 0xff04
	pidfdGetUserNamespace = 0xff09
)

// Namespace owns one user and network namespace pair. It never calls unshare or
// setns on a Go thread: a holder child creates the namespaces and the
// supervisor retains descriptors to them. Methods are safe for concurrent use.
//
// Only NewNamespace builds a usable Namespace. The zero value holds descriptor 0
// in every descriptor field, which would be the process's standard input, so a
// nil or zero-value Namespace refuses Start, Identity and Close with ErrClosed
// and releases nothing.
type Namespace struct {
	made     bool       // set by the constructor alone; the descriptors below are valid only then
	mu       sync.Mutex // guards closing, closed and the descriptors
	closeMu  sync.Mutex // serializes Close, which can be retried
	closing  bool       // set once; new children are refused from then on
	closed   bool
	unclean  atomic.Bool // cleanup is incomplete: no launches, and Close must be retried
	cmu      sync.Mutex  // guards children; never held across a stop
	children map[*Child]struct{}
	sys      *sys
	holder   *exec.Cmd
	holderFD int // pidfd, closed only after the holder is reaped
	netFD    int
	userFD   int
	id       Identity
}

// testHookAfterHolderStart lets tests kill the holder before it is inspected.
var testHookAfterHolderStart func(pidfd int)

// NewNamespace starts a holder in new rootless user and network namespaces and
// retains descriptors to both. A failure releases everything it created. If that
// release is itself incomplete, NewNamespace returns the unusable Namespace
// together with the error, so the caller can still call Close to retry it.
func NewNamespace(ctx context.Context) (*Namespace, error) {
	return newNamespaceWith(ctx, realSys())
}

func newNamespaceWith(ctx context.Context, s *sys) (*Namespace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkInheritance(); err != nil {
		return nil, err
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	n := &Namespace{made: true, holderFD: -1, netFD: -1, userFD: -1, children: map[*Child]struct{}{}, sys: s}
	n.holder = exec.Command(sleep, "infinity") //nolint:gosec // G204: sleep comes from LookPath and the argument is constant.
	n.holder.Env = []string{}
	n.holder.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		Setpgid:     true,
		Pdeathsig:   syscall.SIGKILL,
		PidFD:       &n.holderFD,
	}
	if err := n.holder.Start(); err != nil {
		closeFD(&n.holderFD)
		return nil, holderStartError(err)
	}
	if n.holderFD < 0 { // kernel without CLONE_PIDFD
		return n.failed(ErrUnsupported)
	}
	if testHookAfterHolderStart != nil {
		testHookAfterHolderStart(n.holderFD)
	}
	if err := n.retain(ctx); err != nil {
		return n.failed(err)
	}
	return n, nil
}

// holderStartError classifies a failed holder start and keeps its cause. An error
// that says the host does not allow rootless user and network namespaces is
// ErrUnsupported, the one class a test or CI probe turns into a skip. Anything
// else, whether a resource limit, a failed exec or an error nobody listed, is
// ErrLaunchFailed, so a genuine failure never passes for a host that cannot run
// the suite. An errno cannot tell a refused clone from a refused exec, so a
// permission error from either reads as unsupported.
func holderStartError(err error) error {
	for _, e := range []syscall.Errno{syscall.EPERM, syscall.EACCES, syscall.EINVAL, syscall.ENOSPC, syscall.ENOSYS} {
		if errors.Is(err, e) {
			return fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	return fmt.Errorf("%w: holder start: %w", ErrLaunchFailed, err)
}

// failed releases what the constructor created. When the release is incomplete
// the caller still receives the Namespace, marked unusable, because it holds the
// only handles that can finish the job.
func (n *Namespace) failed(err error) (*Namespace, error) {
	if cerr := n.release(); cerr != nil {
		n.unclean.Store(true)
		return n, errors.Join(err, cerr)
	}
	return nil, err
}

// retain opens both namespaces through the holder's pidfd and proves they are
// distinct from the supervisor's and that the user namespace owns the network
// namespace. The check is a point in time: a child holding CAP_SYS_ADMIN in the
// user namespace can later unshare.
func (n *Namespace) retain(ctx context.Context) error {
	var err error
	if n.userFD, err = pidfdNamespace(n.holderFD, pidfdGetUserNamespace); err != nil {
		return err
	}
	if n.netFD, err = pidfdNamespace(n.holderFD, pidfdGetNetNamespace); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !isNS(n.userFD, unix.CLONE_NEWUSER) || !isNS(n.netFD, unix.CLONE_NEWNET) {
		return ErrNotIsolated
	}
	owner, err := cloexecFD(func() (int, error) { return unix.IoctlRetInt(n.netFD, unix.NS_GET_USERNS) })
	if err != nil {
		return ErrNotIsolated
	}
	defer func() { _ = unix.Close(owner) }()
	if n.id, err = identityOf(n.netFD, n.userFD); err != nil {
		return err
	}
	if o, err := identityOf(n.netFD, owner); err != nil || o.UserDev != n.id.UserDev || o.UserIno != n.id.UserIno {
		return ErrNotIsolated
	}
	self, err := selfIdentity()
	if err != nil || self.NetDev == n.id.NetDev && self.NetIno == n.id.NetIno ||
		self.UserDev == n.id.UserDev && self.UserIno == n.id.UserIno {
		return ErrNotIsolated
	}
	return nil
}

// pidfdNamespace maps ENOTTY (kernel without the ioctl) to ErrUnsupported. Any
// other failure, such as ESRCH for an exited holder, means the process is no
// longer the one the pidfd named, which is a refusal and not an unsupported host.
func pidfdNamespace(pidfd int, req uint) (int, error) {
	fd, err := cloexecFD(func() (int, error) { return unix.IoctlRetInt(pidfd, req) })
	switch {
	case err == nil:
		return fd, nil
	case errors.Is(err, unix.ENOTTY):
		return -1, ErrUnsupported
	default:
		return -1, ErrIdentityMismatch
	}
}

func isNS(fd, kind int) bool {
	got, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	return err == nil && got == kind
}

func identityOf(netFD, userFD int) (Identity, error) {
	var net, user unix.Stat_t
	if unix.Fstat(netFD, &net) != nil || unix.Fstat(userFD, &user) != nil {
		return Identity{}, ErrIdentityMismatch
	}
	return Identity{NetDev: net.Dev, NetIno: net.Ino, UserDev: user.Dev, UserIno: user.Ino}, nil
}

func selfIdentity() (Identity, error) {
	net, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = unix.Close(net) }()
	user, err := unix.Open("/proc/self/ns/user", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = unix.Close(user) }()
	return identityOf(net, user)
}

// constructed reports whether NewNamespace built n. It reads a field no method
// writes after construction, so it needs no lock.
func (n *Namespace) constructed() bool { return n != nil && n.made }

// Identity returns the retained namespace observations.
func (n *Namespace) Identity() (Identity, error) {
	if !n.constructed() {
		return Identity{}, ErrClosed
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing || n.closed || n.unclean.Load() {
		return Identity{}, ErrClosed
	}
	return n.id, nil
}

// Close stops and reaps every child, then kills and reaps the holder and
// releases every descriptor. Calls are serialized and Close can be retried: it
// returns nil once everything is released, and keeps returning nil. If any
// child or the holder cannot be shown reaped, Close returns an error wrapping
// ErrCleanupIncomplete and keeps every descriptor, the holder and the child
// handles, so the next call can finish the job. The namespace refuses new
// children from the first call on. Waiting for a process to exit is bounded, so
// a holder that does not exit makes Close return after the kill deadline, not
// block; Start and Identity wait for that long at most.
func (n *Namespace) Close() error {
	if !n.constructed() {
		return ErrClosed
	}
	n.closeMu.Lock()
	defer n.closeMu.Unlock()
	n.mu.Lock()
	n.closing = true
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()
	n.cmu.Lock()
	kids := make([]*Child, 0, len(n.children))
	for c := range n.children {
		kids = append(kids, c)
	}
	n.cmu.Unlock()
	var errs []error
	for _, c := range kids {
		if _, err := c.Stop(context.Background()); err != nil {
			errs = append(errs, err)
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(errs) == 0 { // pins are released only once every child is proven reaped
		if err := n.release(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		n.unclean.Store(true)
		return errors.Join(errs...)
	}
	n.closed = true
	return nil
}

// release kills the holder's group, reaps it once its exit is observed, then
// closes descriptors. A failure leaves the holder and every descriptor in place,
// so it can be retried.
//
// The holder is signalled, and never waited for blindly: reaping blocks until the
// process exits, so it happens only after the pidfd shows a zombie, within the
// kill deadline. A holder that is still running then, or cannot be read, is not
// reaped and not forgotten. It stays unreaped, so its PID and group ID stay
// reserved and the next attempt can signal it again.
func (n *Namespace) release() error {
	if n.holder != nil && n.holder.Process != nil {
		switch {
		case n.holderFD < 0: // no pidfd: the unreaped child is still ours by PID
			_ = n.holder.Process.Kill()
		case n.sys.probe(n.holderFD).unreaped(): // so the group ID is still ours
			_ = n.sys.killGroup(n.holder.Process.Pid, unix.SIGKILL)
		default:
			_ = n.sys.signalLeader(n.holderFD, unix.SIGKILL)
		}
		if !awaitExit(n.holderState, n.sys.killDeadline) {
			return errors.Join(ErrCleanupIncomplete, errors.New("the holder did not exit after SIGKILL"))
		}
		if _, err := n.sys.reap(n.holder.Process); err != nil {
			return errors.Join(ErrCleanupIncomplete, err)
		}
		n.holder = nil
	}
	closeFD(&n.holderFD)
	closeFD(&n.netFD)
	closeFD(&n.userFD)
	return nil
}

// holderState reads the holder without reaping it. Without a pidfd it asks about
// the PID, which is safe only because the holder is an unreaped child of ours.
func (n *Namespace) holderState() leaderState {
	if n.holderFD >= 0 {
		return n.sys.probe(n.holderFD)
	}
	var info unix.Siginfo
	return classify(unix.Waitid(unix.P_PID, n.holder.Process.Pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil), &info)
}

func closeFD(fd *int) {
	if *fd >= 0 {
		_ = unix.Close(*fd)
		*fd = -1
	}
}
