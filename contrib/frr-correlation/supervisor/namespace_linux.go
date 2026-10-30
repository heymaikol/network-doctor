//go:build linux

package supervisor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
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
type Namespace struct {
	mu       sync.Mutex
	closing  bool // set once; new children are refused from then on
	closed   bool
	unclean  bool
	once     sync.Once
	closeErr error
	cmu      sync.Mutex // guards children; never held across a stop
	children map[*Child]struct{}
	holder   *exec.Cmd
	holderFD int // pidfd, closed only after the holder is reaped
	netFD    int
	userFD   int
	id       Identity
}

// testHookAfterHolderStart lets tests kill the holder before it is inspected.
var testHookAfterHolderStart func(pidfd int)

// NewNamespace starts a holder in new rootless user and network namespaces and
// retains descriptors to both. Any failure releases everything it created.
func NewNamespace(ctx context.Context) (*Namespace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkInheritance(); err != nil {
		return nil, err
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		return nil, ErrUnsupported
	}
	n := &Namespace{holderFD: -1, netFD: -1, userFD: -1, children: map[*Child]struct{}{}}
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
		return nil, ErrUnsupported
	}
	if n.holderFD < 0 { // kernel without CLONE_PIDFD
		_ = n.release()
		return nil, ErrUnsupported
	}
	if testHookAfterHolderStart != nil {
		testHookAfterHolderStart(n.holderFD)
	}
	if err := n.retain(ctx); err != nil {
		if cerr := n.release(); cerr != nil {
			return nil, errors.Join(err, cerr)
		}
		return nil, err
	}
	return n, nil
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

// Identity returns the retained namespace observations.
func (n *Namespace) Identity() (Identity, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing || n.closed || n.unclean {
		return Identity{}, ErrClosed
	}
	return n.id, nil
}

// Close stops and reaps every child, then kills and reaps the holder and
// releases every descriptor. It is safe to call concurrently and repeatedly;
// every call returns the first result. Anything that cannot be shown reaped
// keeps its pidfd, makes the namespace unusable and yields ErrCleanupIncomplete.
func (n *Namespace) Close() error {
	n.once.Do(func() {
		n.mu.Lock()
		n.closing = true
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
		if err := n.release(); err != nil {
			errs = append(errs, err)
		}
		if len(errs) > 0 {
			n.unclean = true
			n.closeErr = errors.Join(errs...)
			return
		}
		n.closed = true
	})
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closeErr
}

// release kills the holder's group, reaps it last, then closes descriptors.
func (n *Namespace) release() error {
	if n.holder != nil && n.holder.Process != nil {
		_ = unix.Kill(-n.holder.Process.Pid, unix.SIGKILL) // leader unreaped, so the pgid is still ours
		_ = n.holder.Process.Kill()
		if _, err := n.holder.Process.Wait(); err != nil {
			return ErrCleanupIncomplete
		}
		n.holder = nil
	}
	closeFD(&n.holderFD)
	closeFD(&n.netFD)
	closeFD(&n.userFD)
	return nil
}

func closeFD(fd *int) {
	if *fd >= 0 {
		_ = unix.Close(*fd)
		*fd = -1
	}
}
