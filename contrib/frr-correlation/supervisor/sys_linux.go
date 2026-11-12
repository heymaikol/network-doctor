//go:build linux

package supervisor

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// sys holds the kernel operations whose failure the supervisor has to survive:
// observing a process, signalling it and reaping it, plus the deadlines that
// bound its waits. Production code uses realSys. Tests replace members so each
// failure path runs deterministically, without a process the kernel really
// refuses to kill.
type sys struct {
	// waitid is waitid(P_PIDFD, pidfd, info, options) with EINTR retried.
	waitid func(pidfd int, info *unix.Siginfo, options int) error
	// reap collects the exit status of a process the supervisor started.
	reap func(p *os.Process) (*os.ProcessState, error)
	// killGroup signals the process group with ID pgid. It names a group by
	// number, so it is called only while a pidfd proves the leader unreaped.
	killGroup func(pgid int, sig unix.Signal) error
	// signalLeader signals exactly the process behind pidfd, and nothing else.
	signalLeader func(pidfd int, sig unix.Signal) error
	// identity reads the namespaces of the process behind pidfd.
	identity func(pidfd int) (Identity, error)
	// startDeadline bounds how long a launched child may take to enter the
	// namespaces. killDeadline bounds the wait for a SIGKILLed process to exit.
	// exitSettle bounds how long a leader whose namespaces cannot be read gets to
	// show that it is exiting.
	startDeadline, killDeadline, exitSettle time.Duration
}

func realSys() *sys {
	return &sys{
		waitid: func(pidfd int, info *unix.Siginfo, options int) error {
			for {
				if err := unix.Waitid(unix.P_PIDFD, pidfd, info, options, nil); err != unix.EINTR {
					return err
				}
			}
		},
		reap:          func(p *os.Process) (*os.ProcessState, error) { return p.Wait() },
		killGroup:     func(pgid int, sig unix.Signal) error { return unix.Kill(-pgid, sig) },
		signalLeader:  func(pidfd int, sig unix.Signal) error { return unix.PidfdSendSignal(pidfd, sig, nil, 0) },
		identity:      pidfdIdentity,
		startDeadline: 5 * time.Second,
		killDeadline:  5 * time.Second,
		exitSettle:    50 * time.Millisecond,
	}
}

// leaderState is what a pidfd shows about the process it names.
type leaderState int

const (
	leaderRunning leaderState = iota // still running
	leaderZombie                     // exited and unreaped: its PID and group ID are still held
	leaderGone                       // ECHILD: reaped by someone else, or never ours to wait for
	leaderUnknown                    // the observation itself failed, so nothing is known
)

// unreaped reports whether the process is proven to still be an unreaped child.
// Only then is its PID, and so its process group ID, guaranteed not to have been
// reissued.
func (l leaderState) unreaped() bool { return l == leaderRunning || l == leaderZombie }

// probe reads the state of the process behind pidfd without blocking and
// without reaping it. An error is never read as an exit.
func (s *sys) probe(pidfd int) leaderState {
	var info unix.Siginfo
	return classify(s.waitid(pidfd, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT), &info)
}

// classify reads the result of a non-blocking waitid that does not reap.
func classify(err error, info *unix.Siginfo) leaderState {
	switch {
	case errors.Is(err, unix.ECHILD):
		return leaderGone
	case err != nil:
		return leaderUnknown
	case info.Signo == 0:
		return leaderRunning
	default:
		return leaderZombie
	}
}

// awaitExit polls state every exitPoll until it shows a zombie, which is the only
// result that proves an exit. A process that is gone can never show one, so that
// ends the wait at once; anything else, an unreadable state included, is retried
// until d has passed. The decision always follows a fresh look.
func awaitExit(state func() leaderState, d time.Duration) bool {
	end := time.Now().Add(d)
	for {
		switch state() {
		case leaderZombie:
			return true
		case leaderGone:
			return false
		}
		if !time.Now().Before(end) {
			return false
		}
		time.Sleep(exitPoll)
	}
}
