//go:build linux

package supervisor

import (
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
	// killGroup signals the process group with ID pgid.
	killGroup func(pgid int, sig unix.Signal) error
	// startDeadline bounds how long a launched child may take to enter the
	// namespaces. killDeadline bounds the wait for a SIGKILLed process to exit.
	startDeadline, killDeadline time.Duration
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
		startDeadline: 5 * time.Second,
		killDeadline:  5 * time.Second,
	}
}

// exited reports whether the process behind pidfd has exited, reaped or not.
func (s *sys) exited(pidfd int) bool {
	var info unix.Siginfo
	if err := s.waitid(pidfd, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT); err != nil {
		return true
	}
	return info.Signo != 0
}
