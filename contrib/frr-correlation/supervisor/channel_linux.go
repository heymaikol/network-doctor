//nolint:unused // ponytail: no production caller until the slice 3 launcher; drop this line then.
package supervisor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// Receive and drain on the channel parent end (contract 3.2, 3.4, A40). Every receive is non-blocking (MSG_DONTWAIT).
// The record grammar and the decision rules are in channel_parse.go.

const (
	chanDataBuf    = 1024 // payload buffer; a longer record arrives with MSG_TRUNC
	chanMaxRecords = 8    // accepted records per drain; the ninth overflows (3.4)
	chanMaxEINTR   = 8    // EINTR returns per receive or drain; the ninth overflows (3.4)
	chanMaxCalls   = 17   // recvmsg calls per receive and per drain (3.4)
)

// Receive failures. Admission reports them as CLOSE reasons. A drain reports them as ErrObservation or
// ErrProtocolViolation (drain).
var (
	errChanDeadline  = errors.New("channel receive deadline passed")
	errChanBudget    = errors.New("channel receive EINTR budget spent")
	errChanCallBound = errors.New("channel receive call ceiling reached")
	errChanPollNval  = fmt.Errorf("%w: poll reports an invalid descriptor", ErrObservation)
)

// chanKind is the outcome of one non-blocking receive.
type chanKind int

const (
	chanRecord chanKind = iota
	chanEOF
	chanAgain
	chanEINTR
	chanErr
)

// chanSys holds the system calls of the receive path. Tests replace the fields. realChanSys returns the kernel calls.
type chanSys struct {
	recvmsg func(fd int, p, oob []byte, flags int) (n, oobn, rflags int, err error)
	poll    func(fd, ms int) (int16, error)
}

func realChanSys() chanSys {
	return chanSys{recvmsg: chanRecvmsg, poll: chanPoll}
}

func chanRecvmsg(fd int, p, oob []byte, flags int) (int, int, int, error) {
	n, oobn, rflags, _, err := unix.Recvmsg(fd, p, oob, flags)
	return n, oobn, rflags, err
}

// chanPoll waits up to ms milliseconds for fd to become readable and returns the revents bits. It uses ppoll,
// because poll is absent on linux/arm64.
func chanPoll(fd, ms int) (int16, error) {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}} //nolint:gosec // G115: fd is an open descriptor, far below int32 range
	ts := unix.NsecToTimespec(int64(ms) * int64(time.Millisecond))
	if _, err := unix.Ppoll(fds, &ts, nil); err != nil {
		return 0, err
	}
	return fds[0].Revents, nil
}

// chanEnd is the parent end of one channel. ctl is the ancillary buffer size. credsOn is the SO_PASSCRED readback
// (3.2), which EOF depends on.
type chanEnd struct {
	fd      int
	ctl     int
	credsOn bool
	sys     chanSys
}

// chanRecvd is one record as the kernel delivered it. fds are the descriptors the record carried, and the caller owns
// them until it closes them. nfds keeps the count after the descriptors are closed (R6).
type chanRecvd struct {
	data  []byte
	flags int
	n     int
	fds   []int
	nfds  int
	creds *unix.Ucred
}

// facts returns what the kernel reported for r, for the decision rules. It does not own the descriptors.
func (r chanRecvd) facts() chanFacts {
	f := chanFacts{
		N:      r.n,
		Trunc:  r.flags&unix.MSG_TRUNC != 0,
		Ctrunc: r.flags&unix.MSG_CTRUNC != 0,
		NFds:   r.nfds,
	}
	if r.creds != nil {
		f.HasCreds = true
		f.CredsPid = int(r.creds.Pid)
	}
	return f
}

// recvNB reads one record without blocking. A zero-byte read is EOF only with credentials on, and with no ancillary
// data and no truncation (3.2). Otherwise it is a record.
func (e chanEnd) recvNB() (chanKind, chanRecvd, error) {
	data := make([]byte, chanDataBuf)
	oob := make([]byte, e.ctl)
	n, oobn, flags, err := e.sys.recvmsg(e.fd, data, oob, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
	switch {
	case errors.Is(err, unix.EAGAIN):
		return chanAgain, chanRecvd{}, err
	case errors.Is(err, unix.EINTR):
		return chanEINTR, chanRecvd{}, err
	case err != nil:
		return chanErr, chanRecvd{}, err
	}
	if e.credsOn && n == 0 && oobn == 0 && flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) == 0 {
		return chanEOF, chanRecvd{}, nil
	}
	r := chanRecvd{data: data[:n], flags: flags, n: n}
	r.fds, r.creds = walkChanCmsgs(oob[:oobn])
	r.nfds = len(r.fds)
	return chanRecord, r, nil
}

// walkChanCmsgs returns the descriptors and the credentials in a control buffer. It walks complete headers by hand,
// so a partial last header (MSG_CTRUNC) ends the walk and does not panic. Lengths use the native size_t (unix.SizeofPtr).
func walkChanCmsgs(oob []byte) ([]int, *unix.Ucred) {
	var fds []int
	var creds *unix.Ucred
	hdr := unix.CmsgLen(0)
	for len(oob) >= hdr {
		l := chanCmsgLen(oob)
		if l < hdr || l > len(oob) {
			break
		}
		lvl := int32(binary.NativeEndian.Uint32(oob[unix.SizeofPtr:]))   //nolint:gosec // G115: cmsg level is an int32 by ABI
		typ := int32(binary.NativeEndian.Uint32(oob[unix.SizeofPtr+4:])) //nolint:gosec // G115: cmsg type is an int32 by ABI
		body := oob[hdr:l]
		if lvl == unix.SOL_SOCKET {
			switch typ {
			case unix.SCM_RIGHTS:
				for i := 0; i+4 <= len(body); i += 4 {
					fds = append(fds, int(int32(binary.NativeEndian.Uint32(body[i:])))) //nolint:gosec // G115: SCM_RIGHTS entries are kernel fds, int32 by ABI
				}
			case unix.SCM_CREDENTIALS:
				if len(body) >= 12 {
					creds = &unix.Ucred{
						Pid: int32(binary.NativeEndian.Uint32(body[0:4])), //nolint:gosec // G115: pid_t is an int32 by ABI
						Uid: binary.NativeEndian.Uint32(body[4:8]),
						Gid: binary.NativeEndian.Uint32(body[8:12]),
					}
				}
			}
		}
		next := (l + unix.SizeofPtr - 1) &^ (unix.SizeofPtr - 1)
		if next > len(oob) {
			break
		}
		oob = oob[next:]
	}
	return fds, creds
}

// chanCmsgLen reads cmsg_len, a size_t in native byte order.
func chanCmsgLen(b []byte) int {
	if unix.SizeofPtr == 8 {
		return int(binary.NativeEndian.Uint64(b)) //nolint:gosec // G115: a cmsg_len above MaxInt wraps negative, and walkChanCmsgs breaks on l < hdr
	}
	return int(binary.NativeEndian.Uint32(b))
}

// waitReadable waits until e is readable or the deadline passes. An EINTR from the poll is retried only before the
// deadline (6.1).
func (e chanEnd) waitReadable(deadline time.Time) error {
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return errChanDeadline
		}
		rev, err := e.sys.poll(e.fd, max(int(left/time.Millisecond), 1))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if rev&unix.POLLNVAL != 0 {
			return errChanPollNval
		}
		if rev&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
			return nil
		}
	}
}

// recvOne receives one record for admission (3.2, 3.4). It polls until the deadline, then reads without blocking.
// An EAGAIN after a readable poll polls again. Each recvmsg counts toward chanMaxCalls and each EINTR toward
// chanMaxEINTR. Both budgets restart at each call of recvOne.
func (e chanEnd) recvOne(deadline time.Time) (chanKind, chanRecvd, error) {
	calls, eintr := 0, 0
	for {
		if err := e.waitReadable(deadline); err != nil {
			return chanErr, chanRecvd{}, err
		}
		if calls == chanMaxCalls {
			return chanErr, chanRecvd{}, errChanCallBound
		}
		calls++
		k, r, err := e.recvNB()
		switch k {
		case chanAgain:
			continue
		case chanEINTR:
			eintr++
			if eintr > chanMaxEINTR {
				return chanErr, chanRecvd{}, errChanBudget
			}
			continue
		default:
			return k, r, err
		}
	}
}

// chanDrainOut is the result of one drain (A40). Recs holds the accepted records. Their descriptors are closed before
// the drain returns. Each record keeps its length, flags, descriptor count and credentials.
type chanDrainOut struct {
	Recs      []chanRecvd
	EINTR     int
	Calls     int
	End       string
	Err       error
	CloexecOK bool
}

// drain reads without blocking until EAGAIN or EOF, or until an overflow or an observation error (A40). It never polls
// or sleeps. An overflow or an observation error poisons st (R6), so every later drain returns POISONED without a
// recvmsg call. Every recvmsg of the drain counts toward chanMaxCalls, including the terminal call.
func (e chanEnd) drain(st *chanState) chanDrainOut {
	o := chanDrainOut{CloexecOK: true}
	if st.poison != nil {
		o.End, o.Err = "POISONED", st.poison
		return o
	}
	for {
		if o.Calls == chanMaxCalls {
			return chanPoison(o, st, "CALL_BOUND", fmt.Errorf("%w: drain call cap without a conclusive end", ErrObservation))
		}
		o.Calls++
		k, r, err := e.recvNB()
		switch k {
		case chanEOF:
			o.End = "EOF"
			return o
		case chanAgain:
			o.End = "EAGAIN"
			return o
		case chanErr:
			return chanPoison(o, st, "ERR", fmt.Errorf("%w: %w", ErrObservation, err))
		case chanEINTR:
			if o.EINTR == chanMaxEINTR {
				return chanPoison(o, st, "OVERFLOW_EINTR", fmt.Errorf("%w: EINTR cap", ErrProtocolViolation))
			}
			o.EINTR++
		case chanRecord:
			o.CloexecOK = o.CloexecOK && chanCloexecAll(r.fds)
			chanCloseFds(r.fds)
			r.fds = nil
			if len(o.Recs) == chanMaxRecords {
				return chanPoison(o, st, "OVERFLOW_RECORD", fmt.Errorf("%w: record cap", ErrProtocolViolation))
			}
			o.Recs = append(o.Recs, r)
		}
	}
}

func chanPoison(o chanDrainOut, st *chanState, end string, err error) chanDrainOut {
	o.End, o.Err = end, err
	st.poison = err
	return o
}

// chanCloexecAll reports whether every descriptor has FD_CLOEXEC. Call it before the descriptors are closed.
func chanCloexecAll(fds []int) bool {
	for _, fd := range fds {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			return false
		}
	}
	return true
}

func chanCloseFds(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}
