// Scratch harness, issue 390 contract v6.1 revision R5 (T32, T-ADM-FRAMING, channel receive and drain).
// Test only, not product code.
//
// The parent runs decision scenarios over a SOCK_SEQPACKET pair with SO_PASSCRED set. Each scenario step is
// one sender process (this binary re-executed with FRAME61_ROLE=sender). A sender stays alive until the parent
// closes its control pipe, so pidfd queries run while the sender is still alive. Pipe write ends are sent as
// fds; the parent keeps the read ends, so each read end must reach EOF once every sender has exited and the
// receiver has closed what it received.
//
// R5 receive rules (contract 3.2, A40, A50). Every receive on the channel parent end is non-blocking
// (MSG_DONTWAIT | MSG_CMSG_CLOEXEC). The only wait is poll with a deadline; poll EINTR is retried only inside
// that deadline. recvmsg EINTR has its own budget. A zero-length result is EOF only when n == 0, oobn == 0,
// no MSG_TRUNC or MSG_CTRUNC, and SO_PASSCRED reads back as 1. Any other n == 0 result is a record.
//
// amd64 layout assumed (cmsg_len is 8 bytes, little endian); the host is x86_64.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

const (
	sysPidfdOpen  = 434
	pidfdInfoSize = 88
	// _IOWR(0xFF, 11, struct pidfd_info) with sizeof(struct pidfd_info) == 88
	pidfdGetInfo = (3 << 30) | (pidfdInfoSize << 16) | (0xFF << 8) | 11
	initRec      = `{"v":1,"type":"init"}`
	prodRec      = `{"v":1,"type":"producer"}`

	dataBuf           = 1024
	admissionDeadline = 5 * time.Second
	// R5 receive budget (contract 3.2, A40). Every record counts, zero-length and truncated ones included.
	maxRecords = 8
	maxEINTR   = 8
	maxCalls   = 17

	pollIn   = 0x1
	pollErr  = 0x8
	pollHup  = 0x10
	pollNval = 0x20
)

// Control buffer sizes (bytes). With SO_PASSCRED set, SCM_CREDENTIALS also needs room.
const (
	bufV6  = 24 // v6 sizing: CMSG_SPACE(4) only. Ignores SCM_CREDENTIALS.
	buf56  = 56 // CMSG_SPACE(12) creds + CMSG_SPACE(4): one header of up to 2 fds
	bufV61 = 64 // v6.1: CMSG_SPACE(12) creds + CMSG_SPACE(16): up to 4 fds in one header
)

var errDeadline = errors.New("admission deadline")
var errBudget = errors.New("receive budget")

// errCallBound is the receive-call ceiling of receiveOne (CALL_BOUND, 3.4; R6-CALL). It is an observation error
// after admission, not a protocol violation: the ninth record and the ninth EINTR stay errBudget. recvLabel keeps
// the label "budget" for both.
var errCallBound = errors.New("receive call ceiling")
var errPollNval = errors.New("poll: invalid descriptor")

// ErrObservation is the sentinel for an unexpected observation failure (A40, 3.4). It is separate from
// ErrProtocolViolation, the sentinel for an overflow (R6).
var ErrObservation = errors.New("observation error")
var ErrProtocolViolation = errors.New("protocol violation")

// Seams. The production calls are the defaults. Only tests replace them (armSeam), and every evidence result
// reports seams_armed, which must be 0.
type recvFn func(fd int, p, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error)

var (
	recvmsgFn  recvFn                          = syscall.Recvmsg
	pollFn     func(fd, ms int) (int16, error) = pollRaw
	identFn    func(fd int) (pidfdInfo, error) = realIdent
	seamsArmed int
)

// armSeam replaces one seam and returns the restore function. Test use only.
func armSeam(recv recvFn, poll func(fd, ms int) (int16, error), ident func(fd int) (pidfdInfo, error)) func() {
	seamsArmed++
	oldRecv, oldPoll, oldIdent := recvmsgFn, pollFn, identFn
	if recv != nil {
		recvmsgFn = recv
	}
	if poll != nil {
		pollFn = poll
	}
	if ident != nil {
		identFn = ident
	}
	return func() {
		recvmsgFn, pollFn, identFn = oldRecv, oldPoll, oldIdent
		seamsArmed--
	}
}

func realIdent(fd int) (pidfdInfo, error) {
	return pidfdInfoOf(fd, 3)
}

type pidfdInfo struct {
	Mask          uint64
	Cgroupid      uint64
	Pid           uint32
	Tgid          uint32
	Ppid          uint32
	Ruid          uint32
	Rgid          uint32
	Euid          uint32
	Egid          uint32
	Suid          uint32
	Sgid          uint32
	Fsuid         uint32
	Fsgid         uint32
	ExitCode      int32
	CoredumpMask  uint32
	CoredumpSig   uint32
	CoredumpCode  uint32
	CoredumpPad   uint32
	SupportedMask uint64
}

// msg is one message one sender sends. Bytes, when set, is the exact wire payload (it can hold bytes that JSON
// text cannot, such as invalid UTF-8). Otherwise Payload is the wire payload.
type msg struct {
	Payload string   `json:"payload"`
	Bytes   []byte   `json:"bytes,omitempty"`
	Pad     int      `json:"pad,omitempty"`
	Fds     []string `json:"fds,omitempty"` // "pipe", "pidfd_self", "pidfd_child"
}

func payloadBytes(m msg) []byte {
	if m.Bytes != nil {
		return m.Bytes
	}
	return []byte(m.Payload)
}

type scenario struct {
	name     string
	passcred bool
	buf      int
	steps    [][]msg // one sender process per step, run in order
	expect   []string
}

type recvd struct {
	data     []byte
	flags    int
	n        int
	oobn     int
	fds      []int
	nfds     int // descriptors the record carried. Kept after fds are closed (R6): the count is evidence.
	parseN   int
	parseErr string
	creds    *syscall.Ucred
}

// wire is the decoded fields of one valid record (3.2 grammar).
type wire struct {
	V     int
	Type  string
	Kind  string
	Value int
}

// rec is one payload after parsing. ok: a valid record. cand: a status candidate (3.2): valid UTF-8, a JSON
// object, and exactly one member named "type" whose value is the string "status".
type rec struct {
	w    wire
	ok   bool
	cand bool
}

type state struct {
	// exit is the ExitStatus commit value (commitExit): "", "KNOWN" or "UNKNOWN". exitRecs counts the records read by
	// every drain on this handle (T2 and CL0a). committed is set by the final commit (CL0a); exit is then frozen.
	exit      string
	committed bool
	exitRecs  int
	stage     int // 0 want init, 1 want producer, 2 admitted, 3 terminal (known or unknown), 4 closed
	pidI      int
	// poison is the sticky post-admission error (R6): ErrObservation after a receive or drain observation
	// error, ErrProtocolViolation after an overflow. Once set, no read or decision on this state yields a status.
	poison error
}

// counters are per run. PollEINTR and RecvEINTR are reported separately so an absorbed interruption shows.
type counters struct {
	PollEINTR int `json:"poll_eintr"`
	RecvEINTR int `json:"recv_eintr"`
	RecvAgain int `json:"recv_again"`
	RecvCalls int `json:"recv_calls"`
}

type rrec struct {
	Decision  string `json:"decision"`
	Bytes     int    `json:"bytes"`
	Flags     string `json:"flags"`
	WalkNfds  int    `json:"walk_nfds"`
	ParseNfds int    `json:"parse_nfds"`
	ParseErr  string `json:"parse_err,omitempty"`
	CredsPid  int    `json:"creds_pid"`
	Cloexec   bool   `json:"cloexec"`
	Type      string `json:"type"`
	// Internal: kernel facts for the oracle. Not printed.
	Data     []byte `json:"-"`
	SentFds  int    `json:"-"`
	SentLen  int    `json:"-"`
	Trunc    bool   `json:"-"`
	CTrunc   bool   `json:"-"`
	InfoOK   bool   `json:"-"`
	InfoPid  uint32 `json:"-"`
	InfoPpid uint32 `json:"-"`
}

type result struct {
	Name       string   `json:"name"`
	Expect     []string `json:"expect"`
	Actual     []string `json:"actual"`
	Records    []rrec   `json:"records"`
	Pipes      int      `json:"pipe_read_ends"`
	EOF        int      `json:"pipe_read_ends_eof"`
	FdBefore   int      `json:"fd_before"`
	FdAfter    int      `json:"fd_after"`
	SenderErr  []string `json:"sender_err,omitempty"`
	Counters   counters `json:"counters"`
	CloexecOK  bool     `json:"cloexec_ok"`
	SeamsArmed int      `json:"seams_armed"`
	Pass       bool     `json:"pass"`
}

var self string

// launchFn starts one sender. Test seam for the stop tests only (stop_test.go). Default: cmd.Start.
var launchFn = func(c *exec.Cmd) error { return c.Start() }

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "frame61:", err)
		os.Exit(3)
	}
}

func pidfdOpen(pid int) (int, error) {
	fd, _, e := syscall.Syscall(sysPidfdOpen, uintptr(pid), 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

func pidfdInfoOf(fd int, mask uint64) (pidfdInfo, error) {
	info := pidfdInfo{Mask: mask}
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(pidfdGetInfo), uintptr(unsafe.Pointer(&info)))
	if e != 0 {
		return info, e
	}
	return info, nil
}

// walk returns every fd from every SCM_RIGHTS header it can walk, and the SCM_CREDENTIALS pid if present.
// It closes nothing. The caller owns the returned fds.
func walk(oob []byte) ([]int, *syscall.Ucred) {
	var fds []int
	var creds *syscall.Ucred
	for len(oob) >= 16 {
		l := int(binary.LittleEndian.Uint64(oob[0:8]))
		if l < 16 || l > len(oob) {
			break
		}
		lvl := int32(binary.LittleEndian.Uint32(oob[8:12]))
		typ := int32(binary.LittleEndian.Uint32(oob[12:16]))
		body := oob[16:l]
		if lvl == syscall.SOL_SOCKET {
			switch typ {
			case syscall.SCM_RIGHTS:
				for i := 0; i+4 <= len(body); i += 4 {
					fds = append(fds, int(int32(binary.LittleEndian.Uint32(body[i:]))))
				}
			case syscall.SCM_CREDENTIALS:
				if len(body) >= 12 {
					creds = &syscall.Ucred{
						Pid: int32(binary.LittleEndian.Uint32(body[0:4])),
						Uid: binary.LittleEndian.Uint32(body[4:8]),
						Gid: binary.LittleEndian.Uint32(body[8:12]),
					}
				}
			}
		}
		next := (l + 7) &^ 7
		if next > len(oob) {
			break
		}
		oob = oob[next:]
	}
	return fds, creds
}

func closeFds(fds []int) {
	for _, f := range fds {
		_ = syscall.Close(f)
	}
}

// cloexecAll reports whether every fd has FD_CLOEXEC (MSG_CMSG_CLOEXEC, 3.2). Call it before closing.
func cloexecAll(fds []int) bool {
	for _, f := range fds {
		flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(f), syscall.F_GETFD, 0)
		if e != 0 || flags&syscall.FD_CLOEXEC == 0 {
			return false
		}
	}
	return true
}

// pollFd mirrors struct pollfd.
type pollFd struct {
	fd      int32
	events  int16
	revents int16
}

// pollRaw polls one fd for POLLIN with a timeout in milliseconds. It returns the revents bits. It uses ppoll with a
// timespec, because SYS_POLL is absent on linux/arm64 (R6 portability). A negative timeout is clamped to 0, so the
// wait is never unbounded (waitReadable clamps to at least 1 ms).
func pollRaw(fd, ms int) (int16, error) {
	if ms < 0 {
		ms = 0
	}
	p := pollFd{fd: int32(fd), events: pollIn}
	ts := syscall.NsecToTimespec(int64(ms) * int64(time.Millisecond))
	_, _, e := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&p)), 1, uintptr(unsafe.Pointer(&ts)), 0, 0, 0)
	if e != 0 {
		return 0, e
	}
	return p.revents, nil
}

type rkind int

const (
	kRecord rkind = iota
	kEOF
	kAgain
	kEINTR
	kErr
)

// recvNB is the one receive primitive on the channel parent end. It never blocks (MSG_DONTWAIT).
// credsOn is the readback of SO_PASSCRED. EOF needs it; without it n == 0 is a record (3.2).
func recvNB(fd, ctl int, credsOn bool) (rkind, recvd, error) {
	return recvNBBuf(fd, make([]byte, dataBuf), ctl, credsOn)
}

// recvNBBuf is recvNB with a caller-sized data buffer. Tests use a zero-length buffer to produce MSG_TRUNC on
// a zero-byte read (Z8).
func recvNBBuf(fd int, data []byte, ctl int, credsOn bool) (rkind, recvd, error) {
	oob := make([]byte, ctl)
	n, oobn, flags, _, err := recvmsgFn(fd, data, oob, syscall.MSG_DONTWAIT|syscall.MSG_CMSG_CLOEXEC)
	if err != nil {
		if e, ok := err.(syscall.Errno); ok {
			switch e {
			case syscall.EAGAIN:
				return kAgain, recvd{}, e
			case syscall.EINTR:
				return kEINTR, recvd{}, e
			}
		}
		return kErr, recvd{}, err
	}
	if credsOn && n == 0 && oobn == 0 && flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) == 0 {
		return kEOF, recvd{}, nil
	}
	r := recvd{data: data[:n], flags: flags, n: n, oobn: oobn}
	r.fds, r.creds = walk(oob[:oobn])
	r.nfds = len(r.fds)
	msgs, perr := syscall.ParseSocketControlMessage(oob[:oobn])
	if perr != nil {
		r.parseErr = perr.Error()
	}
	for i := range msgs {
		if rights, err := syscall.ParseUnixRights(&msgs[i]); err == nil {
			r.parseN += len(rights)
		}
	}
	return kRecord, r, nil
}

// waitReadable waits until the fd is readable, or the deadline passes. EINTR from poll is retried only while
// the deadline has not passed (contract 6.1, Waits).
func waitReadable(fd int, deadline time.Time, c *counters) error {
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return errDeadline
		}
		ms := int(left / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		rev, err := pollFn(fd, ms)
		if err != nil {
			if err == syscall.EINTR {
				c.PollEINTR++
				continue
			}
			return err
		}
		if rev&pollNval != 0 {
			return errPollNval
		}
		if rev&(pollIn|pollHup|pollErr) != 0 {
			return nil
		}
	}
}

// receiveOne is the admission receive path for one expected record (3.2). It polls, then reads non-blocking.
// EAGAIN after a readable poll polls again. Each recvmsg call counts toward maxCalls and each EINTR toward
// maxEINTR. The ninth EINTR is errBudget. The call ceiling of maxCalls is errCallBound. Either is a failure, and
// so is the deadline (errDeadline). The budgets are per receive: they restart at every call of receiveOne (3.4).
func receiveOne(fd, ctl int, credsOn bool, deadline time.Time, c *counters) (rkind, recvd, error) {
	calls, eintr := 0, 0
	for {
		if err := waitReadable(fd, deadline, c); err != nil {
			return kErr, recvd{}, err
		}
		if calls == maxCalls {
			return kErr, recvd{}, errCallBound
		}
		calls++
		c.RecvCalls++
		k, r, err := recvNB(fd, ctl, credsOn)
		switch k {
		case kAgain:
			c.RecvAgain++
			continue
		case kEINTR:
			c.RecvEINTR++
			eintr++
			if eintr > maxEINTR {
				return kErr, recvd{}, errBudget
			}
			continue
		default:
			return k, r, err
		}
	}
}

// drainOut is the result of one drain (A40, used at T2 and CL0a). Recs holds accepted records only. Every
// descriptor of every record read is closed before the drain returns.
type drainOut struct {
	Recs      []recvd
	EINTR     int
	Calls     int
	End       string // EAGAIN, EOF, ERR, POISONED, OVERFLOW_RECORD, OVERFLOW_EINTR, CALL_BOUND
	Err       error
	CloexecOK bool
}

// drain reads without blocking until EAGAIN or EOF, or until an overflow or an observation error (A40). It never
// sleeps. An overflow or observation error poisons st (R6): every later drain on st returns POISONED without
// reading, so no later record restores Known. Records keep their metadata (nfds, flags, n, creds). Their
// descriptors are closed here and r.fds is cleared. r.nfds keeps the count. The budgets are per drain: every recvmsg
// call of this drain counts toward maxCalls (records, EINTR returns and the terminal call), and the count does not
// restart at a record. An EAGAIN ends a drain; it does not repoll (3.4).
func drain(fd, ctl int, credsOn bool, st *state) drainOut {
	o := drainOut{CloexecOK: true}
	if st.poison != nil {
		o.End, o.Err = "POISONED", st.poison
		return o
	}
	for {
		// CALL_BOUND. Unreachable while the record cap and the EINTR cap hold: at most 16 calls are non-terminal, so
		// call 17 is terminal or an overflow. Kept as a guard.
		if o.Calls == maxCalls {
			return poisonDrain(o, st, "CALL_BOUND", fmt.Errorf("%w: drain call cap without a conclusive end", ErrObservation))
		}
		o.Calls++
		k, r, err := recvNB(fd, ctl, credsOn)
		switch k {
		case kEOF:
			o.End = "EOF"
			return o
		case kAgain:
			o.End = "EAGAIN"
			return o
		case kErr:
			return poisonDrain(o, st, "ERR", fmt.Errorf("%w: %v", ErrObservation, err))
		case kEINTR:
			if o.EINTR == maxEINTR {
				return poisonDrain(o, st, "OVERFLOW_EINTR", fmt.Errorf("%w: EINTR cap", ErrProtocolViolation))
			}
			o.EINTR++
		case kRecord:
			o.CloexecOK = o.CloexecOK && cloexecAll(r.fds)
			closeFds(r.fds)
			r.fds = nil // the numbers are closed and must not be used again; r.nfds keeps the count
			if len(o.Recs) == maxRecords {
				return poisonDrain(o, st, "OVERFLOW_RECORD", fmt.Errorf("%w: record cap", ErrProtocolViolation))
			}
			o.Recs = append(o.Recs, r)
		}
	}
}

// poisonDrain ends a drain that did not conclude, and poisons st with the cause (R6).
func poisonDrain(o drainOut, st *state, end string, err error) drainOut {
	o.End, o.Err = end, err
	st.poison = err
	return o
}

// member is one name and raw value of a JSON object, in wire order.
type member struct {
	name string
	raw  json.RawMessage
}

// objectMembers returns the members of one JSON object, or false when the bytes are not exactly one object.
// Names are the decoded names (escapes are resolved). Duplicates are returned, not merged.
func objectMembers(b []byte) ([]member, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var out []member
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, ok := kt.(string)
		if !ok {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		out = append(out, member{name: name, raw: raw})
	}
	tok, err = dec.Token()
	if err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return out, true
}

func find(members []member, name string) json.RawMessage {
	for _, m := range members {
		if m.name == name {
			return m.raw
		}
	}
	return nil
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func decodeStr(raw json.RawMessage, s *string) bool {
	if raw == nil || isNull(raw) {
		return false
	}
	return json.Unmarshal(raw, s) == nil
}

// decodeInt reads a canonical integer (3.2, R6): a JSON integer token that fits Go int on the build target
// (int64 on amd64; a 32-bit build rejects values outside int32, which is not built or measured). Negative zero
// is rejected. A fraction or an exponent does not decode as an integer. Leading zeros never reach here: the object
// scanner rejects them as invalid JSON.
func decodeInt(raw json.RawMessage, n *int) bool {
	if raw == nil || isNull(raw) || bytes.Equal(bytes.TrimSpace(raw), []byte("-0")) {
		return false
	}
	var v int64
	if json.Unmarshal(raw, &v) != nil || int64(int(v)) != v {
		return false
	}
	*n = int(v)
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// parseWire applies the R5 grammar (3.2). A payload is a valid record only if it is UTF-8, is exactly one JSON
// object, has no duplicate member names (after unescaping), has only the names allowed for its type, has
// every required member with the right JSON type, and has no null members. The status candidate test is
// separate: exactly one "type" member whose value is the string "status".
func parseWire(b []byte) rec {
	var out rec
	if !utf8.Valid(b) {
		return out
	}
	members, ok := objectMembers(b)
	if !ok {
		return out
	}
	typeCount := 0
	var typeRaw json.RawMessage
	for _, m := range members {
		if m.name == "type" {
			typeCount++
			typeRaw = m.raw
		}
	}
	if typeCount == 1 {
		var s string
		if decodeStr(typeRaw, &s) && s == "status" {
			out.cand = true
		}
	}
	seen := map[string]bool{}
	for _, m := range members {
		if seen[m.name] {
			return out
		}
		seen[m.name] = true
	}
	if typeCount != 1 {
		return out
	}
	var typ string
	if !decodeStr(typeRaw, &typ) {
		return out
	}
	var allowed []string
	switch typ {
	case "init", "producer":
		allowed = []string{"v", "type"}
	case "status":
		allowed = []string{"v", "type", "kind", "value"}
	default:
		return out
	}
	if len(members) != len(allowed) {
		return out
	}
	for _, m := range members {
		if !contains(allowed, m.name) {
			return out
		}
	}
	w := wire{Type: typ}
	if !decodeInt(find(members, "v"), &w.V) {
		return out
	}
	if typ == "status" {
		if !decodeStr(find(members, "kind"), &w.Kind) || !decodeInt(find(members, "value"), &w.Value) {
			return out
		}
	}
	out.w = w
	out.ok = true
	return out
}

// statusGate is the gate for a record after admission (3.2, 3.4). It returns the close reason for a record that is
// not a clean status from the pid of I, or "" when the gate passes. decidePost and the T2 Known rule (t2Known) both
// use it, so the two cannot disagree (R6).
func statusGate(r *recvd, p rec, pidI int) string {
	switch {
	case r.flags&syscall.MSG_TRUNC != 0:
		return "trunc"
	case r.flags&syscall.MSG_CTRUNC != 0:
		return "ctrunc"
	case r.n == 0:
		return "empty"
	case !p.cand && !p.ok:
		return "malformed"
	case !p.cand:
		return "late_record"
	case r.creds == nil || int(r.creds.Pid) != pidI:
		return "creds"
	case r.nfds > 0:
		return "status_fd"
	}
	return ""
}

// decidePost applies D15 with the R5 rules to a record after admission (3.2, 3.4).
func decidePost(st *state, r *recvd, p rec) string {
	if reason := statusGate(r, p, st.pidI); reason != "" {
		st.stage = 4
		return "CLOSE:" + reason
	}
	if st.stage == 3 {
		return "UNKNOWN:after_terminal"
	}
	st.stage = 3
	if !p.ok {
		return "UNKNOWN:malformed"
	}
	if p.w.V == 1 && (p.w.Kind == "exit" || p.w.Kind == "signal") {
		return "KNOWN"
	}
	return "UNKNOWN:status_shape"
}

// decide is the admission rule (3.3) and the post-admission rule (decidePost). It returns one action per record.
func decide(st *state, r *recvd, p rec, ident func(fd int) (pidfdInfo, error)) string {
	if st.stage == 4 {
		return "DISCARD"
	}
	if st.poison != nil {
		return "UNKNOWN:observed"
	}
	if st.stage >= 2 {
		return decidePost(st, r, p)
	}
	closeWith := func(reason string) string {
		st.stage = 4
		return "CLOSE:" + reason
	}
	if r.flags&syscall.MSG_TRUNC != 0 {
		return closeWith("trunc")
	}
	if r.flags&syscall.MSG_CTRUNC != 0 {
		return closeWith("ctrunc")
	}
	if r.creds == nil {
		return closeWith("nocreds")
	}
	if r.n == 0 {
		return closeWith("empty")
	}
	if p.cand {
		return closeWith("early_status")
	}
	want := []string{"init", "producer"}[st.stage]
	if !p.ok || p.w.Type != want || p.w.V != 1 {
		return closeWith("order")
	}
	if len(r.fds) != 1 {
		return closeWith("count")
	}
	info, err := ident(r.fds[0])
	if err != nil || info.Mask&3 != 3 {
		return closeWith("pidfd_info")
	}
	if st.stage == 0 {
		if int32(info.Pid) != r.creds.Pid {
			return closeWith("creds_pidfd")
		}
		st.pidI = int(r.creds.Pid)
		st.stage = 1
		return "ACCEPT_INIT"
	}
	if int(r.creds.Pid) != st.pidI {
		return closeWith("creds")
	}
	if int(info.Ppid) != st.pidI {
		return closeWith("ppid")
	}
	st.stage = 2
	return "ACCEPT_PRODUCER"
}

// commitExit is the one ExitStatus commit rule (3.4, 6.1, 6.3, 6.4; R6 final). T2 and CL0a call it with each drain
// result on one handle, in order. final is false at T2: the value is provisional and may change. final is true at
// CL0a of the first Close, the commit point: the value it returns is stored and frozen. Every later call returns the
// frozen value unchanged, so a final UNKNOWN never becomes KNOWN and a final KNOWN never changes.
func commitExit(st *state, o drainOut, pidI int, final bool) string {
	if st.committed {
		return st.exit
	}
	v := commitDrain(st, o, pidI)
	if final {
		st.exit, st.committed = v, true
	}
	return v
}

// commitDrain is the value rule of commitExit. KNOWN needs exactly one record across all drains, a valid status that
// passes statusGate with pidI, and clean ends (EAGAIN or EOF) with no poison on the handle. A poison, a bad end or a
// bad record stores UNKNOWN on the handle, and that UNKNOWN is sticky. A clean drain with no record returns UNKNOWN
// and stores nothing: the value is provisional until the commit point. The handle's poison (st.poison) decides first,
// so a poisoned handle is UNKNOWN for good, however a later drain ends.
func commitDrain(st *state, o drainOut, pidI int) string {
	if st.exit == "UNKNOWN" {
		return "UNKNOWN"
	}
	if st.poison != nil || (o.End != "EAGAIN" && o.End != "EOF") {
		st.exit = "UNKNOWN"
		return "UNKNOWN"
	}
	for _, r := range o.Recs {
		st.exitRecs++
		p := parseWire(r.data)
		valid := p.ok && p.w.Type == "status" && p.w.V == 1 && (p.w.Kind == "exit" || p.w.Kind == "signal") && statusGate(&r, p, pidI) == ""
		if st.exitRecs != 1 || !valid {
			st.exit = "UNKNOWN"
			return "UNKNOWN"
		}
		st.exit = "KNOWN"
	}
	if st.exit == "KNOWN" {
		return "KNOWN"
	}
	return "UNKNOWN"
}

// recvLabel names a receive that ended without a record. Before admission it closes; after, it observes.
func recvLabel(k rkind, err error, stage int) string {
	reason := "recv_error"
	switch {
	case k == kEOF:
		reason = "eof"
	case err == errDeadline:
		reason = "timeout"
	case err == errBudget || err == errCallBound:
		reason = "budget"
	}
	if stage < 2 {
		return "CLOSE:" + reason
	}
	if k == kEOF {
		return "EOF"
	}
	return "OBSERVE:" + reason
}

func waitCmd(cmd *exec.Cmd, d time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("sender timeout")
	}
}

// eofWithin reports whether a pipe read end reaches EOF (no writers left) within d.
func eofWithin(fd int, d time.Duration) bool {
	_ = syscall.SetNonblock(fd, true)
	end := time.Now().Add(d)
	buf := make([]byte, 1)
	for {
		n, err := syscall.Read(fd, buf)
		if err == nil && n == 0 {
			return true
		}
		if err != syscall.EAGAIN {
			return false
		}
		if time.Now().After(end) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func countFds() int {
	e, err := os.ReadDir("/proc/self/fd")
	must(err)
	return len(e)
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sentLen is the byte count the sender puts on the wire. Go syscall.Sendmsg sends one NUL byte when the
// payload is empty and a control message is attached (syscall_linux.go sendmsgN), so an empty payload with
// fds is one byte. A payload with no fds and no bytes is zero bytes (a zero-length record).
func sentLen(m msg) int {
	n := len(payloadBytes(m))
	if m.Pad > n {
		n = m.Pad
	}
	if n == 0 && len(m.Fds) > 0 {
		n = 1
	}
	return n
}

// observe poisons st when a post-admission receive ends in an error (3.4, R6). The poison is sticky. Admission
// errors are CLOSE labels and do not poison. EOF is a clean end. The ninth record and the ninth EINTR are protocol violations
// (errBudget). The call ceiling (errCallBound, CALL_BOUND) and any other error are observation errors.
func observe(st *state, k rkind, err error) {
	if st.stage < 2 || st.poison != nil || k != kErr {
		return
	}
	if err == errBudget {
		st.poison = fmt.Errorf("%w: %v", ErrProtocolViolation, err)
		return
	}
	st.poison = fmt.Errorf("%w: %v", ErrObservation, err)
}

// runCase runs one scenario through the R5 receive path and the decision rules. It is the runner for the E10
// table, the generated differential and the seam tests.
func runCase(sc scenario) result {
	res := result{Name: sc.name, Expect: sc.expect, CloexecOK: true}
	res.FdBefore = countFds()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	must(err)
	parentEnd, childEnd := pair[0], pair[1]
	credsOn := false
	if sc.passcred {
		must(syscall.SetsockoptInt(parentEnd, syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1))
		v, err := syscall.GetsockoptInt(parentEnd, syscall.SOL_SOCKET, syscall.SO_PASSCRED)
		must(err)
		credsOn = v == 1 // readback before any launch or receive (3.2)
	}
	if !credsOn {
		// Readback failed: no sender is launched and nothing is received (3.2, 3.3 check 0).
		_ = syscall.Close(childEnd)
		_ = syscall.Close(parentEnd)
		res.Actual = []string{"CLOSE:passcred_unverified"}
		res.FdAfter = countFds()
		res.SeamsArmed = seamsArmed
		res.Pass = equal(res.Actual, sc.expect) && res.FdAfter == res.FdBefore && res.SeamsArmed == 0
		return res
	}
	deadline := time.Now().Add(admissionDeadline)

	var readEnds, ctlWriters, accepted []int
	var cmds []*exec.Cmd
	st := &state{}
	stopped := false // set when a receive ends the channel (R6); no later step is started
	for si, step := range sc.steps {
		if stopped {
			break
		}
		dup, err := syscall.Dup(childEnd)
		must(err)
		extra := []*os.File{os.NewFile(uintptr(dup), "child")}
		for _, m := range step {
			for _, k := range m.Fds {
				if k != "pipe" {
					continue
				}
				var p [2]int
				must(syscall.Pipe2(p[:], syscall.O_CLOEXEC))
				readEnds = append(readEnds, p[0])
				extra = append(extra, os.NewFile(uintptr(p[1]), "w"))
			}
		}
		var cp [2]int
		must(syscall.Pipe2(cp[:], syscall.O_CLOEXEC))
		ctlWriters = append(ctlWriters, cp[1])
		extra = append(extra, os.NewFile(uintptr(cp[0]), "ctl"))

		b, err := json.Marshal(step)
		must(err)
		cmd := exec.Command(self)
		cmd.Env = append(os.Environ(), "FRAME61_ROLE=sender", "FRAME61_MSGS="+string(b))
		cmd.ExtraFiles = extra
		must(launchFn(cmd))
		for _, f := range extra {
			_ = f.Close()
		}
		cmds = append(cmds, cmd)

		for mi, m := range step {
			k, r, rerr := receiveOne(parentEnd, sc.buf, credsOn, deadline, &res.Counters)
			if k == kErr || k == kEOF {
				observe(st, k, rerr)
				label := recvLabel(k, rerr, st.stage)
				res.Actual = append(res.Actual, label)
				res.SenderErr = append(res.SenderErr, fmt.Sprintf("step %d msg %d: receive ended: %s", si, mi, label))
				stopped = true
				break
			}
			p := parseWire(r.data)
			var info pidfdInfo
			var infoErr error
			infoCalled := false
			ident := func(fd int) (pidfdInfo, error) {
				if !infoCalled {
					info, infoErr = identFn(fd)
					infoCalled = true
				}
				return info, infoErr
			}
			act := decide(st, &r, p, ident)
			cp := 0
			if r.creds != nil {
				cp = int(r.creds.Pid)
			}
			cl := cloexecAll(r.fds)
			res.CloexecOK = res.CloexecOK && cl
			rr := rrec{
				Decision: act, Bytes: r.n, Flags: fmt.Sprintf("%#x", r.flags),
				WalkNfds: len(r.fds), ParseNfds: r.parseN, ParseErr: r.parseErr,
				CredsPid: cp, Cloexec: cl, Type: p.w.Type,
				Data: append([]byte(nil), r.data...), SentFds: len(m.Fds), SentLen: sentLen(m),
				Trunc: r.flags&syscall.MSG_TRUNC != 0, CTrunc: r.flags&syscall.MSG_CTRUNC != 0,
			}
			if infoCalled && infoErr == nil {
				rr.InfoOK = info.Mask&3 == 3
				rr.InfoPid = info.Pid
				rr.InfoPpid = info.Ppid
			}
			res.Records = append(res.Records, rr)
			res.Actual = append(res.Actual, act)
			if strings.HasPrefix(act, "ACCEPT_") {
				accepted = append(accepted, r.fds...)
			} else {
				closeFds(r.fds)
			}
			if strings.HasPrefix(act, "CLOSE:") {
				// CLOSE ends the channel (3.4, A42; R6 final). No later step, receive or status is used.
				stopped = true
				break
			}
		}
	}

	// Release every sender (control EOF), then reap them. Only now can the pipe writers go away.
	for _, w := range ctlWriters {
		_ = syscall.Close(w)
	}
	for _, cmd := range cmds {
		if err := waitCmd(cmd, 10*time.Second); err != nil {
			res.SenderErr = append(res.SenderErr, err.Error())
		}
	}
	closeFds(accepted)
	_ = syscall.Close(childEnd)
	_ = syscall.Close(parentEnd)
	res.Pipes = len(readEnds)
	for _, rd := range readEnds {
		if eofWithin(rd, time.Second) {
			res.EOF++
		}
		_ = syscall.Close(rd)
	}
	res.FdAfter = countFds()
	res.SeamsArmed = seamsArmed
	res.Pass = equal(res.Actual, sc.expect) && res.EOF == res.Pipes &&
		res.FdAfter == res.FdBefore && len(res.SenderErr) == 0 && res.CloexecOK && res.SeamsArmed == 0
	return res
}

func statusRec(kind string, value int) string {
	return fmt.Sprintf(`{"v":1,"type":"status","kind":%q,"value":%d}`, kind, value)
}

func pipes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "pipe"
	}
	return out
}

func scenarios() []scenario {
	I := func(fds ...string) msg { return msg{Payload: initRec, Fds: fds} }
	P := func(fds ...string) msg { return msg{Payload: prodRec, Fds: fds} }
	S := func(kind string, value int, fds ...string) msg { return msg{Payload: statusRec(kind, value), Fds: fds} }
	one := func(ms ...msg) [][]msg { return [][]msg{ms} }
	raw := func(payload string, fds ...string) msg { return msg{Payload: payload, Fds: fds} }
	rawb := func(b []byte, fds ...string) msg { return msg{Bytes: b, Fds: fds} }
	// Status candidate whose kind and value fail to decode (kind is a number, not a string).
	badType := `{"v":1,"type":"status","kind":5,"value":0}`
	dupType := `{"v":1,"type":"status","type":"status","kind":"exit","value":0}`
	return []scenario{
		{"full_exit", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN"}},
		{"full_signal", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("signal", 9)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN"}},
		{"init_one_fd_v6_buf24", true, bufV6, one(I("pidfd_self")),
			[]string{"CLOSE:ctrunc"}},
		{"init_one_fd_buf56", true, buf56, one(I("pidfd_self")),
			[]string{"ACCEPT_INIT"}},
		{"init_two_fds_v6_buf24", true, bufV6, one(I(pipes(2)...)),
			[]string{"CLOSE:ctrunc"}},
		{"init_two_fds_buf56", true, buf56, one(I(pipes(2)...)),
			[]string{"CLOSE:count"}},
		{"init_two_fds_buf64", true, bufV61, one(I(pipes(2)...)),
			[]string{"CLOSE:count"}},
		{"init_three_fds_buf56", true, buf56, one(I(pipes(3)...)),
			[]string{"CLOSE:ctrunc"}},
		{"init_three_fds_buf64", true, bufV61, one(I(pipes(3)...)),
			[]string{"CLOSE:count"}},
		{"init_five_fds_buf64", true, bufV61, one(I(pipes(5)...)),
			[]string{"CLOSE:ctrunc"}},
		{"init_oversize_1500", true, bufV61, one(msg{Payload: initRec, Pad: 1500, Fds: pipes(1)}),
			[]string{"CLOSE:trunc"}},
		{"init_pidfd_not_sender", true, bufV61, one(I("pidfd_child")),
			[]string{"CLOSE:creds_pidfd"}},
		{"init_no_fd", true, bufV61, one(I()),
			[]string{"CLOSE:count"}},
		{"passcred_readback_zero", false, bufV61, one(I("pidfd_self")),
			[]string{"CLOSE:passcred_unverified"}},
		{"producer_first", true, bufV61, one(P("pidfd_child")),
			[]string{"CLOSE:order"}},
		{"malformed_init", true, bufV61, one(msg{Payload: "not json", Fds: []string{"pidfd_self"}}),
			[]string{"CLOSE:order"}},
		{"status_before_producer", true, bufV61, one(I("pidfd_self"), S("exit", 0)),
			[]string{"ACCEPT_INIT", "CLOSE:early_status"}},
		// D15 class (a): CLOSE:status_fd. runCase checks the close: pipe EOF and fd count return to baseline.
		{"status_with_fd_after_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0, "pipe")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:status_fd"}},
		{"status_bad_kind", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("bogus", 0)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:status_shape"}},
		// D15 class (a): CLOSE:late_record (repeated producer record after admission).
		{"duplicate_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), P("pidfd_child")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:late_record"}},
		{"record_after_known", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), S("exit", 0)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "UNKNOWN:after_terminal"}},
		{"creds_mismatch_producer", true, bufV61,
			[][]msg{{I("pidfd_self")}, {P("pidfd_child")}},
			[]string{"ACCEPT_INIT", "CLOSE:creds"}},
		{"producer_not_child", true, bufV61, one(I("pidfd_self"), P("pidfd_self")),
			[]string{"ACCEPT_INIT", "CLOSE:ppid"}},
		// R4 (decision 8): records after a valid status, and after a malformed status or a producer.
		{"known_then_status_with_fd", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), S("exit", 0, "pipe")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:status_fd"}},
		{"known_then_status_truncated", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), msg{Payload: statusRec("exit", 0), Pad: 1500}),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:trunc"}},
		{"known_then_status_ctrunc", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), S("exit", 0, pipes(5)...)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:ctrunc"}},
		{"known_then_status_foreign_creds", true, bufV61, [][]msg{{I("pidfd_self"), P("pidfd_child"), S("exit", 0)}, {S("exit", 0)}},
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:creds"}},
		{"known_then_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), P("pidfd_child")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:late_record"}},
		{"known_then_unparseable", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), raw("not json")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:malformed"}},
		// "type_mismatch" names a wrong JSON type for a field (kind given as a number), not a wrong type member.
		{"known_then_status_type_mismatch", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), raw(badType)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "UNKNOWN:after_terminal"}},
		{"malformed_status_then_valid", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw(badType), S("exit", 0)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed", "UNKNOWN:after_terminal"}},
		{"producer_then_unparseable", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw("not json")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:malformed"}},
		{"producer_then_status_type_mismatch", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw(badType)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		// R5 rows (A50): zero-length records, strict grammar, escaped names, invalid UTF-8.
		{"init_zero_length", true, bufV61, one(raw("")),
			[]string{"CLOSE:empty"}},
		{"producer_then_zero_length", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw("")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:empty"}},
		{"known_then_zero_length", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), raw("")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:empty"}},
		{"init_escaped_type_name", true, bufV61, one(msg{Payload: `{"v":1,"type":"init"}`, Fds: []string{"pidfd_self"}}),
			[]string{"ACCEPT_INIT"}},
		{"init_duplicate_type_name", true, bufV61, one(msg{Payload: `{"v":1,"type":"init","type":"init"}`, Fds: []string{"pidfd_self"}}),
			[]string{"CLOSE:order"}},
		{"status_dup_type_after_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw(dupType)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:malformed"}},
		{"status_case_variant_after_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"TYPE":"status","kind":"exit","value":0}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:malformed"}},
		{"status_case_variant_key_candidate", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","Kind":"exit","value":0}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_missing_value_after_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","kind":"exit"}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_extra_member_after_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","kind":"exit","value":0,"x":1}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_null_value_after_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","kind":"exit","value":null}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_nested_value_after_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","kind":"exit","value":{"n":0}}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_invalid_utf8_after_producer", true, bufV61, one(I("pidfd_self"), P("pidfd_child"),
			rawb([]byte("{\"v\":1,\"type\":\"status\",\"kind\":\"exit\",\"value\":0,\"x\":\"\xff\"}"))),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:malformed"}},
		{"known_then_status_dup_type", true, bufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), raw(dupType)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:malformed"}},
	}
}

func probe() {
	fd, err := pidfdOpen(os.Getpid())
	must(err)
	defer syscall.Close(fd)
	for _, in := range []uint64{0, 3} {
		info, e := pidfdInfoOf(fd, in)
		fmt.Printf("probe mask_in=%#x errno=%d mask_out=%#x pid=%d ppid=%d\n",
			in, errnoOf(e), info.Mask, info.Pid, info.Ppid)
	}
	fmt.Printf("probe sizeof=%d ioctl=%#x\n", unsafe.Sizeof(pidfdInfo{}), uint32(pidfdGetInfo))
}

func errnoOf(err error) uintptr {
	if e, ok := err.(syscall.Errno); ok {
		return uintptr(e)
	}
	return 0
}

// sender sends its scripted messages, then stays alive until the parent closes the control pipe.
func sender() {
	var msgs []msg
	must(json.Unmarshal([]byte(os.Getenv("FRAME61_MSGS")), &msgs))
	total := 0
	for _, m := range msgs {
		for _, k := range m.Fds {
			if k == "pipe" {
				total++
			}
		}
	}
	ctlFd := 4 + total // ExtraFiles: socket (fd 3), pipes (fd 4..), control read end last
	next := 4
	var child *exec.Cmd
	defer func() {
		if child != nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	for _, m := range msgs {
		var fds, own []int
		for _, k := range m.Fds {
			switch k {
			case "pipe":
				fds = append(fds, next)
				next++
			case "pidfd_self":
				f, err := pidfdOpen(os.Getpid())
				must(err)
				fds, own = append(fds, f), append(own, f)
			case "pidfd_child":
				if child == nil {
					child = exec.Command("/usr/bin/sleep", "60")
					must(child.Start())
				}
				f, err := pidfdOpen(child.Process.Pid)
				must(err)
				fds, own = append(fds, f), append(own, f)
			default:
				must(fmt.Errorf("unknown fd kind %q", k))
			}
		}
		data := append([]byte(nil), payloadBytes(m)...)
		if m.Pad > len(data) {
			data = append(data, strings.Repeat(" ", m.Pad-len(data))...)
		}
		var oob []byte
		if len(fds) > 0 {
			oob = syscall.UnixRights(fds...)
		}
		must(syscall.Sendmsg(3, data, oob, nil, 0))
		for _, f := range own {
			_ = syscall.Close(f)
		}
	}
	buf := make([]byte, 1)
	for {
		n, err := syscall.Read(ctlFd, buf)
		if err != nil || n == 0 {
			break
		}
	}
}

func main() {
	if os.Getenv("FRAME61_ROLE") == "sender" {
		sender()
		return
	}
	var err error
	self, err = os.Executable()
	must(err)
	if int(unsafe.Sizeof(pidfdInfo{})) != pidfdInfoSize {
		must(fmt.Errorf("pidfd_info size %d, want %d", unsafe.Sizeof(pidfdInfo{}), pidfdInfoSize))
	}
	probe()
	// Warm-up: starts runtime pollers so fd baselines are stable. Result discarded.
	_ = runCase(scenario{name: "warmup", passcred: true, buf: bufV61,
		steps: [][]msg{{{Payload: initRec, Fds: []string{"pidfd_self"}}}}})
	list := scenarios()
	if want := os.Getenv("FRAME61_CASES"); want != "" {
		keep := map[string]bool{}
		for _, n := range strings.Split(want, ",") {
			keep[n] = true
		}
		var sel []scenario
		for _, sc := range list {
			if keep[sc.name] {
				sel = append(sel, sc)
			}
		}
		list = sel
	}
	pass := 0
	for _, sc := range list {
		r := runCase(sc)
		b, err := json.Marshal(r)
		must(err)
		fmt.Println(string(b))
		if r.Pass {
			pass++
		}
	}
	fmt.Printf("SUMMARY pass=%d total=%d\n", pass, len(list))
}
