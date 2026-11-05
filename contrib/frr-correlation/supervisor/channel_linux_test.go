//go:build integration

package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Real-socket tests for the channel receive path (contract 12.2: T32, T-DRAIN-UNIT, T-ADM-FRAMING). They carry the
// integration tag and use only AF_UNIX socketpairs. Every test is rootless and deterministic.

// Control buffer sizes, computed with CmsgSpace (contract A4). chanBufV6 holds one descriptor and no credentials.
// chanBuf56 and chanBufV61 hold the credentials with two and four descriptors.
var (
	chanBufV6  = unix.CmsgSpace(4)
	chanBuf56  = unix.CmsgSpace(12) + unix.CmsgSpace(8)
	chanBufV61 = unix.CmsgSpace(12) + unix.CmsgSpace(16)
)

const (
	chanInitRec = `{"v":1,"type":"init"}`
	chanProdRec = `{"v":1,"type":"producer"}`
)

func chanStatusRec(kind string, value int) string {
	return fmt.Sprintf(`{"v":1,"type":"status","kind":%q,"value":%d}`, kind, value)
}

// chanTestMsg is one message a sender process sends. Bytes, when set, is the exact payload. Pad extends the payload
// with spaces. Fds lists the descriptors the message carries. Every kind is sent as a pipe end: under the slice 1
// fake identity only the count matters, so the pidfd kinds are named as the harness names them and not inspected.
type chanTestMsg struct {
	Payload string
	Bytes   []byte
	Pad     int
	Fds     []string
}

func chanPayload(m chanTestMsg) []byte {
	if m.Bytes != nil {
		return m.Bytes
	}
	return []byte(m.Payload)
}

// chanRow is one framing row: one or more sender processes, the control buffer size, and the expected labels.
type chanRow struct {
	name     string
	passcred bool
	buf      int
	steps    [][]chanTestMsg
	expect   []string
}

// chanAdmission is the admission deadline (3.3).
const chanAdmission = 5 * time.Second

// chanFdCount counts the descriptors of this process through /proc/self/fd.
func chanFdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// chanRunRow runs one row through the production receive path and the decision rules, and returns the labels and
// any leak or sender problem. The loop is the admission order of 3.3: one sender process per step, receives in
// order, and no later step after a CLOSE.
func chanRunRow(t *testing.T, row chanRow) (actual []string, problems []string) {
	t.Helper()
	before := chanFdCount(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentEnd, childEnd := pair[0], pair[1]
	credsOn := false
	if row.passcred {
		if err := unix.SetsockoptInt(parentEnd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
			t.Fatal(err)
		}
		v, err := unix.GetsockoptInt(parentEnd, unix.SOL_SOCKET, unix.SO_PASSCRED)
		if err != nil {
			t.Fatal(err)
		}
		credsOn = v == 1
	}
	if !credsOn {
		// Readback failed: no sender is launched and nothing is received (3.2, 3.3 check 0).
		_ = unix.Close(childEnd)
		_ = unix.Close(parentEnd)
		return []string{"CLOSE:passcred_unverified"}, chanLeak(t, before)
	}

	end := chanEnd{fd: parentEnd, ctl: row.buf, credsOn: true, sys: realChanSys()}
	deadline := time.Now().Add(chanAdmission)
	st := &chanState{}
	var readEnds, ctlWriters, accepted []int
	var cmds []*exec.Cmd
	stopped := false
	for _, step := range row.steps {
		if stopped {
			break
		}
		dup, err := unix.Dup(childEnd)
		if err != nil {
			t.Fatal(err)
		}
		extra := []*os.File{os.NewFile(uintptr(dup), "child")}
		for _, m := range step {
			for range m.Fds {
				var p [2]int
				if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
					t.Fatal(err)
				}
				if err := unix.SetNonblock(p[0], true); err != nil {
					t.Fatal(err)
				}
				readEnds = append(readEnds, p[0])
				extra = append(extra, os.NewFile(uintptr(p[1]), "pipe-w"))
			}
		}
		var cp [2]int
		if err := unix.Pipe2(cp[:], unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		ctlWriters = append(ctlWriters, cp[1])
		extra = append(extra, os.NewFile(uintptr(cp[0]), "ctl"))

		b, err := json.Marshal(step)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestChanSenderHelper$")
		cmd.Env = append(os.Environ(), "CHAN_SENDER=1", "CHAN_SENDER_MSGS="+string(b))
		cmd.ExtraFiles = extra
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		for _, f := range extra {
			_ = f.Close()
		}
		cmds = append(cmds, cmd)

		for range step {
			k, r, rerr := end.recvOne(deadline)
			if k == chanErr || k == chanEOF {
				actual = append(actual, chanRecvLabel(k, rerr))
				stopped = true
				break
			}
			cred := 0
			if r.creds != nil {
				cred = int(r.creds.Pid)
			}
			ident := chanFakeIdent(func(int) (int, int, error) { return cred, st.pidI, nil })
			act := chanDecide(st, r.facts(), parseChanRecord(r.data), r.fds, ident)
			if !chanCloexecAll(r.fds) {
				problems = append(problems, "descriptor without FD_CLOEXEC")
			}
			actual = append(actual, act)
			if strings.HasPrefix(act, "ACCEPT_") {
				accepted = append(accepted, r.fds...)
			} else {
				chanCloseFds(r.fds)
			}
			if strings.HasPrefix(act, "CLOSE:") {
				stopped = true
				break
			}
		}
	}

	// Release the senders (control EOF), then reap them. Only then do the pipe writers in the senders go away.
	for _, w := range ctlWriters {
		_ = unix.Close(w)
	}
	for i, cmd := range cmds {
		if err := chanWaitSender(cmd, 10*time.Second); err != nil {
			problems = append(problems, fmt.Sprintf("sender %d: %v", i, err))
		}
	}
	chanCloseFds(accepted)
	_ = unix.Close(childEnd)
	_ = unix.Close(parentEnd)
	eof := 0
	for _, rd := range readEnds {
		if chanReadEOF(rd) {
			eof++
		}
		_ = unix.Close(rd)
	}
	if eof != len(readEnds) {
		problems = append(problems, fmt.Sprintf("%d of %d pipe ends not at EOF", len(readEnds)-eof, len(readEnds)))
	}
	return actual, append(problems, chanLeak(t, before)...)
}

func chanLeak(t *testing.T, before int) []string {
	if n := chanFdCount(t) - before; n != 0 {
		return []string{fmt.Sprintf("descriptor count changed by %d", n)}
	}
	return nil
}

// chanRecvLabel names the close reason of an admission receive that ended the channel.
func chanRecvLabel(k chanKind, err error) string {
	switch {
	case k == chanEOF:
		return "CLOSE:eof"
	case errors.Is(err, errChanDeadline):
		return "CLOSE:timeout"
	case errors.Is(err, errChanBudget), errors.Is(err, errChanCallBound):
		return "CLOSE:budget"
	}
	return "CLOSE:recv_error"
}

// chanFakeIdent is the test identity. It answers for the record's own sender: the pid is the record's pid, and the
// ppid is the admitted init pid. The real identity (PIDFD_GET_INFO) is slice 2 and is not tested here.
type chanFakeIdent func(fd int) (pid, ppid int, err error)

func (f chanFakeIdent) pidInfo(fd int) (int, int, error) { return f(fd) }

func chanWaitSender(cmd *exec.Cmd, d time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("still running after %v", d)
	}
}

// chanReadEOF reports whether a nonblocking pipe read end is at EOF: no writer is left and nothing is buffered.
func chanReadEOF(rd int) bool {
	buf := make([]byte, 1)
	n, err := unix.Read(rd, buf)
	return n == 0 && err == nil
}

// TestChanSenderHelper is the sender process of the framing rows. It runs only with CHAN_SENDER=1 (the helper
// subprocess pattern of AGENTS.md). It sends its messages on fd 3, then waits until the control pipe closes.
func TestChanSenderHelper(t *testing.T) {
	if os.Getenv("CHAN_SENDER") != "1" {
		t.Skip("helper process only")
	}
	var msgs []chanTestMsg
	if err := json.Unmarshal([]byte(os.Getenv("CHAN_SENDER_MSGS")), &msgs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	total := 0
	for _, m := range msgs {
		total += len(m.Fds)
	}
	ctl := 4 + total // ExtraFiles: socket on fd 3, pipe writers on 4 onward, control read end last
	next := 4
	for _, m := range msgs {
		var fds []int
		for range m.Fds {
			fds = append(fds, next)
			next++
		}
		data := append([]byte(nil), chanPayload(m)...)
		if m.Pad > len(data) {
			data = append(data, strings.Repeat(" ", m.Pad-len(data))...)
		}
		var oob []byte
		if len(fds) > 0 {
			oob = unix.UnixRights(fds...)
		}
		if err := unix.Sendmsg(3, data, oob, nil, 0); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	buf := make([]byte, 1)
	for {
		n, err := unix.Read(ctl, buf)
		if err != nil || n == 0 {
			break
		}
	}
}

// chanFramingRows is the set of T-ADM-FRAMING rows (E10-R6, 47 rows). Two rows are not production rows of slice 1:
// init_pidfd_not_sender and producer_not_child check the real pidfd identity and move to slice 6.
func chanFramingRows() []chanRow {
	I := func(fds ...string) chanTestMsg { return chanTestMsg{Payload: chanInitRec, Fds: fds} }
	P := func(fds ...string) chanTestMsg { return chanTestMsg{Payload: chanProdRec, Fds: fds} }
	S := func(kind string, value int, fds ...string) chanTestMsg {
		return chanTestMsg{Payload: chanStatusRec(kind, value), Fds: fds}
	}
	raw := func(payload string, fds ...string) chanTestMsg { return chanTestMsg{Payload: payload, Fds: fds} }
	rawb := func(b []byte, fds ...string) chanTestMsg { return chanTestMsg{Bytes: b, Fds: fds} }
	one := func(ms ...chanTestMsg) [][]chanTestMsg { return [][]chanTestMsg{ms} }
	pipes := func(n int) []string { return slices.Repeat([]string{"pipe"}, n) }
	badType := `{"v":1,"type":"status","kind":5,"value":0}`
	dupType := `{"v":1,"type":"status","type":"status","kind":"exit","value":0}`
	return []chanRow{
		{"full_exit", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN"}},
		{"full_signal", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("signal", 9)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN"}},
		{"init_one_fd_v6_buf24", true, chanBufV6, one(I("pidfd_self")),
			[]string{"CLOSE:ctrunc"}},
		{"init_one_fd_buf56", true, chanBuf56, one(I("pidfd_self")),
			[]string{"ACCEPT_INIT"}},
		{"init_two_fds_v6_buf24", true, chanBufV6, one(I(pipes(2)...)),
			[]string{"CLOSE:ctrunc"}},
		{"init_two_fds_buf56", true, chanBuf56, one(I(pipes(2)...)),
			[]string{"CLOSE:count"}},
		{"init_two_fds_buf64", true, chanBufV61, one(I(pipes(2)...)),
			[]string{"CLOSE:count"}},
		{"init_three_fds_buf56", true, chanBuf56, one(I(pipes(3)...)),
			[]string{"CLOSE:ctrunc"}},
		{"init_three_fds_buf64", true, chanBufV61, one(I(pipes(3)...)),
			[]string{"CLOSE:count"}},
		{"init_five_fds_buf64", true, chanBufV61, one(I(pipes(5)...)),
			[]string{"CLOSE:ctrunc"}},
		{"init_oversize_1500", true, chanBufV61, one(chanTestMsg{Payload: chanInitRec, Pad: 1500, Fds: pipes(1)}),
			[]string{"CLOSE:trunc"}},
		{"init_no_fd", true, chanBufV61, one(I()),
			[]string{"CLOSE:count"}},
		{"passcred_readback_zero", false, chanBufV61, one(I("pidfd_self")),
			[]string{"CLOSE:passcred_unverified"}},
		{"producer_first", true, chanBufV61, one(P("pidfd_child")),
			[]string{"CLOSE:order"}},
		{"malformed_init", true, chanBufV61, one(chanTestMsg{Payload: "not json", Fds: []string{"pidfd_self"}}),
			[]string{"CLOSE:order"}},
		{"status_before_producer", true, chanBufV61, one(I("pidfd_self"), S("exit", 0)),
			[]string{"ACCEPT_INIT", "CLOSE:early_status"}},
		{"status_with_fd_after_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0, "pipe")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:status_fd"}},
		{"status_bad_kind", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("bogus", 0)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:status_shape"}},
		{"duplicate_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), P("pidfd_child")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:late_record"}},
		{"record_after_known", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), S("exit", 0)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "UNKNOWN:after_terminal"}},
		{"creds_mismatch_producer", true, chanBufV61,
			[][]chanTestMsg{{I("pidfd_self")}, {P("pidfd_child")}},
			[]string{"ACCEPT_INIT", "CLOSE:creds"}},
		{"known_then_status_with_fd", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), S("exit", 0, "pipe")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:status_fd"}},
		{"known_then_status_truncated", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), chanTestMsg{Payload: chanStatusRec("exit", 0), Pad: 1500}),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:trunc"}},
		{"known_then_status_ctrunc", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), S("exit", 0, pipes(5)...)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:ctrunc"}},
		{"known_then_status_foreign_creds", true, chanBufV61, [][]chanTestMsg{{I("pidfd_self"), P("pidfd_child"), S("exit", 0)}, {S("exit", 0)}},
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:creds"}},
		{"known_then_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), P("pidfd_child")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:late_record"}},
		{"known_then_unparseable", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), raw("not json")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:malformed"}},
		{"known_then_status_type_mismatch", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), raw(badType)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "UNKNOWN:after_terminal"}},
		{"malformed_status_then_valid", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw(badType), S("exit", 0)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed", "UNKNOWN:after_terminal"}},
		{"producer_then_unparseable", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw("not json")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:malformed"}},
		{"producer_then_status_type_mismatch", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw(badType)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"init_zero_length", true, chanBufV61, one(raw("")),
			[]string{"CLOSE:empty"}},
		{"producer_then_zero_length", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw("")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:empty"}},
		{"known_then_zero_length", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), raw("")),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:empty"}},
		{"init_escaped_type_name", true, chanBufV61, one(chanTestMsg{Payload: `{"v":1,"type":"init"}`, Fds: []string{"pidfd_self"}}),
			[]string{"ACCEPT_INIT"}},
		{"init_duplicate_type_name", true, chanBufV61, one(chanTestMsg{Payload: `{"v":1,"type":"init","type":"init"}`, Fds: []string{"pidfd_self"}}),
			[]string{"CLOSE:order"}},
		{"status_dup_type_after_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw(dupType)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:malformed"}},
		{"status_case_variant_after_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"TYPE":"status","kind":"exit","value":0}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:malformed"}},
		{"status_case_variant_key_candidate", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","Kind":"exit","value":0}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_missing_value_after_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","kind":"exit"}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_extra_member_after_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","kind":"exit","value":0,"x":1}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_null_value_after_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","kind":"exit","value":null}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_nested_value_after_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), raw(`{"v":1,"type":"status","kind":"exit","value":{"n":0}}`)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "UNKNOWN:malformed"}},
		{"status_invalid_utf8_after_producer", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"),
			rawb([]byte("{\"v\":1,\"type\":\"status\",\"kind\":\"exit\",\"value\":0,\"x\":\"\xff\"}"))),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "CLOSE:malformed"}},
		{"known_then_status_dup_type", true, chanBufV61, one(I("pidfd_self"), P("pidfd_child"), S("exit", 0), raw(dupType)),
			[]string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN", "CLOSE:malformed"}},
	}
}

// TestChannelFramingRows runs the 45 production framing rows. Each row runs once.
func TestChannelFramingRows(t *testing.T) {
	rows := chanFramingRows()
	if len(rows) != 45 {
		t.Fatalf("framing rows: got %d, want 45", len(rows))
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			actual, problems := chanRunRow(t, row)
			if !slices.Equal(actual, row.expect) {
				t.Errorf("labels %v, want %v", actual, row.expect)
			}
			for _, p := range problems {
				t.Errorf("%s", p)
			}
		})
	}
}

// TestChannelRejectsWrongDescriptorCount is T32: a production init receive with 0 to 5 descriptors at both control
// buffer sizes. Each cell has one expected label. Only one descriptor is accepted (3.3 check 1).
func TestChannelRejectsWrongDescriptorCount(t *testing.T) {
	// want[n] is the label for n descriptors. The control buffer size decides between CLOSE:count and CLOSE:ctrunc.
	sizes := []struct {
		name string
		size int
		want [6]string
	}{
		{"buf56", chanBuf56, [6]string{"CLOSE:count", "ACCEPT_INIT", "CLOSE:count", "CLOSE:ctrunc", "CLOSE:ctrunc", "CLOSE:ctrunc"}},
		{"bufV61", chanBufV61, [6]string{"CLOSE:count", "ACCEPT_INIT", "CLOSE:count", "CLOSE:count", "CLOSE:count", "CLOSE:ctrunc"}},
	}
	for _, sz := range sizes {
		for n := 0; n <= 5; n++ {
			row := chanRow{
				name:     fmt.Sprintf("%s_%d_fds", sz.name, n),
				passcred: true,
				buf:      sz.size,
				steps:    [][]chanTestMsg{{{Payload: chanInitRec, Fds: slices.Repeat([]string{"pipe"}, n)}}},
				expect:   []string{sz.want[n]},
			}
			t.Run(row.name, func(t *testing.T) {
				actual, problems := chanRunRow(t, row)
				if !slices.Equal(actual, row.expect) {
					t.Errorf("labels %v, want %v", actual, row.expect)
				}
				for _, p := range problems {
					t.Errorf("%s", p)
				}
			})
		}
	}
}

// chanSocketPair returns an AF_UNIX SOCK_SEQPACKET socketpair. The parent end has SO_PASSCRED set when passcred is
// true. The caller closes both ends.
func chanSocketPair(t *testing.T, passcred bool) (parent, child int) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if passcred {
		if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
			t.Fatal(err)
		}
	}
	return pair[0], pair[1]
}

func chanClose(fds ...int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}

// chanSend sends one message from fd. The kernel attaches the sender's credentials when the receiver has
// SO_PASSCRED set.
func chanSend(t *testing.T, fd int, payload []byte, fds ...int) {
	t.Helper()
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	if err := unix.Sendmsg(fd, payload, oob, nil, 0); err != nil {
		t.Fatal(err)
	}
}

// chanPipe returns a pipe for descriptor tests. The read end is nonblocking, so chanReadEOF can run without a wait.
func chanPipe(t *testing.T) (rd, wr int) {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(p[0], true); err != nil {
		t.Fatal(err)
	}
	return p[0], p[1]
}

// chanScripted returns a recvmsg seam that answers each call with the next entry. A nil entry calls the kernel, and
// the test fails on any call beyond the script.
func chanScripted(t *testing.T, seq ...error) func(int, []byte, []byte, int) (int, int, int, error) {
	i := 0
	return func(fd int, p, oob []byte, flags int) (int, int, int, error) {
		if i >= len(seq) {
			t.Fatalf("recvmsg called %d times, script has %d", i+1, len(seq))
		}
		err := seq[i]
		i++
		if err == nil {
			return chanRecvmsg(fd, p, oob, flags)
		}
		return 0, 0, 0, err
	}
}

// chanCounted wraps the real recvmsg and counts the calls.
type chanCounted struct{ calls int }

func (c *chanCounted) recvmsg(fd int, p, oob []byte, flags int) (int, int, int, error) {
	c.calls++
	return chanRecvmsg(fd, p, oob, flags)
}

// chanDecideRec decides one record received by a drain, with no identity call.
func chanDecideRec(st *chanState, r chanRecvd) string {
	return chanDecide(st, r.facts(), parseChanRecord(r.data), r.fds, nil)
}

func chanStatus(value int) string { return chanStatusRec("exit", value) }

// TestChannelDrainCapAndOverflow is T-DRAIN-UNIT: the drain cases of 12.2 on real socketpairs. Case (l), the POLLNVAL
// readiness case, is in T-T2-POLL, not here. Cases (e), (f), (k), (o) and (p) replace the recvmsg call with a seam, so
// no signal is needed. Admitted state is set in every case that needs it, so the decision rules run on the drained
// records.
func TestChannelDrainCapAndOverflow(t *testing.T) {
	self := os.Getpid()
	admitted := func() *chanState { return &chanState{stage: 2, pidI: self} }

	t.Run("a_eight_records_then_eagain", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		for range chanMaxRecords {
			chanSend(t, child, []byte("r"))
		}
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: realChanSys()}
		o := end.drain(&chanState{})
		if o.End != "EAGAIN" || o.Err != nil || len(o.Recs) != 8 || o.Calls != 9 {
			t.Fatalf("End %s err %v recs %d calls %d, want EAGAIN clean with 8 records and 9 calls",
				o.End, o.Err, len(o.Recs), o.Calls)
		}
	})

	t.Run("b_nine_records_overflow", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		for range chanMaxRecords + 1 {
			chanSend(t, child, []byte(chanStatus(0)))
		}
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: realChanSys()}
		st := admitted()
		o := end.drain(st)
		if o.End != "OVERFLOW_RECORD" || len(o.Recs) != 8 || !errors.Is(o.Err, ErrProtocolViolation) {
			t.Fatalf("End %s recs %d err %v, want OVERFLOW_RECORD with 8 records and ErrProtocolViolation",
				o.End, len(o.Recs), o.Err)
		}
		if got := chanDecideRec(st, o.Recs[0]); got != "UNKNOWN:observed" {
			t.Fatalf("status after overflow decided %q, want UNKNOWN:observed", got)
		}
	})

	t.Run("c_empty_queue_eagain_without_poll", func(t *testing.T) {
		for run := range 5 {
			parent, child := chanSocketPair(t, true)
			sys := realChanSys()
			sys.poll = func(int, int) (int16, error) {
				t.Fatalf("run %d: drain called poll", run)
				return 0, nil
			}
			end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: sys}
			o := end.drain(&chanState{})
			chanClose(parent, child)
			if o.End != "EAGAIN" || o.Err != nil || len(o.Recs) != 0 || o.Calls != 1 {
				t.Fatalf("run %d: End %s err %v recs %d calls %d, want EAGAIN at the first call",
					run, o.End, o.Err, len(o.Recs), o.Calls)
			}
		}
	})

	t.Run("d_eof_is_clean", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent)
		chanClose(child)
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: realChanSys()}
		o := end.drain(&chanState{})
		if o.End != "EOF" || o.Err != nil || len(o.Recs) != 0 {
			t.Fatalf("End %s err %v recs %d, want clean EOF", o.End, o.Err, len(o.Recs))
		}
	})

	t.Run("e_eight_eintr_then_eagain_is_clean", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		seq := slices.Concat(slices.Repeat([]error{unix.EINTR}, chanMaxEINTR), []error{unix.EAGAIN})
		sys := realChanSys()
		sys.recvmsg = chanScripted(t, seq...)
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: sys}
		o := end.drain(&chanState{})
		if o.End != "EAGAIN" || o.Err != nil || o.EINTR != 8 || o.Calls != 9 {
			t.Fatalf("End %s err %v eintr %d calls %d, want clean EAGAIN after 8 EINTR", o.End, o.Err, o.EINTR, o.Calls)
		}
	})

	t.Run("f_nine_eintr_overflow", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		sys := realChanSys()
		sys.recvmsg = chanScripted(t, slices.Repeat([]error{unix.EINTR}, chanMaxEINTR+1)...)
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: sys}
		o := end.drain(&chanState{})
		if o.End != "OVERFLOW_EINTR" || !errors.Is(o.Err, ErrProtocolViolation) {
			t.Fatalf("End %s err %v, want OVERFLOW_EINTR and ErrProtocolViolation", o.End, o.Err)
		}
	})

	t.Run("g_received_descriptors_closed_at_once", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		rd, wr := chanPipe(t)
		defer chanClose(rd)
		chanSend(t, child, []byte(chanStatus(0)), wr)
		chanClose(wr)
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: realChanSys()}
		o := end.drain(&chanState{})
		if o.End != "EAGAIN" || len(o.Recs) != 1 || o.Recs[0].nfds != 1 || o.Recs[0].fds != nil || !o.CloexecOK {
			t.Fatalf("End %s recs %d cloexec %v, want one record with a count of 1, no descriptors kept, and FD_CLOEXEC", o.End, len(o.Recs), o.CloexecOK)
		}
		if !chanReadEOF(rd) {
			t.Fatal("the received pipe writer is still open after the drain")
		}
	})

	t.Run("h_zero_length_with_creds_is_a_record", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		chanSend(t, child, nil)
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: realChanSys()}
		o := end.drain(&chanState{})
		if o.End != "EAGAIN" || len(o.Recs) != 1 || o.Recs[0].n != 0 {
			t.Fatalf("End %s recs %d, want one zero-length record and EAGAIN", o.End, len(o.Recs))
		}
		if got := chanDecideRec(&chanState{}, o.Recs[0]); got != "CLOSE:empty" {
			t.Fatalf("decided %q, want CLOSE:empty", got)
		}
	})

	t.Run("i_zero_length_without_creds_is_a_record", func(t *testing.T) {
		parent, child := chanSocketPair(t, false)
		defer chanClose(parent, child)
		chanSend(t, child, nil)
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: false, sys: realChanSys()}
		o := end.drain(&chanState{})
		if o.End != "EAGAIN" || len(o.Recs) != 1 {
			t.Fatalf("End %s recs %d, want one record and EAGAIN (not EOF)", o.End, len(o.Recs))
		}
		if got := chanDecideRec(&chanState{}, o.Recs[0]); got != "CLOSE:nocreds" {
			t.Fatalf("decided %q, want CLOSE:nocreds", got)
		}
	})

	t.Run("j_truncated_record_counts_and_closes", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		chanSend(t, child, []byte(strings.Repeat(" ", chanDataBuf+100)))
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: realChanSys()}
		o := end.drain(&chanState{})
		if o.End != "EAGAIN" || len(o.Recs) != 1 || o.Recs[0].flags&unix.MSG_TRUNC == 0 {
			t.Fatalf("End %s recs %d, want one truncated record and EAGAIN", o.End, len(o.Recs))
		}
		if got := chanDecideRec(&chanState{}, o.Recs[0]); got != "CLOSE:trunc" {
			t.Fatalf("decided %q, want CLOSE:trunc", got)
		}
	})

	t.Run("k_recvmsg_error_is_observation", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		sys := realChanSys()
		sys.recvmsg = chanScripted(t, unix.EIO)
		st := admitted()
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: sys}
		o := end.drain(st)
		if o.End != "ERR" || !errors.Is(o.Err, ErrObservation) || len(o.Recs) != 0 || st.poison == nil {
			t.Fatalf("End %s err %v recs %d poison %v, want ERR wrapping ErrObservation and a poisoned state",
				o.End, o.Err, len(o.Recs), st.poison)
		}
	})

	t.Run("m_status_with_fd_and_truncated_status_are_not_known", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		rd, wr := chanPipe(t)
		defer chanClose(rd)
		chanSend(t, child, []byte(chanStatus(0)), wr)
		chanClose(wr)
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: realChanSys()}
		st := admitted()
		o := end.drain(st)
		if len(o.Recs) != 1 || o.Recs[0].nfds != 1 {
			t.Fatalf("recs %d, want one record that kept its descriptor count", len(o.Recs))
		}
		if got := chanDecideRec(st, o.Recs[0]); got != "CLOSE:status_fd" {
			t.Fatalf("decided %q, want CLOSE:status_fd", got)
		}
		if !chanReadEOF(rd) {
			t.Fatal("the status descriptor is still open after the drain")
		}

		tparent, tchild := chanSocketPair(t, true)
		defer chanClose(tparent, tchild)
		chanSend(t, tchild, []byte(chanStatus(0)+strings.Repeat(" ", chanDataBuf)))
		tend := chanEnd{fd: tparent, ctl: chanBufV61, credsOn: true, sys: realChanSys()}
		to := tend.drain(admitted())
		if len(to.Recs) != 1 || to.Recs[0].flags&unix.MSG_TRUNC == 0 {
			t.Fatalf("recs %d, want one truncated record", len(to.Recs))
		}
		if got := chanDecideRec(admitted(), to.Recs[0]); got != "CLOSE:trunc" {
			t.Fatalf("decided %q, want CLOSE:trunc", got)
		}
	})

	t.Run("n_overflow_poisons_later_status", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		for range chanMaxRecords + 1 {
			chanSend(t, child, []byte(chanStatus(0)))
		}
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: realChanSys()}
		st := admitted()
		if o := end.drain(st); o.End != "OVERFLOW_RECORD" {
			t.Fatalf("first drain End %s, want OVERFLOW_RECORD", o.End)
		}
		chanSend(t, child, []byte(chanStatus(0)))
		var counted chanCounted
		end.sys.recvmsg = counted.recvmsg
		o := end.drain(st)
		if o.End != "POISONED" || counted.calls != 0 || !errors.Is(o.Err, ErrProtocolViolation) {
			t.Fatalf("later drain End %s calls %d err %v, want POISONED with 0 calls", o.End, counted.calls, o.Err)
		}
		late := chanRecvd{data: []byte(chanStatus(0)), n: len(chanStatus(0)), creds: &unix.Ucred{Pid: int32(self)}}
		if got := chanDecideRec(st, late); got != "UNKNOWN:observed" {
			t.Fatalf("later status decided %q, want UNKNOWN:observed", got)
		}
	})

	t.Run("o_observation_error_poisons_later_status", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		sys := realChanSys()
		sys.recvmsg = chanScripted(t, unix.EIO)
		st := admitted()
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: sys}
		if o := end.drain(st); !errors.Is(o.Err, ErrObservation) {
			t.Fatalf("first drain err %v, want ErrObservation", o.Err)
		}
		chanSend(t, child, []byte(chanStatus(0)))
		var counted chanCounted
		end.sys.recvmsg = counted.recvmsg
		o := end.drain(st)
		if o.End != "POISONED" || counted.calls != 0 {
			t.Fatalf("later drain End %s calls %d, want POISONED with 0 calls", o.End, counted.calls)
		}
		late := chanRecvd{data: []byte(chanStatus(0)), n: len(chanStatus(0)), creds: &unix.Ucred{Pid: int32(self)}}
		if got := chanDecideRec(st, late); got != "UNKNOWN:observed" {
			t.Fatalf("later status decided %q, want UNKNOWN:observed", got)
		}
	})

	t.Run("p_ninth_eintr_in_one_drain_is_protocol_violation", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		chanSend(t, child, []byte(chanStatus(0)))
		// Five EINTR, one real record, then four EINTR: the ninth EINTR of this drain overflows.
		seq := slices.Concat(
			slices.Repeat([]error{unix.EINTR}, 5),
			[]error{nil},
			slices.Repeat([]error{unix.EINTR}, 4),
		)
		sys := realChanSys()
		sys.recvmsg = chanScripted(t, seq...)
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: sys}
		o := end.drain(&chanState{})
		if o.End != "OVERFLOW_EINTR" || o.EINTR != 8 || len(o.Recs) != 1 || !errors.Is(o.Err, ErrProtocolViolation) {
			t.Fatalf("End %s eintr %d recs %d err %v, want OVERFLOW_EINTR at 8 EINTR with ErrProtocolViolation",
				o.End, o.EINTR, len(o.Recs), o.Err)
		}
	})

	t.Run("q_status_then_observation_error_is_not_known", func(t *testing.T) {
		parent, child := chanSocketPair(t, true)
		defer chanClose(parent, child)
		chanSend(t, child, []byte(chanStatus(0)))
		sys := realChanSys()
		sys.recvmsg = chanScripted(t, nil, unix.EIO)
		st := admitted()
		end := chanEnd{fd: parent, ctl: chanBufV61, credsOn: true, sys: sys}
		o := end.drain(st)
		if o.End != "ERR" || len(o.Recs) != 1 || !errors.Is(o.Err, ErrObservation) {
			t.Fatalf("End %s recs %d err %v, want ERR after one status", o.End, len(o.Recs), o.Err)
		}
		if got := chanDecideRec(st, o.Recs[0]); got != "UNKNOWN:observed" {
			t.Fatalf("status before the error decided %q, want UNKNOWN:observed", got)
		}
	})
}
