// Job lifecycle against GO_HELPER subprocesses: streaming, process-tree
// cancellation, timeouts, line truncation, and overflow still delivering the
// terminal event.

package ui

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// TestHelperProcess is re-executed as the child process for the job integration
// tests; it is inert in a normal run.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_HELPER") != "1" {
		return
	}
	switch os.Getenv("GO_HELPER_MODE") {
	case "lines":
		n, _ := strconv.Atoi(os.Getenv("GO_HELPER_N"))
		for i := 0; i < n; i++ {
			fmt.Printf("line %d\n", i)
		}
	case "sleep":
		time.Sleep(30 * time.Second)
	case "longline":
		fmt.Print(strings.Repeat("A", maxLineBytes*2) + "\n")
	case "flood":
		for i := 0; i < floodLines; i++ {
			fmt.Printf("flood %d\n", i)
		}
	case "grandchild":
		// A child of the child, reachable only through the managed tree. Its
		// output is discarded rather than inherited, so it can't hold our
		// stdout pipe open and stall the drain after we die.
		// #nosec G204 G702 -- os.Args[0] deliberately re-executes this test binary.
		child := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
		child.Env = append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE=descendant")
		child.Stdout, child.Stderr = io.Discard, io.Discard
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "grandchild:", err)
			os.Exit(1)
		}
		fmt.Println(child.Process.Pid)
		time.Sleep(30 * time.Second)
	case "descendant":
		time.Sleep(5 * time.Minute)
	}
	os.Exit(0)
}

// grandchildPID reads the pid the helper prints before it parks.
func grandchildPID(t *testing.T, ch chan tea.Msg) int {
	t.Helper()
	timeout := time.After(20 * time.Second)
	for {
		select {
		case msg := <-ch:
			out, ok := msg.(ToolOutputMsg)
			if !ok {
				t.Fatalf("job ended before reporting a pid: %v", msg)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(out.Line))
			if err != nil {
				t.Fatalf("helper printed %q, want a pid", out.Line)
			}
			return pid
		case <-timeout:
			t.Fatal("helper never reported its grandchild's pid")
		}
	}
}

func startHelper(t *testing.T, parent context.Context, mode string, extra ...string) *job {
	t.Helper()
	env := append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE="+mode)
	env = append(env, extra...)
	j, _, err := startTool(parent, 0, "test-"+mode, os.Args[0], []string{"-test.run=TestHelperProcess"}, env, 0)
	if err != nil {
		t.Fatalf("startTool: %v", err)
	}
	return j
}

func drain(t *testing.T, ch chan tea.Msg) ([]string, ToolDoneMsg) {
	t.Helper()
	var out []string
	timeout := time.After(20 * time.Second)
	for {
		select {
		case m := <-ch:
			switch v := m.(type) {
			case ToolOutputMsg:
				out = append(out, v.Line)
			case ToolDoneMsg:
				return out, v
			}
		case <-timeout:
			t.Fatal("drain timed out: terminal event never arrived")
			return out, ToolDoneMsg{}
		}
	}
}

func TestJobStreamsAndCompletes(t *testing.T) {
	j := startHelper(t, context.Background(), "lines", "GO_HELPER_N=3")
	out, done := drain(t, j.ch)
	if len(out) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(out), out)
	}
	if done.Status != JobDone {
		t.Errorf("status = %v, want JobDone", done.Status)
	}
}

func TestJobCancel(t *testing.T) {
	j := startHelper(t, context.Background(), "sleep")
	time.Sleep(50 * time.Millisecond)
	j.cancel()
	_, done := drain(t, j.ch)
	if done.Status != JobCanceled {
		t.Errorf("status = %v, want JobCanceled", done.Status)
	}
}

// helperTimeout is the deadline the timeout tests give a helper subprocess. It
// has to outlast re-execing the test binary: expire before that and exec.Start
// returns the context error, failing the test somewhere short of the timeout
// classification it exists to check. A second is far past a normal spawn and
// still cheap, since these tests wait it out.
const helperTimeout = time.Second

func TestJobTimeout(t *testing.T) {
	// A short parent deadline makes the job's context time out well before the
	// 12s tool timeout; the cause propagates → JobTimedOut.
	parent, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	j := startHelper(t, parent, "sleep")
	_, done := drain(t, j.ch)
	if done.Status != JobTimedOut {
		t.Errorf("status = %v, want JobTimedOut", done.Status)
	}
}

// A per-tool timeout below the parent deadline must govern (pathping's 90 s
// budget rides the same path in the other direction).
func TestJobPerToolTimeout(t *testing.T) {
	env := append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE=sleep")
	j, _, err := startTool(context.Background(), 0, "test-timeout", os.Args[0],
		[]string{"-test.run=TestHelperProcess"}, env, helperTimeout)
	if err != nil {
		t.Fatalf("startTool: %v", err)
	}
	_, done := drain(t, j.ch)
	if done.Status != JobTimedOut {
		t.Errorf("status = %v, want JobTimedOut", done.Status)
	}
}

func TestJobLongLineTruncated(t *testing.T) {
	j := startHelper(t, context.Background(), "longline")
	out, done := drain(t, j.ch)
	if done.Status != JobDone {
		t.Fatalf("status = %v, want JobDone", done.Status)
	}
	if len(out) != 1 {
		t.Fatalf("got %d lines, want 1", len(out))
	}
	if !strings.Contains(out[0], "…[truncated]") {
		t.Error("over-long line should be marked truncated")
	}
	if len(out[0]) > maxLineBytes+64 {
		t.Errorf("truncated line len = %d, want ~%d", len(out[0]), maxLineBytes)
	}
}

// floodLines is how many lines the flood helper prints: far more than chanBuf.
const floodLines = 20000

// A full channel drops and counts every line, and streamReader still reads its
// input to EOF instead of waiting for room, so the child never stalls.
func TestStreamReaderDropsWhenChannelFull(t *testing.T) {
	// In a bubble, a regression that blocks on the full channel fails at once
	// as a deadlock instead of hanging until the test binary times out.
	synctest.Test(t, func(t *testing.T) {
		held := ToolOutputMsg{Line: "held"}
		ch := make(chan tea.Msg, 1)
		ch <- held
		r := strings.NewReader("a\nb\nc")
		var dropped int64
		streamReader(r, "test", "test", 0, ch, &dropped)
		if dropped != 3 {
			t.Errorf("dropped = %d, want 3", dropped)
		}
		if r.Len() != 0 {
			t.Errorf("%d bytes left unread, want the input consumed", r.Len())
		}
		if len(ch) != 1 || <-ch != held {
			t.Error("a full channel's contents changed")
		}
	})
}

// Overflow must drop output lines but still deliver the terminal event, last.
// Nothing reads the channel until synctest.Wait sees every goroutine in the
// bubble durably blocked. Pipe reads and the process wait never count as that,
// so by then the flood is over: the first chanBuf lines fill the channel, the
// rest are dropped, and the job is parked on its terminal send.
func TestJobOverflowKeepsTerminal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		j := startHelper(t, context.Background(), "flood")
		synctest.Wait()
		if len(j.ch) != cap(j.ch) {
			t.Fatalf("channel holds %d of %d before any read, want it full", len(j.ch), cap(j.ch))
		}
		out, done := drain(t, j.ch)
		if done.Status != JobDone {
			t.Fatalf("status = %v, want JobDone (terminal must survive overflow)", done.Status)
		}
		if len(out) != chanBuf {
			t.Errorf("got %d lines before the terminal event, want %d", len(out), chanBuf)
		}
		if done.Dropped != floodLines-chanBuf {
			t.Errorf("dropped = %d, want %d", done.Dropped, floodLines-chanBuf)
		}
		select {
		case m := <-j.ch:
			t.Errorf("message after the terminal event: %v", m)
		default:
		}
	})
}
