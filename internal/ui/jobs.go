package ui

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// JobStatus is a drill-down job's lifecycle terminal state (plus the two
// pre-terminal states for display).
type JobStatus int

const (
	JobQueued JobStatus = iota
	JobRunning
	JobDone
	JobFailed
	JobCanceled
	JobTimedOut
)

func (s JobStatus) String() string {
	switch s {
	case JobQueued:
		return "queued"
	case JobRunning:
		return "running"
	case JobDone:
		return "done"
	case JobFailed:
		return "failed"
	case JobCanceled:
		return "canceled"
	case JobTimedOut:
		return "timed out"
	}
	return "?"
}

// ToolOutputMsg is one sanitized output line. JobID+Generation identity lets
// Update drop stale-job messages.
type ToolOutputMsg struct {
	JobID      string
	Generation int
	Stderr     bool
	Line       string
}

// ToolDoneMsg is the single guaranteed terminal event for a job. It travels on
// the same channel as output (single FIFO) so buffered final lines can't arrive
// after it.
type ToolDoneMsg struct {
	JobID      string
	Generation int
	Status     JobStatus
	Dropped    int64 // output lines dropped under overflow
}

const (
	// toolTimeout is the default job budget; genuinely slow tools (pathping,
	// nmap) bring their own via Tool.Timeout.
	toolTimeout = 12 * time.Second
	// chanBuf absorbs output bursts between Update reads. A tool that
	// out-talks the UI anyway gets its excess dropped and counted (Dropped) —
	// the UI never blocks to spare a chatty subprocess's feelings.
	chanBuf      = 256
	maxLineBytes = 4096
)

// job is a running external command. The channel carries ToolOutputMsg lines and
// then exactly one ToolDoneMsg, last.
type job struct {
	id     string
	ch     chan tea.Msg
	cancel context.CancelFunc
}

// startTool launches name+args as a process-group leader, streaming sanitized
// output lines and a guaranteed terminal event on job.ch. env nil = inherit.
// timeout <= 0 means the default toolTimeout.
// Returns the job and the first wait command to feed into Bubble Tea.
func startTool(parent context.Context, gen int, id, name string, args, env []string, timeout time.Duration) (*job, tea.Cmd, error) {
	if timeout <= 0 {
		timeout = toolTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	setProcGroup(cmd) // own process group (Unix) so we can kill descendants (e.g. mtr-packet)
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = 2 * time.Second // don't hang on Wait if a child holds the pipe

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, err
	}

	j := &job{id: id, ch: make(chan tea.Msg, chanBuf), cancel: cancel}
	var dropped int64

	go func() {
		defer cancel()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); streamReader(stdout, false, id, gen, j.ch, &dropped) }()
		go func() { defer wg.Done(); streamReader(stderr, true, id, gen, j.ch, &dropped) }()
		wg.Wait() // drain both pipes to EOF before Wait (no drain/wait race)
		werr := cmd.Wait()
		// Guaranteed (blocking) terminal send, last — never dropped.
		j.ch <- ToolDoneMsg{
			JobID:      id,
			Generation: gen,
			Status:     classifyJob(ctx, werr),
			Dropped:    atomic.LoadInt64(&dropped),
		}
	}()

	return j, waitForMsg(j.ch), nil
}

// waitForMsg reads the next job message. Update re-issues it after each
// ToolOutputMsg and stops after the ToolDoneMsg.
func waitForMsg(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// streamReader reads capped, sanitized lines and pushes them non-blocking: it
// always consumes the bytes (so the child never stalls) and only drops the
// *message* when the channel is full, so the terminal event can still be
// delivered (no deadlock).
func streamReader(r io.Reader, stderr bool, id string, gen int, ch chan<- tea.Msg, dropped *int64) {
	br := bufio.NewReader(r)
	for {
		line, err := readCappedLine(br)
		if line != "" {
			select {
			case ch <- ToolOutputMsg{JobID: id, Generation: gen, Stderr: stderr, Line: textsafe.Clean(winSafe(line))}:
			default:
				atomic.AddInt64(dropped, 1)
			}
		}
		if err != nil {
			return
		}
	}
}

// readCappedLine reads one line up to maxLineBytes; a longer line is truncated
// (marked) and the rest consumed, so a newline-less flood can't exhaust memory.
func readCappedLine(br *bufio.Reader) (string, error) {
	var b []byte
	for {
		c, err := br.ReadByte()
		if err != nil {
			return string(b), err
		}
		if c == '\n' {
			return string(b), nil
		}
		switch {
		case len(b) < maxLineBytes:
			b = append(b, c)
		case len(b) == maxLineBytes:
			b = append(b, "…[truncated]"...)
		} // else discard until newline
	}
}

// classifyJob is centralized, success-wins: a process that exited 0 just as its
// deadline expired is Done, not TimedOut. Only on a Wait error do we consult the
// context cause.
func classifyJob(ctx context.Context, werr error) JobStatus {
	if werr == nil {
		return JobDone
	}
	switch context.Cause(ctx) {
	case context.Canceled:
		return JobCanceled
	case context.DeadlineExceeded:
		return JobTimedOut
	default:
		return JobFailed
	}
}

// winSafe makes invalid UTF-8 from Windows consoles (OEM code page) visible as
// '?' instead of letting the sanitizer drop it silently. Windows subprocess
// boundary only — Unix sanitization semantics are untouched.
func winSafe(s string) string {
	if runtime.GOOS == "windows" {
		return strings.ToValidUTF8(s, "?")
	}
	return s
}
