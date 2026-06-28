package main

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
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

// Stream identifies which pipe an output line came from.
type Stream int

const (
	StreamStdout Stream = iota
	StreamStderr
)

// ToolOutputMsg is one sanitized output line. JobID+Generation identity lets
// Update drop stale-job messages.
type ToolOutputMsg struct {
	JobID      string
	Generation int
	Stream     Stream
	Line       string
}

// ToolDoneMsg is the single guaranteed terminal event for a job. It travels on
// the same channel as output (single FIFO) so buffered final lines can't arrive
// after it.
type ToolDoneMsg struct {
	JobID      string
	Generation int
	Status     JobStatus
	Err        error
	Dropped    int64 // output lines dropped under overflow
}

const (
	toolTimeout  = 12 * time.Second
	chanBuf      = 256
	maxLineBytes = 4096
)

// job is a running external command. The channel carries ToolOutputMsg lines and
// then exactly one ToolDoneMsg, last.
type job struct {
	id     string
	gen    int
	cmd    *exec.Cmd
	ch     chan tea.Msg
	cancel context.CancelFunc
}

// startTool launches name+args as a process-group leader, streaming sanitized
// output lines and a guaranteed terminal event on job.ch. env nil = inherit.
// Returns the job and the first wait command to feed into Bubble Tea.
func startTool(parent context.Context, gen int, id, name string, args, env []string) (*job, tea.Cmd, error) {
	ctx, cancel := context.WithTimeout(parent, toolTimeout)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	// Own process group so we can kill descendants (e.g. mtr-packet).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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

	j := &job{id: id, gen: gen, cmd: cmd, ch: make(chan tea.Msg, chanBuf), cancel: cancel}
	var dropped int64

	go func() {
		defer cancel()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); streamReader(stdout, StreamStdout, id, gen, j.ch, &dropped) }()
		go func() { defer wg.Done(); streamReader(stderr, StreamStderr, id, gen, j.ch, &dropped) }()
		wg.Wait() // drain both pipes to EOF before Wait (no drain/wait race)
		werr := cmd.Wait()
		// Guaranteed (blocking) terminal send, last — never dropped.
		j.ch <- ToolDoneMsg{
			JobID:      id,
			Generation: gen,
			Status:     classifyJob(ctx, werr),
			Err:        werr,
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
func streamReader(r io.Reader, stream Stream, id string, gen int, ch chan<- tea.Msg, dropped *int64) {
	br := bufio.NewReader(r)
	for {
		line, err := readCappedLine(br)
		if line != "" {
			select {
			case ch <- ToolOutputMsg{JobID: id, Generation: gen, Stream: stream, Line: sanitize(line)}:
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

// killGroup SIGKILLs the whole process group so descendants die too.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		return syscall.Kill(-pgid, syscall.SIGKILL)
	}
	return cmd.Process.Kill()
}
