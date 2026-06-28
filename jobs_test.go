package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
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
		for i := 0; i < 20000; i++ {
			fmt.Printf("flood %d\n", i)
		}
	}
	os.Exit(0)
}

func startHelper(t *testing.T, parent context.Context, mode string, extra ...string) *job {
	t.Helper()
	env := append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE="+mode)
	env = append(env, extra...)
	j, _, err := startTool(parent, 0, "test-"+mode, os.Args[0], []string{"-test.run=TestHelperProcess"}, env)
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
			t.Fatal("drain timed out — terminal event never arrived")
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

func TestJobTimeout(t *testing.T) {
	// A short parent deadline makes the job's context time out well before the
	// 12s tool timeout; the cause propagates → JobTimedOut.
	parent, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	j := startHelper(t, parent, "sleep")
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

// Overflow must drop output lines but still deliver the terminal event.
func TestJobOverflowKeepsTerminal(t *testing.T) {
	j := startHelper(t, context.Background(), "flood")
	time.Sleep(200 * time.Millisecond) // let the reader fill+drop before we read
	out, done := drain(t, j.ch)
	if done.Status != JobDone {
		t.Fatalf("status = %v, want JobDone (terminal must survive overflow)", done.Status)
	}
	if len(out) >= 20000 {
		t.Errorf("expected some lines dropped, got all %d", len(out))
	}
	if done.Dropped == 0 {
		t.Error("expected a non-zero dropped count under overflow")
	}
}
