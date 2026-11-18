package remote

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// A refusal that ssh reports at the same moment as the deadline is still a refusal. The ssh exit
// is the answer, so the error is not marked as a run timeout, and a refused connection cannot pass
// for an ordinary component timeout.
func TestRefusalWinsOverTheDeadline(t *testing.T) {
	ctx := context.Background()
	opCtx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	err := transportError(ctx, opCtx, time.Second, "lab", sshFailedStatus, "Permission denied (publickey).", true, errors.New("eof"))
	if errors.Is(err, ErrRunTimedOut) {
		t.Fatalf("a refusal that landed on the deadline is marked as a run timeout: %v", err)
	}
	if !strings.Contains(err.Error(), "could not open the connection") {
		t.Fatalf("the refusal lost its text: %v", err)
	}
}

// A deadline that ends before ssh starts is not a run timeout: no connection was attempted, so
// the mark is for a started client only. The allowance is a nanosecond, so the deadline has passed
// by the time the client would start.
func TestDeadlineBeforeStartIsNotARunTimeout(t *testing.T) {
	savedAllowance, savedProgram := transportAllowance, sshProgram
	transportAllowance = time.Nanosecond
	sshProgram = "/bin/sh"
	savedTerminal := sshverify.TerminalAvailable
	sshverify.TerminalAvailable = func() bool { return true }
	t.Cleanup(func() {
		transportAllowance, sshProgram = savedAllowance, savedProgram
		sshverify.TerminalAvailable = savedTerminal
	})
	_, err := RunBatch(context.Background(), "lab", "", Request{})
	if err == nil {
		t.Fatal("a run whose deadline had passed started a client")
	}
	if errors.Is(err, ErrRunTimedOut) {
		t.Fatalf("a deadline that ended before ssh started is marked as a run timeout: %v", err)
	}
}
