package remote

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A refusal that ssh reports at the same moment as the deadline is still a refusal. The ssh exit
// is the answer, so the error is not marked as a run timeout, and a refused connection cannot pass
// for an ordinary component timeout.
func TestRefusalWinsOverTheDeadline(t *testing.T) {
	ctx := context.Background()
	opCtx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	err := transportError(ctx, opCtx, time.Second, "lab", sshFailedStatus, "Permission denied (publickey).", errors.New("eof"))
	if errors.Is(err, ErrRunTimedOut) {
		t.Fatalf("a refusal that landed on the deadline is marked as a run timeout: %v", err)
	}
	if !strings.Contains(err.Error(), "could not open the connection") {
		t.Fatalf("the refusal lost its text: %v", err)
	}
}
