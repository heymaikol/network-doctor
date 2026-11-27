package sshverify

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// silentOptions returns options whose agent never answers. Each connection is an
// in-memory pipe whose far end is held open and never written to, so a request
// waits on the agent until the check closes its side. The held ends are closed
// when the test ends.
func silentOptions(t *testing.T, timeout time.Duration) Options {
	t.Helper()
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	return Options{
		Timeout: timeout,
		Agent: func() (io.ReadWriteCloser, error) {
			client, server := net.Pipe()
			mu.Lock()
			held = append(held, server)
			mu.Unlock()
			return client, nil
		},
	}
}

// within runs f and fails the test if it has not returned within limit. The
// limit is far above the timeouts under test, so a failure means f blocked.
func within(t *testing.T, limit time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s is still blocked after %v, past its timeout", what, limit)
	}
}

// A silent agent cannot hold a key listing past the check's timeout.
func TestSilentAgentListingEndsAtItsTimeout(t *testing.T) {
	opts := silentOptions(t, 300*time.Millisecond)
	within(t, 3*time.Second, "ListAgentKeys", func() {
		keys, err := ListAgentKeys(context.Background(), Target{}, opts)
		if err == nil || keys != nil {
			t.Errorf("a silent agent listed %v, err %v; want no keys and an error", keys, err)
		}
	})
}

// Cancelling the context ends a key listing at once, without waiting for the timeout.
func TestCancelledAgentListingReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opts := silentOptions(t, time.Minute)
	time.AfterFunc(100*time.Millisecond, cancel)
	within(t, 3*time.Second, "ListAgentKeys after cancellation", func() {
		if _, err := ListAgentKeys(ctx, Target{}, opts); err == nil {
			t.Error("a cancelled listing returned no error")
		}
	})
}

// A silent agent cannot hold the agent-key preparation past the timeout, and the
// check reports a local failure, so nothing is sent.
func TestSilentAgentPreparationEndsAtItsTimeout(t *testing.T) {
	opts := silentOptions(t, 300*time.Millisecond)
	within(t, 3*time.Second, "agent key preparation", func() {
		cred, r := prepare(context.Background(), Target{}, Attempt{Method: MethodAgent, AgentFingerprint: "SHA256:x"}, opts)
		if cred != nil {
			cred.close()
			t.Error("a silent agent produced a credential")
		}
		if r.Outcome != LocalFailure {
			t.Errorf("outcome = %q, want a local failure with nothing sent", r.Outcome)
		}
	})
}

// Positive control: a responsive agent still lists its keys and prepares its signer.
func TestResponsiveAgentStillListsAndSigns(t *testing.T) {
	signer, priv := newEd25519(t)
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	opts := Options{Timeout: 5 * time.Second, Agent: fakeAgent(t, priv)}

	keys, err := ListAgentKeys(context.Background(), Target{}, opts)
	if err != nil || len(keys) != 1 || keys[0].Fingerprint != fp {
		t.Fatalf("ListAgentKeys = %v, %v; want the agent's one key", keys, err)
	}
	cred, r := prepare(context.Background(), Target{}, Attempt{Method: MethodAgent, AgentFingerprint: fp}, opts)
	if cred == nil {
		t.Fatalf("prepare returned no credential: %v", r)
	}
	cred.close()
}
