package ui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh/agent"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// silentAgentOptions returns options whose agent never answers. The far end of
// each pipe is held open and never written to, so a request waits on the agent
// until the check closes its side. The held ends are closed when the test ends.
func silentAgentOptions(t *testing.T, timeout time.Duration, dial func(context.Context, string) (net.Conn, error)) sshverify.Options {
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
	return sshverify.Options{
		Timeout: timeout,
		Dial:    dial,
		Agent: func() (io.ReadWriteCloser, error) {
			client, server := net.Pipe()
			mu.Lock()
			held = append(held, server)
			mu.Unlock()
			return client, nil
		},
	}
}

// A silent agent cannot hold back a discovery result. The discovery here fails
// at once, so the command should return within the test's limit, which is far
// above the agent timeout.
func TestSilentAgentDoesNotHoldDiscovery(t *testing.T) {
	target := sshverify.Target{Host: "h", Port: 22, User: "u"}
	opts := silentAgentOptions(t, 300*time.Millisecond, func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("no route in this test")
	})
	done := make(chan tea.Msg, 1)
	go func() { done <- discoverCmd(context.Background(), 1, target, opts)() }()
	select {
	case msg := <-done:
		if _, ok := msg.(verifyResultMsg); !ok {
			t.Fatalf("discovery returned %T, want its result", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the discovery result is still held after 3s by a silent agent")
	}
}

// Positive control: a responsive agent's keys arrive in their own message.
func TestResponsiveAgentKeysArriveSeparately(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "test identity"}); err != nil {
		t.Fatal(err)
	}
	serve := func() (io.ReadWriteCloser, error) {
		client, server := net.Pipe()
		go func() { _ = agent.ServeAgent(keyring, server) }()
		return client, nil
	}
	opts := sshverify.Options{Timeout: 5 * time.Second, Agent: serve}
	msg := agentKeysCmd(context.Background(), 2, sshverify.Target{}, opts)()
	keys, ok := msg.(verifyKeysMsg)
	if !ok || len(keys.keys) != 1 || keys.id != 2 {
		t.Fatalf("agent keys = %#v, want one key for panel 2", msg)
	}
}
