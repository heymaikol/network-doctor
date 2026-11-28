package ui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
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
	msg := agentKeysCmd(context.Background(), 2, 1, sshverify.Target{}, opts)()
	keys, ok := msg.(verifyKeysMsg)
	if !ok || len(keys.keys) != 1 || keys.id != 2 {
		t.Fatalf("agent keys = %#v, want one key for panel 2", msg)
	}
}

// The listing reaches the chooser through the model's update, not only through
// the command. A message the update drops leaves the chooser empty.
func TestVerifyAgentKeysReachTheChooserThroughUpdate(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	for i, mt := range verifyMethods {
		if mt == sshverify.MethodAgent {
			m.verify.method = i
		}
	}
	next, _ := m.Update(verifyKeysMsg{id: m.verify.id, keys: []sshverify.AgentKey{{Fingerprint: "SHA256:test", Type: "ssh-ed25519", Comment: "test"}}})
	if got := next.(model).verify.agentKeys; len(got) != 1 {
		t.Fatalf("the chooser has %d agent keys, want 1: the listing message was not delivered", len(got))
	}
}

func TestVerifyAgentPickerRequiresEnterAndClearsSelectionOnMove(t *testing.T) {
	m := resolved(t, pressed(t, sshModel(t), keyPress("S")))
	m.verify.method = 2
	m.verify.agentKeys = []sshverify.AgentKey{
		{Fingerprint: "SHA256:first", Comment: "first"},
		{Fingerprint: "SHA256:second", Comment: "second"},
	}
	m.verify.focus(vrAgent)
	if a, note := m.verify.attempt(); note == "" || a.AgentFingerprint != "" {
		t.Fatalf("agent key chosen without Enter: attempt=%+v note=%q", a, note)
	}
	u, _ := m.handleVerifyKey(keyPress("down"))
	m = asModel(t, u)
	if m.verify.agentIdx != 1 || m.verify.agentChosen {
		t.Fatalf("down selected agent key: index=%d chosen=%v", m.verify.agentIdx, m.verify.agentChosen)
	}
	u, _ = m.handleVerifyKey(keyPress("enter"))
	m = asModel(t, u)
	if m.verify.row != vrDiscover || !m.verify.agentChosen {
		t.Fatalf("enter did not select agent key: row=%v chosen=%v", m.verify.row, m.verify.agentChosen)
	}
	if a, note := m.verify.attempt(); note != "" || a.AgentFingerprint != "SHA256:second" {
		t.Fatalf("selected agent key = %+v, note %q", a, note)
	}
	m.verify.focus(vrAgent)
	u, _ = m.handleVerifyKey(keyPress("up"))
	m = asModel(t, u)
	if m.verify.agentChosen || m.verify.agentIdx != 0 {
		t.Fatalf("moving reused agent selection: index=%d chosen=%v", m.verify.agentIdx, m.verify.agentChosen)
	}
	if a, note := m.verify.attempt(); note == "" || a.AgentFingerprint != "" {
		t.Fatalf("moving kept an agent credential: %+v, note %q", a, note)
	}
}

func TestVerifyAgentPickerRefusesAnEmptyList(t *testing.T) {
	m := resolved(t, pressed(t, sshModel(t), keyPress("S")))
	m.verify.method = 2
	m.verify.focus(vrAgent)
	u, _ := m.handleVerifyKey(keyPress("enter"))
	m = asModel(t, u)
	if m.verify.row != vrAgent || m.verify.agentChosen || !strings.Contains(m.verify.note, "Discover methods") {
		t.Fatalf("empty agent picker: row=%v chosen=%v note=%q", m.verify.row, m.verify.agentChosen, m.verify.note)
	}
}

func TestVerifyAgentPickerDisplaysAWindowWithGuidance(t *testing.T) {
	m := resolved(t, pressed(t, sshModel(t), keyPress("S")))
	m.verify.method = 2
	m.width = 66
	for i := 0; i < 8; i++ {
		name := string(rune('a' + i))
		m.verify.agentKeys = append(m.verify.agentKeys, sshverify.AgentKey{Type: "ssh-ed25519", Comment: "key-" + name, Fingerprint: "SHA256:" + name})
	}
	m.verify.focus(vrAgent)
	check := func(first, last string) {
		t.Helper()
		text := ansi.Strip(m.verifyView())
		if !strings.Contains(text, first) || !strings.Contains(text, last) || !strings.Contains(text, "choose with arrows, press enter to select") || strings.Contains(text, "showing ") {
			t.Fatalf("agent key list not displayed correctly: %q", text)
		}
		lines := strings.Split(text, "\n")
		for i, line := range lines {
			if strings.Contains(line, "choose with arrows, press enter to select") {
				if i == 0 || strings.TrimSpace(strings.Trim(lines[i-1], "│")) != "" {
					t.Fatalf("agent hint must follow a blank line: %q", text)
				}
				return
			}
		}
	}
	check("▸ key-a", "▹ key-e")
	for i := 0; i < 6; i++ {
		u, _ := m.handleVerifyKey(keyPress("down"))
		m = asModel(t, u)
	}
	check("▸ key-g", "▹ key-h")
	u, _ := m.handleVerifyKey(keyPress("enter"))
	m = asModel(t, u)
	if text := ansi.Strip(m.verifyView()); !strings.Contains(text, "✓ key-g") {
		t.Fatalf("selected agent key not marked: %q", text)
	}
	t.Logf("sanitized ssh-agent chooser:\n%s", ansi.Strip(m.verifyView()))
}

// Only the newest listing fills the chooser. A replaced listing, or one for a
// route that was dropped, arrives late and must not replace the keys.
func TestVerifyStaleAgentListingIsDropped(t *testing.T) {
	m := pressed(t, sshModel(t), keyPress("S"))
	m = resolved(t, m)
	m.verify.keysSeq = 2
	m, _, _ = m.handleVerifyMsg(verifyKeysMsg{id: m.verify.id, seq: 1, keys: []sshverify.AgentKey{{Fingerprint: "old"}}})
	if len(m.verify.agentKeys) != 0 {
		t.Fatalf("a replaced listing filled the chooser: %v", m.verify.agentKeys)
	}
	m, _, _ = m.handleVerifyMsg(verifyKeysMsg{id: m.verify.id, seq: 2, keys: []sshverify.AgentKey{{Fingerprint: "new"}}})
	if len(m.verify.agentKeys) != 1 || m.verify.agentKeys[0].Fingerprint != "new" {
		t.Fatalf("the newest listing did not fill the chooser: %v", m.verify.agentKeys)
	}
	m.verify.dropRoute()
	m, _, _ = m.handleVerifyMsg(verifyKeysMsg{id: m.verify.id, seq: 2, keys: []sshverify.AgentKey{{Fingerprint: "late"}}})
	if len(m.verify.agentKeys) != 0 {
		t.Fatalf("a listing for a dropped route filled the chooser: %v", m.verify.agentKeys)
	}
}

// A listing still running when its route is dropped is cancelled, so it does not
// keep the agent busy for a route nobody will use.
func TestDropRouteCancelsARunningAgentListing(t *testing.T) {
	m := pressed(t, sshModel(t), keyPress("S"))
	m = resolved(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.verify.keysCancel = cancel
	m.verify.dropRoute()
	if ctx.Err() == nil {
		t.Fatal("the agent listing of a dropped route was not cancelled")
	}
	if m.verify.keysCancel != nil {
		t.Fatal("the dropped route kept a cancel for its agent listing")
	}
}

// A discovery numbers its agent listing. A discovery that starts while an earlier
// listing still runs replaces it, so the earlier listing is dropped when it lands.
func TestNewDiscoveryDropsTheEarlierAgentListing(t *testing.T) {
	m := resolved(t, pressed(t, sshModel(t), keyPress("S")))
	for i, mt := range verifyMethods {
		if mt == sshverify.MethodAgent {
			m.verify.method = i
		}
	}
	m, _ = m.startVerifyAction(false)
	first := m.verify.keysSeq
	m.verify.busy = false // the discovery result arrived; its listing is still running
	m.verify.agentKeys = []sshverify.AgentKey{{Fingerprint: "old"}}
	m.verify.agentChosen = true
	m, _ = m.startVerifyAction(false)
	if len(m.verify.agentKeys) != 0 || m.verify.agentChosen {
		t.Fatalf("new discovery kept stale selection: keys=%v chosen=%v", m.verify.agentKeys, m.verify.agentChosen)
	}
	m, _, _ = m.handleVerifyMsg(verifyKeysMsg{id: m.verify.id, seq: first, keys: []sshverify.AgentKey{{Fingerprint: "old"}}})
	if len(m.verify.agentKeys) != 0 {
		t.Fatalf("an earlier listing filled the chooser: %v", m.verify.agentKeys)
	}
}
