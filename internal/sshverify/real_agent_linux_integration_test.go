//go:build integration && linux

package sshverify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A real ssh-agent must list its key and sign one authentication attempt.
func TestRealSSHAgentKeyVerifiesOverLoopback(t *testing.T) {
	for _, binary := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity")
	if output, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("create temporary key: %v: %s", err, output)
	}

	socket := filepath.Join(dir, "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	agentCmd := exec.CommandContext(ctx, "ssh-agent", "-D", "-a", socket)
	agentCmd.Stderr = os.Stderr
	if err := agentCmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = agentCmd.Wait()
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the temporary ssh-agent did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	add := exec.Command("ssh-add", "-q", keyPath)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("add temporary key to ssh-agent: %v: %s", err, output)
	}

	target := Target{Host: "127.0.0.1", Port: 22, User: testUser, AgentSocket: socket}
	keys, err := ListAgentKeys(context.Background(), target, Options{Timeout: 5 * time.Second})
	if err != nil || len(keys) != 1 || keys[0].Type != ssh.KeyAlgoED25519 {
		t.Fatalf("real ssh-agent keys = %+v, error %v", keys, err)
	}

	host, _ := newEd25519(t)
	s := newServer(host)
	s.cfg.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.pubkey.Add(1)
		if ssh.FingerprintSHA256(key) != keys[0].Fingerprint {
			return nil, os.ErrPermission
		}
		return nil, nil
	}
	target.Port = listenLoopback(t, s)
	trustOpenSSH(t, host.PublicKey())
	r := VerifyDirect(context.Background(), target, Attempt{Method: MethodAgent, AgentFingerprint: keys[0].Fingerprint}, Options{Timeout: 5 * time.Second})
	if r.Outcome != Verified || r.Method != MethodAgent || s.pubkey.Load() != 1 || s.opens.Load() != 0 {
		t.Fatalf("real ssh-agent verification = %+v, key attempts %d, channels %d", r, s.pubkey.Load(), s.opens.Load())
	}
}
