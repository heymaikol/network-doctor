//go:build integration

package sshverify

// Real-socket checks. They need the integration build tag and stay on
// loopback: a server listens on 127.0.0.1 and an agent on a Unix socket in a
// private temporary directory.

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// listenLoopback serves s on a real loopback socket until the test ends.
func listenLoopback(t *testing.T, s *server) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestVerifyOverLoopbackTCP(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	port := listenLoopback(t, s)
	known := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"[127.0.0.1]:" + strconv.Itoa(port)}, host.PublicKey())
	if err := os.WriteFile(known, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tg := Target{Host: "127.0.0.1", Port: port, User: testUser, KnownHosts: []string{known}}
	opts := Options{Timeout: 5 * time.Second}
	ctx := context.Background()

	if r := Discover(ctx, tg, opts); r.Outcome != Discovered || len(r.Methods) != 1 || r.Methods[0] != "password" {
		t.Fatalf("discover over TCP = %+v", r)
	}
	if r := Verify(ctx, tg, Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts); r.Outcome != Verified {
		t.Fatalf("verify over TCP = %+v", r)
	}
	if r := Verify(ctx, tg, Attempt{Method: MethodPassword, Password: []byte(testWrongPass)}, opts); r.Outcome != Refused {
		t.Fatalf("wrong password over TCP = %+v", r)
	}
	if got := s.opens.Load(); got != 0 {
		t.Errorf("server saw %d channel opens over the real socket", got)
	}
}

// The agent path over a real Unix socket: the listing reads the socket, and
// a verification offers exactly the chosen key.
func TestAgentOverUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "nd-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, priv := newEd25519(t)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "loopback"}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()

	host, _ := newEd25519(t)
	s := newServer(host)
	s.cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.pubkey.Add(1)
		return nil, nil
	}
	port := listenLoopback(t, s)
	known := filepath.Join(dir, "known_hosts")
	line := knownhosts.Line([]string{"[127.0.0.1]:" + strconv.Itoa(port)}, host.PublicKey())
	if err := os.WriteFile(known, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tg := Target{Host: "127.0.0.1", Port: port, User: testUser, KnownHosts: []string{known}, AgentSocket: sock}

	keys, err := ListAgentKeys(context.Background(), tg, Options{})
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListAgentKeys over the socket = %v, %v", keys, err)
	}
	r := Verify(context.Background(), tg, Attempt{Method: MethodAgent, AgentFingerprint: keys[0].Fingerprint}, Options{Timeout: 5 * time.Second})
	if r.Outcome != Verified || s.pubkey.Load() != 1 {
		t.Fatalf("agent verify over the socket = %+v, key attempts %d", r, s.pubkey.Load())
	}
}
