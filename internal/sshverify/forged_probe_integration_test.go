//go:build integration && unix

package sshverify

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// listenPerConnection serves each connection with the host key chosen by its position: the first
// connection, the probe's, presents first, and every later connection presents second. Each password
// it is offered is counted.
func listenPerConnection(t *testing.T, first, second ssh.Signer, passwords *atomic.Int32) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			signer := second
			if n.Add(1) == 1 {
				signer = first
			}
			cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
				passwords.Add(1)
				return nil, errors.New("denied")
			}}
			cfg.AddHostKey(signer)
			go func(c net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no channels")
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// An untrusted host with an empty known_hosts must not receive a password. Its first certificate's
// key ID forges a match and an acceptance line, so the probe can end at the acceptance line before
// OpenSSH's genuine refusal is read. Its second certificate carries a clean key ID equal to the one
// the probe read, so the key ID check alone does not stop the password.
func TestUntrustedHostGetsNoPasswordWhenItForgesTheProbe(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	forged := "x\" CA ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"debug1: Host '[127.0.0.1]:2622' is known and matches the ED25519-CERT host certificate.\n" +
		"Authenticated to 127.0.0.1 ([127.0.0.1]:2622) using \"none\".\n" +
		"debug1: x"
	first := certifiedSigner(t, ca, host, forged)
	second := certifiedSigner(t, ca, host, "x")
	var passwords atomic.Int32
	port := listenPerConnection(t, first, second, &passwords)

	dir := t.TempDir()
	known := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(known, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(cfg, []byte("Host 127.0.0.1\n  Port "+strconv.Itoa(port)+"\n  UserKnownHostsFile "+known+"\n  GlobalKnownHostsFile none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := sshTestArgs
	sshTestArgs = []string{"-F", cfg}
	t.Cleanup(func() { sshTestArgs = saved })
	tg, err := Resolve(context.Background(), "127.0.0.1", 0, testUser)
	if err != nil {
		t.Fatal(err)
	}

	r := Verify(context.Background(), tg, Attempt{Method: MethodPassword, Password: []byte(testPassword)}, Options{Timeout: 8 * time.Second})

	if got := passwords.Load(); got != 0 {
		t.Fatalf("an untrusted host received %d password(s) after forging the probe (outcome %q, %s)", got, r.Outcome, r.Detail)
	}
}
