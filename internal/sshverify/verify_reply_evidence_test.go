package sshverify

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The callback sees the same method lists after a refusal and after a reply cut short, so it
// cannot tell them apart. The library's final error can: a complete refusal ends in its own
// "unable to authenticate" error, and a cut reply ends in the read error. The verifier relies
// on that difference, and this test records both halves of it.
func TestLibraryGivesTheSameCallbackContextButADifferentErrorAfterARefusalAndAPartialReply(t *testing.T) {
	type seen struct {
		allowed, tried, partial []string
		err                     error
	}
	run := func(t *testing.T, partial bool) seen {
		t.Helper()
		host, _ := newEd25519(t)
		client, srv := bufferedPipe()
		cfg := &ssh.ServerConfig{}
		cfg.AddHostKey(host)
		cfg.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			if partial {
				_, _ = srv.Write([]byte{0, 0, 0, 40, 0, 0})
				_ = srv.Close()
				return nil, errors.New("partial")
			}
			return nil, errors.New("refused")
		}
		go func() { _, _, _, _ = ssh.NewServerConn(srv, cfg) }()

		var calls int
		var at seen
		conf := &ssh.ClientConfig{
			User:            "user",
			HostKeyCallback: ssh.FixedHostKey(host.PublicKey()),
			AuthCallback: func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
				calls++
				if calls > 1 {
					at = seen{
						allowed: append([]string(nil), ctx.AllowedMethods...),
						tried:   append([]string(nil), ctx.TriedMethods...),
						partial: append([]string(nil), ctx.PartialSuccessMethods...),
					}
					return nil, nil
				}
				return ssh.Password("pw"), nil
			},
		}
		c, _, _, err := ssh.NewClientConn(client, "evidence", conf)
		if c != nil {
			_ = c.Close()
		}
		at.err = err
		if calls < 2 {
			t.Fatalf("the callback ran %d time(s); the second call is the evidence", calls)
		}
		return at
	}

	refused := run(t, false)
	cut := run(t, true)
	t.Logf("after a refusal: allowed=%q tried=%q err=%v", refused.allowed, refused.tried, refused.err)
	t.Logf("after a partial reply: allowed=%q tried=%q err=%v", cut.allowed, cut.tried, cut.err)
	if !reflect.DeepEqual(refused.allowed, cut.allowed) || !reflect.DeepEqual(refused.tried, cut.tried) || !reflect.DeepEqual(refused.partial, cut.partial) {
		t.Fatalf("the callback context differs; the evidence no longer holds: refused=%+v cut=%+v", refused, cut)
	}
	if !isRefusal(refused.err) {
		t.Fatalf("a complete refusal did not end in the library's refusal error: %v", refused.err)
	}
	if isRefusal(cut.err) {
		t.Fatalf("a cut reply ended in the library's refusal error: %v", cut.err)
	}
	if !errors.Is(cut.err, io.ErrUnexpectedEOF) && !errors.Is(cut.err, io.EOF) {
		t.Fatalf("a cut reply did not end in a read error: %v", cut.err)
	}
}

// signalConn reports a read that returns bytes after the server has the password. Earlier reads
// carry the key exchange and the reply to "none", and they must not count. The server ends the
// connection only after the client has read its partial reply, so the test cannot pass by losing
// the bytes.
type signalConn struct {
	net.Conn
	sent <-chan struct{}
	got  chan struct{}
	once sync.Once
}

func (c *signalConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		select {
		case <-c.sent:
			c.once.Do(func() { close(c.got) })
		default:
		}
	}
	return n, err
}

// A reply that arrives in part, and then the connection ends, is no answer from the server.
func TestPartialReplyIsTransportFailure(t *testing.T) {
	host, _ := newEd25519(t)
	known := knownHostsFor(t, host.PublicKey())
	sent := make(chan struct{})
	got := make(chan struct{})
	opts := Options{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			client, srv := bufferedPipe()
			cfg := &ssh.ServerConfig{}
			cfg.AddHostKey(host)
			cfg.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
				close(sent)
				_, _ = srv.Write([]byte{0, 0, 0, 40, 0, 0}) // part of a reply
				select {
				case <-got:
				case <-time.After(5 * time.Second): // a bound for a broken run, not a timing assumption
				}
				_ = srv.Close()
				return nil, errors.New("partial")
			}
			go func() { _, _, _, _ = ssh.NewServerConn(srv, cfg) }()
			return &signalConn{Conn: client, sent: sent, got: got}, nil
		},
	}

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)
	select {
	case <-got:
	default:
		t.Fatal("the client never read the partial reply, so this run proves nothing")
	}
	if r.Outcome != TransportFailure {
		t.Fatalf("outcome = %q, want transport failure: a cut reply is not a refusal; detail %q", r.Outcome, r.Detail)
	}
}

// The server cuts its reply to "none", before the callback is offered a method. That must not
// read as "the server does not offer this method".
type cutAtWrite struct {
	net.Conn
	mu     sync.Mutex
	writes int
	at     int
}

func (c *cutAtWrite) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	hit := c.writes == c.at
	c.mu.Unlock()
	if hit {
		_, _ = c.Conn.Write(p[:6])
		_ = c.Close()
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func TestCutNoneReplyIsTransportFailureNotNotOffered(t *testing.T) {
	host, _ := newEd25519(t)
	known := knownHostsFor(t, host.PublicKey())
	opts := Options{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			client, srv := bufferedPipe()
			cfg := &ssh.ServerConfig{}
			cfg.AddHostKey(host)
			cfg.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
				return nil, errors.New("refused")
			}
			go func() { _, _, _, _ = ssh.NewServerConn(&cutAtWrite{Conn: srv, at: 7}, cfg) }()
			return client, nil
		},
	}

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)
	if r.Outcome != TransportFailure {
		t.Fatalf("outcome = %q, want transport failure; a cut reply to none is not a method list; detail %q", r.Outcome, r.Detail)
	}
}
