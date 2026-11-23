package sshverify

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A server that drops the connection before it answers the first request leaves the
// library no method list. Discovery must report that as a transport failure, not as an
// empty list that the server sent.
func TestDiscoveryDroppedBeforeMethodsIsTransportFailure(t *testing.T) {
	host, _ := newEd25519(t)
	known := knownHostsFor(t, host.PublicKey())
	opts := Options{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			client, srv := bufferedPipe()
			entered, release := make(chan struct{}, 1), make(chan struct{})
			cfg := &ssh.ServerConfig{NoClientAuth: true} // the none callback runs only with this set
			cfg.AddHostKey(host)
			cfg.NoClientAuthCallback = func(ssh.ConnMetadata) (*ssh.Permissions, error) {
				entered <- struct{}{}
				<-release // hold the none request: the server never answers it
				return nil, errors.New("late")
			}
			go func() { _, _, _, _ = ssh.NewServerConn(srv, cfg) }()
			// The connection ends while the request is held, so the client gets no reply at all.
			go func() { <-entered; _ = srv.Close(); close(release) }()
			return client, nil
		},
	}

	r := Discover(context.Background(), target(known), opts)
	if r.Outcome != TransportFailure {
		t.Fatalf("outcome = %q, want transport failure; detail %q", r.Outcome, r.Detail)
	}
	if len(r.Methods) != 0 {
		t.Errorf("methods = %q, want none, since the server sent no list", r.Methods)
	}
}
