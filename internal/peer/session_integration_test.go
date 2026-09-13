//go:build integration

package peer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPeerSessionLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := NewListener(ctx, []string{"127.0.0.1:0"}, Options{Name: "machine-a", Version: "test", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	pairingCode := listener.PairingCode()
	pairing, err := decodePairing(pairingCode, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		result Result
		err    error
	}
	listenerDone := make(chan outcome, 1)
	go func() {
		result, err := listener.Run(ctx)
		listenerDone <- outcome{result, err}
	}()
	connector, err := Connect(ctx, pairingCode, Options{Name: "machine-b", Version: "test", Timeout: time.Second})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	listening := <-listenerDone
	if listening.err != nil {
		t.Fatalf("listen: %v", listening.err)
	}
	for role, result := range map[string]Result{"listener": listening.result, "connector": connector} {
		if !result.OK || result.Diagnosis.ID != DiagnosisBidirectionalOK {
			t.Errorf("%s result = %+v", role, result)
		}
		passes := 0
		for _, observation := range result.Observations {
			if err := validateObservation(observation); err != nil {
				t.Errorf("%s observation fails wire validation: %+v: %v", role, observation, err)
			}
			if observation.Status == "PASS" {
				passes++
				if !observation.TCPConnected || !observation.TLSAuthenticated || !observation.ApplicationTraffic || observation.PayloadBytes != payloadSize {
					t.Errorf("%s incomplete pass evidence: %+v", role, observation)
				}
			}
		}
		if passes != 2 {
			t.Errorf("%s pass count = %d, want two IPv4 directions", role, passes)
		}
	}
	if connector.Local.Name != "machine-b" || connector.Remote.Name != "machine-a" || listening.result.Local.Name != "machine-a" {
		t.Errorf("endpoint identities: listener %+v, connector %+v", listening.result, connector)
	}

	for role, result := range map[string]Result{"listener": listening.result, "connector": connector} {
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{pairingCode, strings.TrimPrefix(pairingCode, pairingPrefix), encodeSecret(pairing.Pin[:]), encodeSecret(pairing.Token[:])} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Errorf("%s result leaked pairing credential", role)
			}
		}
	}
}

func TestPeerSessionDualStackLoopback(t *testing.T) {
	preflight, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	_ = preflight.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := NewListener(ctx, []string{"127.0.0.1:0", "[::1]:0"}, Options{Name: "dual-a", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	done := make(chan error, 1)
	go func() {
		_, err := listener.Run(ctx)
		done <- err
	}()
	result, err := Connect(ctx, listener.PairingCode(), Options{Name: "dual-b", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !result.OK || len(result.Observations) != 4 {
		t.Fatalf("dual-stack result = %+v", result)
	}
	for _, observation := range result.Observations {
		if observation.Status != "PASS" {
			t.Errorf("dual-stack observation = %+v", observation)
		}
		// Both families carry real socket endpoints here, so this is where a
		// validator that misjudges an address family stops the session.
		if err := validateObservation(observation); err != nil {
			t.Errorf("dual-stack observation fails wire validation: %+v: %v", observation, err)
		}
	}
}

func TestWrongCredentialDoesNotConsumeListenerSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := NewListener(ctx, []string{"127.0.0.1:0"}, Options{Name: "listener", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	wrong, err := decodePairing(listener.PairingCode(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrong.Token[0] ^= 0xff
	wrongCode, err := encodePairing(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Connect(ctx, wrongCode, Options{Name: "wrong", Timeout: 500 * time.Millisecond}); err == nil {
		t.Fatal("wrong credential connected")
	} else if strings.Contains(err.Error(), encodeSecret(wrong.Token[:])) {
		t.Fatalf("error leaked credential: %v", err)
	}
	listener.server.mu.Lock()
	inbound, control := len(listener.server.inbound), listener.server.controlUsed
	listener.server.mu.Unlock()
	listener.server.auth.mu.Lock()
	nonces := len(listener.server.auth.nonces)
	listener.server.auth.mu.Unlock()
	if inbound != 0 || control || nonces != 0 {
		t.Fatalf("wrong credential started diagnostics: inbound=%d control=%t nonces=%d", inbound, control, nonces)
	}

	listenerDone := make(chan error, 1)
	go func() {
		_, err := listener.Run(ctx)
		listenerDone <- err
	}()
	if _, err := Connect(ctx, listener.PairingCode(), Options{Name: "right", Timeout: time.Second}); err != nil {
		t.Fatalf("valid credential after rejection: %v", err)
	}
	if err := <-listenerDone; err != nil {
		t.Fatalf("listener after rejection: %v", err)
	}
}

func TestListenerCancellationClosesWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := NewListener(ctx, []string{"127.0.0.1:0"}, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := listener.Run(context.Background()); err == nil {
		t.Fatal("canceled listener returned no error")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionCapRejectsExcessWithoutEndingSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := NewListener(ctx, []string{"127.0.0.1:0"}, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	connections := make([]net.Conn, 0, maxConnections)
	for range maxConnections {
		conn, err := net.DialTimeout("tcp4", listener.Endpoints()[0], time.Second)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	waitForConnections(t, listener.server, maxConnections)
	extra, err := net.DialTimeout("tcp4", listener.Endpoints()[0], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	waitForPeerClose(t, extra)
	if listener.server.ctx.Err() != nil {
		t.Fatal("excess unauthenticated connection ended the listener")
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	waitForConnections(t, listener.server, 0)
	done := make(chan error, 1)
	go func() {
		_, err := listener.Run(ctx)
		done <- err
	}()
	if _, err := Connect(ctx, listener.PairingCode(), Options{Name: "valid", Timeout: time.Second}); err != nil {
		t.Fatalf("valid session after excess connection: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("listener after excess connection: %v", err)
	}
}

func TestDuplicateControlAttemptsAllowOneSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := NewListener(ctx, []string{"127.0.0.1:0"}, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	listenerDone := make(chan error, 1)
	go func() {
		_, err := listener.Run(ctx)
		listenerDone <- err
	}()

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := Connect(ctx, listener.PairingCode(), Options{Timeout: time.Second})
			results <- err
		}()
	}
	close(start)
	succeeded := 0
	for range 2 {
		if err := <-results; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful connector count = %d, want one", succeeded)
	}
	if err := <-listenerDone; err != nil {
		t.Fatalf("listener with duplicate connector: %v", err)
	}
}

func waitForConnections(t *testing.T, server *endpointServer, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.mu.Lock()
		got := len(server.connections)
		server.mu.Unlock()
		if got == want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("tracked connections did not reach %d", want)
}

func TestReverseProbeDoesNotDialAnUnverifiedPeerAddress(t *testing.T) {
	victim, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan bool, 1)
	go func() {
		conn, err := victim.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err == nil
	}()
	address := victim.Addr().String()
	observations := probeOffer(context.Background(), []wireEndpoint{{Address: address, Family: FamilyIPv4}},
		[sha256.Size]byte{}, [tokenSize]byte{}, nil, nil, time.Second, DirectionListenerToConnector)
	_ = victim.Close()
	if <-accepted {
		t.Fatal("an unverified peer offer received a TCP connection")
	}
	if len(observations) != 1 || observations[0].Status != "N/A" || observations[0].Cause != CausePeerAddressUnverified {
		t.Fatalf("observations = %+v, want an unverified address result", observations)
	}
}
