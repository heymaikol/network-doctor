//go:build integration

package peer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func TestAuthenticatedReplayIsRejectedOnTheSocketPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := NewListener(ctx, []string{"127.0.0.1:0"}, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	p, err := decodePairing(listener.PairingCode(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	nonce := encodedByte(nonceSize, 0x41)
	message := wireMessage{
		Version: ProtocolVersion, Type: "probe", Token: encodeSecret(p.Token[:]),
		Nonce: nonce, Challenge: encodedByte(payloadSize, 0x42),
	}
	for range 2 {
		conn := dialPinnedListener(t, p)
		if err := writeMessage(ctx, conn, time.Second, message); err != nil {
			t.Fatal(err)
		}
		waitForPeerClose(t, conn)
	}
	if err := listener.server.auth.authenticate(message.Token, nonce); !errors.Is(err, errReplay) {
		t.Fatalf("recorded socket nonce = %v, want replay", err)
	}
	listener.server.mu.Lock()
	inbound, control := len(listener.server.inbound), listener.server.controlUsed
	listener.server.mu.Unlock()
	if inbound != 0 || control {
		t.Fatalf("replayed operation changed state: inbound=%d control=%t", inbound, control)
	}
	completeValidSession(t, ctx, listener)
}

func TestMalformedAuthenticatedWireInputCannotStartDiagnostics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := NewListener(ctx, []string{"127.0.0.1:0"}, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	p, err := decodePairing(listener.PairingCode(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, 4)
	binary.BigEndian.PutUint32(oversized, maxMessageSize+1)
	invalidJSON := framedPayload([]byte(`{"version":1,"type":`))
	invalidAddress := map[string]any{
		"version": 1, "type": "hello", "token": encodeSecret(p.Token[:]),
		"nonce": encodedByte(nonceSize, 1), "challenge": encodedByte(payloadSize, 2),
		"offer": map[string]any{
			"endpoints": []any{map[string]any{"address": "example.com:443", "family": FamilyIPv4}},
			"pin":       encodedByte(sha256.Size, 3), "token": encodedByte(tokenSize, 4),
		},
	}
	tests := [][]byte{
		framedValue(t, map[string]any{"version": 2, "type": "done"}),
		invalidJSON,
		oversized,
		framedValue(t, map[string]any{"version": 1, "type": "hello"}),
		framedValue(t, map[string]any{"version": 1, "type": "done", "unknown": strings.Repeat("x", 256)}),
		framedValue(t, map[string]any{"version": 1, "type": "probe", "token": "short", "nonce": "short", "challenge": "short"}),
		framedValue(t, map[string]any{"version": 1, "type": "evidence", "observations": []any{map[string]any{}, map[string]any{}, map[string]any{}}}),
		framedValue(t, invalidAddress),
	}
	for i, frame := range tests {
		conn := dialPinnedListener(t, p)
		if _, err := conn.Write(frame); err != nil {
			t.Fatalf("case %d write: %v", i, err)
		}
		waitForPeerClose(t, conn)
	}
	listener.server.mu.Lock()
	inbound, control := len(listener.server.inbound), listener.server.controlUsed
	listener.server.mu.Unlock()
	listener.server.auth.mu.Lock()
	nonces := len(listener.server.auth.nonces)
	listener.server.auth.mu.Unlock()
	if inbound != 0 || control || nonces != 0 {
		t.Fatalf("malformed input changed state: inbound=%d control=%t nonces=%d", inbound, control, nonces)
	}
	completeValidSession(t, ctx, listener)
}

func TestPinnedPeerVersionMismatchIsExplicit(t *testing.T) {
	credential, err := newCredential(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	p := pairing{
		Expires:   time.Now().Add(time.Minute),
		Endpoints: []wireEndpoint{{Address: listener.Addr().String(), Family: FamilyIPv4}},
		Pin:       credential.pin, Token: credential.token,
	}
	code, err := encodePairing(p)
	if err != nil {
		t.Fatal(err)
	}
	response := framedValue(t, map[string]any{"version": ProtocolVersion + 1, "type": "hello_ok"})
	serverDone := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, serverTLSConfig(credential))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := conn.HandshakeContext(ctx); err != nil {
			serverDone <- err
			return
		}
		if _, err := readMessage(ctx, conn, time.Second); err != nil {
			serverDone <- err
			return
		}
		_, err = conn.Write(response)
		serverDone <- err
	}()
	if _, err := Connect(context.Background(), code, Options{Timeout: time.Second}); !errors.Is(err, errVersionMismatch) {
		t.Fatalf("version mismatch = %v, want explicit version error", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestProbePhaseFailuresRemainDistinct(t *testing.T) {
	t.Run("TLS", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := listener.Accept()
			if err == nil {
				_, _ = conn.Write([]byte("not TLS"))
				_ = conn.Close()
			}
		}()
		observation := probeEndpoint(context.Background(), wireEndpoint{Address: listener.Addr().String(), Family: FamilyIPv4},
			[sha256.Size]byte{}, [tokenSize]byte{}, netip.Addr{}, time.Second, DirectionConnectorToListener)
		_ = listener.Close()
		<-done
		if !observation.TCPConnected || observation.TLSAuthenticated || observation.Cause != CauseTLSAuthenticationFailed {
			t.Fatalf("TLS observation = %+v", observation)
		}
		if err := validateObservation(observation); err != nil {
			t.Fatalf("wire validation rejected a real TLS-phase observation: %v", err)
		}
	})

	t.Run("application", func(t *testing.T) {
		credential, err := newCredential(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			raw, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer raw.Close()
			conn := tls.Server(raw, serverTLSConfig(credential))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := conn.HandshakeContext(ctx); err != nil {
				done <- err
				return
			}
			if _, err := readMessage(ctx, conn, time.Second); err != nil {
				done <- err
				return
			}
			done <- writeMessage(ctx, conn, time.Second, wireMessage{Version: ProtocolVersion, Type: "done"})
		}()
		observation := probeEndpoint(context.Background(), wireEndpoint{Address: listener.Addr().String(), Family: FamilyIPv4},
			credential.pin, credential.token, netip.Addr{}, time.Second, DirectionConnectorToListener)
		_ = listener.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !observation.TCPConnected || !observation.TLSAuthenticated || observation.ApplicationTraffic || observation.Cause != CauseApplicationTrafficFailed {
			t.Fatalf("application observation = %+v", observation)
		}
		if err := validateObservation(observation); err != nil {
			t.Fatalf("wire validation rejected a real application-phase observation: %v", err)
		}
		got := Analyze(EndpointIdentity{}, EndpointIdentity{}, []Observation{observation})
		if got.ID != DiagnosisApplicationFailure {
			t.Fatalf("application diagnosis = %+v", got)
		}
	})
}

func TestDisconnectAfterAuthenticationEndsSessionCleanly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := NewListener(ctx, []string{"127.0.0.1:0"}, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	p, err := decodePairing(listener.PairingCode(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := newCredential(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := randomEncoded(nonceSize)
	challenge, _ := randomEncoded(payloadSize)
	conn := dialPinnedListener(t, p)
	if err := writeMessage(ctx, conn, time.Second, wireMessage{
		Version: ProtocolVersion, Type: "hello", Token: encodeSecret(p.Token[:]), Nonce: nonce, Challenge: challenge,
		Offer: &wireOffer{Endpoints: []wireEndpoint{{Address: "127.0.0.1:1", Family: FamilyIPv4}}, Pin: encodeSecret(reverse.pin[:]), Token: encodeSecret(reverse.token[:])},
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := listener.Run(ctx)
		done <- err
	}()
	response, err := readMessage(ctx, conn, time.Second)
	if err != nil || response.Type != "hello_ok" {
		t.Fatalf("hello response = %+v, %v", response, err)
	}
	_ = conn.Close()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "read connector evidence") {
			t.Fatalf("disconnect error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not finish after authenticated peer disconnected")
	}
}

func TestCancellationClosesAStalledTLSHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := NewListener(ctx, []string{"127.0.0.1:0"}, Options{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := listener.Run(context.Background())
		done <- err
	}()
	raw, err := net.DialTimeout("tcp4", listener.Endpoints()[0], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	waitForConnections(t, listener.server, 1)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled TLS wait returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not cancel a stalled TLS handshake")
	}
	waitForPeerClose(t, raw)
}

func TestCancellationInterruptsAStalledApplicationRead(t *testing.T) {
	credential, err := newCredential(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requestRead := make(chan struct{})
	release := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, serverTLSConfig(credential))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if conn.HandshakeContext(ctx) != nil {
			return
		}
		if _, err := readMessage(ctx, conn, time.Second); err != nil {
			return
		}
		close(requestRead)
		<-release
	}()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan Observation, 1)
	go func() {
		result <- probeEndpoint(ctx, wireEndpoint{Address: listener.Addr().String(), Family: FamilyIPv4},
			credential.pin, credential.token, netip.Addr{}, 10*time.Second, DirectionConnectorToListener)
	}()
	select {
	case <-requestRead:
	case <-time.After(2 * time.Second):
		close(release)
		_ = listener.Close()
		t.Fatal("hostile peer did not reach the application read")
	}
	cancel()
	select {
	case observation := <-result:
		if !observation.TCPConnected || !observation.TLSAuthenticated || observation.Cause != diagnostic.ConnectionCauseCanceled {
			t.Fatalf("canceled application observation = %+v", observation)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("application read did not obey cancellation")
	}
	close(release)
	_ = listener.Close()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("hostile peer did not stop after application cancellation")
	}
}

func dialPinnedListener(t *testing.T, p pairing) *tls.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp4", p.Endpoints[0].Address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, clientTLSConfig(p.Pin))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	return conn
}

func waitForPeerClose(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer kept an invalid connection open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("peer did not close an invalid connection: %v", err)
	}
	_ = conn.Close()
}

func completeValidSession(t *testing.T, ctx context.Context, listener *Listener) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := listener.Run(ctx)
		done <- err
	}()
	if result, err := Connect(ctx, listener.PairingCode(), Options{Timeout: time.Second}); err != nil || !result.OK {
		t.Fatalf("valid session after hostile input = %+v, %v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("listener after hostile input: %v", err)
	}
}

func framedValue(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return framedPayload(payload)
}

func framedPayload(payload []byte) []byte {
	var frame bytes.Buffer
	// #nosec G115 -- tests pass only payloads far below the uint32 frame range.
	_ = binary.Write(&frame, binary.BigEndian, uint32(len(payload)))
	_, _ = frame.Write(payload)
	return frame.Bytes()
}
