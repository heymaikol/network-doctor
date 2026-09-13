package peer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

type memoryConn struct {
	bytes.Buffer
	deadline time.Time
}

func (conn *memoryConn) Close() error                         { return nil }
func (conn *memoryConn) LocalAddr() net.Addr                  { return testAddr("127.0.0.1:1") }
func (conn *memoryConn) RemoteAddr() net.Addr                 { return testAddr("127.0.0.1:2") }
func (conn *memoryConn) SetDeadline(deadline time.Time) error { conn.deadline = deadline; return nil }
func (conn *memoryConn) SetReadDeadline(deadline time.Time) error {
	conn.deadline = deadline
	return nil
}
func (conn *memoryConn) SetWriteDeadline(deadline time.Time) error {
	conn.deadline = deadline
	return nil
}

type testAddr string

func (address testAddr) Network() string { return "tcp" }
func (address testAddr) String() string  { return string(address) }

func encodedByte(size int, value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, size))
}

func validProbeMessage() wireMessage {
	return wireMessage{
		Version: ProtocolVersion, Type: "probe", Token: encodedByte(tokenSize, 1),
		Nonce: encodedByte(nonceSize, 2), Challenge: encodedByte(payloadSize, 3),
	}
}

func framedJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4+len(payload))
	// #nosec G115 -- json.Marshal of this fixed test value is far below uint32.
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}

func TestProtocolMessageRoundTrip(t *testing.T) {
	want := validProbeMessage()
	conn := &memoryConn{}
	if err := writeMessage(context.Background(), conn, time.Second, want); err != nil {
		t.Fatal(err)
	}
	got, err := readMessage(context.Background(), conn, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("message = %+v, want %+v", got, want)
	}
}

func TestProtocolRejectsMalformedFrames(t *testing.T) {
	invalidUTF8 := framedJSON(t, wireMessage{
		Version: ProtocolVersion, Type: "hello_ok", Nonce: encodedByte(nonceSize, 2),
		Challenge: encodedByte(payloadSize, 3), Name: "x",
	})
	invalidUTF8[bytes.LastIndex(invalidUTF8, []byte(`"x"`))+1] = 0xff
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"truncated header", []byte{0, 0}, io.ErrUnexpectedEOF},
		{"empty", []byte{0, 0, 0, 0}, errInvalidMessage},
		{"oversized", []byte{0, 1, 0, 0}, errInvalidMessage},
		{"truncated payload", []byte{0, 0, 0, 2, '{'}, io.ErrUnexpectedEOF},
		{"unknown field", framedJSON(t, map[string]any{"version": 1, "type": "done", "surprise": true}), errInvalidMessage},
		{"invalid UTF-8", invalidUTF8, errInvalidMessage},
		{"wrong version", framedJSON(t, map[string]any{"version": 2, "type": "done"}), errVersionMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &memoryConn{}
			_, _ = conn.Write(test.frame)
			_, err := readMessage(context.Background(), conn, time.Second)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestProtocolReadObeysCanceledContext(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readMessage(ctx, client, time.Second); err == nil {
		t.Fatal("read on canceled context returned no error")
	}
}

func TestProtocolReadObeysExpiredDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	if _, err := readMessage(ctx, client, time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read error = %v, want deadline exceeded", err)
	}
}

func TestParallelObservationsStartsEveryBoundedProbe(t *testing.T) {
	started := make(chan int, maxEndpointCount)
	release := make(chan struct{})
	done := make(chan []Observation, 1)
	go func() {
		done <- parallelObservations(maxEndpointCount, func(i int) Observation {
			started <- i
			<-release
			return Observation{Ms: int64(i)}
		})
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	seen := map[int]bool{}
	for range maxEndpointCount {
		select {
		case i := <-started:
			seen[i] = true
		case <-timer.C:
			close(release)
			t.Fatal("bounded family probes did not start concurrently")
		}
	}
	close(release)
	got := <-done
	if len(seen) != maxEndpointCount || len(got) != maxEndpointCount || got[0].Ms != 0 || got[1].Ms != 1 {
		t.Fatalf("parallel observations = %+v; started = %v", got, seen)
	}
}

func TestEvidenceWaitLeavesRoomForTheBoundedPeerProbe(t *testing.T) {
	if got := evidenceWait(time.Second); got != 3*time.Second {
		t.Fatalf("evidence wait = %s, want 3s", got)
	}
	if got := evidenceWait(MaxOperationTimeout); got != SessionLifetime {
		t.Fatalf("maximum evidence wait = %s, want %s", got, SessionLifetime)
	}
}

func TestEvidenceVerifierAcceptsOnlyUnobservedPeerAddresses(t *testing.T) {
	server := &endpointServer{inbound: map[string]Observation{}}
	reported := []Observation{{
		Direction: DirectionListenerToConnector, Family: FamilyIPv6,
		Status: "N/A", Cause: CausePeerAddressUnverified,
	}}
	if _, err := server.verifyReported(reported, DirectionListenerToConnector); err != nil {
		t.Fatalf("unverified address: %v", err)
	}
	server.inbound[FamilyIPv6] = pass(DirectionListenerToConnector, FamilyIPv6)
	if _, err := server.verifyReported(reported, DirectionListenerToConnector); !errors.Is(err, errInvalidMessage) {
		t.Fatalf("unverified address with an observed connection = %v, want invalid message", err)
	}
}

func TestPairingRoundTripAndVersionHandling(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	want := pairing{
		Expires: now.Add(time.Minute),
		Endpoints: []wireEndpoint{
			{Address: "192.0.2.10:4242", Family: FamilyIPv4},
			{Address: "[2001:db8::10]:4242", Family: FamilyIPv6},
		},
	}
	copy(want.Pin[:], bytes.Repeat([]byte{4}, sha256.Size))
	copy(want.Token[:], bytes.Repeat([]byte{5}, tokenSize))
	code, err := encodePairing(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodePairing(code, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Expires != want.Expires || !bytes.Equal(got.Pin[:], want.Pin[:]) || !bytes.Equal(got.Token[:], want.Token[:]) || len(got.Endpoints) != 2 {
		t.Fatalf("decoded pairing = %+v", got)
	}
	if _, err := decodePairing(strings.Replace(code, pairingPrefix, "ndp2.", 1), now); !errors.Is(err, errVersionMismatch) {
		t.Fatalf("new protocol prefix error = %v, want version mismatch", err)
	}
	if _, err := decodePairing(code, want.Expires); !errors.Is(err, errExpiredPairing) {
		t.Fatalf("stale pairing error = %v, want expired", err)
	}
}

func TestPairingRejectsInvalidEndpoints(t *testing.T) {
	for _, address := range []string{"", ":0", "0.0.0.0:1", "255.255.255.255:1", "example.com:1", "127.0.0.1", "127.0.0.1:65536"} {
		if _, _, err := NormalizeListenAddress(address); err == nil {
			t.Errorf("NormalizeListenAddress(%q) returned no error", address)
		}
	}
	if address, family, err := NormalizeListenAddress("[2001:db8::1]:0"); err != nil || address != "[2001:db8::1]:0" || family != FamilyIPv6 {
		t.Fatalf("IPv6 listen address = %q, %q, %v", address, family, err)
	}
}

func TestConnectorBindsScopeAnInterfaceLinkLocalSource(t *testing.T) {
	endpoints := []wireEndpoint{{Address: "[fe80::1%eth0]:4242", Family: FamilyIPv6}}
	binds, err := connectorBinds(context.Background(), endpoints,
		&diagnostic.SourceAddresses{IPv6: net.ParseIP("fe80::2"), Iface: "eth0"}, time.Second)
	if err != nil || len(binds) != 1 || binds[0] != "[fe80::2%eth0]:0" {
		t.Fatalf("reverse binds = %v, %v, want [fe80::2%%eth0]:0", binds, err)
	}
	// Without a named interface the link-local source cannot be advertised as
	// an endpoint, so it yields no reverse listener rather than a broken one.
	if binds, err := connectorBinds(context.Background(), endpoints,
		&diagnostic.SourceAddresses{IPv6: net.ParseIP("fe80::2")}, time.Second); err == nil {
		t.Fatalf("unscoped link-local source produced binds %v", binds)
	}
}

func TestAuthenticatorRejectsWrongAndReplayedCredentials(t *testing.T) {
	var token [tokenSize]byte
	copy(token[:], bytes.Repeat([]byte{7}, tokenSize))
	auth := authenticator{token: token}
	nonce := encodedByte(nonceSize, 8)
	if err := auth.authenticate(encodedByte(tokenSize, 9), nonce); !errors.Is(err, errAuthentication) {
		t.Fatalf("wrong token error = %v", err)
	}
	if err := auth.authenticate(encodedByte(tokenSize, 7), nonce); err != nil {
		t.Fatalf("valid auth: %v", err)
	}
	if err := auth.authenticate(encodedByte(tokenSize, 7), nonce); !errors.Is(err, errReplay) {
		t.Fatalf("replay error = %v, want replay", err)
	}
}

func TestAuthenticatorBoundsExchanges(t *testing.T) {
	var token [tokenSize]byte
	auth := authenticator{token: token}
	encodedToken := encodeSecret(token[:])
	for i := range maxConnections {
		if err := auth.authenticate(encodedToken, encodedByte(nonceSize, byte(i))); err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
	}
	if err := auth.authenticate(encodedToken, encodedByte(nonceSize, 0xff)); !errors.Is(err, errTooManyExchanges) {
		t.Fatalf("exchange beyond cap = %v", err)
	}
}

func TestCertificatePinAuthenticatesTheExpectedPeerOnly(t *testing.T) {
	certificate := &x509.Certificate{Raw: []byte("one ephemeral certificate")}
	pin := sha256.Sum256(certificate.Raw)
	verify := clientTLSConfig(pin).VerifyConnection
	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}); err != nil {
		t.Fatalf("correct pin: %v", err)
	}
	wrong := sha256.Sum256([]byte("another certificate"))
	if err := clientTLSConfig(wrong).VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}); !errors.Is(err, errAuthentication) {
		t.Fatalf("wrong pin error = %v", err)
	}
}

func TestSessionCredentialsAreFreshAndRequireTLS13(t *testing.T) {
	first, err := newCredential(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := newCredential(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.pin[:], second.pin[:]) || bytes.Equal(first.token[:], second.token[:]) {
		t.Fatal("two sessions reused certificate or token material")
	}
	if serverTLSConfig(first).MinVersion != tls.VersionTLS13 || clientTLSConfig(first.pin).MinVersion != tls.VersionTLS13 {
		t.Fatal("peer TLS minimum is not TLS 1.3")
	}
}

func TestErrorsDoNotContainPairingSecrets(t *testing.T) {
	secret := encodedByte(tokenSize, 0x5a)
	message := validProbeMessage()
	message.Token = secret
	message.Nonce = "bad"
	if err := validateMessage(message); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("validation error = %q, want safe error", err)
	}
	observation := Observation{
		Direction: DirectionConnectorToListener, Family: FamilyIPv4,
		Status: "FAIL", Cause: "\x1b]52;c;aGk=\a", Destination: "127.0.0.1:1",
	}
	if err := validateObservation(observation); err == nil {
		t.Fatal("peer-controlled cause outside the fixed vocabulary was accepted")
	}
}

func FuzzDecodeMessage(f *testing.F) {
	payload, _ := json.Marshal(map[string]any{"version": 1, "type": "done"})
	frame := make([]byte, 4+len(payload))
	// #nosec G115 -- json.Marshal of this fixed fuzz seed is far below uint32.
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	f.Add(frame)
	f.Add([]byte{0, 0, 0, 1, '{'})
	pairingCode, _ := encodePairing(pairing{
		Expires:   time.Unix(1_800_000_060, 0),
		Endpoints: []wireEndpoint{{Address: "127.0.0.1:1", Family: FamilyIPv4}},
	})
	f.Add([]byte(pairingCode))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxMessageSize+4 {
			data = data[:maxMessageSize+4]
		}
		conn := &memoryConn{}
		_, _ = conn.Write(data)
		_, _ = readMessage(context.Background(), conn, time.Second)
		_, _ = decodePairing(string(data), time.Unix(1_800_000_000, 0))
	})
}

func TestEndpointsCarryTheIPv6LinkLocalZone(t *testing.T) {
	// A link-local address names a destination only together with the
	// interface scope, so the scoped form is the usable one and the bare
	// form is not. Windows writes that scope as a number.
	for _, address := range []string{"[fe80::1%eth0]:4242", "[fe80::1%12]:4242", "[fe80::1%eth0]:0"} {
		got, family, err := NormalizeListenAddress(address)
		if err != nil || got != address || family != FamilyIPv6 {
			t.Errorf("NormalizeListenAddress(%q) = %q, %q, %v", address, got, family, err)
		}
	}
	for _, address := range []string{
		"[fe80::1]:4242", "[fe80::1%]:4242", "[fe80::1%eth 0]:4242", "[fe80::1%\x1b]0;x\a]:4242",
		"[2001:db8::1%eth0]:4242", "[::1%lo]:4242", "[::ffff:169.254.1.1%eth0]:4242",
	} {
		if _, _, err := NormalizeListenAddress(address); err == nil {
			t.Errorf("NormalizeListenAddress(%q) returned no error", address)
		}
	}
	scoped := "[fe80::1%eth0]:4242"
	if family := familyForAddress(scoped); family != FamilyIPv6 {
		t.Errorf("familyForAddress(%q) = %q, want %q", scoped, family, FamilyIPv6)
	}
	now := time.Unix(1_800_000_000, 0)
	code, err := encodePairing(pairing{
		Expires:   now.Add(time.Minute),
		Endpoints: []wireEndpoint{{Address: scoped, Family: FamilyIPv6}},
	})
	if err != nil {
		t.Fatalf("encode scoped pairing: %v", err)
	}
	got, err := decodePairing(code, now)
	if err != nil || len(got.Endpoints) != 1 || got.Endpoints[0].Address != scoped {
		t.Fatalf("decoded scoped pairing = %+v, %v", got.Endpoints, err)
	}
	if err := validateOffer(wireOffer{
		Endpoints: []wireEndpoint{{Address: scoped, Family: FamilyIPv6}},
		Pin:       encodedByte(sha256.Size, 1), Token: encodedByte(tokenSize, 2),
	}); err != nil {
		t.Fatalf("scoped endpoint in an offer: %v", err)
	}
	// The zone has to reach the host-level views too: the source a probe
	// binds to and the peer address the reverse probe dials.
	server := &endpointServer{
		endpoints: []wireEndpoint{{Address: scoped, Family: FamilyIPv6}},
		inbound:   map[string]Observation{FamilyIPv6: {Source: "[fe80::2%eth0]:5"}},
	}
	if source := server.sourceIPs()[FamilyIPv6]; source.String() != "fe80::1%eth0" {
		t.Errorf("bind source = %q, want fe80::1%%eth0", source)
	}
	if remote := server.observedRemoteIPs(netip.Addr{})[FamilyIPv6]; remote.String() != "fe80::2%eth0" {
		t.Errorf("observed peer = %q, want fe80::2%%eth0", remote)
	}
	// A listening socket reports a scoped bind back without its zone, and that
	// bare address is not connectable, so the advertised endpoint restores it.
	if got := advertisedEndpoint("[fe80::1%eth0]:0", "[fe80::1]:38825"); got != "[fe80::1%eth0]:38825" {
		t.Errorf("advertised scoped endpoint = %q, want [fe80::1%%eth0]:38825", got)
	}
	if got := advertisedEndpoint("192.0.2.10:0", "192.0.2.10:38825"); got != "192.0.2.10:38825" {
		t.Errorf("advertised endpoint = %q, want 192.0.2.10:38825", got)
	}
}

// producerCauses restates, from the producer and not from the validator, the
// causes a v1 endpoint can record once it has stopped where these two phase
// booleans say it stopped. dialPeerTLS either never connects, or connects and
// fails the pinned TLS handshake; only probeEndpoint, on an authenticated
// connection, can fail the fixed payload exchange. A bounded deadline or a
// canceled session ends any of the three, so those two belong everywhere.
func producerCauses(tcpConnected, tlsAuthenticated bool) []string {
	shared := []string{diagnostic.ConnectionCauseTimeout, diagnostic.ConnectionCauseCanceled}
	switch {
	case tlsAuthenticated:
		return append(shared, CauseApplicationTrafficFailed)
	case tcpConnected:
		return append(shared, CauseTLSAuthenticationFailed)
	default:
		return append(shared, diagnostic.ConnectionCauseRefused, diagnostic.ConnectionCauseUnreachable)
	}
}

// producerCanEmit describes one wire observation the producers can actually
// build. It is written from dialPeerTLS, probeEndpoint, probeOffer and
// markPass so that it disagrees with validateObservation whenever either one
// drifts away from the protocol contract.
func producerCanEmit(observation Observation, sourceFamily, destinationFamily string) bool {
	if observation.Direction != DirectionListenerToConnector && observation.Direction != DirectionConnectorToListener {
		return false
	}
	if observation.Family != FamilyIPv4 && observation.Family != FamilyIPv6 {
		return false
	}
	if observation.Status == diagnostic.StatusNA.String() {
		// An untested family measures nothing: probeOffer reports an
		// unverified peer address, and completeObservations fills in a family
		// that was never dialed. Neither records an attempt.
		return (observation.Cause == CausePeerAddressUnverified || observation.Cause == CauseFamilyUnavailable) &&
			observation.Source == "" && observation.Destination == "" &&
			!observation.TCPConnected && !observation.TLSAuthenticated && !observation.ApplicationTraffic &&
			observation.PayloadBytes == 0 && observation.Ms == 0
	}
	// Every tested row comes from a dial. dialPeerTLS names the destination
	// before it connects, adds the local socket exactly when the connection is
	// established, and dials one family over tcp4 or tcp6, so both socket
	// endpoints belong to the family the row is filed under.
	if observation.Destination == "" || destinationFamily != observation.Family {
		return false
	}
	if observation.TCPConnected != (observation.Source != "") ||
		observation.Source != "" && sourceFamily != observation.Family {
		return false
	}
	if observation.TLSAuthenticated && !observation.TCPConnected {
		return false
	}
	switch observation.Status {
	case diagnostic.StatusPass.String():
		// markPass runs only on an authenticated connection that completed the
		// fixed exchange, and it clears the cause.
		return observation.Cause == "" && observation.TCPConnected && observation.TLSAuthenticated &&
			observation.ApplicationTraffic && observation.PayloadBytes == payloadSize
	case diagnostic.StatusFail.String():
		return !observation.ApplicationTraffic && observation.PayloadBytes == 0 &&
			slices.Contains(producerCauses(observation.TCPConnected, observation.TLSAuthenticated), observation.Cause)
	default:
		return false
	}
}

func TestObservationValidatorAcceptsExactlyTheProducerStates(t *testing.T) {
	// The family travels with each spelling so the expectation never depends
	// on the parser the validator uses. An IPv4-mapped address is the IPv4
	// address it carries, and a link-local address keeps its zone.
	endpoints := []struct{ address, family string }{
		{"", ""},
		{"192.0.2.10:4242", FamilyIPv4},
		{"[2001:db8::10]:4242", FamilyIPv6},
		{"[::ffff:192.0.2.10]:4242", FamilyIPv4},
		{"[fe80::10%eth0]:4242", FamilyIPv6},
	}
	causes := []string{
		"", CauseFamilyUnavailable, CausePeerAddressUnverified, CauseTLSAuthenticationFailed,
		CauseApplicationTrafficFailed, diagnostic.ConnectionCauseRefused, diagnostic.ConnectionCauseUnreachable,
		diagnostic.ConnectionCauseTimeout, diagnostic.ConnectionCauseCanceled, diagnostic.ConnectionCauseReset,
	}
	booleans := []bool{false, true}
	var states []Observation
	for _, status := range []string{"PASS", "FAIL", "N/A", "SKIP"} {
		for _, cause := range causes {
			for _, tcpConnected := range booleans {
				for _, tlsAuthenticated := range booleans {
					for _, applicationTraffic := range booleans {
						for _, payload := range []int{0, payloadSize} {
							for _, ms := range []int64{0, 1} {
								states = append(states, Observation{
									Status: status, Cause: cause, TCPConnected: tcpConnected,
									TLSAuthenticated: tlsAuthenticated, ApplicationTraffic: applicationTraffic,
									PayloadBytes: payload, Ms: ms,
								})
							}
						}
					}
				}
			}
		}
	}
	accepted := map[string]bool{}
	for _, family := range []string{FamilyIPv4, FamilyIPv6} {
		for _, source := range endpoints {
			for _, destination := range endpoints {
				for _, state := range states {
					observation := state
					observation.Direction = DirectionConnectorToListener
					observation.Family = family
					observation.Source, observation.Destination = source.address, destination.address
					want := producerCanEmit(observation, source.family, destination.family)
					if got := validateObservation(observation) == nil; got != want {
						t.Fatalf("validateObservation(%+v) accepted = %v, want %v", observation, got, want)
					}
					if want {
						accepted[observation.Status+"/"+observation.Cause+"/"+
							strconv.FormatBool(observation.TCPConnected)+"/"+strconv.FormatBool(observation.TLSAuthenticated)] = true
					}
				}
			}
		}
	}
	// Every state the producer reaches has to remain reachable, so an
	// over-restrictive validator fails here rather than silently discarding
	// honest peer evidence.
	want := map[string]bool{
		"PASS//true/true":                           true,
		"FAIL/connection_refused/false/false":       true,
		"FAIL/unreachable/false/false":              true,
		"FAIL/timeout/false/false":                  true,
		"FAIL/canceled/false/false":                 true,
		"FAIL/tls_authentication_failed/true/false": true,
		"FAIL/timeout/true/false":                   true,
		"FAIL/canceled/true/false":                  true,
		"FAIL/application_traffic_failed/true/true": true,
		"FAIL/timeout/true/true":                    true,
		"FAIL/canceled/true/true":                   true,
		"N/A/family_unavailable/false/false":        true,
		"N/A/peer_address_unverified/false/false":   true,
	}
	if !maps.Equal(accepted, want) {
		t.Fatalf("accepted producer states = %v, want %v", slices.Sorted(maps.Keys(accepted)), slices.Sorted(maps.Keys(want)))
	}
}

func TestObservationValidatorBoundsMeasurements(t *testing.T) {
	valid := Observation{
		Direction: DirectionConnectorToListener, Family: FamilyIPv4, Destination: "192.0.2.10:4242",
		Status: "FAIL", Cause: diagnostic.ConnectionCauseRefused, Ms: 1,
	}
	if err := validateObservation(valid); err != nil {
		t.Fatalf("refused observation: %v", err)
	}
	for name, mutate := range map[string]func(*Observation){
		"negative duration":         func(o *Observation) { o.Ms = -1 },
		"duration past the session": func(o *Observation) { o.Ms = SessionLifetime.Milliseconds() + 1 },
		"oversized cause":           func(o *Observation) { o.Cause = strings.Repeat("x", 49) },
		"oversized endpoint":        func(o *Observation) { o.Destination = strings.Repeat("x", maxEndpointSize+1) },
		"negative payload":          func(o *Observation) { o.PayloadBytes = -1 },
		"unusable endpoint port":    func(o *Observation) { o.Destination = "192.0.2.10:0" },
	} {
		observation := valid
		mutate(&observation)
		if err := validateObservation(observation); !errors.Is(err, errInvalidMessage) {
			t.Errorf("%s error = %v, want invalid message", name, err)
		}
	}
}

func TestContradictoryEvidenceCannotReachTheDiagnosis(t *testing.T) {
	listenerIdentity := EndpointIdentity{Role: RoleListener, ListenAddresses: []string{"192.0.2.1:4242"}}
	connectorIdentity := EndpointIdentity{Role: RoleConnector, ListenAddresses: []string{"192.0.2.2:4242"}}
	observedInbound := Observation{Source: "192.0.2.2:5000", Destination: "192.0.2.1:4242"}
	refusedAfterTLS := Observation{
		Direction: DirectionConnectorToListener, Family: FamilyIPv4,
		Source: "192.0.2.2:5000", Destination: "192.0.2.1:4242", Status: "FAIL",
		Cause: diagnostic.ConnectionCauseRefused, TCPConnected: true, TLSAuthenticated: true, Ms: 5,
	}
	mislabeledFamily := Observation{
		Direction: DirectionConnectorToListener, Family: FamilyIPv6,
		Source: "192.0.2.2:5001", Destination: "192.0.2.1:4242", Status: "FAIL",
		Cause: CauseConnectionUnreachable, TCPConnected: true, Ms: 5,
	}
	honestRefusal := Observation{
		Direction: DirectionConnectorToListener, Family: FamilyIPv4, Destination: "192.0.2.1:4242",
		Status: "FAIL", Cause: diagnostic.ConnectionCauseRefused, Ms: 5,
	}
	honestPass := Observation{
		Direction: DirectionConnectorToListener, Family: FamilyIPv4,
		Source: "192.0.2.2:5000", Destination: "192.0.2.1:4242", Status: "PASS",
		TCPConnected: true, TLSAuthenticated: true, ApplicationTraffic: true, PayloadBytes: payloadSize, Ms: 5,
	}
	tests := []struct {
		name        string
		contradicts Observation
		honest      []Observation
		inbound     map[string]Observation
		wantID      string
		wantVerdict string
	}{
		{
			// A refused connection never reached an endpoint, so it cannot
			// also have connected and authenticated TLS. Analyze reads those
			// phase booleans, so the row used to be read as a working
			// connection whose application failed.
			name:        "connection refusal after authenticated TLS",
			contradicts: refusedAfterTLS, honest: []Observation{honestRefusal},
			wantID: DiagnosisDirectionalFailure, wantVerdict: diagnostic.VerdictService,
		},
		{
			// Both socket endpoints are IPv4, so this row measured IPv4. Filed
			// under IPv6 it used to invent a second tested family and turn a
			// healthy session into an address-family asymmetry.
			name:        "IPv6 row carrying the IPv4 socket pair",
			contradicts: mislabeledFamily, honest: []Observation{honestPass},
			inbound: map[string]Observation{FamilyIPv4: observedInbound},
			wantID:  DiagnosisBidirectionalOK, wantVerdict: diagnostic.VerdictOK,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateObservation(test.contradicts); !errors.Is(err, errInvalidMessage) {
				t.Fatalf("contradictory observation error = %v, want invalid message", err)
			}
			// The attack arrives as bytes, so the read side has to refuse it
			// before verifyReported or Analyze ever see it.
			conn := &memoryConn{}
			_, _ = conn.Write(framedJSON(t, wireMessage{
				Version: ProtocolVersion, Type: "evidence", Observations: []Observation{test.contradicts},
			}))
			if _, err := readMessage(context.Background(), conn, time.Second); !errors.Is(err, errInvalidMessage) {
				t.Fatalf("wire evidence error = %v, want invalid message", err)
			}
			// The honest report of the same session still reaches its
			// diagnosis through the real verifier.
			inbound := test.inbound
			if inbound == nil {
				inbound = map[string]Observation{}
			}
			server := &endpointServer{inbound: inbound}
			verified, err := server.verifyReported(test.honest, DirectionConnectorToListener)
			if err != nil {
				t.Fatalf("honest evidence: %v", err)
			}
			got := Analyze(listenerIdentity, connectorIdentity,
				append([]Observation{pass(DirectionListenerToConnector, FamilyIPv4)}, verified...))
			if got.ID != test.wantID || got.Verdict != test.wantVerdict {
				t.Fatalf("honest diagnosis = %s/%s, want %s/%s", got.ID, got.Verdict, test.wantID, test.wantVerdict)
			}
		})
	}
}
