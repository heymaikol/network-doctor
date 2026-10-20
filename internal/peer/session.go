package peer

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// Options contains local, bounded session settings. Version is the netdoc
// build version written into the peer-specific result, not the wire version.
type Options struct {
	Name    string
	Version string
	Timeout time.Duration
	Sources *diagnostic.SourceAddresses
}

// Listener is one freshly authenticated peer session. It accepts one control
// connection and at most the bounded family probes belonging to that session.
type Listener struct {
	server      *endpointServer
	pairingCode string
	expires     time.Time
	options     Options
	runOnce     sync.Once
	runResult   Result
	runErr      error
	expiryTimer *time.Timer
	closeOnce   sync.Once
	closeErr    error
	pairingMu   sync.RWMutex
}

// NewListener binds the exact addresses supplied by --peer-listen and creates
// a fresh certificate and token. No credential is persisted.
func NewListener(ctx context.Context, addresses []string, options Options) (*Listener, error) {
	options = normalizeOptions(options)
	if options.Timeout > MaxOperationTimeout {
		return nil, fmt.Errorf("peer timeout cannot exceed %s", MaxOperationTimeout)
	}
	now := time.Now()
	expires := now.Add(PairingLifetime)
	server, err := newEndpointServer(ctx, addresses, options, true, DirectionConnectorToListener)
	if err != nil {
		return nil, err
	}
	p := pairing{Expires: expires, Endpoints: server.endpoints, Pin: server.credential.pin, Token: server.credential.token}
	code, err := encodePairing(p)
	if err != nil {
		_ = server.Close()
		return nil, err
	}
	listener := &Listener{server: server, pairingCode: code, expires: expires, options: options}
	listener.expiryTimer = time.AfterFunc(PairingLifetime, func() { _ = listener.Close() })
	return listener, nil
}

// PairingCode is the printable, short-lived direct-connect credential.
func (listener *Listener) PairingCode() string {
	listener.pairingMu.RLock()
	defer listener.pairingMu.RUnlock()
	return listener.pairingCode
}

// Endpoints are the exact direct addresses embedded in the pairing string.
func (listener *Listener) Endpoints() []string { return endpointAddresses(listener.server.endpoints) }

// Expires reports when the listener and its pairing credential stop working.
func (listener *Listener) Expires() time.Time { return listener.expires }

// Close ends the session and invalidates its in-memory credential.
func (listener *Listener) Close() error {
	listener.closeOnce.Do(func() {
		if listener.expiryTimer != nil {
			listener.expiryTimer.Stop()
		}
		listener.closeErr = listener.server.Close()
		listener.pairingMu.Lock()
		listener.pairingCode = ""
		listener.pairingMu.Unlock()
	})
	return listener.closeErr
}

// Run waits for the one authenticated connector, performs the reverse probes,
// exchanges structural evidence, and returns the listener's local view.
func (listener *Listener) Run(ctx context.Context) (Result, error) {
	listener.runOnce.Do(func() {
		listener.runResult, listener.runErr = listener.run(ctx)
		listener.runErr = errors.Join(listener.runErr, listener.Close())
	})
	return listener.runResult, listener.runErr
}

func (listener *Listener) run(ctx context.Context) (Result, error) {
	select {
	case control := <-listener.server.controls:
		listener.expiryTimer.Stop()
		defer control.close()
		return listener.runControl(ctx, control)
	case err := <-listener.server.fatal:
		return Result{}, err
	case <-listener.server.ctx.Done():
		return Result{}, listener.server.ctx.Err()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

func (listener *Listener) runControl(parent context.Context, control acceptedControl) (Result, error) {
	ctx, cancel := sessionContext(parent, listener.server.ctx)
	defer cancel()
	hello := control.message
	if hello.Type != "hello" || hello.Offer == nil {
		return Result{}, errInvalidMessage
	}
	challenge := hello.Challenge
	if err := writeMessage(ctx, control.conn, listener.options.Timeout, wireMessage{
		Version: ProtocolVersion, Type: "hello_ok", Nonce: hello.Nonce,
		Challenge: challenge, Name: listener.server.name,
	}); err != nil {
		return Result{}, safeSessionError("answer peer hello", err)
	}
	control.ms = sessionMs(control.started)
	clientEvidence, err := readMessage(ctx, control.conn, evidenceWait(listener.options.Timeout))
	if err != nil || clientEvidence.Type != "evidence" {
		return Result{}, safeSessionError("read connector evidence", err)
	}
	connectorToListener, err := listener.server.verifyReported(clientEvidence.Observations, DirectionConnectorToListener)
	if err != nil {
		return Result{}, err
	}

	pin, token, err := credentialFromOffer(*hello.Offer)
	if err != nil {
		return Result{}, err
	}
	listenerToConnector := probeOffer(ctx, hello.Offer.Endpoints, pin, token, listener.server.sourceIPs(),
		listener.server.observedRemoteIPs(control.remoteIP()), listener.options.Timeout, DirectionListenerToConnector)
	if err := writeMessage(ctx, control.conn, listener.options.Timeout, wireMessage{
		Version: ProtocolVersion, Type: "evidence", Observations: listenerToConnector,
	}); err != nil {
		return Result{}, safeSessionError("send listener evidence", err)
	}
	done, err := readMessage(ctx, control.conn, listener.options.Timeout)
	if err != nil || done.Type != "done" {
		return Result{}, safeSessionError("finish peer session", err)
	}

	listenerIdentity := listener.server.identity(RoleListener, "")
	connectorIdentity := identityFromOffer(RoleConnector, hello.Name, *hello.Offer, control.conn.RemoteAddr().String())
	observations := append(listenerToConnector, connectorToListener...)
	return buildResult(RoleListener, listener.options.Version, listenerIdentity, connectorIdentity, control.channel(), observations), nil
}

// Connect reads no files and performs only the two bounded peer operations
// described by the pairing string. The string itself never enters a result or
// returned error.
func Connect(parent context.Context, code string, options Options) (Result, error) {
	options = normalizeOptions(options)
	if options.Timeout > MaxOperationTimeout {
		return Result{}, fmt.Errorf("peer timeout cannot exceed %s", MaxOperationTimeout)
	}
	p, err := decodePairing(code, time.Now())
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(parent, SessionLifetime)
	defer cancel()

	binds, err := connectorBinds(ctx, p.Endpoints, options.Sources, options.Timeout)
	if err != nil {
		return Result{}, err
	}
	reverse, err := newEndpointServer(ctx, binds, options, false, DirectionListenerToConnector)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = reverse.Close() }()

	offer := offerFromCredential(reverse.endpoints, reverse.credential)
	reverseSources := reverse.sourceIPs()
	control, err := connectControl(ctx, p, offer, reverseSources, options)
	if err != nil {
		return Result{}, err
	}
	defer control.close()

	type request struct {
		endpoint wireEndpoint
		source   netip.Addr
	}
	requests := make([]request, 0, len(p.Endpoints))
	for _, endpoint := range p.Endpoints {
		source, available := reverseSources[endpoint.Family]
		if options.Sources != nil && !available {
			continue
		}
		requests = append(requests, request{endpoint: endpoint, source: source})
	}
	observations := parallelObservations(len(requests), func(i int) Observation {
		request := requests[i]
		return probeEndpoint(ctx, request.endpoint, p.Pin, p.Token, request.source, options.Timeout, DirectionConnectorToListener)
	})
	if err := writeMessage(ctx, control.conn, options.Timeout, wireMessage{
		Version: ProtocolVersion, Type: "evidence", Observations: observations,
	}); err != nil {
		return Result{}, safeSessionError("send connector evidence", err)
	}
	serverEvidence, err := readMessage(ctx, control.conn, evidenceWait(options.Timeout))
	if err != nil || serverEvidence.Type != "evidence" {
		return Result{}, safeSessionError("read listener evidence", err)
	}
	listenerToConnector, err := reverse.verifyReported(serverEvidence.Observations, DirectionListenerToConnector)
	if err != nil {
		return Result{}, err
	}
	if err := writeMessage(ctx, control.conn, options.Timeout, wireMessage{Version: ProtocolVersion, Type: "done"}); err != nil {
		return Result{}, safeSessionError("finish peer session", err)
	}

	listenerIdentity := EndpointIdentity{
		Role: RoleListener, Name: control.peerName, ListenAddresses: endpointAddresses(p.Endpoints),
		ObservedAddress: control.conn.RemoteAddr().String(),
	}
	connectorIdentity := reverse.identity(RoleConnector, control.conn.LocalAddr().String())
	all := append(listenerToConnector, observations...)
	return buildResult(RoleConnector, options.Version, listenerIdentity, connectorIdentity, control.channel(), all), nil
}

type acceptedControl struct {
	server     *endpointServer
	conn       *tls.Conn
	message    wireMessage
	started    time.Time
	localAddr  string
	remoteAddr string
	ms         int64
}

func (control *acceptedControl) close() {
	_ = control.conn.Close()
	control.server.untrack(control.conn.NetConn())
}

func (control acceptedControl) channel() ChannelObservation {
	return ChannelObservation{
		Established: true, Family: familyForAddress(control.localAddr), Local: control.localAddr,
		Remote: control.remoteAddr, Ms: control.ms,
	}
}

func (control acceptedControl) remoteIP() netip.Addr {
	addr, _ := endpointAddr(control.remoteAddr)
	return addr
}

type controlClient struct {
	conn     *tls.Conn
	family   string
	peerName string
	ms       int64
}

func (control *controlClient) close() { _ = control.conn.Close() }

func (control *controlClient) channel() ChannelObservation {
	return ChannelObservation{
		Established: true, Family: control.family, Local: control.conn.LocalAddr().String(),
		Remote: control.conn.RemoteAddr().String(), Ms: control.ms,
	}
}

func connectControl(ctx context.Context, p pairing, offer wireOffer, sources map[string]netip.Addr, options Options) (*controlClient, error) {
	for _, endpoint := range p.Endpoints {
		source, available := sources[endpoint.Family]
		if options.Sources != nil && !available {
			continue
		}
		started := time.Now()
		conn, observation := dialPeerTLS(ctx, endpoint, p.Pin, source, options.Timeout, DirectionConnectorToListener)
		if conn == nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		nonce, nonceErr := randomEncoded(nonceSize)
		challenge, challengeErr := randomEncoded(payloadSize)
		if nonceErr != nil || challengeErr != nil {
			_ = conn.Close()
			return nil, errors.Join(nonceErr, challengeErr)
		}
		hello := wireMessage{
			Version: ProtocolVersion, Type: "hello", Token: encodeSecret(p.Token[:]),
			Nonce: nonce, Challenge: challenge, Name: options.Name, Offer: &offer,
		}
		if err := writeMessage(ctx, conn, options.Timeout, hello); err != nil {
			markApplicationFailure(&observation, err)
			_ = conn.Close()
			continue
		}
		response, err := readMessage(ctx, conn, options.Timeout)
		if errors.Is(err, errVersionMismatch) {
			_ = conn.Close()
			return nil, errVersionMismatch
		}
		if err != nil || response.Type != "hello_ok" || response.Nonce != nonce || response.Challenge != challenge {
			markApplicationFailure(&observation, err)
			_ = conn.Close()
			continue
		}
		markPass(&observation)
		observation.Ms = sessionMs(started)
		return &controlClient{conn: conn, family: endpoint.Family, peerName: cleanName(response.Name), ms: observation.Ms}, nil
	}
	return nil, errors.New("could not establish the authenticated peer channel")
}

func probeOffer(ctx context.Context, endpoints []wireEndpoint, pin [sha256.Size]byte, token [tokenSize]byte, sources, observed map[string]netip.Addr, timeout time.Duration, direction string) []Observation {
	return parallelObservations(len(endpoints), func(i int) Observation {
		endpoint := endpoints[i]
		remote := observed[endpoint.Family]
		if !remote.IsValid() {
			return Observation{
				Direction: direction, Family: endpoint.Family,
				Status: diagnostic.StatusNA.String(), Cause: CausePeerAddressUnverified,
			}
		}
		_, port, _ := net.SplitHostPort(endpoint.Address)
		// remote.String() keeps the %zone of a scoped link-local address.
		endpoint.Address = net.JoinHostPort(remote.String(), port)
		return probeEndpoint(ctx, endpoint, pin, token, sources[endpoint.Family], timeout, direction)
	})
}

func parallelObservations(count int, probe func(int) Observation) []Observation {
	observations := make([]Observation, count)
	var group sync.WaitGroup
	for i := range count {
		group.Go(func() { observations[i] = probe(i) })
	}
	group.Wait()
	return observations
}

func evidenceWait(timeout time.Duration) time.Duration {
	return min(3*timeout, SessionLifetime)
}

func probeEndpoint(ctx context.Context, endpoint wireEndpoint, pin [sha256.Size]byte, token [tokenSize]byte, source netip.Addr, timeout time.Duration, direction string) Observation {
	started := time.Now()
	conn, observation := dialPeerTLS(ctx, endpoint, pin, source, timeout, direction)
	if conn == nil {
		return observation
	}
	defer func() { _ = conn.Close() }()
	nonce, nonceErr := randomEncoded(nonceSize)
	challenge, challengeErr := randomEncoded(payloadSize)
	if nonceErr != nil || challengeErr != nil {
		markApplicationFailure(&observation, errors.Join(nonceErr, challengeErr))
		observation.Ms = sessionMs(started)
		return observation
	}
	request := wireMessage{
		Version: ProtocolVersion, Type: "probe", Token: encodeSecret(token[:]), Nonce: nonce, Challenge: challenge,
	}
	if err := writeMessage(ctx, conn, timeout, request); err != nil {
		markApplicationFailure(&observation, err)
		observation.Ms = sessionMs(started)
		return observation
	}
	response, err := readMessage(ctx, conn, timeout)
	if err != nil || response.Type != "probe_ok" || response.Nonce != nonce || response.Challenge != challenge {
		markApplicationFailure(&observation, err)
		observation.Ms = sessionMs(started)
		return observation
	}
	markPass(&observation)
	observation.Ms = sessionMs(started)
	return observation
}

func dialPeerTLS(ctx context.Context, endpoint wireEndpoint, pin [sha256.Size]byte, source netip.Addr, timeout time.Duration, direction string) (*tls.Conn, Observation) {
	start := time.Now()
	observation := Observation{
		Direction: direction, Family: endpoint.Family, Destination: endpoint.Address,
		Status: diagnostic.StatusFail.String(), Cause: CauseConnectionUnreachable,
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := net.Dialer{}
	if source.IsValid() {
		// TCPAddrFromAddrPort carries the zone a link-local bind needs.
		dialer.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, 0))
	}
	network := "tcp6"
	if endpoint.Family == FamilyIPv4 {
		network = "tcp4"
	}
	raw, err := dialer.DialContext(dialCtx, network, endpoint.Address)
	observation.Ms = sessionMs(start)
	if err != nil {
		observation.Cause = diagnostic.ConnectionFailureCause(err)
		return nil, observation
	}
	observation.TCPConnected = true
	observation.Source, observation.Destination = raw.LocalAddr().String(), raw.RemoteAddr().String()
	conn := tls.Client(raw, clientTLSConfig(pin))
	if err := conn.HandshakeContext(dialCtx); err != nil {
		_ = raw.Close()
		observation.Ms = sessionMs(start)
		switch diagnostic.ConnectionFailureCause(err) {
		case diagnostic.ConnectionCauseTimeout:
			observation.Cause = diagnostic.ConnectionCauseTimeout
		case diagnostic.ConnectionCauseCanceled:
			observation.Cause = diagnostic.ConnectionCauseCanceled
		default:
			observation.Cause = CauseTLSAuthenticationFailed
		}
		return nil, observation
	}
	observation.TLSAuthenticated = true
	observation.Cause = CauseApplicationTrafficFailed
	observation.Ms = sessionMs(start)
	return conn, observation
}

func markPass(observation *Observation) {
	observation.Status, observation.Cause = diagnostic.StatusPass.String(), ""
	observation.ApplicationTraffic, observation.PayloadBytes = true, payloadSize
}

func markApplicationFailure(observation *Observation, err error) {
	observation.Status = diagnostic.StatusFail.String()
	observation.Cause = CauseApplicationTrafficFailed
	switch diagnostic.ConnectionFailureCause(err) {
	case diagnostic.ConnectionCauseTimeout:
		observation.Cause = diagnostic.ConnectionCauseTimeout
	case diagnostic.ConnectionCauseCanceled:
		observation.Cause = diagnostic.ConnectionCauseCanceled
	}
}

type endpointServer struct {
	ctx              context.Context
	cancel           context.CancelFunc
	options          Options
	name             string
	credential       credential
	endpoints        []wireEndpoint
	listeners        []net.Listener
	auth             authenticator
	allowControl     bool
	inboundDirection string
	controls         chan acceptedControl
	fatal            chan error

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	inbound     map[string]Observation
	controlUsed bool
	closed      bool
	wg          sync.WaitGroup
}

func newEndpointServer(parent context.Context, addresses []string, options Options, allowControl bool, inboundDirection string) (*endpointServer, error) {
	if len(addresses) == 0 || len(addresses) > maxEndpointCount {
		return nil, errors.New("peer mode needs one listen address per available address family")
	}
	options = normalizeOptions(options)
	ctx, cancel := context.WithCancel(parent)
	credential, err := newCredential(time.Now())
	if err != nil {
		cancel()
		return nil, err
	}
	server := &endpointServer{
		ctx: ctx, cancel: cancel, options: options, name: options.Name, credential: credential,
		auth: authenticator{token: credential.token}, allowControl: allowControl, inboundDirection: inboundDirection,
		controls: make(chan acceptedControl, 1), fatal: make(chan error, 1),
		connections: make(map[net.Conn]struct{}), inbound: make(map[string]Observation),
	}
	seen := map[string]bool{}
	for _, requested := range addresses {
		address, family, err := NormalizeListenAddress(requested)
		if err != nil || seen[family] {
			_ = server.Close()
			return nil, errors.New("peer listen addresses must be unique exact IPv4 or IPv6 addresses")
		}
		seen[family] = true
		network := "tcp6"
		if family == FamilyIPv4 {
			network = "tcp4"
		}
		listener, err := new(net.ListenConfig).Listen(ctx, network, address)
		if err != nil {
			_ = server.Close()
			return nil, fmt.Errorf("listen on %s: %w", address, err)
		}
		server.listeners = append(server.listeners, listener)
		server.endpoints = append(server.endpoints, wireEndpoint{Address: advertisedEndpoint(address, listener.Addr().String()), Family: family})
	}
	for _, listener := range server.listeners {
		server.wg.Add(1)
		go server.accept(listener)
	}
	context.AfterFunc(ctx, func() { _ = server.Close() })
	return server, nil
}

// advertisedEndpoint is the address peers are told to dial. A listening socket
// reports no zone for a scoped link-local bind, and that bare address is not
// connectable, so the requested host is kept and only the port comes from the
// listener, which is what port zero asks the kernel to choose.
func advertisedEndpoint(requested, bound string) string {
	host, _, hostErr := net.SplitHostPort(requested)
	_, port, portErr := net.SplitHostPort(bound)
	if hostErr != nil || portErr != nil {
		return bound
	}
	return net.JoinHostPort(host, port)
}

func (server *endpointServer) accept(listener net.Listener) {
	defer server.wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if server.ctx.Err() == nil {
				server.fail(err)
			}
			return
		}
		server.mu.Lock()
		tooMany := len(server.connections) >= maxConnections
		if !tooMany {
			server.connections[conn] = struct{}{}
		}
		server.mu.Unlock()
		if tooMany {
			_ = conn.Close()
			continue
		}
		server.wg.Add(1)
		go server.handle(conn)
	}
}

func (server *endpointServer) handle(raw net.Conn) {
	defer server.wg.Done()
	transferred := false
	defer func() {
		if !transferred {
			_ = raw.Close()
			server.untrack(raw)
		}
	}()
	ctx, cancel := context.WithTimeout(server.ctx, server.options.Timeout)
	defer cancel()
	started := time.Now()
	conn := tls.Server(raw, serverTLSConfig(server.credential))
	if err := conn.HandshakeContext(ctx); err != nil {
		return
	}
	message, err := readMessage(ctx, conn, server.options.Timeout)
	if err != nil || server.auth.authenticate(message.Token, message.Nonce) != nil {
		return
	}
	switch message.Type {
	case "probe":
		server.mu.Lock()
		controlReady := !server.allowControl || server.controlUsed
		server.mu.Unlock()
		observation := Observation{
			Direction: server.inboundDirection, Family: familyForAddress(conn.LocalAddr().String()),
			Source: conn.RemoteAddr().String(), Destination: conn.LocalAddr().String(),
			Status: diagnostic.StatusPass.String(), TCPConnected: true, TLSAuthenticated: true,
			ApplicationTraffic: true, PayloadBytes: lenMustDecode(message.Challenge), Ms: sessionMs(started),
		}
		if !controlReady || !server.claimInbound(observation) {
			return
		}
		if err := writeMessage(ctx, conn, server.options.Timeout, wireMessage{
			Version: ProtocolVersion, Type: "probe_ok", Nonce: message.Nonce, Challenge: message.Challenge,
		}); err != nil {
			server.removeInbound(observation.Family)
			return
		}
	case "hello":
		server.mu.Lock()
		allowed := server.allowControl && !server.controlUsed
		if allowed {
			server.controlUsed = true
		}
		server.mu.Unlock()
		if !allowed {
			return
		}
		control := acceptedControl{
			server: server, conn: conn, message: message, started: started,
			localAddr: conn.LocalAddr().String(), remoteAddr: conn.RemoteAddr().String(),
		}
		select {
		case server.controls <- control:
			transferred = true
		case <-server.ctx.Done():
		}
	}
}

func (server *endpointServer) claimInbound(observation Observation) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, exists := server.inbound[observation.Family]; exists {
		return false
	}
	server.inbound[observation.Family] = observation
	return true
}

func (server *endpointServer) removeInbound(family string) {
	server.mu.Lock()
	delete(server.inbound, family)
	server.mu.Unlock()
}

func (server *endpointServer) verifyReported(reported []Observation, direction string) ([]Observation, error) {
	if len(reported) == 0 || len(reported) > maxObservationCount {
		return nil, errInvalidMessage
	}
	server.mu.Lock()
	actual := make(map[string]Observation, len(server.inbound))
	for family, observation := range server.inbound {
		actual[family] = observation
	}
	server.mu.Unlock()
	seen := map[string]bool{}
	for i := range reported {
		observation := &reported[i]
		if observation.Direction != direction || seen[observation.Family] {
			return nil, errInvalidMessage
		}
		seen[observation.Family] = true
		if observation.Status == diagnostic.StatusNA.String() {
			if observation.Cause != CausePeerAddressUnverified {
				return nil, errInvalidMessage
			}
			if _, connected := actual[observation.Family]; connected {
				return nil, errInvalidMessage
			}
			continue
		}
		if observation.Status == diagnostic.StatusPass.String() {
			local, ok := actual[observation.Family]
			if !ok || !observation.TCPConnected || !observation.TLSAuthenticated || !observation.ApplicationTraffic || observation.PayloadBytes != payloadSize {
				return nil, errInvalidMessage
			}
			observation.Source, observation.Destination = local.Source, local.Destination
		}
	}
	return reported, nil
}

func (server *endpointServer) sourceIPs() map[string]netip.Addr {
	out := make(map[string]netip.Addr, len(server.endpoints))
	for _, endpoint := range server.endpoints {
		out[endpoint.Family], _ = endpointAddr(endpoint.Address)
	}
	return out
}

func (server *endpointServer) observedRemoteIPs(control netip.Addr) map[string]netip.Addr {
	observed := make(map[string]netip.Addr, maxEndpointCount)
	if control.IsValid() {
		observed[familyForAddr(control)] = control
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	for family, observation := range server.inbound {
		if addr, ok := endpointAddr(observation.Source); ok && familyForAddr(addr) == family {
			observed[family] = addr
		}
	}
	return observed
}

func (server *endpointServer) identity(role, observed string) EndpointIdentity {
	return EndpointIdentity{Role: role, Name: server.name, ListenAddresses: endpointAddresses(server.endpoints), ObservedAddress: observed}
}

func (server *endpointServer) fail(err error) {
	select {
	case server.fatal <- err:
	default:
	}
}

func (server *endpointServer) untrack(conn net.Conn) {
	server.mu.Lock()
	delete(server.connections, conn)
	server.mu.Unlock()
}

func (server *endpointServer) Close() error {
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		return nil
	}
	server.closed = true
	server.cancel()
	listeners := append([]net.Listener(nil), server.listeners...)
	connections := make([]net.Conn, 0, len(server.connections))
	for conn := range server.connections {
		connections = append(connections, conn)
	}
	server.mu.Unlock()
	var errs []error
	for _, listener := range listeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	for _, conn := range connections {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	server.wg.Wait()
	server.credential = credential{}
	server.auth.mu.Lock()
	server.auth.token = [tokenSize]byte{}
	server.auth.nonces = nil
	server.auth.mu.Unlock()
	return errors.Join(errs...)
}

func connectorBinds(ctx context.Context, endpoints []wireEndpoint, sources *diagnostic.SourceAddresses, timeout time.Duration) ([]string, error) {
	var binds []string
	for _, endpoint := range endpoints {
		var source netip.Addr
		if sources != nil {
			if endpoint.Family == FamilyIPv4 {
				source, _ = netip.AddrFromSlice(sources.IPv4)
			} else {
				source, _ = netip.AddrFromSlice(sources.IPv6)
			}
			source = source.Unmap()
		}
		if !source.IsValid() && sources != nil {
			continue
		}
		if !source.IsValid() {
			var err error
			source, err = routeSource(ctx, endpoint, timeout)
			if err != nil {
				continue
			}
		}
		if sources != nil && source.Is6() && source.IsLinkLocalUnicast() {
			// An interface-selected source carries no zone, and a link-local
			// address needs one; --iface named the interface it belongs to.
			source = source.WithZone(sources.Iface)
		}
		bind := net.JoinHostPort(source.String(), "0")
		if _, _, err := NormalizeListenAddress(bind); err != nil {
			// A source that cannot be advertised as a peer endpoint is no
			// reverse listener for this family, but the other family may be.
			continue
		}
		binds = append(binds, bind)
	}
	if len(binds) == 0 {
		return nil, errors.New("cannot choose a local address for the reverse peer listener")
	}
	return binds, nil
}

func routeSource(ctx context.Context, endpoint wireEndpoint, timeout time.Duration) (netip.Addr, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	network := "udp6"
	if endpoint.Family == FamilyIPv4 {
		network = "udp4"
	}
	conn, err := new(net.Dialer).DialContext(dialCtx, network, endpoint.Address)
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	address, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("no usable source address")
	}
	// AddrPort keeps the zone the kernel reported for a link-local source,
	// which the reverse listener then has to bind by.
	source := address.AddrPort().Addr().Unmap()
	if !source.IsValid() || source.IsUnspecified() {
		return netip.Addr{}, errors.New("no usable source address")
	}
	return source, nil
}

func identityFromOffer(role, name string, offer wireOffer, observed string) EndpointIdentity {
	return EndpointIdentity{Role: role, Name: cleanName(name), ListenAddresses: endpointAddresses(offer.Endpoints), ObservedAddress: observed}
}

func endpointAddresses(endpoints []wireEndpoint) []string {
	addresses := make([]string, len(endpoints))
	for i, endpoint := range endpoints {
		addresses[i] = endpoint.Address
	}
	return addresses
}

func normalizeOptions(options Options) Options {
	if options.Timeout <= 0 {
		options.Timeout = diagnostic.DefaultProbeTimeout
	}
	if options.Name == "" {
		options.Name, _ = os.Hostname()
	}
	options.Name = cleanName(options.Name)
	return options
}

func cleanName(name string) string {
	name = textsafe.Clean(name)
	if len(name) <= maxPeerNameSize {
		return name
	}
	for len(name) > maxPeerNameSize {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return name
}

func familyForAddress(address string) string {
	addr, ok := endpointAddr(address)
	if !ok {
		return ""
	}
	return familyForAddr(addr)
}

// familyForAddr expects an unmapped address, as endpointAddr returns.
func familyForAddr(addr netip.Addr) string {
	switch {
	case addr.Is4():
		return FamilyIPv4
	case addr.IsValid():
		return FamilyIPv6
	default:
		return ""
	}
}

func lenMustDecode(value string) int {
	decoded, _ := decodeFixed(value, payloadSize)
	return len(decoded)
}

func sessionMs(started time.Time) int64 {
	return min(diagnostic.Ms(time.Since(started)), SessionLifetime.Milliseconds())
}

func safeSessionError(action string, err error) error {
	if err == nil {
		return fmt.Errorf("%s: %w", action, errInvalidMessage)
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, errVersionMismatch), errors.Is(err, errInvalidMessage):
		return fmt.Errorf("%s: %w", action, err)
	default:
		return fmt.Errorf("%s failed", action)
	}
}

func sessionContext(parent, server context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, SessionLifetime)
	stop := context.AfterFunc(server, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}
