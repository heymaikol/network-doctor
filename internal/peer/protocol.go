package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

const (
	PairingLifetime     = 5 * time.Minute
	SessionLifetime     = time.Minute
	MaxOperationTimeout = 30 * time.Second
	MaxPairingCodeSize  = 512
	maxMessageSize      = 16 << 10
	maxEndpointSize     = 96
	maxZoneSize         = 32
	maxEndpointCount    = 2
	maxObservationCount = 2
	maxPeerNameSize     = 128
	maxConnections      = 8
	payloadSize         = 32
	tokenSize           = 32
	nonceSize           = 16
	pairingPrefix       = "ndp1."
)

var (
	errInvalidPairing   = errors.New("invalid peer pairing string")
	errExpiredPairing   = errors.New("peer pairing string has expired")
	errVersionMismatch  = errors.New("incompatible peer protocol version")
	errInvalidMessage   = errors.New("invalid peer protocol message")
	errAuthentication   = errors.New("peer authentication failed")
	errReplay           = errors.New("replayed peer request")
	errTooManyExchanges = errors.New("peer exchange limit exceeded")
)

// IsPairingError reports a local pairing-input validation failure. The CLI
// maps it to its existing bad-argument exit code without exposing credentials.
func IsPairingError(err error) bool {
	return errors.Is(err, errInvalidPairing) || errors.Is(err, errExpiredPairing) || errors.Is(err, errVersionMismatch)
}

type wireEndpoint struct {
	Address string `json:"address"`
	Family  string `json:"family"`
}

type wireOffer struct {
	Endpoints []wireEndpoint `json:"endpoints"`
	Pin       string         `json:"pin"`
	Token     string         `json:"token"`
}

type wireMessage struct {
	Version      int           `json:"version"`
	Type         string        `json:"type"`
	Token        string        `json:"token,omitempty"`
	Nonce        string        `json:"nonce,omitempty"`
	Challenge    string        `json:"challenge,omitempty"`
	Name         string        `json:"name,omitempty"`
	Offer        *wireOffer    `json:"offer,omitempty"`
	Observations []Observation `json:"observations,omitempty"`
}

type pairing struct {
	Expires   time.Time
	Endpoints []wireEndpoint
	Pin       [sha256.Size]byte
	Token     [tokenSize]byte
}

type credential struct {
	certificate tls.Certificate
	pin         [sha256.Size]byte
	token       [tokenSize]byte
}

func newCredential(now time.Time) (credential, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return credential{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return credential{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Network Doctor peer session"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(PairingLifetime + time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, public, private)
	if err != nil {
		return credential{}, err
	}
	var token [tokenSize]byte
	if _, err := rand.Read(token[:]); err != nil {
		return credential{}, err
	}
	return credential{
		certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private},
		pin:         sha256.Sum256(der), token: token,
	}, nil
}

func serverTLSConfig(c credential) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.certificate}}
}

func clientTLSConfig(pin [sha256.Size]byte) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// #nosec G402 -- normal certificate verification is replaced by the
		// SHA-256 certificate pin carried in the authenticated pairing string.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errAuthentication
			}
			got := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], pin[:]) != 1 {
				return errAuthentication
			}
			return nil
		},
	}
}

func encodePairing(p pairing) (string, error) {
	if len(p.Endpoints) == 0 || len(p.Endpoints) > maxEndpointCount {
		return "", errInvalidPairing
	}
	expires := p.Expires.Unix()
	if expires <= 0 {
		return "", errInvalidPairing
	}
	var payload bytes.Buffer
	// #nosec G115 -- the positive int64 checked above is representable as uint64.
	_ = binary.Write(&payload, binary.BigEndian, uint64(expires))
	// #nosec G115 -- endpoint count is checked against the two-entry limit above.
	payload.WriteByte(byte(len(p.Endpoints)))
	seen := map[string]bool{}
	for _, endpoint := range p.Endpoints {
		address, family, err := normalizeEndpoint(endpoint.Address, false)
		if err != nil || endpoint.Family != family || seen[family] || len(address) > maxEndpointSize {
			return "", errInvalidPairing
		}
		seen[family] = true
		// #nosec G115 -- address length is checked against the 96-byte limit above.
		payload.WriteByte(byte(len(address)))
		payload.WriteString(address)
	}
	payload.Write(p.Pin[:])
	payload.Write(p.Token[:])
	code := pairingPrefix + base64.RawURLEncoding.EncodeToString(payload.Bytes())
	if len(code) > MaxPairingCodeSize {
		return "", errInvalidPairing
	}
	return code, nil
}

func decodePairing(code string, now time.Time) (pairing, error) {
	if len(code) > MaxPairingCodeSize {
		return pairing{}, errInvalidPairing
	}
	if !strings.HasPrefix(code, pairingPrefix) {
		prefix, _, found := strings.Cut(code, ".")
		_, versionErr := strconv.Atoi(strings.TrimPrefix(prefix, "ndp"))
		if found && strings.HasPrefix(prefix, "ndp") && versionErr == nil {
			return pairing{}, errVersionMismatch
		}
		return pairing{}, errInvalidPairing
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(code, pairingPrefix))
	if err != nil {
		return pairing{}, errInvalidPairing
	}
	reader := bytes.NewReader(raw)
	var expires uint64
	if binary.Read(reader, binary.BigEndian, &expires) != nil {
		return pairing{}, errInvalidPairing
	}
	count, err := reader.ReadByte()
	if err != nil || count == 0 || count > maxEndpointCount {
		return pairing{}, errInvalidPairing
	}
	p := pairing{Expires: time.Unix(int64(expires), 0)}
	seen := map[string]bool{}
	for range int(count) {
		size, err := reader.ReadByte()
		if err != nil || size == 0 || size > maxEndpointSize {
			return pairing{}, errInvalidPairing
		}
		addressBytes := make([]byte, int(size))
		if _, err := io.ReadFull(reader, addressBytes); err != nil {
			return pairing{}, errInvalidPairing
		}
		address, family, err := normalizeEndpoint(string(addressBytes), false)
		if err != nil || seen[family] {
			return pairing{}, errInvalidPairing
		}
		seen[family] = true
		p.Endpoints = append(p.Endpoints, wireEndpoint{Address: address, Family: family})
	}
	if _, err := io.ReadFull(reader, p.Pin[:]); err != nil {
		return pairing{}, errInvalidPairing
	}
	if _, err := io.ReadFull(reader, p.Token[:]); err != nil || reader.Len() != 0 {
		return pairing{}, errInvalidPairing
	}
	if !p.Expires.After(now) || p.Expires.After(now.Add(PairingLifetime+time.Minute)) {
		return pairing{}, errExpiredPairing
	}
	return p, nil
}

// NormalizeListenAddress validates one --peer-listen value. It accepts port
// zero so the kernel can choose a temporary port, but requires an exact local
// unicast IP because a wildcard is not an address another machine can dial.
func NormalizeListenAddress(address string) (string, string, error) {
	return normalizeEndpoint(address, true)
}

// endpointAddr parses the IP half of an already-formed host:port endpoint.
// netip keeps the %zone of a scoped IPv6 link-local address; net.ParseIP
// rejects the address instead, which loses the interface the peer is on.
func endpointAddr(address string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func normalizeEndpoint(address string, allowZero bool) (string, string, error) {
	if len(address) == 0 || len(address) > maxEndpointSize {
		return "", "", errInvalidPairing
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", errInvalidPairing
	}
	// netip.ParseAddr keeps the %zone that scopes an IPv6 link-local address
	// to one interface; net.ParseIP rejects the whole address instead. Unmap
	// first so an IPv4-mapped form is judged as the IPv4 address it is.
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", "", errInvalidPairing
	}
	zone := addr.Zone()
	addr = addr.Unmap()
	if addr.Is6() && addr.IsLinkLocalUnicast() {
		// Without the scope a link-local address names no reachable
		// destination, so the bare form is not a usable peer endpoint.
		if !validZone(zone) {
			return "", "", errInvalidPairing
		}
	} else if zone != "" {
		return "", "", errInvalidPairing
	}
	if !addr.IsGlobalUnicast() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
		return "", "", errInvalidPairing
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 || port == 0 && !allowZero {
		return "", "", errInvalidPairing
	}
	family := FamilyIPv6
	if addr.Is4() {
		family = FamilyIPv4
	}
	// JoinHostPort brackets the IPv6 literal, zone included.
	return net.JoinHostPort(addr.String(), strconv.Itoa(port)), family, nil
}

// validZone bounds an interface scope to what real zones look like: a Unix
// interface name or a Windows numeric scope identifier. Endpoints reach here
// from a peer, and they are stored and displayed, so the zone may not carry
// arbitrary text.
func validZone(zone string) bool {
	if zone == "" || len(zone) > maxZoneSize {
		return false
	}
	for _, r := range zone {
		alphanumeric := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !alphanumeric && r != '.' && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func encodeSecret(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodeFixed(value string, size int) ([]byte, bool) {
	if len(value) > base64.RawURLEncoding.EncodedLen(size) {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return decoded, err == nil && len(decoded) == size
}

type authenticator struct {
	token  [tokenSize]byte
	mu     sync.Mutex
	nonces map[string]struct{}
}

func (a *authenticator) authenticate(token, nonce string) error {
	provided, ok := decodeFixed(token, tokenSize)
	if !ok || subtle.ConstantTimeCompare(provided, a.token[:]) != 1 {
		return errAuthentication
	}
	decodedNonce, ok := decodeFixed(nonce, nonceSize)
	if !ok {
		return errInvalidMessage
	}
	key := string(decodedNonce)
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.nonces) >= maxConnections {
		return errTooManyExchanges
	}
	if _, exists := a.nonces[key]; exists {
		return errReplay
	}
	if a.nonces == nil {
		a.nonces = make(map[string]struct{}, maxConnections)
	}
	a.nonces[key] = struct{}{}
	return nil
}

func randomEncoded(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return encodeSecret(value), nil
}

func writeMessage(ctx context.Context, conn net.Conn, timeout time.Duration, message wireMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := validateMessage(message); err != nil {
		return err
	}
	payload, err := json.Marshal(message)
	if err != nil || len(payload) == 0 || len(payload) > maxMessageSize {
		return errInvalidMessage
	}
	if err := setDeadline(ctx, conn, timeout); err != nil {
		return err
	}
	frame := make([]byte, 4+len(payload))
	// #nosec G115 -- payload length was checked against the 16 KiB frame limit.
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	for len(frame) > 0 {
		written, err := conn.Write(frame)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		frame = frame[written:]
	}
	return nil
}

func readMessage(ctx context.Context, conn net.Conn, timeout time.Duration) (wireMessage, error) {
	if err := ctx.Err(); err != nil {
		return wireMessage{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := setDeadline(ctx, conn, timeout); err != nil {
		return wireMessage{}, err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		if ctx.Err() != nil {
			return wireMessage{}, ctx.Err()
		}
		return wireMessage{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxMessageSize {
		return wireMessage{}, errInvalidMessage
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(conn, payload); err != nil {
		if ctx.Err() != nil {
			return wireMessage{}, ctx.Err()
		}
		return wireMessage{}, err
	}
	if !utf8.Valid(payload) {
		return wireMessage{}, errInvalidMessage
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var message wireMessage
	if err := decoder.Decode(&message); err != nil {
		return wireMessage{}, errInvalidMessage
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return wireMessage{}, errInvalidMessage
	}
	if err := validateMessage(message); err != nil {
		return wireMessage{}, err
	}
	return message, nil
}

func setDeadline(ctx context.Context, conn net.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(min(timeout, SessionLifetime))
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return conn.SetDeadline(deadline)
}

func validateMessage(message wireMessage) error {
	if message.Version != ProtocolVersion {
		return errVersionMismatch
	}
	if len(message.Type) == 0 || len(message.Type) > 24 || len(message.Name) > maxPeerNameSize {
		return errInvalidMessage
	}
	switch message.Type {
	case "hello":
		if message.Offer == nil || !validAuthFields(message) || validateOffer(*message.Offer) != nil {
			return errInvalidMessage
		}
	case "hello_ok":
		if message.Token != "" || message.Offer != nil || !validNonceChallenge(message) {
			return errInvalidMessage
		}
	case "probe_ok":
		if message.Token != "" || message.Name != "" || message.Offer != nil || !validNonceChallenge(message) {
			return errInvalidMessage
		}
	case "probe":
		if message.Name != "" || message.Offer != nil || !validAuthFields(message) {
			return errInvalidMessage
		}
	case "evidence":
		if message.Token != "" || message.Nonce != "" || message.Challenge != "" || message.Name != "" || message.Offer != nil || len(message.Observations) > maxObservationCount {
			return errInvalidMessage
		}
		for _, observation := range message.Observations {
			if validateObservation(observation) != nil {
				return errInvalidMessage
			}
		}
	case "done":
		if message.Token != "" || message.Nonce != "" || message.Challenge != "" || message.Name != "" || message.Offer != nil || len(message.Observations) != 0 {
			return errInvalidMessage
		}
	default:
		return errInvalidMessage
	}
	return nil
}

func validAuthFields(message wireMessage) bool {
	_, tokenOK := decodeFixed(message.Token, tokenSize)
	return tokenOK && validNonceChallenge(message)
}

func validNonceChallenge(message wireMessage) bool {
	_, nonceOK := decodeFixed(message.Nonce, nonceSize)
	_, challengeOK := decodeFixed(message.Challenge, payloadSize)
	return nonceOK && challengeOK && len(message.Observations) == 0
}

func validateOffer(offer wireOffer) error {
	if len(offer.Endpoints) == 0 || len(offer.Endpoints) > maxEndpointCount {
		return errInvalidMessage
	}
	if _, ok := decodeFixed(offer.Pin, sha256.Size); !ok {
		return errInvalidMessage
	}
	if _, ok := decodeFixed(offer.Token, tokenSize); !ok {
		return errInvalidMessage
	}
	seen := map[string]bool{}
	for _, endpoint := range offer.Endpoints {
		address, family, err := normalizeEndpoint(endpoint.Address, false)
		if err != nil || address != endpoint.Address || family != endpoint.Family || seen[family] {
			return errInvalidMessage
		}
		seen[family] = true
	}
	return nil
}

func validateObservation(observation Observation) error {
	if observation.Direction != DirectionListenerToConnector && observation.Direction != DirectionConnectorToListener {
		return errInvalidMessage
	}
	if observation.Family != FamilyIPv4 && observation.Family != FamilyIPv6 {
		return errInvalidMessage
	}
	if len(observation.Source) > maxEndpointSize || len(observation.Destination) > maxEndpointSize || len(observation.Cause) > 48 || observation.PayloadBytes < 0 || observation.PayloadBytes > payloadSize || observation.Ms < 0 || observation.Ms > SessionLifetime.Milliseconds() {
		return errInvalidMessage
	}
	if observation.TLSAuthenticated && !observation.TCPConnected || observation.ApplicationTraffic && !observation.TLSAuthenticated {
		return errInvalidMessage
	}
	// dialPeerTLS records the socket pair exactly when the TCP connection is
	// established, so a connected attempt without them, or an unconnected one
	// carrying them, is not an attempt this protocol can have made.
	if observation.TCPConnected != (observation.Source != "") {
		return errInvalidMessage
	}
	switch observation.Status {
	case "PASS":
		if observation.Cause != "" || !observation.TCPConnected || !observation.TLSAuthenticated || !observation.ApplicationTraffic || observation.PayloadBytes != payloadSize || observation.Destination == "" {
			return errInvalidMessage
		}
	case "FAIL":
		// The destination is set before the dial, so every tested attempt
		// names the address it tried.
		if observation.ApplicationTraffic || observation.PayloadBytes != 0 || observation.Destination == "" ||
			!validFailureCause(observation.Cause, observationPhaseOf(observation)) {
			return errInvalidMessage
		}
	case "N/A":
		if (observation.Cause != CauseFamilyUnavailable && observation.Cause != CausePeerAddressUnverified) || observation.Source != "" || observation.Destination != "" || observation.TCPConnected || observation.TLSAuthenticated || observation.ApplicationTraffic || observation.PayloadBytes != 0 || observation.Ms != 0 {
			return errInvalidMessage
		}
	default:
		return errInvalidMessage
	}
	// A probe dials one family over tcp4 or tcp6, so both socket endpoints
	// belong to the family the row is filed under. normalizeEndpoint decides
	// that the same way the rest of the protocol does, which keeps an
	// IPv4-mapped form IPv4 and keeps a link-local zone attached.
	for _, address := range []string{observation.Source, observation.Destination} {
		if address == "" {
			continue
		}
		_, family, err := normalizeEndpoint(address, false)
		if err != nil || family != observation.Family {
			return errInvalidMessage
		}
	}
	return nil
}

// observationPhase is how far one attempt got before it stopped. dialPeerTLS
// establishes the TCP connection, then authenticates the TLS peer, and only
// then can probeEndpoint reach the fixed payload exchange.
type observationPhase int

const (
	phaseConnecting observationPhase = iota
	phaseSecuring
	phaseExchanging
)

func observationPhaseOf(observation Observation) observationPhase {
	switch {
	case observation.TLSAuthenticated:
		return phaseExchanging
	case observation.TCPConnected:
		return phaseSecuring
	default:
		return phaseConnecting
	}
}

// validFailureCause reports whether the v1 producer can record this cause in
// this phase. The bounded deadline and a canceled session end any phase, so
// they match everywhere; every other cause names the one phase that emits it.
func validFailureCause(cause string, phase observationPhase) bool {
	switch cause {
	case diagnostic.ConnectionCauseTimeout, diagnostic.ConnectionCauseCanceled:
		return true
	case diagnostic.ConnectionCauseRefused, diagnostic.ConnectionCauseUnreachable:
		return phase == phaseConnecting
	case CauseTLSAuthenticationFailed:
		return phase == phaseSecuring
	case CauseApplicationTrafficFailed:
		return phase == phaseExchanging
	default:
		return false
	}
}

func offerFromCredential(endpoints []wireEndpoint, c credential) wireOffer {
	return wireOffer{Endpoints: endpoints, Pin: encodeSecret(c.pin[:]), Token: encodeSecret(c.token[:])}
}

func credentialFromOffer(offer wireOffer) (pin [sha256.Size]byte, token [tokenSize]byte, err error) {
	pinBytes, pinOK := decodeFixed(offer.Pin, sha256.Size)
	tokenBytes, tokenOK := decodeFixed(offer.Token, tokenSize)
	if !pinOK || !tokenOK {
		return pin, token, errInvalidMessage
	}
	copy(pin[:], pinBytes)
	copy(token[:], tokenBytes)
	return pin, token, nil
}
