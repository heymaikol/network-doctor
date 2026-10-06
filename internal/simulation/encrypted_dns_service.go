package simulation

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	// encryptedDNSProbeService is the conventional name for the fixture netdoc's
	// encrypted-DNS row talks to, so the runner can find its trust anchor.
	encryptedDNSProbeService = "internet-encrypted-dns"
	// encryptedDNSDoTPort is fixed by RFC 7858. The service's configurable port
	// is the DoH one, which is ordinary HTTPS.
	encryptedDNSDoTPort = 853
	// encryptedDNSPath and encryptedDNSMediaType mirror what netdoc's probe
	// sends: an RFC 8484 POST of a wire-format query.
	encryptedDNSPath      = "/dns-query"
	encryptedDNSMediaType = "application/dns-message"
)

// encryptedDNSServer answers netdoc's encrypted-DNS probe over both transports
// from the same static zone the plaintext DNS fixture uses: RFC 8484 over HTTPS
// on the service port, RFC 7858 length-framed DNS over TLS on 853. Like every
// other simulator service it is a probe fixture, not a resolver: it answers
// one static zone and nothing else.
type encryptedDNSServer struct {
	doh       *http.Server
	listeners []net.Listener
	caPath    string

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

// listenFamiliesFunc is the listener factory, injectable so a test can bind
// loopback ephemeral ports instead of the privileged ones the protocols fix.
type listenFamiliesFunc func(addresses []string, port string) ([]net.Listener, error)

func startEncryptedDNSService(ctx context.Context, svc Service, addresses []string, trustDir string, recorder *evidenceRecorder) (*encryptedDNSServer, error) {
	return startEncryptedDNSServiceWith(ctx, svc, addresses, trustDir, listenTCPFamilies, recorder)
}

func startEncryptedDNSServiceWith(ctx context.Context, svc Service, addresses []string, trustDir string, listen listenFamiliesFunc, recorder *evidenceRecorder) (*encryptedDNSServer, error) {
	zone, err := parseZone(svc.Zone, svc.Records)
	if err != nil {
		return nil, err
	}
	material, err := generateTLSMaterial(ctx, *svc.Certificate, time.Now())
	if err != nil {
		return nil, err
	}
	rootDir := filepath.Join(trustDir, probeTrustSubdir)
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, err
	}
	caPath := filepath.Join(rootDir, svc.Name+"-ca.pem")
	if err := writePublicCA(caPath, material.caPEM); err != nil {
		return nil, err
	}
	config := &tls.Config{Certificates: []tls.Certificate{material.certificate}, MinVersion: tls.VersionTLS12}
	server := &encryptedDNSServer{caPath: caPath, conns: make(map[net.Conn]struct{})}
	server.doh = &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveDoH(w, r, zone, svc, recorder) }),
		TLSConfig:         config,
		ReadHeaderTimeout: 5 * time.Second,
		// A probe that connects to prove TCP works and hangs up without a
		// ClientHello is the direct-egress check doing its job, not an error.
		ErrorLog: log.New(io.Discard, "", 0),
	}

	doh, err := listen(addresses, strconv.Itoa(svc.Port))
	if err != nil {
		_ = server.Close()
		return nil, err
	}
	dot, err := listen(addresses, strconv.Itoa(encryptedDNSDoTPort))
	if err != nil {
		for _, listener := range doh {
			_ = listener.Close()
		}
		_ = server.Close()
		return nil, err
	}
	server.listeners = append(doh, dot...)
	for _, listener := range doh {
		server.wg.Add(1)
		go func(listener net.Listener) {
			defer server.wg.Done()
			_ = server.doh.ServeTLS(listener, "", "")
		}(listener)
	}
	for _, listener := range dot {
		server.wg.Add(1)
		go func(listener net.Listener) {
			defer server.wg.Done()
			server.serveDoT(listener, config, zone, svc, recorder)
		}(listener)
	}
	return server, nil
}

// serveDoH answers the one request shape netdoc's probe makes. Anything else is
// a 404: the fixture proves that a real RFC 8484 exchange completed, so it must
// not answer a request the probe is not supposed to be sending.
func serveDoH(w http.ResponseWriter, r *http.Request, zone map[string][]netip.Addr, svc Service, recorder *evidenceRecorder) {
	if r.URL.Path != encryptedDNSPath || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	query, err := io.ReadAll(io.LimitReader(r.Body, dnsMaxMsg))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reply := dnsReply(query, zone)
	if reply == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Recorded once the body is on its way out, with what was in it: a fixture
	// configured to answer with a malformed message has done nothing until a
	// client has actually been handed one.
	served := func(result string) {
		_ = recorder.record(evidenceEvent{Kind: evidenceServiceReply, Service: svc.Name,
			ServiceType: ServiceEncryptedDNS, ServicePort: svc.Port, ServiceStatus: http.StatusOK, Result: result})
	}
	w.Header().Set("Content-Type", encryptedDNSMediaType)
	if svc.DoHResponse == DoHResponseInvalid {
		_, _ = w.Write([]byte("not dns"))
		served(DoHResponseInvalid)
		return
	}
	_, _ = w.Write(reply)
	served(replyResponded)
}

// serveDoT is DNS over TLS: every message, in both directions, behind the
// two-byte length prefix DNS-over-TCP framing requires. Each answer is
// recorded once it is written, as DoH's are, because the probe stops at the
// first transport that answers and DoH may never be asked at all.
func (s *encryptedDNSServer) serveDoT(listener net.Listener, config *tls.Config, zone map[string][]netip.Addr, svc Service, recorder *evidenceRecorder) {
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		s.track(raw, true)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(raw, false)
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(tlsConnectionLimit))
			conn := tls.Server(raw, config)
			if err := conn.Handshake(); err != nil {
				return
			}
			for {
				var header [2]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(header[:]))
				if size == 0 || size > dnsMaxMsg {
					return
				}
				msg := make([]byte, size)
				if _, err := io.ReadFull(conn, msg); err != nil {
					return
				}
				reply := dnsReply(msg, zone)
				if reply == nil {
					return
				}
				framed, err := frameDoTReply(reply)
				if err != nil {
					return
				}
				if _, err := conn.Write(framed); err != nil {
					return
				}
				_ = recorder.record(evidenceEvent{Kind: evidenceServiceReply, Service: svc.Name,
					ServiceType: ServiceEncryptedDNS, ServicePort: encryptedDNSDoTPort, Result: replyResponded})
			}
		}()
	}
}

func frameDoTReply(reply []byte) ([]byte, error) {
	if len(reply) > 1<<16-1 {
		return nil, errors.New("DNS response exceeds DoT frame length")
	}
	// #nosec G115 -- the immediately preceding check proves the length fits this uint16 protocol field.
	framed := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(reply)), uint16(len(reply)))
	return append(framed, reply...), nil
}

func (s *encryptedDNSServer) track(conn net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[conn] = struct{}{}
	} else {
		delete(s.conns, conn)
	}
}

func (s *encryptedDNSServer) Close() error {
	var closeErr error
	s.once.Do(func() {
		if s.doh != nil {
			if err := s.doh.Close(); err != nil {
				closeErr = errors.Join(closeErr, err)
			}
		}
		for _, listener := range s.listeners {
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		if s.caPath != "" {
			if err := os.Remove(s.caPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				closeErr = errors.Join(closeErr, err)
			}
			_ = os.Remove(filepath.Dir(s.caPath))
		}
	})
	return closeErr
}
