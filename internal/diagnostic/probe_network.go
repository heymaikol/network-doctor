package diagnostic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// opsFromSources copies the package-level ops for one pass, and binds every
// dial to the selected interface's addresses when there is a selection. A copy
// is taken even with no selection, because a pass owns its own route cache.
func opsFromSources(sources *SourceAddresses) *netops {
	o := *defaultOps
	if sources == nil {
		return &o
	}
	copySources := &SourceAddresses{
		IPv4: append(net.IP(nil), sources.IPv4...),
		IPv6: append(net.IP(nil), sources.IPv6...),
	}
	o.sources = copySources
	o.dialContext = dialContextFromSources(copySources)
	o.dialTLS = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		conn, err := o.dialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	o.lookupIP = func(ctx context.Context, host string) ([]net.IP, []string, error) {
		return lookupIPWithDial(ctx, host, o.dialContext)
	}
	o.lookupPublicIP = func(ctx context.Context, host, server string) ([]net.IP, []string, error) {
		return lookupIPPublicWithDial(ctx, host, o.dialContext, server)
	}
	o.portalCheck = func(ctx context.Context, ep portalEndpoint) (portalObservation, error) {
		return portalCheckWithDial(ctx, ep, o.dialContext)
	}
	return &o
}

func dialerFromSource(source net.IP, network string, resolverDial func(context.Context, string, string) (net.Conn, error)) *net.Dialer {
	var local net.Addr = &net.TCPAddr{IP: source}
	if strings.HasPrefix(network, "udp") {
		local = &net.UDPAddr{IP: source}
	}
	d := &net.Dialer{LocalAddr: local}
	// Hostname resolution performed inside DialContext must use the same source
	// path too. Resolver destinations are already numeric, so this cannot recurse.
	d.Resolver = &net.Resolver{PreferGo: true, Dial: resolverDial}
	return d
}

func dialContextFromSources(sources *SourceAddresses) func(context.Context, string, string) (net.Conn, error) {
	var dial func(context.Context, string, string) (net.Conn, error)
	dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if source, family := sources.forDial(network, addr); family != 0 {
			if source == nil {
				return nil, fmt.Errorf("selected interface has no IPv%d source address", family)
			}
			return dialFamily(ctx, source, network, addr, dial)
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		type result struct {
			conn net.Conn
			err  error
		}
		results := make(chan result, 2)
		// won marks the connection the fan-in below will hand to the caller.
		// Whoever loses the claim owns its socket and has to close it.
		var won atomic.Bool
		families := 0
		for _, item := range []struct {
			source  net.IP
			network string
		}{{sources.IPv4, network + "4"}, {sources.IPv6, network + "6"}} {
			if item.source == nil {
				continue
			}
			families++
			go func(source net.IP, familyNetwork string) {
				conn, err := dialFamily(ctx, source, familyNetwork, addr, dial)
				// Exactly one report per launched goroutine, or the fan-in waits
				// for a result that can never arrive. A connection that cannot be
				// handed back, because the deadline passed or the other family
				// already won, is closed here rather than left to the GC.
				if err == nil && (ctx.Err() != nil || !won.CompareAndSwap(false, true)) {
					_ = conn.Close()
					conn = nil
					if err = ctx.Err(); err == nil {
						err = errFamilyLost
					}
				}
				results <- result{conn, err}
			}(item.source, item.network)
		}
		var errs []error
		for range families {
			result := <-results
			if result.err == nil {
				return result.conn, nil
			}
			errs = append(errs, result.err)
		}
		return nil, errors.Join(errs...)
	}
	return dial
}

// forDial returns the selected source and address family. Family zero means a
// hostname on a generic network, which must try each selected family.
func (s SourceAddresses) forDial(network, addr string) (net.IP, int) {
	if strings.HasSuffix(network, "4") {
		return s.IPv4, 4
	}
	if strings.HasSuffix(network, "6") {
		return s.IPv6, 6
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				return s.IPv4, 4
			}
			return s.IPv6, 6
		}
	}
	return nil, 0
}

// applyDialWarnings downgrades a successful dial result to Warn when it is
// degraded: high connect latency, observed sibling address failures,
// or an ambiguous source interface. Notes are appended to Detail.
func applyDialWarnings(r *ProbeResult, rtt time.Duration, extra ...string) {
	notes := extra
	if rtt >= warnRTT {
		notes = append(notes, fmt.Sprintf("high latency (%dms)", rtt.Milliseconds()))
	}
	// A dial canceled because another address won is useful attempt evidence,
	// but it does not prove that address failed. Callers hand over only the
	// winning family's attempts (see targetTCPProbe).
	var addresses, failures []net.IP
	for _, attempt := range r.Attempts {
		if !containsResolvedIP(addresses, attempt.IP) {
			addresses = append(addresses, attempt.IP)
		}
		if attempt.Err != nil && !isCanceledAttempt(attempt) && !containsResolvedIP(failures, attempt.IP) {
			failures = append(failures, attempt.IP)
		}
	}
	if len(failures) > 0 {
		notes = append(notes, fmt.Sprintf("%d of %d address(es) failed", len(failures), len(addresses)))
	}
	if r.ifaceAmbiguous {
		notes = append(notes, "ambiguous source interface")
	}
	if len(notes) > 0 {
		r.Status = StatusWarn
		r.Detail += "; warning: " + strings.Join(notes, ", ")
	}
}

// compatibleSourceIPs drops destinations whose address family the selected
// interface has no source address for. Probes that dial a fixed endpoint use it
// so --iface never produces a cross-family dial, and so an interface that
// simply lacks a family reports N/A rather than a failure it could not avoid.
// Without a selection every family is usable and the list is returned as-is.
func (o *netops) compatibleSourceIPs(ips []net.IP) []net.IP {
	if o.sources == nil {
		return ips
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil && o.sources.IPv4 != nil || ip.To4() == nil && o.sources.IPv6 != nil {
			out = append(out, ip)
		}
	}
	return out
}

// familyState reports what the direct-egress dial proved about one address
// family. No eligible endpoint means the selected source has no address of that
// family, so nothing was dialed and there is nothing to report: the state stays
// empty rather than claiming an outage in a family that was never tested.
func familyState(ips []net.IP, conn net.Conn) string {
	switch {
	case len(ips) == 0:
		return ""
	case conn != nil:
		return FamilyReachable
	default:
		return FamilyUnreachable
	}
}

// targetFamilyState requires every eligible address to have been attempted
// before it calls a whole target family unreachable. A canceled probe or an
// early winner in another family cannot turn unattempted addresses into proof.
func targetFamilyState(ips []net.IP, conn net.Conn, attempts []Attempt) string {
	if len(ips) == 0 {
		return ""
	}
	if conn != nil {
		return FamilyReachable
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(attempts, func(attempt Attempt) bool { return attempt.IP.Equal(ip) }) {
			return ""
		}
	}
	return FamilyUnreachable
}

// interleaveFamilies orders addresses IPv6-first, alternating families
// (RFC 8305 §4), so one broken family can't monopolize the attempt sequence.
func interleaveFamilies(ips []net.IP) []net.IP {
	v4, v6 := splitFamilies(ips)
	if len(v6) == 0 || len(v4) == 0 {
		return ips
	}
	out := make([]net.IP, 0, len(ips))
	for i := 0; i < len(v6) || i < len(v4); i++ {
		if i < len(v6) {
			out = append(out, v6[i])
		}
		if i < len(v4) {
			out = append(out, v4[i])
		}
	}
	return out
}

func splitFamilies(ips []net.IP) (v4, v6 []net.IP) {
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	return v4, v6
}

// dialIPs races ip:port connection attempts Happy Eyeballs style (RFC 8305):
// addresses are interleaved by family (IPv6 first), each attempt starts
// attemptDelay after the previous one (sooner once it fails), and the first
// success cancels the rest. Returns the winning conn, the IP that won (pinned
// for protocol probes), failed attempts that started before the win plus the
// winner, and the winning RTT. A cancelled/expired ctx dials nothing.
func (o *netops) dialIPs(ctx context.Context, ips []net.IP, port int) (net.Conn, net.IP, []Attempt, time.Duration) {
	ips = interleaveFamilies(ips)
	if len(ips) > maxAttempts {
		ips = ips[:maxAttempts]
	}
	if len(ips) == 0 {
		return nil, nil, nil, 0
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel() // unblocks pending winner hand-offs so losers close their conns

	type result struct {
		conn net.Conn
		att  Attempt
	}
	results := make(chan result, len(ips))
	next := make(chan struct{}, len(ips)) // a failure fast-forwards the stagger
	started := make(chan struct{}, len(ips))
	scheduled := make(chan struct{})

	go func() {
		defer close(scheduled)
		for i, ip := range ips {
			if i > 0 {
				t := time.NewTimer(attemptDelay)
				select {
				case <-t.C:
				case <-next:
				case <-dctx.Done():
					t.Stop()
					return
				}
				t.Stop()
			}
			if dctx.Err() != nil {
				return
			}
			started <- struct{}{}
			go func(ip net.IP) {
				start := time.Now()
				network := "tcp6"
				if ip.To4() != nil {
					network = "tcp4"
				}
				conn, err := o.dialContext(dctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
				att := Attempt{IP: ip, Dur: since(start), Err: err}
				if err != nil {
					att.Cause = ConnectionFailureCause(err)
					att.Aborted = dctx.Err() != nil
				}
				results <- result{conn, att}
				if err != nil {
					next <- struct{}{}
				}
			}(ip)
		}
	}()

	// A winner cancels the dials already in flight. Drain those started dials so
	// their failures remain visible and no successful loser leaks its socket.
	var attempts []Attempt
	completed := 0
	drain := func() {
		cancel()
		<-scheduled
		for completed < len(started) {
			got := <-results
			completed++
			if got.conn != nil {
				_ = got.conn.Close()
			}
			if got.att.Err != nil {
				attempts = append(attempts, got.att)
			}
		}
	}
	for completed < len(ips) {
		select {
		case got := <-results:
			completed++
			if got.att.Err != nil {
				if got.conn != nil {
					_ = got.conn.Close()
				}
				attempts = append(attempts, got.att)
				continue
			}
			drain()
			attempts = append(attempts, got.att) // winner last
			return got.conn, got.att.IP, attempts, got.att.Dur
		case <-ctx.Done():
			before := len(attempts)
			drain()
			for i := before; i < len(attempts); i++ {
				attempts[i].Aborted = true
			}
			return nil, nil, attempts, 0
		}
	}
	<-scheduled
	return nil, nil, attempts, 0
}

// pathIdentity returns the source IP for a destination, the interface name to
// show for it, and whether that mapping was ambiguous. On a successful connect
// it reads the winning LocalAddr (ground truth); otherwise it falls back to a
// UDP "connect" (sends no packets) for path identity only, not a reachability
// claim.
func (o *netops) pathIdentity(ctx context.Context, conn net.Conn, dstIP net.IP, port int) (net.IP, string, bool) {
	var src net.IP
	if conn != nil {
		if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			src = la.IP
		}
	} else if dstIP != nil {
		if c, err := o.dialContext(ctx, "udp", net.JoinHostPort(dstIP.String(), strconv.Itoa(port))); err == nil {
			if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
				src = la.IP
			}
			_ = c.Close()
		}
	}
	if src == nil {
		return nil, "", false
	}
	name, ambiguous := o.ifaceForIP(src)
	return src, name, ambiguous
}

func joinIPs(ips []net.IP) string {
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = ip.String()
	}
	return strings.Join(parts, ", ")
}
