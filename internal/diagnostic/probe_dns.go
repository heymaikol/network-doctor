package diagnostic

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// resolverTargetRecorder collects what the Go resolver passed to Dial. A and
// AAAA lookups can call it concurrently, so collection is synchronized and the
// snapshot is sorted and deduplicated before it becomes diagnostic evidence.
type resolverTargetRecorder struct {
	mu      sync.Mutex
	targets []string
}

func (r *resolverTargetRecorder) add(target string) {
	r.mu.Lock()
	r.targets = append(r.targets, target)
	r.mu.Unlock()
}

func (r *resolverTargetRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	targets := append([]string(nil), r.targets...)
	slices.Sort(targets)
	return slices.Compact(targets)
}

// lookupIPWithDial resolves host and reports every resolver the lookup dialed.
// The identities come free from the Go resolver's Dial hook, which already
// parses resolv.conf, so we don't have to. Release builds are CGO_ENABLED=0 and
// so already resolve this way; PreferGo only pins that behavior for local cgo
// builds.
//
// Every target, not the last one: LookupIP(ctx, "ip", host) asks A and AAAA as
// independent queries that dial and fail over independently, so the two halves
// of one result can come from two different servers. Dial is called before a
// query goes out and says nothing about the reply, so what a run can prove is
// which servers it tried. Naming any of them as the source of an answer is a
// claim the resolver never made.
//
// Where the Go resolver isn't used the hook is never called, the list comes
// back empty, and the row says nothing rather than guessing. Reading
// GetNetworkParams would fix that on Windows, if the missing identity ever
// bites.
func lookupIPWithDial(ctx context.Context, host string, dial func(context.Context, string, string) (net.Conn, error)) ([]net.IP, []string, error) {
	var targets resolverTargetRecorder
	r := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			targets.add(addr)
			return dial(ctx, network, addr)
		},
	}
	ips, err := r.LookupIP(ctx, "ip", host)
	return ips, targets.snapshot(), err
}

// errNoDNSAllowed refuses every dial answeredWithoutDNS makes, which is how
// that lookup is kept off the network.
var errNoDNSAllowed = errors.New("no DNS query may leave this lookup")

// errHostsFileAnswer is a public lookup that succeeded without a DNS answer
// behind it. The machine resolves the name by itself, so what came back is a
// local override rather than a second opinion, and publicDNSProbe reports N/A.
var errHostsFileAnswer = errors.New("this machine answers the name without DNS, so no public DNS answer is provable")

// answeredWithoutDNS reports whether this machine can resolve host with no DNS
// at all. It asks the Go resolver again through a Dial hook that refuses every
// connection, so no query can leave and the hosts file is the only source left:
// PreferGo has exactly two, and this one removes the other.
//
// That one network-free lookup is what makes the second opinion provable, and it
// is needed because the two host lookup orders hide the same answer in different
// places. Under "hosts: files dns" the file is read before any query, so the hit
// never reaches Dial. Under "hosts: dns files" the file is read after a query
// that came back empty, so the hit follows a real dial to the public server and
// is returned with a nil error (net/dnsclient_unix.go, goLookupIPCNAMEOrder).
// Counting dialed targets sees the first and misses the second; this sees both.
func answeredWithoutDNS(ctx context.Context, host string) bool {
	r := net.Resolver{
		PreferGo: true,
		Dial:     func(context.Context, string, string) (net.Conn, error) { return nil, errNoDNSAllowed },
	}
	// Not the caller's context: every dial fails at once so this cannot block,
	// and a budget that expired between the answer and this check must not be
	// read as "the machine has nothing to say about this name".
	ips, err := r.LookupIP(context.WithoutCancel(ctx), "ip", host)
	return err == nil && len(ips) > 0
}

// lookupIPPublicWithDial bypasses the configured resolver for a second opinion.
// Unavailability is reported as N/A by publicDNSProbe, never as a failure.
//
// A returned answer is one the public server provably supplied. Only a success
// needs the check: an empty answer, an NXDOMAIN, and a transport failure all
// mean the hosts file had nothing to add, because a hit there would have
// replaced them. So the guard runs on the one outcome that could be a local
// override, and hands back errHostsFileAnswer rather than addresses the server
// may never have sent. The targets survive either way: they are what this run
// tried, which is true whoever answered.
func lookupIPPublicWithDial(ctx context.Context, host string, dial func(context.Context, string, string) (net.Conn, error), server string) ([]net.IP, []string, error) {
	var targets resolverTargetRecorder
	var responses publicDNSResponses
	r := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			targets.add(server)
			conn, err := dial(ctx, network, server)
			if err != nil {
				return conn, err
			}
			_, packet := conn.(net.PacketConn)
			observed := &publicDNSConn{Conn: conn, packet: packet, responses: &responses}
			if packet {
				return publicDNSPacketConn{observed}, nil
			}
			return observed, nil
		},
	}
	ips, err := r.LookupIP(ctx, "ip", host)
	if err == nil && len(ips) > 0 && answeredWithoutDNS(ctx, host) {
		return nil, targets.snapshot(), errHostsFileAnswer
	}
	if err != nil {
		responses.mu.Lock()
		defer responses.mu.Unlock()
		if responses.failure != nil {
			err = &publicDNSAnsweredError{responses.failure}
		} else if responses.answered && !dnsNotFound(err) {
			err = &publicDNSAnsweredError{err}
		}
	}
	return ips, targets.snapshot(), err
}

// publicDNSAnsweredError preserves proof of a response even if Go's final
// error is a timeout on the sibling family or a subsequent retry.
type publicDNSAnsweredError struct{ error }

func (e *publicDNSAnsweredError) Unwrap() error { return e.error }

type publicDNSResponses struct {
	mu       sync.Mutex
	answered bool
	failure  *dnsResponseError
}

// publicDNSConn observes the single query Go sends per connection. Verification
// reuses the encrypted-DNS header, question and record framing checks for both
// A and AAAA. Reading bytes or opening a socket alone never proves an answer.
type publicDNSConn struct {
	net.Conn
	packet    bool
	query     dnsQuery
	read      []byte
	responses *publicDNSResponses
}

func (c *publicDNSConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	msg := p[:n]
	if !c.packet {
		if len(msg) < 2 || int(binary.BigEndian.Uint16(msg[:2])) != len(msg)-2 {
			return n, err
		}
		msg = msg[2:]
	}
	if len(msg) >= dnsHeaderLen && binary.BigEndian.Uint16(msg[4:6]) == 1 {
		end, parseErr := skipDNSName(msg, dnsHeaderLen)
		if parseErr == nil && end+4 <= len(msg) {
			c.query = dnsQuery{id: binary.BigEndian.Uint16(msg[:2]), question: append([]byte(nil), msg[dnsHeaderLen:end+4]...)}
		}
	}
	return n, err
}

func (c *publicDNSConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.packet {
		c.observe(p[:n])
	} else {
		// Go reads one length-prefixed response, at most 65535 bytes, per
		// connection. Reads may split both the prefix and the message.
		c.read = append(c.read, p[:n]...)
		if len(c.read) >= 2 && len(c.read)-2 == int(binary.BigEndian.Uint16(c.read[:2])) {
			c.observe(c.read[2:])
			c.read = nil
		}
	}
	return n, err
}

func (c *publicDNSConn) observe(msg []byte) {
	// Unlike encrypted DNS, plaintext needs the echoed question even for
	// FORMERR/NOTIMP: there is no authenticated transport to correlate it.
	if len(c.query.question) == 0 || len(msg) < dnsHeaderLen || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return
	}
	err := c.query.verify(msg)
	var responseErr *dnsResponseError
	if err != nil && !errors.As(err, &responseErr) {
		return
	}
	c.responses.mu.Lock()
	defer c.responses.mu.Unlock()
	c.responses.answered = true
	// Keep a deterministic service error across concurrent A/AAAA replies.
	if responseErr != nil && (c.responses.failure == nil || responseErr.rcode < c.responses.failure.rcode) {
		c.responses.failure = responseErr
	}
}

// Go selects datagram framing by the PacketConn interface, not Dial's network
// argument. Preserve it while observing the connected socket's Read and Write.
type publicDNSPacketConn struct{ *publicDNSConn }

func (c publicDNSPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.Conn.(net.PacketConn).ReadFrom(p)
}

func (c publicDNSPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.Conn.(net.PacketConn).WriteTo(p, addr)
}

// dnsServerLabel shortens a resolver dial address for a probe row: the bare host
// on port 53, host:port otherwise, since a stub resolver on 5353 is worth seeing.
func dnsServerLabel(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if port == "53" {
		return host
	}
	return addr
}

func dnsFailureCause(err error) string {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return ""
	}
	if dnsErr.IsTimeout || timeoutError(err) {
		return DNSCauseTimeout
	}
	// The pure-Go resolver reports a received SERVFAIL as a DNSError whose
	// IsTemporary bit varies across supported Go versions. Once timeout and
	// NXDOMAIN are excluded, the remaining resolver failures are retryable
	// transport/server failures and belong to the temporary class.
	if dnsErr.IsTemporary || !dnsErr.IsNotFound {
		return DNSCauseTemporaryFailure
	}
	return ""
}

// dnsAnswer is one query's outcome, carried back from the goroutine that asked.
type dnsAnswer struct {
	ips     []net.IP
	targets []string
	err     error
}

// retryableDNS reports whether a failure is worth a second query. A timeout or
// a temporary server failure says something about the resolver's health at that
// instant; NXDOMAIN, like an answer, says something about the name, and asking
// twice cannot change either.
func retryableDNS(err error) bool {
	switch dnsFailureCause(err) {
	case DNSCauseTimeout, DNSCauseTemporaryFailure:
		return true
	}
	return false
}

// lookupIPRetrying resolves host and samples the resolver a second time when
// the first query neither answers nor fails conclusively. The second query goes
// out as soon as the first fails (SERVFAIL, or a stub that gives up early),
// and otherwise halfway through the probe budget, alongside a first query that
// is still waiting.
//
// Alongside, not instead of: cutting the first query short to make room would
// halve the patience of every DNS probe, and a resolver that answers late but
// within the budget would be reported as a timeout it never had. Two queries in
// flight cost one extra packet and settle both cases: the resolver that
// recovers mid-probe is heard, and the slow one keeps its own answer.
func (o *netops) lookupIPRetrying(ctx context.Context, host string) ([]net.IP, []string, error) {
	// Buffered for both queries: the loser of the race writes after the winner
	// has been returned, and must not block until the context releases it.
	answers := make(chan dnsAnswer, 2)
	ask := func() {
		ips, targets, err := o.lookupIP(ctx, host)
		answers <- dnsAnswer{ips, targets, err}
	}
	go ask()
	budget := DefaultProbeTimeout
	if deadline, ok := ctx.Deadline(); ok {
		budget = time.Until(deadline)
	}
	resample := time.NewTimer(budget / 2)
	defer resample.Stop()
	outstanding, spare := 1, true
	send := func() {
		if spare {
			spare, outstanding = false, outstanding+1
			go ask()
		}
	}
	var last dnsAnswer
	var targets []string
	for outstanding > 0 {
		select {
		case <-resample.C:
			send()
		case answer := <-answers:
			outstanding--
			targets = append(targets, answer.targets...)
			slices.Sort(targets)
			targets = slices.Compact(targets)
			if !retryableDNS(answer.err) {
				return answer.ips, targets, answer.err
			}
			last = answer
			send()
		}
	}
	return last.ips, targets, last.err
}

// resolverTargetsNote is what the recorded targets may be reported as, and it
// is an attempt in every count. One dialed target is not provenance either:
// with "hosts: dns files" ordering the Go resolver queries DNS first and reads
// the hosts file only when that came back with nothing, so a lookup can dial
// one server, be answered by neither it nor any other server, and return
// addresses no resolver supplied. Dial is also called before a query goes out
// and before the connection is even established, so it never says who replied.
// "Tried" is the whole of what this evidence carries.
//
// Empty where no resolver was dialed, so a row that asked nothing says nothing.
func resolverTargetsNote(targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	labels := make([]string, len(targets))
	for i, target := range targets {
		labels[i] = dnsServerLabel(target)
	}
	if len(labels) == 1 {
		return " (resolver tried: " + labels[0] + ")"
	}
	return " (resolvers tried: " + strings.Join(labels, ", ") + ")"
}

func resolverTargetIPs(targets []string) []net.IP {
	ips := make([]net.IP, 0, len(targets))
	for _, target := range targets {
		if ip := resolverIP(target); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func (o *netops) dnsProbe(host string, litIP net.IP) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
		var r ProbeResult
		if litIP != nil {
			r.Status, r.Addrs, r.SelectedIP = StatusNA, []net.IP{litIP}, litIP
			r.Detail = "literal IP " + litIP.String() + ", no DNS needed"
			return r
		}
		ips, targets, err := o.lookupIPRetrying(ctx, host)
		// "which server told me this" is the first question on a split-DNS or
		// router-vs-Pi-hole setup, and often the whole answer, so every target
		// the run dialed is recorded, and the path to each one with it: a
		// resolver reached over one interface while the application traffic
		// leaves by another is the shape of split DNS, and it is not visible
		// from either row alone. What is not recorded is a claim the run cannot
		// support, so the row names every target it dialed as an attempt and
		// credits the answer to none of them, one target included.
		r.ResolverTargets = targets
		note := resolverTargetsNote(targets)
		routes := o.explainedRouteDecisions(o.referenceRouteDecisions(), resolverTargetIPs(targets)...)
		if err != nil {
			r.Status = StatusFail
			r.Cause = dnsFailureCause(err)
			r.DNSNotFound = dnsNotFound(err)
			r.Detail = "cannot resolve " + host + note + ": " + err.Error()
			r.Fix = dnsFix(runtime.GOOS)
			r.Routes = routes
			return r
		}
		if len(ips) == 0 {
			r.Status = StatusFail
			r.DNSNotFound = true
			r.Detail, r.Fix = "no A/AAAA records for "+host+note, "no address returned: check the hostname / DNS"
			r.Routes = routes
			return r
		}
		r.Status, r.Addrs, r.Routes = StatusPass, ips, routes
		r.Detail = host + " → " + joinIPs(ips) + note
		return r
	}
}

// publicDNSProbe asks a second-opinion resolver the same question the system
// resolver was asked. resolvers is the one address the user named, or the
// automatic candidates, which are tried in order and only moved along when a
// lookup obtained no usable DNS response: a resolver that answered, refused, or
// said the name does not exist has answered this row, whatever it said. That is
// what keeps a host with one working address family from losing the second
// opinion, and it is deliberately not offered to an explicit --public-dns,
// which names the resolver to ask and no other.
//
// The row reports the attempt that ended it, and carries every resolver it
// dialed. Both are needed and neither substitutes for the other: the targets
// are what this run tried, and the answer is only ever credited to the server
// that supplied it.
func (o *netops) publicDNSProbe(host string, litIP net.IP, resolvers []string) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
		if litIP != nil {
			return ProbeResult{Status: StatusNA, Detail: "literal IP " + litIP.String() + ", no DNS needed"}
		}
		var tried []string
		var unreachable []string
		var last ProbeResult
		for i, ip := range resolvers {
			attemptCtx, cancel := publicDNSAttemptContext(ctx, len(resolvers)-i)
			r, err := o.publicDNSAttempt(attemptCtx, host, ip)
			cancel()
			// Every resolver dialed so far, in the order they were dialed, on
			// whichever attempt ends up being reported.
			tried = append(tried, r.ResolverTargets...)
			if len(tried) > 0 {
				r.ResolverTargets = tried
			}
			if err == nil {
				return r
			}
			unreachable = append(unreachable, ip+": "+err.Error())
			last = r
		}
		if len(unreachable) > 1 {
			last.Detail = "public DNS unavailable via " + strings.Join(unreachable, "; via ")
		}
		return last
	}
}

// publicDNSAttemptContext bounds one automatic candidate to an even share of
// the time the probe has left, so a resolver that is routed but silently
// dropped cannot spend the whole row and leave the other family untried. The
// last candidate, a lone explicit resolver, and a probe running without a
// deadline are left alone: they have nothing to make room for.
func publicDNSAttemptContext(ctx context.Context, left int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok || left < 2 {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, time.Now().Add(time.Until(deadline)/time.Duration(left)))
}

// publicDNSAttempt queries one resolver. A non-nil error permits fallback only
// when no usable DNS response was observed. It does not prove unreachability:
// malformed replies and transport failures can both leave no usable response.
func (o *netops) publicDNSAttempt(ctx context.Context, host, publicDNSIP string) (ProbeResult, error) {
	ips, targets, err := o.lookupPublicIP(ctx, host, publicDNSServer(publicDNSIP))
	// A resolver this run dialed is still only a resolver this run tried, so
	// the targets stay on the row as attempt evidence while the answer they
	// did not prove is dropped. Ahead of the target count deliberately: under
	// "hosts: dns files" the public server really was queried, so "never
	// asked" would be the wrong reason for the same N/A.
	if errors.Is(err, errHostsFileAnswer) {
		return ProbeResult{Status: StatusNA, ResolverTargets: targets,
			Detail: "no second opinion: this machine resolves " + host + " without DNS, so a local override cannot be told from " + publicDNSIP + "'s answer"}, nil
	}
	if len(targets) == 0 {
		// No query left this machine, so no other resolver would have been
		// asked either: this is the lookup declining to go out, not a path.
		detail := "lookup completed without querying public DNS"
		if err != nil {
			detail = "public DNS was not queried: " + err.Error()
		}
		return ProbeResult{Status: StatusNA, Detail: detail}, nil
	}
	var answered *publicDNSAnsweredError
	if errors.As(err, &answered) {
		return ProbeResult{Status: StatusNA, ResolverTargets: targets, resolver: publicDNSIP,
			Detail: "public DNS " + publicDNSIP + " answered, but could not resolve " + host + ": " + answered.Error(),
			Fix:    "the resolver answered but did not complete the lookup: retry later or check resolver policy"}, nil
	}
	if dnsNotFound(err) || err == nil && len(ips) == 0 {
		return ProbeResult{
			Status:          StatusPass,
			DNSNotFound:     true,
			ResolverTargets: targets,
			resolver:        publicDNSIP,
			Detail:          publicDNSIP + " reports no A/AAAA records for " + host,
		}, nil
	}
	if err != nil {
		return ProbeResult{Status: StatusNA, ResolverTargets: targets, resolver: publicDNSIP,
			Detail: "public DNS unavailable via " + publicDNSIP + ": " + err.Error()}, err
	}
	return ProbeResult{
		Status:          StatusPass,
		Addrs:           ips,
		ResolverTargets: targets,
		resolver:        publicDNSIP,
		Detail:          host + " → " + joinIPs(ips) + " (via " + publicDNSIP + ")",
	}, nil
}

func dnsNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
