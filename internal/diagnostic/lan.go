package diagnostic

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	LANScanTimeout = 60 * time.Second
	lanWorkers     = 32 // per active probe, at most 96 in flight
	lanAttempt     = 750 * time.Millisecond
)

// A local ICMP send permission denial is not a silent peer. Some policies
// deny only particular destinations, so the whole method is unavailable only
// when every attempted destination was denied this way.
var errLANICMPSendDenied = errors.New("local ICMP send denied")

// LANEvidence records what an address supplied during a LAN scan.
type LANEvidence uint8

const (
	LANICMP LANEvidence = 1 << iota
	LANTCP
	LANNeighbor
)

func (e LANEvidence) Confirmed() bool { return e&(LANICMP|LANTCP) != 0 }

func (e LANEvidence) String() string {
	var names []string
	for _, source := range []struct {
		flag LANEvidence
		name string
	}{{LANICMP, "ICMP echo"}, {LANTCP, "TCP response"}, {LANNeighbor, "neighbor cache"}} {
		if e&source.flag != 0 {
			names = append(names, source.name)
		}
	}
	return strings.Join(names, ", ")
}

type LANObservation struct {
	IP       netip.Addr
	Evidence LANEvidence
}

// LANBinding identifies the interface and address used by a LAN snapshot.
type LANBinding struct {
	Source    netip.Addr
	Interface string
	Index     int
	prefix    netip.Prefix
	hardware  string
}

type lanLink struct {
	net.Interface
	source       netip.Addr
	prefix       netip.Prefix
	locals       map[netip.Addr]bool
	sharedSource bool
}

// DiscoverLAN streams evidence for a private IPv4 source's local subnet,
// capped at its /24. Each update carries all evidence seen for that IP so far.
// The callback runs serially and must return promptly. Warnings describe
// unavailable sources. Already emitted observations survive cancellation.
func DiscoverLAN(ctx context.Context, source netip.Addr, iface string, bound func(LANBinding), emit func(LANObservation)) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, LANScanTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	link, err := findLANLink(source, iface, net.Interfaces, (*net.Interface).Addrs)
	if err != nil {
		return nil, err
	}
	readNeighbors := lanNeighborReader(link)
	bound(link.binding())
	echo, echoErr := lanEchoProbe(link)
	dial := link.dialer()
	return scanLAN(ctx, link, echo, echoErr, dial.DialContext, readNeighbors, emit)
}

func (l lanLink) binding() LANBinding {
	return LANBinding{Source: l.source, Interface: l.Name, Index: l.Index, prefix: l.prefix, hardware: string(l.HardwareAddr)}
}

func (l lanLink) dialer() net.Dialer {
	return net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.IP(l.source.AsSlice())},
		Control:   lanSocketControl(l),
	}
}

func findLANLink(source netip.Addr, name string, interfaces func() ([]net.Interface, error), addrs func(*net.Interface) ([]net.Addr, error)) (lanLink, error) {
	if !source.Is4() || !source.IsPrivate() {
		return lanLink{}, errors.New("LAN discovery requires a private IPv4 source")
	}
	ifaces, err := interfaces()
	if err != nil {
		return lanLink{}, fmt.Errorf("list LAN interfaces: %w", err)
	}
	link := lanLink{source: source, locals: make(map[netip.Addr]bool)}
	owners, matches := 0, 0
	for _, iface := range ifaces {
		addresses, err := addrs(&iface)
		if err != nil {
			return lanLink{}, fmt.Errorf("read addresses for %s: %w", iface.Name, err)
		}
		var prefix netip.Prefix
		for _, addr := range addresses {
			p, err := netip.ParsePrefix(addr.String())
			if err != nil || !p.Addr().Is4() {
				continue
			}
			link.locals[p.Addr()] = true
			if p.Addr() == source && (!prefix.IsValid() || p.Bits() > prefix.Bits()) {
				prefix = p
			}
		}
		if !prefix.IsValid() {
			continue
		}
		owners++
		if name == "" || iface.Name == name {
			link.Interface, link.prefix = iface, prefix.Masked()
			matches++
		}
	}
	if matches != 1 || link.Index <= 0 || link.Flags&net.FlagUp == 0 || link.Flags&net.FlagLoopback != 0 {
		return lanLink{}, fmt.Errorf("LAN source %s must identify one active interface", source)
	}
	link.sharedSource = owners > 1
	return link, nil
}

func (l lanLink) targets() []netip.Addr {
	var network, broadcast netip.Addr
	if l.prefix.Bits() < 31 {
		network = l.prefix.Addr()
		b := network.As4()
		hostMask := ^uint32(0) >> l.prefix.Bits()
		binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(b[:])|hostMask)
		broadcast = netip.AddrFrom4(b)
	}
	var ips []netip.Addr
	scope := netip.PrefixFrom(l.source, 24).Masked()
	for ip := scope.Addr(); scope.Contains(ip); ip = ip.Next() {
		if l.prefix.Contains(ip) && !l.locals[ip] && ip != l.source && ip != network && ip != broadcast {
			ips = append(ips, ip)
		}
	}
	return ips
}

type lanProbe func(context.Context, netip.Addr) (bool, error)

func scanLAN(ctx context.Context, link lanLink, echo lanProbe, echoErr error,
	dial func(context.Context, string, string) (net.Conn, error), neighbors func() ([]netip.Addr, error),
	emit func(LANObservation),
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ips := link.targets()
	var mu sync.Mutex
	seen := make(map[netip.Addr]LANEvidence)
	record := func(ip netip.Addr, evidence LANEvidence) {
		mu.Lock()
		defer mu.Unlock()
		if combined := seen[ip] | evidence; combined != seen[ip] {
			seen[ip] = combined
			emit(LANObservation{IP: ip, Evidence: combined})
		}
	}
	readNeighbors := func() error {
		entries, err := neighbors()
		for _, ip := range entries {
			if slices.Contains(ips, ip) {
				record(ip, LANNeighbor)
			}
		}
		return err
	}
	cacheErr := readNeighbors()
	probes := []struct {
		name      string
		evidence  LANEvidence
		probe     lanProbe
		err       error
		attempts  atomic.Uint32
		denials   atomic.Uint32
		denied    atomic.Bool
		deniedErr error
	}{
		{name: "ICMP echo", evidence: LANICMP, probe: echo, err: echoErr},
		{name: "TCP 80", evidence: LANTCP, probe: lanTCPProbe(dial, "80")},
		{name: "TCP 443", evidence: LANTCP, probe: lanTCPProbe(dial, "443")},
	}
	var wg sync.WaitGroup
	for i := range probes {
		p := &probes[i]
		if p.probe == nil {
			continue
		}
		var unavailable atomic.Bool
		for worker := range min(lanWorkers, len(ips)) {
			wg.Go(func() {
				for j := worker; j < len(ips) && ctx.Err() == nil && !unavailable.Load(); j += lanWorkers {
					attempt, cancel := context.WithTimeout(ctx, lanAttempt)
					ok, err := p.probe(attempt, ips[j])
					cancel()
					p.attempts.Add(1)
					if errors.Is(err, errLANICMPSendDenied) {
						p.denials.Add(1)
						if p.denied.CompareAndSwap(false, true) {
							p.deniedErr = err
						}
						continue
					}
					if ok {
						record(ips[j], p.evidence)
					}
					if err != nil && unavailable.CompareAndSwap(false, true) {
						p.err = err
					}
				}
			})
		}
	}
	wg.Wait()
	for i := range probes {
		p := &probes[i]
		if p.err == nil && p.attempts.Load() != 0 && p.attempts.Load() == p.denials.Load() {
			p.err = p.deniedErr
		}
	}
	if ctx.Err() == nil && cacheErr == nil {
		// Ordinary IP traffic may have populated the cache via kernel ARP.
		cacheErr = readNeighbors()
	}
	var warnings []string
	if cacheErr != nil {
		warnings = append(warnings, "Neighbor cache unavailable: "+cacheErr.Error())
	}
	for i := range probes {
		if p := &probes[i]; p.err != nil {
			warnings = append(warnings, p.name+" unavailable: "+p.err.Error())
		}
	}
	if err := ctx.Err(); err != nil {
		return warnings, err
	}
	if cacheErr != nil && probes[0].err != nil && probes[1].err != nil && probes[2].err != nil {
		return warnings, errors.New("no LAN discovery mechanism available")
	}
	return warnings, nil
}

var errLANUnavailable = errors.New("interface binding unavailable")

func lanDialUnavailable(err error) bool {
	var syscallErr *os.SyscallError
	return errors.Is(err, errLANUnavailable) || errors.As(err, &syscallErr) &&
		(syscallErr.Syscall == "socket" || syscallErr.Syscall == "bind")
}

func lanSocketControl(link lanLink) func(string, string, syscall.RawConn) error {
	return func(_, _ string, conn syscall.RawConn) error {
		var bindErr error
		if err := conn.Control(func(fd uintptr) { bindErr = bindLANSocket(fd, link) }); err != nil {
			return fmt.Errorf("%w: %w", errLANUnavailable, err)
		}
		if bindErr != nil {
			return fmt.Errorf("%w: %w", errLANUnavailable, bindErr)
		}
		return nil
	}
}

func lanTCPProbe(dial func(context.Context, string, string) (net.Conn, error), port string) lanProbe {
	return func(ctx context.Context, ip netip.Addr) (bool, error) {
		conn, err := dial(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
		if err == nil {
			_ = conn.Close()
			return true, nil
		}
		if lanDialUnavailable(err) {
			return false, err
		}
		return isConnectionRefused(err), nil
	}
}

func validLANHardware(addr []byte) bool {
	return len(addr) != 0 && (len(addr) != 6 || addr[0]&1 == 0) && slices.ContainsFunc(addr, func(b byte) bool { return b != 0 })
}
