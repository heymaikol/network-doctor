//go:build linux

package diagnostic

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
)

// The tests below build kernel replies byte by byte, so the parser is checked
// against the wire format rather than against whatever this developer's own
// machine happens to route today.

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, v)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

// rtMsg lays out an rtmsg header the way the kernel does.
func rtMsg(family, dstLen, table, rtType uint8, attrs ...[]byte) netlinkMessage {
	data := make([]byte, rtMsgLen)
	data[0], data[1], data[4], data[7] = family, dstLen, table, rtType
	for _, a := range attrs {
		data = append(data, a...)
	}
	return netlinkMessage{Type: unix.RTM_NEWROUTE, Data: data}
}

func TestParseRouteReplyReadsTheKernelsDecision(t *testing.T) {
	dst := netip.MustParseAddr("198.51.100.7")
	msg := rtMsg(unix.AF_INET, 16, unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
		rtAttr(unix.RTA_GATEWAY, net.ParseIP("192.168.1.1").To4()),
		rtAttr(unix.RTA_PREFSRC, net.ParseIP("192.168.1.20").To4()),
		rtAttr(unix.RTA_PRIORITY, u32(100)),
		rtAttr(unix.RTA_TABLE, u32(unix.RT_TABLE_MAIN)),
	)
	got, ok := parseRouteReply([]netlinkMessage{msg}, dst, nil)
	if !ok {
		t.Fatal("a well formed reply was not parsed")
	}
	// The kernel echoes the length the request asked about rather than the
	// entry it matched, so no prefix is claimed on this platform.
	if got.Prefix.IsValid() {
		t.Errorf("prefix = %q, want none: a route lookup reply does not carry the matched entry", got.Prefix)
	}
	if got.Gateway.String() != "192.168.1.1" || got.Source.String() != "192.168.1.20" {
		t.Errorf("gateway/source = %v/%v, want 192.168.1.1/192.168.1.20", got.Gateway, got.Source)
	}
	if !got.MetricKnown || got.Metric != 100 {
		t.Errorf("metric = %d (known %t), want 100", got.Metric, got.MetricKnown)
	}
	if got.Table != "" {
		t.Errorf("table = %q, want the main table reported as unremarkable", got.Table)
	}
	if got.Unreachable {
		t.Error("a unicast route was reported as unreachable")
	}
}

// A metric of 0 is a real metric on Linux, and an absent RTA_PRIORITY is not
// the same thing.
func TestParseRouteReplyKeepsAZeroMetricApartFromNone(t *testing.T) {
	dst := netip.MustParseAddr("198.51.100.7")
	with, _ := parseRouteReply([]netlinkMessage{rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST, rtAttr(unix.RTA_PRIORITY, u32(0)))}, dst, nil)
	if !with.MetricKnown || with.Metric != 0 {
		t.Errorf("an explicit metric of 0 = %d (known %t), want a recorded zero", with.Metric, with.MetricKnown)
	}
	without, _ := parseRouteReply([]netlinkMessage{rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST)}, dst, nil)
	if without.MetricKnown {
		t.Error("an absent metric was reported as known")
	}
}

// The kernel's own way of saying there is no route. RTN_THROW is not one of
// them: it abandons a table and sends the lookup on to the next rule, so a
// later table may still route the destination and calling it "no route" would
// answer a question the kernel had not finished asking.
func TestParseRouteReplyReportsUnreachableRouteTypes(t *testing.T) {
	dst := netip.MustParseAddr("198.51.100.7")
	thrown, ok := parseRouteReply([]netlinkMessage{rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_THROW)}, dst, nil)
	if ok && thrown.Unreachable {
		t.Error("a throw route was reported as no route, but it only ends one table's lookup")
	}
	for _, rtType := range []uint8{unix.RTN_UNREACHABLE, unix.RTN_BLACKHOLE, unix.RTN_PROHIBIT} {
		got, ok := parseRouteReply([]netlinkMessage{rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, rtType)}, dst, nil)
		if !ok || !got.Unreachable {
			t.Errorf("rtm_type %d = %+v/%v, want an unreachable decision", rtType, got, ok)
		}
		if got.Iface != "" || got.Prefix.IsValid() {
			t.Errorf("rtm_type %d invented path fields: %+v", rtType, got)
		}
	}
}

// A next hop the kernel expressed in the other address family is still a next
// hop. Reading only RTA_GATEWAY would leave the decision looking gatewayless,
// and a gatewayless decision is reported as on-link, which would be netdoc
// saying there is no router in the way while the kernel was naming one.
func TestParseRouteReplyReadsAViaNextHop(t *testing.T) {
	dst := netip.MustParseAddr("198.51.100.7")
	via := append(append([]byte{}, u16(unix.AF_INET6)...), net.ParseIP("fe80::1").To16()...)
	got, ok := parseRouteReply([]netlinkMessage{
		rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST, rtAttr(unix.RTA_VIA, via)),
	}, dst, nil)
	if !ok || got.Gateway == nil || got.Gateway.String() != "fe80::1" {
		t.Fatalf("gateway = %v (ok %v), want the via next hop", got.Gateway, ok)
	}
	got.Iface = "eth0"
	if reason := routeReason(got, RouteDecision{}); reason == RouteReasonOnLink {
		t.Errorf("reason = %q for a destination the kernel gave a router for", reason)
	}
	// A malformed or unfamiliar rtvia is no next hop rather than a guess.
	for _, bad := range [][]byte{{}, u16(unix.AF_INET6), append(u16(unix.AF_INET), 1, 2, 3), u16(0xff)} {
		if ip := netlinkVia(bad); ip != nil {
			t.Errorf("netlinkVia(%v) = %v, want none", bad, ip)
		}
	}
}

// A policy-routing table keeps its number, because the number is the point.
func TestRouteTableNameKeepsPolicyTableNumbers(t *testing.T) {
	cases := map[uint32]struct {
		name  string
		known bool
	}{
		// The main table is a table the kernel named, spelled as the
		// unremarkable case; RT_TABLE_UNSPEC is the kernel naming none, and
		// the two must not come out the same.
		unix.RT_TABLE_MAIN:    {"", true},
		unix.RT_TABLE_UNSPEC:  {"", false},
		unix.RT_TABLE_LOCAL:   {"local", true},
		unix.RT_TABLE_DEFAULT: {"default", true},
		51820:                 {"table 51820", true},
	}
	for id, want := range cases {
		got, known := routeTableName(id)
		if got != want.name || known != want.known {
			t.Errorf("routeTableName(%d) = %q/%v, want %q/%v", id, got, known, want.name, want.known)
		}
	}
	// rtm_table saturates at a byte, so the attribute has to win.
	dst := netip.MustParseAddr("198.51.100.7")
	got, _ := parseRouteReply([]netlinkMessage{rtMsg(unix.AF_INET, 0, 253, unix.RTN_UNICAST, rtAttr(unix.RTA_TABLE, u32(51820)))}, dst, nil)
	if got.Table != "table 51820" {
		t.Errorf("table = %q, want the attribute to win over the saturated byte", got.Table)
	}
}

// A reply that is not a route, and a truncated one, are both "no answer"
// rather than a decision assembled out of zeroes.
func TestParseRouteReplyRefusesWhatIsNotADecision(t *testing.T) {
	dst := netip.MustParseAddr("198.51.100.7")
	if _, ok := parseRouteReply(nil, dst, nil); ok {
		t.Error("an empty reply produced a decision")
	}
	if _, ok := parseRouteReply([]netlinkMessage{{Type: unix.RTM_NEWLINK, Data: make([]byte, rtMsgLen)}}, dst, nil); ok {
		t.Error("a link message was parsed as a route")
	}
	if _, ok := parseRouteReply([]netlinkMessage{{Type: unix.RTM_NEWROUTE, Data: []byte{1, 2}}}, dst, nil); ok {
		t.Error("a truncated route message produced a decision")
	}
}

// rtm_dst_len is the length the request asked about, not the entry the kernel
// matched: every answer to a host lookup comes back at the full address
// length whatever the table holds. Reading it as the matched prefix would
// report every destination as a host route, so no length in the reply may
// produce one.
func TestParseRouteReplyNeverReadsTheEchoedPrefixLength(t *testing.T) {
	dst := netip.MustParseAddr("198.51.100.7")
	for _, dstLen := range []uint8{0, 16, 32, 99} {
		got, ok := parseRouteReply([]netlinkMessage{rtMsg(unix.AF_INET, dstLen, unix.RT_TABLE_MAIN, unix.RTN_UNICAST)}, dst, nil)
		if !ok {
			t.Fatalf("dst_len %d: the reply was rejected outright", dstLen)
		}
		if got.Prefix.IsValid() {
			t.Errorf("dst_len %d produced prefix %q, want none", dstLen, got.Prefix)
		}
		if routeReason(got, RouteDecision{}) == RouteReasonHostRoute {
			t.Errorf("dst_len %d was read as a host route", dstLen)
		}
	}
}

// Destinations that leave by one interface read that interface once per pass,
// not once per destination. The probe budget allows maxAttempts destinations,
// so that many routes through one egress is the realistic worst case.
func TestParseRouteReplyAcquiresASharedInterfaceOnce(t *testing.T) {
	var acquired []int
	saved := linkAcquire
	linkAcquire = func(index int) (string, int, ifaceFacts) {
		acquired = append(acquired, index)
		return "eth0", 1500, ifaceFacts{Name: "eth0", NoLinkLayer: true}
	}
	t.Cleanup(func() { linkAcquire = saved })
	links := newLinkCache()
	for i := range maxAttempts {
		dst := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})
		msg := rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST, rtAttr(unix.RTA_OIF, u32(7)))
		got, ok := parseRouteReply([]netlinkMessage{msg}, dst, links)
		if !ok || got.Iface != "eth0" {
			t.Fatalf("destination %d = %+v/%v, want a route through eth0", i, got, ok)
		}
	}
	if len(acquired) != 1 {
		t.Errorf("acquired interface %d times for %d destinations through it (indexes %v), want once", len(acquired), maxAttempts, acquired)
	}
}

// Outside a pass there is no cache, and each decision reads its interface, as
// every lookup did before the pass cache existed.
func TestNilLinkCacheReadsEveryDecision(t *testing.T) {
	var acquired int
	saved := linkAcquire
	linkAcquire = func(int) (string, int, ifaceFacts) {
		acquired++
		return "eth0", 1500, ifaceFacts{Name: "eth0"}
	}
	t.Cleanup(func() { linkAcquire = saved })
	for i := range 3 {
		dst := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})
		msg := rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST, rtAttr(unix.RTA_OIF, u32(7)))
		if _, ok := parseRouteReply([]netlinkMessage{msg}, dst, nil); !ok {
			t.Fatalf("destination %d was not parsed", i)
		}
	}
	if acquired != 3 {
		t.Errorf("acquired interface %d times without a pass cache, want one per decision", acquired)
	}
}

// Different interfaces stay apart: each index is read once, and a decision
// reports the interface its own index named, never another pass's.
func TestLinkCacheKeepsInterfacesApart(t *testing.T) {
	names := map[int]string{7: "eth0", 9: "wg0"}
	reads := map[int]int{}
	saved := linkAcquire
	linkAcquire = func(index int) (string, int, ifaceFacts) {
		reads[index]++
		return names[index], 1500, ifaceFacts{Name: names[index]}
	}
	t.Cleanup(func() { linkAcquire = saved })
	links := newLinkCache()
	dst := netip.MustParseAddr("198.51.100.7")
	for _, index := range []uint32{7, 9, 7, 9, 7} {
		msg := rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST, rtAttr(unix.RTA_OIF, u32(index)))
		got, ok := parseRouteReply([]netlinkMessage{msg}, dst, links)
		if !ok || got.Iface != names[int(index)] {
			t.Fatalf("index %d = %+v/%v, want %q", index, got, ok, names[int(index)])
		}
	}
	if reads[7] != 1 || reads[9] != 1 {
		t.Errorf("reads = %v, want one per interface index", reads)
	}
}

// A read that found nothing is the answer for the pass. The interface stays
// unknown, and asking again would only repeat the miss.
func TestLinkCacheKeepsAFailedReadAsTheAnswer(t *testing.T) {
	var reads int
	saved := linkAcquire
	linkAcquire = func(int) (string, int, ifaceFacts) {
		reads++
		return "", 0, ifaceFacts{}
	}
	t.Cleanup(func() { linkAcquire = saved })
	links := newLinkCache()
	dst := netip.MustParseAddr("198.51.100.7")
	for range 3 {
		msg := rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST, rtAttr(unix.RTA_OIF, u32(7)))
		got, ok := parseRouteReply([]netlinkMessage{msg}, dst, links)
		if !ok || got.Iface != "" || got.MTU != 0 || got.Tunnel != TunnelUnknown {
			t.Fatalf("failed read = %+v/%v, want an unknown interface", got, ok)
		}
	}
	if reads != 1 {
		t.Errorf("read the failed interface %d times, want once per pass", reads)
	}
}

// The cache changes when an interface is read, never what a decision says.
func TestLinkCacheDecisionsMatchUncachedReads(t *testing.T) {
	saved := linkAcquire
	linkAcquire = func(int) (string, int, ifaceFacts) {
		return "wg0", 1420, ifaceFacts{Name: "wg0", Kind: "wireguard", PointToPoint: true}
	}
	t.Cleanup(func() { linkAcquire = saved })
	dst := netip.MustParseAddr("198.51.100.7")
	msg := rtMsg(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
		rtAttr(unix.RTA_GATEWAY, net.ParseIP("192.168.1.1").To4()), rtAttr(unix.RTA_OIF, u32(5)))
	plain, _ := parseRouteReply([]netlinkMessage{msg}, dst, nil)
	cached, _ := parseRouteReply([]netlinkMessage{msg}, dst, newLinkCache())
	if !reflect.DeepEqual(plain, cached) {
		t.Errorf("cached decision = %+v, want the uncached %+v", cached, plain)
	}
	if cached.Iface != "wg0" || cached.MTU != 1420 {
		t.Errorf("decision = %+v, want wg0 at MTU 1420", cached)
	}
}

// Askers for an interface already being read wait for that read, which happens
// once. synctest.Wait returns only once every asker is blocked in the cache.
func TestLinkCacheReadsOneInterfaceOnceWhileInFlight(t *testing.T) {
	saved := linkAcquire
	defer func() { linkAcquire = saved }()
	synctest.Test(t, func(t *testing.T) {
		var reads atomic.Int32
		release := make(chan struct{})
		linkAcquire = func(int) (string, int, ifaceFacts) {
			reads.Add(1)
			<-release
			return "eth0", 1500, ifaceFacts{Name: "eth0"}
		}
		links := newLinkCache()
		var wg sync.WaitGroup
		for range 3 {
			wg.Go(func() {
				if name, _, _ := links.get(7); name != "eth0" {
					t.Errorf("waiter read %q, want eth0", name)
				}
			})
		}
		synctest.Wait()
		if n := reads.Load(); n != 1 {
			t.Errorf("%d reads in flight, want 1", n)
		}
		close(release)
		wg.Wait()
	})
}

// Reads of different interfaces overlap: each waits inside the read until the
// other has entered too. A cache holding one lock across a read cannot allow it.
func TestLinkCacheReadsDifferentInterfacesConcurrently(t *testing.T) {
	saved := linkAcquire
	t.Cleanup(func() { linkAcquire = saved })
	// Buffered for both workers, so a read that runs late never blocks on
	// announcing itself.
	entered, release := make(chan int, 2), make(chan struct{})
	linkAcquire = func(index int) (string, int, ifaceFacts) {
		entered <- index
		<-release
		return "eth0", 1500, ifaceFacts{Name: "eth0"}
	}
	links := newLinkCache()
	var wg sync.WaitGroup
	// Deferred, so every return path, including the failed Fatal, closes release
	// and joins both workers before Cleanup restores linkAcquire. Defers run in
	// reverse order: close(release) first, then the Wait.
	defer wg.Wait()
	defer close(release)
	for _, index := range []int{7, 9} {
		wg.Go(func() { links.get(index) })
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("interface reads were serialized: the second never entered while the first was in flight")
		}
	}
}

// Each pass builds its own lookups, so the interface cache is fresh on every
// Watch Mode pass, and one pass's reads never serve the next.
func TestEachPassGetsItsOwnLinkCache(t *testing.T) {
	saved := linkAcquire
	var reads int
	linkAcquire = func(index int) (string, int, ifaceFacts) {
		reads++
		return saved(index)
	}
	t.Cleanup(func() { linkAcquire = saved })
	loopback := func(routeFor func(dst, source net.IP) (RouteDecision, bool)) {
		for i := 1; i <= 4; i++ {
			if _, ok := routeFor(net.IPv4(127, 0, 0, byte(i)), nil); !ok {
				t.Skip("the kernel did not answer loopback route lookups in this environment")
			}
		}
	}
	first, _ := newPassRouteLookups()
	loopback(first)
	if reads != 1 {
		t.Errorf("first pass read loopback %d times for four destinations, want once", reads)
	}
	second, _ := newPassRouteLookups()
	loopback(second)
	if reads != 2 {
		t.Errorf("second pass read loopback %d times in total, want a fresh read (2)", reads)
	}
}

// BuildProbesFromSources asks for one lookup pair per pass and installs it, so
// each pass's probes answer from the pair that pass was built with. A count
// alone would pass even if the pair were built and never reached the cache.
func TestBuildProbesFromSourcesBuildsOnePassLookupPair(t *testing.T) {
	saved := defaultOps.passRoutes
	var built int
	defaultOps.passRoutes = func() (
		func(dst, source net.IP) (RouteDecision, bool),
		func(dst, source net.IP, zone string) (RouteDecision, bool),
	) {
		built++
		name := fmt.Sprintf("pass-%d", built)
		return func(net.IP, net.IP) (RouteDecision, bool) {
				return RouteDecision{Iface: name}, true
			}, func(net.IP, net.IP, string) (RouteDecision, bool) {
				return RouteDecision{}, false
			}
	}
	t.Cleanup(func() { defaultOps.passRoutes = saved })
	for pass := 1; pass <= 2; pass++ {
		var got string
		for _, p := range BuildProbesFromSources(nil, nil, "", false) {
			if p.ID == ProbeIface {
				if r := p.Run(context.Background(), map[ProbeID]ProbeResult{}); len(r.Routes) != 0 {
					got = r.Routes[0].Iface
				}
			}
		}
		if want := fmt.Sprintf("pass-%d", pass); got != want {
			t.Errorf("pass %d reported route via %q, want %q from its own lookup pair", pass, got, want)
		}
	}
	if built != 2 {
		t.Errorf("built %d lookup pairs for two passes, want one each", built)
	}
}

// One pass asking about sixteen loopback destinations, all leaving by lo. The
// real kernel answers every lookup, so the gap between the two rows is the
// interface reads a pass no longer repeats. Numbers are for loopback only.
func BenchmarkRouteLookupsOneEgress(b *testing.B) {
	dsts := make([]net.IP, maxAttempts)
	for i := range dsts {
		dsts[i] = net.IPv4(127, 0, 0, byte(i+1))
	}
	b.Run("uncached", func(b *testing.B) {
		for b.Loop() {
			for _, dst := range dsts {
				lookupRouteDecision(dst, nil)
			}
		}
	})
	b.Run("per-pass", func(b *testing.B) {
		for b.Loop() {
			routeFor, _ := newPassRouteLookups()
			for _, dst := range dsts {
				routeFor(dst, nil)
			}
		}
	})
}

// The real kernel, on this machine, for a destination that is certainly not a
// host route: it must not come back claiming to be one.
func TestLookupRouteDecisionClaimsNoMatchedPrefix(t *testing.T) {
	got, ok := lookupRouteDecision(net.ParseIP("127.0.0.1"), nil)
	if !ok {
		t.Skip("the kernel did not answer a route lookup in this environment")
	}
	if got.Prefix.IsValid() {
		t.Errorf("prefix = %q, want none on a platform that does not report the matched entry", got.Prefix)
	}
}

func TestNetlinkAttrsWalksTheAttributeStream(t *testing.T) {
	var b []byte
	b = append(b, rtAttr(unix.RTA_OIF, u32(3))...)
	b = append(b, rtAttr(unix.RTA_GATEWAY, net.ParseIP("192.168.1.1").To4())...)
	b = append(b, rtAttr(iflaIfName, []byte("wg0\x00"))...)
	attrs := netlinkAttrs(b)
	if len(attrs) != 3 {
		t.Fatalf("walked %d attributes, want 3", len(attrs))
	}
	if attrs[0].Type != unix.RTA_OIF || binary.NativeEndian.Uint32(attrs[0].Value) != 3 {
		t.Errorf("first attribute = %+v, want the output interface index", attrs[0])
	}
	if got := nullTerminated(attrs[2].Value); got != "wg0" {
		t.Errorf("interface name = %q, want wg0", got)
	}
	// A length field that runs past the buffer stops the walk instead of
	// reading beyond it.
	truncated := append([]byte(nil), b...)
	binary.NativeEndian.PutUint16(truncated[0:2], uint16(len(truncated)+8)) // #nosec G115 -- a fixed test buffer
	if got := netlinkAttrs(truncated); len(got) != 0 {
		t.Errorf("a length past the end yielded %d attributes, want none", len(got))
	}
	if got := netlinkAttrs([]byte{1}); len(got) != 0 {
		t.Errorf("a stub buffer yielded %d attributes, want none", len(got))
	}
}

// The nested-attribute type bits are masked off, which is what lets the link
// kind be read out of IFLA_LINKINFO.
func TestNetlinkAttrsStripsTheNestedFlag(t *testing.T) {
	b := rtAttr(iflaLinkInfo|0x8000, rtAttr(iflaInfoKind, []byte("wireguard\x00")))
	attrs := netlinkAttrs(b)
	if len(attrs) != 1 || attrs[0].Type != iflaLinkInfo {
		t.Fatalf("attributes = %+v, want one IFLA_LINKINFO", attrs)
	}
	nested := netlinkAttrs(attrs[0].Value)
	if len(nested) != 1 || nullTerminated(nested[0].Value) != "wireguard" {
		t.Errorf("nested attributes = %+v, want the wireguard kind", nested)
	}
}

func TestNetlinkMessagesReportsTheKernelsError(t *testing.T) {
	errMsg := make([]byte, nlMsgHdrLen+4)
	binary.NativeEndian.PutUint32(errMsg[0:4], uint32(len(errMsg))) // #nosec G115 -- a fixed test buffer
	binary.NativeEndian.PutUint16(errMsg[4:6], unix.NLMSG_ERROR)
	code := -int32(unix.ENETUNREACH)
	binary.NativeEndian.PutUint32(errMsg[nlMsgHdrLen:], uint32(code)) // #nosec G115 -- a negated errno, the kernel's own encoding
	if _, err := netlinkMessages(errMsg); !errors.Is(err, unix.ENETUNREACH) {
		t.Errorf("netlinkMessages error = %v, want ENETUNREACH", err)
	}
	// An acknowledgement of zero is success, not an error.
	binary.NativeEndian.PutUint32(errMsg[nlMsgHdrLen:], 0)
	if msgs, err := netlinkMessages(errMsg); err != nil || len(msgs) != 0 {
		t.Errorf("netlinkMessages(ack) = %+v/%v, want no messages and no error", msgs, err)
	}
}

// The errors that mean "there is no route" are told apart from the ones that
// mean the lookup itself failed, which must never be recorded as no route.
func TestUnreachableNetlinkErrorNamesOnlyRoutingFailures(t *testing.T) {
	for _, err := range []error{unix.ENETUNREACH, unix.EHOSTUNREACH, unix.ENETDOWN} {
		if !unreachableNetlinkError(err) {
			t.Errorf("%v is not treated as an absent route", err)
		}
	}
	for _, err := range []error{unix.EACCES, unix.EPERM, unix.EINVAL, unix.ENOBUFS, nil} {
		if unreachableNetlinkError(err) {
			t.Errorf("%v was treated as an absent route", err)
		}
	}
}

// The real kernel, asked about the loopback address. It needs no privileges,
// no network, and no particular routing table: every Linux machine routes
// 127.0.0.1 to loopback, and a machine that does not is broken in a way this
// test is entitled to notice.
func TestLookupRouteDecisionAnswersForLoopback(t *testing.T) {
	got, ok := lookupRouteDecision(net.ParseIP("127.0.0.1"), nil)
	if !ok {
		t.Skip("the kernel did not answer a route lookup in this environment")
	}
	if got.Unreachable {
		t.Fatalf("loopback reported unreachable: %+v", got)
	}
	if got.Iface == "" {
		t.Errorf("decision = %+v, want a selected interface", got)
	}
	if got.Tunnel != TunnelDirect {
		t.Errorf("loopback tunnel state = %q, want %q", got.Tunnel, TunnelDirect)
	}
}

// The lookup has to ask about the flow netdoc's own probes make. Under --iface
// every dial leaves from a chosen local address, and a policy rule selecting
// on source address resolves differently for a packet that carries one, so the
// request carries it too. src_len has to be set beside the attribute or the
// kernel reads it as a zero-length prefix and ignores the constraint.
func TestRouteLookupRequestCarriesTheBoundSource(t *testing.T) {
	dst := netip.MustParseAddr("198.51.100.7")
	plain := routeLookupRequest(dst, netip.Addr{}, 0)
	if plain[2] != 0 {
		t.Errorf("src_len = %d on an unconstrained lookup, want 0", plain[2])
	}
	for _, attr := range netlinkAttrs(plain[rtMsgLen:]) {
		if attr.Type == unix.RTA_SRC {
			t.Error("an unconstrained lookup carried a source address")
		}
	}

	src := netip.MustParseAddr("192.168.1.20")
	bound := routeLookupRequest(dst, src, 0)
	if bound[2] != 32 {
		t.Errorf("src_len = %d, want 32 so the kernel reads the source as one address", bound[2])
	}
	var carried net.IP
	for _, attr := range netlinkAttrs(bound[rtMsgLen:]) {
		if attr.Type == unix.RTA_SRC {
			carried = netlinkIP(attr.Value)
		}
	}
	if carried == nil || carried.String() != "192.168.1.20" {
		t.Errorf("RTA_SRC = %v, want the bound source", carried)
	}

	v6 := netip.MustParseAddr("2001:db8::7")
	if got := routeLookupRequest(v6, netip.MustParseAddr("2001:db8::20"), 0); got[2] != 128 {
		t.Errorf("IPv6 src_len = %d, want 128", got[2])
	}
}

// A scoped link-local lookup is bound to its zone's interface, the way the
// connected socket is: RTA_OIF carries the index, and nothing else changes.
func TestRouteLookupRequestCarriesTheZoneInterface(t *testing.T) {
	dst := netip.MustParseAddr("fe80::1")
	for _, oif := range []uint32{0, 7} {
		var got []uint32
		for _, attr := range netlinkAttrs(routeLookupRequest(dst, netip.Addr{}, int(oif))[rtMsgLen:]) {
			if attr.Type == unix.RTA_OIF && len(attr.Value) == 4 {
				got = append(got, binary.NativeEndian.Uint32(attr.Value))
			}
		}
		if oif == 0 && len(got) != 0 || oif != 0 && (len(got) != 1 || got[0] != oif) {
			t.Errorf("oif %d: RTA_OIF = %v", oif, got)
		}
	}
}

// Against the real kernel, a scoped lookup answers for the zone's interface or
// not at all. Loopback is the one interface every host has; whatever this
// kernel says about fe80::1 through it, it may not name another link. Its
// index is 1 in every network namespace, which covers the numeric zone.
func TestScopedRouteLookupNamesOnlyItsZone(t *testing.T) {
	for _, zone := range []string{"lo", "1"} {
		got, ok := lookupScopedRouteDecision(net.ParseIP("fe80::1"), nil, zone)
		if ok && !got.Unreachable && got.Iface != "lo" {
			t.Errorf("zone %q: route via %q, want lo or no answer", zone, got.Iface)
		}
	}
	if got, ok := lookupScopedRouteDecision(net.ParseIP("fe80::1"), nil, "netdoc-no-such-if"); ok {
		t.Errorf("unknown zone answered %+v, want no route", got)
	}
}

// A source only constrains a lookup in its own family. One in the other family
// is not a constraint the kernel could apply, so it is dropped rather than
// sent as an attribute the reply would be wrong about.
func TestRouteQuerySourceKeepsOnlyAUsableConstraint(t *testing.T) {
	v4, v6 := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8::7")
	if got := routeQuerySource(v4, net.ParseIP("192.168.1.20")); got.String() != "192.168.1.20" {
		t.Errorf("IPv4 source = %v, want it kept", got)
	}
	// A v4-in-v6 encoded address is still an IPv4 source, which is how
	// net.ParseIP hands one back.
	if got := routeQuerySource(v4, net.ParseIP("::ffff:192.168.1.20")); got.String() != "192.168.1.20" {
		t.Errorf("mapped IPv4 source = %v, want it unmapped and kept", got)
	}
	for _, c := range []struct {
		name   string
		dst    netip.Addr
		source net.IP
	}{
		{"no binding at all", v4, nil},
		{"an IPv6 source for an IPv4 lookup", v4, net.ParseIP("2001:db8::20")},
		{"an IPv4 source for an IPv6 lookup", v6, net.ParseIP("192.168.1.20")},
		{"nonsense", v4, net.IP{1, 2, 3}},
	} {
		if got := routeQuerySource(c.dst, c.source); got.IsValid() {
			t.Errorf("%s produced the constraint %v, want none", c.name, got)
		}
	}
}

// The real kernel, asked the constrained question every source-bound run asks.
// Loopback needs no network, no privileges, and no particular table: every
// Linux machine routes 127.0.0.1 to lo from 127.0.0.1.
func TestLookupRouteDecisionAnswersAConstrainedLookup(t *testing.T) {
	loopback := net.ParseIP("127.0.0.1")
	got, ok := lookupRouteDecision(loopback, loopback)
	if !ok {
		t.Skip("the kernel did not answer a route lookup in this environment")
	}
	if got.Unreachable || got.Iface == "" {
		t.Fatalf("constrained loopback decision = %+v, want a selected interface", got)
	}
	// The kernel has no source selection left to report once the question
	// carried one, and the address the flow leaves from is still known.
	if got.Source == nil || !got.Source.Equal(loopback) {
		t.Errorf("source = %v, want the address the lookup was constrained to", got.Source)
	}
	// A source in the other address family is not a constraint this lookup
	// could carry, so it is dropped and the kernel answers the plain question.
	other, ok := lookupRouteDecision(loopback, net.ParseIP("2001:db8::20"))
	if !ok || other.Iface != got.Iface {
		t.Errorf("cross-family source = %+v/%v, want the unconstrained answer for %q", other, ok, got.Iface)
	}
	// A source the kernel will not route from is answered as no route, which
	// is this flow's truthful answer and not a path to invent one for: the
	// addresses a run binds to are its own, so a flow the kernel refuses is a
	// flow the probe would have failed to make.
	refused, ok := lookupRouteDecision(loopback, net.ParseIP("203.0.113.9"))
	if ok && refused.Iface != "" && refused.Iface != got.Iface {
		t.Errorf("a refused source produced the invented path %+v", refused)
	}
}

// The real kernel on the table distinction the shared model now carries. IPv6
// loopback is resolved in the local table on every Linux machine and an
// ordinary destination in main, so this proves both that a table is read and
// that a known main table is not the same value as a known other one.
func TestLookupRouteDecisionReadsTheRoutingTableTheKernelUsed(t *testing.T) {
	local, ok := lookupRouteDecision(net.ParseIP("::1"), nil)
	if !ok || local.Unreachable {
		t.Skip("the kernel did not answer an IPv6 loopback route lookup in this environment")
	}
	if !local.TableKnown {
		t.Fatal("a Linux route decision reported no table knowledge at all")
	}
	if local.Table != "local" {
		t.Errorf("table = %q, want the local table the kernel resolved ::1 in", local.Table)
	}
	main, ok := lookupRouteDecision(net.ParseIP("127.0.0.1"), nil)
	if !ok || main.Unreachable {
		t.Skip("the kernel did not answer an IPv4 loopback route lookup in this environment")
	}
	if !main.TableKnown || main.Table != "" {
		t.Errorf("table = %q (known %t), want a known main table", main.Table, main.TableKnown)
	}
	// Both are tables the kernel consults on its own, so the pair is the same
	// routing domain as far as any conclusion goes. A table a rule selected is
	// not, and this machine has no such rule to offer, so it is stated here.
	if comparePaths(main, local).Table != pathSame {
		t.Error("the kernel's own local and main tables compared as different routing domains")
	}
	policy := main
	policy.Table = "table 51820"
	if comparePaths(main, policy).Table != pathDiffers {
		t.Error("a known main table compared as the same domain as a policy table")
	}
}

func TestMainIPv6DefaultsExcludeOtherTables(t *testing.T) {
	main := rtMsg(unix.AF_INET6, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
		rtAttr(unix.RTA_OIF, u32(2)), rtAttr(unix.RTA_GATEWAY, net.ParseIP("2001:db8::1").To16()), rtAttr(unix.RTA_PRIORITY, u32(50)))
	foreign := rtMsg(unix.AF_INET6, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
		rtAttr(unix.RTA_TABLE, u32(100)), rtAttr(unix.RTA_OIF, u32(3)), rtAttr(unix.RTA_PRIORITY, u32(1)))
	specific := rtMsg(unix.AF_INET6, 64, unix.RT_TABLE_MAIN, unix.RTN_UNICAST, rtAttr(unix.RTA_OIF, u32(3)))
	name := func(index int) string {
		if index == 2 {
			return "eth0"
		}
		return "eth1"
	}
	routes := mainIPv6Defaults([]netlinkMessage{foreign, main, specific}, name)
	if len(routes) != 1 || routes[0].iface != "eth0" || routes[0].metric != 50 || !routes[0].gateway.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("main defaults = %+v", routes)
	}
	worst := rtMsg(unix.AF_INET6, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST, rtAttr(unix.RTA_OIF, u32(2)), rtAttr(unix.RTA_PRIORITY, u32(0xffffffff)))
	if routes := mainIPv6Defaults([]netlinkMessage{worst}, name); len(routes) != 1 || routes[0].metric != 0xffffffff {
		t.Fatalf("highest priority defaults = %+v", routes)
	}
	multipath := rtMsg(unix.AF_INET6, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST, rtAttr(unix.RTA_MULTIPATH, nil))
	if routes := mainIPv6Defaults([]netlinkMessage{main, multipath}, name); routes != nil {
		t.Fatalf("partial inventory = %+v", routes)
	}
}
