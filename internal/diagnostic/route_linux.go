//go:build linux

package diagnostic

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// Route intelligence on Linux asks the kernel the same question `ip route get`
// asks: an RTM_GETROUTE request carrying one destination, answered by the FIB
// lookup the kernel would perform for a real packet. That is deliberate. The
// alternative is reading every table and every policy rule and reimplementing
// the selection, which would be a second, worse copy of the kernel's answer,
// and which would be wrong the moment a rule netdoc did not model exists.
//
// The socket is netlink, not a subprocess. The routing table is not
// human-readable output to parse here: it is a machine interface the kernel
// serves without privileges, and it is namespace-aware, so a lookup made
// inside one of the simulator's network namespaces answers for that namespace.

// netlinkTimeout bounds one kernel exchange. A local socket answers in
// microseconds; this exists so a wedged one cannot spend a probe's budget.
const netlinkTimeout = 500 * time.Millisecond

// netlinkReplyMax bounds one reply. A route answer is a few hundred bytes and
// a link answer with all its statistics is a few thousand.
const netlinkReplyMax = 64 << 10

const (
	nlMsgHdrLen    = unix.SizeofNlMsghdr
	rtMsgLen       = unix.SizeofRtMsg
	ifInfoMsgLen   = unix.SizeofIfInfomsg
	rtAttrHdrLen   = unix.SizeofRtAttr
	iflaLinkInfo   = 0x12 // IFLA_LINKINFO
	iflaInfoKind   = 0x1  // IFLA_INFO_KIND, nested inside IFLA_LINKINFO
	iflaIfName     = 0x3  // IFLA_IFNAME
	iflaMTU        = 0x4  // IFLA_MTU
	rtmFLookupTbl  = 0x1000
	rtaNHID        = 30 // RTA_NH_ID, a nexthop object rather than an inline gateway
	netlinkAlignTo = 4
)

func nlAlign(n int) int { return (n + netlinkAlignTo - 1) &^ (netlinkAlignTo - 1) }

// routeFailureCause and the route decision below read different things for
// different questions, so they stay separate: one classifies a failed default
// path from the whole table, the other asks about one destination.

// lookupRouteDecision asks the kernel which route one destination takes, for
// the flow this run actually makes.
//
// source is the local address the pass binds its dials to, and it is part of
// the question rather than decoration: `ip rule from <address> lookup <table>`
// is policy routing's commonest shape, and the FIB lookup resolves it only
// when the lookup carries the source the packet would carry. Asking without
// one under --iface would describe a path the run never took.
//
// A kernel that refuses the constrained question is asked the plain one
// instead. The answer is then the machine's own decision rather than this
// flow's, which is exactly what every unbound run already records, and is
// better than reporting no route intelligence at all.
//
// "No route" is deliberately not one of the refusals. The kernel answering
// that nothing leads to the destination from this source is an answer, and it
// is the right one: the source is an address of this machine that the run's
// own sockets bind to, so a flow the kernel will not route is a flow the probe
// will not make either. Retrying unconstrained there would replace the truth
// about this run with a path it never used.
func lookupRouteDecision(dst, source net.IP) (RouteDecision, bool) {
	addr, ok := netip.AddrFromSlice(dst)
	if !ok {
		return RouteDecision{}, false
	}
	addr = addr.Unmap()
	src := routeQuerySource(addr, source)
	decision, ok := routeLookup(addr, src)
	if !ok && src.IsValid() {
		return routeLookup(addr, netip.Addr{})
	}
	return decision, ok
}

// routeQuerySource is the source address a lookup for dst may carry: the
// pass's own binding, when there is one and it is in dst's family. A source in
// the other family is not a constraint the kernel could apply to this lookup,
// so it is dropped rather than sent.
func routeQuerySource(dst netip.Addr, source net.IP) netip.Addr {
	src, ok := netip.AddrFromSlice(source)
	if !ok {
		return netip.Addr{}
	}
	if src = src.Unmap(); src.Is4() != dst.Is4() {
		return netip.Addr{}
	}
	return src
}

// routeLookupRequest builds the rtmsg body of one lookup: a destination, and
// the source the flow would carry when there is one.
//
// dst_len is the length of the address supplied, which is how a lookup asks
// about one host rather than about a prefix. src_len says the same about the
// source, and both have to be set or the kernel reads the attribute as a
// prefix of length zero and the constraint is silently lost.
func routeLookupRequest(dst, src netip.Addr) []byte {
	family, raw := uint8(unix.AF_INET), dst.AsSlice()
	if !dst.Is4() {
		family = unix.AF_INET6
	}
	body := make([]byte, rtMsgLen)
	body[0] = family
	body[1] = uint8(len(raw) * 8) // #nosec G115 -- an IP address is 4 or 16 bytes, so this is 32 or 128
	binary.NativeEndian.PutUint32(body[8:], rtmFLookupTbl)
	body = append(body, rtAttr(unix.RTA_DST, raw)...)
	if src.IsValid() {
		srcRaw := src.AsSlice()
		body[2] = uint8(len(srcRaw) * 8) // #nosec G115 -- an IP address is 4 or 16 bytes
		body = append(body, rtAttr(unix.RTA_SRC, srcRaw)...)
	}
	return body
}

// routeLookup performs one RTM_GETROUTE exchange, optionally constrained to a
// source address.
func routeLookup(dst, src netip.Addr) (RouteDecision, bool) {
	replies, err := netlinkExchange(unix.RTM_GETROUTE, routeLookupRequest(dst, src))
	if err != nil {
		if unreachableNetlinkError(err) {
			return RouteDecision{Unreachable: true}, true
		}
		return RouteDecision{}, false
	}
	decision, ok := parseRouteReply(replies, dst)
	// A lookup that supplied the source is answered without RTA_PREFSRC,
	// since the kernel has no selection left to report. The address the flow
	// leaves from is still known: it is the one the question carried.
	if ok && decision.Source == nil && !decision.Unreachable && src.IsValid() {
		decision.Source = net.IP(src.AsSlice())
	}
	return decision, ok
}

// parseRouteReply reads the kernel's answer into a decision. It takes the
// first RTM_NEWROUTE in the reply: a lookup for one destination is answered
// with one route, and a multipath route reports its chosen next hop there.
func parseRouteReply(replies []netlinkMessage, dst netip.Addr) (RouteDecision, bool) {
	for _, msg := range replies {
		if msg.Type != unix.RTM_NEWROUTE || len(msg.Data) < rtMsgLen {
			continue
		}
		out := RouteDecision{}
		// The three route types that answer "nothing leads there". RTN_THROW
		// is deliberately not among them: it tells the kernel to abandon this
		// table and carry on with the next rule, so a later table may well
		// route the destination, and reporting it as no route would be netdoc
		// answering a question the lookup had not finished asking. An
		// unresolved throw comes back as ENETUNREACH instead, which is caught
		// where the exchange fails.
		switch msg.Data[7] { // rtm_type
		case unix.RTN_UNREACHABLE, unix.RTN_BLACKHOLE, unix.RTN_PROHIBIT:
			out.Unreachable = true
			return out, true
		}
		// The matched prefix is deliberately not read here. A route lookup
		// reply carries rtm_dst_len, but the kernel echoes the length the
		// request asked about rather than the length of the entry it matched:
		// every answer to a host lookup comes back as /32 or /128, whatever
		// the table holds. Reconstructing a prefix from it would report every
		// destination as a host route, so Prefix stays unset on this platform
		// and routeReason answers from the path instead.
		// rtm_table is a byte and saturates at 253 for a table id that needs
		// RTA_TABLE to be expressed, so the attribute wins where both exist.
		table := uint32(msg.Data[4])
		for _, attr := range netlinkAttrs(msg.Data[rtMsgLen:]) {
			switch attr.Type {
			case unix.RTA_OIF:
				if len(attr.Value) >= 4 {
					out.Iface, out.MTU, out.TunnelKind = linkFacts(int(binary.NativeEndian.Uint32(attr.Value)))
				}
			case unix.RTA_GATEWAY:
				out.Gateway = netlinkIP(attr.Value)
			// A next hop in the other address family, which is how an IPv4
			// route reached through an IPv6 neighbour is expressed. It is a
			// next hop like any other, and reading only RTA_GATEWAY would
			// leave the decision looking gatewayless and be reported as
			// on-link when the kernel named a router.
			case unix.RTA_VIA:
				if out.Gateway == nil {
					out.Gateway = netlinkVia(attr.Value)
				}
			case unix.RTA_PREFSRC:
				out.Source = netlinkIP(attr.Value)
			case unix.RTA_PRIORITY:
				if len(attr.Value) >= 4 {
					out.Metric, out.MetricKnown = int(binary.NativeEndian.Uint32(attr.Value)), true
				}
			case unix.RTA_TABLE:
				if len(attr.Value) >= 4 {
					table = binary.NativeEndian.Uint32(attr.Value)
				}
			}
		}
		out.Table, out.TableKnown = routeTableName(table)
		out.Tunnel, out.TunnelKind = classifyTunnel(linkClassificationFacts(out.Iface, out.TunnelKind))
		return out, true
	}
	return RouteDecision{}, false
}

// routeTableName spells the routing table a decision came from, and says
// whether the kernel named one at all. The three the kernel reserves get their
// names; any other id is reported as its number, because a numbered table is
// exactly what policy routing installs and a diagnosis that hid the number
// would hide the whole point. The main table is spelled as empty, since a
// decision from it is the unremarkable case and saying so on every row would
// be noise.
//
// RT_TABLE_UNSPEC is the one id that is not an answer. It is the kernel
// leaving the field alone, and it comes back as unknown rather than as the
// main table: "this came from main" and "nobody said" are different facts, and
// only the first one distinguishes a flow that stayed in the ordinary routing
// domain from one that a rule sent elsewhere.
func routeTableName(id uint32) (string, bool) {
	switch id {
	case unix.RT_TABLE_UNSPEC:
		return "", false
	case unix.RT_TABLE_MAIN:
		return "", true
	case unix.RT_TABLE_LOCAL:
		return "local", true
	case unix.RT_TABLE_DEFAULT:
		return "default", true
	}
	return "table " + strconv.FormatUint(uint64(id), 10), true
}

// linkFacts reads one interface's name, MTU, and kernel-reported device kind
// by index. Everything it cannot read stays zero, which every caller reads as
// unknown rather than as a value.
func linkFacts(index int) (name string, mtu int, kind string) {
	if index <= 0 {
		return "", 0, ""
	}
	body := make([]byte, ifInfoMsgLen)
	body[0] = unix.AF_UNSPEC
	// #nosec G115 -- guarded above: a positive interface index is a uint32 in the kernel
	binary.NativeEndian.PutUint32(body[4:], uint32(index)) // ifi_index
	replies, err := netlinkExchange(unix.RTM_GETLINK, body)
	if err != nil {
		// The kernel knows this index; a failed query is a broken socket, not
		// a missing interface, so fall back to the portable interface list
		// rather than reporting an unnamed path.
		if ifi, err := net.InterfaceByIndex(index); err == nil {
			return ifi.Name, ifi.MTU, ""
		}
		return "", 0, ""
	}
	for _, msg := range replies {
		if msg.Type != unix.RTM_NEWLINK || len(msg.Data) < ifInfoMsgLen {
			continue
		}
		for _, attr := range netlinkAttrs(msg.Data[ifInfoMsgLen:]) {
			switch attr.Type {
			case iflaIfName:
				name = nullTerminated(attr.Value)
			case iflaMTU:
				if len(attr.Value) >= 4 {
					mtu = int(binary.NativeEndian.Uint32(attr.Value))
				}
			case iflaLinkInfo:
				// IFLA_INFO_KIND is the kernel's own name for the device type
				// ("wireguard", "tun", "gre", "bridge"). It is the structural
				// answer that keeps tunnel detection off interface names.
				for _, nested := range netlinkAttrs(attr.Value) {
					if nested.Type == iflaInfoKind {
						kind = nullTerminated(nested.Value)
					}
				}
			}
		}
		return name, mtu, kind
	}
	return "", 0, ""
}

// linkClassificationFacts assembles what classifyTunnel reads. The kernel kind
// comes from netlink above; the shape comes from the portable interface list,
// which is what answers for a device the kernel named no kind for.
func linkClassificationFacts(name, kind string) ifaceFacts {
	f := ifaceFacts{Name: name, Kind: kind}
	if name == "" {
		return f
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return f
	}
	f.PointToPoint = ifi.Flags&net.FlagPointToPoint != 0
	f.Loopback = ifi.Flags&net.FlagLoopback != 0
	f.NoLinkLayer = len(ifi.HardwareAddr) == 0
	return f
}

// defaultRoutesFor reads main-table defaults only. IPv4's /proc view has that
// scope; IPv6's spans tables without identifying them, so use netlink there.
// Policy-selected decisions cannot be compared against this inventory.
func defaultRoutesFor(family string) []defaultRouteState {
	if family == counterfactualIPv6 {
		body := make([]byte, rtMsgLen)
		body[0] = unix.AF_INET6
		replies, err := netlinkExchangeFlags(unix.RTM_GETROUTE, body, unix.NLM_F_DUMP)
		if err != nil {
			return nil
		}
		return mainIPv6Defaults(replies, func(index int) string {
			if iface, err := net.InterfaceByIndex(index); err == nil {
				return iface.Name
			}
			return ""
		})
	}
	raw, err := os.ReadFile(procIPv4Routes)
	if err != nil {
		return nil
	}
	return parseDefaultRoutes(raw)
}

func mainIPv6Defaults(replies []netlinkMessage, interfaceName func(int) string) []defaultRouteState {
	var out []defaultRouteState
	for _, msg := range replies {
		if msg.Type != unix.RTM_NEWROUTE || len(msg.Data) < rtMsgLen ||
			msg.Data[0] != unix.AF_INET6 || msg.Data[1] != 0 || msg.Data[2] != 0 || msg.Data[7] != unix.RTN_UNICAST {
			continue
		}
		table := uint32(msg.Data[4])
		var route defaultRouteState
		multipath := false
		for _, attr := range netlinkAttrs(msg.Data[rtMsgLen:]) {
			switch attr.Type {
			case unix.RTA_TABLE:
				if len(attr.Value) >= 4 {
					table = binary.NativeEndian.Uint32(attr.Value)
				}
			case unix.RTA_OIF:
				if len(attr.Value) >= 4 {
					route.iface = interfaceName(int(binary.NativeEndian.Uint32(attr.Value)))
				}
			case unix.RTA_GATEWAY:
				route.gateway = netlinkIP(attr.Value)
			case unix.RTA_PRIORITY:
				if len(attr.Value) >= 4 {
					route.metric = int(binary.NativeEndian.Uint32(attr.Value))
				}
			case unix.RTA_MULTIPATH, rtaNHID:
				multipath = true
			}
		}
		if table != unix.RT_TABLE_MAIN {
			continue
		}
		// An unrepresented competitor could win. Do not rank a partial set.
		if multipath || route.iface == "" {
			return nil
		}
		out = append(out, route)
	}
	return out
}

// netlinkMessage is one message out of a netlink reply, split from the stream
// here rather than borrowed from a helper so the same walker serves route
// messages, link messages, and the nested attributes inside them.
type netlinkMessage struct {
	Type uint16
	Data []byte
}

type netlinkAttr struct {
	Type  uint16
	Value []byte
}

// netlinkAttrs walks a run of rtattr structures. A length that does not fit
// what is left ends the walk rather than panicking: this parses bytes from the
// kernel, and a parser for kernel bytes still has to be a parser.
func netlinkAttrs(b []byte) []netlinkAttr {
	var out []netlinkAttr
	for len(b) >= rtAttrHdrLen {
		length := int(binary.NativeEndian.Uint16(b[0:2]))
		if length < rtAttrHdrLen || length > len(b) {
			return out
		}
		out = append(out, netlinkAttr{
			Type:  binary.NativeEndian.Uint16(b[2:4]) & 0x3fff, // strip NESTED/BYTEORDER
			Value: b[rtAttrHdrLen:length],
		})
		aligned := nlAlign(length)
		if aligned >= len(b) {
			return out
		}
		b = b[aligned:]
	}
	return out
}

// netlinkMessages splits a reply buffer into messages, and reports the kernel's
// own error when the reply is one.
func netlinkMessages(b []byte) ([]netlinkMessage, error) {
	var out []netlinkMessage
	for len(b) >= nlMsgHdrLen {
		length := int(binary.NativeEndian.Uint32(b[0:4]))
		msgType := binary.NativeEndian.Uint16(b[4:6])
		if length < nlMsgHdrLen || length > len(b) {
			return out, nil
		}
		data := b[nlMsgHdrLen:length]
		switch msgType {
		case unix.NLMSG_DONE:
			return out, nil
		case unix.NLMSG_ERROR:
			if len(data) < 4 {
				return out, errors.New("netlink error message is truncated")
			}
			// The kernel reports errno negated. Zero is the acknowledgement
			// that a request with no reply body succeeded.
			// #nosec G115 -- the kernel writes a negated errno here, so the
			// round trip through int32 is the documented encoding rather than
			// a narrowing conversion.
			code := int32(binary.NativeEndian.Uint32(data[0:4]))
			if code != 0 {
				return out, unix.Errno(-code) // #nosec G115 -- a negated errno is small and positive once flipped
			}
			return out, nil
		default:
			out = append(out, netlinkMessage{Type: msgType, Data: data})
		}
		aligned := nlAlign(length)
		if aligned >= len(b) {
			return out, nil
		}
		b = b[aligned:]
	}
	return out, nil
}

// netlinkExchange sends one request and reads one reply. The socket is opened
// and closed per exchange: the run's route cache means a pass makes a handful
// of these, and a short-lived socket cannot outlive the namespace it was
// opened in.
func netlinkExchange(msgType uint16, body []byte) ([]netlinkMessage, error) {
	return netlinkExchangeFlags(msgType, body, 0)
}

func netlinkExchangeFlags(msgType uint16, body []byte, flags uint16) ([]netlinkMessage, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	timeout := unix.NsecToTimeval(int64(netlinkTimeout))
	// A missing timeout option is not worth abandoning the query over; the
	// only cost is that a wedged kernel socket would block, which the option
	// exists to prevent and which does not happen on a working one.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)

	request := make([]byte, nlMsgHdrLen+len(body))
	// #nosec G115 -- the request is a header plus a body this file builds, tens of bytes
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], msgType)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|flags)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	copy(request[nlMsgHdrLen:], body)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, netlinkReplyMax)
	if flags&unix.NLM_F_DUMP != 0 {
		return readRouteDump(fd, buf)
	}
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, err
	}
	return netlinkMessages(buf[:n])
}

// A dump must finish within one exchange's time and byte budgets. Partial or
// interrupted inventories cannot establish which default is preferred.
func readRouteDump(fd int, buf []byte) ([]netlinkMessage, error) {
	deadline := time.Now().Add(netlinkTimeout)
	var raw []byte
	for time.Now().Before(deadline) {
		timeout := unix.NsecToTimeval(int64(time.Until(deadline)))
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
			return nil, err
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		if n == 0 || len(raw)+n >= netlinkReplyMax {
			return nil, errors.New("route dump exceeds reply budget")
		}
		chunk := buf[:n]
		for len(chunk) >= nlMsgHdrLen {
			length := int(binary.NativeEndian.Uint32(chunk[:4]))
			if length < nlMsgHdrLen || length > len(chunk) {
				return nil, errors.New("truncated route dump")
			}
			if binary.NativeEndian.Uint16(chunk[6:8])&unix.NLM_F_DUMP_INTR != 0 {
				return nil, errors.New("interrupted route dump")
			}
			if binary.NativeEndian.Uint16(chunk[4:6]) == unix.NLMSG_DONE {
				if length >= nlMsgHdrLen+4 && binary.NativeEndian.Uint32(chunk[nlMsgHdrLen:]) != 0 {
					return nil, errors.New("route dump failed")
				}
				return netlinkMessages(raw)
			}
			if _, err := netlinkMessages(chunk[:length]); err != nil {
				return nil, err
			}
			step := nlAlign(length)
			if step > len(chunk) {
				return nil, errors.New("truncated route dump alignment")
			}
			raw = append(raw, chunk[:step]...)
			chunk = chunk[step:]
		}
		if len(chunk) != 0 {
			return nil, errors.New("truncated route dump header")
		}
	}
	return nil, errors.New("route dump timed out")
}

// rtAttr encodes one attribute, padded to the netlink alignment.
func rtAttr(attrType uint16, value []byte) []byte {
	out := make([]byte, nlAlign(rtAttrHdrLen+len(value)))
	// #nosec G115 -- every attribute this file writes is an address or a word
	binary.NativeEndian.PutUint16(out[0:2], uint16(rtAttrHdrLen+len(value)))
	binary.NativeEndian.PutUint16(out[2:4], attrType)
	copy(out[rtAttrHdrLen:], value)
	return out
}

// unreachableNetlinkError separates the kernel saying "there is no route" from
// every other reason a query can fail. Only the first is evidence; the rest
// leave route intelligence silent rather than reporting an outage that is
// really a broken socket.
func unreachableNetlinkError(err error) bool {
	return errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) ||
		errors.Is(err, unix.ENETDOWN)
}

func netlinkIP(b []byte) net.IP {
	if len(b) != net.IPv4len && len(b) != net.IPv6len {
		return nil
	}
	ip := append(net.IP(nil), b...)
	if ip.IsUnspecified() {
		return nil
	}
	return ip
}

// netlinkVia reads an rtvia: a two-byte address family followed by an address
// in that family. Anything else, including a family whose address length does
// not match, is no next hop rather than a guess at one.
func netlinkVia(b []byte) net.IP {
	if len(b) < 2 {
		return nil
	}
	addr := b[2:]
	switch binary.NativeEndian.Uint16(b) {
	case unix.AF_INET:
		if len(addr) != net.IPv4len {
			return nil
		}
	case unix.AF_INET6:
		if len(addr) != net.IPv6len {
			return nil
		}
	default:
		return nil
	}
	return netlinkIP(addr)
}

func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
