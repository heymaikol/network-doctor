package routepath

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"
)

// multipointRefusal is the reason a gre or ipip device with remote any draws. Its
// remote is not one address, so it has no single far end.
const multipointRefusal = "remote any is a multipoint tunnel, which names no single remote"

// fallbackKinds are the device kinds the kernel creates as fallbacks in every network
// namespace once their modules load: gre0, gretap0, erspan0, and tunl0. A device of
// one of these kinds is inert only when its captures match the shape below exactly
// and nothing names it. Neither its kind nor its name decides it.
var fallbackKinds = map[string]bool{"gre": true, "gretap": true, "erspan": true, "ipip": true}

// fallbackShape is what the kernel gives an inactive fallback of one kind in
// ip -d -j link: its link type, the zero link address of its family, and its
// info_data, each attribute with its exact JSON value. Any other attribute refuses
// the device, so a key, a mark, or an endpoint that is set is never read as a zero.
type fallbackShape struct {
	linkType string
	address  string
	data     map[string]string
}

// fallbackShapes are the shapes the lab saw in fresh namespaces on iproute2 6.17 and
// kernel 7.2.10. erspan carries okey 0.0.0.0 with no ikey, iseq, or oseq. A user-made
// erspan that sets a key prints ikey, okey, iseq, and oseq, and one made with no key
// is refused by the kernel (RTNETLINK EINVAL). A user-made erspan also lacks
// netns-immutable, which the import requires, so the zero okey is seen only on the
// module's own fallback.
var fallbackShapes = map[string]fallbackShape{
	"gre": {linkType: "gre", address: "0.0.0.0", data: map[string]string{
		"local": `"any"`, "remote": `"any"`, "ttl": "0", "pmtudisc": "false"}},
	"gretap": {linkType: "ether", address: "00:00:00:00:00:00", data: map[string]string{
		"local": `"any"`, "remote": `"any"`, "ttl": "0", "pmtudisc": "false"}},
	"erspan": {linkType: "ether", address: "00:00:00:00:00:00", data: map[string]string{
		"local": `"any"`, "remote": `"any"`, "ttl": "0", "pmtudisc": "false",
		"okey": `"0.0.0.0"`, "erspan_index": "0", "erspan_ver": "1"}},
	"ipip": {linkType: "ipip", address: "0.0.0.0", data: map[string]string{
		"local": `"any"`, "remote": `"any"`, "proto": `"any"`, "ttl": "0", "pmtudisc": "false"}},
}

// routeTypesWithoutDevice are the route types that name no device. Every other route
// must name one, or the captures do not show where it sends traffic.
var routeTypesWithoutDevice = map[string]bool{"blackhole": true, "unreachable": true, "prohibit": true, "throw": true}

// ipAddr is one device of ip -j addr show, reduced to what the fallback check reads.
type ipAddr struct {
	Index   int
	Address string
	Up      bool
	Addrs   int // how many addresses the device lists
}

// parseIPAddr reads one ip -j addr show array. Each device must give its index,
// flags, link address, and address list, since the fallback check needs all four.
func parseIPAddr(data []byte) (map[string]ipAddr, error) {
	elems, err := readObjects(data, TunnelCommandAddr)
	if err != nil {
		return nil, err
	}
	out := make(map[string]ipAddr, len(elems))
	for _, raw := range elems {
		obj, err := object(raw)
		if err != nil {
			return nil, err
		}
		if err := checkKeyCase(obj, "ifindex", "ifname", "flags", "address", "addr_info"); err != nil {
			return nil, err
		}
		var e struct {
			Name     string             `json:"ifname"`
			Index    *int               `json:"ifindex"`
			Flags    []string           `json:"flags"`
			Address  *string            `json:"address"`
			AddrInfo *[]json.RawMessage `json:"addr_info"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, errors.New("has a device field of the wrong type")
		}
		if e.Name == "" || e.Index == nil || e.Flags == nil || e.Address == nil || e.AddrInfo == nil {
			return nil, errors.New("lists a device without its name, index, flags, link address, or address list")
		}
		if _, dup := out[e.Name]; dup {
			return nil, errors.New("lists an interface twice")
		}
		out[e.Name] = ipAddr{Index: *e.Index, Address: *e.Address, Up: slices.Contains(e.Flags, "UP"), Addrs: len(*e.AddrInfo)}
	}
	return out, nil
}

// ipRoute is one route of ip -4 or -6 -j route show table all, reduced to the
// devices it names.
type ipRoute struct {
	Type string
	Dev  string
	Nhid bool
	Hops []string // the device of each nexthop, "" where a hop names none
}

// parseRoutes reads one route capture of command. The route fields the import reads
// are checked for case and repetition, and the rest of each route is left alone.
func parseRoutes(data []byte, command string) ([]ipRoute, error) {
	elems, err := readObjects(data, command)
	if err != nil {
		return nil, err
	}
	out := make([]ipRoute, 0, len(elems))
	for _, raw := range elems {
		obj, err := object(raw)
		if err != nil {
			return nil, err
		}
		if err := checkKeyCase(obj, "type", "dev", "nhid", "nexthops"); err != nil {
			return nil, err
		}
		var e struct {
			Type     string `json:"type"`
			Dev      string `json:"dev"`
			Nexthops []struct {
				Dev string `json:"dev"`
			} `json:"nexthops"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, errors.New("has a route field of the wrong type")
		}
		var hops []map[string]json.RawMessage
		if raw, ok := obj["nexthops"]; ok {
			if err := json.Unmarshal(raw, &hops); err != nil {
				return nil, errors.New("has a route field of the wrong type")
			}
		}
		for _, h := range hops {
			if err := checkKeyCase(h, "dev"); err != nil {
				return nil, err
			}
		}
		r := ipRoute{Type: e.Type, Dev: e.Dev, Nhid: setValue(obj["nhid"])}
		for _, h := range e.Nexthops {
			r.Hops = append(r.Hops, h.Dev)
		}
		out = append(out, r)
	}
	return out, nil
}

// nodeEvidence is what one node's address and route captures show about its devices.
// reason, when set, is why none of the node's fallback devices can be called inert.
// refs names, for each device a route or nexthop reaches, the first one that does.
// window holds the captures the evidence came from, for the collection window.
type nodeEvidence struct {
	reason string
	addrs  map[string]ipAddr
	refs   map[string]string
	window []TunnelCapture
}

// proveFallbackEvidence reads one node's address and route captures against its link
// capture. A node whose captures are missing, repeated, unusable, or in disagreement
// has no inert fallback. Its devices are still read as before, and a fallback that
// would otherwise be inert is refused with the reason.
func (r *TunnelImport) proveFallbackEvidence(node string, set linkSet, addrCaps, route4Caps, route6Caps []TunnelCapture) nodeEvidence {
	ev := nodeEvidence{refs: map[string]string{}}
	addrCap, addrHead := r.oneCapture(node, TunnelCommandAddr, addrCaps)
	r4Cap, r4Head := r.oneCapture(node, TunnelCommandRoute4, route4Caps)
	r6Cap, r6Head := r.oneCapture(node, TunnelCommandRoute6, route6Caps)
	if addrHead != "" {
		ev.fail(addrHead + ", so its addresses are not shown")
	}
	if r4Head != "" {
		ev.fail(r4Head + ", so its IPv4 routes are not shown")
	}
	if r6Head != "" {
		ev.fail(r6Head + ", so its IPv6 routes are not shown")
	}
	// Each capture supplied alone is read even when another is missing, so a malformed
	// one is refused rather than passed over. The heads above name what is missing;
	// the parses below add what is wrong with what is there.
	var addrs map[string]ipAddr
	var routes4, routes6 []ipRoute
	var err error
	if addrHead == "" {
		addrs, err = parseIPAddr(addrCap.Data)
		if err != nil {
			r.refuse(addrCap.Source, addrCap.Node, "", err.Error())
			ev.fail(fmt.Sprintf("node %s has an unusable ip -j addr show capture, so its addresses are not shown", node))
		}
	}
	if r4Head == "" {
		routes4, err = parseRoutes(r4Cap.Data, TunnelCommandRoute4)
		if err != nil {
			r.refuse(r4Cap.Source, r4Cap.Node, "", err.Error())
			ev.fail(fmt.Sprintf("node %s has an unusable ip -4 -j route show table all capture, so its IPv4 routes are not shown", node))
		}
	}
	if r6Head == "" {
		routes6, err = parseRoutes(r6Cap.Data, TunnelCommandRoute6)
		if err != nil {
			r.refuse(r6Cap.Source, r6Cap.Node, "", err.Error())
			ev.fail(fmt.Sprintf("node %s has an unusable ip -6 -j route show table all capture, so its IPv6 routes are not shown", node))
		}
	}
	if ev.reason != "" {
		return ev
	}

	ev.addrs = addrs
	ev.fail(crossCheck(node, set.links, addrs))
	ev.addRoutes(node, TunnelCommandRoute4, routes4, set.links)
	ev.addRoutes(node, TunnelCommandRoute6, routes6, set.links)
	ev.window = []TunnelCapture{set.capture, addrCap, r4Cap, r6Cap}
	return ev
}

// oneCapture returns the one capture of list. When the node has none, or several, it
// returns the head of the reason the node's evidence fails: a node with several
// captures of one command refuses each of them, since none can be told apart.
func (r *TunnelImport) oneCapture(node, command string, list []TunnelCapture) (TunnelCapture, string) {
	switch len(list) {
	case 0:
		return TunnelCapture{}, fmt.Sprintf("node %s has no %s capture", node, command)
	case 1:
		return list[0], ""
	}
	for _, c := range list {
		r.refuse(c.Source, c.Node, "", fmt.Sprintf("node %s has %d %s captures; the import needs one", node, len(list), command))
	}
	return TunnelCapture{}, fmt.Sprintf("node %s has %d %s captures", node, len(list), command)
}

// crossCheck says why a node's address capture and link capture do not describe the
// same devices, or returns "" when they agree on each device's index, link address,
// and UP state. The two captures are taken at different moments, so a device created
// or changed between them shows up here rather than being read as inert.
func crossCheck(node string, links map[string]ipLink, addrs map[string]ipAddr) string {
	if !slices.Equal(slices.Sorted(maps.Keys(links)), slices.Sorted(maps.Keys(addrs))) {
		return fmt.Sprintf("node %s: ip -j addr show and ip -d -j link disagree about the interfaces they list, so its addresses are not shown", node)
	}
	for _, name := range slices.Sorted(maps.Keys(links)) {
		l, a := links[name], addrs[name]
		var detail string
		switch {
		case l.Index != a.Index:
			detail = "ifindex"
		case l.Address != a.Address:
			detail = "address"
		case slices.Contains(l.Flags, "UP") != a.Up:
			detail = "UP state"
		}
		if detail != "" {
			return fmt.Sprintf("node %s: ip -j addr show and ip -d -j link disagree about the %s of one interface, so its addresses are not shown", node, detail)
		}
	}
	return ""
}

// addRoutes reads one node's routes of one family. A route that names a nexthop
// object makes the node's evidence unusable, since the device it reaches is not shown.
// Every device a route or nexthop names is recorded, so the fallback check can refuse
// it by name, and a name the link capture does not list is a contradiction.
func (ev *nodeEvidence) addRoutes(node, command string, routes []ipRoute, links map[string]ipLink) {
	for i, r := range routes {
		at := fmt.Sprintf("route %d of %s", i+1, command)
		if r.Nhid {
			ev.fail(fmt.Sprintf("node %s: %s uses a nexthop object, so the devices it reaches are not shown", node, at))
		}
		if r.Dev == "" && len(r.Hops) == 0 && !routeTypesWithoutDevice[r.Type] {
			ev.fail(fmt.Sprintf("node %s: %s names no device", node, at))
		}
		if r.Dev != "" {
			ev.uses(node, at, r.Dev, links)
		}
		for _, hop := range r.Hops {
			ev.uses(node, "a nexthop of "+at, hop, links)
		}
	}
}

// uses records that by, a route or nexthop, reaches dev. A device it names that the
// link capture does not list, or a nexthop that names none, is a contradiction.
func (ev *nodeEvidence) uses(node, by, dev string, links map[string]ipLink) {
	switch _, listed := links[dev]; {
	case dev == "":
		ev.fail(fmt.Sprintf("node %s: %s names no device", node, by))
	case !listed:
		ev.fail(fmt.Sprintf("node %s: %s names a device the link capture does not list", node, by))
	default:
		if _, seen := ev.refs[dev]; !seen {
			ev.refs[dev] = by
		}
	}
}

// fail keeps the first reason the node's evidence fails, and ignores an empty one.
func (ev *nodeEvidence) fail(reason string) {
	if reason != "" && ev.reason == "" {
		ev.reason = reason
	}
}

// maxFallbackSpread bounds how far apart the captures a fallback's inertness is read
// from may be collected: the node's link, address, route, and rules captures. The lab
// measured each node's five commands within 37 ms on a quiet host, and within 24 ms
// beside a race run, so 250 ms leaves room for a loaded host. A configuration change
// can land between the first and last capture. The bound narrows that window to this
// span; it does not exclude a change inside it.
const maxFallbackSpread = 250 * time.Millisecond

// checkWindow refuses the node's fallback evidence when its captures were collected
// more than maxFallbackSpread apart. It runs after the rules capture joins the window,
// so every capture the evidence rests on is inside the span. A capture with no time
// never reaches the window, since ImportTunnels refuses it first.
func (ev *nodeEvidence) checkWindow(node string) {
	if ev.reason != "" || len(ev.window) == 0 {
		return
	}
	first, last := ev.window[0].CollectedAt, ev.window[0].CollectedAt
	for _, c := range ev.window[1:] {
		if c.CollectedAt.Before(first) {
			first = c.CollectedAt
		}
		if c.CollectedAt.After(last) {
			last = c.CollectedAt
		}
	}
	if last.Sub(first) > maxFallbackSpread {
		ev.fail(fmt.Sprintf("node %s: its captures were collected more than %s apart, so a change between them is not ruled out", node, maxFallbackSpread))
	}
}

// fallbackReason says why a fallback-shaped device is not inert, or returns "" when it
// is. Rules and node evidence come first: a node whose captures cannot be trusted has
// no inert device, and a rule that selects by device could steer one. Then the device
// is read attribute by attribute in a fixed order, and a route that names it or an
// address on it refuses it whatever its shape. The name is never read.
func (ev nodeEvidence) fallbackReason(l ipLink, name string, rules ruleState) string {
	switch {
	case rules.reason != "":
		return rules.reason
	case ev.reason != "":
		return ev.reason
	}
	shape := fallbackShapes[l.kind()]
	_, hasData := l.Info.keys["info_data"]
	switch {
	case slices.Contains(l.Flags, "UP"):
		return "it is administratively up"
	case l.OperState != "DOWN":
		return "it has flags and operstate that contradict each other"
	case !isTrue(l.raw["netns-immutable"]):
		return "it is not marked netns-immutable"
	case setValue(l.raw["master"]):
		return "it is enslaved to a master device"
	case setValue(l.raw["link"]), setValue(l.raw["link_netnsid"]):
		return "it has a link to another device or namespace"
	case len(l.Info.keys) != 2 || !hasData:
		return "it has a linkinfo attribute the import does not read"
	case l.LinkType != shape.linkType:
		return "it has a link type its kind does not have"
	case l.Address != shape.address:
		return "it has a link address other than the zero address of its kind"
	}
	if why := shape.attributesWrong(l.Info.Data); why != "" {
		return why
	}
	// crossCheck makes the two captures list the same devices, so ImportTunnels never
	// reaches this case. The guard stays so a missing address refuses the device,
	// rather than reading as the zero ipAddr, which shows no addresses.
	a, listed := ev.addrs[name]
	switch {
	case !listed:
		return "it is not listed by ip -j addr show"
	case a.Addrs != 0:
		return "it has an address"
	}
	if by, named := ev.refs[name]; named {
		return "it is named by " + by
	}
	return ""
}

// attributesWrong says which info_data attribute of a device differs from its shape,
// or returns "" when the attributes are exactly the shape's. Missing attributes are
// reported first, then extra ones, then wrong values, each in name order. An extra
// attribute is named only when the import watches it, so no unknown name is echoed.
func (s fallbackShape) attributesWrong(data map[string]json.RawMessage) string {
	for _, k := range slices.Sorted(maps.Keys(s.data)) {
		if _, ok := data[k]; !ok {
			return fmt.Sprintf("it lacks the info_data attribute %s, which a fallback carries", k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(data)) {
		if _, ok := s.data[k]; ok {
			continue
		}
		if slices.Contains(watchedInfoKeys, k) {
			return fmt.Sprintf("it has an info_data attribute %s, which a fallback does not carry", k)
		}
		return "it has an info_data attribute a fallback does not carry"
	}
	for _, k := range slices.Sorted(maps.Keys(s.data)) {
		if string(bytes.TrimSpace(data[k])) != s.data[k] {
			return fmt.Sprintf("it has an info_data attribute %s with a value a fallback does not carry", k)
		}
	}
	return ""
}

// fallbackRefusal is the reason a fallback-shaped device draws when it is not inert.
// It keeps the reason its kind has always drawn, then says why it is not inert. The
// cause may be node-wide; the kind's reason still leads, so the text a multipoint
// device has always drawn stays a prefix of it.
func fallbackRefusal(kind, why string) string {
	base := multipointRefusal
	if kind == "gretap" || kind == "erspan" {
		base = fmt.Sprintf("has kind %q, which the import does not read", kind)
	}
	return base + "; it is not an inert fallback: " + why
}

// isMultipoint reports whether a device's remote is any, the multipoint form.
func isMultipoint(l ipLink) bool {
	return isAny(l.Info.Data["remote"])
}

// inert records a fallback device the evidence shows to be inactive, with the captures
// that showed it and the span of their collection times.
func (ev nodeEvidence) inert(node, name, kind string) InertDevice {
	d := InertDevice{Node: node, Interface: name, Kind: kind}
	for i, c := range ev.window {
		d.Sources = append(d.Sources, c.Source)
		if i == 0 || c.CollectedAt.Before(d.From) {
			d.From = c.CollectedAt
		}
		if i == 0 || c.CollectedAt.After(d.Until) {
			d.Until = c.CollectedAt
		}
	}
	return d
}

// perNode groups captures by node, keeping their order.
func perNode(list []TunnelCapture) map[string][]TunnelCapture {
	out := map[string][]TunnelCapture{}
	for _, c := range list {
		out[c.Node] = append(out[c.Node], c)
	}
	return out
}

// setValue reports whether a raw JSON value is present and not null.
func setValue(raw json.RawMessage) bool {
	return len(raw) > 0 && string(bytes.TrimSpace(raw)) != "null"
}

// isTrue reports whether a raw JSON value is the literal true.
func isTrue(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "true"
}

// isAny reports whether a raw JSON value is the string "any".
func isAny(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == `"any"`
}
