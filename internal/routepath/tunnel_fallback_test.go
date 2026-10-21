package routepath

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The captures of a fresh network namespace, as iproute2 prints them. lo and the
// four kernel fallbacks are listed by the link, address, and route commands the
// import reads. Each row edits one of these, and every other device stays inert.
const (
	fbLo      = `{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"operstate":"UNKNOWN","link_type":"loopback","address":"00:00:00:00:00:00","netns-immutable":true}`
	fbGRE0    = `{"ifindex":2,"ifname":"gre0","flags":["NOARP"],"operstate":"DOWN","link":null,"link_type":"gre","address":"0.0.0.0","netns-immutable":true,"linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"any","ttl":0,"pmtudisc":false}}}`
	fbGRETAP0 = `{"ifindex":3,"ifname":"gretap0","flags":["BROADCAST","MULTICAST"],"operstate":"DOWN","link":null,"link_type":"ether","address":"00:00:00:00:00:00","netns-immutable":true,"linkinfo":{"info_kind":"gretap","info_data":{"local":"any","remote":"any","ttl":0,"pmtudisc":false}}}`
	fbERSPAN0 = `{"ifindex":4,"ifname":"erspan0","flags":["BROADCAST","MULTICAST"],"operstate":"DOWN","link":null,"link_type":"ether","address":"00:00:00:00:00:00","netns-immutable":true,"linkinfo":{"info_kind":"erspan","info_data":{"local":"any","remote":"any","ttl":0,"pmtudisc":false,"okey":"0.0.0.0","erspan_index":0,"erspan_ver":1}}}`
	fbTUNL0   = `{"ifindex":5,"ifname":"tunl0","flags":["NOARP"],"operstate":"DOWN","link":null,"link_type":"ipip","address":"0.0.0.0","netns-immutable":true,"linkinfo":{"info_kind":"ipip","info_data":{"local":"any","remote":"any","proto":"any","ttl":0,"pmtudisc":false}}}`

	fbAddrLo      = `{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"operstate":"UNKNOWN","link_type":"loopback","address":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]}`
	fbAddrGRE0    = `{"ifindex":2,"ifname":"gre0","flags":["NOARP"],"operstate":"DOWN","link_type":"gre","address":"0.0.0.0","addr_info":[]}`
	fbAddrGRETAP0 = `{"ifindex":3,"ifname":"gretap0","flags":["BROADCAST","MULTICAST"],"operstate":"DOWN","link_type":"ether","address":"00:00:00:00:00:00","addr_info":[]}`
	fbAddrERSPAN0 = `{"ifindex":4,"ifname":"erspan0","flags":["BROADCAST","MULTICAST"],"operstate":"DOWN","link_type":"ether","address":"00:00:00:00:00:00","addr_info":[]}`
	fbAddrTUNL0   = `{"ifindex":5,"ifname":"tunl0","flags":["NOARP"],"operstate":"DOWN","link_type":"ipip","address":"0.0.0.0","addr_info":[]}`

	fbRouteV4 = `[{"type":"local","dst":"127.0.0.0/8","dev":"lo","table":"local","protocol":"kernel","scope":"host","prefsrc":"127.0.0.1","flags":[]}]`
	fbRouteV6 = `[{"type":"local","dst":"::1","dev":"lo","table":"local","protocol":"kernel","metric":0,"flags":[],"pref":"medium"}]`

	// The devices a test adds to a base set for the underlay rows: a plain eth0 and
	// the real gre1 that rides it.
	fbETH0     = `{"ifindex":7,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP","link_type":"ether","address":"02:00:00:00:00:01"}`
	fbAddrETH0 = `{"ifindex":7,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP","link_type":"ether","address":"02:00:00:00:00:01","addr_info":[{"family":"inet","local":"10.0.12.1","prefixlen":30}]}`
	fbGRE1     = `{"ifindex":6,"ifname":"gre1","flags":["NOARP"],"operstate":"DOWN","link":"eth0","link_type":"gre","address":"10.0.12.1","linkinfo":{"info_kind":"gre","info_data":{"local":"10.0.12.1","remote":"10.0.12.2","ttl":0,"pmtudisc":true}}}`
	fbAddrGRE1 = `{"ifindex":6,"ifname":"gre1","flags":["NOARP"],"operstate":"DOWN","link":"eth0","link_type":"gre","address":"10.0.12.1","addr_info":[]}`
)

const (
	cmdAddr   = "ip -j addr show"
	cmdRoute4 = "ip -4 -j route show table all"
	cmdRoute6 = "ip -6 -j route show table all"

	// The reasons a fallback draws when it is not inert. A device-level cause is
	// appended to the reason the import has always given for its kind.
	multipoint = "remote any is a multipoint tunnel, which names no single remote"
	gretapKind = `has kind "gretap", which the import does not read`
	erspanKind = `has kind "erspan", which the import does not read`
	notInert   = "; it is not an inert fallback: "
)

// fbKindReason is the reason each fallback kind has always drawn, before a cause is
// appended to it.
var fbKindReason = map[string]string{"gre0": multipoint, "gretap0": gretapKind, "erspan0": erspanKind, "tunl0": multipoint}

// fbCaps is one node's captures for the fallback rows. links and addrs name the same
// devices in the same order. omit is the command whose capture is left out, and dup
// the one listed twice.
type fbCaps struct {
	links, addrs []string
	v4, v6       string
	rules        string
	omit, dup    string
}

func fbBase() fbCaps {
	return fbCaps{
		links: []string{fbLo, fbGRE0, fbGRETAP0, fbERSPAN0, fbTUNL0},
		addrs: []string{fbAddrLo, fbAddrGRE0, fbAddrGRETAP0, fbAddrERSPAN0, fbAddrTUNL0},
		v4:    fbRouteV4,
		v6:    fbRouteV6,
		rules: defaultRules,
	}
}

func (c fbCaps) captures() []TunnelCapture {
	all := []TunnelCapture{
		{Source: "ip-link-r1", Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: []byte("[" + strings.Join(c.links, ",") + "]")},
		{Source: "ip-addr-r1", Node: "r1", Command: cmdAddr, CollectedAt: t0.Add(10 * time.Millisecond), Data: []byte("[" + strings.Join(c.addrs, ",") + "]")},
		{Source: "ip-route4-r1", Node: "r1", Command: cmdRoute4, CollectedAt: t0.Add(20 * time.Millisecond), Data: []byte(c.v4)},
		{Source: "ip-route6-r1", Node: "r1", Command: cmdRoute6, CollectedAt: t0.Add(30 * time.Millisecond), Data: []byte(c.v6)},
		{Source: "ip-rule-r1", Node: "r1", Command: TunnelCommandRules, CollectedAt: t0.Add(40 * time.Millisecond), Data: []byte(c.rules)},
	}
	var out []TunnelCapture
	for _, tc := range all {
		if tc.Command == c.omit {
			continue
		}
		out = append(out, tc)
		if tc.Command == c.dup {
			again := tc
			again.Source += "-again"
			out = append(out, again)
		}
	}
	return out
}

// subOnce replaces the one occurrence of old in s. A fixture that does not hold old
// exactly once is a bad row, so it panics rather than testing the wrong thing.
func subOnce(s, old, new string) string {
	if strings.Count(s, old) != 1 {
		panic("fixture text is not unique: " + old)
	}
	return strings.Replace(s, old, new, 1)
}

// fallbackNames are the four kernel fallbacks, in the order the rows refer to them.
var fallbackNames = []string{"gre0", "gretap0", "erspan0", "tunl0"}

// fallbackRefusals returns the refusal reason of each fallback device the import
// refused on r1, keyed by device name.
func fallbackRefusals(imp TunnelImport) map[string]string {
	got := map[string]string{}
	for _, r := range imp.Refused {
		if slices.Contains(fallbackNames, r.Interface) {
			got[r.Interface] = r.Reason
		}
	}
	return got
}

// TestInertFallbacksAreExempt checks that the four kernel fallbacks, as a fresh
// namespace prints them with their addresses and routes, draw no refusal and make
// no tunnel record.
func TestInertFallbacksAreExempt(t *testing.T) {
	imp, err := ImportTunnels(importModel(t), fbBase().captures())
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Refused) != 0 {
		t.Errorf("inert fallbacks were refused: %+v", imp.Refused)
	}
	if len(imp.Tunnels) != 0 || len(imp.Unproven) != 0 {
		t.Errorf("inert fallbacks made a record: tunnels %+v, unproven %+v", imp.Tunnels, imp.Unproven)
	}
	if len(imp.Inert) != 4 {
		t.Errorf("want all four fallbacks listed inert, got %+v", imp.Inert)
	}

	// A blackhole route names no device and steers nothing into a fallback.
	c := fbBase()
	c.v4 = `[{"type":"blackhole","dst":"198.51.100.0/24","table":"main","protocol":"static","flags":[]},` + fbRouteV4[1:]
	imp, err = ImportTunnels(importModel(t), c.captures())
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Refused) != 0 || len(imp.Inert) != 4 {
		t.Errorf("a blackhole route kept the fallbacks from being inert: refused %+v, inert %+v", imp.Refused, imp.Inert)
	}
}

// TestInertFallbackRefusals gives each false exemption its own row. Every row
// changes one thing, so the one device it names is the only fallback refused, and
// the reason names that one thing. A node-level row changes evidence that every
// fallback on r1 depends on, so all four are refused with the same reason.
func TestInertFallbackRefusals(t *testing.T) {
	rows := []struct {
		name string
		edit func(c *fbCaps)
		dev  string // the one fallback refused, or "" when all four are refused
		want string
	}{
		{"administratively up device", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"flags":["NOARP"],"operstate":"DOWN"`, `"flags":["NOARP","UP","LOWER_UP"],"operstate":"UNKNOWN"`)
			c.addrs[1] = subOnce(fbAddrGRE0, `"flags":["NOARP"],"operstate":"DOWN"`, `"flags":["NOARP","UP","LOWER_UP"],"operstate":"UNKNOWN"`)
		}, "gre0", multipoint + notInert + "it is administratively up"},

		{"address listed on a DOWN device", func(c *fbCaps) {
			c.addrs[1] = subOnce(fbAddrGRE0, `"addr_info":[]`, `"addr_info":[{"family":"inet","local":"10.9.0.1","prefixlen":32,"scope":"global"}]`)
		}, "gre0", multipoint + notInert + "it has an address"},

		{"link address other than zero", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"address":"0.0.0.0"`, `"address":"10.9.0.1"`)
			c.addrs[1] = subOnce(fbAddrGRE0, `"address":"0.0.0.0"`, `"address":"10.9.0.1"`)
		}, "gre0", multipoint + notInert + "it has a link address other than the zero address of its kind"},

		{"IPv4 route names the device", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.9.0.0/16","dev":"gre0","table":"main","protocol":"static","scope":"link","flags":[]},` + fbRouteV4[1:]
		}, "gre0", multipoint + notInert + "it is named by route 1 of ip -4 -j route show table all"},

		{"IPv6 route names the device", func(c *fbCaps) {
			c.v6 = `[{"type":"unicast","dst":"2001:db8:9::/48","dev":"gre0","table":"main","protocol":"static","metric":1024,"flags":[],"pref":"medium"},` + fbRouteV6[1:]
		}, "gre0", multipoint + notInert + "it is named by route 1 of ip -6 -j route show table all"},

		{"multipath nexthop names the device", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.8.0.0/16","table":"main","protocol":"static","scope":"global","flags":[],"nexthops":[{"dev":"gre0","weight":1,"flags":[]},{"dev":"lo","weight":1,"flags":[]}]},` + fbRouteV4[1:]
		}, "gre0", multipoint + notInert + "it is named by a nexthop of route 1 of ip -4 -j route show table all"},

		{"route uses a nexthop object", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.8.0.0/16","nhid":12,"table":"main","protocol":"static","flags":[]},` + fbRouteV4[1:]
		}, "", "node r1: route 1 of ip -4 -j route show table all uses a nexthop object, so the devices it reaches are not shown"},

		{"route names no device", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.8.0.0/16","table":"main","protocol":"static","flags":[]},` + fbRouteV4[1:]
		}, "", "node r1: route 1 of ip -4 -j route show table all names no device"},

		{"nexthop names no device", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.8.0.0/16","table":"main","protocol":"static","flags":[],"nexthops":[{"gateway":"10.0.0.1","weight":1}]},` + fbRouteV4[1:]
		}, "", "node r1: a nexthop of route 1 of ip -4 -j route show table all names no device"},

		{"route names a device the link capture does not list", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.8.0.0/16","dev":"wg9","table":"main","protocol":"static","flags":[]},` + fbRouteV4[1:]
		}, "", "node r1: route 1 of ip -4 -j route show table all names a device the link capture does not list"},

		{"no IPv4 route capture", func(c *fbCaps) { c.omit = cmdRoute4 },
			"", "node r1 has no ip -4 -j route show table all capture, so its IPv4 routes are not shown"},

		{"no IPv6 route capture", func(c *fbCaps) { c.omit = cmdRoute6 },
			"", "node r1 has no ip -6 -j route show table all capture, so its IPv6 routes are not shown"},

		{"no address capture", func(c *fbCaps) { c.omit = cmdAddr },
			"", "node r1 has no ip -j addr show capture, so its addresses are not shown"},

		{"nexthop dev key in another case", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.8.0.0/16","table":"main","protocol":"static","flags":[],"nexthops":[{"dev":"gre0","DEV":"lo"}]},` + fbRouteV4[1:]
		}, "", "node r1 has an unusable ip -4 -j route show table all capture, so its IPv4 routes are not shown"},

		{"route dev key in another case", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.8.0.0/16","DEV":"gre0","table":"main","protocol":"static","flags":[]},` + fbRouteV4[1:]
		}, "", "node r1 has an unusable ip -4 -j route show table all capture, so its IPv4 routes are not shown"},

		{"route key repeated", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.8.0.0/16","table":"main","table":"local","protocol":"static","flags":[]},` + fbRouteV4[1:]
		}, "", "node r1 has an unusable ip -4 -j route show table all capture, so its IPv4 routes are not shown"},

		{"address key repeated", func(c *fbCaps) {
			c.addrs[1] = subOnce(fbAddrGRE0, `"ifindex":2`, `"ifindex":2,"ifindex":2`)
		}, "", "node r1 has an unusable ip -j addr show capture, so its addresses are not shown"},

		{"two address captures", func(c *fbCaps) { c.dup = cmdAddr },
			"", "node r1 has 2 ip -j addr show captures, so its addresses are not shown"},

		{"address capture disagrees on ifindex", func(c *fbCaps) {
			c.addrs[1] = subOnce(fbAddrGRE0, `"ifindex":2`, `"ifindex":9`)
		}, "", "node r1: ip -j addr show and ip -d -j link disagree about the ifindex of one interface, so its addresses are not shown"},

		{"address capture disagrees on UP state", func(c *fbCaps) {
			c.addrs[1] = subOnce(fbAddrGRE0, `"flags":["NOARP"],"operstate":"DOWN"`, `"flags":["NOARP","UP","LOWER_UP"],"operstate":"UNKNOWN"`)
		}, "", "node r1: ip -j addr show and ip -d -j link disagree about the UP state of one interface, so its addresses are not shown"},

		{"address capture lists fewer interfaces", func(c *fbCaps) {
			c.addrs = slices.Delete(slices.Clone(c.addrs), 1, 2)
		}, "", "node r1: ip -j addr show and ip -d -j link disagree about the interfaces they list, so its addresses are not shown"},

		{"policy rules missing", func(c *fbCaps) { c.omit = TunnelCommandRules },
			"", "node r1 has no ip -j rule show capture, so its policy rules are not shown"},

		{"extra info_data key ikey", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"pmtudisc":false}`, `"pmtudisc":false,"ikey":"0.0.0.7"}`)
		}, "gre0", multipoint + notInert + "it has an info_data attribute ikey, which a fallback does not carry"},

		{"fwmark set on a fallback", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"pmtudisc":false}`, `"pmtudisc":false,"fwmark":"0x5"}`)
		}, "gre0", multipoint + notInert + "it has an info_data attribute fwmark, which a fallback does not carry"},

		{"zero okey on a gre device", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"pmtudisc":false}`, `"pmtudisc":false,"okey":"0.0.0.0"}`)
		}, "gre0", multipoint + notInert + "it has an info_data attribute okey, which a fallback does not carry"},

		{"erspan with iseq set", func(c *fbCaps) {
			c.links[3] = subOnce(fbERSPAN0, `"erspan_ver":1}`, `"erspan_ver":1,"iseq":true}`)
		}, "erspan0", erspanKind + notInert + "it has an info_data attribute iseq, which a fallback does not carry"},

		{"ttl changed on a fallback", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"ttl":0`, `"ttl":64`)
		}, "gre0", multipoint + notInert + "it has an info_data attribute ttl with a value a fallback does not carry"},

		{"non-wildcard local endpoint", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"local":"any"`, `"local":"10.0.0.1"`)
		}, "gre0", multipoint + notInert + "it has an info_data attribute local with a value a fallback does not carry"},

		{"fallback attribute missing", func(c *fbCaps) {
			c.links[4] = subOnce(fbTUNL0, `,"pmtudisc":false}`, `}`)
		}, "tunl0", multipoint + notInert + "it lacks the info_data attribute pmtudisc, which a fallback carries"},

		{"user-created device named gre0", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"netns-immutable":true,`, ``)
		}, "gre0", multipoint + notInert + "it is not marked netns-immutable"},

		{"netns-immutable false", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"netns-immutable":true`, `"netns-immutable":false`)
		}, "gre0", multipoint + notInert + "it is not marked netns-immutable"},

		{"enslaved to a master", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"link":null,`, `"link":null,"master":"vrf9",`)
		}, "gre0", multipoint + notInert + "it is enslaved to a master device"},

		{"underlay link set", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"link":null`, `"link":"eth0"`)
		}, "gre0", multipoint + notInert + "it has a link to another device or namespace"},

		{"link_netnsid set", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"link":null,`, `"link":null,"link_netnsid":0,`)
		}, "gre0", multipoint + notInert + "it has a link to another device or namespace"},

		{"operstate contradicts flags", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"operstate":"DOWN"`, `"operstate":"UNKNOWN"`)
			c.addrs[1] = subOnce(fbAddrGRE0, `"operstate":"DOWN"`, `"operstate":"UNKNOWN"`)
		}, "gre0", multipoint + notInert + "it has flags and operstate that contradict each other"},

		{"link type of another kind", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"link_type":"gre"`, `"link_type":"ipip"`)
		}, "gre0", multipoint + notInert + "it has a link type its kind does not have"},

		{"linkinfo attribute the import does not read", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"info_kind":"gre",`, `"info_kind":"gre","info_slave_kind":"vrf",`)
		}, "gre0", multipoint + notInert + "it has a linkinfo attribute the import does not read"},

		{"kind the import does not read", func(c *fbCaps) {
			c.links[1] = subOnce(fbGRE0, `"info_kind":"gre"`, `"info_kind":"sit"`)
		}, "gre0", `has kind "sit", which the import does not read`},

		// A key spelled in capitals in a capture the fallbacks depend on refuses the
		// node, so every fallback of it is refused, whatever the other captures show.
		{"address key spelled in capitals", func(c *fbCaps) {
			c.addrs[1] = subOnce(fbAddrGRE0, `"ifindex":2`, `"IFINDEX":2`)
		}, "", "node r1 has an unusable ip -j addr show capture, so its addresses are not shown"},

		{"route key spelled in capitals", func(c *fbCaps) {
			c.v4 = subOnce(fbRouteV4, `"dev":"lo"`, `"DEV":"lo"`)
		}, "", "node r1 has an unusable ip -4 -j route show table all capture, so its IPv4 routes are not shown"},

		{"nexthop key spelled in capitals", func(c *fbCaps) {
			c.v4 = `[{"type":"unicast","dst":"10.8.0.0/16","table":"main","protocol":"static","scope":"global","flags":[],"nexthops":[{"DEV":"gre0","weight":1,"flags":[]},{"dev":"lo","weight":1,"flags":[]}]},` + fbRouteV4[1:]
		}, "", "node r1 has an unusable ip -4 -j route show table all capture, so its IPv4 routes are not shown"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			c := fbBase()
			row.edit(&c)
			imp, err := ImportTunnels(importModel(t), c.captures())
			if err != nil {
				t.Fatal(err)
			}
			got := fallbackRefusals(imp)
			if row.dev == "" {
				for _, dev := range fallbackNames {
					if want := fbKindReason[dev] + notInert + row.want; got[dev] != want {
						t.Errorf("%s: reason %q, want %q", dev, got[dev], want)
					}
				}
				return
			}
			if len(got) != 1 || got[row.dev] != row.want {
				t.Errorf("fallbacks refused %v, want only %s with reason %q", got, row.dev, row.want)
			}
			if len(imp.Tunnels) != 0 {
				t.Errorf("a refused fallback made a record: %+v", imp.Tunnels)
			}
		})
	}
}

// TestPolicyRuleSteeringRefusesEveryFallback checks that a rule selecting by a
// device steers its fallbacks: the rules must be the kernel default set for any of
// them to be inert, and the import refuses all four when they are not.
func TestPolicyRuleSteeringRefusesEveryFallback(t *testing.T) {
	c := fbBase()
	c.rules = `[{"priority":0,"src":"all","table":"local"},{"priority":100,"iif":"gre0","table":"main"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`
	imp, err := ImportTunnels(importModel(t), c.captures())
	if err != nil {
		t.Fatal(err)
	}
	got := fallbackRefusals(imp)
	const steered = "node r1: a rule has a key the import does not read, so it cannot be a kernel default rule"
	for _, dev := range fallbackNames {
		if want := fbKindReason[dev] + notInert + steered; got[dev] != want {
			t.Errorf("%s: reason %q, want %q", dev, got[dev], want)
		}
	}
}

// TestTunnelImportRefusesRepeatedAndMisCasedKeys checks the strict reading of the
// ip -d -j link fields the import uses. A key repeated in one object, or spelled
// in another case than the one the import reads, refuses the whole capture or the
// device, since encoding/json would otherwise read one of its values silently.
func TestTunnelImportRefusesRepeatedAndMisCasedKeys(t *testing.T) {
	const remote = `"local":"10.0.12.1","remote":"10.0.12.2"`
	cases := []struct {
		name   string
		device string
		want   string
	}{
		{"repeated ifname with conflicting values",
			`{"ifname":"eth0","ifname":"eth9","link_type":"ether"}`, "repeats a key"},
		{"IFNAME spelled in capitals",
			`{"IFNAME":"eth9","link_type":"ether"}`, `differs from "ifname" only in case`},
		{"repeated linkinfo",
			`{"ifname":"eth9","link_type":"ether","linkinfo":{"info_kind":"gre","info_data":{` + remote + `}},"linkinfo":{}}`, "repeats a key"},
		{"LinkInfo spelled in capitals",
			`{"ifname":"eth9","link_type":"ether","LinkInfo":{"info_kind":"vrf"}}`, `differs from "linkinfo" only in case`},
		{"info_kind spelled in capitals",
			`{"ifname":"gre1","link":"eth0","linkinfo":{"INFO_KIND":"gre","info_data":{` + remote + `}}}`, `differs from "info_kind" only in case`},
		{"fwmark spelled in capitals on a real gre tunnel",
			`{"ifname":"gre1","link":"eth0","linkinfo":{"info_kind":"gre","info_data":{` + remote + `,"FWMARK":"0x5"}}}`, `differs from "fwmark" only in case`},
		{"repeated fwmark",
			`{"ifname":"gre1","link":"eth0","linkinfo":{"info_kind":"gre","info_data":{` + remote + `,"fwmark":"0x5","fwmark":"0x0"}}}`, "repeats a key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			caps := []TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, c.device), ruleCapture("ip-rule-r1", "r1", defaultRules)}
			imp, err := ImportTunnels(importModel(t), caps)
			if err != nil {
				t.Fatal(err)
			}
			if len(imp.Tunnels) != 0 {
				t.Errorf("a device with a bad key made a record: %+v", imp.Tunnels)
			}
			if !refusedFor(imp, c.want) {
				t.Errorf("refusals %+v, want one containing %q", imp.Refused, c.want)
			}
		})
	}
}

// TestTunnelImportKeepsUnrelatedIPLinkFields checks that a field the import does
// not read, which iproute2 may add, draws no refusal. The strict reading is not a
// whole-object schema.
func TestTunnelImportKeepsUnrelatedIPLinkFields(t *testing.T) {
	eth := `{"ifname":"eth0","link_type":"ether","mtu":1500,"qdisc":"fq_codel","group":"default","altnames":["enp0s3"],"ifalias":"uplink"}`
	caps := []TunnelCapture{linkCapture("ip-link-r1", "r1", eth), ruleCapture("ip-rule-r1", "r1", defaultRules)}
	imp, err := ImportTunnels(importModel(t), caps)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Refused) != 0 {
		t.Errorf("unrelated fields were refused: %+v", imp.Refused)
	}
}

// TestRealGRERequiresItsUnderlayWithInertEvidence checks that the addr and route
// captures leave a real gre tunnel where it was. Its underlay is still proven by the
// rules capture and by nothing else, so with the rules missing gre1 is not recorded,
// and with them present it is.
func TestRealGRERequiresItsUnderlayWithInertEvidence(t *testing.T) {
	build := func(omit string) TunnelImport {
		c := fbBase()
		c.links = append(c.links, fbETH0, fbGRE1)
		c.addrs = append(c.addrs, fbAddrETH0, fbAddrGRE1)
		c.omit = omit
		imp, err := ImportTunnels(importModel(t), c.captures())
		if err != nil {
			t.Fatal(err)
		}
		return imp
	}

	proven := build("")
	if len(proven.Tunnels) != 1 || proven.Tunnels[0].Interface != "gre1" {
		t.Errorf("with rules present, tunnels = %+v, want gre1", proven.Tunnels)
	}
	if got := fallbackRefusals(proven); len(got) != 0 {
		t.Errorf("inert fallbacks refused with rules present: %v", got)
	}

	unproven := build(TunnelCommandRules)
	if len(unproven.Tunnels) != 0 {
		t.Errorf("with rules missing, gre1 was recorded: %+v", unproven.Tunnels)
	}
	if !refusedFor(unproven, "the underlay routing table is not proven: node r1 has no ip -j rule show capture") {
		t.Errorf("gre1 refusal missing: %+v", unproven.Refused)
	}
}

// TestFallbackCapturesMustBeCollectedTogether checks the collection window of a node's
// fallback evidence. Every capture of the node is taken at t0 except one, which is
// moved to the far edge of the window. At exactly maxFallbackSpread the four fallbacks
// stay inert, and each record spans the window. One nanosecond further, every fallback
// on the node is refused, whichever capture is the outlier.
func TestFallbackCapturesMustBeCollectedTogether(t *testing.T) {
	why := "node r1: its captures were collected more than " + maxFallbackSpread.String() + " apart, so a change between them is not ruled out"
	for _, source := range []string{"ip-link-r1", "ip-addr-r1", "ip-route4-r1", "ip-route6-r1", "ip-rule-r1"} {
		t.Run(source, func(t *testing.T) {
			at := func(spread time.Duration) TunnelImport {
				caps := fbBase().captures()
				for i := range caps {
					caps[i].CollectedAt = t0
					if caps[i].Source == source {
						caps[i].CollectedAt = t0.Add(spread)
					}
				}
				imp, err := ImportTunnels(importModel(t), caps)
				if err != nil {
					t.Fatal(err)
				}
				return imp
			}

			edge := at(maxFallbackSpread)
			if len(edge.Refused) != 0 || len(edge.Inert) != 4 {
				t.Fatalf("at the bound: refused %+v, inert %+v", edge.Refused, edge.Inert)
			}
			for _, d := range edge.Inert {
				if !d.From.Equal(t0) || !d.Until.Equal(t0.Add(maxFallbackSpread)) {
					t.Errorf("%s window %s to %s, want %s to %s", d.Interface, d.From, d.Until, t0, t0.Add(maxFallbackSpread))
				}
			}

			past := at(maxFallbackSpread + time.Nanosecond)
			if len(past.Inert) != 0 {
				t.Fatalf("past the bound: inert %+v", past.Inert)
			}
			got := fallbackRefusals(past)
			for _, dev := range fallbackNames {
				if want := fbKindReason[dev] + notInert + why; got[dev] != want {
					t.Errorf("%s: reason %q, want %q", dev, got[dev], want)
				}
			}
		})
	}
}

// TestFallbackCaptureWithNoTimeIsRefused checks that a capture with no collection time
// is refused, and that its node has no fallback shown inert without it.
func TestFallbackCaptureWithNoTimeIsRefused(t *testing.T) {
	caps := fbBase().captures()
	for i := range caps {
		if caps[i].Source == "ip-rule-r1" {
			caps[i].CollectedAt = time.Time{}
		}
	}
	imp, err := ImportTunnels(importModel(t), caps)
	if err != nil {
		t.Fatal(err)
	}
	if !refusedFor(imp, "has no collection time") || len(imp.Inert) != 0 {
		t.Errorf("refused %+v, inert %+v; want the rules capture refused and no fallback inert", imp.Refused, imp.Inert)
	}
}

// TestFallbackWithoutAddressListingIsRefused calls fallbackReason with evidence that
// does not list the device. ImportTunnels cannot reach this case, since crossCheck
// keeps the two captures' devices equal, so the guard is exercised directly. A device
// missing from the address listing must be refused, never read as address-free.
func TestFallbackWithoutAddressListingIsRefused(t *testing.T) {
	links, err := parseIPLink([]byte("[" + fbGRE0 + "]"))
	if err != nil {
		t.Fatal(err)
	}
	ev := nodeEvidence{addrs: map[string]ipAddr{}, refs: map[string]string{}}
	if got, want := ev.fallbackReason(links[0], "gre0", ruleState{}), "it is not listed by ip -j addr show"; got != want {
		t.Errorf("fallbackReason = %q, want %q", got, want)
	}
}

// TestEvidenceReadersRefuseNulls checks that a null where iproute2 never prints one is
// refused, not read as zero or empty. A null array is no capture, so it is refused
// rather than taken for an empty inventory. An empty array is what the kernel prints
// for none, so it is read. The link field is not on the list: every device with no
// underlay prints "link": null.
func TestEvidenceReadersRefuseNulls(t *testing.T) {
	if _, err := parseIPLink([]byte("[" + fbGRE0 + "]")); err != nil {
		t.Fatalf("a device with link null was refused: %v", err)
	}
	if _, err := parseRoutes([]byte("[]"), cmdRoute4); err != nil {
		t.Errorf("an empty route table was refused: %v", err)
	}
	if _, err := parseIPLink([]byte("null")); err == nil {
		t.Error("a null ip -d -j link capture was read")
	}
	if _, err := parseIPAddr([]byte("null")); err == nil {
		t.Error("a null ip -j addr show capture was read")
	}
	if _, err := parseRoutes([]byte("null"), cmdRoute4); err == nil {
		t.Error("a null route capture was read as an empty table")
	}
	rows := []struct{ name, old, new string }{
		{"null ifname", `"ifname":"gre0"`, `"ifname":null`},
		{"null ifindex", `"ifindex":2`, `"ifindex":null`},
		{"null flags", `"flags":["NOARP"]`, `"flags":null`},
		{"null operstate", `"operstate":"DOWN"`, `"operstate":null`},
		{"null link_type", `"link_type":"gre"`, `"link_type":null`},
		{"null address", `"address":"0.0.0.0"`, `"address":null`},
		{"null linkinfo", `"linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"any","ttl":0,"pmtudisc":false}}`, `"linkinfo":null`},
		{"null info_kind", `"info_kind":"gre"`, `"info_kind":null`},
		{"linkinfo with no kind", `"info_kind":"gre",`, ``},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if _, err := parseIPLink([]byte("[" + subOnce(fbGRE0, r.old, r.new) + "]")); err == nil {
				t.Errorf("a device with %s was read", r.name)
			}
		})
	}
}

// TestEvidenceReadersRefuseRepeatedNestedKeys checks that a key repeated inside a nested
// object refuses the element, as a repeat at the top does, and that a key spelled in
// capitals refuses it too. A route's nexthop and an address's addr_info are the nested
// objects the fallback check reads.
func TestEvidenceReadersRefuseRepeatedNestedKeys(t *testing.T) {
	route := `[{"type":"unicast","dst":"10.8.0.0/16","table":"main","nexthops":[{"dev":"gre0","dev":"lo"}]}]`
	if _, err := parseRoutes([]byte(route), cmdRoute4); err == nil {
		t.Error("a nexthop with two dev keys was read")
	}
	capitals := `[{"type":"unicast","dst":"10.8.0.0/16","table":"main","NEXTHOPS":[{"dev":"gre0"}]}]`
	if _, err := parseRoutes([]byte(capitals), cmdRoute4); err == nil {
		t.Error("a nexthops key spelled in capitals was read")
	}
	addr := `[{"ifindex":2,"ifname":"gre0","flags":["NOARP"],"operstate":"DOWN","link_type":"gre","address":"0.0.0.0","addr_info":[{"family":"inet","local":"10.9.0.1","local":"10.9.0.2"}]}]`
	if _, err := parseIPAddr([]byte(addr)); err == nil {
		t.Error("an address with two local keys was read")
	}
}

// TestRefusalsDoNotEchoCaptureValues checks that the refusals which name a device, a
// master, or an underlay leave the capture's own value out of the reason. The name is
// one a capture could hold, so an echo would show in the text.
func TestRefusalsDoNotEchoCaptureValues(t *testing.T) {
	const secret = "zq-secret-name"
	dup := `{"ifindex":3,"ifname":"` + secret + `","flags":[],"operstate":"DOWN","link_type":"ether"}`
	devs, err := parseIPLink([]byte("[" + dup + "," + dup + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := indexLinks(devs); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("a repeated name was refused with %v, want a refusal without the name", err)
	}

	line := wgIfaceLine(secret, "off")
	if _, err := parseWGDump([]byte(line + "\n" + line)); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("a repeated wg interface was refused with %v, want a refusal without the name", err)
	}

	links := map[string]ipLink{"tun": {Name: "tun", Master: secret}}
	if _, err := vrfOf(links, "tun", "the tunnel"); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("an enslaved device was refused with %v, want a refusal without the master", err)
	}

	gre := `{"ifname":"gre9","link":"` + secret + `","linkinfo":{"info_kind":"gre","info_data":{"remote":"10.0.25.1"}}}`
	imp, err := ImportTunnels(importModel(t), []TunnelCapture{{Source: "ip-link-r1", Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: []byte("[" + fbETH0 + "," + gre + "]")}})
	if err != nil {
		t.Fatal(err)
	}
	if !refusedFor(imp, "its underlay device is not in the capture") {
		t.Errorf("refusals %+v, want the underlay refusal", imp.Refused)
	}
	for _, r := range imp.Refused {
		if strings.Contains(r.Reason, secret) {
			t.Errorf("refusal %q names the underlay device", r.Reason)
		}
	}
}
