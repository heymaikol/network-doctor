package diagnostic

import (
	"net"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

type advertisedName struct {
	name  string
	score int
}

// bestNames keeps the friendliest name seen so far for each IP. A device that
// advertises half a dozen services shows up once per service, and the records
// disagree about what it is called.
type bestNames map[string]advertisedName

// put scores one candidate for ip. Ties break toward the shorter name because
// services like to hang their own suffix off the same underlying device name.
func (b bestNames) put(ip, name string, score int) {
	name = strings.TrimSpace(textsafe.Clean(strings.ToValidUTF8(name, "?")))
	if name == "" || len(name) > 100 {
		return
	}
	if old := b[ip]; score > old.score || score == old.score && len(name) < len(old.name) {
		b[ip] = advertisedName{name, score}
	}
}

func (b bestNames) plain() map[string]string {
	names := make(map[string]string, len(b))
	for ip, candidate := range b {
		names[ip] = candidate.name
	}
	return names
}

// nameCandidate picks the most human of the labels one service record carries,
// and says how much it is worth. TXT wins over the instance name because a
// Chromecast's instance is a UUID while its fn= is what the owner typed into
// the setup app; googlecast wins over other fn= records because a TV and its
// streaming stick answer for the same address and the TV's own name is the
// less confusing of the two. An empty txt scores nothing on its own.
func nameCandidate(host, instance, svc, txt string) (string, int) {
	name, score := host, 1
	if instance != "" {
		name, score = instance, 2
		if strings.HasPrefix(instance, host+" - ") {
			name = host
		}
	}
	switch {
	case svc == "_googlecast._tcp" && txtValue(txt, "fn") != "":
		name, score = txtValue(txt, "fn"), 5
	case txtValue(txt, "fn") != "":
		name, score = txtValue(txt, "fn"), 4
	case txtValue(txt, "ty") != "":
		name, score = txtValue(txt, "ty"), 3
	}
	return name, score
}

func parseAvahiNames(out []byte, ips []string) map[string]string {
	wanted := make(map[string]bool, len(ips))
	for _, ip := range ips {
		wanted[ip] = true
	}

	best := bestNames{}
	// out is already fully in memory, so split it rather than scanning: a
	// bufio.Scanner abandons the rest of the output on one overlong TXT record.
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.SplitN(line, ";", 10)
		if len(fields) < 9 || fields[0] != "=" || !wanted[fields[7]] || net.ParseIP(fields[7]) == nil {
			continue
		}
		var txt string
		if len(fields) == 10 {
			txt = fields[9]
		}
		host := strings.TrimSuffix(unescapeDNS(fields[6]), ".local")
		name, score := nameCandidate(host, unescapeDNS(fields[3]), fields[4], txt)
		best.put(fields[7], name, score)
	}
	return best.plain()
}

// zoneEntry is one instance's worth of `dns-sd -Z` output: the labels that
// name it and the host its SRV points at, which is all we need once the host
// is turned back into an address.
type zoneEntry struct {
	host     string // SRV target, trailing dot intact so it resolves as a FQDN
	instance string
	svc      string
	txt      string
}

// parseDNSSDZone reads the zone-file format Apple's dns-sd prints under -Z:
// one SRV and one TXT line per instance, owner names escaped the same
// backslash-decimal way Avahi escapes them.
//
//	Living\032Room\032TV._googlecast._tcp  SRV 0 0 8009 tv.local. ; Replace with...
//	Living\032Room\032TV._googlecast._tcp  TXT "id=ab" "fn=Living Room TV"
func parseDNSSDZone(out []byte) []zoneEntry {
	byInstance := map[string]*zoneEntry{}
	var order []string

	for _, line := range strings.Split(string(out), "\n") {
		owner, rest := cutField(strings.TrimSpace(line))
		rtype, rdata := cutField(rest)
		if owner == "" || strings.HasPrefix(owner, ";") {
			continue
		}
		// The service type is the last two labels of the owner name; anything
		// before them is the instance, dots inside it escaped by dns-sd.
		svcStart := strings.LastIndex(owner, "._")
		if svcStart < 0 {
			continue
		}
		svcStart = strings.LastIndex(owner[:svcStart], "._")
		if svcStart < 0 {
			continue // a bare service type: the PTR line, which tells us nothing
		}
		instance := owner[:svcStart]

		entry := byInstance[owner]
		if entry == nil {
			entry = &zoneEntry{instance: unescapeDNS(instance), svc: owner[svcStart+1:]}
			byInstance[owner] = entry
			order = append(order, owner)
		}
		switch rtype {
		case "SRV":
			// priority weight port target
			if target := strings.Fields(rdata); len(target) >= 4 {
				entry.host = target[3]
			}
		case "TXT":
			entry.txt = rdata
		}
	}

	entries := make([]zoneEntry, 0, len(order))
	for _, owner := range order {
		if entry := byInstance[owner]; entry.host != "" {
			entries = append(entries, *entry)
		}
	}
	return entries
}

// cutField splits off the first whitespace-separated field, leaving the rest
// untouched: TXT rdata holds quoted values with spaces in them, so it can only
// be split from the left a fixed number of times.
func cutField(s string) (field, rest string) {
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i:], " \t")
}

func txtValue(txt, key string) string {
	start := strings.Index(txt, `"`+key+`=`)
	if start < 0 {
		return ""
	}
	value := txt[start+len(key)+2:]
	var ok bool
	value, _, ok = strings.Cut(value, `"`)
	if !ok {
		return ""
	}
	return unescapeDNS(value)
}

// unescapeDNS undoes the \DDD decimal escapes both Avahi and dns-sd use for
// bytes that would otherwise break the label they sit in.
func unescapeDNS(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i+3 < len(s) && s[i] == '\\' &&
			s[i+1] >= '0' && s[i+1] <= '9' &&
			s[i+2] >= '0' && s[i+2] <= '9' &&
			s[i+3] >= '0' && s[i+3] <= '9' {
			b.WriteByte((s[i+1]-'0')*100 + (s[i+2]-'0')*10 + s[i+3] - '0')
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
