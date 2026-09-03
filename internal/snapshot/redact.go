package snapshot

import (
	"encoding/binary"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	sharedIPv4Prefix    = netip.MustParsePrefix("100.64.0.0/10")
	siteLocalIPv6Prefix = netip.MustParsePrefix("fec0::/10")

	credentialHeaderRE = regexp.MustCompile(`(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]*`)
	credentialValueRE  = regexp.MustCompile(`(?i)\b([A-Za-z0-9_-]*(?:password|passwd|passphrase|token|secret|api[-_]?key)[A-Za-z0-9_-]*)\s*[:=]\s*[^\s,;]+`)
	authValueRE        = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	privateKeyRE       = regexp.MustCompile(`(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----`)
	urlTextRE          = regexp.MustCompile(`(?i)\b(?:https?|socks5h?|ssh)://[^\s"'<>\x00-\x1f]+`)
	ipTextRE           = regexp.MustCompile(`\[[0-9A-Fa-f:.%]+\](?::[0-9]+)?|[0-9A-Fa-f:.%]+`)
	hostTextRE         = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]{0,62}\.)+(?:[a-z]{2,63}|local|internal|lan|home|test)\b`)
	identityTextRE     = regexp.MustCompile(`(?i)\b(username|user|hostname|host|machine|ssid)\s*[:=]\s*([^\s,;]+)`)
	certificateHostRE  = regexp.MustCompile(`(?i)\b(cert(?:ificate)? is for)\s+([^,:;\s]+)`)
	unixPathRE         = regexp.MustCompile(`(?m)(^|[\s("'=])(/[^\s,;)]*)`)
	windowsPathRE      = regexp.MustCompile(`(?im)(^|[\s("'=])([A-Z]:\\[^\s,;)]*)`)
)

// SanitizeForSupport returns a privacy-conscious copy of s. It builds every
// output type field by field so a new snapshot field is omitted from support
// artifacts until it is deliberately classified here.
func SanitizeForSupport(s Snapshot) Snapshot {
	r := newRedactor()
	r.collectSnapshot(s)
	r.finishCollection()
	return r.snapshot(s)
}

func newRedactor() *redactor {
	r := &redactor{
		aliases:        map[string]map[string]string{},
		ips:            map[string]string{},
		prefixes:       map[string]string{},
		retainIP:       map[string]bool{},
		originalIPs:    map[string]bool{},
		originalPrefix: map[string]bool{},
		prefixIPCounts: map[string]uint32{},
		aliasCounters:  map[string]int{},
		ipCounters:     map[string]uint32{},
	}
	r.seedLocalIdentity()
	return r
}

func (r *redactor) finishCollection() {
	sort.SliceStable(r.prefixOrder, func(i, j int) bool { return r.prefixOrder[i].Bits() > r.prefixOrder[j].Bits() })
}

// SanitizeProfileForSupport applies one redaction mapping across every
// component, so the same endpoint keeps the same pseudonym throughout the
// artifact.
func SanitizeProfileForSupport(profile ProfileSnapshot) ProfileSnapshot {
	r := newRedactor()
	for _, component := range profile.Components {
		r.collectSnapshot(component.Snapshot)
	}
	r.finishCollection()
	out := ProfileSnapshot{
		Schema: profile.Schema, CreatedAt: profile.CreatedAt,
		Tool:       Tool{Version: r.text(profile.Tool.Version), OS: profile.Tool.OS, Arch: profile.Tool.Arch},
		Profile:    ProfileIdentity{Name: profile.Profile.Name, Version: profile.Profile.Version, Title: r.text(profile.Profile.Title)},
		Components: make([]ProfileComponent, len(profile.Components)),
		Aggregate:  ProfileAggregate{Status: profile.Aggregate.Status, Summary: r.text(profile.Aggregate.Summary)},
		OK:         profile.OK, Redaction: &Redaction{Sanitized: true, Policy: SupportRedactionPolicy},
	}
	for i, component := range profile.Components {
		out.Components[i] = ProfileComponent{
			ID: component.ID, Label: r.text(component.Label), Focus: component.Focus,
			Status: component.Status, Fallback: component.Fallback, Snapshot: r.snapshot(component.Snapshot),
		}
	}
	if profile.Aggregate.Finding != nil {
		out.Aggregate.Finding = &ProfileFinding{
			ID:                 profile.Aggregate.Finding.ID,
			AffectedComponents: append([]string(nil), profile.Aggregate.Finding.AffectedComponents...),
			WorkingComponents:  append([]string(nil), profile.Aggregate.Finding.WorkingComponents...),
		}
	}
	return out
}

// localIdentity is this machine's own name and account name. It is a variable
// so a test can pin it: what it returns is a property of the host, and a test
// that read the real one would assert against whatever machine ran it.
//
// The account name comes from the home directory rather than from os/user,
// which keeps this free of the cgo resolver path that release builds exclude.
var localIdentity = func() (hostname, username string) {
	hostname, _ = os.Hostname()
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		username = filepath.Base(home)
	}
	return hostname, username
}

// genericIdentity are names that describe a role rather than a person or a
// machine. Every system has them, so aliasing one buys no privacy and would
// rewrite ordinary diagnostic words that merely contain it.
var genericIdentity = map[string]bool{
	"root": true, "user": true, "admin": true, "administrator": true,
	"localhost": true, "home": true, "users": true, "guest": true,
}

// seedLocalIdentity registers this machine's hostname and account name before
// the snapshot is walked, so every later text pass replaces them the way it
// replaces any other known value.
//
// Neither is a structured snapshot field, so without this seeding they could
// only ever be caught by a pattern, and neither has one worth matching: a
// single-label hostname like "buildbox" and an account name like "jrivera" are
// indistinguishable from ordinary words. They are also exactly the two values
// most likely to be in a path, a certificate name, or a resolver error.
func (r *redactor) seedLocalIdentity() {
	hostname, username := localIdentity()
	if seedable(hostname) {
		alias := r.alias("host", hostname)
		// A machine answers to both "buildbox.corp" and "buildbox". They are
		// one host, so they share one alias rather than looking like two.
		if base, _, ok := strings.Cut(hostname, "."); ok && seedable(base) {
			r.aliases["host"][base] = alias
		}
	}
	if seedable(username) {
		r.alias("user", username)
	}
}

// seedable rejects the values that would cost more than they protect. Short
// names collide with ordinary words under substring replacement, and a role
// name identifies nobody.
func seedable(value string) bool {
	return len(value) >= 3 && !genericIdentity[strings.ToLower(value)]
}

type redactor struct {
	aliases        map[string]map[string]string
	aliasCounters  map[string]int
	ips            map[string]string
	ipCounters     map[string]uint32
	prefixes       map[string]string
	retainIP       map[string]bool
	originalIPs    map[string]bool
	originalPrefix map[string]bool
	prefixOrder    []netip.Prefix
	prefixIPCounts map[string]uint32
}

func (r *redactor) collectSnapshot(s Snapshot) {
	if s.Target != nil {
		r.collectHost(s.Target.Host)
		r.collectIP(s.Target.IP, false)
	}
	r.collectIP(s.Options.PublicDNS, true)
	if s.Options.Source != nil {
		r.alias("interface", s.Options.Source.Interface)
		r.collectIP(s.Options.Source.IPv4, false)
		r.collectIP(s.Options.Source.IPv6, false)
	}
	for _, check := range s.Checks {
		if check.Observed == nil {
			continue
		}
		o := check.Observed
		for _, address := range o.Addresses {
			r.collectIP(address, false)
		}
		r.collectIP(o.SelectedIP, false)
		r.collectIP(o.Resolver, true)
		for _, target := range o.ResolverTargets {
			r.collectResolverTarget(target, check.ID == "dns_public")
		}
		r.collectIP(o.SourceIP, false)
		r.alias("interface", o.Interface)
		r.alias("ssid", o.SSID)
		if o.Portal != nil {
			r.collectURL(o.Portal.RedirectURL)
		}
		for _, attempt := range o.Attempts {
			r.collectIP(attempt.IP, false)
		}
		for _, route := range o.Routes {
			r.collectIP(route.Destination, false)
			r.collectIP(route.Gateway, false)
			r.collectIP(route.Source, false)
			if route.Prefix != "" {
				r.originalPrefix[route.Prefix] = true
				if prefix, err := netip.ParsePrefix(route.Prefix); err == nil && prefix.Bits() != 0 && !r.hasPrefix(prefix) {
					r.prefixOrder = append(r.prefixOrder, prefix)
				}
			}
			r.alias("interface", route.Interface)
			for _, competing := range route.Competing {
				r.alias("interface", competing.Interface)
			}
		}
	}
	if s.Incident != nil {
		for _, nested := range []*Snapshot{s.Incident.Before, s.Incident.During, s.Incident.Recovered} {
			if nested != nil {
				r.collectSnapshot(*nested)
			}
		}
	}
}

func (r *redactor) hasPrefix(prefix netip.Prefix) bool {
	for _, existing := range r.prefixOrder {
		if existing == prefix {
			return true
		}
	}
	return false
}

func (r *redactor) collectHost(value string) {
	if value == "" {
		return
	}
	if _, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		r.collectIP(strings.Trim(value, "[]"), false)
		return
	}
	r.alias("host", value)
}

func (r *redactor) collectURL(value string) {
	u, err := url.Parse(value)
	if err == nil && u.Hostname() != "" {
		r.collectHost(u.Hostname())
	}
}

func (r *redactor) collectIP(value string, retain bool) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return
	}
	address = address.Unmap().WithZone("")
	key := address.String()
	r.originalIPs[key] = true
	if retain && publicResolverAddress(address) {
		r.retainIP[key] = true
	}
}

func (r *redactor) snapshot(s Snapshot) Snapshot {
	out := Snapshot{
		Schema: s.Schema, CreatedAt: s.CreatedAt,
		Tool: Tool{Version: r.text(s.Tool.Version), OS: s.Tool.OS, Arch: s.Tool.Arch},
		Options: Options{
			ProbeTimeoutMs: s.Options.ProbeTimeoutMs,
			PublicDNS:      r.address(s.Options.PublicDNS),
			PublicDNSAuto:  s.Options.PublicDNSAuto,
			Check:          append([]string(nil), s.Options.Check...),
			Skip:           append([]string(nil), s.Options.Skip...),
		},
		Checks: make([]Check, len(s.Checks)),
		Diagnosis: Diagnosis{
			Verdict: s.Diagnosis.Verdict, Summary: r.text(s.Diagnosis.Summary),
			Blamed: s.Diagnosis.Blamed, FailedStage: s.Diagnosis.FailedStage,
		},
		OK:        s.OK,
		Redaction: &Redaction{Sanitized: true, Policy: SupportRedactionPolicy},
	}
	if s.Target != nil {
		host := r.host(s.Target.Host)
		out.Target = &Target{
			Raw: r.text(s.Target.Raw), Host: host, IP: r.address(s.Target.IP),
			Port: s.Target.Port, Protocol: s.Target.Protocol, PortExplicit: s.Target.PortExplicit,
		}
	}
	if s.Options.Source != nil {
		out.Options.Source = &Source{
			Interface: r.alias("interface", s.Options.Source.Interface),
			IPv4:      r.address(s.Options.Source.IPv4), IPv6: r.address(s.Options.Source.IPv6),
		}
	}
	for i, check := range s.Checks {
		out.Checks[i] = r.check(check)
	}
	for _, finding := range s.Diagnosis.Findings {
		out.Diagnosis.Findings = append(out.Diagnosis.Findings, r.finding(finding))
	}
	if s.Incident != nil {
		out.Incident = &Incident{
			StartedAt: s.Incident.StartedAt, EndedAt: s.Incident.EndedAt, Passes: s.Incident.Passes,
		}
		for _, state := range []struct {
			from *Snapshot
			into **Snapshot
		}{
			{s.Incident.Before, &out.Incident.Before},
			{s.Incident.During, &out.Incident.During},
			{s.Incident.Recovered, &out.Incident.Recovered},
		} {
			if state.from != nil {
				nested := r.snapshot(*state.from)
				*state.into = &nested
			}
		}
	}
	return out
}

func (r *redactor) check(c Check) Check {
	out := Check{
		ID: c.ID, Name: r.text(c.Name), Deps: append([]string(nil), c.Deps...),
		Status: c.Status, Cause: c.Cause, CauseFamily: c.CauseFamily, Ran: c.Ran, DurationMs: c.DurationMs,
		Detail: r.text(c.Detail), Fix: r.text(c.Fix),
	}
	if c.Derived != nil {
		// Both fields are conclusions the run reached, not measurements: they
		// name no address, prefix, operator, or routability, and say strictly
		// less than the row's own status and detail already do. Copied as
		// stored, because recomputing either one here would need the original
		// addresses this pass exists to remove.
		out.Derived = &Derived{
			StatusDowngraded: c.Derived.StatusDowngraded,
			AnswerComparison: c.Derived.AnswerComparison,
		}
	}
	if c.Observed == nil {
		return out
	}
	o := c.Observed
	observed := &Observed{
		DNSNotFound: o.DNSNotFound, Resolver: r.address(o.Resolver),
		SourceIP: r.address(o.SourceIP), Interface: r.alias("interface", o.Interface),
		SSID: r.alias("ssid", o.SSID), Timeout: o.Timeout,
		InterfaceAmbiguous: o.InterfaceAmbiguous, ClockOffsetMs: o.ClockOffsetMs,
	}
	for _, target := range o.ResolverTargets {
		observed.ResolverTargets = append(observed.ResolverTargets, r.resolverTarget(target))
	}
	for _, address := range o.Addresses {
		observed.Addresses = append(observed.Addresses, r.address(address))
	}
	observed.SelectedIP = r.address(o.SelectedIP)
	if o.Families != nil {
		observed.Families = &Families{IPv4: o.Families.IPv4, IPv6: o.Families.IPv6}
	}
	if o.Portal != nil {
		observed.Portal = &Portal{RedirectURL: r.sanitizeURL(o.Portal.RedirectURL)}
	}
	for _, attempt := range o.Attempts {
		observed.Attempts = append(observed.Attempts, Attempt{
			IP: r.address(attempt.IP), DurationMs: attempt.DurationMs,
			Error: r.text(attempt.Error), Cause: attempt.Cause, Aborted: attempt.Aborted,
		})
	}
	for _, route := range o.Routes {
		item := Route{
			Destination: r.address(route.Destination), Family: route.Family,
			Interface: r.alias("interface", route.Interface), Gateway: r.address(route.Gateway),
			Source: r.address(route.Source), Prefix: r.prefix(route.Prefix), Metric: route.Metric,
			Table: r.routeTable(route.Table), TableKnown: route.TableKnown,
			InterfaceMTU: route.InterfaceMTU,
			Tunnel:       route.Tunnel, TunnelKind: route.TunnelKind,
			Unreachable: route.Unreachable, Reason: route.Reason,
		}
		for _, competing := range route.Competing {
			item.Competing = append(item.Competing, CompetingRoute{
				Interface: r.alias("interface", competing.Interface), Metric: competing.Metric,
			})
		}
		observed.Routes = append(observed.Routes, item)
	}
	out.Observed = observed
	return out
}

func (r *redactor) finding(f Finding) Finding {
	out := Finding{
		ID: f.ID, Verdict: f.Verdict, Summary: r.text(f.Summary), Focus: f.Focus,
		Confidence: f.Confidence, Evidence: append([]string(nil), f.Evidence...),
	}
	for _, evidence := range f.CausalEvidence {
		out.CausalEvidence = append(out.CausalEvidence, r.causalEvidence(evidence))
	}
	if f.Counterfactual != nil {
		out.Counterfactual = &Counterfactual{Variable: f.Counterfactual.Variable}
		for _, alternative := range f.Counterfactual.Alternatives {
			item := CounterfactualAlternative{Value: r.value(alternative.Value), Outcome: alternative.Outcome}
			for _, evidence := range alternative.Evidence {
				item.Evidence = append(item.Evidence, r.causalEvidence(evidence))
			}
			out.Counterfactual.Alternatives = append(out.Counterfactual.Alternatives, item)
		}
	}
	return out
}

func (r *redactor) causalEvidence(e CausalEvidence) CausalEvidence {
	return CausalEvidence{
		Kind: e.Kind, Check: e.Check, Observation: e.Observation,
		Value: r.value(e.Value), Candidate: e.Candidate, Reason: e.Reason,
	}
}

func (r *redactor) value(value string) string {
	if _, err := netip.ParseAddr(value); err == nil {
		return r.address(value)
	}
	return r.text(value)
}

func (r *redactor) host(value string) string {
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "host-") && strings.HasSuffix(value, ".invalid") {
		return value
	}
	if _, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return r.address(strings.Trim(value, "[]"))
	}
	return r.alias("host", value)
}

func (r *redactor) alias(kind, value string) string {
	if value == "" {
		return ""
	}
	values := r.aliases[kind]
	if values == nil {
		values = map[string]string{}
		r.aliases[kind] = values
	}
	if alias := values[value]; alias != "" {
		return alias
	}
	for _, alias := range values {
		if value == alias {
			return value
		}
	}
	r.aliasCounters[kind]++
	suffix := strconv.Itoa(r.aliasCounters[kind])
	if kind == "host" {
		suffix += ".invalid"
	}
	alias := kind + "-" + suffix
	values[value] = alias
	return alias
}

func (r *redactor) routeTable(value string) string {
	if value == "" || value == "main" || value == "default" || value == "local" {
		return value
	}
	if _, err := strconv.ParseUint(value, 10, 32); err == nil {
		return value
	}
	return r.alias("route-table", value)
}

func (r *redactor) address(value string) string {
	if value == "" {
		return ""
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		// Every caller here holds a field the schema declares as an address.
		// A value that will not parse as one is not diagnostic information, so
		// it is dropped rather than handed to the text pass: the text pass
		// keeps what it does not recognize, which is right for a sentence and
		// wrong for a field that should have held an address.
		return redactedAddress
	}
	address = address.Unmap().WithZone("")
	key := address.String()
	for _, alias := range r.ips {
		if key == alias {
			return key
		}
	}
	if r.retainIP[key] && publicResolverAddress(address) {
		return key
	}
	if alias := r.ips[key]; alias != "" {
		return alias
	}
	// Both searches below are bounded. A candidate is rejected when it collides
	// with an address the snapshot already holds or with an alias handed out
	// earlier, and a narrow prefix cannot always resolve that by counting: a
	// /32 host route is ordinary on a VPN and offers exactly one host address,
	// so an unbounded search there spins forever. Falling through to the
	// family-wide pseudonym loses a prefix relationship; it never leaks.
	for _, originalPrefix := range r.prefixOrder {
		if !originalPrefix.Contains(address) {
			continue
		}
		mappedPrefix, err := netip.ParsePrefix(r.prefix(originalPrefix.String()))
		if err != nil {
			break
		}
		for range aliasAttempts(mappedPrefix.Addr().BitLen() - mappedPrefix.Bits()) {
			r.prefixIPCounts[originalPrefix.String()]++
			alias := pseudonymWithin(mappedPrefix, r.prefixIPCounts[originalPrefix.String()]).String()
			if !r.originalIPs[alias] && !r.usedIPAlias(alias) {
				r.ips[key] = alias
				return alias
			}
		}
		break
	}
	kind, alias := addressKind(address), ""
	for range maxAliasAttempts {
		r.ipCounters[kind]++
		alias = pseudonymAddress(address, r.ipCounters[kind]).String()
		if !r.originalIPs[alias] && !r.usedIPAlias(alias) {
			break
		}
	}
	r.ips[key] = alias
	return alias
}

func (r *redactor) collectResolverTarget(target string, retain bool) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	r.collectIP(host, retain)
}

func (r *redactor) resolverTarget(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return r.address(target)
	}
	return net.JoinHostPort(r.address(host), port)
}

// redactedAddress and redactedURL replace a value that should have been an
// address or a URL and was not. They are deliberately not valid values of
// either kind, so nothing downstream reads one as a real endpoint.
const (
	redactedAddress = "<address-redacted>"
	redactedURL     = "<url-redacted>"
)

// maxAliasAttempts caps every pseudonym search. Each generator varies at most
// 16 bits of counter before it repeats, so a search that gets this far has
// already seen every value it can produce.
const maxAliasAttempts = 1 << 16

// aliasAttempts is how many distinct hosts a mapped prefix can name, capped at
// the point where the generator repeats anyway.
func aliasAttempts(hostBits int) int {
	if hostBits < 0 {
		return 0
	}
	if hostBits >= 16 {
		return maxAliasAttempts
	}
	return 1 << hostBits
}

func (r *redactor) usedIPAlias(value string) bool {
	for _, alias := range r.ips {
		if alias == value {
			return true
		}
	}
	return false
}

func pseudonymWithin(prefix netip.Prefix, n uint32) netip.Addr {
	if prefix.Addr().Is4() {
		raw := prefix.Addr().As4()
		value := binary.BigEndian.Uint32(raw[:])
		hostBits := 32 - prefix.Bits()
		if hostBits > 0 {
			mask := uint32(1)<<hostBits - 1
			value |= n & mask
		}
		binary.BigEndian.PutUint32(raw[:], value)
		return netip.AddrFrom4(raw)
	}
	raw := prefix.Addr().As16()
	hostBits := 128 - prefix.Bits()
	for bit, value := 0, n; bit < hostBits && value > 0; bit, value = bit+1, value>>1 {
		if value&1 != 0 {
			position := 127 - bit
			raw[position/8] |= 1 << (7 - position%8)
		}
	}
	return netip.AddrFrom16(raw)
}

func sensitiveAddress(address netip.Addr) bool {
	return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() ||
		sharedIPv4Prefix.Contains(address) || siteLocalIPv6Prefix.Contains(address)
}

func publicResolverAddress(address netip.Addr) bool {
	return address.IsGlobalUnicast() && !sensitiveAddress(address)
}

func addressKind(address netip.Addr) string {
	switch {
	case address.IsLoopback():
		return "loopback"
	case address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast():
		return "link-local"
	case address.IsPrivate() || sharedIPv4Prefix.Contains(address) || siteLocalIPv6Prefix.Contains(address):
		return "private"
	case address.IsMulticast():
		return "multicast"
	default:
		return "public-local"
	}
}

func pseudonymAddress(address netip.Addr, n uint32) netip.Addr {
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], n)
	if address.Is4() {
		switch addressKind(address) {
		case "loopback":
			return netip.AddrFrom4([4]byte{127, counter[1], counter[2], counter[3]})
		case "link-local":
			return netip.AddrFrom4([4]byte{169, 254, counter[2], counter[3]})
		case "multicast":
			return netip.AddrFrom4([4]byte{233, 252, counter[2], counter[3]})
		case "public-local":
			return netip.AddrFrom4([4]byte{198, 18, counter[2], counter[3]})
		default:
			return netip.AddrFrom4([4]byte{10, counter[1], counter[2], counter[3]})
		}
	}
	var bytes [16]byte
	switch addressKind(address) {
	case "loopback":
		bytes[15] = counter[3]
	case "link-local":
		bytes[0], bytes[1] = 0xfe, 0x80
	case "multicast":
		bytes[0], bytes[1] = 0xff, 0x3e
	case "public-local":
		bytes[0], bytes[1], bytes[2], bytes[3] = 0x20, 0x01, 0x0d, 0xb8
	default:
		bytes[0] = 0xfd
	}
	copy(bytes[12:], counter[:])
	return netip.AddrFrom16(bytes)
}

func (r *redactor) prefix(value string) string {
	if value == "" || value == "0.0.0.0/0" || value == "::/0" {
		return value
	}
	if alias := r.prefixes[value]; alias != "" {
		return alias
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return r.alias("prefix", value)
	}
	var alias string
	for n := uint32(1); n <= maxAliasAttempts; n++ {
		alias = pseudonymPrefix(prefix, n).String()
		used := r.originalPrefix[alias]
		if !used {
			for _, existing := range r.prefixes {
				used = used || existing == alias
			}
		}
		if !used {
			break
		}
	}
	r.prefixes[value] = alias
	return alias
}

func pseudonymPrefix(prefix netip.Prefix, n uint32) netip.Prefix {
	address := prefix.Addr().Unmap()
	bits := prefix.Bits()
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], n)
	if address.Is4() {
		if bits < 16 {
			bits = 16
		}
		var raw [4]byte
		switch addressKind(address) {
		case "loopback":
			raw[0] = 127
		case "link-local":
			raw[0] = 169
		case "multicast":
			raw[0] = 233
		case "public-local":
			raw[0], raw[1] = 198, 18+counter[2]
			if bits < 24 {
				bits = 24
			}
			raw[2] = counter[3]
			return netip.PrefixFrom(netip.AddrFrom4(raw), bits).Masked()
		default:
			raw[0] = 10
		}
		if bits < 24 {
			raw[1] = counter[3]
		} else {
			raw[1], raw[2] = counter[2], counter[3]
		}
		return netip.PrefixFrom(netip.AddrFrom4(raw), bits).Masked()
	}
	if bits < 48 {
		bits = 48
	}
	raw := pseudonymAddress(address, n).As16()
	if bits < 64 {
		raw[4], raw[5] = counter[2], counter[3]
	} else {
		raw[6], raw[7] = counter[2], counter[3]
	}
	return netip.PrefixFrom(netip.AddrFrom16(raw), bits).Masked()
}

func (r *redactor) sanitizeURL(value string) string {
	if value == "" {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return redactedURL
	}
	host := r.host(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	u.Host, u.User, u.RawQuery, u.Fragment, u.ForceQuery = host, nil, "", "", false
	if u.Path != "" && u.Path != "/" {
		u.Path, u.RawPath = "/path", ""
	}
	return u.String()
}

func (r *redactor) text(value string) string {
	if value == "" {
		return ""
	}
	value = r.replaceKnown(value)
	value = privateKeyRE.ReplaceAllString(value, "<private-key-redacted>")
	value = credentialHeaderRE.ReplaceAllString(value, "$1: <redacted>")
	value = credentialValueRE.ReplaceAllString(value, "$1=<redacted>")
	value = authValueRE.ReplaceAllString(value, "$1 <redacted>")
	value = urlTextRE.ReplaceAllStringFunc(value, r.sanitizeURL)
	value = ipTextRE.ReplaceAllStringFunc(value, r.textAddress)
	value = hostTextRE.ReplaceAllStringFunc(value, func(host string) string {
		if strings.HasSuffix(strings.ToLower(host), ".invalid") {
			return host
		}
		return r.alias("host", host)
	})
	value = identityTextRE.ReplaceAllStringFunc(value, r.redactIdentity)
	value = certificateHostRE.ReplaceAllStringFunc(value, r.redactCertificateHost)
	value = unixPathRE.ReplaceAllStringFunc(value, func(match string) string { return r.redactPath(match, "/") })
	value = windowsPathRE.ReplaceAllStringFunc(value, func(match string) string { return r.redactPath(match, `:\`) })
	return value
}

func (r *redactor) redactCertificateHost(match string) string {
	parts := certificateHostRE.FindStringSubmatch(match)
	if len(parts) != 3 {
		return match
	}
	return parts[1] + " " + r.alias("host", parts[2])
}

func (r *redactor) replaceKnown(value string) string {
	type pair struct{ from, to string }
	var pairs []pair
	for _, values := range r.aliases {
		for from, to := range values {
			pairs = append(pairs, pair{from, to})
		}
	}
	for from, to := range r.ips {
		pairs = append(pairs, pair{from, to})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if len(pairs[i].from) == len(pairs[j].from) {
			return pairs[i].from < pairs[j].from
		}
		return len(pairs[i].from) > len(pairs[j].from)
	})
	if len(pairs) == 0 {
		return value
	}
	// Longest key first at every position, so a fully qualified name is
	// replaced before the short name inside it, and each match has to stand on
	// its own: these keys are substrings of ordinary words often enough to
	// matter, and an interface named "lo" must not turn "hello" into "helX".
	var b strings.Builder
	for i := 0; i < len(value); {
		replaced := false
		for _, pair := range pairs {
			if pair.from == "" || !strings.HasPrefix(value[i:], pair.from) ||
				!standsAlone(value, i, len(pair.from)) {
				continue
			}
			b.WriteString(pair.to)
			i += len(pair.from)
			replaced = true
			break
		}
		if !replaced {
			b.WriteByte(value[i])
			i++
		}
	}
	return b.String()
}

// standsAlone reports whether value[i:i+n] is a whole run rather than the
// middle of a longer identifier. A key that already begins or ends with a
// non-identifier character, such as a hostname's dot or an SSID's space,
// supplies that side's boundary itself.
func standsAlone(value string, i, n int) bool {
	if i > 0 && identifierByte(value[i-1]) && identifierByte(value[i]) {
		return false
	}
	if end := i + n; end < len(value) && identifierByte(value[end-1]) && identifierByte(value[end]) {
		return false
	}
	return true
}

func identifierByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '-'
}

// textAddress pseudonymizes one address-shaped run of text. The candidate is
// tried whole first and then with trailing separators removed, because the
// pattern that finds it cannot tell a dot inside an address from the one that
// ends the sentence carrying it: "no route to 192.168.7.31." has to redact the
// same address that "no route to 192.168.7.31, retrying" does.
func (r *redactor) textAddress(value string) string {
	for _, trimmed := range [2]string{value, strings.TrimRight(value, ".:")} {
		suffix := value[len(trimmed):]
		if address, err := netip.ParseAddr(trimmed); err == nil {
			return r.address(address.String()) + suffix
		}
		if endpoint, err := netip.ParseAddrPort(trimmed); err == nil {
			return netip.AddrPortFrom(mustAddr(r.address(endpoint.Addr().String())), endpoint.Port()).String() + suffix
		}
	}
	return value
}

func mustAddr(value string) netip.Addr {
	address, _ := netip.ParseAddr(value)
	return address
}

func (r *redactor) redactIdentity(match string) string {
	parts := identityTextRE.FindStringSubmatch(match)
	if len(parts) != 3 {
		return match
	}
	kind := strings.ToLower(parts[1])
	aliasKind := "user"
	switch kind {
	case "ssid":
		aliasKind = "ssid"
	case "host", "hostname", "machine":
		aliasKind = "host"
	}
	return parts[1] + "=" + r.alias(aliasKind, parts[2])
}

func (r *redactor) redactPath(match, marker string) string {
	index := strings.Index(match, marker)
	if index < 0 {
		return match
	}
	if marker == `:\` {
		index--
	}
	path := match[index:]
	// A bare separator names nothing, and registering one as a known value
	// would rewrite every path separator in every string sanitized after it.
	// The check named "QUIC / UDP 443" is a label, not a filesystem path.
	if strings.Trim(path, `/\`) == "" {
		return match
	}
	return match[:index] + r.alias("path", path)
}
