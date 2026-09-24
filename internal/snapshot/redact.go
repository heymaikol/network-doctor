package snapshot

import (
	"cmp"
	"encoding/binary"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	// The output walk, run while collecting, reserves the identities only
	// the text patterns find. See redactor.collecting.
	r.snapshot(s)
	r.finishCollection()
	return r.snapshot(s)
}

func newRedactor() *redactor {
	r := &redactor{
		collecting:      true,
		aliases:         map[string]map[string]string{},
		originalAliases: map[string]map[string]bool{},
		ips:             map[string]string{},
		issuedIPAliases: map[string]bool{},
		prefixes:        map[string]string{},
		retainIP:        map[string]bool{},
		originalIPs:     map[string]bool{},
		recordedIPs:     map[string]bool{},
		originalPrefix:  map[string]bool{},
		prefixIPCounts:  map[string]uint32{},
		aliasCounters:   map[string]int{},
		ipCounters:      map[string]uint32{},
	}
	r.seedLocalIdentity()
	return r
}

func (r *redactor) finishCollection() {
	sort.SliceStable(r.prefixOrder, func(i, j int) bool { return r.prefixOrder[i].Bits() > r.prefixOrder[j].Bits() })
	r.collecting = false
	// Allocation waits until here, in the order the values were collected, so
	// every alias is chosen knowing every original in every alias namespace.
	for _, collected := range r.aliasOrder {
		alias := r.alias(collected.kind, collected.value)
		if collected.shortName != "" {
			r.mapAlias(r.aliases[collected.kind], collected.shortName, alias)
		}
	}
	// A spelling reserved in multiple alias namespaces needs every candidate
	// before free text can choose one. Allocate each affected namespace only
	// through its last ambiguous original, preserving earlier alias numbers.
	var ambiguous []aliasedValue
	kinds := make([]string, 0, len(r.originalAliases))
	for kind := range r.originalAliases {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	reservedIndex := make(map[aliasedValue]int, len(r.reservedOrder))
	for i, reserved := range r.reservedOrder {
		reservedIndex[aliasedValue{kind: reserved.kind, value: aliasKey(reserved.kind, reserved.value)}] = i + 1
	}
	eagerThrough := map[string]int{}
	for _, reserved := range r.reservedOrder {
		var matching []string
		for _, kind := range kinds {
			if r.originalAliases[kind][aliasKey(kind, reserved.value)] {
				matching = append(matching, kind)
			}
		}
		if len(matching) > 1 {
			for _, kind := range matching {
				eagerThrough[kind] = max(eagerThrough[kind], reservedIndex[aliasedValue{kind: kind, value: aliasKey(kind, reserved.value)}])
				ambiguous = append(ambiguous, aliasedValue{kind: kind, value: reserved.value})
			}
		}
	}
	for i, reserved := range r.reservedOrder {
		if i < eagerThrough[reserved.kind] {
			r.alias(reserved.kind, reserved.value)
		}
	}
	// A host's case-folded identity can match another namespace's spelling,
	// even when that exact host spelling was never reserved as a host.
	for _, candidate := range ambiguous {
		r.alias(candidate.kind, candidate.value)
	}
}

// SanitizeProfileForSupport applies one redaction mapping across every
// component, so the same endpoint keeps the same pseudonym throughout the
// artifact.
func SanitizeProfileForSupport(profile ProfileSnapshot) ProfileSnapshot {
	r := newRedactor()
	for _, component := range profile.Components {
		r.collectSnapshot(component.Snapshot)
	}
	r.profile(profile) // reserves text identities, as in SanitizeForSupport
	r.finishCollection()
	return r.profile(profile)
}

func (r *redactor) profile(profile ProfileSnapshot) ProfileSnapshot {
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

// seedLocalIdentity collects this machine's hostname and account name before
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
		r.collectAlias("host", hostname)
		// A machine answers to both "buildbox.corp" and "buildbox". They are
		// one host, so they share one alias rather than looking like two.
		if base, _, ok := strings.Cut(hostname, "."); ok && seedable(base) {
			r.reserve("host", base)
			r.aliasOrder[len(r.aliasOrder)-1].shortName = base
		}
	}
	if seedable(username) {
		r.collectAlias("user", username)
	}
}

// seedable rejects the values that would cost more than they protect. Short
// names collide with ordinary words under substring replacement, and a role
// name identifies nobody.
func seedable(value string) bool {
	return len(value) >= 3 && !genericIdentity[strings.ToLower(value)]
}

type redactor struct {
	// collecting is true until finishCollection. While it is, the output walk
	// can run as a collection pass: alias() and address() only reserve what
	// they are handed and prefix() allocates nothing, so every original the text
	// patterns will find is reserved by the same code that later rewrites it.
	collecting      bool
	aliases         map[string]map[string]string
	originalAliases map[string]map[string]bool
	aliasOrder      []aliasedValue
	reservedOrder   []aliasedValue
	aliasCounters   map[string]int
	ips             map[string]string
	issuedIPAliases map[string]bool
	ipCounters      map[string]uint32
	prefixes        map[string]string
	retainIP        map[string]bool
	originalIPs     map[string]bool
	recordedIPs     map[string]bool
	originalPrefix  map[string]bool
	prefixOrder     []netip.Prefix
	prefixIPCounts  map[string]uint32
	// replacements is aliases and ips as the sorted table replaceKnown scans.
	// It is nil until built and again after any write to either mapping, which
	// is why every such write goes through mapAlias or mapIP.
	replacements []replacement
}

type replacement struct{ from, to string }

func (r *redactor) mapAlias(values map[string]string, value, alias string) {
	values[value] = alias
	r.replacements = nil
}

func (r *redactor) mapIP(key, alias string) {
	r.ips[key] = alias
	r.issuedIPAliases[alias] = true
	r.replacements = nil
}

func (r *redactor) collectSnapshot(s Snapshot) {
	if s.Target != nil {
		r.collectHost(s.Target.Host)
		r.collectIP(s.Target.IP, false)
	}
	r.collectIP(s.Options.PublicDNS, true)
	if s.Options.Source != nil {
		r.collectAlias("interface", s.Options.Source.Interface)
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
		r.collectAlias("interface", o.Interface)
		r.collectAlias("ssid", o.SSID)
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
				r.originalPrefix[supportPrefixKey(route.Prefix)] = true
				// A mapped prefix never contains the unmapped addresses
				// address() looks up, so it is left out rather than turned
				// into the IPv4 network it names, which would widen what
				// prefix-aware address pseudonyms follow.
				if parsed, err := netip.ParsePrefix(route.Prefix); err == nil && !parsed.Addr().Is4In6() {
					if prefix := supportPrefix(parsed); prefix.Bits() != 0 && !slices.Contains(r.prefixOrder, prefix) {
						r.prefixOrder = append(r.prefixOrder, prefix)
					}
				}
			}
			r.collectAlias("interface", route.Interface)
			for _, competing := range route.Competing {
				r.collectAlias("interface", competing.Interface)
			}
		}
	}
	for _, finding := range s.Diagnosis.Findings {
		r.collectFinding(finding)
	}
	if s.Incident != nil {
		for _, nested := range []*Snapshot{s.Incident.Before, s.Incident.During, s.Incident.Recovered} {
			if nested != nil {
				r.collectSnapshot(*nested)
			}
		}
	}
}

// collectFinding registers the addresses a diagnosis names. A finding can cite
// an address that no observed row recorded, and an original that never reaches
// originalIPs is an original the pseudonym search will happily hand to another
// address: address() then reads the citation as a value it sanitized itself
// and returns it exactly as written. That leaks the original and collapses the
// two addresses the finding was distinguishing.
//
// Which field holds an address is read from the declared kind, the same table
// the output side reads, so a value shaped like an address under a field that
// means something else is not collected as one.
func (r *redactor) collectFinding(f Finding) {
	for _, evidence := range f.CausalEvidence {
		r.collectTypedValue(causalValueKinds[evidence.Observation], evidence.Value)
	}
	if f.Counterfactual == nil {
		return
	}
	for _, alternative := range f.Counterfactual.Alternatives {
		r.collectTypedValue(counterfactualValueKinds[f.Counterfactual.Variable], alternative.Value)
		// Validation already requires every nested item to appear in the
		// finding's own evidence, but the collection of a field belongs with
		// the field: the pass that sanitizes this one has to be the pass that
		// collected it, not a rule somewhere else that happens to cover it.
		for _, evidence := range alternative.Evidence {
			r.collectTypedValue(causalValueKinds[evidence.Observation], evidence.Value)
		}
	}
}

// collectTypedValue registers one declared-kind value that the output side
// will send through address(). Retention is deliberately not offered: a
// diagnosis naming a public resolver is an interpretation, not the recording
// that decides whether that address stays readable.
func (r *redactor) collectTypedValue(semantics valueSemantics, value string) {
	// The cases are typedValue's own, because a value has to be collected into
	// the namespace it will later be rewritten out of: an interface name that
	// only the diagnosis carries is still an original of the interface aliases,
	// and so is a value whose kind this build cannot name.
	switch {
	case value == "":
	case semantics.kind == valueKindAddress:
		r.collectIP(value, false)
	case semantics.kind == valueKindInterface:
		r.collectAlias("interface", value)
	case semantics.retains(value):
	default:
		r.collectAlias("value", value)
	}
}

// aliasedValue is one original waiting for a pseudonym out of kind's namespace.
// shortName, when set, is another spelling of the same identity that takes the
// same pseudonym.
type aliasedValue struct{ kind, value, shortName string }

// collectAlias records an original that the output side will send through
// alias(), and defers the allocation itself to finishCollection. The counter
// alone cannot choose a safe name: "interface-1" and "value-1" are strings a
// real device and a real field can hold, and an alias equal to one of them
// either hands that original back verbatim or collapses it with whichever
// original received the alias.
func (r *redactor) collectAlias(kind, value string) {
	if value == "" {
		return
	}
	r.reserve(kind, value)
	r.aliasOrder = append(r.aliasOrder, aliasedValue{kind: kind, value: value})
}

// reserve records value as an original of kind's namespace. An unambiguous
// value outside an affected namespace is allocated when output first meets it.
//
// An original spelled like an address is also kept out of the address
// pseudonyms, the only generated values that can spell one. An interface
// named "198.18.0.1" is no address, but an address pseudonym equal to it
// would still publish that name. Only originalIPs changes: the spelling is
// not recorded as an address, so it keeps its own namespace everywhere else.
func (r *redactor) reserve(kind, value string) {
	originals := r.originalAliases[kind]
	if originals == nil {
		originals = map[string]bool{}
		r.originalAliases[kind] = originals
	}
	key := aliasKey(kind, value)
	if !originals[key] {
		originals[key] = true
		r.reservedOrder = append(r.reservedOrder, aliasedValue{kind: kind, value: value})
	}
	r.reserveIP(key)
}

// aliasKey is the identity an original holds in kind's namespace. A hostname
// is read the way DNS reads it and compare.sameEndpointName compares recorded
// targets: without regard to ASCII case or the one trailing dot that spells
// the root. Every other namespace is compared exactly.
func aliasKey(kind, value string) string {
	if kind != "host" {
		return value
	}
	return strings.ToLower(strings.TrimSuffix(value, "."))
}

// reservedAlias checks each original using the identity rule of the namespace
// that holds it. The alias still belongs to its own namespace.
func (r *redactor) reservedAlias(alias string) bool {
	for kind, originals := range r.originalAliases {
		if originals[aliasKey(kind, alias)] {
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
	r.collectAlias("host", value)
}

func (r *redactor) collectURL(value string) {
	u, err := url.Parse(value)
	if err == nil && u.Hostname() != "" {
		r.collectHost(u.Hostname())
	}
}

// collectIP records an address a field declares as one. recordedIPs holds
// only these, while originalIPs also holds what text patterns find by
// spelling alone.
func (r *redactor) collectIP(value string, retain bool) {
	address, ok := r.reserveIP(value)
	if !ok {
		return
	}
	key := address.String()
	r.recordedIPs[key] = true
	if retain && publicResolverAddress(address) {
		r.retainIP[key] = true
	}
}

// reserveIP records value as an original address without declaring it one.
func (r *redactor) reserveIP(value string) (netip.Addr, bool) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return address, false
	}
	address = address.Unmap().WithZone("")
	r.originalIPs[address.String()] = true
	return address, true
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
	// ConnectCleartext is copied deliberately. It is a boolean observation about
	// the proxy transport the configuration selected, so it carries no hostname,
	// address, credential, identifier, or user-supplied string of its own, and
	// nothing here could recompute it once the proxy row's text is rewritten.
	observed := &Observed{
		DNSNotFound: o.DNSNotFound, Resolver: r.address(o.Resolver),
		SourceIP: r.address(o.SourceIP), Interface: r.alias("interface", o.Interface),
		SSID: r.alias("ssid", o.SSID), Timeout: o.Timeout,
		InterfaceAmbiguous: o.InterfaceAmbiguous, ClockOffsetMs: o.ClockOffsetMs,
		ConnectCleartext: o.ConnectCleartext,
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
			item := CounterfactualAlternative{
				Value:   r.typedValue(counterfactualValueKinds[f.Counterfactual.Variable], alternative.Value),
				Outcome: alternative.Outcome,
			}
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
		Value: r.typedValue(causalValueKinds[e.Observation], e.Value), Candidate: e.Candidate, Reason: e.Reason,
	}
}

// typedValue rewrites one value whose meaning the artifact declares beside it,
// and never reads that meaning off the value's own spelling. An interface can
// be named "192.0.2.1", and sending that name through the address namespace
// hands the evidence a value the route it cites no longer carries, which is an
// artifact netdoc then refuses to encode.
//
// The pseudonym has to come out of the same namespace as the field the value
// references, because the whole worth of an evidence item is that a reader can
// check it against the row beside it. An address therefore goes through the
// address pseudonyms, an interface through the interface aliases, and both
// land on whatever the recorded field landed on.
//
// A value whose kind this build cannot name is aliased rather than kept. That
// is the fail-safe direction: a later netdoc may name a value this one has
// never heard of, and the one thing known about such a string is that nothing
// here can prove it carries no identity.
func (r *redactor) typedValue(semantics valueSemantics, value string) string {
	switch {
	case value == "":
		return ""
	case semantics.kind == valueKindAddress:
		return r.address(value)
	case semantics.kind == valueKindInterface:
		return r.alias("interface", value)
	case semantics.retains(value):
		return value
	}
	return r.alias("value", value)
}

func (r *redactor) host(value string) string {
	if value == "" {
		return ""
	}
	if _, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return r.address(strings.Trim(value, "[]"))
	}
	// alias() already tells a collected original from an alias it generated,
	// and a spelling like "host-2.invalid" cannot: users type those too.
	return r.alias("host", value)
}

func (r *redactor) alias(kind, value string) string {
	if value == "" {
		return ""
	}
	if r.collecting {
		r.reserve(kind, value)
		return value
	}
	values := r.aliases[kind]
	if values == nil {
		values = map[string]string{}
		r.aliases[kind] = values
	}
	if alias := values[value]; alias != "" {
		return alias
	}
	// Another spelling of a mapped identity takes its alias, and is kept under
	// its own spelling too so replaceKnown finds it in text.
	key := aliasKey(kind, value)
	for original, alias := range values {
		if aliasKey(kind, alias) == key {
			return value
		}
		if aliasKey(kind, original) == key {
			r.mapAlias(values, value, alias)
			return alias
		}
	}
	// Skipping the names originals hold is what keeps aliases disjoint from
	// them, and that disjointness is what makes the already-an-alias check
	// above safe. Every original is reserved before the first allocation, so
	// skipping value itself only guards a value the collection pass missed.
	// The search is bounded: each skip consumes one of the finitely many
	// originals collected across namespaces, or value.
	alias := ""
	for {
		r.aliasCounters[kind]++
		suffix := strconv.Itoa(r.aliasCounters[kind])
		if kind == "host" {
			suffix += ".invalid"
		}
		alias = kind + "-" + suffix
		if candidate := aliasKey(kind, alias); candidate != key && !r.reservedAlias(alias) {
			break
		}
	}
	r.mapAlias(values, value, alias)
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
	if r.collecting {
		// Structured fields were collected with their retain flag already;
		// this reaches the addresses only the text patterns find, and one
		// found in a sentence is no configured resolver, so it is not retained.
		// Nor is it recorded: an interface named "192.0.2.1" is found here by
		// its spelling, and that makes it no address. See replaceKnown.
		r.reserveIP(value)
		return value
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
	if r.issuedIPAliases[key] {
		return key
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
			if !r.originalIPs[alias] && !r.issuedIPAliases[alias] {
				r.mapIP(key, alias)
				return alias
			}
		}
		break
	}
	kind, alias := addressKind(address), ""
	for range maxAliasAttempts {
		r.ipCounters[kind]++
		alias = pseudonymAddress(address, r.ipCounters[kind]).String()
		if !r.originalIPs[alias] && !r.issuedIPAliases[alias] {
			break
		}
	}
	r.mapIP(key, alias)
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
	if value == "" {
		return value
	}
	parsed, err := netip.ParsePrefix(value)
	if err != nil {
		return r.alias("prefix", value)
	}
	prefix := supportPrefix(parsed)
	// Every spelling of a default route is written as the default route.
	// A mapped prefix broader than /96 is not one: it names no IPv4 width.
	if prefix.Bits() == 0 && !prefix.Addr().Is4In6() {
		return prefix.String()
	}
	key := prefix.String()
	if alias := r.prefixes[key]; alias != "" {
		return alias
	}
	if r.collecting {
		return value
	}
	var alias string
	for n := uint32(1); n <= maxAliasAttempts; n++ {
		candidate := pseudonymPrefix(prefix, n)
		alias = candidate.String()
		// A prefix is written with its address, so a candidate whose address
		// is an original IP would publish that IP verbatim. Containment is
		// fine; only the spelled address has to differ.
		used := r.originalPrefix[alias] || r.originalIPs[candidate.Addr().Unmap().String()]
		if !used {
			for _, existing := range r.prefixes {
				used = used || existing == alias
			}
		}
		if !used {
			break
		}
	}
	r.prefixes[key] = alias
	return alias
}

// supportPrefix is the network a recorded route prefix names, which is the
// identity its support pseudonym is kept under. Host bits name no second
// network, and a mapped prefix at /96 or narrower is the IPv4 network inside
// the wrapper, as validation and pseudonymPrefix both read it. A mapped prefix
// broader than /96 has no IPv4 width to name, so it is kept as recorded.
//
// This is not compare.prefixKey: a comparison reports what two artifacts
// recorded, so it keeps the distinctions this identity erases.
func supportPrefix(prefix netip.Prefix) netip.Prefix {
	if !prefix.Addr().Is4In6() {
		return prefix.Masked()
	}
	if prefix.Bits() < 96 {
		return prefix
	}
	return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
}

// supportPrefixKey is supportPrefix for a recorded value, which is kept as it
// is when it is not a prefix at all.
func supportPrefixKey(value string) string {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return value
	}
	return supportPrefix(prefix).String()
}

func pseudonymPrefix(prefix netip.Prefix, n uint32) netip.Prefix {
	address := prefix.Addr()
	bits := prefix.Bits()
	// Unmapping removes the 96-bit IPv6 wrapper from the prefix too.
	// Validation reads any mapped prefix as IPv4, so one broader than /96
	// becomes IPv4 as well; it has no IPv4 width, and the IPv4 minimum below
	// takes over.
	if address.Is4In6() {
		address, bits = address.Unmap(), max(bits-96, 0)
	}
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
		// A name under .invalid is normally an alias, or a longer name that
		// replaceKnown built around one, and is kept. One the collection pass
		// found in the original text is someone's hostname all the same.
		if strings.HasSuffix(strings.ToLower(host), ".invalid") && !r.collecting && !r.originalAliases["host"][aliasKey("host", host)] {
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

// replacementTable returns the known values longest first, equal lengths in
// byte order. One spelling can be a key in two mappings, so the target breaks
// the last tie and the order never depends on map iteration. Every alias
// begins with its namespace, so between two alias namespaces that tie is the
// namespace name: free text gives no context to choose one. A spelling that is
// also a recorded address does not reach this tie at all; see replaceKnown.
func (r *redactor) replacementTable() []replacement {
	if r.replacements != nil {
		return r.replacements
	}
	pairs := make([]replacement, 0)
	for _, values := range r.aliases {
		for from, to := range values {
			pairs = append(pairs, replacement{from, to})
		}
	}
	for from, to := range r.ips {
		pairs = append(pairs, replacement{from, to})
	}
	slices.SortFunc(pairs, func(a, b replacement) int {
		return cmp.Or(cmp.Compare(len(b.from), len(a.from)), cmp.Compare(a.from, b.from), cmp.Compare(a.to, b.to))
	})
	r.replacements = pairs
	return pairs
}

func (r *redactor) replaceKnown(value string) string {
	pairs := r.replacementTable()
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
			// A spelling recorded both as an address and in an alias namespace,
			// an interface named "192.0.2.1" beside the address 192.0.2.1, is
			// written as the address. That is what the text patterns read the
			// spelling as, and it keeps one pseudonym for the token however the
			// fields are ordered: aliases are allocated before the output walk
			// and addresses during it, so the table alone would choose the
			// alias in fields sanitized before the address was first met.
			// A retained address would publish the alias original, so it keeps
			// its alias. Both maps are keyed by canonical address, so an alias
			// spelled "2001:DB8::1" or "::ffff:192.0.2.1" is looked up the same way.
			to, key := pair.to, pair.from
			if address, err := netip.ParseAddr(key); err == nil {
				key = address.Unmap().WithZone("").String()
			}
			if r.recordedIPs[key] && !r.retainIP[key] {
				to = r.address(pair.from)
			}
			b.WriteString(to)
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
//
// The pattern's bracketed form also matches what neither parser accepts: an
// address in brackets with no port, which is how an IPv6 target is typed, and
// a bracketed IPv4 address or out-of-range port. Those are read by their shape
// instead, the address between the brackets and any port kept as written, and
// the brackets stay only around an IPv6 pseudonym, as AddrPort writes them.
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
	if rest, ok := strings.CutPrefix(value, "["); ok {
		if inner, port, ok := strings.Cut(rest, "]"); ok {
			if address, err := netip.ParseAddr(inner); err == nil {
				alias := r.address(address.String())
				if mustAddr(alias).Is6() {
					alias = "[" + alias + "]"
				}
				return alias + port
			}
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
