package diagnostic

// What is proved here is not "these probe IDs were skipped". It is that no
// network operation caused solely by Network Doctor's own reference
// infrastructure is attempted at all.
//
// The seam is netops, which is every touchpoint a probe has with the network
// and the operating system. Each network-emitting field is replaced with one
// that records what it was asked to reach and then refuses, so a run leaves
// behind the complete list of destinations it tried. The assertion is over that
// list, not over the probe inventory: a row that survives the policy and then
// dials a built-in endpoint on the quiet fails here exactly as loudly as a row
// that should not have run.
//
// Every case has its negative control. The same graph is run with the policy
// off first, and the forbidden destinations have to turn up, or the case proves
// only that the harness cannot see them.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// referenceTarget is the endpoint a user asked about in these tests. It never
// resolves, and no substring of it appears in any built-in destination, so a
// recorded attempt is unambiguously one or the other.
const referenceTarget = "example.invalid"

// builtInDestinations is every fixed destination netdoc reaches for on its own
// account, spelled the way a recorded attempt spells it. Derived from the
// constants the probes dial, so moving an endpoint moves this with it.
func builtInDestinations() []string {
	fixed := []string{
		ConnectivityProbeHost, ncsiProbeHost, EncryptedDNSHost,
		internetEndpointCloudflareIPv4, internetEndpointGoogleIPv4,
		internetEndpointCloudflareIPv6, internetEndpointGoogleIPv6,
		DefaultPublicDNS, autoPublicDNSFallback,
	}
	slices.Sort(fixed)
	return slices.Compact(fixed)
}

// egressLog is what one run attempted, in the order the probes asked.
type egressLog struct {
	mu       sync.Mutex
	attempts []string
}

func (l *egressLog) record(what string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts = append(l.attempts, what)
}

func (l *egressLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.attempts)
}

// referenceAttempts are the recorded attempts that named a built-in
// destination. Substring matching on purpose: an attempt is recorded as the
// address, URL, or host the probe handed the seam, and any of those spellings
// carrying a fixed endpoint is the traffic this mode forbids.
func (l *egressLog) referenceAttempts() []string {
	var out []string
	for _, attempt := range l.all() {
		for _, dst := range builtInDestinations() {
			if strings.Contains(attempt, dst) {
				out = append(out, attempt)
				break
			}
		}
	}
	return out
}

// errNoNetworkInThisTest refuses every operation the harness records. The
// probes report failures, which is fine: this file asks what was attempted,
// never what came back.
var errNoNetworkInThisTest = errors.New("this test refuses every network operation")

// recordingOps is netops with every network-emitting field replaced by a
// recorder that refuses. The local fields answer just enough for the graph to
// run: one interface that is up, no Wi-Fi, no route intelligence.
func recordingOps(log *egressLog) *netops {
	return &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 1, Name: "netdoc0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) { return nil, nil },
		lookupIP: func(_ context.Context, host string) ([]net.IP, []string, error) {
			log.record("dns query for " + host)
			return nil, nil, errNoNetworkInThisTest
		},
		lookupPublicIP: func(_ context.Context, host, server string) ([]net.IP, []string, error) {
			log.record("dns query for " + host + " to resolver " + server)
			return nil, nil, errNoNetworkInThisTest
		},
		dialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			log.record(network + " dial to " + addr)
			return nil, errNoNetworkInThisTest
		},
		dialTLS: func(_ context.Context, network, addr string, cfg *tls.Config) (net.Conn, bool, error) {
			log.record(network + " TLS dial to " + addr + " as " + cfg.ServerName)
			return nil, false, errNoNetworkInThisTest
		},
		quicHandshake: func(context.Context, net.Conn, *tls.Config) (quicState, error) {
			log.record("QUIC handshake")
			return quicState{}, errNoNetworkInThisTest
		},
		portalCheck: func(_ context.Context, ep portalEndpoint) (portalObservation, error) {
			log.record("HTTP GET " + ep.url)
			return portalObservation{}, errNoNetworkInThisTest
		},
		// The proxy row's own dial goes to this machine's configured proxy,
		// which the policy allows. What it then asks that proxy to tunnel to is
		// the compiled-in connectivity host, and it names that host here before
		// any of it, so the question itself is the observation.
		proxyFromEnv: func(req *http.Request) (*url.URL, error) {
			log.record("proxy lookup for " + req.URL.Host)
			return nil, nil
		},
		ssid:       func(context.Context, string) string { return "" },
		sendBuffer: func(net.Conn) (int, error) { return 0, errNoNetworkInThisTest },
		queued:     func(net.Conn) (int, error) { return 0, errNoNetworkInThisTest },
		tcpMSS:     func(net.Conn) (int, error) { return 0, errNoNetworkInThisTest },
	}
}

// netopsEmittingFields are the touchpoints that can put a packet on the wire or
// name a destination to something that will. netopsLocalFields are the ones
// that only ask this machine about itself.
var (
	netopsEmittingFields = []string{"lookupIP", "lookupPublicIP", "dialContext", "dialTLS", "quicHandshake", "portalCheck", "proxyFromEnv"}
	netopsLocalFields    = []string{"interfaces", "interfaceAddrs", "sources", "sendBuffer", "queued", "tcpMSS", "tlsRootCAs", "ssid", "routeCause", "routeFor", "defaultRoutes", "routes"}
)

// TestEveryNetopsTouchpointIsClassifiedAndRecorded is the guard that keeps the
// rest of this file honest as netdoc grows. A new way to reach the network has
// to be classified here, and if it can emit, the recorder above has to stub it,
// or the denial run below would sail straight past it into the real network.
func TestEveryNetopsTouchpointIsClassifiedAndRecorded(t *testing.T) {
	ops := recordingOps(new(egressLog))
	value := reflect.ValueOf(*ops)
	for i := range value.NumField() {
		name := value.Type().Field(i).Name
		emitting := slices.Contains(netopsEmittingFields, name)
		if !emitting && !slices.Contains(netopsLocalFields, name) {
			t.Errorf("netops field %q is neither classified as network-emitting nor as local; reference_policy.go decides what may be reached, so say which this is", name)
			continue
		}
		if emitting && value.Field(i).IsNil() {
			t.Errorf("recordingOps leaves the network-emitting field %q nil, so a probe using it would reach the real network instead of being recorded", name)
		}
	}
}

// runRecorded builds one graph, applies one selection, and returns everything
// the run attempted. The timeout is short because nothing here waits: every
// operation refuses at once.
func runRecorded(t *testing.T, target *Target, publicDNS string, publicDNSAuto bool, selection ProbeSelection) *egressLog {
	t.Helper()
	log := new(egressLog)
	ops := recordingOps(log)
	probes := selection.Apply(ops.buildProbes(target, publicDNS, publicDNSAuto))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	RunAll(ctx, probes, 500*time.Millisecond)
	return log
}

func targetForReference(t *testing.T) *Target {
	t.Helper()
	parsed, err := ParseTarget(referenceTarget)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func assertNoReferenceEgress(t *testing.T, where string, log *egressLog) {
	t.Helper()
	if attempts := log.referenceAttempts(); len(attempts) > 0 {
		t.Errorf("%s attempted built-in reference egress: %v", where, attempts)
	}
}

func assertAttemptedAll(t *testing.T, where string, log *egressLog, want ...string) {
	t.Helper()
	attempts := log.all()
	for _, w := range want {
		if !slices.ContainsFunc(attempts, func(a string) bool { return strings.Contains(a, w) }) {
			t.Errorf("%s never attempted %q; recorded attempts were %v", where, w, attempts)
		}
	}
}

// TestOrdinaryRunAttemptsEveryBuiltInReferenceDestination is the negative
// control every other case in this file rests on. Without the flag the ordinary
// graph reaches for all of it, and the recorder sees all of it, so a later
// silence means the traffic stopped rather than that the harness went blind.
func TestOrdinaryRunAttemptsEveryBuiltInReferenceDestination(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target *Target
	}{
		{"with a target", targetForReference(t)},
		{"generic", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := runRecorded(t, tc.target, DefaultPublicDNS, true, ProbeSelection{})
			assertAttemptedAll(t, "the ordinary run", log,
				// The direct-egress row's fixed anycast endpoints.
				internetEndpointCloudflareIPv4+":443",
				// Both captive-portal observation points.
				"http://"+ConnectivityProbeHost+"/generate_204",
				"http://"+ncsiProbeHost+"/connecttest.txt",
				// The fixed QUIC endpoint, resolved before it is dialed.
				"dns query for "+ConnectivityProbeHost,
				// The built-in second-opinion resolver.
				"to resolver "+publicDNSServer(DefaultPublicDNS),
				// The fixed encrypted-DNS provider, reached on the DoT port
				// its own transport uses.
				internetEndpointCloudflareIPv4+":853",
				// The compiled-in host the proxy row asks about.
				"proxy lookup for "+ConnectivityProbeHost,
			)
		})
	}
}

// TestNoReferenceEgressAttemptsNoBuiltInDestination is the property itself, in
// the two run shapes and under a repeated pass. The target run also has to keep
// doing its job: suppressing everything would satisfy the first assertion and
// none of the point.
func TestNoReferenceEgressAttemptsNoBuiltInDestination(t *testing.T) {
	t.Run("target run still probes the target", func(t *testing.T) {
		log := runRecorded(t, targetForReference(t), DefaultPublicDNS, true, ProbeSelection{NoReferenceEgress: true})
		assertNoReferenceEgress(t, "a target run", log)
		assertAttemptedAll(t, "a target run", log, "dns query for "+referenceTarget)
	})

	// The generic run's DNS rows exist only to have something to resolve, and
	// what they resolve is compiled in. Nothing may be asked at all.
	t.Run("generic run manufactures no DNS question", func(t *testing.T) {
		log := runRecorded(t, nil, DefaultPublicDNS, true, ProbeSelection{NoReferenceEgress: true})
		assertNoReferenceEgress(t, "a generic run", log)
		for _, attempt := range log.all() {
			if strings.Contains(attempt, "dns query") {
				t.Errorf("a generic run asked %q with no target to ask about", attempt)
			}
		}
	})

	// Watch Mode is passes of the same selection over a graph rebuilt each
	// time, so the guarantee has to survive rebuilding rather than live in one
	// filtered list.
	t.Run("repeated passes stay quiet", func(t *testing.T) {
		selection := ProbeSelection{NoReferenceEgress: true}
		for range 3 {
			assertNoReferenceEgress(t, "watch pass", runRecorded(t, targetForReference(t), DefaultPublicDNS, true, selection))
		}
	})
}

// TestNoReferenceEgressKeepsAResolverTheUserNamed is the provenance rule in its
// sharpest form. 9.9.9.9 is a third party by any measure, and it is still the
// user's choice, so the second opinion stays; nothing else comes back with it.
func TestNoReferenceEgressKeepsAResolverTheUserNamed(t *testing.T) {
	const named = "9.9.9.9"
	log := runRecorded(t, targetForReference(t), named, false, ProbeSelection{NoReferenceEgress: true})
	assertNoReferenceEgress(t, "a run with a named resolver", log)
	assertAttemptedAll(t, "a run with a named resolver", log,
		"dns query for "+referenceTarget+" to resolver "+publicDNSServer(named))

	// Without a target the same resolver would be asked netdoc's own question,
	// so the row goes whoever chose the server.
	generic := runRecorded(t, nil, named, false, ProbeSelection{NoReferenceEgress: true})
	assertNoReferenceEgress(t, "a generic run with a named resolver", generic)
	for _, attempt := range generic.all() {
		if strings.Contains(attempt, "to resolver") {
			t.Errorf("a generic run queried %q, which can only be netdoc's own question", attempt)
		}
	}
}

// TestNoReferenceEgressSurvivesSelectorComposition covers the other half of
// "absolute": a selection that names rows cannot compose its way past the
// policy. --check pulling a dependency closure, --skip removing a sibling, and
// both together all leave the built-in destinations untouched.
func TestNoReferenceEgressSurvivesSelectorComposition(t *testing.T) {
	set := func(ids ...ProbeID) map[ProbeID]struct{} {
		out := make(map[ProbeID]struct{}, len(ids))
		for _, id := range ids {
			out[id] = struct{}{}
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		selection ProbeSelection
	}{
		{"check pulls a closure", ProbeSelection{Check: set(ProbeHTTPS), NoReferenceEgress: true}},
		{"skip removes a sibling", ProbeSelection{Skip: set(ProbeTLS), NoReferenceEgress: true}},
		{"check and skip together", ProbeSelection{Check: set(ProbeHTTPS, ProbePMTU), Skip: set(ProbePMTU), NoReferenceEgress: true}},
		// The composition a profile produces: the service checks name the
		// generic reference rows, and the policy still wins.
		{"a profile's own check list", ProbeSelection{
			Check:             set(ProbeInternet, ProbeProxy, ProbeDNSPublic, ProbePMTU, ProbeHTTPS),
			NoReferenceEgress: true,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertNoReferenceEgress(t, tc.name, runRecorded(t, targetForReference(t), DefaultPublicDNS, true, tc.selection))
		})
	}
}

// TestNoReferenceEgressOnlyShrinksTheGraph pins the two structural invariants
// the runtime budget depends on: the mode is a filter and never a rewrite, so
// the surviving rows are a subsequence of the ordinary graph, and no probe
// gains a dependency, which is what would deepen the schedule.
func TestNoReferenceEgressOnlyShrinksTheGraph(t *testing.T) {
	ops := recordingOps(new(egressLog))
	for _, target := range []*Target{targetForReference(t), nil} {
		full := ops.buildProbes(target, DefaultPublicDNS, true)
		filtered := ProbeSelection{NoReferenceEgress: true}.Apply(full)
		if len(filtered) > len(full) {
			t.Fatalf("filtered graph has %d probes, more than the %d it was filtered from", len(filtered), len(full))
		}
		deps := make(map[ProbeID][]ProbeID, len(full))
		next := 0
		for _, p := range full {
			deps[p.ID] = p.Deps
			if next < len(filtered) && filtered[next].ID == p.ID {
				next++
			}
		}
		if next != len(filtered) {
			t.Errorf("filtered graph is not a subsequence of the ordinary one: %v out of %v", ids(filtered), ids(full))
		}
		for _, p := range filtered {
			if !slices.Equal(p.Deps, deps[p.ID]) {
				t.Errorf("probe %q depends on %v after filtering, not on %v", p.ID, p.Deps, deps[p.ID])
			}
			for _, dep := range p.Deps {
				if !slices.ContainsFunc(filtered, func(kept Probe) bool { return kept.ID == dep }) {
					t.Errorf("probe %q survived without its dependency %q", p.ID, dep)
				}
			}
		}
	}
}

func ids(probes []Probe) []ProbeID {
	out := make([]ProbeID, len(probes))
	for i, p := range probes {
		out[i] = p.ID
	}
	return out
}

// TestReferenceEgressProbesMatchTheGraphMarks keeps the list the CLI resolves
// and the marks the graph carries from drifting apart. They are the same policy
// asked in two ways, and --via depends on the answers agreeing: the local side
// sends the list, and the remote applies it to a graph it marked itself.
func TestReferenceEgressProbesMatchTheGraphMarks(t *testing.T) {
	ops := recordingOps(new(egressLog))
	for _, tc := range []struct {
		name           string
		target         *Target
		publicDNSAuto  bool
		publicDNSNamed bool
	}{
		{"target, automatic resolver", targetForReference(t), true, false},
		{"target, named resolver", targetForReference(t), false, true},
		{"generic, automatic resolver", nil, true, false},
		{"generic, named resolver", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var marked []ProbeID
			for _, p := range ops.buildProbes(tc.target, DefaultPublicDNS, tc.publicDNSAuto) {
				if p.Reference {
					marked = append(marked, p.ID)
				}
			}
			listed := ReferenceEgressProbes(tc.target != nil, tc.publicDNSNamed)
			// The inventory order the CLI uses is not the graph's row order, so
			// compare as sets.
			slices.Sort(marked)
			sorted := slices.Clone(listed)
			slices.Sort(sorted)
			if !slices.Equal(marked, sorted) {
				t.Errorf("the graph marks %v, but ReferenceEgressProbes lists %v", marked, sorted)
			}
			if len(listed) == 0 {
				t.Error("no probe is reference egress in this shape, which no shape of an ordinary run is")
			}
		})
	}
}

// TestOrdinaryRunsAreUnchangedWithoutTheFlag is the compatibility half. Nothing
// about a run that never asked for this may move, so the default graph and the
// default selection have to produce exactly what they always did.
func TestOrdinaryRunsAreUnchangedWithoutTheFlag(t *testing.T) {
	ops := recordingOps(new(egressLog))
	for _, target := range []*Target{targetForReference(t), nil} {
		full := ops.buildProbes(target, DefaultPublicDNS, true)
		if got := (ProbeSelection{}).Apply(full); !slices.Equal(ids(got), ids(full)) {
			t.Errorf("an empty selection changed the graph: %v, want %v", ids(got), ids(full))
		}
		skipOne := ProbeSelection{Skip: map[ProbeID]struct{}{ProbeSSID: {}}}
		want := slices.DeleteFunc(ids(full), func(id ProbeID) bool { return id == ProbeSSID })
		if got := skipOne.Apply(full); !slices.Equal(ids(got), want) {
			t.Errorf("--skip alone changed more than the row it named: %v, want %v", ids(got), want)
		}
	}
}
