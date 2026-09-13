package incident

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// Environment and Outcome split a comparison by matching the paths it emits,
// and the paths are produced somewhere else. That is the drift this ledger
// exists to catch: internal/compare can learn to report a new piece of
// evidence, and this package keeps answering "nothing about the path changed"
// because a string was never added to it. That already happened once, when the
// DNS row moved the system resolver's identity out of Observed.Resolver and
// into Observed.ResolverTargets.
//
// So every field of snapshot.Observed carries a decision here, the decision is
// proved by running the real comparison rather than by reading the matcher,
// and a field added to Observed fails this test until somebody makes the same
// call about it.
type classification struct {
	// environment is what this field's changes must be classified as: true for
	// how the machine reaches the network, false for what the checks made of
	// it.
	environment bool
	// why states the reading, because the entries that claim less are the ones
	// a maintainer will want to argue with.
	why string
	// before and after differ in this field alone. The comparison is run over
	// them, so what this ledger checks is the path production emits.
	before, after snapshot.Observed
}

func ms(v int64) *int64 { return &v }

var observedClassification = map[string]classification{
	"Addresses": {true, "the addresses the name resolved to are the destinations traffic is aimed at",
		snapshot.Observed{Addresses: []string{"198.51.100.7"}},
		snapshot.Observed{Addresses: []string{"198.51.100.8"}}},
	"SelectedIP": {true, "the address this row actually used",
		snapshot.Observed{SelectedIP: "198.51.100.7"},
		snapshot.Observed{SelectedIP: "198.51.100.8"}},
	"DNSNotFound": {false, "an answer the resolver gave, which is a result and not a path",
		snapshot.Observed{},
		snapshot.Observed{DNSNotFound: true}},
	"Resolver": {true, "the second-opinion server this run was configured to ask",
		snapshot.Observed{Resolver: "9.9.9.9"},
		snapshot.Observed{Resolver: "1.1.1.1"}},
	"ResolverTargets": {true, "the DNS service addresses the lookup dialed, which is where a system resolver change shows up",
		snapshot.Observed{ResolverTargets: []string{"192.168.1.1:53"}},
		snapshot.Observed{ResolverTargets: []string{"10.0.0.53:53"}}},
	"SourceIP": {true, "the local end of the connection the kernel chose",
		snapshot.Observed{SourceIP: "10.0.0.2"},
		snapshot.Observed{SourceIP: "10.0.0.3"}},
	"Interface": {true, "the interface traffic left by",
		snapshot.Observed{Interface: "wlan0"},
		snapshot.Observed{Interface: "wg0"}},
	"SSID": {true, "the network this machine is attached to",
		snapshot.Observed{SSID: "home"},
		snapshot.Observed{SSID: "cafe"}},
	"InterfaceAmbiguous": {false, "how well the run could name the interface, not a move by the interface itself",
		snapshot.Observed{},
		snapshot.Observed{InterfaceAmbiguous: true}},
	"Families": {false, "per-family reachability, which is a probe result",
		snapshot.Observed{Families: &snapshot.Families{IPv4: "reachable"}},
		snapshot.Observed{Families: &snapshot.Families{IPv4: "unreachable"}}},
	"Portal": {false, "interception found by dialing, which is the failure rather than a candidate explanation for it",
		snapshot.Observed{},
		snapshot.Observed{Portal: &snapshot.Portal{RedirectURL: "http://portal.example/login"}}},
	"Attempts": {false, "what one connection attempt did",
		snapshot.Observed{Attempts: []snapshot.Attempt{{IP: "198.51.100.7", Cause: "refused"}}},
		snapshot.Observed{Attempts: []snapshot.Attempt{{IP: "198.51.100.7", Cause: "timeout"}}}},
	"ClockOffsetMs": {false, "a measurement this machine took, not a path it took",
		snapshot.Observed{ClockOffsetMs: ms(1000)},
		snapshot.Observed{ClockOffsetMs: ms(90000)}},
	"Timeout": {false, "how a probe failed",
		snapshot.Observed{},
		snapshot.Observed{Timeout: true}},
	"Routes": {true, "the route decision the operating system reported for a destination",
		snapshot.Observed{Routes: []snapshot.Route{{Destination: "198.51.100.7", Family: "ipv4", Interface: "wlan0"}}},
		snapshot.Observed{Routes: []snapshot.Route{{Destination: "198.51.100.7", Family: "ipv4", Interface: "wg0"}}}},
	"ConnectCleartext": {false, "a transport observation recorded on a tunnel that already succeeded",
		snapshot.Observed{},
		snapshot.Observed{ConnectCleartext: true}},
}

// observedPass is one run that differs from another only in the evidence one
// check row recorded, so a comparison of two of them reports that field alone.
func observedPass(at time.Time, o snapshot.Observed) snapshot.Snapshot {
	return snapshot.Snapshot{
		Tool: snapshot.Tool{Version: "dev", OS: "linux", Arch: "amd64"}, Schema: snapshot.Schema,
		CreatedAt: stamp(at), OK: true,
		Target: &snapshot.Target{Raw: "example.com", Host: "example.com", Port: 443, Protocol: "tls+http"},
		Checks: []snapshot.Check{{
			ID: "dns", Name: "DNS", Status: snapshot.StatusPass, Ran: true, DurationMs: 1, Observed: &o,
		}},
		Diagnosis: snapshot.Diagnosis{Verdict: "ok"},
	}
}

func TestEveryObservedFieldIsClassified(t *testing.T) {
	typ := reflect.TypeOf(snapshot.Observed{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		entry, ok := observedClassification[field.Name]
		if !ok {
			t.Errorf("snapshot.Observed.%s has no environment/outcome decision. "+
				"Add one to observedClassification: a change in it either describes how this "+
				"machine reaches the network or describes what a check made of it, and incident "+
				"reports read that split.", field.Name)
			continue
		}
		if entry.why == "" {
			t.Errorf("snapshot.Observed.%s is classified without a reason", field.Name)
		}
		// The JSON tag is the name internal/compare builds the path from, so
		// requiring it in the emitted path ties this ledger to the spelling
		// production uses rather than to one repeated here.
		tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if tag == "" {
			t.Errorf("snapshot.Observed.%s has no JSON tag to key a comparison path on", field.Name)
			continue
		}
		at := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
		changes := compare.Snapshots(observedPass(at, entry.before), observedPass(at.Add(time.Second), entry.after)).Changes
		var named int
		for _, c := range changes {
			if c.Section != compare.SectionCheck || !strings.Contains(c.Path, ".observed."+tag) {
				continue
			}
			named++
			if got := environmental(c); got != entry.environment {
				t.Errorf("%s: %s classified environment=%v, want %v (%s)",
					field.Name, c.Path, got, entry.environment, entry.why)
			}
		}
		if named == 0 {
			t.Errorf("%s: comparing two runs that differ only in this field reported no change under "+
				".observed.%s, so this entry proves nothing. Fix the pair or the comparison.", field.Name, tag)
		}
	}
	for name := range observedClassification {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("observedClassification has a stale entry for snapshot.Observed.%s", name)
		}
	}
}
