package snapshot

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// A watch pass, as netdoc actually records one: the build that ran, the target
// and options it was started with, and the whole check graph it built from
// them, with one row per probe whatever that probe reported.
//
// failing flips only what a failure changes, which is what a later pass of the
// same session can differ in. Everything else is fixed before the first pass.
func watchPass(at string, failing bool) Snapshot {
	dns := Check{
		ID: "dns", Name: "DNS example.com", Status: StatusPass, Ran: true, DurationMs: 12,
		Observed: &Observed{Addresses: []string{"198.51.100.7"}, SelectedIP: "198.51.100.7"},
	}
	tcp := Check{
		ID: "target_tcp", Name: "TCP example.com:443", Deps: []string{"dns"},
		Status: StatusPass, Ran: true, DurationMs: 31,
		Observed: &Observed{SelectedIP: "198.51.100.7", Interface: "wlan0", SSID: "Office"},
	}
	s := Snapshot{
		Schema: Schema, CreatedAt: at, OK: true,
		Tool:   Tool{Version: "1.4.0", OS: "linux", Arch: "amd64"},
		Target: &Target{Raw: "example.com:443", Host: "example.com", Port: 443, Protocol: "tls+http", PortExplicit: true},
		Options: Options{
			ProbeTimeoutMs: 3000, PublicDNS: "1.1.1.1",
			Source: &Source{Interface: "wlan0", IPv4: "192.0.2.15", IPv6: "2001:db8::15"},
		},
		Diagnosis: Diagnosis{Verdict: "ok", Summary: "Everything checked out."},
	}
	if failing {
		tcp.Status, tcp.Cause, tcp.Detail = StatusFail, "timeout", "Connection timed out."
		s.OK = false
		s.Diagnosis = Diagnosis{
			Verdict: "network", Summary: "The target did not accept a connection.",
			Blamed: "target_tcp", FailedStage: "target_tcp",
			Findings: []Finding{{
				ID: "target_unreachable", Verdict: "network", Summary: "The target is unreachable.",
				Focus: "target_tcp", Confidence: ConfidenceHigh, Evidence: []string{"target_tcp"},
			}},
		}
	}
	s.Checks = []Check{dns, tcp}
	return s
}

// watchIncident is one failure as one watch session records it: four passes of
// the same graph, against the same target, from the same build.
func watchIncident() Snapshot {
	before := watchPass("2026-08-25T12:03:51Z", false)
	during := watchPass("2026-08-25T12:04:01Z", true)
	recovered := watchPass("2026-08-25T12:04:06Z", false)
	onset := watchPass("2026-08-25T12:03:56Z", true)
	onset.Incident = &Incident{
		StartedAt: "2026-08-25T12:03:56Z", EndedAt: "2026-08-25T12:04:06Z", Passes: 3,
		Before: &before, During: &during, Recovered: &recovered,
	}
	return onset
}

// decodeIncident is the external trust boundary, reached the way a hostile or
// hand edited file reaches it. Marshal rather than Encode builds the bytes,
// because Encode is one of the two readers under test and cannot be used to
// produce a file it is supposed to refuse.
func decodeIncident(t *testing.T, s Snapshot) error {
	t.Helper()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(data)
	return err
}

// The headline artifact: an incident whose nested states are each a perfectly
// valid snapshot of a completely different watch session. No single netdoc
// process could produce it, every part of it validates on its own, and before
// this rule existed the whole of it was accepted by both readers.
func TestIncidentValidationRejectsStatesFromAnotherWatchSession(t *testing.T) {
	s := watchIncident()
	other := watchPass("2026-08-25T12:03:51Z", false)
	other.Tool = Tool{Version: "0.9.1", OS: "windows", Arch: "arm64"}
	other.Target = &Target{Raw: "intranet.corp:8443", Host: "intranet.corp", Port: 8443, Protocol: "tls+http", PortExplicit: true}
	other.Options = Options{ProbeTimeoutMs: 500, PublicDNS: "9.9.9.9", PublicDNSAuto: true, Skip: []string{"pmtu"}}
	other.Checks = []Check{{ID: "iface", Name: "Interface", Status: StatusPass, Ran: true, DurationMs: 2}}
	s.Incident.Before = &other

	// Each half is a snapshot. It is only the claim that they are two states
	// of one incident that nothing can have observed.
	if err := Validate(other); err != nil {
		t.Fatalf("the foreign state is not individually valid, so it proves nothing: %v", err)
	}
	lifted := s
	lifted.Incident = nil
	if err := Validate(lifted); err != nil {
		t.Fatalf("the onset is not individually valid, so it proves nothing: %v", err)
	}

	if _, err := Encode(s); err == nil || !strings.Contains(err.Error(), "one watch session") {
		t.Errorf("Encode error = %v, want it to refuse states from another watch session", err)
	}
	if err := decodeIncident(t, s); err == nil || !strings.Contains(err.Error(), "one watch session") {
		t.Errorf("Decode error = %v, want it to refuse states from another watch session", err)
	}
}

// A watch session exists to record change, so the states around a failure are
// expected to disagree about almost everything a probe measured. This is the
// other half of the rule above: the evidence moves, the session does not.
func TestIncidentAcceptsRealEvidenceMovingDuringTheFailure(t *testing.T) {
	s := watchIncident()
	before := s.Incident.Before
	before.Checks[0].Observed = &Observed{Addresses: []string{"198.51.100.7", "198.51.100.8"}, SelectedIP: "198.51.100.8"}
	before.Checks[1].Observed = &Observed{
		SelectedIP: "198.51.100.8", Interface: "eth0", SourceIP: "192.0.2.15",
		Routes: []Route{{Destination: "198.51.100.8", Family: "ipv4", Interface: "eth0", Gateway: "192.0.2.1"}},
	}
	before.Checks[0].Status, before.Checks[0].DurationMs = StatusWarn, 4001
	before.Diagnosis = Diagnosis{Verdict: "degraded", Summary: "Name resolution was slow."}

	during := s.Incident.During
	during.Checks[0].Observed = &Observed{DNSNotFound: true}
	during.Checks[0].Status, during.Checks[0].Cause = StatusFail, "dns_nxdomain"
	during.Checks[1].Status, during.Checks[1].Cause = StatusSkip, ""
	during.Checks[1].Observed = nil
	during.Diagnosis = Diagnosis{
		Verdict: "dns", Summary: "The name no longer resolves.", Blamed: "dns", FailedStage: "dns",
		Findings: []Finding{{ID: "dns_broken", Verdict: "dns", Summary: "Resolution failed.", Confidence: ConfidenceMedium, Evidence: []string{"dns"}}},
	}

	recovered := s.Incident.Recovered
	recovered.Checks[1].Observed = &Observed{SelectedIP: "203.0.113.4", Interface: "wlan0", SSID: "Cafe", Timeout: false}
	recovered.Checks[1].DurationMs = 7

	if _, err := Encode(s); err != nil {
		t.Fatalf("Encode refused an incident whose evidence moved: %v", err)
	}
	if err := decodeIncident(t, s); err != nil {
		t.Fatalf("Decode refused an incident whose evidence moved: %v", err)
	}
}

// The ledger. Every field of the structs that make up a watch pass is
// classified once, and the classification is a claim this file then checks
// against the validator rather than taking on trust.
//
// identity is the run settings one watch session fixes before its first pass.
// Each mutation is applied to the state before the onset, which is otherwise
// an ordinary pass of the same session, and each must make the artifact
// unreadable: two passes of one session cannot disagree about any of these.
var identity = map[string]func(*Snapshot){
	// The build. One session is one process, so the version, the operating
	// system and the architecture are whatever it was compiled and started as.
	"Snapshot.Tool": func(s *Snapshot) { s.Tool.Version = "0.9.1" },
	"Tool.Version":  func(s *Snapshot) { s.Tool.Version = "0.9.1" },
	"Tool.OS":       func(s *Snapshot) { s.Tool.OS = "windows" },
	"Tool.Arch":     func(s *Snapshot) { s.Tool.Arch = "arm64" },
	// The endpoint. Switching targets inside the TUI rebuilds the probes and
	// throws the timeline away, so even a respelling of the same endpoint is a
	// new session and never a later pass of this one.
	"Snapshot.Target":     func(s *Snapshot) { s.Target.Host = "elsewhere.example.net" },
	"Target.Raw":          func(s *Snapshot) { s.Target.Raw = "example.com" },
	"Target.Host":         func(s *Snapshot) { s.Target.Host = "elsewhere.example.net" },
	"Target.IP":           func(s *Snapshot) { s.Target.IP = "198.51.100.7" },
	"Target.Port":         func(s *Snapshot) { s.Target.Port = 8443 },
	"Target.Protocol":     func(s *Snapshot) { s.Target.Protocol = "tcp" },
	"Target.PortExplicit": func(s *Snapshot) { s.Target.PortExplicit = false },
	// The run settings. All of them come from the command line and none of
	// them can be changed while the session runs.
	"Snapshot.Options":       func(s *Snapshot) { s.Options.ProbeTimeoutMs = 500 },
	"Options.ProbeTimeoutMs": func(s *Snapshot) { s.Options.ProbeTimeoutMs = 500 },
	"Options.PublicDNS":      func(s *Snapshot) { s.Options.PublicDNS = "9.9.9.9" },
	"Options.PublicDNSAuto":  func(s *Snapshot) { s.Options.PublicDNSAuto = true },
	"Options.Check":          func(s *Snapshot) { s.Options.Check = []string{"dns"} },
	"Options.Skip":           func(s *Snapshot) { s.Options.Skip = []string{"pmtu"} },
	"Options.Source":         func(s *Snapshot) { s.Options.Source = nil },
	// The local binding, resolved once at startup from -iface and reused by
	// every probe of every pass.
	"Source.Interface": func(s *Snapshot) { s.Options.Source.Interface = "eth9" },
	"Source.IPv4":      func(s *Snapshot) { s.Options.Source.IPv4 = "203.0.113.9" },
	"Source.IPv6":      func(s *Snapshot) { s.Options.Source.IPv6 = "2001:db8::99" },
	// The check graph. It is built once from the target and the options, and
	// every pass records every row it built, including the rows that were
	// skipped or never reported, so the shape of the list is a setting and not
	// a result.
	"Snapshot.Checks": func(s *Snapshot) { s.Checks = s.Checks[:1] },
	"Check.ID":        func(s *Snapshot) { s.Checks[1].ID = "target_tcp_v2" },
	"Check.Name":      func(s *Snapshot) { s.Checks[1].Name = "TCP somewhere.else:443" },
	"Check.Deps":      func(s *Snapshot) { s.Checks[1].Deps = nil },
}

// varies is the other half: what a watch session is running in order to see
// move. Each mutation must leave the artifact readable, because an incident
// whose evidence could not change would record nothing worth recording.
var varies = map[string]func(*Snapshot){
	"Snapshot.CreatedAt": func(s *Snapshot) { s.CreatedAt = "2026-08-25T12:03:46Z" },
	"Snapshot.Diagnosis": func(s *Snapshot) {
		s.Diagnosis = Diagnosis{Verdict: "degraded", Summary: "Name resolution was slow."}
	},
	"Check.Status": func(s *Snapshot) { s.Checks[0].Status = StatusWarn },
	"Check.Cause":  func(s *Snapshot) { s.Checks[0].Cause = "dns_slow" },
	"Check.CauseFamily": func(s *Snapshot) {
		s.Checks[0].Cause, s.Checks[0].CauseFamily = "dns_slow", "ipv6"
	},
	"Check.Ran":        func(s *Snapshot) { s.Checks[0].Ran = false },
	"Check.DurationMs": func(s *Snapshot) { s.Checks[0].DurationMs = 4001 },
	"Check.Detail":     func(s *Snapshot) { s.Checks[0].Detail = "Resolution took four seconds." },
	"Check.Fix":        func(s *Snapshot) { s.Checks[0].Fix = "Try another resolver." },
	"Check.Observed": func(s *Snapshot) {
		s.Checks[0].Observed = &Observed{Addresses: []string{"203.0.113.4"}, SelectedIP: "203.0.113.4"}
	},
	"Check.Derived": func(s *Snapshot) { s.Checks[0].Derived = &Derived{AnswerComparison: AnswerComparisonAgree} },
}

// elsewhere is the third answer a field can have: held identical, or held to a
// shape, by a rule this one would duplicate. Naming the rule is the point, so
// that adding a field here is a decision and not an escape hatch.
var elsewhere = map[string]string{
	"Snapshot.Schema":    "the nested schema rule: every state carries this build's schema",
	"Snapshot.OK":        "the incident phase rule: the onset and the during state failed, the before and recovered states did not",
	"Snapshot.Redaction": "the incident redaction rule: every state is sanitized or none is",
	"Snapshot.Incident":  "the one run rule: a nested state carries no incident of its own",
}

// watchPassTypes are the structs a watch pass is made of, minus the evidence
// types hanging off a check row. Everything a probe measured is under
// Check.Observed and Check.Derived, and those are classified whole: adding a
// reading to Observed adds an observation, never a run setting.
func watchPassTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(Snapshot{}), reflect.TypeOf(Tool{}), reflect.TypeOf(Target{}),
		reflect.TypeOf(Options{}), reflect.TypeOf(Source{}), reflect.TypeOf(Check{}),
	}
}

// A field that is neither session identity nor free to move is a field nobody
// decided about, and the next one added would default to whichever answer the
// validator happened to give. This fails until someone says which it is.
func TestEveryWatchPassFieldIsClassified(t *testing.T) {
	known := map[string]bool{}
	for _, typ := range watchPassTypes() {
		for i := range typ.NumField() {
			key := typ.Name() + "." + typ.Field(i).Name
			known[key] = true
			_, isIdentity := identity[key]
			_, isVarying := varies[key]
			_, isElsewhere := elsewhere[key]
			switch {
			case isIdentity && isVarying, isIdentity && isElsewhere, isVarying && isElsewhere:
				t.Errorf("%s is classified more than once", key)
			case !isIdentity && !isVarying && !isElsewhere:
				t.Errorf("%s is unclassified: decide whether it defines watch session identity, is free to move between passes, or is held by another incident rule", key)
			}
		}
	}
	for key := range identity {
		if !known[key] {
			t.Errorf("the watch session ledger classifies %s, which is no longer a field", key)
		}
	}
	for key := range varies {
		if !known[key] {
			t.Errorf("the watch session ledger classifies %s, which is no longer a field", key)
		}
	}
	for key := range elsewhere {
		if !known[key] {
			t.Errorf("the watch session ledger classifies %s, which is no longer a field", key)
		}
	}
}

// The behavioral half of the ledger. Each identity claim is checked against
// both readers, and each mutated state is checked to be a valid snapshot on
// its own first, so a rejection proves the session rule fired and not that the
// mutation broke the state.
func TestEveryIdentityFieldIsEnforced(t *testing.T) {
	for name, mutate := range identity {
		t.Run(name, func(t *testing.T) {
			s := watchIncident()
			mutate(s.Incident.Before)
			standalone := *s.Incident.Before
			if err := Validate(standalone); err != nil {
				t.Fatalf("the mutated state is not a valid snapshot on its own, so this proves nothing: %v", err)
			}
			if _, err := Encode(s); err == nil || !strings.Contains(err.Error(), "one watch session") {
				t.Errorf("Encode error = %v, want it to refuse a moved %s", err, name)
			}
			if err := decodeIncident(t, s); err == nil || !strings.Contains(err.Error(), "one watch session") {
				t.Errorf("Decode error = %v, want it to refuse a moved %s", err, name)
			}
		})
	}
}

func TestEveryVaryingFieldStaysAccepted(t *testing.T) {
	for name, mutate := range varies {
		t.Run(name, func(t *testing.T) {
			s := watchIncident()
			mutate(s.Incident.Before)
			if _, err := Encode(s); err != nil {
				t.Errorf("Encode refused a moved %s: %v", name, err)
			}
			if err := decodeIncident(t, s); err != nil {
				t.Errorf("Decode refused a moved %s: %v", name, err)
			}
		})
	}
}

// Support redaction rewrites hostnames, addresses and interface names, and it
// rewrites them through one mapping for the whole artifact. A sanitized
// incident therefore still says its states came from one session, which is the
// property that would break if each nested state were sanitized on its own.
func TestSanitizedIncidentStaysOneWatchSession(t *testing.T) {
	data, err := Encode(SanitizeForSupport(watchIncident()))
	if err != nil {
		t.Fatalf("Encode sanitized incident: %v", err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode sanitized incident: %v", err)
	}
	for name, state := range map[string]*Snapshot{
		"before": got.Incident.Before, "during": got.Incident.During, "recovered": got.Incident.Recovered,
	} {
		if reason := WatchSessionMismatch(got, *state); reason != "" {
			t.Errorf("sanitizing moved the %s state's %s", name, reason)
		}
	}
}

// A snapshot with no target is a generic run, and the absence is part of the
// session's identity: a session watching an endpoint and a session watching
// nothing in particular are two sessions, whichever way round the states sit.
func TestWatchSessionMismatchReadsAnAbsentTargetAsIdentity(t *testing.T) {
	targeted := watchPass("2026-08-25T12:03:51Z", false)
	generic := targeted
	generic.Target = nil
	if WatchSessionMismatch(targeted, generic) != "target" || WatchSessionMismatch(generic, targeted) != "target" {
		t.Errorf("an absent target compares as the same session as a present one")
	}
	if reason := WatchSessionMismatch(generic, generic); reason != "" {
		t.Errorf("two generic runs of one session differ by %q", reason)
	}
}
