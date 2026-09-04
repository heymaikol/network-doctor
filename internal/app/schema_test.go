// Guards for schema/report-v1.schema.json, the published JSON Schema for the
// ordinary `netdoc --json` report.
//
// A static schema file is worth nothing on its own: it describes a producer
// that keeps moving, and nothing in a JSON document tells you it drifted. So
// three separate things are checked here, because each one catches a different
// way the file can go stale.
//
// The first is the obvious one, and the weakest: real reports validate. They
// are produced the way a user produces them, by running the CLI and by calling
// buildReport, never from hand-written JSON fixtures that would drift away from
// the structs on their own.
//
// The second is the reverse direction, and it is the one that matters for
// keeping the file honest. The published schema deliberately permits additional
// properties (the report is additive within v1, and a consumer pinned to this
// file has to keep validating against a newer netdoc), so a field added to
// internal/report and never written down here would sail through every
// validation above. Reflection over the report types closes that hole: every
// serialized field must appear in the schema, with a requiredness that matches
// its `omitempty`.
//
// The third is the vocabularies. The schema freezes an enum only where the
// repository maintains a closed public one, and each of those is compared
// against the Go declarations it came from rather than a list copied by hand,
// so adding a Status, a Verdict, an EvidenceKind or a RouteReason without
// updating the schema fails here instead of shipping.

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
)

const (
	// reportSchemaPath is a constant so reading it needs no gosec exemption.
	reportSchemaPath = "../../schema/report-v1.schema.json"
	// diagnosticDir holds the authoritative declarations of every closed
	// vocabulary the schema publishes.
	diagnosticDir = "../diagnostic"
)

// compileReportSchema parses and compiles the published file, which is what
// makes malformed schema syntax impossible to land: a broken $ref, an unknown
// keyword shape or invalid JSON fails before any report is validated.
func compileReportSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(reportSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s is not valid JSON: %v", reportSchemaPath, err)
	}
	c := jsonschema.NewCompiler()
	const id = "https://raw.githubusercontent.com/heymaikol/network-doctor/main/schema/report-v1.schema.json"
	if err := c.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(id)
	if err != nil {
		t.Fatalf("compiling %s: %v", reportSchemaPath, err)
	}
	return sch
}

// validateJSON runs one serialized report against the schema.
func validateJSON(sch *jsonschema.Schema, blob []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(blob))
	if err != nil {
		return err
	}
	return sch.Validate(inst)
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// reportScenario is one run's probe state, named so a validation failure says
// which shape of report broke.
type reportScenario struct {
	name    string
	target  *diagnostic.Target
	probes  []diagnostic.Probe
	results map[diagnostic.ProbeID]diagnostic.ProbeResult
	// watch marks the scenario that carries the field only `--json --watch`
	// adds, so the streamed line is covered by the same schema as the one-shot
	// document it is otherwise identical to.
	watch bool
}

func probe(id diagnostic.ProbeID, name string) diagnostic.Probe {
	return diagnostic.Probe{ID: id, Name: name}
}

// reportScenarios are the runs the schema has to describe. Between them they
// have to reach every nested structure the report can carry, which
// TestPublishedReportsValidateAgainstSchema asserts rather than assumes.
func reportScenarios() []reportScenario {
	target := &diagnostic.Target{Host: "example.com", Port: 443, Proto: diagnostic.ProtoTLSHTTP}
	chain := []diagnostic.Probe{
		probe(diagnostic.ProbeIface, "Interface"),
		probe(diagnostic.ProbeInternet, "Internet"),
		probe(diagnostic.ProbeDNS, "DNS example.com"),
		probe(diagnostic.ProbeDNSPublic, "Public DNS"),
		probe(diagnostic.ProbeTargetTCP, "TCP example.com:443"),
		probe(diagnostic.ProbeTLS, "TLS"),
	}
	metric := 100

	return []reportScenario{
		{
			// Generic mode: no target at all, so the report carries an explicit
			// null rather than omitting the key.
			name:   "generic no target",
			target: nil,
			probes: []diagnostic.Probe{probe(diagnostic.ProbeIface, "Interface"), probe(diagnostic.ProbeInternet, "Internet")},
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeIface:    {Status: diagnostic.StatusPass, Dur: 2 * time.Millisecond, Detail: "interface wlan0 is up"},
				diagnostic.ProbeInternet: {Status: diagnostic.StatusPass, Dur: 30 * time.Millisecond, Detail: "direct egress works"},
			},
		},
		{
			// The healthy one-shot report, which is what most consumers see
			// most of the time: no findings, no failed stage, minimal rows.
			name:   "healthy target",
			target: target,
			probes: chain,
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeIface:     {Status: diagnostic.StatusPass, Dur: time.Millisecond, Detail: "interface wlan0 is up"},
				diagnostic.ProbeInternet:  {Status: diagnostic.StatusPass, Dur: 30 * time.Millisecond, Detail: "direct egress works"},
				diagnostic.ProbeDNS:       {Status: diagnostic.StatusPass, Dur: 12 * time.Millisecond, Detail: "resolved", Addrs: []net.IP{net.ParseIP("192.0.2.10")}},
				diagnostic.ProbeDNSPublic: {Status: diagnostic.StatusPass, Dur: 14 * time.Millisecond, Detail: "resolved", Addrs: []net.IP{net.ParseIP("192.0.2.10")}},
				diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusPass, Dur: 20 * time.Millisecond, Detail: "connected", SelectedIP: net.ParseIP("192.0.2.10")},
				diagnostic.ProbeTLS:       {Status: diagnostic.StatusPass, Dur: 40 * time.Millisecond, Detail: "TLS handshake OK"},
			},
		},
		{
			// A watch pass. Identical to the report above except for the ts the
			// stream adds, which is the whole of what watch mode changes.
			name:   "watch pass",
			target: target,
			watch:  true,
			probes: []diagnostic.Probe{probe(diagnostic.ProbeIface, "Interface")},
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeIface: {Status: diagnostic.StatusPass, Dur: time.Millisecond, Detail: "interface wlan0 is up"},
			},
		},
		{
			// Every status a row can carry at once, including the INCOMPLETE
			// that no probe returns: the TLS row is in the check set and absent
			// from the results, which is what an interrupted run leaves behind.
			name:   "every status",
			target: target,
			probes: chain,
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeIface:     {Status: diagnostic.StatusPass, Dur: time.Millisecond, Detail: "interface wlan0 is up"},
				diagnostic.ProbeInternet:  {Status: diagnostic.StatusWarn, Dur: 900 * time.Millisecond, Detail: "slow", Fix: "Check the uplink."},
				diagnostic.ProbeDNS:       {Status: diagnostic.StatusFail, Dur: 4 * time.Second, Detail: "timed out", Cause: diagnostic.DNSCauseTimeout},
				diagnostic.ProbeDNSPublic: {Status: diagnostic.StatusSkip, Detail: "skipped"},
				diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusNA, Detail: "not applicable"},
			},
		},
		{
			// A captive portal, which is the run that carries a portal object,
			// per-attempt evidence, address families, and a remediation with an
			// argv command under its finding.
			name:   "captive portal with attempts and routes",
			target: target,
			probes: chain,
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeIface: {
					Status: diagnostic.StatusPass, Dur: time.Millisecond, Detail: "interface wlan0 is up",
					Iface: "wlan0", Network: "Cafe WiFi", Source: net.ParseIP("192.0.2.55"),
					Routes: []diagnostic.RouteDecision{{
						Destination: net.ParseIP("198.51.100.1"), Family: "ipv4", Iface: "wlan0",
						Gateway: net.ParseIP("192.0.2.1"), Source: net.ParseIP("192.0.2.55"),
						Table: "main", TableKnown: true, MTU: 1500, MetricKnown: true, Metric: metric,
						Tunnel: diagnostic.TunnelDirect, Reason: diagnostic.RouteReasonDefault,
						Competing: []diagnostic.CompetingRoute{{Iface: "eth0", Metric: 200}},
					}},
				},
				diagnostic.ProbeInternet: {
					Status: diagnostic.StatusFail, Dur: 2 * time.Second, Detail: "intercepted",
					Portal:   &diagnostic.Portal{RedirectURL: "https://portal.example.net/login"},
					Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyUnreachable, IPv6: diagnostic.FamilyUnreachable},
					Attempts: []diagnostic.Attempt{
						{IP: net.ParseIP("198.51.100.1"), Dur: 300 * time.Microsecond, Err: os.ErrDeadlineExceeded, Cause: diagnostic.ConnectionCauseTimeout},
						{IP: net.ParseIP("198.51.100.2"), Dur: 2 * time.Second, Aborted: true},
					},
				},
				diagnostic.ProbeDNS:       {Status: diagnostic.StatusSkip, Detail: "skipped"},
				diagnostic.ProbeDNSPublic: {Status: diagnostic.StatusSkip, Detail: "skipped"},
				diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusSkip, Detail: "skipped"},
				diagnostic.ProbeTLS:       {Status: diagnostic.StatusSkip, Detail: "skipped"},
			},
		},
		{
			// Nothing off this machine works and the kernel says why, which is
			// the run whose finding carries a remediation with steps and an
			// argv command under it.
			name:   "offline with a route cause",
			target: target,
			probes: chain,
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeIface: {Status: diagnostic.StatusPass, Dur: time.Millisecond, Detail: "interface wlan0 is up"},
				diagnostic.ProbeInternet: {
					Status: diagnostic.StatusFail, Dur: 2 * time.Second, Detail: "no egress",
					Cause: diagnostic.RouteCauseNoDefaultRoute,
					Routes: []diagnostic.RouteDecision{{
						Destination: net.ParseIP("198.51.100.1"), Family: "ipv4",
						Unreachable: true, Reason: diagnostic.RouteReasonNoRoute,
					}},
				},
				diagnostic.ProbeDNS:       {Status: diagnostic.StatusFail, Dur: 4 * time.Second, Detail: "timed out", Cause: diagnostic.DNSCauseTimeout},
				diagnostic.ProbeDNSPublic: {Status: diagnostic.StatusFail, Dur: 4 * time.Second, Detail: "timed out", Cause: diagnostic.DNSCauseTimeout},
				diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusSkip, Detail: "skipped"},
				diagnostic.ProbeTLS:       {Status: diagnostic.StatusSkip, Detail: "skipped"},
			},
		},
		{
			// Two resolvers answering with different networks: the run that
			// produces a counterfactual, with its alternatives and their own
			// nested causal evidence.
			name:   "dns disagreement counterfactual",
			target: target,
			probes: chain,
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeIface:    {Status: diagnostic.StatusPass, Dur: time.Millisecond, Detail: "interface wlan0 is up"},
				diagnostic.ProbeInternet: {Status: diagnostic.StatusPass, Dur: 30 * time.Millisecond, Detail: "direct egress works"},
				diagnostic.ProbeDNS: {
					Status: diagnostic.StatusPass, Dur: 12 * time.Millisecond, Detail: "resolved",
					Addrs: []net.IP{net.ParseIP("10.1.2.3")}, ResolverTargets: []string{"127.0.0.53:53"},
				},
				diagnostic.ProbeDNSPublic: {
					Status: diagnostic.StatusPass, Dur: 14 * time.Millisecond, Detail: "resolved",
					Addrs: []net.IP{net.ParseIP("192.0.2.10")}, ResolverTargets: []string{"8.8.8.8:53"},
				},
				diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusPass, Dur: 20 * time.Millisecond, Detail: "connected", SelectedIP: net.ParseIP("10.1.2.3")},
				diagnostic.ProbeTLS:       {Status: diagnostic.StatusPass, Dur: 40 * time.Millisecond, Detail: "TLS handshake OK"},
			},
		},
		{
			// One address family working while the other does not, which is the
			// run that carries an address-family counterfactual and the
			// address_families object on two rows at once.
			name:   "address family split",
			target: target,
			probes: chain,
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
				diagnostic.ProbeIface: {Status: diagnostic.StatusPass, Dur: time.Millisecond, Detail: "interface wlan0 is up"},
				diagnostic.ProbeInternet: {
					Status: diagnostic.StatusPass, Dur: 30 * time.Millisecond, Detail: "direct egress works",
					Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyReachable, IPv6: diagnostic.FamilyReachable},
				},
				diagnostic.ProbeDNS: {
					Status: diagnostic.StatusPass, Dur: 12 * time.Millisecond, Detail: "resolved",
					Addrs: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")},
				},
				diagnostic.ProbeDNSPublic: {
					Status: diagnostic.StatusPass, Dur: 14 * time.Millisecond, Detail: "resolved",
					Addrs: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")},
				},
				diagnostic.ProbeTargetTCP: {
					Status: diagnostic.StatusWarn, Dur: 20 * time.Millisecond, Detail: "connected over IPv4",
					SelectedIP: net.ParseIP("192.0.2.10"),
					Families:   &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyReachable, IPv6: diagnostic.FamilyUnreachable},
					Attempts: []diagnostic.Attempt{
						{IP: net.ParseIP("2001:db8::10"), Dur: time.Second, Err: os.ErrDeadlineExceeded, Cause: diagnostic.ConnectionCauseUnreachable},
						{IP: net.ParseIP("192.0.2.10"), Dur: 20 * time.Millisecond},
					},
				},
				diagnostic.ProbeTLS: {Status: diagnostic.StatusPass, Dur: 40 * time.Millisecond, Detail: "TLS handshake OK"},
			},
		},
		{
			// Nothing reported at all: the shape a run interrupted before its
			// first probe answered leaves behind, where every row is INCOMPLETE.
			name:    "interrupted before any result",
			target:  target,
			probes:  chain,
			results: map[diagnostic.ProbeID]diagnostic.ProbeResult{},
		},
	}
}

// TestPublishedReportsValidateAgainstSchema runs every scenario through the
// real report builder and the real encoder, then insists the set of scenarios
// actually exercised the nested structures rather than only the easy top level.
func TestPublishedReportsValidateAgainstSchema(t *testing.T) {
	sch := compileReportSchema(t)
	covered := map[string]bool{}
	statuses := map[string]bool{}

	for _, sc := range reportScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			rep := buildReport(sc.target, sc.probes, sc.results)
			if sc.watch {
				// Set exactly where runHeadless sets it, in the same format.
				rep.Ts = time.Now().UTC().Format(time.RFC3339)
				covered["ts"] = true
			}
			blob := mustMarshal(t, rep)
			if err := validateJSON(sch, blob); err != nil {
				t.Fatalf("report does not validate: %v\n%s", err, blob)
			}
			recordCoverage(rep, covered, statuses)
		})
	}

	// Every status the format allows has to have been produced by a real run
	// above, INCOMPLETE included, or the acceptance below proves nothing.
	for _, want := range []string{"PASS", "WARN", "FAIL", "SKIP", "N/A", report.StatusIncomplete} {
		if !statuses[want] {
			t.Errorf("no scenario produced a %s row, so the schema's acceptance of it is untested", want)
		}
	}
	for _, want := range []string{
		"ts", "target_null", "failed_stage", "findings", "confidence", "evidence", "causal_evidence",
		"counterfactual", "alternative_evidence", "remediation", "remediation_command", "remediation_steps",
		"address_families", "portal", "attempts", "attempt_error", "attempt_aborted", "addrs",
		"resolver_targets", "routes", "route_metric", "route_competing", "route_tunnel", "route_reason", "cause", "fix",
	} {
		if !covered[want] {
			t.Errorf("no scenario produced %s, so that part of the schema is unvalidated", want)
		}
	}
}

// recordCoverage notes which optional structures a report actually carried, so
// the suite can prove it validated a rich document and not only a healthy one.
func recordCoverage(rep report.Report, covered, statuses map[string]bool) {
	if rep.Target == nil {
		covered["target_null"] = true
	}
	if rep.FailedStage != "" {
		covered["failed_stage"] = true
	}
	for _, c := range rep.Checks {
		statuses[c.Status] = true
		for key, present := range map[string]bool{
			"cause": c.Cause != "", "fix": c.Fix != "", "addrs": len(c.Addrs) > 0,
			"resolver_targets": len(c.ResolverTargets) > 0, "address_families": c.Families != nil,
			"portal": c.Portal != nil, "attempts": len(c.Attempts) > 0, "routes": len(c.Routes) > 0,
		} {
			covered[key] = covered[key] || present
		}
		for _, a := range c.Attempts {
			covered["attempt_error"] = covered["attempt_error"] || a.Err != ""
			covered["attempt_aborted"] = covered["attempt_aborted"] || a.Aborted
		}
		for _, r := range c.Routes {
			covered["route_metric"] = covered["route_metric"] || r.Metric != nil
			covered["route_competing"] = covered["route_competing"] || len(r.Competing) > 0
			covered["route_tunnel"] = covered["route_tunnel"] || r.Tunnel != ""
			covered["route_reason"] = covered["route_reason"] || r.Reason != ""
		}
	}
	for _, f := range rep.Findings {
		covered["findings"] = true
		covered["confidence"] = covered["confidence"] || f.Confidence != ""
		covered["evidence"] = covered["evidence"] || len(f.Evidence) > 0
		covered["causal_evidence"] = covered["causal_evidence"] || len(f.CausalEvidence) > 0
		if f.Counterfactual != nil {
			covered["counterfactual"] = true
			for _, alternative := range f.Counterfactual.Alternatives {
				covered["alternative_evidence"] = covered["alternative_evidence"] || len(alternative.Evidence) > 0
			}
		}
		if f.Remediation != nil {
			covered["remediation"] = true
			covered["remediation_command"] = covered["remediation_command"] || len(f.Remediation.Command) > 0
			covered["remediation_steps"] = covered["remediation_steps"] || len(f.Remediation.Steps) > 0
		}
	}
}

// TestCommandLineJSONOutputValidatesAgainstSchema validates the bytes a user
// actually gets, indentation and trailing newline included, rather than a
// report marshalled a second way inside a test.
func TestCommandLineJSONOutputValidatesAgainstSchema(t *testing.T) {
	sch := compileReportSchema(t)
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			status := diagnostic.StatusPass
			if p.ID == diagnostic.ProbeTargetTCP {
				status = diagnostic.StatusFail
			}
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: status, Dur: time.Millisecond, Detail: "detail"}
		}
		return results
	}

	for _, args := range [][]string{
		{"--json", "example.com:443"},
		{"--json"},
		{"--json", "--check", "iface", "example.com"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			run(args, &stdout, &stderr)
			if stdout.Len() == 0 {
				t.Fatalf("no report on stdout; stderr: %s", stderr.String())
			}
			if err := validateJSON(sch, stdout.Bytes()); err != nil {
				t.Fatalf("CLI output does not validate: %v\n%s", err, stdout.String())
			}
		})
	}
}

// TestSchemaRejectsMalformedReports is the other half of the contract: a schema
// that accepts everything proves nothing about the documents that pass it.
func TestSchemaRejectsMalformedReports(t *testing.T) {
	sch := compileReportSchema(t)
	base := map[string]any{
		"version": "1.2.3",
		"target":  map[string]any{"host": "example.com", "port": 443, "protocol": "tls+http"},
		"checks": []any{map[string]any{
			"id": "iface", "name": "Interface", "status": "PASS", "ms": 1, "detail": "up",
		}},
		"summary": "All checks passed.",
		"verdict": "ok",
		"ok":      true,
	}
	if err := validateJSON(sch, mustMarshal(t, base)); err != nil {
		t.Fatalf("the baseline document must validate, or the mutations below prove nothing: %v", err)
	}

	mutate := func(f func(m map[string]any)) []byte {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		f(m)
		return mustMarshal(t, m)
	}
	check := func(m map[string]any) map[string]any {
		row := map[string]any{}
		maps.Copy(row, base["checks"].([]any)[0].(map[string]any))
		maps.Copy(row, m)
		return row
	}

	for _, tt := range []struct {
		name string
		blob []byte
	}{
		{"missing ok", mutate(func(m map[string]any) { delete(m, "ok") })},
		{"missing checks", mutate(func(m map[string]any) { delete(m, "checks") })},
		{"missing target key", mutate(func(m map[string]any) { delete(m, "target") })},
		{"ok as a string", mutate(func(m map[string]any) { m["ok"] = "true" })},
		{"checks as an object", mutate(func(m map[string]any) { m["checks"] = map[string]any{} })},
		{"unknown verdict", mutate(func(m map[string]any) { m["verdict"] = "broken" })},
		{"port out of range", mutate(func(m map[string]any) {
			m["target"] = map[string]any{"host": "example.com", "port": 70000, "protocol": "tls+http"}
		})},
		{"unknown protocol", mutate(func(m map[string]any) {
			m["target"] = map[string]any{"host": "example.com", "port": 443, "protocol": "gopher"}
		})},
		// The status vocabulary is the one consumers branch on first, so an
		// invented value has to be rejected outright rather than tolerated as
		// "some new status".
		{"unknown check status", mutate(func(m map[string]any) {
			m["checks"] = []any{check(map[string]any{"status": "MAYBE"})}
		})},
		{"lowercase check status", mutate(func(m map[string]any) {
			m["checks"] = []any{check(map[string]any{"status": "pass"})}
		})},
		{"check missing status", mutate(func(m map[string]any) {
			row := check(nil)
			delete(row, "status")
			m["checks"] = []any{row}
		})},
		{"ms as a string", mutate(func(m map[string]any) {
			m["checks"] = []any{check(map[string]any{"ms": "12"})}
		})},
		{"unknown address family state", mutate(func(m map[string]any) {
			m["checks"] = []any{check(map[string]any{"address_families": map[string]any{"ipv4": "maybe"}})}
		})},
		{"unknown confidence", mutate(func(m map[string]any) {
			m["findings"] = []any{map[string]any{"id": "offline", "confidence": "certain"}}
		})},
		{"unknown evidence kind", mutate(func(m map[string]any) {
			m["findings"] = []any{map[string]any{"id": "offline", "causal_evidence": []any{
				map[string]any{"kind": "suggests", "check": "iface"},
			}}}
		})},
		{"finding without an id", mutate(func(m map[string]any) {
			m["findings"] = []any{map[string]any{"focus": "iface"}}
		})},
		{"remediation without an action", mutate(func(m map[string]any) {
			m["findings"] = []any{map[string]any{"id": "offline", "remediation": map[string]any{"id": "check_local_path"}}}
		})},
		{"remediation command as a shell string", mutate(func(m map[string]any) {
			m["findings"] = []any{map[string]any{"id": "offline", "remediation": map[string]any{
				"id": "check_local_path", "action": "Look at the routes", "command": "ip route",
			}}}
		})},
		{"unknown route reason", mutate(func(m map[string]any) {
			m["checks"] = []any{check(map[string]any{"routes": []any{
				map[string]any{"destination": "198.51.100.1", "reason": "vibes"},
			}})}
		})},
		{"route without a destination", mutate(func(m map[string]any) {
			m["checks"] = []any{check(map[string]any{"routes": []any{map[string]any{"interface": "wlan0"}}})}
		})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateJSON(sch, tt.blob); err == nil {
				t.Errorf("schema accepted a malformed report: %s", tt.blob)
			}
		})
	}
}

// TestSchemaDescribesEverySerializedField walks the report types the way the
// encoder does and insists the schema documents each field. The published file
// permits additional properties on purpose, so nothing else in this package
// would notice a field added to internal/report and never written down.
func TestSchemaDescribesEverySerializedField(t *testing.T) {
	defs := schemaDefs(t)
	seen := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt.Name()] {
			return
		}
		seen[rt.Name()] = true
		def, ok := defs[rt.Name()].(map[string]any)
		if !ok {
			t.Errorf("$defs has no %q, so that type is undescribed", rt.Name())
			return
		}
		properties, _ := def["properties"].(map[string]any)
		var required []string
		// An object every one of whose fields carries omitempty has no required
		// list at all, which is a legal schema and not a missing one.
		names, _ := def["required"].([]any)
		for _, name := range names {
			required = append(required, name.(string))
		}
		documented := map[string]bool{}
		for i := range rt.NumField() {
			field := rt.Field(i)
			tag := field.Tag.Get("json")
			name, options, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				t.Errorf("%s.%s has no json tag, so what it serializes as is not knowable here", rt.Name(), field.Name)
				continue
			}
			documented[name] = true
			if _, ok := properties[name]; !ok {
				t.Errorf("%s.%s serializes as %q and the schema does not describe it", rt.Name(), field.Name, name)
			}
			// omitempty is exactly the producer's own statement about whether a
			// key is always written, so the schema's required list has to agree
			// with it field for field.
			optional := strings.Contains(options, "omitempty")
			if got := slices.Contains(required, name); got == optional {
				t.Errorf("%s.%s serializes as %q with omitempty=%v but the schema lists it required=%v",
					rt.Name(), field.Name, name, optional, got)
			}
			walk(field.Type)
		}
		for name := range properties {
			if !documented[name] {
				t.Errorf("the schema describes %s.%s, which nothing serializes any more", rt.Name(), name)
			}
		}
	}
	walk(reflect.TypeOf(report.Report{}))

	// The audit is only worth as much as its reach, so the types it had to
	// visit are named rather than left to the walk to discover.
	for _, name := range []string{
		"Report", "Target", "Check", "Finding", "CausalEvidence", "Counterfactual",
		"CounterfactualAlternative", "Remediation", "Families", "Portal", "Attempt",
		"Route", "CompetingRoute",
	} {
		if !seen[name] {
			t.Errorf("report.%s was never reached from report.Report, so the walk missed it", name)
		}
	}
}

// TestSchemaEnumsMatchGoVocabularies compares each frozen enum with the Go
// declaration it describes, read out of internal/diagnostic rather than copied
// here, so a vocabulary that grows cannot leave the published schema behind.
//
// Only the vocabularies the repository actually keeps closed are checked,
// because only those are frozen in the schema. Finding ids, remediation ids,
// check ids, failure causes and tunnel kinds are documented as growing over
// time and stay open strings there, so there is nothing to compare.
func TestSchemaEnumsMatchGoVocabularies(t *testing.T) {
	values := diagnosticVocabularies(t)
	defs := schemaDefs(t)

	// The status vocabulary is the runtime probe states plus the one value no
	// probe can return, which internal/report owns.
	status := append(slices.Clone(values["statusNames"]), report.StatusIncomplete)

	for _, tt := range []struct {
		def  string
		want []string
	}{
		{"status", status},
		{"protocol", values["protoNames"]},
		{"verdict", values["Verdict*"]},
		{"confidence", values["Confidence"]},
		{"evidenceKind", values["EvidenceKind"]},
		{"observation", values["ObservationID"]},
		{"notEvaluatedReason", values["NotEvaluatedReason"]},
		{"tunnel", values["TunnelState"]},
		{"routeReason", values["RouteReason"]},
		{"familyState", values["FamilyReachable,FamilyUnreachable"]},
		{"routeFamily", values["counterfactualIPv4,counterfactualIPv6"]},
	} {
		t.Run(tt.def, func(t *testing.T) {
			def, ok := defs[tt.def].(map[string]any)
			if !ok {
				t.Fatalf("the schema has no $defs/%s", tt.def)
			}
			var got []string
			for _, v := range def["enum"].([]any) {
				got = append(got, v.(string))
			}
			// An empty constant is the zero value of a vocabulary whose field
			// carries omitempty, so it is never serialized and never an enum
			// member. TunnelUnknown and RouteReasonUnknown are the two.
			want := slices.DeleteFunc(slices.Clone(tt.want), func(s string) bool { return s == "" })
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("$defs/%s enum is %v, and the Go vocabulary is %v", tt.def, got, want)
			}
		})
	}

	// The two five-value arrays are read positionally out of Go source above,
	// so this pins that neither grew a member the schema has not been told
	// about, which a renamed-value comparison alone would not catch.
	if got := diagnostic.Status(len(values["statusNames"])).String(); got != "?" {
		t.Errorf("a status beyond statusNames stringifies as %q, so the vocabulary grew", got)
	}
	if got := diagnostic.Proto(len(values["protoNames"])).String(); got != "none" {
		t.Errorf("a protocol beyond protoNames stringifies as %q, so the vocabulary grew", got)
	}
}

// schemaDefs returns the published file's $defs, which both audits read.
func schemaDefs(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(reportSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs map[string]any `json:"$defs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Defs
}

// diagnosticVocabularies reads the closed vocabularies out of the diagnostic
// package's own source. Typed constants are collected under their type name,
// which is what makes an added member visible here; the untyped verdict block,
// the two name arrays, and the handful of individually named constants are
// collected under keys naming what was asked for.
func diagnosticVocabularies(t *testing.T) map[string][]string {
	t.Helper()
	byName := map[string]string{}
	out := map[string][]string{}
	entries, err := os.ReadDir(diagnosticDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(diagnosticDir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
					continue
				}
				declared := value.Names[0].Name
				if literal, ok := stringLiteral(value.Values[0]); ok {
					byName[declared] = literal
					if ident, ok := value.Type.(*ast.Ident); ok {
						out[ident.Name] = append(out[ident.Name], literal)
					} else if strings.HasPrefix(declared, "Verdict") {
						out["Verdict*"] = append(out["Verdict*"], literal)
					}
					continue
				}
				// The status and protocol name tables are arrays rather than
				// constants, and they are the vocabulary itself.
				if composite, ok := value.Values[0].(*ast.CompositeLit); ok && (declared == "statusNames" || declared == "protoNames") {
					for _, element := range composite.Elts {
						literal, ok := stringLiteral(element)
						if !ok {
							t.Fatalf("%s holds a non-literal element", declared)
						}
						out[declared] = append(out[declared], literal)
					}
				}
			}
		}
	}
	for _, group := range []string{"FamilyReachable,FamilyUnreachable", "counterfactualIPv4,counterfactualIPv6"} {
		for _, name := range strings.Split(group, ",") {
			literal, ok := byName[name]
			if !ok {
				t.Fatalf("internal/diagnostic no longer declares %s", name)
			}
			out[group] = append(out[group], literal)
		}
	}
	for _, key := range []string{
		"statusNames", "protoNames", "Verdict*", "Confidence", "EvidenceKind", "ObservationID",
		"NotEvaluatedReason", "TunnelState", "RouteReason",
	} {
		if len(out[key]) == 0 {
			t.Fatalf("no %s vocabulary was found in %s", key, diagnosticDir)
		}
	}
	return out
}

func stringLiteral(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return value, true
}
