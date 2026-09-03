package snapshot

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The two sets below are the support policy, written down field by field.
//
// The test under them fills every string in the schema with a sentinel and
// fails on any sentinel that survives sanitization without being named in one
// of them. A field added to the schema later is therefore a failing test until
// somebody classifies it, which is the point: the dangerous way to add a field
// is the way that needs no decision.

// retainedBySupportPolicy is every string a support artifact keeps verbatim.
// Each is a closed vocabulary, a build fact, or a timestamp, so none of them
// can carry a value the local machine or its network chose.
var retainedBySupportPolicy = map[string]bool{
	// The artifact's own identity and provenance.
	".Schema":             true,
	".CreatedAt":          true,
	".Tool.Version":       true,
	".Tool.OS":            true,
	".Tool.Arch":          true,
	".Redaction.Policy":   true,
	".Incident.StartedAt": true,
	".Incident.EndedAt":   true,
	// Probe IDs, a fixed vocabulary rejected before a run starts if unknown.
	".Options.Check[0]":                  true,
	".Options.Skip[0]":                   true,
	".Checks[0].ID":                      true,
	".Checks[0].Deps[0]":                 true,
	".Diagnosis.Blamed":                  true,
	".Diagnosis.FailedStage":             true,
	".Diagnosis.Findings[0].ID":          true,
	".Diagnosis.Findings[0].Focus":       true,
	".Diagnosis.Findings[0].Evidence[0]": true,
	// Outcome vocabularies: statuses, causes, verdicts, and the typed words the
	// causal-evidence, counterfactual, and route models are written in.
	".Target.Protocol":                                                              true,
	".Checks[0].Status":                                                             true,
	".Checks[0].Cause":                                                              true,
	".Checks[0].CauseFamily":                                                        true,
	".Checks[0].Derived.AnswerComparison":                                           true,
	".Checks[0].Observed.Families.IPv4":                                             true,
	".Checks[0].Observed.Families.IPv6":                                             true,
	".Checks[0].Observed.Attempts[0].Cause":                                         true,
	".Checks[0].Observed.Routes[0].Family":                                          true,
	".Checks[0].Observed.Routes[0].Reason":                                          true,
	".Checks[0].Observed.Routes[0].Tunnel":                                          true,
	".Diagnosis.Verdict":                                                            true,
	".Diagnosis.Findings[0].Verdict":                                                true,
	".Diagnosis.Findings[0].Confidence":                                             true,
	".Diagnosis.Findings[0].CausalEvidence[0].Kind":                                 true,
	".Diagnosis.Findings[0].CausalEvidence[0].Check":                                true,
	".Diagnosis.Findings[0].CausalEvidence[0].Observation":                          true,
	".Diagnosis.Findings[0].CausalEvidence[0].Candidate":                            true,
	".Diagnosis.Findings[0].CausalEvidence[0].Reason":                               true,
	".Diagnosis.Findings[0].Counterfactual.Variable":                                true,
	".Diagnosis.Findings[0].Counterfactual.Alternatives[0].Outcome":                 true,
	".Diagnosis.Findings[0].Counterfactual.Alternatives[0].Evidence[0].Kind":        true,
	".Diagnosis.Findings[0].Counterfactual.Alternatives[0].Evidence[0].Check":       true,
	".Diagnosis.Findings[0].Counterfactual.Alternatives[0].Evidence[0].Observation": true,
	".Diagnosis.Findings[0].Counterfactual.Alternatives[0].Evidence[0].Candidate":   true,
	".Diagnosis.Findings[0].Counterfactual.Alternatives[0].Evidence[0].Reason":      true,
	// The operating system's own word for a class of device ("wireguard",
	// "utun"), never the name of one particular device.
	".Checks[0].Observed.Routes[0].TunnelKind": true,
}

// proseBySupportPolicy is every string that holds a human sentence rather than
// a value with a shape. Each is rewritten by pattern, not by structure: known
// hostnames, addresses, SSIDs, interfaces, paths, URLs, and credentials are
// replaced wherever they appear, and anything else is left readable, because a
// support artifact whose diagnosis has been redacted into silence is not worth
// sharing.
//
// This is where the policy's stated limit lives. A sentinel here survives on
// purpose: it is a bare word with no identifying syntax, and nothing can tell
// one of those from an ordinary English word. The fixture tests beside this one
// cover what the patterns do catch.
var proseBySupportPolicy = map[string]bool{
	".Target.Raw":                                    true,
	".Checks[0].Name":                                true,
	".Checks[0].Detail":                              true,
	".Checks[0].Fix":                                 true,
	".Checks[0].Observed.Attempts[0].Error":          true,
	".Diagnosis.Summary":                             true,
	".Diagnosis.Findings[0].Summary":                 true,
	".Diagnosis.Findings[0].CausalEvidence[0].Value": true,
	".Diagnosis.Findings[0].Counterfactual.Alternatives[0].Value":             true,
	".Diagnosis.Findings[0].Counterfactual.Alternatives[0].Evidence[0].Value": true,
}

// TestSupportSanitizesEveryUnclassifiedSchemaString walks the schema itself
// rather than a hand-written fixture, so it covers fields nobody remembered to
// put in one.
func TestSupportSanitizesEveryUnclassifiedSchemaString(t *testing.T) {
	pinLocalIdentity(t)
	var s Snapshot
	sentinels := map[string]string{}
	fillSchema(t, reflect.ValueOf(&s).Elem(), "", sentinels)
	if len(sentinels) < 40 {
		t.Fatalf("filled only %d schema strings, so this test is not walking the schema", len(sentinels))
	}

	// json.Marshal rather than Encode: this snapshot is a schema walk, not a
	// valid run, and Encode would reject its invented statuses before it ever
	// serialized the fields under test.
	data, err := json.Marshal(SanitizeForSupport(s))
	if err != nil {
		t.Fatal(err)
	}
	var leaked []string
	for path, sentinel := range sentinels {
		if !strings.Contains(string(data), sentinel) {
			continue
		}
		// A nested incident state is the same type sanitized by the same code,
		// so it answers to the same policy entry as the run that carries it.
		classified := incidentTrimmed(path)
		if !retainedBySupportPolicy[classified] && !proseBySupportPolicy[classified] {
			leaked = append(leaked, path)
		}
	}
	sort.Strings(leaked)
	for _, path := range leaked {
		t.Errorf("support snapshot kept %s verbatim. Sanitize it in redact.go, or classify it: "+
			"retainedBySupportPolicy if it cannot carry an identity, proseBySupportPolicy if it is a "+
			"human sentence the text pass rewrites by pattern", path)
	}
}

func TestProfileSupportSanitizesEveryUnclassifiedSchemaString(t *testing.T) {
	pinLocalIdentity(t)
	var profile ProfileSnapshot
	sentinels := map[string]string{}
	fillSchema(t, reflect.ValueOf(&profile).Elem(), "", sentinels)
	data, err := json.Marshal(SanitizeProfileForSupport(profile))
	if err != nil {
		t.Fatal(err)
	}
	profilePolicy := map[string]bool{
		".Schema": true, ".CreatedAt": true, ".Tool.Version": true, ".Tool.OS": true, ".Tool.Arch": true,
		".Profile.Name": true, ".Profile.Title": true, ".Components[0].ID": true, ".Components[0].Label": true,
		".Components[0].Focus": true, ".Components[0].Status": true, ".Components[0].Fallback": true,
		".Aggregate.Status": true, ".Aggregate.Summary": true, ".Aggregate.Finding.ID": true,
		".Aggregate.Finding.AffectedComponents[0]": true, ".Aggregate.Finding.WorkingComponents[0]": true,
		".Redaction.Policy": true,
	}
	for path, sentinel := range sentinels {
		if !strings.Contains(string(data), sentinel) {
			continue
		}
		if nested, ok := strings.CutPrefix(path, ".Components[0].Snapshot"); ok {
			nested = incidentTrimmed(nested)
			if retainedBySupportPolicy[nested] || proseBySupportPolicy[nested] {
				continue
			}
		}
		if !profilePolicy[path] {
			t.Errorf("support profile snapshot kept %s verbatim without a policy classification", path)
		}
	}
}

// TestSupportPolicySetsNameOnlyRealFields keeps both sets honest in the other
// direction: a renamed or deleted field must not leave a stale entry behind,
// quietly exempting whatever takes that path next.
func TestSupportPolicySetsNameOnlyRealFields(t *testing.T) {
	var s Snapshot
	sentinels := map[string]string{}
	fillSchema(t, reflect.ValueOf(&s).Elem(), "", sentinels)
	for _, set := range []map[string]bool{retainedBySupportPolicy, proseBySupportPolicy} {
		for path := range set {
			if _, ok := sentinels[path]; !ok {
				t.Errorf("the support policy names %s, which is not a string field of the schema", path)
			}
		}
	}
	for path := range retainedBySupportPolicy {
		if proseBySupportPolicy[path] {
			t.Errorf("%s is classified both retained and prose; it can only be one", path)
		}
	}
}

// TestSupportProseFieldsStillLoseKnownValues is the other half of the prose
// category. A prose field keeps words it cannot recognize, but it must never
// keep a value the sanitizer already knows about from a structured field.
func TestSupportProseFieldsStillLoseKnownValues(t *testing.T) {
	pinLocalIdentity(t)
	s := Snapshot{
		Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z",
		Target: &Target{Raw: "labbox:8443", Host: "labbox", Port: 8443, Protocol: "tls"},
		Checks: []Check{{
			ID: "dns", Name: "DNS labbox", Status: StatusFail,
			Detail: "labbox did not resolve via 192.168.31.7 on wlan0 (Cafe Wifi 5G)",
			Fix:    "check labbox in /home/jrivera/hosts",
			Observed: &Observed{
				Resolver: "192.168.31.7", Interface: "wlan0", SSID: "Cafe Wifi 5G",
				Attempts: []Attempt{{IP: "192.168.31.7", Error: "no route to 192.168.31.7."}},
			},
		}},
		Diagnosis: Diagnosis{Verdict: "dns", Summary: "labbox unreachable from wlan0"},
	}
	data, err := Encode(SanitizeForSupport(s))
	if err != nil {
		t.Fatal(err)
	}
	// "labbox" is a single-label name no pattern marks as a hostname. It is
	// caught because Target.Host declared it, which is the whole reason the
	// sanitizer collects known values before it rewrites any text.
	for _, secret := range []string{"labbox", "192.168.31.7", "wlan0", "Cafe Wifi 5G", "/home/jrivera"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("prose field leaked the known value %q:\n%s", secret, data)
		}
	}
}

// incidentTrimmed maps a path inside an incident state onto the same path in
// the run that carries it.
func incidentTrimmed(path string) string {
	for _, state := range [...]string{".Incident.Before", ".Incident.During", ".Incident.Recovered"} {
		if rest, ok := strings.CutPrefix(path, state); ok {
			return rest
		}
	}
	return path
}

// fillSchema puts a unique sentinel in every string reachable from v, and a
// non-zero value in everything else, so no field is left at a zero value the
// encoder would omit and the test would never see.
func fillSchema(t *testing.T, v reflect.Value, path string, sentinels map[string]string) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		sentinel := "zz" + strings.NewReplacer(".", "", "[", "", "]", "").Replace(path) + "zz"
		sentinels[path] = sentinel
		v.SetString(sentinel)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(7)
	case reflect.Pointer:
		// One level of incident nesting is the format's own limit: a nested
		// state may not carry an incident of its own.
		if strings.HasSuffix(path, ".Incident") && strings.Count(path, ".Incident") > 1 {
			return
		}
		v.Set(reflect.New(v.Type().Elem()))
		fillSchema(t, v.Elem(), path, sentinels)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillSchema(t, v.Index(0), path+"[0]", sentinels)
	case reflect.Struct:
		for i := range v.NumField() {
			fillSchema(t, v.Field(i), path+"."+v.Type().Field(i).Name, sentinels)
		}
	default:
		t.Fatalf("schema field %s has kind %s, which this walker does not fill. "+
			"Teach it that kind so the coverage test keeps covering the whole schema", path, v.Kind())
	}
}

// pinLocalIdentity replaces the machine's real name and account with fixed
// ones, so a test asserts against the same values everywhere it runs.
func pinLocalIdentity(t *testing.T) {
	t.Helper()
	original := localIdentity
	localIdentity = func() (string, string) { return "sanitizer-test-box.example", "sanitizer-test-account" }
	t.Cleanup(func() { localIdentity = original })
}
