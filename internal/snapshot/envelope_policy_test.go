package snapshot

import (
	"reflect"
	"strings"
	"testing"
)

// This ledger records decisions, not just field names. Adding a stable field
// requires a format-level policy even when this reader cannot validate it.
// "runtime" means the artifact lacks the knowledge needed to check the claim.
func TestEnvelopeValidationPolicyIsComplete(t *testing.T) {
	policies := map[reflect.Type]map[string]string{
		reflect.TypeOf(Snapshot{}): {
			"Schema":    "validated: Decode and Validate require v1; Encode stamps the writer's schema",
			"CreatedAt": "validated: UTC RFC 3339 capture time, shared with profile envelopes",
			"Tool":      "validated: complete provenance, without a build inventory",
			"Target":    "validated: null means generic; a present endpoint must be structurally usable",
			"Options":   "validated: invocation settings have format-level constraints, not a live probe registry",
			"Checks":    "validated: validate owns row identity, execution, graph and evidence rules",
			"Diagnosis": "derived: validate ties references and projections to recorded checks",
			"OK":        "derived: validate computes failure and incompleteness from checks",
			"Redaction": "validated: existing explicit support policy metadata rule",
			"Incident":  "derived: validateIncident owns chronology, session identity and nested records",
		},
		reflect.TypeOf(Tool{}): {
			"Version": "free-form: nonblank build identity; no semver or recognized-version requirement",
			"OS":      "forward-compatible: nonblank platform identity; future OS names remain readable",
			"Arch":    "forward-compatible: nonblank architecture identity; no GOARCH inventory",
		},
		reflect.TypeOf(Target{}): {
			"Raw":          "free-form: nonblank original spelling; support rewrites it, so do not reparse or compare it",
			"Host":         "validated: nonblank endpoint host; hostname grammar belongs to the producer",
			"IP":           "derived: present exactly for a literal Host and equal by IP value, including mapped IPv4",
			"Port":         "validated: network endpoint port in 1..65535, independent of scheme defaults",
			"Protocol":     "forward-compatible: nonblank protocol identity; a future probe protocol is additive vocabulary",
			"PortExplicit": "runtime: deriving this requires parsing Raw using producer-specific target grammar",
		},
		reflect.TypeOf(Options{}): {
			"ProbeTimeoutMs": "validated: nonnegative milliseconds; zero means unrecorded, since netdoc accepts only whole positive milliseconds to run",
			"PublicDNS":      "validated: IP address or empty, as the published v1 contract promises",
			"PublicDNSAuto":  "runtime: resolver default and fallback policy belong to probes; the remote worker permits empty resolver with auto",
			"Check":          "forward-compatible: nonblank IDs; selections can be absent from this graph and future IDs stay readable",
			"Skip":           "forward-compatible: nonblank IDs; skipped nodes can be absent and check/skip overlap is valid",
			"Source":         "validated: optional resolved binding, with usable address families when present",
		},
		reflect.TypeOf(Source{}): {
			"Interface": "free-form: platform-owned name; empty denotes one exact IP, never two families; local existence is runtime knowledge",
			"IPv4":      "validated: optional usable IPv4; at least one family must exist; no local ownership lookup",
			"IPv6":      "validated: optional usable IPv6, not mapped IPv4; link-local needs no zone here because Interface carries scope",
		},
		reflect.TypeOf(ProfileSnapshot{}): {
			"Schema":     "validated: separate profile identity checked before content; EncodeProfile stamps it",
			"CreatedAt":  "validated: same UTC capture-time contract as ordinary snapshots, not ordered against remote clocks",
			"Tool":       "validated: shared provenance; local aggregator can differ from remote component tools",
			"Profile":    "validated: existing name syntax, positive version and nonempty title; no installed-profile inventory",
			"Components": "validated: unique component IDs, complete ordinary snapshots and existing fallback rules",
			"Aggregate":  "derived: existing profile aggregation checks tie status and finding to component outcomes",
			"OK":         "derived: existing aggregate failure rule determines this value",
			"Redaction":  "derived: existing policy checks require agreement with component metadata",
		},
		reflect.TypeOf(ProfileIdentity{}): {
			"Name":    "forward-compatible: existing name syntax, no built-in profile inventory",
			"Version": "validated: existing positive profile-definition version, independent of tool version",
			"Title":   "free-form: existing nonempty display label, never regenerated prose",
		},

		reflect.TypeOf(ProfileAggregate{}): {
			"Status":  "derived: AggregateProfile determines the existing closed result vocabulary",
			"Summary": "free-form: existing nonempty human summary, not regenerated wording",
			"Finding": "derived: existing aggregate finding presence, ID and component projections",
		},
		reflect.TypeOf(ProfileFinding{}): {
			"ID":                 "derived: existing FindingID projection of profile name and aggregate outcome",
			"AffectedComponents": "derived: existing exact projection of nonpassing component IDs",
			"WorkingComponents":  "derived: existing exact projection of working component IDs",
		},
		reflect.TypeOf(ProfileComponent{}): {
			"ID":       "validated: existing nonempty unique identity and fallback reference rules",
			"Label":    "free-form: existing nonempty display label",
			"Focus":    "forward-compatible: existing nonempty check identity; missing focus row has defined aggregation semantics",
			"Status":   "derived: existing ProfileComponentStatus projection of the nested run",
			"Fallback": "validated: existing optional reference to another component",
			"Snapshot": "validated: complete ordinary snapshot, recursively using the authoritative validator",
		},
	}
	for typ, fields := range policies {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			policy, ok := fields[field.Name]
			if !ok {
				t.Errorf("%s.%s has no validation policy; establish its invariant and regression coverage", typ.Name(), field.Name)
				continue
			}
			category, reason, ok := strings.Cut(policy, ": ")
			switch category {
			case "validated", "derived", "free-form", "forward-compatible", "runtime":
			default:
				t.Errorf("%s.%s has unknown policy %q", typ.Name(), field.Name, category)
			}
			if !ok || strings.TrimSpace(reason) == "" {
				t.Errorf("%s.%s needs a reason for its policy", typ.Name(), field.Name)
			}
		}
		for name := range fields {
			if _, ok := typ.FieldByName(name); !ok {
				t.Errorf("stale policy for %s.%s", typ.Name(), name)
			}
		}
	}
}
