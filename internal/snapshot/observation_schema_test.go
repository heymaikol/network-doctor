package snapshot

import (
	"reflect"
	"strings"
	"testing"
)

// This ledger is about file validity, separate from the support and replay
// ledgers: preserving a field does not establish that its value is possible.
// IP rules also accept the documented erasure marker only in support-v1.
// Every field reachable from Check needs a decision, including numeric fields
// and new nested types. Each entry names the rule or explains its absence.
// "parent" means a nested validator or the existing run-envelope invariant.
var observationValidationPolicy = map[string]string{
	"Check.ID":                    "parent: unique nonempty identity in validate",
	"Check.Name":                  "human: display name",
	"Check.Deps":                  "parent: validateDependencyGraph",
	"Check.Status":                "parent: validCheckStatus and execution state",
	"Check.Cause":                 "opaque: additive reason IDs; no probe vocabulary in the format",
	"Check.CauseFamily":           "structural: optional ipv4/ipv6; cause required by validate",
	"Check.Ran":                   "parent: ExecutionContradicts",
	"Check.DurationMs":            "structural: nonnegative; zero may mean a submillisecond historical reading",
	"Check.Detail":                "human: never parsed for validity",
	"Check.Fix":                   "human: never parsed for validity",
	"Check.Observed":              "parent: validateObservation; execution state excludes unread evidence",
	"Check.Derived":               "parent: optional conclusions; AnswerComparison checked by validate",
	"Observed.Addresses":          "structural: each entry is an IP address",
	"Observed.SelectedIP":         "structural: optional IP address; may come from a different operation than Addresses",
	"Observed.DNSNotFound":        "opaque: positive observation; no per-query identity to relate it to other DNS readings",
	"Observed.Resolver":           "structural: optional resolver IP address",
	"Observed.ResolverTargets":    "opaque: raw resolver Dial service addresses; no response provenance, global ordering or uniqueness",
	"Observed.SourceIP":           "structural: optional IP address",
	"Observed.Interface":          "opaque: OS name or ambiguous display text",
	"Observed.SSID":               "opaque: network-supplied identifier",
	"Observed.Families":           "parent: optional independently tested family states",
	"Observed.Portal":             "parent: presence records interception; URL remains optional",
	"Observed.Attempts":           "parent: each attempt validated; repeated IPs and mixed outcomes are valid",
	"Observed.ClockOffsetMs":      "opaque: signed milliseconds; no Go time.Duration storage limit imposed on v1",
	"Observed.Timeout":            "opaque: positive observation; no check-specific status inference",
	"Observed.InterfaceAmbiguous": "opaque: observation, not a count or list of interfaces",
	"Observed.Routes":             "parent: validateObservedRoute for each decision",
	"Observed.ConnectCleartext":   "opaque: positive transport observation; false proves nothing; no probe-ID restriction",
	"Families.IPv4":               "structural: absent, reachable or unreachable",
	"Families.IPv6":               "structural: absent, reachable or unreachable",
	"Portal.RedirectURL":          "opaque: optional display link; support policy may replace it with a non-URL marker",
	"Attempt.IP":                  "structural: required IP address",
	"Attempt.DurationMs":          "structural: nonnegative milliseconds; zero remains compatible",
	"Attempt.Error":               "human: external error sentence, not proof of a typed cause",
	"Attempt.Cause":               "opaque: additive cause; old and non-TCP attempts may have only Error",
	"Attempt.Aborted":             "opaque: enclosing cancellation may race an independent failure; no closed cause relationship",
	"Route.Destination":           "structural: required IP address",
	"Route.Family":                "structural: optional ipv4/ipv6 matching destination, including mapped IPv4",
	"Route.Interface":             "opaque: platform interface identifier",
	"Route.Gateway":               "structural: optional IP; cross-family next hops are possible, and Linux records one from RTA_VIA",
	"Route.Source":                "structural: optional IP; no producer pins its family, so no platform-specific address selection rules",
	"Route.Prefix":                "structural: optional CIDR in the destination's family, mapped IPv4 included; support pseudonyms need not contain the destination",
	"Route.Metric":                "opaque: optional platform preference; no portable ranking scale or integer-width cap",
	"Route.Table":                 "opaque: OS routing domain; predates TableKnown in v1",
	"Route.TableKnown":            "opaque: absent is unknown even when a legacy table name remains",
	"Route.InterfaceMTU":          "structural: nonnegative byte count; zero means unknown; no path-MTU bounds",
	"Route.Tunnel":                "structural: absent, direct, likely or tunnel",
	"Route.TunnelKind":            "structural: requires tunnel; OS device-kind vocabulary stays extensible",
	"Route.Unreachable":           "opaque: kernel observation; do not reconstruct platform-specific route selection",
	"Route.Reason":                "opaque: additive selection explanation; no duplicated routeReason logic",
	"Route.Competing":             "parent: competitors retain platform-specific preference values",
	"CompetingRoute.Interface":    "opaque: platform interface identifier",
	"CompetingRoute.Metric":       "opaque: platform ranking value; not a measurement in a portable unit",
	"Derived.StatusDowngraded":    "opaque: later reasoning relaxed an outcome; current WARN-only implementation is not a v1 restriction",
	"Derived.AnswerComparison":    "structural: validAnswerComparison in validate; no probe-ID or recomputation requirement",
}

func TestObservationSchemaHasValidationPolicy(t *testing.T) {
	seen := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := range typ.NumField() {
			field := typ.Field(i)
			key := typ.Name() + "." + field.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			policy := observationValidationPolicy[key]
			category, reason, ok := strings.Cut(policy, ": ")
			if !ok || reason == "" {
				t.Errorf("%s needs a validation policy and rationale", key)
			}
			switch category {
			case "structural", "parent", "opaque", "human":
			default:
				t.Errorf("%s has unrecognized validation category %q", key, category)
			}
			walk(field.Type)
		}
	}
	walk(reflect.TypeFor[Check]())
	for key := range observationValidationPolicy {
		if !seen[key] {
			t.Errorf("stale observation policy for %s", key)
		}
	}
}
