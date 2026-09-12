package diagnostic

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// The .ndoc boundary is two hand-written projections facing each other.
// BuildSnapshot copies a live ProbeResult into the durable model a field at a
// time, and replayResult copies it back a field at a time. That is deliberate:
// the file format is a published contract and generating it would make a
// rename a silent change to it. The cost is that nothing in the compiler ties
// the two halves together, so a new piece of evidence reaches the far side
// only because somebody remembered the other projection exists.
//
// This file is the ledger that makes forgetting fail. Every field of every
// type the boundary touches carries one of the decisions below, and both the
// structural test and the behavioral one read the same table, so a
// classification is a claim that gets checked rather than a comment.
const (
	// replayed is evidence written to the artifact and rebuilt into a
	// ProbeResult, because the diagnosis is recomputed from it.
	replayed = "replayed"
	// persisted is evidence written to the artifact and deliberately not
	// rebuilt. A reader or a comparison uses it; the truth table does not.
	persisted = "artifact only"
	// prose is a derived human sentence. It is written because a person reads
	// the file, and it is never parsed back.
	prose = "prose"
	// transient is run-time execution state that crosses nothing: it is
	// consumed before a snapshot exists, and what it concluded is persisted
	// somewhere else.
	transient = "transient"
	// redundant is a field whose authoritative value is another field. It is
	// rebuilt from that one, or left behind.
	redundant = "redundant"
)

// decision is one field's place at the boundary. why is required for every
// category except replayed, because every one of those is a field that stops
// somewhere, and the reason it stops is the thing a maintainer needs to read.
type decision struct {
	category string
	why      string
}

// evidenceProjection classifies every field of the live evidence model and of
// the durable one. Keys are reflect's own type names, so a renamed field shows
// up as an unclassified one plus a stale entry rather than as silence.
//
// The two halves are listed separately because they are two different
// questions. A runtime field asks "does this reach the artifact"; a snapshot
// field asks "does replay rebuild it". A field can be a yes to the first and a
// no to the second, which is exactly the case this ledger exists to keep
// visible.
var evidenceProjection = map[string]decision{
	// The live result. Everything here either reaches the artifact or says why
	// it does not.
	"diagnostic.ProbeResult.ID":               {category: replayed},
	"diagnostic.ProbeResult.Status":           {category: replayed},
	"diagnostic.ProbeResult.Cause":            {category: replayed},
	"diagnostic.ProbeResult.causeFamily":      {category: replayed},
	"diagnostic.ProbeResult.Families":         {category: replayed},
	"diagnostic.ProbeResult.downgraded":       {category: replayed},
	"diagnostic.ProbeResult.answerComparison": {category: replayed},
	"diagnostic.ProbeResult.Portal":           {category: replayed},
	"diagnostic.ProbeResult.Addrs":            {category: replayed},
	"diagnostic.ProbeResult.DNSNotFound":      {category: replayed},
	"diagnostic.ProbeResult.ResolverTargets":  {category: replayed},
	"diagnostic.ProbeResult.SelectedIP":       {category: replayed},
	"diagnostic.ProbeResult.Source":           {category: replayed},
	"diagnostic.ProbeResult.Iface":            {category: replayed},
	"diagnostic.ProbeResult.Network":          {category: replayed},
	"diagnostic.ProbeResult.Routes":           {category: replayed},
	"diagnostic.ProbeResult.Attempts":         {category: replayed},
	"diagnostic.ProbeResult.ConnectCleartext": {category: replayed},
	"diagnostic.ProbeResult.timedOut":         {category: replayed},
	"diagnostic.ProbeResult.clockOffset":      {category: replayed},
	"diagnostic.ProbeResult.resolver":         {category: replayed},
	"diagnostic.ProbeResult.ifaceAmbiguous":   {category: replayed},
	"diagnostic.ProbeResult.alternateDefaults": {category: transient, why: "reference-path selection state. " +
		"reconcilePreferredPath consumes it inside Finalize, which runs before any snapshot is built, and what it " +
		"concluded is persisted as the direct-egress row's cause. Restoring it would mean storing the routing table " +
		"netdoc read rather than the answer it reached from it."},
	"diagnostic.ProbeResult.Dur": {category: persisted, why: "wall time. It is written as duration_ms and as ran, " +
		"which is how a reader tells a probe that finished in under a millisecond from one that never executed. No " +
		"diagnosis rule reads it, and restoring it would let a snapshot rebuilt from a replay claim a probe body ran."},
	"diagnostic.ProbeResult.Detail": {category: prose, why: "a derived sentence the format documents as never parsed back"},
	"diagnostic.ProbeResult.Fix":    {category: prose, why: "a derived sentence the format documents as never parsed back"},

	"diagnostic.Attempt.IP":      {category: replayed},
	"diagnostic.Attempt.Cause":   {category: replayed},
	"diagnostic.Attempt.Aborted": {category: replayed},
	"diagnostic.Attempt.Dur":     {category: persisted, why: "one attempt's wall time, evidence a comparison reads and no diagnosis rule does"},
	"diagnostic.Attempt.Err": {category: redundant, why: "Cause is the authoritative failure. Replay rebuilds a " +
		"typed marker from it so a failed attempt still reads as failed, and the original sentence stays in the " +
		"artifact as prose. An attempt on the target row carrying error text and no cause is refused rather than " +
		"half restored."},

	"diagnostic.RouteDecision.Destination": {category: replayed},
	"diagnostic.RouteDecision.Family":      {category: replayed},
	"diagnostic.RouteDecision.Iface":       {category: replayed},
	"diagnostic.RouteDecision.Gateway":     {category: replayed},
	"diagnostic.RouteDecision.Source":      {category: replayed},
	"diagnostic.RouteDecision.Table":       {category: replayed},
	"diagnostic.RouteDecision.TableKnown":  {category: replayed},
	"diagnostic.RouteDecision.MTU":         {category: replayed},
	"diagnostic.RouteDecision.Tunnel":      {category: replayed},
	"diagnostic.RouteDecision.Unreachable": {category: replayed},
	"diagnostic.RouteDecision.Competing":   {category: replayed},
	"diagnostic.RouteDecision.Prefix": {category: persisted, why: "the route entry the kernel said it matched. " +
		"routeReason is the only thing that reads a prefix, it runs against a live routing answer, and what it " +
		"concluded is stored in Reason."},
	"diagnostic.RouteDecision.Metric":      {category: persisted, why: "route preference, read by routeReason at run time and by no diagnosis rule"},
	"diagnostic.RouteDecision.MetricKnown": {category: persisted, why: "the presence bit for Metric, which is absent from the artifact rather than written as 0"},
	"diagnostic.RouteDecision.TunnelKind": {category: persisted, why: "the operating system's own name for the " +
		"device. Display text and comparison evidence; Tunnel is the state every diagnosis rule branches on."},
	"diagnostic.RouteDecision.Reason": {category: persisted, why: "derived at run time from the kernel's answer plus " +
		"the path general traffic took. Replay builds no route graph and re-runs no selection, so recomputing it " +
		"would be inventing a decision nothing witnessed; the run's own answer is what the artifact carries."},

	"diagnostic.CompetingRoute.Iface":    {category: replayed},
	"diagnostic.CompetingRoute.Metric":   {category: replayed},
	"diagnostic.FamilyConnectivity.IPv4": {category: replayed},
	"diagnostic.FamilyConnectivity.IPv6": {category: replayed},
	"diagnostic.Portal.RedirectURL":      {category: replayed},
	"diagnostic.Target.Raw":              {category: replayed},
	"diagnostic.Target.Host":             {category: replayed},
	"diagnostic.Target.IP":               {category: replayed},
	"diagnostic.Target.Port":             {category: replayed},
	"diagnostic.Target.Proto":            {category: replayed},
	"diagnostic.Target.PortExplicit":     {category: replayed},

	// The durable model. Everything here either comes back as diagnostic state
	// or says why the artifact keeps it without replay reading it.
	"snapshot.Check.ID":          {category: replayed},
	"snapshot.Check.Status":      {category: replayed},
	"snapshot.Check.Cause":       {category: replayed},
	"snapshot.Check.CauseFamily": {category: replayed},
	"snapshot.Check.Observed":    {category: replayed},
	"snapshot.Check.Derived":     {category: replayed},
	"snapshot.Check.Name":        {category: persisted, why: "display text built from the probe and the target; replay keys rows by id"},
	"snapshot.Check.Deps": {category: persisted, why: "the dependency graph as executed, so a reader can rebuild " +
		"it without a live probe list. Interpret takes the order of the rows, not the edges between them."},
	"snapshot.Check.Ran":        {category: persisted, why: "whether the probe body executed, which a duration of 0 cannot say on its own"},
	"snapshot.Check.DurationMs": {category: persisted, why: "wall time, the durable form of ProbeResult.Dur"},
	"snapshot.Check.Detail":     {category: prose, why: "a derived sentence the format documents as never parsed back"},
	"snapshot.Check.Fix":        {category: prose, why: "a derived sentence the format documents as never parsed back"},

	"snapshot.Observed.Addresses":          {category: replayed},
	"snapshot.Observed.SelectedIP":         {category: replayed},
	"snapshot.Observed.DNSNotFound":        {category: replayed},
	"snapshot.Observed.Resolver":           {category: replayed},
	"snapshot.Observed.ResolverTargets":    {category: replayed},
	"snapshot.Observed.SourceIP":           {category: replayed},
	"snapshot.Observed.Interface":          {category: replayed},
	"snapshot.Observed.SSID":               {category: replayed},
	"snapshot.Observed.Families":           {category: replayed},
	"snapshot.Observed.Portal":             {category: replayed},
	"snapshot.Observed.Attempts":           {category: replayed},
	"snapshot.Observed.ClockOffsetMs":      {category: replayed},
	"snapshot.Observed.Timeout":            {category: replayed},
	"snapshot.Observed.InterfaceAmbiguous": {category: replayed},
	"snapshot.Observed.Routes":             {category: replayed},
	"snapshot.Observed.ConnectCleartext":   {category: replayed},

	"snapshot.Derived.StatusDowngraded": {category: replayed},
	"snapshot.Derived.AnswerComparison": {category: replayed},
	"snapshot.Families.IPv4":            {category: replayed},
	"snapshot.Families.IPv6":            {category: replayed},
	"snapshot.Portal.RedirectURL":       {category: replayed},

	"snapshot.Attempt.IP":         {category: replayed},
	"snapshot.Attempt.Cause":      {category: replayed},
	"snapshot.Attempt.Aborted":    {category: replayed},
	"snapshot.Attempt.DurationMs": {category: persisted, why: "one attempt's wall time, the durable form of Attempt.Dur"},
	"snapshot.Attempt.Error":      {category: prose, why: "the sanitized error sentence; Cause is the machine-readable half and replay reads that"},

	"snapshot.Route.Destination":  {category: replayed},
	"snapshot.Route.Family":       {category: replayed},
	"snapshot.Route.Interface":    {category: replayed},
	"snapshot.Route.Gateway":      {category: replayed},
	"snapshot.Route.Source":       {category: replayed},
	"snapshot.Route.Table":        {category: replayed},
	"snapshot.Route.TableKnown":   {category: replayed},
	"snapshot.Route.InterfaceMTU": {category: replayed},
	"snapshot.Route.Tunnel":       {category: replayed},
	"snapshot.Route.Unreachable":  {category: replayed},
	"snapshot.Route.Competing":    {category: replayed},
	"snapshot.Route.Prefix":       {category: persisted, why: "the matched entry, read at run time by routeReason and by no diagnosis rule"},
	"snapshot.Route.Metric":       {category: persisted, why: "route preference, read at run time by routeReason and by no diagnosis rule"},
	"snapshot.Route.TunnelKind":   {category: persisted, why: "the device kind as the operating system names it; Tunnel is the state rules branch on"},
	"snapshot.Route.Reason":       {category: persisted, why: "the run's own account of why a route won, which replay cannot recompute without re-running selection"},

	"snapshot.CompetingRoute.Interface": {category: replayed},
	"snapshot.CompetingRoute.Metric":    {category: replayed},

	"snapshot.Target.Raw":          {category: replayed},
	"snapshot.Target.Host":         {category: replayed},
	"snapshot.Target.IP":           {category: replayed},
	"snapshot.Target.Port":         {category: replayed},
	"snapshot.Target.Protocol":     {category: replayed},
	"snapshot.Target.PortExplicit": {category: replayed},
}

// auditedTypes are the two evidence models the ledger covers. The snapshot
// envelope above a check row is deliberately not here: schema, tool, options,
// created_at and the diagnosis are not probe evidence, they are owned by the
// caller or by the interpretation, and compare's parity table and remote's
// agreement table already hold those to their own obligations.
func auditedTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(ProbeResult{}), reflect.TypeOf(Attempt{}), reflect.TypeOf(RouteDecision{}),
		reflect.TypeOf(CompetingRoute{}), reflect.TypeOf(FamilyConnectivity{}), reflect.TypeOf(Portal{}),
		reflect.TypeOf(Target{}),
		reflect.TypeOf(snapshot.Check{}), reflect.TypeOf(snapshot.Observed{}), reflect.TypeOf(snapshot.Derived{}),
		reflect.TypeOf(snapshot.Families{}), reflect.TypeOf(snapshot.Portal{}), reflect.TypeOf(snapshot.Attempt{}),
		reflect.TypeOf(snapshot.Route{}), reflect.TypeOf(snapshot.CompetingRoute{}), reflect.TypeOf(snapshot.Target{}),
	}
}

func fieldKey(typ reflect.Type, i int) string { return typ.String() + "." + typ.Field(i).Name }

// auditedNames is the same set by name, which is how the comparison below
// knows whether to descend into a struct or treat it as one value.
var auditedNames = func() map[string]bool {
	names := map[string]bool{}
	for _, typ := range auditedTypes() {
		names[typ.String()] = true
	}
	return names
}()

// The structural half. A field added to the live evidence model or to the
// durable one has to be given a decision here, which is the whole point: the
// author of the new field is the person who knows whether it has to survive
// into the artifact, survive replay as well, or stop at either line.
func TestEveryEvidenceFieldIsClassifiedAtTheSnapshotBoundary(t *testing.T) {
	known := map[string]bool{}
	for _, typ := range auditedTypes() {
		for i := range typ.NumField() {
			key := fieldKey(typ, i)
			known[key] = true
			d, ok := evidenceProjection[key]
			if !ok {
				t.Errorf("%s crosses the snapshot boundary unclassified. Decide what it is and add it to "+
					"evidenceProjection: %q (BuildSnapshot writes it and replay rebuilds it), %q (written to the "+
					".ndoc, deliberately not rebuilt), %q (a human sentence), %q (run-time state that never "+
					"crosses), or %q (another field is authoritative)",
					key, replayed, persisted, prose, transient, redundant)
				continue
			}
			switch d.category {
			case replayed:
			case persisted, prose, transient, redundant:
				if d.why == "" {
					t.Errorf("%s is classified %q with no reason. A field that stops at the boundary has to say why",
						key, d.category)
				}
			default:
				t.Errorf("%s has unknown classification %q", key, d.category)
			}
		}
	}
	for key := range evidenceProjection {
		if !known[key] {
			t.Errorf("evidenceProjection classifies %s, which is no longer a field", key)
		}
	}
}

// maximalResult is one live result carrying a nonzero value in every field a
// probe can fill, including the unexported cross-probe evidence only this
// package can see. It is the input to the behavioral half: a field left at its
// zero value would round trip perfectly while proving nothing.
//
// It is the independent DNS row because that is the only row allowed to carry
// a recorded answer comparison, and it is WARN because a recorded status
// downgrade is only coherent on one. The route is deliberately awkward: a
// known metric of 0 would be indistinguishable from an absent one, so the
// fixture uses a metric the artifact has to spell out.
func maximalResult() ProbeResult {
	return ProbeResult{
		ID: ProbeDNSPublic, Status: StatusWarn,
		Cause: DNSCauseTimeout, causeFamily: counterfactualIPv4,
		Families:   &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyUnreachable},
		downgraded: true,
		// The iface name is a sentinel: the transient assertion below looks for
		// it in the encoded artifact and has to not find it.
		alternateDefaults: map[string][]defaultRouteState{counterfactualIPv4: {{iface: transientSentinel}}},
		answerComparison:  comparisonDisagree,
		Portal:            &Portal{RedirectURL: "http://portal.example/login"},
		Addrs:             []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")},
		DNSNotFound:       true,
		ResolverTargets:   []string{"192.0.2.53:53"},
		SelectedIP:        net.ParseIP("192.0.2.10"),
		Source:            net.ParseIP("198.51.100.5"),
		Iface:             "eth0",
		Network:           "Example Wifi",
		Routes: []RouteDecision{{
			Destination: net.ParseIP("192.0.2.10"), Family: counterfactualIPv4, Iface: "wg0",
			Gateway: net.ParseIP("10.20.0.1"), Source: net.ParseIP("10.20.0.2"),
			Prefix: netip.MustParsePrefix("10.20.0.0/16"), Metric: 42, MetricKnown: true,
			Table: "table 51820", TableKnown: true, MTU: 1420,
			Tunnel: TunnelKnown, TunnelKind: "wireguard", Unreachable: true,
			Reason: RouteReasonMoreSpecific, Competing: []CompetingRoute{{Iface: "wlan0", Metric: 600}},
		}},
		Attempts: []Attempt{{
			IP: net.ParseIP("192.0.2.10"), Dur: 12 * time.Millisecond,
			Err: errors.New("connection refused"), Cause: ConnectionCauseRefused, Aborted: true,
		}},
		Dur:              7 * time.Millisecond,
		Detail:           "the second opinion disagreed",
		Fix:              "check the configured resolver",
		ConnectCleartext: true,
		timedOut:         true,
		clockOffset:      90 * time.Second,
		resolver:         "192.0.2.53",
		ifaceAmbiguous:   true,
	}
}

// transientSentinel is a value no projection may copy. It goes into the one
// field classified as transient, and the artifact must not contain it.
const transientSentinel = "zz-transient-alternate-zz"

func maximalTarget() *Target {
	return &Target{Raw: "example.com:443", Host: "example.com", IP: net.ParseIP("192.0.2.10"),
		Port: 443, Proto: ProtoTLSHTTP, PortExplicit: true}
}

// projected runs the fixture down the real path: BuildSnapshot, a real Encode,
// a real Decode, and the same per-row conversion ReplaySnapshot performs. It
// returns the bytes, the decoded row, and the result replay rebuilt from it.
func projected(t *testing.T) ([]byte, snapshot.Snapshot, ProbeResult) {
	t.Helper()
	live := maximalResult()
	probes := []Probe{{ID: ProbeDNSPublic, Name: "Public DNS", Deps: []ProbeID{ProbeIface}}}
	s := BuildSnapshot(maximalTarget(), probes, map[ProbeID]ProbeResult{ProbeDNSPublic: live})
	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatalf("the projection fixture is not a valid snapshot: %v", err)
	}
	decoded, err := snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	// The whole entry point, so the fixture is proved to be an artifact replay
	// actually accepts rather than one only the row conversion below tolerates.
	if _, err := ReplaySnapshot(decoded); err != nil {
		t.Fatalf("the projection fixture does not replay: %v", err)
	}
	back, err := replayResult(ProbeDNSPublic, StatusWarn, decoded.Checks[0])
	if err != nil {
		t.Fatalf("replaying the projection fixture: %v", err)
	}
	return data, decoded, back
}

// The behavioral half for everything the boundary is supposed to carry both
// ways. Every field the ledger calls replayed has to come back out of a real
// artifact with the value it went in with, and every field that does not come
// back has to be one the ledger already expects to stop.
//
// This is what makes a classification a claim rather than a comment: marking a
// new field replayed without teaching replayResult about it fails here, and
// quietly dropping a field replay used to rebuild fails here too.
func TestReplayedEvidenceSurvivesTheRealArtifactPath(t *testing.T) {
	live := maximalResult()
	assertNoZeroFields(t, "diagnostic.ProbeResult", reflect.ValueOf(live))
	assertNoZeroFields(t, "diagnostic.Target", reflect.ValueOf(*maximalTarget()))

	_, _, back := projected(t)
	lost := map[string]bool{}
	compareEvidence(t, "", reflect.ValueOf(live), reflect.ValueOf(back), lost)
	for key := range lost {
		d := evidenceProjection[key]
		if d.category == replayed {
			t.Errorf("%s is classified %q but did not survive the artifact round trip. Either teach "+
				"replayResult to rebuild it, or reclassify it and say why replay does not need it",
				key, replayed)
		}
	}
}

// The other side of the same contract. A field the ledger says stops at replay
// still has to reach the artifact, because "not rebuilt" and "not written" are
// different decisions and only one of them is a loss.
func TestPersistedEvidenceReachesTheArtifact(t *testing.T) {
	data, decoded, back := projected(t)
	check := decoded.Checks[0]
	if len(check.Observed.Routes) != 1 || len(check.Observed.Attempts) != 1 {
		t.Fatalf("the fixture row lost its structured evidence: %+v", check.Observed)
	}
	route, attempt := check.Observed.Routes[0], check.Observed.Attempts[0]
	for _, carried := range []struct {
		key  string
		got  any
		want any
	}{
		{"diagnostic.ProbeResult.Dur", check.DurationMs, int64(7)},
		{"snapshot.Check.Ran", check.Ran, true},
		{"snapshot.Check.Name", check.Name, "Public DNS"},
		{"snapshot.Check.Deps", strings.Join(check.Deps, ","), string(ProbeIface)},
		{"diagnostic.ProbeResult.Detail", check.Detail, "the second opinion disagreed"},
		{"diagnostic.ProbeResult.Fix", check.Fix, "check the configured resolver"},
		{"diagnostic.Attempt.Dur", attempt.DurationMs, int64(12)},
		{"diagnostic.Attempt.Err", attempt.Error, "connection refused"},
		{"diagnostic.RouteDecision.Prefix", route.Prefix, "10.20.0.0/16"},
		{"diagnostic.RouteDecision.TunnelKind", route.TunnelKind, "wireguard"},
		{"diagnostic.RouteDecision.Reason", route.Reason, string(RouteReasonMoreSpecific)},
	} {
		if carried.got != carried.want {
			t.Errorf("%s is classified %q but the artifact recorded %v, want %v",
				carried.key, evidenceProjection[carried.key].category, carried.got, carried.want)
		}
	}
	// Metric is the one that cannot be checked by value alone: absent and 0 are
	// different answers, so the artifact has to carry a present pointer.
	if route.Metric == nil || *route.Metric != 42 {
		t.Errorf("diagnostic.RouteDecision.Metric is classified %q but the artifact recorded %v",
			persisted, route.Metric)
	}
	// And the transient one has to be nowhere in the file at all.
	if strings.Contains(string(data), transientSentinel) {
		t.Errorf("diagnostic.ProbeResult.alternateDefaults is classified %q but its value reached the artifact:\n%s",
			transient, data)
	}
	// A field that stops at replay has to actually stop there, or the ledger is
	// describing code that no longer exists.
	if len(back.Routes) != 1 {
		t.Fatalf("replay rebuilt %d routes, want one", len(back.Routes))
	}
	if back.Routes[0].MetricKnown || back.Routes[0].Reason != "" || back.Routes[0].Prefix.IsValid() {
		t.Errorf("replay rebuilt route fields the ledger says it leaves in the artifact: %+v", back.Routes[0])
	}
}

// The forward half of the same guard, and the one a field with no runtime twin
// needs. A new field on the durable model classified as replayed would round
// trip as zero to zero and prove nothing, so this asks the opposite question:
// did BuildSnapshot put something in every field of every durable evidence
// type. A field nothing fills fails here, which is the signal that either the
// projection or the fixture has not been told about it.
func TestBuildSnapshotFillsEveryDurableEvidenceField(t *testing.T) {
	_, decoded, _ := projected(t)
	assertEveryFieldCarriesAValue(t, "snapshot.Snapshot.Checks", reflect.ValueOf(decoded.Checks[0]))
	assertEveryFieldCarriesAValue(t, "snapshot.Snapshot.Target", reflect.ValueOf(decoded.Target))
}

// assertEveryFieldCarriesAValue walks one durable evidence value and reports
// every classified field the fixture left at its zero value. It descends only
// into the types the ledger covers, and it reads the first element of a list,
// which is enough: the fixture carries exactly one of each.
func assertEveryFieldCarriesAValue(t *testing.T, key string, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			t.Errorf("the artifact carries no %s, so nothing under it is proved to survive BuildSnapshot", key)
			return
		}
		assertEveryFieldCarriesAValue(t, key, v.Elem())
	case reflect.Slice:
		if v.Len() == 0 {
			t.Errorf("the artifact carries an empty %s, so nothing in it is proved to survive BuildSnapshot", key)
			return
		}
		assertEveryFieldCarriesAValue(t, key, v.Index(0))
	case reflect.Struct:
		if !auditedNames[v.Type().String()] {
			return
		}
		for i := range v.NumField() {
			field, name := v.Field(i), fieldKey(v.Type(), i)
			if field.IsZero() {
				t.Errorf("%s reached the artifact at its zero value. Either BuildSnapshot does not write it, "+
					"or maximalResult does not exercise it: both hide whether it survives the boundary", name)
				continue
			}
			assertEveryFieldCarriesAValue(t, name, field)
		}
	}
}

// A replayed artifact is only evidence of anything if the fixture that made it
// had something in every field. This is the guard on that, and it walks the
// unexported fields too, since the cross-probe evidence lives there.
func assertNoZeroFields(t *testing.T, name string, v reflect.Value) {
	t.Helper()
	for i := range v.NumField() {
		if v.Field(i).IsZero() {
			t.Errorf("the projection fixture leaves %s.%s at its zero value, so the round trip proves nothing about it",
				name, v.Type().Field(i).Name)
		}
	}
}

// compareEvidence walks a live result and its replayed twin together and
// records the ledger key of every value that did not survive.
//
// A difference inside a type the ledger does not classify, such as a
// netip.Prefix's internals or the bytes of an address, is attributed to the
// classified field holding it. That is what keeps a failure readable: it names
// a decision a maintainer can make rather than a private struct member.
func compareEvidence(t *testing.T, key string, live, back reflect.Value, lost map[string]bool) {
	t.Helper()
	switch live.Kind() {
	case reflect.Struct:
		for i := range live.NumField() {
			inner := key
			if auditedNames[live.Type().String()] {
				inner = fieldKey(live.Type(), i)
			}
			compareEvidence(t, inner, live.Field(i), back.Field(i), lost)
		}
		return
	case reflect.Pointer:
		if live.IsNil() != back.IsNil() {
			lost[key] = true
			return
		}
		if !live.IsNil() {
			compareEvidence(t, key, live.Elem(), back.Elem(), lost)
		}
		return
	case reflect.Interface:
		if live.IsNil() != back.IsNil() {
			lost[key] = true
			return
		}
		// A different dynamic type is already a lost value, and descending into
		// one would compare fields that do not line up.
		if !live.IsNil() {
			if live.Elem().Type() != back.Elem().Type() {
				lost[key] = true
				return
			}
			compareEvidence(t, key, live.Elem(), back.Elem(), lost)
		}
		return
	case reflect.Slice, reflect.Array:
		if live.Len() != back.Len() {
			lost[key] = true
			return
		}
		for i := range live.Len() {
			compareEvidence(t, key, live.Index(i), back.Index(i), lost)
		}
		return
	case reflect.Map:
		if live.Len() != back.Len() {
			lost[key] = true
			return
		}
		for it := live.MapRange(); it.Next(); {
			other := back.MapIndex(it.Key())
			if !other.IsValid() {
				lost[key] = true
				return
			}
			compareEvidence(t, key, it.Value(), other, lost)
		}
		return
	}
	// Everything left is a leaf. Comparing a non-comparable one would panic, so
	// a type this walker cannot descend into is reported as a gap in the walker
	// rather than as a lost value.
	if !live.Type().Comparable() {
		t.Fatalf("%s holds %s, which this walker cannot compare; give compareEvidence a case that descends into it",
			key, live.Type())
	}
	if !live.Equal(back) {
		lost[key] = true
	}
}

// The walker has to compare what a map holds, not only how much it holds. A
// replayed map that keeps its size while its contents change is still a lost
// value, and nothing else in this file would notice.
func TestCompareEvidenceDetectsMapContentChanges(t *testing.T) {
	const key = "diagnostic.ProbeResult.alternateDefaults"
	for _, tc := range []struct {
		name string
		back map[string][]defaultRouteState
		lost bool
	}{
		{"same contents", map[string][]defaultRouteState{counterfactualIPv4: {{iface: transientSentinel}}}, false},
		{"same length, different key", map[string][]defaultRouteState{counterfactualIPv6: {{iface: transientSentinel}}}, true},
		{"same length, different value", map[string][]defaultRouteState{counterfactualIPv4: {{iface: "eth9"}}}, true},
		{"different length", map[string][]defaultRouteState{
			counterfactualIPv4: {{iface: transientSentinel}},
			counterfactualIPv6: {{iface: transientSentinel}},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			live, back := maximalResult(), maximalResult()
			back.alternateDefaults = tc.back
			lost := map[string]bool{}
			compareEvidence(t, "diagnostic.ProbeResult", reflect.ValueOf(live), reflect.ValueOf(back), lost)
			if lost[key] != tc.lost {
				t.Errorf("compareEvidence reported %s lost = %v, want %v", key, lost[key], tc.lost)
			}
			for other := range lost {
				if other != key {
					t.Errorf("compareEvidence blamed %s for a change to the map", other)
				}
			}
		})
	}
}
