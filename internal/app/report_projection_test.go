// The `netdoc --json` boundary is one hand-written projection: buildReport
// copies a live diagnostic model into the stable internal/report types a field
// at a time, and reportRoutes does the same for the route decisions under a
// row. That is deliberate, for the same reason the .ndoc conversion is written
// out by hand: the JSON document is a published contract, and letting it follow
// a runtime struct would turn a rename into a breaking change nobody chose.
//
// The cost is the same too. Nothing in the compiler ties the live model to the
// published one, so a new piece of evidence reaches the report only because
// somebody remembered buildReport exists. The published schema cannot close
// that hole: every optional key is still valid when it is absent, so a
// projection that quietly stops running leaves a document that validates
// perfectly and says less than the run knew.
//
// This file is the ledger that makes forgetting fail. Every field on both sides
// of buildReport carries one of the decisions below, and the behavioral tests
// read the same table, so a classification is a claim that gets checked rather
// than a comment.
//
// It is not the .ndoc ledger with different names. That boundary asks "does
// replay rebuild this", because the artifact exists to recompute a diagnosis.
// This one asks "does a consumer of the public document get to see this", which
// is a different question with different right answers: Detail and Fix stop at
// replay and are published here, and the interpretation Interpret reaches is
// published here as findings while the evidence behind it stays in the run.

package app

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
)

const (
	// published is a value that crosses buildReport into the public document,
	// possibly transformed on the way. Every one of these is proved below with
	// the transformation spelled out, so "it is published" is never taken on
	// trust.
	published = "published"
	// interpreted is live evidence the report publishes only through the
	// conclusion Interpret drew from it: a summary, a verdict, a finding. The
	// observation itself is deliberately not a key of its own.
	interpreted = "interpreted"
	// derived is a report field buildReport computes rather than copying from
	// any single live value.
	derived = "derived"
	// envelope is a report field whose value does not come from the diagnostic
	// model at all. It still has to name its owner.
	envelope = "envelope"
	// transient is run-time state that is consumed before a report exists.
	transient = "transient"
	// redundant is a field whose authoritative value is another field the
	// report already carries.
	redundant = "redundant"
	// absent is a field deliberately left out of the published document.
	absent = "absent"
)

// decision is one field's place at the report boundary. why is required for
// every category except published, because every one of those is a field a
// consumer of the JSON will never see, and the reason it stops is the thing a
// maintainer needs to read before deciding to move it.
type decision struct {
	category string
	why      string
}

// reportProjection classifies every field buildReport reads and every field it
// can write. Keys are reflect's own type names, so a renamed field shows up as
// an unclassified one plus a stale entry rather than as silence.
//
// The two halves are listed separately because they are two different
// questions. A live field asks "does this reach the document"; a report field
// asks "where does this value come from". A field can be a yes to the first and
// still need an answer to the second, which is exactly what keeps a key nobody
// fills any more from sitting in the schema looking supported.
var reportProjection = map[string]decision{
	// The probe list. buildReport iterates it rather than the results map, so
	// the identity and the display name of a row come from here.
	"diagnostic.Probe.ID":   {category: published},
	"diagnostic.Probe.Name": {category: published},
	"diagnostic.Probe.Deps": {category: absent, why: "the dependency graph as executed. The .ndoc artifact carries " +
		"it because a reader of a file has no probe list to rebuild it from; the report publishes rows in graph " +
		"order, which is the part a consumer reads, and has never published the edges."},
	"diagnostic.Probe.Run": {category: transient, why: "the probe body, a function value. It produced the " +
		"ProbeResult every row below is built from and has nothing left to say once the run is over."},
	"diagnostic.Probe.Reference": {category: absent, why: "whether this node dials Network Doctor's own reference " +
		"infrastructure. It decides which probes the graph builds, so what it concluded is already visible as the " +
		"set of rows the document carries."},

	// The target, which the report republishes as the parsed endpoint.
	"diagnostic.Target.Host":  {category: published},
	"diagnostic.Target.Port":  {category: published},
	"diagnostic.Target.Proto": {category: published},
	"diagnostic.Target.Raw": {category: absent, why: "the spelling the run was asked for, kept for the restart " +
		"prompt and the TUI's history. The report publishes the parsed endpoint, which is what a consumer branches " +
		"on; carrying the raw spelling beside it would put two statements of one target in the same document."},
	"diagnostic.Target.IP": {category: redundant, why: "non-nil only when the target is an IP literal, in which " +
		"case Host already holds that literal. target.host carries it either way."},
	"diagnostic.Target.PortExplicit": {category: absent, why: "whether the port was typed or came from a scheme " +
		"default. It is how the parser reached target.port, not what it reached, and the TUI reads it to offer an " +
		"ssh command. The document publishes the effective port."},

	// The live result. Everything here either reaches the document or says why
	// a consumer is not given it.
	"diagnostic.ProbeResult.Status":           {category: published},
	"diagnostic.ProbeResult.Cause":            {category: published},
	"diagnostic.ProbeResult.Families":         {category: published},
	"diagnostic.ProbeResult.Portal":           {category: published},
	"diagnostic.ProbeResult.Addrs":            {category: published},
	"diagnostic.ProbeResult.ResolverTargets":  {category: published},
	"diagnostic.ProbeResult.SelectedIP":       {category: published},
	"diagnostic.ProbeResult.Source":           {category: published},
	"diagnostic.ProbeResult.Iface":            {category: published},
	"diagnostic.ProbeResult.Network":          {category: published},
	"diagnostic.ProbeResult.Routes":           {category: published},
	"diagnostic.ProbeResult.Attempts":         {category: published},
	"diagnostic.ProbeResult.Dur":              {category: published},
	"diagnostic.ProbeResult.Detail":           {category: published},
	"diagnostic.ProbeResult.Fix":              {category: published},
	"diagnostic.ProbeResult.ConnectCleartext": {category: published},
	"diagnostic.ProbeResult.ID": {category: redundant, why: "the row's own idea of which probe it is. buildReport " +
		"keys rows by the Probe it iterated, so a result that disagreed with the node that produced it could not " +
		"reach the document under the wrong id."},
	"diagnostic.ProbeResult.DNSNotFound": {category: interpreted, why: "the resolver having answered with no " +
		"records. Interpret reads it to reach dns_name_not_found and to build the DNS counterfactual, and the " +
		"document publishes that conclusion as a finding; the row itself already shows an empty addrs beside a " +
		"status a consumer can branch on."},
	"diagnostic.ProbeResult.causeFamily": {category: interpreted, why: "the address family that supplied Cause. " +
		"Interpret carries it into causal evidence as the value of a family observation, which is where the " +
		"document publishes it, and remediation reads it to pick the route a competitor is worth naming on."},
	"diagnostic.ProbeResult.downgraded": {category: interpreted, why: "a direct-egress failure that downgradeEgress " +
		"rewrote to Warn because a proxy worked. The row publishes the status it ended at; whether that status was " +
		"rewritten is a fact about the truth table, and Interpret reads it to reach proxy_only_network."},
	"diagnostic.ProbeResult.answerComparison": {category: interpreted, why: "what reconcileDNS concluded when it " +
		"compared two resolvers' answers. The document publishes the conclusion as the dns_disagreement finding " +
		"and its counterfactual, and both rows' addrs are already there for a consumer that wants to compare them."},
	"diagnostic.ProbeResult.timedOut": {category: interpreted, why: "an HTTP or HTTPS failure that was a timeout. " +
		"It is half the path-MTU correlation Interpret draws, and the document publishes that as the " +
		"probable_path_mtu_problem finding."},
	"diagnostic.ProbeResult.clockOffset": {category: interpreted, why: "this machine's clock against a reference " +
		"endpoint's Date header. Interpret reads it only to separate a TLS clock skew from a bad certificate, and " +
		"the document publishes that separation as the finding id."},
	"diagnostic.ProbeResult.resolver": {category: interpreted, why: "the second-opinion DNS server the public row " +
		"queried, kept so the cross-probe pass can name it in a sentence. It reaches the document inside detail."},
	"diagnostic.ProbeResult.ifaceAmbiguous": {category: interpreted, why: "the source address having resolved to " +
		"more than one interface. Iface carries the display text for that case and is published; the flag exists " +
		"so the warning path is not triggered by a real interface whose name happens to match that text."},
	"diagnostic.ProbeResult.alternateDefaults": {category: transient, why: "reference-path selection state. " +
		"reconcilePreferredPath consumes it inside Finalize, before any report is built, and what it concluded is " +
		"published as the direct-egress row's cause."},

	"diagnostic.FamilyConnectivity.IPv4": {category: published},
	"diagnostic.FamilyConnectivity.IPv6": {category: published},
	"diagnostic.Portal.RedirectURL":      {category: published},

	"diagnostic.Attempt.IP":      {category: published},
	"diagnostic.Attempt.Dur":     {category: published},
	"diagnostic.Attempt.Err":     {category: published},
	"diagnostic.Attempt.Cause":   {category: published},
	"diagnostic.Attempt.Aborted": {category: published},

	"diagnostic.RouteDecision.Destination": {category: published},
	"diagnostic.RouteDecision.Family":      {category: published},
	"diagnostic.RouteDecision.Iface":       {category: published},
	"diagnostic.RouteDecision.Gateway":     {category: published},
	"diagnostic.RouteDecision.Source":      {category: published},
	"diagnostic.RouteDecision.Prefix":      {category: published},
	"diagnostic.RouteDecision.Metric":      {category: published},
	"diagnostic.RouteDecision.MetricKnown": {category: published},
	"diagnostic.RouteDecision.Table":       {category: published},
	"diagnostic.RouteDecision.TableKnown":  {category: published},
	"diagnostic.RouteDecision.MTU":         {category: published},
	"diagnostic.RouteDecision.Tunnel":      {category: published},
	"diagnostic.RouteDecision.TunnelKind":  {category: published},
	"diagnostic.RouteDecision.Unreachable": {category: published},
	"diagnostic.RouteDecision.Reason":      {category: published},
	"diagnostic.RouteDecision.Competing":   {category: published},
	"diagnostic.CompetingRoute.Iface":      {category: published},
	"diagnostic.CompetingRoute.Metric":     {category: published},

	// The finished interpretation. buildReport runs Interpret once and reads
	// every diagnostic field of the document off that one answer.
	"diagnostic.Diagnosis.Verdict":  {category: published},
	"diagnostic.Diagnosis.Summary":  {category: published},
	"diagnostic.Diagnosis.Findings": {category: published},
	"diagnostic.Diagnosis.Blamed": {category: redundant, why: "the row a screen should put a cursor on, which " +
		"falls back to the first failed row when the diagnosis names none. The document publishes both halves " +
		"already: findings[0].focus is the row the diagnosis actually names, and failed_stage is the fallback."},

	"diagnostic.DiagnosisFinding.ID":             {category: published},
	"diagnostic.DiagnosisFinding.Focus":          {category: published},
	"diagnostic.DiagnosisFinding.Confidence":     {category: published},
	"diagnostic.DiagnosisFinding.Evidence":       {category: published},
	"diagnostic.DiagnosisFinding.Counterfactual": {category: published},
	"diagnostic.DiagnosisFinding.Verdict": {category: absent, why: "this finding's own broad class. The document " +
		"publishes one verdict for the run, which is the primary finding's, plus every finding's stable id. A " +
		"per-finding severity key has never been part of the v1 document, and a consumer that wants one branches " +
		"on the id."},
	"diagnostic.DiagnosisFinding.Summary": {category: absent, why: "this finding's own sentence. The document " +
		"publishes the run's summary, which is the primary finding's, and prose is the half that gets reworded: " +
		"the finding id is what a consumer is meant to read. The TUI renders the rest from the same diagnosis."},

	"diagnostic.CausalEvidence.Kind":                {category: published},
	"diagnostic.CausalEvidence.Check":               {category: published},
	"diagnostic.CausalEvidence.Observation":         {category: published},
	"diagnostic.CausalEvidence.Value":               {category: published},
	"diagnostic.CausalEvidence.Candidate":           {category: published},
	"diagnostic.CausalEvidence.Reason":              {category: published},
	"diagnostic.Counterfactual.Variable":            {category: published},
	"diagnostic.Counterfactual.Alternatives":        {category: published},
	"diagnostic.CounterfactualAlternative.Value":    {category: published},
	"diagnostic.CounterfactualAlternative.Outcome":  {category: published},
	"diagnostic.CounterfactualAlternative.Evidence": {category: published},
	"diagnostic.Remediation.ID":                     {category: published},
	"diagnostic.Remediation.Action":                 {category: published},
	"diagnostic.Remediation.Why":                    {category: published},
	"diagnostic.Remediation.Steps":                  {category: published},
	"diagnostic.Remediation.Command":                {category: published},
	"diagnostic.Remediation.Expect":                 {category: published},

	// The published document. Everything here either names the live value it
	// came from or says who fills it instead.
	"report.Report.Target":   {category: published},
	"report.Report.Checks":   {category: published},
	"report.Report.Summary":  {category: published},
	"report.Report.Verdict":  {category: published},
	"report.Report.Findings": {category: published},
	"report.Report.OK": {category: derived, why: "no row failed and every row reported, computed across the whole " +
		"probe list rather than copied from one result. TestBuildReport and the INCOMPLETE guards own its meaning."},
	"report.Report.FailedStage": {category: derived, why: "the id of the first row that failed, which is a fact " +
		"about the order of the run rather than a field of any result."},
	"report.Report.Version": {category: envelope, why: "the netdoc build that produced the document, from the " +
		"package version var that -ldflags sets. It is not a probe observation, and via_test pins that a remote " +
		"run publishes the worker's build rather than this one's."},
	"report.Report.Ts": {category: envelope, why: "the pass timestamp, set by runHeadless and only under " +
		"--json --watch, where the output is a stream that needs one. buildReport never writes it, so a one-shot " +
		"document stays byte-identical to what it has always been. TestRunJSONWatchStreamsOnePerLine owns it."},

	"report.Target.Host":     {category: published},
	"report.Target.Port":     {category: published},
	"report.Target.Protocol": {category: published},

	"report.Check.ID":               {category: published},
	"report.Check.Name":             {category: published},
	"report.Check.Status":           {category: published},
	"report.Check.Cause":            {category: published},
	"report.Check.Families":         {category: published},
	"report.Check.Ms":               {category: published},
	"report.Check.Detail":           {category: published},
	"report.Check.Fix":              {category: published},
	"report.Check.Addrs":            {category: published},
	"report.Check.ResolverTargets":  {category: published},
	"report.Check.SelectedIP":       {category: published},
	"report.Check.Source":           {category: published},
	"report.Check.Iface":            {category: published},
	"report.Check.Network":          {category: published},
	"report.Check.Portal":           {category: published},
	"report.Check.Attempts":         {category: published},
	"report.Check.Routes":           {category: published},
	"report.Check.ConnectCleartext": {category: published},

	"report.Families.IPv4":      {category: published},
	"report.Families.IPv6":      {category: published},
	"report.Portal.RedirectURL": {category: published},

	"report.Attempt.IP":      {category: published},
	"report.Attempt.Ms":      {category: published},
	"report.Attempt.Err":     {category: published},
	"report.Attempt.Cause":   {category: published},
	"report.Attempt.Aborted": {category: published},

	"report.Route.Destination":        {category: published},
	"report.Route.Family":             {category: published},
	"report.Route.Interface":          {category: published},
	"report.Route.Gateway":            {category: published},
	"report.Route.Source":             {category: published},
	"report.Route.Prefix":             {category: published},
	"report.Route.Metric":             {category: published},
	"report.Route.Table":              {category: published},
	"report.Route.TableKnown":         {category: published},
	"report.Route.InterfaceMTU":       {category: published},
	"report.Route.Tunnel":             {category: published},
	"report.Route.TunnelKind":         {category: published},
	"report.Route.Unreachable":        {category: published},
	"report.Route.Reason":             {category: published},
	"report.Route.Competing":          {category: published},
	"report.CompetingRoute.Interface": {category: published},
	"report.CompetingRoute.Metric":    {category: published},

	"report.Finding.ID":             {category: published},
	"report.Finding.Focus":          {category: published},
	"report.Finding.Confidence":     {category: published},
	"report.Finding.Evidence":       {category: published},
	"report.Finding.CausalEvidence": {category: published},
	"report.Finding.Counterfactual": {category: published},
	"report.Finding.Remediation":    {category: published},

	"report.CausalEvidence.Kind":                {category: published},
	"report.CausalEvidence.Check":               {category: published},
	"report.CausalEvidence.Observation":         {category: published},
	"report.CausalEvidence.Value":               {category: published},
	"report.CausalEvidence.Candidate":           {category: published},
	"report.CausalEvidence.Reason":              {category: published},
	"report.Counterfactual.Variable":            {category: published},
	"report.Counterfactual.Alternatives":        {category: published},
	"report.CounterfactualAlternative.Value":    {category: published},
	"report.CounterfactualAlternative.Outcome":  {category: published},
	"report.CounterfactualAlternative.Evidence": {category: published},
	"report.Remediation.ID":                     {category: published},
	"report.Remediation.Action":                 {category: published},
	"report.Remediation.Why":                    {category: published},
	"report.Remediation.Steps":                  {category: published},
	"report.Remediation.Command":                {category: published},
	"report.Remediation.Expect":                 {category: published},
}

// rowSourceTypes are the live values buildReport copies a row out of. They are
// separated from the interpretation below because the two halves are proved
// differently: a row field is a stringification this test states in full, and a
// diagnosis field is a value the test recomputes and compares.
func rowSourceTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(diagnostic.Probe{}), reflect.TypeOf(diagnostic.Target{}),
		reflect.TypeOf(diagnostic.ProbeResult{}), reflect.TypeOf(diagnostic.FamilyConnectivity{}),
		reflect.TypeOf(diagnostic.Portal{}), reflect.TypeOf(diagnostic.Attempt{}),
		reflect.TypeOf(diagnostic.RouteDecision{}), reflect.TypeOf(diagnostic.CompetingRoute{}),
	}
}

// diagnosisSourceTypes are the interpretation buildReport publishes as
// findings, plus the advice hanging off the primary one.
func diagnosisSourceTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(diagnostic.Diagnosis{}), reflect.TypeOf(diagnostic.DiagnosisFinding{}),
		reflect.TypeOf(diagnostic.CausalEvidence{}), reflect.TypeOf(diagnostic.Counterfactual{}),
		reflect.TypeOf(diagnostic.CounterfactualAlternative{}), reflect.TypeOf(diagnostic.Remediation{}),
	}
}

// reportTypes are the published document, every type reachable from the root.
func reportTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(report.Report{}), reflect.TypeOf(report.Target{}), reflect.TypeOf(report.Check{}),
		reflect.TypeOf(report.Families{}), reflect.TypeOf(report.Portal{}), reflect.TypeOf(report.Attempt{}),
		reflect.TypeOf(report.Route{}), reflect.TypeOf(report.CompetingRoute{}), reflect.TypeOf(report.Finding{}),
		reflect.TypeOf(report.CausalEvidence{}), reflect.TypeOf(report.Counterfactual{}),
		reflect.TypeOf(report.CounterfactualAlternative{}), reflect.TypeOf(report.Remediation{}),
	}
}

func auditedReportTypes() []reflect.Type {
	return append(append(rowSourceTypes(), diagnosisSourceTypes()...), reportTypes()...)
}

func projectionKey(typ reflect.Type, i int) string { return typ.String() + "." + typ.Field(i).Name }

// reportAudited is the report half by name, which is how the coverage walk
// knows whether to descend into a struct or stop at it.
var reportAudited = func() map[string]bool {
	names := map[string]bool{}
	for _, typ := range reportTypes() {
		names[typ.String()] = true
	}
	return names
}()

// The structural half. A field added to either side of buildReport has to be
// given a decision here, which is the whole point: the author of the new field
// is the person who knows whether a consumer of the public document should see
// it, and saying "no" costs them one sentence rather than nothing at all.
func TestEveryFieldIsClassifiedAtTheReportBoundary(t *testing.T) {
	known := map[string]bool{}
	for _, typ := range auditedReportTypes() {
		for i := range typ.NumField() {
			key, field := projectionKey(typ, i), typ.Field(i)
			known[key] = true
			d, ok := reportProjection[key]
			if !ok {
				t.Errorf("%s sits at the --json boundary unclassified. Decide what it is and add it to "+
					"reportProjection: %q (a consumer sees it), %q (only the conclusion drawn from it is "+
					"published), %q (buildReport computes it), %q (filled outside buildReport), %q (consumed "+
					"before a report exists), %q (another published field is authoritative), or %q (left out "+
					"on purpose)",
					key, published, interpreted, derived, envelope, transient, redundant, absent)
				continue
			}
			switch d.category {
			case published:
				// An unexported field cannot be read from this package, so
				// buildReport cannot be copying one. Exporting a field later
				// lands here and asks for the proof below.
				if !field.IsExported() {
					t.Errorf("%s is unexported and classified %q, which buildReport cannot do", key, published)
				}
			case interpreted, derived, envelope, transient, redundant, absent:
				if d.why == "" {
					t.Errorf("%s is classified %q with no reason. A field a consumer of the JSON never sees has "+
						"to say why", key, d.category)
				}
			default:
				t.Errorf("%s has unknown classification %q", key, d.category)
			}
		}
	}
	for key := range reportProjection {
		if !known[key] {
			t.Errorf("reportProjection classifies %s, which is no longer a field", key)
		}
	}
}

// maximalRow is one live result carrying a distinctive value in every exported
// field a probe can fill. Nothing here is a round number shared with another
// field: a projection that read Source where it meant SelectedIP, or dropped a
// pointer presence bit, has to produce a value this fixture can tell apart from
// the right one.
//
// The route is deliberately awkward. An unreachable destination that still
// names a gateway is not a shape a kernel usually reports, but every field of a
// route decision has to carry something or the projection of that field is
// proved by nothing, and a known metric of 0 would be indistinguishable from an
// absent one.
func maximalRow() diagnostic.ProbeResult {
	return diagnostic.ProbeResult{
		ID:     diagnostic.ProbeTargetTCP,
		Status: diagnostic.StatusWarn,
		Cause:  diagnostic.ConnectionCauseRefused,
		Families: &diagnostic.FamilyConnectivity{
			IPv4: diagnostic.FamilyReachable, IPv6: diagnostic.FamilyUnreachable,
		},
		Portal:          &diagnostic.Portal{RedirectURL: "http://portal.example/fixture-signin"},
		Addrs:           []net.IP{net.ParseIP("192.0.2.71"), net.ParseIP("2001:db8::71")},
		DNSNotFound:     true,
		ResolverTargets: []string{"192.0.2.53:5353"},
		SelectedIP:      net.ParseIP("192.0.2.71"),
		Source:          net.ParseIP("198.51.100.72"),
		Iface:           "fixture-eth0",
		Network:         "Fixture Wifi",
		Routes: []diagnostic.RouteDecision{{
			Destination: net.ParseIP("203.0.113.74"),
			Family:      "ipv4",
			Iface:       "fixture-wg0",
			Gateway:     net.ParseIP("10.75.0.1"),
			Source:      net.ParseIP("10.75.0.76"),
			Prefix:      netip.MustParsePrefix("10.75.0.0/16"),
			Metric:      77, MetricKnown: true,
			Table: "table 51820", TableKnown: true,
			MTU:    1378,
			Tunnel: diagnostic.TunnelKnown, TunnelKind: "fixture-wireguard",
			Unreachable: true,
			Reason:      diagnostic.RouteReasonMoreSpecific,
			Competing:   []diagnostic.CompetingRoute{{Iface: "fixture-wlan0", Metric: 79}},
		}},
		Attempts: []diagnostic.Attempt{{
			IP:  net.ParseIP("203.0.113.73"),
			Dur: 891*time.Millisecond + 400*time.Microsecond,
			Err: errors.New("fixture attempt failure"), Cause: diagnostic.ConnectionCauseTimeout,
			Aborted: true,
		}},
		// Not a round number of milliseconds, so the floored conversion is
		// proved rather than assumed: a projection that rounded or that
		// published nanoseconds would not land on this.
		Dur:              4567*time.Millisecond + 890*time.Microsecond,
		Detail:           "fixture detail sentence",
		Fix:              "fixture fix sentence",
		ConnectCleartext: true,
	}
}

// maximalRowScenario is the fixture as a run: one probe, one result, one
// target, so every value below is unambiguous about which row it came from.
func maximalRowScenario(t *testing.T) reportScenario {
	t.Helper()
	// The real parser, so the target fixture cannot drift from a target a user
	// can actually ask for. An IP literal with an explicit port and a scheme is
	// the one spelling that fills every field of diagnostic.Target at once.
	target, err := diagnostic.ParseTarget("https://[2001:db8::c0de]:8443")
	if err != nil {
		t.Fatal(err)
	}
	return reportScenario{
		name:    "maximal row",
		target:  target,
		probes:  []diagnostic.Probe{{ID: diagnostic.ProbeTargetTCP, Name: "Fixture TCP row", Deps: []diagnostic.ProbeID{diagnostic.ProbeIface}, Reference: true}},
		results: map[diagnostic.ProbeID]diagnostic.ProbeResult{diagnostic.ProbeTargetTCP: maximalRow()},
	}
}

// ruledOutScenario is the run whose evidence names an alternative it excluded.
// A TLS handshake that failed on the name, over a TCP connection that worked,
// is the shape that rules out tls_tcp_unreachable, and a ruled-out item is the
// only one that carries a candidate.
func ruledOutScenario() reportScenario {
	target := &diagnostic.Target{Host: "example.com", Port: 443, Proto: diagnostic.ProtoTLSHTTP}
	return reportScenario{
		name:   "tls name ruled out the unreachable candidate",
		target: target,
		probes: []diagnostic.Probe{
			probe(diagnostic.ProbeIface, "Interface"),
			probe(diagnostic.ProbeInternet, "Internet (TCP egress)"),
			probe(diagnostic.ProbeDNS, "DNS example.com"),
			probe(diagnostic.ProbeTargetTCP, "TCP example.com:443"),
			probe(diagnostic.ProbeTLS, "TLS example.com"),
		},
		results: map[diagnostic.ProbeID]diagnostic.ProbeResult{
			diagnostic.ProbeIface:     {Status: diagnostic.StatusPass, Dur: time.Millisecond, Detail: "interface wlan0 is up"},
			diagnostic.ProbeInternet:  {Status: diagnostic.StatusPass, Dur: 30 * time.Millisecond, Detail: "direct egress works"},
			diagnostic.ProbeDNS:       {Status: diagnostic.StatusPass, Dur: 12 * time.Millisecond, Detail: "resolved"},
			diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusPass, Dur: 20 * time.Millisecond, Detail: "connected"},
			diagnostic.ProbeTLS: {
				Status: diagnostic.StatusFail, Dur: 40 * time.Millisecond, Detail: "certificate is for another name",
				Cause: diagnostic.TLSCauseHostnameMismatch,
			},
		},
	}
}

// projectionScenarios are every run the two completeness walks read. The
// schema suite's scenarios are reused rather than restated, because they are
// already the set that reaches the document's nested structures, and the two
// fixtures above add the shapes they do not cover: a row with every field
// filled at once, and evidence that names a candidate it excluded.
func projectionScenarios(t *testing.T) []reportScenario {
	t.Helper()
	return append(reportScenarios(), maximalRowScenario(t), ruledOutScenario())
}

// crossed asserts one projection and records that the field it names has been
// proved. want is written as the transformation buildReport is supposed to have
// performed on the live value, never as a literal copied beside the fixture, so
// reading the line tells you what the boundary is expected to do.
func crossed(t *testing.T, proven map[string]bool, key string, got, want any) {
	t.Helper()
	proven[key] = true
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s is classified %q and the report carries %#v, want %#v", key, published, got, want)
	}
}

// TestEveryPublishedFieldCrossesTheReportBoundary is the behavioral half, and
// the reason a classification here is a claim rather than a comment. It proves
// each side separately and then insists that nothing classified published was
// left unproved, so marking a new field published without wiring it through
// buildReport fails, and so does quietly dropping a projection that used to run.
func TestEveryPublishedFieldCrossesTheReportBoundary(t *testing.T) {
	proven := map[string]bool{}
	t.Run("row", func(t *testing.T) { proveRowProjection(t, proven) })
	t.Run("diagnosis", func(t *testing.T) { proveDiagnosisProjection(t, proven) })
	t.Run("document", func(t *testing.T) { proveDocumentIsFilled(t, proven) })

	for key, d := range reportProjection {
		if d.category == published && !proven[key] {
			t.Errorf("%s is classified %q and nothing proved it crosses. Either wire it through buildReport and "+
				"extend the proof beside its neighbors, or reclassify it and say why a consumer does not get it",
				key, published)
		}
	}
}

// proveRowProjection runs the maximal fixture through the real builder and
// states, field by field, what the published row is supposed to hold. Every
// transformation the boundary performs is written out here: an address becomes
// its string, a duration becomes floored milliseconds, a typed enum becomes its
// underlying string, an error becomes its message, and a metric plus its
// presence bit become an optional number.
func proveRowProjection(t *testing.T, proven map[string]bool) {
	sc := maximalRowScenario(t)
	live := sc.results[diagnostic.ProbeTargetTCP]
	assertFixtureIsFullyPopulated(t, live, *sc.target)

	rep := buildReport(sc.target, sc.probes, sc.results)
	if len(rep.Checks) != 1 {
		t.Fatalf("the fixture built %d rows, want one", len(rep.Checks))
	}
	c := rep.Checks[0]

	// The document a consumer receives has to be a legal one, or everything
	// below is proving the shape of a report nobody would accept.
	if err := validateJSON(compileReportSchema(t), mustMarshal(t, rep)); err != nil {
		t.Fatalf("the maximal fixture does not validate against the published schema: %v", err)
	}

	crossed(t, proven, "diagnostic.Probe.ID", c.ID, string(sc.probes[0].ID))
	crossed(t, proven, "diagnostic.Probe.Name", c.Name, sc.probes[0].Name)

	if rep.Target == nil {
		t.Fatal("the fixture published no target")
	}
	crossed(t, proven, "diagnostic.Target.Host", rep.Target.Host, sc.target.Host)
	crossed(t, proven, "diagnostic.Target.Port", rep.Target.Port, sc.target.Port)
	crossed(t, proven, "diagnostic.Target.Proto", rep.Target.Protocol, sc.target.Proto.String())
	crossed(t, proven, "report.Target.Host", rep.Target.Host, "2001:db8::c0de")
	crossed(t, proven, "report.Target.Port", rep.Target.Port, 8443)
	crossed(t, proven, "report.Target.Protocol", rep.Target.Protocol, "tls+http")

	crossed(t, proven, "diagnostic.ProbeResult.Status", c.Status, live.Status.String())
	crossed(t, proven, "diagnostic.ProbeResult.Cause", c.Cause, live.Cause)
	crossed(t, proven, "diagnostic.ProbeResult.Detail", c.Detail, live.Detail)
	crossed(t, proven, "diagnostic.ProbeResult.Fix", c.Fix, live.Fix)
	crossed(t, proven, "diagnostic.ProbeResult.ResolverTargets", c.ResolverTargets, live.ResolverTargets)
	crossed(t, proven, "diagnostic.ProbeResult.Iface", c.Iface, live.Iface)
	crossed(t, proven, "diagnostic.ProbeResult.Network", c.Network, live.Network)
	crossed(t, proven, "diagnostic.ProbeResult.ConnectCleartext", c.ConnectCleartext, live.ConnectCleartext)
	crossed(t, proven, "diagnostic.ProbeResult.Addrs", c.Addrs, []string{"192.0.2.71", "2001:db8::71"})
	crossed(t, proven, "diagnostic.ProbeResult.SelectedIP", c.SelectedIP, live.SelectedIP.String())
	crossed(t, proven, "diagnostic.ProbeResult.Source", c.Source, live.Source.String())
	// 4567.89ms, published as the whole milliseconds that actually elapsed.
	crossed(t, proven, "diagnostic.ProbeResult.Dur", c.Ms, int64(4567))

	if c.Families == nil {
		t.Fatal("the fixture published no address families")
	}
	crossed(t, proven, "diagnostic.ProbeResult.Families", c.Families,
		&report.Families{IPv4: live.Families.IPv4, IPv6: live.Families.IPv6})
	crossed(t, proven, "diagnostic.FamilyConnectivity.IPv4", c.Families.IPv4, live.Families.IPv4)
	crossed(t, proven, "diagnostic.FamilyConnectivity.IPv6", c.Families.IPv6, live.Families.IPv6)

	if c.Portal == nil {
		t.Fatal("the fixture published no portal")
	}
	crossed(t, proven, "diagnostic.ProbeResult.Portal", c.Portal, &report.Portal{RedirectURL: live.Portal.RedirectURL})
	crossed(t, proven, "diagnostic.Portal.RedirectURL", c.Portal.RedirectURL, live.Portal.RedirectURL)

	if len(c.Attempts) != 1 {
		t.Fatalf("the fixture published %d attempts, want one", len(c.Attempts))
	}
	a, la := c.Attempts[0], live.Attempts[0]
	crossed(t, proven, "diagnostic.ProbeResult.Attempts", len(c.Attempts), len(live.Attempts))
	crossed(t, proven, "diagnostic.Attempt.IP", a.IP, la.IP.String())
	crossed(t, proven, "diagnostic.Attempt.Dur", a.Ms, int64(891))
	crossed(t, proven, "diagnostic.Attempt.Err", a.Err, la.Err.Error())
	crossed(t, proven, "diagnostic.Attempt.Cause", a.Cause, la.Cause)
	crossed(t, proven, "diagnostic.Attempt.Aborted", a.Aborted, la.Aborted)

	if len(c.Routes) != 1 {
		t.Fatalf("the fixture published %d routes, want one", len(c.Routes))
	}
	r, lr := c.Routes[0], live.Routes[0]
	crossed(t, proven, "diagnostic.ProbeResult.Routes", len(c.Routes), len(live.Routes))
	crossed(t, proven, "diagnostic.RouteDecision.Destination", r.Destination, lr.Destination.String())
	crossed(t, proven, "diagnostic.RouteDecision.Family", r.Family, lr.Family)
	crossed(t, proven, "diagnostic.RouteDecision.Iface", r.Interface, lr.Iface)
	crossed(t, proven, "diagnostic.RouteDecision.Gateway", r.Gateway, lr.Gateway.String())
	crossed(t, proven, "diagnostic.RouteDecision.Source", r.Source, lr.Source.String())
	crossed(t, proven, "diagnostic.RouteDecision.Prefix", r.Prefix, lr.Prefix.String())
	crossed(t, proven, "diagnostic.RouteDecision.Table", r.Table, lr.Table)
	crossed(t, proven, "diagnostic.RouteDecision.TableKnown", r.TableKnown, lr.TableKnown)
	crossed(t, proven, "diagnostic.RouteDecision.MTU", r.InterfaceMTU, lr.MTU)
	crossed(t, proven, "diagnostic.RouteDecision.Tunnel", r.Tunnel, string(lr.Tunnel))
	crossed(t, proven, "diagnostic.RouteDecision.TunnelKind", r.TunnelKind, lr.TunnelKind)
	crossed(t, proven, "diagnostic.RouteDecision.Unreachable", r.Unreachable, lr.Unreachable)
	crossed(t, proven, "diagnostic.RouteDecision.Reason", r.Reason, string(lr.Reason))
	crossed(t, proven, "diagnostic.RouteDecision.Competing", len(r.Competing), len(lr.Competing))
	crossed(t, proven, "diagnostic.CompetingRoute.Iface", r.Competing[0].Interface, lr.Competing[0].Iface)
	crossed(t, proven, "diagnostic.CompetingRoute.Metric", r.Competing[0].Metric, lr.Competing[0].Metric)

	// The metric is the one field a value alone cannot prove: absent and 0 are
	// different answers, so the presence bit is what decides whether the key
	// exists and the number is what it holds.
	if r.Metric == nil {
		t.Fatalf("diagnostic.RouteDecision.MetricKnown is classified %q and the report omitted the metric", published)
	}
	crossed(t, proven, "diagnostic.RouteDecision.Metric", *r.Metric, lr.Metric)

	unknown := live
	unknown.Routes = []diagnostic.RouteDecision{{Destination: lr.Destination, Metric: 77}}
	bare := buildReport(sc.target, sc.probes,
		map[diagnostic.ProbeID]diagnostic.ProbeResult{diagnostic.ProbeTargetTCP: unknown})
	if got := bare.Checks[0].Routes[0].Metric; got != nil {
		t.Errorf("diagnostic.RouteDecision.MetricKnown was false and the report published a metric of %d", *got)
	}
	proven["diagnostic.RouteDecision.MetricKnown"] = true
}

// assertFixtureIsFullyPopulated is the guard on the proof above: a field left
// at its zero value would compare equal to a projection that never ran.
// Unexported fields are not reachable from this package, which is the same
// reason the structural test refuses to let one be classified published;
// internal/diagnostic/projection_test.go is where those are exercised.
func assertFixtureIsFullyPopulated(t *testing.T, live diagnostic.ProbeResult, target diagnostic.Target) {
	t.Helper()
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.Slice:
			for i := range v.Len() {
				walk(v.Index(i))
			}
		case reflect.Struct:
			for i := range v.NumField() {
				field := v.Type().Field(i)
				if !field.IsExported() {
					continue
				}
				key := projectionKey(v.Type(), i)
				if reportProjection[key].category != published {
					continue
				}
				if v.Field(i).IsZero() {
					t.Errorf("the fixture leaves %s at its zero value, so its projection is proved by nothing", key)
					continue
				}
				walk(v.Field(i))
			}
		}
	}
	walk(reflect.ValueOf(live))
	walk(reflect.ValueOf(target))
}

// proveDiagnosisProjection asks the different question the interpretation half
// needs. Findings are not stringified observations, they are one Diagnosis that
// buildReport computes internally, so the proof is to recompute it from the
// same inputs and hold the document to it value for value. That keeps the test
// honest across rewordings of the prose, which the finding ids deliberately
// outlive, and still fails the moment a field stops being copied.
func proveDiagnosisProjection(t *testing.T, proven map[string]bool) {
	seen := map[string]bool{}
	for _, sc := range projectionScenarios(t) {
		t.Run(sc.name, func(t *testing.T) {
			order := make([]diagnostic.ProbeID, len(sc.probes))
			for i, p := range sc.probes {
				order[i] = p.ID
			}
			d := diagnostic.Interpret(sc.target, order, sc.results)
			rep := buildReport(sc.target, sc.probes, sc.results)

			crossed(t, proven, "diagnostic.Diagnosis.Summary", rep.Summary, d.Summary)
			crossed(t, proven, "diagnostic.Diagnosis.Verdict", rep.Verdict, d.Verdict)
			crossed(t, proven, "diagnostic.Diagnosis.Findings", len(rep.Findings), len(d.Findings))
			seen["diagnostic.Diagnosis.Summary"] = true
			seen["diagnostic.Diagnosis.Verdict"] = true
			seen["diagnostic.Diagnosis.Findings"] = true

			for i, f := range d.Findings {
				got := rep.Findings[i]
				crossed(t, proven, "diagnostic.DiagnosisFinding.ID", got.ID, string(f.ID))
				crossed(t, proven, "diagnostic.DiagnosisFinding.Focus", got.Focus, string(f.Focus))
				crossed(t, proven, "diagnostic.DiagnosisFinding.Confidence", got.Confidence, string(f.Confidence))
				crossed(t, proven, "diagnostic.DiagnosisFinding.Evidence", got.Evidence, evidenceRowStrings(f))
				proveCausalEvidence(t, proven, got.CausalEvidence, f.Evidence)
				proveCounterfactual(t, proven, got.Counterfactual, f.Counterfactual)
				recordFinding(seen, f)
				if i == 0 {
					proveRemediation(t, proven, seen, got.Remediation, d, sc.results)
				}
			}
		})
	}
	// A field the comparison above never saw a value in was compared zero to
	// zero, which proves nothing. The scenarios have to between them produce a
	// run rich enough to fill each one.
	for _, typ := range diagnosisSourceTypes() {
		for i := range typ.NumField() {
			key := projectionKey(typ, i)
			if reportProjection[key].category == published && !seen[key] {
				t.Errorf("no scenario produced a %s, so the comparison above compared it zero to zero. Add a run "+
					"that reaches it, or say why the report does not carry it", key)
			}
		}
	}
}

// evidenceRowStrings and causalEvidence restate the two projections buildReport
// performs on a finding's evidence: the compatible row-id list, and the typed
// items beside it.
func evidenceRowStrings(f diagnostic.DiagnosisFinding) []string {
	var out []string
	for _, id := range f.EvidenceRows() {
		out = append(out, string(id))
	}
	return out
}

func causalEvidence(items []diagnostic.CausalEvidence) []report.CausalEvidence {
	var out []report.CausalEvidence
	for _, e := range items {
		out = append(out, report.CausalEvidence{
			Kind: string(e.Kind), Check: string(e.Check), Observation: string(e.Observation),
			Value: e.Value, Candidate: string(e.Candidate), Reason: string(e.Reason),
		})
	}
	return out
}

// proveCausalEvidence compares the whole projected slice at once, which checks
// all six members of every item together. The members are then named one by
// one, so a seventh cannot be added to CausalEvidence without either landing in
// the restatement above or failing the completeness check.
func proveCausalEvidence(t *testing.T, proven map[string]bool, got []report.CausalEvidence, live []diagnostic.CausalEvidence) {
	t.Helper()
	for _, name := range []string{"Kind", "Check", "Observation", "Value", "Candidate", "Reason"} {
		proven["diagnostic.CausalEvidence."+name] = true
	}
	if want := causalEvidence(live); !reflect.DeepEqual(got, want) {
		t.Errorf("the finding's causal evidence is %#v, want %#v", got, want)
	}
}

func proveCounterfactual(t *testing.T, proven map[string]bool, got *report.Counterfactual, live *diagnostic.Counterfactual) {
	t.Helper()
	proven["diagnostic.DiagnosisFinding.Counterfactual"] = true
	if (got == nil) != (live == nil) {
		t.Errorf("diagnostic.DiagnosisFinding.Counterfactual is classified %q and the report carries %v for a "+
			"diagnosis that carries %v", published, got, live)
		return
	}
	if live == nil {
		return
	}
	crossed(t, proven, "diagnostic.Counterfactual.Variable", got.Variable, string(live.Variable))
	crossed(t, proven, "diagnostic.Counterfactual.Alternatives", len(got.Alternatives), len(live.Alternatives))
	for i, alternative := range live.Alternatives {
		crossed(t, proven, "diagnostic.CounterfactualAlternative.Value", got.Alternatives[i].Value, alternative.Value)
		crossed(t, proven, "diagnostic.CounterfactualAlternative.Outcome",
			got.Alternatives[i].Outcome, string(alternative.Outcome))
		crossed(t, proven, "diagnostic.CounterfactualAlternative.Evidence",
			got.Alternatives[i].Evidence, causalEvidence(alternative.Evidence))
	}
}

// proveRemediation holds the advice on the primary finding to the advice
// Remediate gives for the same diagnosis on this machine's operating system,
// which is the same call buildReport makes.
func proveRemediation(t *testing.T, proven, seen map[string]bool, got *report.Remediation, d diagnostic.Diagnosis, res map[diagnostic.ProbeID]diagnostic.ProbeResult) {
	t.Helper()
	rem, ok := diagnostic.Remediate(d, res, runtime.GOOS)
	if ok != (got != nil) {
		t.Errorf("Remediate answered %v for this diagnosis and the report carries %v", ok, got)
		return
	}
	if !ok {
		return
	}
	crossed(t, proven, "diagnostic.Remediation.ID", got.ID, string(rem.ID))
	crossed(t, proven, "diagnostic.Remediation.Action", got.Action, rem.Action)
	crossed(t, proven, "diagnostic.Remediation.Why", got.Why, rem.Why)
	crossed(t, proven, "diagnostic.Remediation.Steps", got.Steps, rem.Steps)
	crossed(t, proven, "diagnostic.Remediation.Command", got.Command, rem.Command)
	crossed(t, proven, "diagnostic.Remediation.Expect", got.Expect, rem.Expect)
	for key, present := range map[string]bool{
		"diagnostic.Remediation.ID":      rem.ID != "",
		"diagnostic.Remediation.Action":  rem.Action != "",
		"diagnostic.Remediation.Why":     rem.Why != "",
		"diagnostic.Remediation.Steps":   len(rem.Steps) > 0,
		"diagnostic.Remediation.Command": len(rem.Command) > 0,
		"diagnostic.Remediation.Expect":  rem.Expect != "",
	} {
		seen[key] = seen[key] || present
	}
}

// recordFinding notes which diagnosis fields a scenario actually filled, so the
// completeness check above can tell a proved projection from a pair of zeroes.
func recordFinding(seen map[string]bool, f diagnostic.DiagnosisFinding) {
	mark := func(key string, present bool) { seen[key] = seen[key] || present }
	mark("diagnostic.DiagnosisFinding.ID", f.ID != "")
	mark("diagnostic.DiagnosisFinding.Focus", f.Focus != "")
	mark("diagnostic.DiagnosisFinding.Confidence", f.Confidence != "")
	mark("diagnostic.DiagnosisFinding.Evidence", len(f.Evidence) > 0)
	mark("diagnostic.DiagnosisFinding.Counterfactual", f.Counterfactual != nil)
	for _, e := range f.Evidence {
		recordEvidence(seen, e)
	}
	if f.Counterfactual != nil {
		mark("diagnostic.Counterfactual.Variable", f.Counterfactual.Variable != "")
		mark("diagnostic.Counterfactual.Alternatives", len(f.Counterfactual.Alternatives) > 0)
		for _, alternative := range f.Counterfactual.Alternatives {
			mark("diagnostic.CounterfactualAlternative.Value", alternative.Value != "")
			mark("diagnostic.CounterfactualAlternative.Outcome", alternative.Outcome != "")
			mark("diagnostic.CounterfactualAlternative.Evidence", len(alternative.Evidence) > 0)
			for _, e := range alternative.Evidence {
				recordEvidence(seen, e)
			}
		}
	}
}

func recordEvidence(seen map[string]bool, e diagnostic.CausalEvidence) {
	for key, present := range map[string]bool{
		"diagnostic.CausalEvidence.Kind":        e.Kind != "",
		"diagnostic.CausalEvidence.Check":       e.Check != "",
		"diagnostic.CausalEvidence.Observation": e.Observation != "",
		"diagnostic.CausalEvidence.Value":       e.Value != "",
		"diagnostic.CausalEvidence.Candidate":   e.Candidate != "",
		"diagnostic.CausalEvidence.Reason":      e.Reason != "",
	} {
		seen[key] = seen[key] || present
	}
}

// proveDocumentIsFilled asks the question from the far side, and it is the one
// a report field with no single live twin needs. A key added to internal/report
// and classified published but never written would validate against the schema
// forever, because every optional key is legal when it is absent. So this walks
// the documents the scenarios actually produce and insists something filled
// each field at least once.
func proveDocumentIsFilled(t *testing.T, proven map[string]bool) {
	filled := map[string]bool{}
	for _, sc := range projectionScenarios(t) {
		rep := buildReport(sc.target, sc.probes, sc.results)
		recordFilledFields(reflect.ValueOf(rep), filled)
	}
	for _, typ := range reportTypes() {
		for i := range typ.NumField() {
			key := projectionKey(typ, i)
			switch reportProjection[key].category {
			case published, derived:
				if !filled[key] {
					t.Errorf("no run filled %s, which is classified %q. Either buildReport does not write it any "+
						"more, or no scenario reaches it: both let a consumer read a document that is missing it "+
						"without anything noticing", key, reportProjection[key].category)
					continue
				}
				proven[key] = true
			}
		}
	}
}

// recordFilledFields walks one built document and notes every audited field
// holding something other than its zero value.
func recordFilledFields(v reflect.Value, filled map[string]bool) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			recordFilledFields(v.Elem(), filled)
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			recordFilledFields(v.Index(i), filled)
		}
	case reflect.Struct:
		if !reportAudited[v.Type().String()] {
			return
		}
		for i := range v.NumField() {
			if !v.Field(i).IsZero() {
				filled[projectionKey(v.Type(), i)] = true
			}
			recordFilledFields(v.Field(i), filled)
		}
	}
}
