// Package report defines netdoc's stable machine-readable report contract.
package report

// StatusIncomplete is the one status value no probe can return. It marks a
// check that the run built but that never reported a result at all, which is
// what a cancelled or interrupted run leaves behind. It exists because the
// alternative is worse: diagnostic.Status has PASS as its Go zero value, so a
// missing result would otherwise serialize as a passing check, and a report is
// evidence. An incomplete row is not a skipped row either; nothing decided to
// leave it out, the run just ended first. A report holding one is never ok.
//
// The vocabulary is written down here rather than borrowed from the runtime
// status type for the same reason the snapshot format writes down its own: a
// consumer decides what a row means by comparing against these, never by
// trusting a Go zero value.
const StatusIncomplete = "INCOMPLETE"

// Report is the stable JSON object emitted by netdoc -json. Its field names
// and status vocabulary (PASS/WARN/FAIL/SKIP/N/A, plus INCOMPLETE for a check
// that never reported) are compatibility-sensitive.
type Report struct {
	Version string `json:"version"`
	// Ts is set only under -json -watch, where the output is a stream and each
	// pass needs to say when it ran. A single report doesn't carry one, so the
	// one-shot output stays byte-identical to what it has always been.
	Ts      string  `json:"ts,omitempty"`
	Target  *Target `json:"target"` // null in generic (no-target) mode
	Checks  []Check `json:"checks"`
	Summary string  `json:"summary"`
	Verdict string  `json:"verdict"`
	// FailedStage is the id of the first check that failed, omitted when none
	// did, the one field a CI job needs to route a bug report.
	FailedStage string `json:"failed_stage,omitempty"`
	// Findings are the specific conclusions the diagnosis drew, most important
	// first. Omitted when the run reached none, which is the healthy case and
	// also the run that is impaired in no way worth naming: summary and verdict
	// answer for those, and inventing an identity for them would be a claim the
	// probes did not support.
	Findings []Finding `json:"findings,omitempty"`
	OK       bool      `json:"ok"`
}

// Finding is one thing the run proved wrong, in the report's own vocabulary.
// It is netdoc's conclusion about a network, not to be confused with the
// simulator's hunt findings, which are defects found in netdoc itself.
//
// ID is the stable identity to branch on; Focus is the check id whose detail
// and fix belong to this conclusion, so the remedy stays where it was written
// instead of being copied into a second catalogue; Evidence names the checks
// the conclusion was drawn from, Focus first.
type Finding struct {
	ID    string `json:"id"`
	Focus string `json:"focus,omitempty"`
	// Confidence is how strongly the observations support this finding as an
	// explanation, in the stable vocabulary high/medium/low/
	// insufficient_evidence. It is descriptive: it never decides the id, the
	// verdict, the focus, the remediation, or the exit code. It is not a
	// probability and carries no number. Absent from a producer that predates
	// it, which is not the same as low.
	Confidence string   `json:"confidence,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	// CausalEvidence states how each observed check fact bears on this finding
	// or an alternative. Evidence above remains the compatible row-ID
	// projection for existing consumers.
	CausalEvidence []CausalEvidence `json:"causal_evidence,omitempty"`
	Counterfactual *Counterfactual  `json:"counterfactual,omitempty"`
	// Remediation is what to do about this finding, as data rather than prose
	// to be parsed out of fix. Omitted when the conclusion has no advice
	// beyond what the checks already say.
	Remediation *Remediation `json:"remediation,omitempty"`
}

// CausalEvidence is one typed relationship to an observation in Checks.
// Candidate is present only for contradiction and ruled_out items. Reason is
// present only when the relevant check was not evaluated.
type CausalEvidence struct {
	Kind        string `json:"kind"`
	Check       string `json:"check"`
	Observation string `json:"observation,omitempty"`
	Value       string `json:"value,omitempty"`
	Candidate   string `json:"candidate,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type Counterfactual struct {
	Variable     string                      `json:"variable"`
	Alternatives []CounterfactualAlternative `json:"alternatives"`
}

type CounterfactualAlternative struct {
	Value    string           `json:"value"`
	Outcome  string           `json:"outcome"`
	Evidence []CausalEvidence `json:"evidence"`
}

// Remediation is the structured next action for a finding: an additive object
// that gives automation the same advice the app shows, without parsing fix or
// detail.
//
// Command is an argv, never a shell string, and netdoc never runs it: it is a
// safe read-only command offered for a person to run and read. Absent when the
// advice is prose alone.
type Remediation struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Why     string   `json:"why,omitempty"`
	Steps   []string `json:"steps,omitempty"`
	Command []string `json:"command,omitempty"`
	Expect  string   `json:"expect,omitempty"`
}

type Target struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type Check struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Status   string    `json:"status"`
	Cause    string    `json:"cause,omitempty"`
	Families *Families `json:"address_families,omitempty"`
	Ms       int64     `json:"ms"` // wall time, truncated but floored at 1; 0 means the check never ran
	Detail   string    `json:"detail"`
	Fix      string    `json:"fix,omitempty"`
	Addrs    []string  `json:"addrs,omitempty"`
	// ResolverTargets are DNS service addresses recorded as tried. They are
	// attempt evidence, not answering-resolver or per-address provenance.
	ResolverTargets []string  `json:"resolver_targets,omitempty"`
	SelectedIP      string    `json:"selected_ip,omitempty"`
	Source          string    `json:"source,omitempty"`
	Iface           string    `json:"iface,omitempty"`
	Network         string    `json:"network,omitempty"`
	Portal          *Portal   `json:"portal,omitempty"`
	Attempts        []Attempt `json:"attempts,omitempty"`
	// Routes are the operating system's own route decisions for the
	// destinations this check is about, one per destination address. Additive
	// and omitted where the platform cannot answer, which is never the same as
	// "no route": an entry with unreachable set says that.
	Routes []Route `json:"routes,omitempty"`
	// ConnectCleartext is true when this row reached its result over a plaintext
	// HTTP CONNECT: the destination hostname was sent to the proxy without TLS on
	// the client-to-proxy hop. It describes the proxy transport the configuration
	// selected and is not a claim that anything on the path read the name. Absent
	// (omitted) means the observation was not recorded, which covers a row that
	// used TLS to the proxy, a non-proxy row, a proxy the run never reached, and
	// a CONNECT the proxy refused after the destination hostname was already on
	// the wire. It never means a TLS hop was confirmed, and never means that no
	// cleartext hostname was sent.
	ConnectCleartext bool `json:"connect_cleartext,omitempty"`
}

// Route is one destination's selected path as the operating system reported
// it. An absent optional field means the platform did not supply it, never
// zero: metric is a pointer because 0 is a real route metric.
type Route struct {
	Destination string `json:"destination"`
	Family      string `json:"family,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	Source      string `json:"source,omitempty"`
	Prefix      string `json:"prefix,omitempty"`
	Metric      *int   `json:"metric,omitempty"`
	// Table is meaningful only with TableKnown: the main routing table is
	// written as an absent value, and so is a platform that never named one.
	Table      string `json:"table,omitempty"`
	TableKnown bool   `json:"table_known,omitempty"`
	// InterfaceMTU is the selected link's own MTU, never a measured path MTU.
	InterfaceMTU int              `json:"interface_mtu,omitempty"`
	Tunnel       string           `json:"tunnel,omitempty"`
	TunnelKind   string           `json:"tunnel_kind,omitempty"`
	Unreachable  bool             `json:"unreachable,omitempty"`
	Reason       string           `json:"reason,omitempty"`
	Competing    []CompetingRoute `json:"competing,omitempty"`
}

type CompetingRoute struct {
	Interface string `json:"interface,omitempty"`
	Metric    int    `json:"metric"`
}

// A family the selected --iface source has no address for was never dialed, so
// its state is empty and the key is omitted rather than serialized as "": an
// absent family reads as untested, which is what it is.
type Families struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type Portal struct {
	RedirectURL string `json:"redirect_url,omitempty"`
}

type Attempt struct {
	IP      string `json:"ip"`
	Ms      int64  `json:"ms"` // same flooring as Check.Ms
	Err     string `json:"error,omitempty"`
	Cause   string `json:"cause,omitempty"`
	Aborted bool   `json:"aborted,omitempty"`
}
