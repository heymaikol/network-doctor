// Package routepath explains how traffic to one destination should leave a
// known network, and checks that explanation against forwarding and recorded
// evidence. It reads a netmodel.Model and recorded Checks. It sends no probe,
// resolves no name, and reads no live state.
//
// Two walks run over the same (node, VRF) graph:
//
//   - The expected walk follows control-plane state, then configured state. It
//     says where the routing protocols intend traffic to go.
//   - The forwarding walk follows the FIB only. It says where the kernel will
//     actually send traffic, and it stops at any decision the FIB cannot prove.
//
// The two are compared hop by hop, and recorded Checks are attached to the
// segments they name. A failed Check is reported as a region of segments, never
// as a named node, because one recorded failure cannot say which hop broke.
//
// When the file names the source address, a third walk follows the forwarding
// table back from the destination's routing domain. Its route is compared with
// the forward route as an Asymmetry. An asymmetric pair raises a concern only
// with a policy boundary, a routing-domain change, or a recorded failure on one
// direction. Asymmetry alone is never a failure.
//
// When the file holds intended routes, one more walk follows intent where it
// states a route and the FIB elsewhere. At each node where intent decides, the
// intended decision is compared with the FIB as Drift, rated by what the
// difference does to delivery. What the evidence cannot prove is unknown.
package routepath

import (
	"net/netip"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// Start is the node and routing domain where traffic to the destination leaves.
type Start struct {
	Node string `json:"node"`
	VRF  string `json:"vrf"`
}

// Check is one recorded forwarding result for the segment that leaves Node in
// VRF through Interface toward Destination. It was recorded elsewhere, and
// nothing here sends traffic to produce it. A segment with no Check is unknown,
// never failed.
type Check struct {
	netmodel.Provenance
	Node        string
	VRF         string
	Interface   string
	Destination netip.Addr
	// NextHop is the next-hop address the check exercised, when the recording
	// names one. Without it, the check applies to its interface only when that
	// interface carries a single next hop.
	NextHop netip.Addr
	Result  CheckResult
}

// CheckResult is what a recorded Check says happened.
type CheckResult string

const (
	CheckPass CheckResult = "pass"
	CheckFail CheckResult = "fail"
)

// File is a decoded topology file: where traffic starts, what the model knows,
// and what was recorded about specific segments.
type File struct {
	Source Start
	// SourceAddr is the address the source uses toward the destination. When it
	// is set, Explain also walks the return direction toward it.
	SourceAddr netip.Addr
	Model      netmodel.Model
	Checks     []Check
	Boundaries []Boundary
}

// Kind says what happens to the destination at one node.
type Kind string

const (
	KindForward     Kind = "forward"     // one or more next hops; several are ECMP alternatives
	KindLocal       Kind = "local"       // the destination is an address on this node
	KindDiscard     Kind = "discard"     // the route drops the destination
	KindNoRoute     Kind = "no_route"    // a complete table holds no route to the destination
	KindUnknown     Kind = "unknown"     // the evidence cannot decide what happens here
	KindConflicting Kind = "conflicting" // the evidence disagrees; both sides are kept
	KindLoop        Kind = "loop"        // the walk came back to a node already on its path
	KindTruncated   Kind = "truncated"   // a traversal bound stopped the walk
	KindUnresolved  Kind = "unresolved"  // the next hop address is not owned by any modeled node
	KindAmbiguous   Kind = "ambiguous"   // the next hop address is owned by more than one node
	KindOnLink      Kind = "on_link"     // the destination is on link, and no modeled node owns it
)

// Outcome is the recorded result for one segment.
type Outcome string

const (
	OutcomeNone        Outcome = "none"
	OutcomePass        Outcome = "pass"
	OutcomeFail        Outcome = "fail"
	OutcomeConflicting Outcome = "conflicting"
	// OutcomeUnattributed is a recorded check that names no next hop on an
	// interface that carries several. It is not assigned to any of them.
	OutcomeUnattributed Outcome = "unattributed"
)

// Agreement says whether the forwarding decision at a hop matches the expected
// decision at the same node.
type Agreement string

const (
	AgreementAgrees    Agreement = "agrees"
	AgreementDisagrees Agreement = "disagrees"
	AgreementUnknown   Agreement = "unknown"
)

// FindingKind names one disagreement between evidence layers, or a condition
// that stops reliable reconstruction.
type FindingKind string

const (
	// FindingControlNotInFIB: the control plane expects a route the FIB lacks,
	// so the kernel does not forward on it. Nothing was sent.
	FindingControlNotInFIB FindingKind = "control_route_not_in_fib"
	// FindingFIBDiffers: the FIB and the control plane both have a route for the
	// destination, and they name different forwarding.
	FindingFIBDiffers FindingKind = "fib_differs_from_control"
	// FindingForwardingFailed: the FIB route is installed, and a recorded check
	// says traffic on that segment failed.
	FindingForwardingFailed FindingKind = "fib_forwarding_failed"
	// FindingConflict: the evidence at one node disagrees with itself.
	FindingConflict FindingKind = "conflicting_evidence"
	// FindingLoop: the walk returned to a node it already visited.
	FindingLoop FindingKind = "loop"
)

// Support is one row of evidence behind a decision. Absent marks a complete
// observation that lacks the prefix, which is evidence too.
type Support struct {
	Source      string `json:"source"`
	CollectedAt string `json:"collected_at"`
	Origin      string `json:"origin,omitempty"`
	Absent      bool   `json:"absent,omitempty"`
}

// NextHop is one forwarding alternative as the evidence states it.
type NextHop struct {
	Addr      string `json:"addr,omitempty"`
	Interface string `json:"interface,omitempty"`
}

// Decision is what one walk concluded at one node.
type Decision struct {
	Kind Kind `json:"kind"`
	// Basis is the plane whose rows made the decision. It is empty when no
	// plane was consulted.
	Basis netmodel.Plane `json:"basis,omitempty"`
	// Prefix is the longest matching prefix the evidence holds. Proven says
	// whether a complete table backs that choice.
	Prefix string `json:"prefix,omitempty"`
	Proven bool   `json:"proven"`
	// Shadowed lists less specific prefixes that also matched the destination
	// and lost to Prefix.
	Shadowed  []string  `json:"shadowed,omitempty"`
	NextHops  []NextHop `json:"next_hops,omitempty"`
	Evidence  []Support `json:"evidence,omitempty"`
	Agreement Agreement `json:"agreement,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// Segment is one edge of a walk: a next hop leaving From through Interface.
type Segment struct {
	From      string    `json:"from"`
	VRF       string    `json:"vrf"`
	Interface string    `json:"interface,omitempty"`
	NextHop   string    `json:"next_hop,omitempty"`
	Outcome   Outcome   `json:"outcome"`
	Checks    []Support `json:"checks,omitempty"`
}

// Hop is one node of a walk tree. Via is the segment that reached it, and it is
// absent at the source. Several Next entries are ECMP alternatives.
type Hop struct {
	Node     string   `json:"node"`
	VRF      string   `json:"vrf"`
	Via      *Segment `json:"via,omitempty"`
	Decision Decision `json:"decision"`
	Next     []Hop    `json:"next,omitempty"`
}

// Finding is one disagreement or stop condition, attached to the node where it
// was seen.
type Finding struct {
	Kind   FindingKind `json:"kind"`
	Node   string      `json:"node"`
	VRF    string      `json:"vrf"`
	Detail string      `json:"detail"`
}

// FailureRegion is the segments that could hold a recorded failure. It runs
// from the last segment with a recorded pass up to the first recorded failure,
// and it includes every alternative at each point along the way, because a pass
// on one alternative proves nothing about the others.
type FailureRegion struct {
	Fail       Segment   `json:"fail"`
	Candidates []Segment `json:"candidates"`
}

// Explanation is the complete answer for one source and destination. Expected
// and Forwarding are the two walks, and Findings are where they disagree.
type Explanation struct {
	Source      Start           `json:"source"`
	Destination string          `json:"destination"`
	Expected    Hop             `json:"expected"`
	Forwarding  Hop             `json:"forwarding"`
	Findings    []Finding       `json:"findings"`
	Regions     []FailureRegion `json:"failure_regions"`
	Limitations []string        `json:"limitations"`
	Truncated   bool            `json:"truncated"`
	// Asymmetry compares this forward route with the return route. It is nil
	// unless the topology names the source address.
	Asymmetry *Asymmetry `json:"asymmetry,omitempty"`
	// Drift compares intended routes with the FIB. It is nil unless the
	// topology holds intended routes.
	Drift *Drift `json:"drift,omitempty"`
}
