package routepath

import (
	"fmt"
	"slices"
	"strings"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// DriftLevel says what a difference between intended routes and the FIB does
// to delivery. driftRank orders the levels.
type DriftLevel string

const (
	DriftNone             DriftLevel = "none"
	DriftBenign           DriftLevel = "benign"
	DriftUnknown          DriftLevel = "unknown"
	DriftRedundancyLost   DriftLevel = "redundancy_lost"
	DriftReachabilityLost DriftLevel = "reachability_lost"
)

// driftRank runs from least to most severe. Unknown outranks benign and none,
// so a node the evidence cannot decide never summarizes as healthy.
var driftRank = []DriftLevel{DriftNone, DriftBenign, DriftUnknown, DriftRedundancyLost, DriftReachabilityLost}

// Fact is one row behind a drift finding: who said what, on which plane, when.
// No Prefix means the table lists no route for the decision's prefix, and
// Complete says whether that silence proves absence.
type Fact struct {
	Source      string         `json:"source"`
	CollectedAt string         `json:"collected_at"`
	Plane       netmodel.Plane `json:"plane"`
	Complete    bool           `json:"complete"`
	Origin      string         `json:"origin,omitempty"`
	Prefix      string         `json:"prefix,omitempty"`
	NextHops    []NextHop      `json:"next_hops,omitempty"`
	Discard     bool           `json:"discard,omitempty"`
}

// DriftFinding is one node where the intended decision and the FIB decision
// differ, or cannot be compared. Facts lists the intended rows, then the FIB
// rows.
type DriftFinding struct {
	Level      DriftLevel `json:"level"`
	Node       string     `json:"node"`
	VRF        string     `json:"vrf"`
	Detail     string     `json:"detail"`
	Intended   Decision   `json:"intended"`
	Forwarding Decision   `json:"forwarding"`
	Facts      []Fact     `json:"facts"`
}

// Drift compares intended routes with the FIB at each node where intent states
// a decision. Intended is the walk that follows intent where it speaks and the
// FIB elsewhere, and Compared counts the nodes where intent decided. Level is
// the worst finding, and at least unknown when a walk was truncated.
type Drift struct {
	Level     DriftLevel     `json:"level"`
	Compared  int            `json:"compared"`
	Truncated bool           `json:"truncated"`
	Intended  Hop            `json:"intended"`
	Findings  []DriftFinding `json:"findings"`
}

// reach is what a walk shows about delivery from one node.
type reach int

const (
	reachOK      reach = iota // every leaf is local
	reachUnknown              // no leaf fails, and the walk proves no delivery
	reachFailed               // some leaf drops or loops
)

// drift compares intent with the FIB along the intended walk. It returns nil
// when the file holds no intended routes, so the explanation is unchanged.
func (w *walker) drift(e *Explanation) *Drift {
	if !slices.ContainsFunc(w.obs, func(o netmodel.Observation) bool {
		return o.Plane == netmodel.PlaneIntended && (len(o.Routes) > 0 || o.RoutesComplete)
	}) {
		return nil
	}
	intended, trunc := w.run(intendedPlanes, state{e.Source.Node, e.Source.VRF})
	trunc = trunc || e.Truncated
	live, want := map[state]reach{}, map[state]reach{}
	root := reachOf(&e.Forwarding, live)
	reachOf(&intended, want)
	// A bound hides part of a walk, so nothing it shows proves delivery.
	bounded := func(r reach) reach {
		if trunc {
			return max(r, reachUnknown)
		}
		return r
	}
	d := &Drift{Level: DriftNone, Truncated: trunc, Intended: intended, Findings: []DriftFinding{}}
	if trunc {
		d.Level = DriftUnknown
	}
	seen := map[state]bool{}
	walkHops(&intended, func(h *Hop) {
		s := state{h.Node, h.VRF}
		// When every plane is silent, decide still names intended as the basis,
		// with no prefix. Intent stated nothing there.
		if h.Decision.Basis != netmodel.PlaneIntended || (h.Decision.Kind == KindUnknown && h.Decision.Prefix == "") || seen[s] {
			return
		}
		seen[s] = true
		d.Compared++
		after, on := live[s]
		if !on {
			after = root
		}
		if f, ok := w.classify(s, on, bounded(after), bounded(want[s])); ok {
			d.Findings = append(d.Findings, f)
			if slices.Index(driftRank, f.Level) > slices.Index(driftRank, d.Level) {
				d.Level = f.Level
			}
		}
	})
	return d
}

// classify compares the intended and FIB decisions at s. on says whether the
// live walk visits s. after is the live reach from s, or from the source when
// the live walk does not visit s, and want is the intended reach from s. It
// reports false when the two decisions match.
func (w *walker) classify(s state, on bool, after, want reach) (DriftFinding, bool) {
	in, ih := w.decide([]netmodel.Plane{netmodel.PlaneIntended}, s)
	fib, fh := w.decide(forwardingPlanes, s)
	f := DriftFinding{Node: s.node, VRF: s.vrf, Intended: in, Forwarding: fib, Facts: slices.Concat(
		w.facts(s, netmodel.PlaneIntended, in.Prefix), w.facts(s, netmodel.PlaneFIB, fib.Prefix))}
	drops := func(d Decision) bool { return d.Kind == KindNoRoute || d.Kind == KindDiscard }
	same := (drops(in) && drops(fib)) || (in.Kind == fib.Kind && netmodel.CoversHops(fh, ih) && netmodel.CoversHops(ih, fh))
	// fewer is a FIB that keeps some intended next hops and adds none. That
	// assumes a route lists every ECMP next hop.
	fewer := len(fh) > 0 && netmodel.CoversHops(ih, fh) && !netmodel.CoversHops(fh, ih)
	var why string
	switch {
	case !concrete(in.Kind) || !concrete(fib.Kind):
		f.Level, why = DriftUnknown, "the two cannot be compared"
		if !slices.ContainsFunc(f.Facts, func(x Fact) bool { return x.Plane == netmodel.PlaneFIB }) {
			why = fmt.Sprintf("no FIB observation for %s (%s)", s.node, s.vrf)
		}
	case !in.Proven && prefixBits(in.Prefix) <= prefixBits(fib.Prefix):
		// As with control, a partial intended table may hide a more specific
		// route, so it cannot show what the FIB differs from.
		f.Level, why = DriftUnknown, "the intended table is partial, so a more specific intended route may exist"
	case same && in.Prefix == fib.Prefix:
		return f, false
	case same:
		f.Level, why = DriftBenign, "the same decision on another prefix"
	case drops(in):
		f.Level, why = DriftUnknown, "intent drops and the FIB forwards, which is not classified"
	case on && after == reachFailed && want == reachOK:
		f.Level, why = DriftReachabilityLost, "the FIB path fails where the intended path reaches the destination"
	case fewer || (!on && drops(fib)):
		f.Level, why = DriftRedundancyLost, "the FIB lacks an intended alternative, and the destination is still reached"
		if after != reachOK {
			f.Level, why = DriftUnknown, "the FIB lacks an intended alternative, and delivery is not proven"
		}
	case after == reachOK:
		f.Level, why = DriftBenign, "the destination is still reached"
	default:
		f.Level, why = DriftUnknown, "delivery is not proven, so the impact is unknown"
	}
	f.Detail = "intent expects " + sideText(in) + "; the FIB has " + sideText(fib) + "; " + why
	return f, true
}

func sideText(d Decision) string {
	if concrete(d.Kind) {
		return describe(d)
	}
	return string(d.Kind) + " (" + stopText(d) + ")"
}

// reachOf returns the reach from h, and records the worst reach of each node in
// by. A leaf that drops or loops fails. Any other leaf that is not local, and a
// segment with a recorded outcome other than none or pass, leave it unknown.
func reachOf(h *Hop, by map[state]reach) reach {
	r := reachOK
	switch h.Decision.Kind {
	case KindLocal, KindForward:
	case KindNoRoute, KindDiscard, KindLoop:
		r = reachFailed
	default:
		r = reachUnknown
	}
	for i := range h.Next {
		c := &h.Next[i]
		cr := reachOf(c, by)
		if c.Via.Outcome != OutcomeNone && c.Via.Outcome != OutcomePass {
			cr = max(cr, reachUnknown)
		}
		r = max(r, cr)
	}
	if h.Node != "" {
		s := state{h.Node, h.VRF}
		by[s] = max(by[s], r)
	}
	return r
}

// facts lists each route of plane p at s for prefix, in canonical order. A row
// with no route for prefix is listed too, since its silence proves absence only
// when its table is complete.
func (w *walker) facts(s state, p netmodel.Plane, prefix string) []Fact {
	var out []Fact
	for _, o := range w.obs {
		if o.Node != s.node || o.VRF != s.vrf || o.Plane != p {
			continue
		}
		row := Fact{Source: o.Source, CollectedAt: utcText(o.CollectedAt), Plane: p, Complete: o.RoutesComplete}
		n := len(out)
		for _, r := range o.Routes {
			if r.Prefix.String() == prefix {
				f := row
				f.Origin, f.Prefix, f.NextHops, f.Discard = r.Origin, prefix, nextHopTexts(r.NextHops), r.Discard
				out = append(out, f)
			}
		}
		if len(out) == n {
			out = append(out, row)
		}
	}
	return out
}

// renderDrift prints the comparison, the intended walk, and each finding with
// the rows behind it.
func renderDrift(line func(string, ...any), d *Drift) {
	line("")
	line("Drift (intended routes vs FIB): %s", d.Level)
	line("  nodes where intent decides: %d", d.Compared)
	if d.Truncated {
		line("  A walk stopped at a traversal bound, so drift is at least unknown.")
	}
	line("  intended walk (intent where it states a route, FIB elsewhere):")
	renderTree(line, &d.Intended, 2)
	line("  drift findings:")
	if len(d.Findings) == 0 {
		line("    none")
	}
	for _, f := range d.Findings {
		line("    %s at %s (%s): %s", f.Level, f.Node, f.VRF, f.Detail)
		for _, x := range f.Facts {
			line("      %s", factText(x))
		}
	}
}

func factText(f Fact) string {
	table := "partial"
	if f.Complete {
		table = "complete"
	}
	what := "no route for this decision"
	if f.Prefix != "" {
		k := KindForward
		if f.Discard {
			k = KindDiscard
		}
		what = strings.TrimSpace(f.Origin + " " + describe(Decision{Kind: k, Prefix: f.Prefix, NextHops: f.NextHops}))
	}
	return fmt.Sprintf("%s (%s, %s) %s at %s", f.Source, f.Plane, table, what, f.CollectedAt)
}
