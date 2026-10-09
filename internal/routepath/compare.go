package routepath

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// compareWalks sets the agreement on each forwarding hop that the FIB decided,
// and returns every place the two walks disagree. Loops and conflicts are
// reported from either walk, since either one can stop reconstruction.
func compareWalks(exp, fwd *Hop) []Finding {
	expected := map[state]*Hop{}
	walkHops(exp, func(h *Hop) {
		if h.Node == "" {
			return
		}
		if _, seen := expected[state{h.Node, h.VRF}]; !seen {
			expected[state{h.Node, h.VRF}] = h
		}
	})
	var out []Finding
	add := func(f Finding) {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	walkHops(fwd, func(h *Hop) {
		if h.Decision.Basis == netmodel.PlaneFIB && h.Node != "" {
			h.Decision.Agreement = AgreementUnknown
			if e := expected[state{h.Node, h.VRF}]; e != nil {
				if kind, detail, differs := disagreement(e, h); differs {
					h.Decision.Agreement = AgreementDisagrees
					add(Finding{Kind: kind, Node: h.Node, VRF: h.VRF, Detail: detail})
				} else if e.Decision.Proven && concrete(e.Decision.Kind) && concrete(h.Decision.Kind) {
					h.Decision.Agreement = AgreementAgrees
				}
			}
		}
		if h.Via != nil && h.Via.Outcome == OutcomeFail {
			add(Finding{Kind: FindingForwardingFailed, Node: h.Via.From, VRF: h.Via.VRF, Detail: "recorded check failed on segment " + segText(*h.Via) + checkSourcesText(h.Via.Checks)})
		}
		noteConditions(h, add)
	})
	walkHops(exp, func(h *Hop) { noteConditions(h, add) })
	return out
}

func noteConditions(h *Hop, add func(Finding)) {
	switch h.Decision.Kind {
	case KindLoop:
		add(Finding{Kind: FindingLoop, Node: h.Node, VRF: h.VRF, Detail: "path returns to " + h.Node + ", which is already on it"})
	case KindConflicting:
		add(Finding{Kind: FindingConflict, Node: h.Node, VRF: h.VRF, Detail: string(h.Decision.Basis) + " evidence conflicts; no path is chosen"})
	}
}

// disagreement compares the expected decision at a node with the FIB decision
// there. It reports nothing when either side makes no concrete claim, so an
// unknown never reads as a disagreement.
func disagreement(exp, fwd *Hop) (FindingKind, string, bool) {
	ek, fk := exp.Decision.Kind, fwd.Decision.Kind
	if !concrete(ek) || !concrete(fk) {
		return "", "", false
	}
	switch {
	case ek == KindNoRoute && fk == KindNoRoute:
		return "", "", false
	case fk == KindNoRoute:
		return FindingControlNotInFIB, fmt.Sprintf("control expects %s; the FIB holds no route for the destination", describe(exp.Decision)), true
	case ek == KindNoRoute:
		return FindingFIBDiffers, fmt.Sprintf("control holds no route; the FIB forwards on %s", describe(fwd.Decision)), true
	case exp.Decision.Prefix != fwd.Decision.Prefix && prefixBits(exp.Decision.Prefix) > prefixBits(fwd.Decision.Prefix):
		return FindingControlNotInFIB, fmt.Sprintf("control expects %s; the FIB uses the less specific %s", describe(exp.Decision), describe(fwd.Decision)), true
	case !exp.Decision.Proven:
		// A partial control table may hold a more specific route that changes the
		// expected answer, so it cannot show what the FIB differs from.
		return "", "", false
	case exp.Decision.Prefix != fwd.Decision.Prefix, ek != fk, !slices.Equal(exp.Decision.NextHops, fwd.Decision.NextHops):
		return FindingFIBDiffers, fmt.Sprintf("control expects %s; the FIB has %s", describe(exp.Decision), describe(fwd.Decision)), true
	}
	return "", "", false
}

// concrete is a decision that names what happens to the destination, as
// opposed to one that says the evidence could not decide.
func concrete(k Kind) bool { return k == KindForward || k == KindDiscard || k == KindNoRoute }

func describe(d Decision) string {
	if d.Kind == KindNoRoute {
		return "no route"
	}
	if d.Kind == KindDiscard {
		return d.Prefix + " discard"
	}
	hops := make([]string, len(d.NextHops))
	for i, h := range d.NextHops {
		hops[i] = h.Interface
		if h.Addr != "" {
			hops[i] += " via " + h.Addr
		}
	}
	return d.Prefix + " " + strings.Join(hops, ", ")
}

func prefixBits(s string) int {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return -1
	}
	return p.Bits()
}

// failureRegions finds each recorded failure that is the first on its branch.
// The region runs from the last segment with a recorded pass up to the failure.
// Every alternative leaving a point inside that run is a candidate, because one
// pass on an alternative proves nothing about its siblings.
func failureRegions(root *Hop) []FailureRegion {
	out := []FailureRegion{}
	var visit func(path []*Hop)
	visit = func(path []*Hop) {
		cur := path[len(path)-1]
		for i := range cur.Next {
			child := &cur.Next[i]
			full := append(slices.Clone(path), child)
			if child.Via != nil && child.Via.Outcome == OutcomeFail && !failedAbove(full[:len(full)-1]) {
				out = append(out, regionOf(full))
			}
			visit(full)
		}
	}
	visit([]*Hop{root})
	return out
}

// failedAbove reports whether a segment on the branch already failed. full[0]
// is the source, which has no segment.
func failedAbove(full []*Hop) bool {
	for _, h := range full[1:] {
		if h.Via.Outcome == OutcomeFail {
			return true
		}
	}
	return false
}

func regionOf(full []*Hop) FailureRegion {
	last := len(full) - 1
	start := 0
	for j := 1; j < last; j++ {
		if full[j].Via.Outcome == OutcomePass {
			start = j
		}
	}
	region := FailureRegion{Fail: *full[last].Via, Candidates: []Segment{}}
	for _, point := range full[start:last] {
		for _, c := range point.Next {
			if c.Via != nil && !containsSegment(region.Candidates, *c.Via) {
				region.Candidates = append(region.Candidates, *c.Via)
			}
		}
	}
	return region
}

// limitations says where reconstruction stopped or rests on an unproven
// decision, in both walks. Each line names the node or the segment it is about.
func limitations(exp, fwd *Hop) []string {
	var texts []string
	walksOf := map[string][]string{}
	add := func(walk, text string) {
		if _, seen := walksOf[text]; !seen {
			texts = append(texts, text)
		}
		if !slices.Contains(walksOf[text], walk) {
			walksOf[text] = append(walksOf[text], walk)
		}
	}
	for _, walk := range []struct {
		label, unknown string
		root           *Hop
	}{{"expected", "expected route unknown", exp}, {"forwarding", "forwarding unknown", fwd}} {
		walkHops(walk.root, func(h *Hop) {
			where := nodeLabel(h)
			switch h.Decision.Kind {
			case KindUnknown:
				add(walk.label, where+": "+walk.unknown+"; "+h.Decision.Reason)
			case KindConflicting:
				add(walk.label, where+": evidence conflicts; no path is chosen")
			case KindLoop:
				add(walk.label, where+": path returns to a node already on it; the walk stops")
			case KindTruncated:
				add(walk.label, where+": traversal bound reached; the path continues beyond what is shown")
			case KindUnresolved, KindAmbiguous:
				add(walk.label, where+": "+h.Decision.Reason+"; the path stops here")
			case KindOnLink:
				add(walk.label, where+": destination is on-link through "+h.Via.Interface+"; no modeled node owns it; the path stops here")
			case KindForward:
				if !h.Decision.Proven {
					add(walk.label, where+": decision is not proven; a more specific route may exist")
				}
			}
			if h.Via != nil {
				switch h.Via.Outcome {
				case OutcomeConflicting:
					add(walk.label, "recorded checks disagree on segment "+segText(*h.Via)+checkSourcesText(h.Via.Checks))
				case OutcomeUnattributed:
					add(walk.label, "recorded check on segment "+segText(*h.Via)+" names no next hop, and the interface carries several; it is not attributed to any of them"+checkSourcesText(h.Via.Checks))
				}
			}
		})
	}
	out := []string{}
	for _, text := range texts {
		if walks := walksOf[text]; len(walks) == 1 {
			text += " (" + walks[0] + " walk)"
		}
		out = append(out, text)
	}
	return out
}

// checkSourcesText names the recorded checks a segment rests on, so a failure or
// a conflict traces back to its input. It is empty when no check applies.
func checkSourcesText(cs []Support) string {
	if len(cs) == 0 {
		return ""
	}
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = c.Source + " at " + c.CollectedAt
	}
	return " (checks: " + strings.Join(parts, "; ") + ")"
}

// containsSegment compares segments by their route identity. A segment can carry
// its checks, which are slices, so the struct itself is not comparable.
func containsSegment(segs []Segment, want Segment) bool {
	for _, s := range segs {
		if s.From == want.From && s.VRF == want.VRF && s.Interface == want.Interface && s.NextHop == want.NextHop {
			return true
		}
	}
	return false
}

func nodeLabel(h *Hop) string {
	if h.Node == "" && h.Via != nil {
		return segText(*h.Via)
	}
	return h.Node + " (" + h.VRF + ")"
}

func segText(s Segment) string {
	to := "on-link"
	if s.NextHop != "" {
		to = "via " + s.NextHop
	}
	return fmt.Sprintf("%s (%s) %s %s", s.From, s.VRF, s.Interface, to)
}

// walkHops visits every hop in a tree, parents before children, in tree order.
func walkHops(h *Hop, fn func(*Hop)) {
	fn(h)
	for i := range h.Next {
		walkHops(&h.Next[i], fn)
	}
}
