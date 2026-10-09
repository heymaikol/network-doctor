package routepath

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// Text renders the explanation for a person. Every line passes through
// textsafe.Clean, because node names and interface names come from the file.
// The output depends only on the explanation, so the same input always prints
// the same bytes.
func (e Explanation) Text() string {
	var b strings.Builder
	line := func(format string, args ...any) {
		b.WriteString(textsafe.Clean(fmt.Sprintf(format, args...)))
		b.WriteByte('\n')
	}
	line("Destination %s from %s (%s)", e.Destination, e.Source.Node, e.Source.VRF)
	if e.Truncated {
		line("The walk stopped at a traversal bound; the paths below are incomplete.")
	}
	line("")
	line("Expected (control plane, then configured):")
	renderTree(line, &e.Expected, 1)
	line("")
	line("Forwarding (FIB):")
	renderTree(line, &e.Forwarding, 1)
	line("")
	line("Findings:")
	if len(e.Findings) == 0 {
		line("  none")
	}
	for _, f := range e.Findings {
		line("  %s at %s (%s): %s", f.Kind, f.Node, f.VRF, f.Detail)
	}
	line("")
	line("Failure regions (a recorded failure lies in one candidate segment; no hop is named):")
	if len(e.Regions) == 0 {
		line("  none")
	}
	for _, r := range e.Regions {
		candidates := make([]string, len(r.Candidates))
		for i, c := range r.Candidates {
			candidates[i] = segText(c)
		}
		line("  failed on %s", segText(r.Fail))
		line("  candidates: %s", strings.Join(candidates, "; "))
	}
	line("")
	line("Limitations:")
	if len(e.Limitations) == 0 {
		line("  none")
	}
	for _, l := range e.Limitations {
		line("  - %s", l)
	}
	return b.String()
}

// renderTree prints one walk. A child line leads with the segment that reached
// it, and its recorded check, so each arrow reads as one fact.
func renderTree(line func(string, ...any), h *Hop, depth int) {
	indent := strings.Repeat("  ", depth)
	if h.Node == "" {
		line("%s-> %s: %s", indent, arrowText(*h.Via), decisionText(h.Decision))
		return
	}
	prefix := ""
	if h.Via != nil {
		prefix = "-> " + arrowText(*h.Via) + ": "
	}
	line("%s%s%s (%s): %s", indent, prefix, h.Node, h.VRF, decisionText(h.Decision))
	for i := range h.Next {
		renderTree(line, &h.Next[i], depth+1)
	}
}

// arrowText is the segment as a tree arrow shows it: the egress, the next hop,
// and the recorded check when there is one. The source node is already on the
// line above, so it is not repeated.
func arrowText(s Segment) string {
	text := s.Interface
	if s.NextHop != "" {
		text += " via " + s.NextHop
	} else {
		text += " on-link"
	}
	switch s.Outcome {
	case OutcomePass, OutcomeFail, OutcomeConflicting:
		text += " [check " + string(s.Outcome) + "]"
	}
	return text
}

func decisionText(d Decision) string {
	var parts []string
	switch d.Kind {
	case KindForward:
		parts = append(parts, "forward "+d.Prefix+" via "+nextHopsText(d.NextHops))
	case KindDiscard:
		parts = append(parts, "discard "+d.Prefix)
	case KindNoRoute:
		parts = append(parts, "no route in the complete "+string(d.Basis)+" table")
	case KindLocal:
		parts = append(parts, "local: the destination is an address on this node")
	default:
		parts = append(parts, string(d.Kind)+": "+d.Reason)
	}
	if d.Basis != "" && (d.Kind == KindForward || d.Kind == KindDiscard) {
		parts = append(parts, "basis "+string(d.Basis))
		if d.Proven {
			parts = append(parts, "proven")
		} else {
			parts = append(parts, "unproven")
		}
	}
	if len(d.Evidence) > 0 {
		parts = append(parts, "evidence "+evidenceText(d.Evidence))
	}
	switch d.Agreement {
	case AgreementAgrees:
		parts = append(parts, "agrees with control")
	case AgreementDisagrees:
		parts = append(parts, "disagrees with control")
	case AgreementUnknown:
		parts = append(parts, "no comparable control decision")
	}
	return strings.Join(parts, "; ")
}

// evidenceText names the rows a decision rests on, so each hop says where its
// route came from. A complete table that lacks the route is named too, because
// that absence is part of the proof.
func evidenceText(ev []Support) string {
	out := make([]string, len(ev))
	for i, s := range ev {
		switch {
		case s.Absent:
			out[i] = "no route in " + s.Source
		case s.Origin != "":
			out[i] = s.Source + " (" + s.Origin + ")"
		default:
			out[i] = s.Source
		}
	}
	return strings.Join(out, ", ")
}

func nextHopsText(hops []NextHop) string {
	out := make([]string, len(hops))
	for i, h := range hops {
		out[i] = h.Interface
		if h.Addr != "" {
			out[i] += " " + h.Addr
		}
	}
	return strings.Join(out, " or ")
}

// JSON is the stable machine-readable form. Field order follows the struct
// declarations, and no field is a map, so the encoding is deterministic.
func (e Explanation) JSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}
