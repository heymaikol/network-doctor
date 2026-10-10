package compare

import (
	"encoding/json"
	"strings"
)

// RouteBound and RouteUnbound are the two outcomes of binding a topology file
// to one side. Unbound never means the side is at fault, only that the file
// could not be tied to that side's own recorded route.
const (
	RouteBound   = "bound"
	RouteUnbound = "unbound"
)

// FirstHop values say how the side's recorded next hop compared with the
// topology's forwarding decision at its source. Only agreement binds.
const (
	FirstHopAgrees        = "agrees"
	FirstHopConflicts     = "conflicts"
	FirstHopNotComparable = "not_comparable"
)

// routeComparedNames and routeNotComparedNames say, for a person, what each
// closed-vocabulary field in Compared and NotCompared stands for.
var (
	routeComparedNames = map[string]string{
		"source": "source address", "next_hop": "next hop",
		"prefix": "matched prefix", "routing_table": "routing table",
	}
	routeNotComparedNames = map[string]string{
		"interface":     "interface names (names are not established across machines)",
		"prefix":        "matched prefix (this side recorded none)",
		"routing_table": "routing table (this side recorded none)",
	}
)

// RoutePath is the routing context that one topology file adds to one side of
// a two-sided reading. It is built from that file and from that side's own
// recorded route for the target, never from the other side's measurements. The
// explanation is predicted and recorded routing tables. It is not a measured
// reply, and it never changes Checks, Diagnosis, or the exit code.
type RoutePath struct {
	// Side is "a" or "b", the side the file was named for.
	Side   string `json:"side"`
	Status string `json:"status"`
	// Reason says why the file did not bind. It is prose for a person and is
	// never parsed back.
	Reason      string      `json:"reason,omitempty"`
	Destination string      `json:"destination,omitempty"`
	Source      string      `json:"source,omitempty"`
	Basis       *RouteBasis `json:"basis,omitempty"`
	// FirstHop is the forwarding comparison. It is present only when that
	// comparison ran, so an unbound entry refused earlier has none.
	FirstHop string `json:"first_hop,omitempty"`
	// Compared lists the fields a bound reading checked against the topology, and
	// NotCompared the fields it could not check. Both use a closed vocabulary:
	// source, next_hop, prefix, routing_table, and interface.
	Compared    []string        `json:"compared,omitempty"`
	NotCompared []string        `json:"not_compared,omitempty"`
	Explanation json.RawMessage `json:"explanation,omitempty"`
	// Text is the human rendering of Explanation. The route-path renderer has
	// already sanitized every line it prints.
	Text string `json:"-"`
}

// RouteBasis says what kind of evidence each part of a bound explanation rests
// on. The values are a closed vocabulary, so a script can tell a prediction from
// a recorded table without reading prose.
type RouteBasis struct {
	// Expected is the control and configured tables' prediction of the path.
	Expected string `json:"expected"`
	// Forwarding is the recorded FIB rows, which the file states, not packets.
	Forwarding string `json:"forwarding"`
	// Return is the reply route derived from the recorded FIB rows. It is a
	// prediction, and no reply was observed.
	Return string `json:"return"`
	// Checks are results recorded elsewhere. This reading measured none of them.
	Checks string `json:"checks"`
}

// BoundRouteBasis is the basis every bound explanation carries.
func BoundRouteBasis() *RouteBasis {
	return &RouteBasis{
		Expected:   "control_plane_prediction",
		Forwarding: "recorded_fib",
		Return:     "recorded_fib_prediction",
		Checks:     "recorded_elsewhere",
	}
}

// routeText renders the route context. It follows the placement and caveats,
// and it names the side with the same headings the rest of the reading uses.
func (t TwoSided) routeText(aHeading, bHeading string) string {
	var b strings.Builder
	b.WriteString("\nRoute context from topology files. It describes predicted and recorded routing tables, not measured replies, and it does not change the placement above. Checks in the file were recorded elsewhere, and this reading measured none of them.\n")
	for _, p := range t.RoutePaths {
		heading := aHeading
		if p.Side == "b" {
			heading = bHeading
		}
		if p.Status != RouteBound {
			b.WriteString(heading + ": not bound. " + clean(p.Reason) + "\n")
			continue
		}
		b.WriteString(heading + ": bound. Source " + clean(p.Source) + " toward " + clean(p.Destination) + ".\n")
		b.WriteString("Compared with the topology: " + routeNames(p.Compared, routeComparedNames) + ".\n")
		b.WriteString("Not compared: " + routeNames(p.NotCompared, routeNotComparedNames) + ".\n")
		b.WriteString(p.Text)
	}
	return b.String()
}

// routeNames turns closed-vocabulary field names into the words for a person.
func routeNames(fields []string, names map[string]string) string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, names[f])
	}
	return strings.Join(out, ", ")
}
