package ospf

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// This file compares the link-state database with the calculated OSPF routes.
// It takes vendor-neutral evidence. A reader in another package turns one
// vendor's captures into these types. Nothing here parses a vendor format, and
// nothing here names a cause: a finding says what the evidence shows and what
// the captures cannot show.

// LSAType names an OSPFv2 advertisement type with the name the report shows.
type LSAType string

const (
	LSARouter      LSAType = "router"       // Type 1
	LSANetwork     LSAType = "network"      // Type 2
	LSASummary     LSAType = "summary"      // Type 3
	LSAASBRSummary LSAType = "asbr-summary" // Type 4
	LSAExternal    LSAType = "external"     // Type 5
	LSANSSA        LSAType = "nssa"         // Type 7
)

// countedTypes are the area-scoped types with counters in the process state.
var countedTypes = []LSAType{LSARouter, LSANetwork, LSASummary, LSAASBRSummary, LSANSSA}

// The kinds of LSDB finding. They share the Kind type with the adjacency
// findings, and each value is the text the report prints.
const (
	KindPrefixNotCalculated  Kind = "lsdb_prefix_not_calculated"
	KindLSDBIncomplete       Kind = "lsdb_incomplete"
	KindComparisonUnverified Kind = "ospf_comparison_unverified"
)

const (
	maxAge        = 3600     // LSA age at which an advertisement is withdrawn (RFC 2328)
	lsInfinity    = 0xffffff // LSInfinity, the metric of an unusable route (libospf.h)
	aseIntervalMs = 1000     // AS-external calculation timer (ospf_ase.c, OSPF_ASE_CALC_INTERVAL)
)

// Count is a number of LSAs and the sum of their checksums.
type Count struct {
	Number   uint64 `json:"number"`
	Checksum uint64 `json:"checksum"`
}

// Area is one area's SPF counter and its per-type LSA counters, as the process
// state reports them.
type Area struct {
	SPFExecuted uint64            `json:"spf_executed"`
	Counts      map[LSAType]Count `json:"counts"`
}

// Process is one read of the process state. RouterID is empty when the capture
// holds no router ID, as for an instance that has not taken one. That is not an
// empty LSDB, and the comparison treats it as unknown.
type Process struct {
	Source        string          `json:"source"`
	CollectedAt   time.Time       `json:"collected_at"`
	RouterID      string          `json:"router_id,omitempty"`
	HoldtimeMaxMs uint64          `json:"holdtime_max_ms"`
	SPFDelayMs    uint64          `json:"spf_delay_ms"`
	External      Count           `json:"external"`
	Areas         map[string]Area `json:"areas,omitempty"`
}

// Prefix is one prefix an advertisement names. Note says what the reader did to
// it, such as masking host bits.
type Prefix struct {
	Prefix netip.Prefix `json:"prefix"`
	Note   string       `json:"note,omitempty"`
}

// LSA is one advertisement. Area is empty for AS-scope advertisements (Type 5).
// Metric is set for Type 5 only. Prefixes holds what the advertisement names, and
// Note holds what the reader could not derive from it.
type LSA struct {
	Area              string   `json:"area,omitempty"`
	Type              LSAType  `json:"type"`
	LinkStateID       string   `json:"link_state_id"`
	AdvertisingRouter string   `json:"advertising_router"`
	Age               uint64   `json:"age"`
	Sequence          string   `json:"sequence"`
	Checksum          uint64   `json:"checksum"`
	Metric            *uint64  `json:"metric,omitempty"`
	Prefixes          []Prefix `json:"prefixes,omitempty"`
	Note              string   `json:"note,omitempty"`
}

// Unsupported counts entries of a type the comparison does not derive. Area is
// empty for AS-scope entries.
type Unsupported struct {
	Area    string `json:"area,omitempty"`
	Section string `json:"section"`
	Entries int    `json:"entries"`
}

// UnknownContent names content the reader does not recognize. Area is empty for
// content outside every area. Such content may hold prefixes, so the comparison
// draws no prefix finding in its scope.
type UnknownContent struct {
	Area    string `json:"area,omitempty"`
	Section string `json:"section"`
}

// LSDB is one read of the link-state database.
type LSDB struct {
	Source      string           `json:"source"`
	CollectedAt time.Time        `json:"collected_at"`
	RouterID    string           `json:"router_id"`
	LSAs        []LSA            `json:"lsas"`
	Unsupported []Unsupported    `json:"unsupported,omitempty"`
	Unknown     []UnknownContent `json:"unknown,omitempty"`
}

// Route is one calculated prefix route.
type Route struct {
	Prefix    netip.Prefix `json:"prefix"`
	RouteType string       `json:"route_type"`
	Area      string       `json:"area,omitempty"`
	Cost      uint64       `json:"cost"`
	Type2Cost *uint64      `json:"type2_cost,omitempty"`
	NextHops  int          `json:"next_hops"`
}

// Routes is one read of the calculated route table. Known is false for an empty
// table, which the command prints as an empty object. That object does not tell
// "nothing computed yet" from "nothing to route", so the comparison treats it as
// unknown.
type Routes struct {
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collected_at"`
	Known       bool      `json:"known"`
	Routers     int       `json:"routers"`
	Entries     []Route   `json:"entries"`
}

// Refusal names a capture that could not be read. Kind is "process", "lsdb", or
// "routes".
type Refusal struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// NodeInput is the evidence for one node in one VRF. Processes holds the
// accepted process-state captures in any order. LSDB and Routes are nil when no
// accepted capture gave them.
type NodeInput struct {
	Node      string
	VRF       string
	Processes []Process
	LSDB      *LSDB
	Routes    *Routes
	Refused   []Refusal
}

// Guard says whether the captures bracket one stable state. Passed is false when
// any check fails, and Reasons names each failed check. A passed guard is a
// guarded comparison. It is not proof that OSPF stayed still between the
// captures, because the collection times come from the caller.
type Guard struct {
	Passed  bool     `json:"passed"`
	Reasons []string `json:"reasons,omitempty"`
}

// Reconciliation compares one area and type of the LSDB with the process state.
// Process is nil when the process state has no such area.
type Reconciliation struct {
	Area    string  `json:"area,omitempty"`
	Type    LSAType `json:"type"`
	Matched bool    `json:"matched"`
	LSDB    Count   `json:"lsdb"`
	Process *Count  `json:"process,omitempty"`
}

// LSAFact is one advertisement with the use the comparison made of it.
type LSAFact struct {
	LSA
	Use string `json:"use"`
}

// LSDBFinding is one reading of the LSDB evidence. The advertisement fields are
// set when the finding is about one advertisement, and Type names the scope when
// it is about an area or a whole VRF.
type LSDBFinding struct {
	Kind              Kind      `json:"kind"`
	Strength          Strength  `json:"strength"`
	Node              string    `json:"node"`
	VRF               string    `json:"vrf"`
	Area              string    `json:"area,omitempty"`
	Type              LSAType   `json:"type,omitempty"`
	Scope             string    `json:"scope,omitempty"` // "lsdb", "routes", "router-id", or a section name, for a finding not about one type
	Prefix            string    `json:"prefix,omitempty"`
	LinkStateID       string    `json:"link_state_id,omitempty"`
	AdvertisingRouter string    `json:"advertising_router,omitempty"`
	Sequence          string    `json:"sequence,omitempty"`
	Source            string    `json:"source,omitempty"`
	CollectedAt       time.Time `json:"collected_at,omitzero"`
	Detail            string    `json:"detail"`
	Limit             string    `json:"limit"`
}

// ReadInfo names the capture that gave a set of facts, with its declared
// collection time.
type ReadInfo struct {
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collected_at"`
}

// NodeReport is the comparison for one node in one VRF. The facts are what the
// captures reported. LSDBRead and RoutesRead name the captures that gave the LSA
// and route facts, and each is nil when that capture was not read.
type NodeReport struct {
	Node           string           `json:"node"`
	VRF            string           `json:"vrf"`
	Guard          Guard            `json:"guard"`
	Processes      []Process        `json:"processes,omitempty"`
	Reconciliation []Reconciliation `json:"reconciliation,omitempty"`
	LSDBRead       *ReadInfo        `json:"lsdb_read,omitempty"`
	LSAs           []LSAFact        `json:"lsas,omitempty"`
	Unsupported    []Unsupported    `json:"unsupported,omitempty"`
	RoutesRead     *ReadInfo        `json:"routes_read,omitempty"`
	Routes         []Route          `json:"routes,omitempty"`
	Findings       []LSDBFinding    `json:"findings"`
}

// LSDBReport is the LSDB comparison of one import.
type LSDBReport struct {
	Nodes       []NodeReport `json:"nodes"`
	Limitations []string     `json:"limitations"`
}

// lsdbLimitations are the limits every LSDB report carries.
var lsdbLimitations = []string{
	"the LSDB and the calculated routes are what FRR printed for the captures. They are not the RIB and not the kernel forwarding table.",
	"the guard compares declared collection times and counters. A passed guard is a guarded comparison, not proof that OSPF did not change between the captures.",
	"only the default VRF is read. Only prefixes from Type 1 stub links and from Type 5 advertisements of other routers are compared.",
	"Type 2, Type 3, Type 4, Type 7, and opaque advertisements are reported as facts. No finding is drawn from them.",
	"point-to-point and virtual links are not derived to prefixes. Their advertisements are reported as facts only.",
	"an advertising router ID is not mapped to a node. The report names routers by router ID.",
}

// Finding limits. Each one says what the evidence cannot show. None names a
// cause.
const (
	limitPrefixNotCalculated = "The LSDB advertises this prefix, and the calculated OSPF route table has no route for it. The evidence names no cause and says nothing about forwarding."
	limitLSDBIncomplete      = "The LSDB or route evidence is incomplete for this scope. Nothing is concluded about the prefixes it would cover."
	limitUnverified          = "The captures do not show one stable state of OSPF, or a capture is missing. No comparison is made for this node."
)

// CompareLSDB reads the evidence of each node and returns its guard, its facts,
// and its findings. The result does not depend on the order of the input.
func CompareLSDB(nodes []NodeInput) LSDBReport {
	ordered := slices.Clone(nodes)
	slices.SortFunc(ordered, func(a, b NodeInput) int {
		return cmp.Or(strings.Compare(a.VRF, b.VRF), strings.Compare(a.Node, b.Node))
	})
	out := LSDBReport{Limitations: lsdbLimitations, Nodes: []NodeReport{}}
	for _, n := range ordered {
		out.Nodes = append(out.Nodes, compareNode(n))
	}
	return out
}

// scopeKey names one area and type of the LSDB. The external scope has an empty
// area.
type scopeKey struct {
	area string
	t    LSAType
}

// gate records which scopes may be compared. A scope is compared only when its
// reconciliation matched, and no unknown content or identity mismatch blocks it.
type gate struct {
	vrf        bool
	areas      map[string]bool
	reconciled map[scopeKey]bool
}

func (g gate) allows(area string, t LSAType) bool {
	return !g.vrf && !g.areas[area] && g.reconciled[scopeKey{area, t}]
}

// compareNode runs the guard, the reconciliation, and the finding rules for one
// node.
func compareNode(n NodeInput) NodeReport {
	rep := NodeReport{Node: n.Node, VRF: n.VRF, Findings: []LSDBFinding{}}
	procs := slices.Clone(n.Processes)
	slices.SortStableFunc(procs, func(a, b Process) int {
		return cmp.Or(a.CollectedAt.Compare(b.CollectedAt), strings.Compare(a.Source, b.Source))
	})
	rep.Processes = procs
	if n.LSDB != nil {
		rep.LSDBRead = &ReadInfo{Source: n.LSDB.Source, CollectedAt: n.LSDB.CollectedAt}
		rep.Unsupported = sortedUnsupported(n.LSDB.Unsupported)
	}
	if n.Routes != nil {
		rep.RoutesRead = &ReadInfo{Source: n.Routes.Source, CollectedAt: n.Routes.CollectedAt}
	}

	a, reasons := checkGuard(n, procs)
	rep.Guard = Guard{Passed: len(reasons) == 0, Reasons: reasons}
	var findings []LSDBFinding
	if len(reasons) > 0 {
		findings = append(findings, LSDBFinding{
			Kind: KindComparisonUnverified, Strength: Unknown, Node: n.Node, VRF: n.VRF,
			Detail: "The comparison is withheld: " + strings.Join(reasons, "; ") + ".",
			Limit:  limitUnverified,
		})
	}
	for _, r := range n.Refused {
		if r.Kind == "lsdb" || r.Kind == "routes" {
			findings = append(findings, LSDBFinding{
				Kind: KindLSDBIncomplete, Strength: Unknown, Node: n.Node, VRF: n.VRF,
				Scope: r.Kind, Source: r.Source,
				Detail: fmt.Sprintf("The %s capture was refused: %s.", r.Kind, r.Reason),
				Limit:  limitLSDBIncomplete,
			})
		}
	}

	// The reconciliation checks the LSDB against process state A, the earlier
	// capture. The guard has already required A and D to agree.
	var g gate
	if a != nil && a.RouterID != "" && n.LSDB != nil {
		var rows []Reconciliation
		rows, findings = reconcile(n, a, findings)
		rep.Reconciliation = rows
		g = gateOf(n, a, rows, &findings)
	}

	var canCompare string
	switch {
	case len(reasons) > 0:
		canCompare = "the guard failed"
	case n.Routes == nil || !n.Routes.Known:
		canCompare = "the calculated route table is not known"
	case n.LSDB == nil:
		canCompare = "the LSDB was not read"
	}
	if n.LSDB != nil && a != nil && a.RouterID != "" && n.Routes != nil && !n.Routes.Known {
		findings = append(findings, LSDBFinding{
			Kind: KindLSDBIncomplete, Strength: Unknown, Node: n.Node, VRF: n.VRF,
			Scope: "routes", Source: n.Routes.Source, CollectedAt: n.Routes.CollectedAt,
			Detail: "The calculated route table is empty or was not captured, so prefixes cannot be compared.",
			Limit:  limitLSDBIncomplete,
		})
	}

	if n.LSDB != nil {
		lsdb := slices.Clone(n.LSDB.LSAs)
		slices.SortStableFunc(lsdb, compareLSA)
		routes := routeSet(n.Routes)
		for _, l := range lsdb {
			use, candidates := lsaUse(l, a, g, canCompare)
			rep.LSAs = append(rep.LSAs, LSAFact{LSA: l, Use: use})
			for _, p := range candidates {
				if !routes[p.Prefix] {
					findings = append(findings, prefixFinding(n, l, p))
				}
			}
		}
	}
	if n.Routes != nil {
		rep.Routes = sortedRoutes(n.Routes.Entries)
	}
	sortFindings(findings)
	rep.Findings = append(rep.Findings, findings...)
	return rep
}

// checkGuard returns the process state A, the earlier capture, and every failed
// guard check. A is nil when fewer than two readable process states exist.
func checkGuard(n NodeInput, procs []Process) (*Process, []string) {
	var reasons []string
	for _, r := range n.Refused {
		if r.Kind == "process" {
			reasons = append(reasons, fmt.Sprintf("process-state capture %q was refused: %s", r.Source, r.Reason))
		}
	}
	if len(procs) != 2 {
		reasons = append(reasons, fmt.Sprintf("the comparison needs two readable process-state captures, before and after; there are %d", len(procs)))
		return nil, reasons
	}
	a, d := &procs[0], &procs[1]
	if a.CollectedAt.Equal(d.CollectedAt) {
		// Neither capture can be named the earlier one, so neither may stand for A.
		return nil, append(reasons, "the two process-state captures have the same collection time, so their order is unknown")
	}
	if n.LSDB == nil {
		reasons = append(reasons, "no readable LSDB capture")
	}
	if n.Routes == nil {
		reasons = append(reasons, "no readable calculated-route capture")
	}
	if n.LSDB != nil && n.Routes != nil {
		b, e := n.LSDB.CollectedAt, n.Routes.CollectedAt
		if !a.CollectedAt.Before(b) || !b.Before(e) || !e.Before(d.CollectedAt) {
			reasons = append(reasons, fmt.Sprintf("the captures are out of order or tied: A %s, B %s, E %s, D %s",
				stamp(a.CollectedAt), stamp(b), stamp(e), stamp(d.CollectedAt)))
		}
	}
	if a.RouterID == "" || d.RouterID == "" {
		reasons = append(reasons, "capture A or D holds no router ID, so OSPF has no identity to compare")
	} else if a.RouterID != d.RouterID {
		reasons = append(reasons, fmt.Sprintf("the router ID changed from %s to %s", a.RouterID, d.RouterID))
	}
	bound, timerReasons := windowBound(a, d)
	reasons = append(reasons, timerReasons...)
	if len(timerReasons) == 0 {
		if window := d.CollectedAt.Sub(a.CollectedAt); window <= time.Duration(bound)*time.Millisecond {
			reasons = append(reasons, fmt.Sprintf("the window of %s does not exceed the %dms timer bound", window, bound))
		}
	}
	return a, append(reasons, compareStates(a, d)...)
}

// compareStates lists how A and D differ. It names an SPF counter only when that
// counter moved. A timer change is named as a configuration change. It does not
// show that SPF ran.
func compareStates(a, d *Process) []string {
	var reasons []string
	if a.HoldtimeMaxMs != d.HoldtimeMaxMs {
		reasons = append(reasons, fmt.Sprintf("the holdtime maximum changed from %d ms to %d ms between A and D", a.HoldtimeMaxMs, d.HoldtimeMaxMs))
	}
	if a.SPFDelayMs != d.SPFDelayMs {
		reasons = append(reasons, fmt.Sprintf("the SPF delay changed from %d ms to %d ms between A and D", a.SPFDelayMs, d.SPFDelayMs))
	}
	ka, kd := slices.Sorted(maps.Keys(a.Areas)), slices.Sorted(maps.Keys(d.Areas))
	if !slices.Equal(ka, kd) {
		return append(reasons, fmt.Sprintf("the area inventory changed from %s to %s", strings.Join(ka, ","), strings.Join(kd, ",")))
	}
	for _, id := range ka {
		aa, da := a.Areas[id], d.Areas[id]
		if aa.SPFExecuted != da.SPFExecuted {
			reasons = append(reasons, fmt.Sprintf("the SPF counter of area %s changed from %d to %d", id, aa.SPFExecuted, da.SPFExecuted))
		}
		for _, t := range countedTypes {
			if aa.Counts[t] != da.Counts[t] {
				reasons = append(reasons, fmt.Sprintf("the %s LSA count or checksum of area %s changed between A and D", t, id))
			}
		}
	}
	if a.External != d.External {
		reasons = append(reasons, "the AS-external LSA count or checksum changed between A and D")
	}
	return reasons
}

// reconcile checks each area and type of the LSDB against the process state. It
// returns one row per area and type, and an lsdb_incomplete finding for each row
// that does not match.
func reconcile(n NodeInput, a *Process, findings []LSDBFinding) ([]Reconciliation, []LSDBFinding) {
	got := map[scopeKey]Count{}
	areas := map[string]bool{}
	for id := range a.Areas {
		areas[id] = true
	}
	for _, l := range n.LSDB.LSAs {
		if l.Area != "" {
			areas[l.Area] = true
		}
		c := got[scopeKey{l.Area, l.Type}]
		c.Number++
		c.Checksum += l.Checksum
		got[scopeKey{l.Area, l.Type}] = c
	}
	var rows []Reconciliation
	add := func(area string, t LSAType, want *Count) {
		lsdb := got[scopeKey{area, t}]
		row := Reconciliation{Area: area, Type: t, LSDB: lsdb, Process: want, Matched: want != nil && lsdb == *want}
		rows = append(rows, row)
		if row.Matched {
			return
		}
		detail := fmt.Sprintf("The LSDB holds %d %s advertisements with a checksum sum of %d", lsdb.Number, t, lsdb.Checksum)
		if want == nil {
			detail += ", and the process state has no such area"
		} else {
			detail += fmt.Sprintf(", and the process state counts %d with a checksum sum of %d", want.Number, want.Checksum)
		}
		findings = append(findings, LSDBFinding{
			Kind: KindLSDBIncomplete, Strength: Unknown, Node: n.Node, VRF: n.VRF,
			Area: area, Type: t, Source: n.LSDB.Source, CollectedAt: n.LSDB.CollectedAt,
			Detail: detail + ".", Limit: limitLSDBIncomplete,
		})
	}
	ext := a.External
	add("", LSAExternal, &ext)
	for _, id := range slices.Sorted(maps.Keys(areas)) {
		st, ok := a.Areas[id]
		for _, t := range countedTypes {
			if !ok {
				add(id, t, nil)
				continue
			}
			c := st.Counts[t]
			add(id, t, &c)
		}
	}
	return rows, findings
}

// gateOf turns the reconciliation rows and the LSDB's own identity and unknown
// content into the scopes that may be compared. Each blocking condition also
// adds the lsdb_incomplete finding that explains it.
func gateOf(n NodeInput, a *Process, rows []Reconciliation, findings *[]LSDBFinding) gate {
	g := gate{areas: map[string]bool{}, reconciled: map[scopeKey]bool{}}
	for _, row := range rows {
		g.reconciled[scopeKey{row.Area, row.Type}] = row.Matched
	}
	if n.LSDB.RouterID != a.RouterID {
		g.vrf = true
		*findings = append(*findings, LSDBFinding{
			Kind: KindLSDBIncomplete, Strength: Unknown, Node: n.Node, VRF: n.VRF,
			Scope: "router-id", Source: n.LSDB.Source, CollectedAt: n.LSDB.CollectedAt,
			Detail: fmt.Sprintf("The LSDB reports router ID %s, and the process state reports %s, so the LSDB may not be from this instance.", n.LSDB.RouterID, a.RouterID),
			Limit:  limitLSDBIncomplete,
		})
	}
	for _, u := range n.LSDB.Unknown {
		if u.Area == "" {
			g.vrf = true
		} else {
			g.areas[u.Area] = true
		}
		*findings = append(*findings, LSDBFinding{
			Kind: KindLSDBIncomplete, Strength: Unknown, Node: n.Node, VRF: n.VRF,
			Area: u.Area, Scope: u.Section, Source: n.LSDB.Source, CollectedAt: n.LSDB.CollectedAt,
			Detail: fmt.Sprintf("The LSDB holds content in section %q that the reader does not recognize.", u.Section),
			Limit:  limitLSDBIncomplete,
		})
	}
	return g
}

// maxTimerMs is the largest SPF timer a capture may declare. The CLI takes each of
// "timers throttle spf" delay, initial hold, and maximum hold only up to 600000
// ms (FRR 10.7.0, ospfd/ospf_vty.c:2344), and the process state prints the delay
// and the maximum hold from those values. Above it, FRR cannot have set the timer.
const maxTimerMs = 600000

// windowBound returns the wait that the window must exceed, in milliseconds. It
// is the larger of the holdtime maximum plus SPF delay read from A and from D,
// and at least the AS-external calculation interval. A timer above maxTimerMs
// gives no bound. Each such timer is named as a reason, and the sum is never
// formed from it.
func windowBound(a, d *Process) (int64, []string) {
	var reasons []string
	for _, p := range []struct {
		label string
		p     *Process
	}{{"A", a}, {"D", d}} {
		for _, t := range []struct {
			name string
			ms   uint64
		}{{"holdtime maximum", p.p.HoldtimeMaxMs}, {"SPF delay", p.p.SPFDelayMs}} {
			if t.ms > maxTimerMs {
				reasons = append(reasons, fmt.Sprintf("the %s of capture %s is %d ms, above the %d ms limit of timers throttle spf", t.name, p.label, t.ms, maxTimerMs))
			}
		}
	}
	if len(reasons) > 0 {
		return 0, reasons
	}
	bound := int64(aseIntervalMs)
	for _, p := range []*Process{a, d} {
		// Each timer is at most maxTimerMs here, so the sum fits int64.
		bound = max(bound, int64(p.HoldtimeMaxMs)+int64(p.SPFDelayMs)) // #nosec G115 -- each timer is at most maxTimerMs
	}
	return bound, nil
}

// lsaUse decides whether an advertisement is compared, and says why not when it
// is not. Its candidate prefixes are the ones a finding may name. The external
// rules follow the FRR route calculation in ospfd/ospf_ase.c (lines 187-260): an
// LSA at MaxAge, a self-originated LSA, and a metric of OSPF_LS_INFINITY
// (libospf.h:37) are skipped, because the calculation skips them too.
func lsaUse(l LSA, a *Process, g gate, canCompare string) (string, []Prefix) {
	switch {
	case l.Age >= maxAge:
		return "not compared: MaxAge", nil
	case l.Type == LSAExternal && a != nil && l.AdvertisingRouter == a.RouterID:
		return "not compared: self-originated; the calculation skips these", nil
	case l.Type == LSAExternal && l.Metric != nil && *l.Metric >= lsInfinity:
		return "not compared: metric is LSInfinity", nil
	case l.Type != LSARouter && l.Type != LSAExternal:
		return "reported only: this type is not compared", nil
	case l.Type == LSARouter && len(l.Prefixes) == 0:
		return "reported only: no stub link", nil
	case canCompare != "":
		return "not compared: " + canCompare, nil
	case !g.allows(l.Area, l.Type):
		return "not compared: this area or type did not reconcile", nil
	}
	return "compared", l.Prefixes
}

// prefixFinding is the lsdb_prefix_not_calculated finding for one prefix.
func prefixFinding(n NodeInput, l LSA, p Prefix) LSDBFinding {
	return LSDBFinding{
		Kind: KindPrefixNotCalculated, Strength: ConsistentWith, Node: n.Node, VRF: n.VRF,
		Area: l.Area, Type: l.Type, Prefix: p.Prefix.String(),
		LinkStateID: l.LinkStateID, AdvertisingRouter: l.AdvertisingRouter, Sequence: l.Sequence,
		Source: n.LSDB.Source, CollectedAt: n.LSDB.CollectedAt,
		Detail: fmt.Sprintf("The %s advertisement %s from router %s names %s. No calculated route has that prefix.",
			l.Type, l.LinkStateID, l.AdvertisingRouter, p.Prefix),
		Limit: limitPrefixNotCalculated,
	}
}

// routeSet returns the prefixes of the calculated table. A nil or unknown table
// has none.
func routeSet(r *Routes) map[netip.Prefix]bool {
	set := map[netip.Prefix]bool{}
	if r == nil {
		return set
	}
	for _, e := range r.Entries {
		set[e.Prefix] = true
	}
	return set
}

// sortedUnsupported orders the unsupported counts by area, then section, so the
// report does not depend on the order the decoder met them.
func sortedUnsupported(in []Unsupported) []Unsupported {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b Unsupported) int {
		return cmp.Or(strings.Compare(a.Area, b.Area), strings.Compare(a.Section, b.Section))
	})
	return out
}

func sortedRoutes(in []Route) []Route {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b Route) int { return strings.Compare(a.Prefix.String(), b.Prefix.String()) })
	return out
}

func compareLSA(a, b LSA) int {
	return cmp.Or(
		strings.Compare(a.Area, b.Area),
		strings.Compare(string(a.Type), string(b.Type)),
		strings.Compare(a.LinkStateID, b.LinkStateID),
		strings.Compare(a.AdvertisingRouter, b.AdvertisingRouter),
	)
}

func sortFindings(fs []LSDBFinding) {
	slices.SortStableFunc(fs, func(a, b LSDBFinding) int {
		return cmp.Or(
			strings.Compare(string(a.Kind), string(b.Kind)),
			strings.Compare(a.Area, b.Area),
			strings.Compare(a.Scope, b.Scope),
			strings.Compare(string(a.Type), string(b.Type)),
			strings.Compare(a.Prefix, b.Prefix),
			strings.Compare(a.LinkStateID, b.LinkStateID),
			strings.Compare(a.AdvertisingRouter, b.AdvertisingRouter),
		)
	})
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
