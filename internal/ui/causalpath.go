// The causal path strip: the one line under the answer that draws the target's
// own dependency chain, so a failed rung and the checks that never got to run
// behind it read as one story rather than as five independent failures.
//
// It presents what the diagnosis already decided and interprets nothing: the
// rungs come from the probes this run was actually built with, the glyphs from
// their results, and the root marker from the diagnosis's own focus.

package ui

import (
	"slices"

	"github.com/charmbracelet/lipgloss"
	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// pathTips are the rungs a target path can end on: the endpoint connect and
// the protocol checks that sit on top of it. Every other node in the DAG hangs
// off the side of that chain (Path MTU, QUIC, the proxy, the second-opinion and
// encrypted resolvers, Wi-Fi), and sweeping those into one line would draw a
// sequence the run never had.
var pathTips = []diagnostic.ProbeID{
	diagnostic.ProbeTargetTCP, diagnostic.ProbeTLS, diagnostic.ProbeHTTP,
	diagnostic.ProbeHTTPS, diagnostic.ProbeSSH, diagnostic.ProbeSMTP,
}

// pathLabels are the short names the strip draws. The probe rows carry the
// host and port, which is what the Checks panel below is for; a path is only
// scannable if each rung is one word.
var pathLabels = map[diagnostic.ProbeID]string{
	diagnostic.ProbeIface:     "Interface",
	diagnostic.ProbeDNS:       "DNS",
	diagnostic.ProbeTargetTCP: "TCP",
	diagnostic.ProbeTLS:       "TLS",
	diagnostic.ProbeHTTP:      "HTTP",
	diagnostic.ProbeHTTPS:     "HTTPS",
	diagnostic.ProbeSSH:       "SSH",
	diagnostic.ProbeSMTP:      "SMTP",
}

// pathRootLabel marks the rung the diagnosis is about. It is a word rather than
// a colour, for the same reason the consequence label is: colour alone is not a
// distinction every reader or every terminal can see.
const pathRootLabel = "[root]"

// pathMaxRows is how far the strip may wrap before it stops being something to
// take in at a glance. Past it the line is dropped: the Checks panel below is
// still saying all of this, at length.
const pathMaxRows = 2

// servicePath is the chain this run has to walk to reach the target's service:
// the longest dependency chain ending at one of pathTips, root first. It is
// read off the probes the run was built with, so the protocol, an IP literal,
// --check and --skip all decide it for free, and a node this plan does not have
// can never appear in it.
//
// nil when the plan holds no target rung at all, which is every targetless run
// and any selection that kept none: a generic run has no target path, and
// inventing one would be drawing a claim the run did not make.
func servicePath(probes []diagnostic.Probe) []diagnostic.ProbeID {
	byID := make(map[diagnostic.ProbeID]diagnostic.Probe, len(probes))
	for _, p := range probes {
		byID[p.ID] = p
	}
	var best []diagnostic.ProbeID
	for _, p := range probes {
		if !slices.Contains(pathTips, p.ID) {
			continue
		}
		// Strictly longer, so a tie keeps the earlier rung: two tips of equal
		// depth are on separate branches (plain HTTP beside the endpoint
		// connect), and the endpoint the target names comes first in the plan.
		if chain := depChain(byID, p.ID); len(chain) > len(best) {
			best = chain
		}
	}
	return best
}

// depChain is id's dependency chain within one plan, root first, and nil when
// id is not in it. Where a node has more than one dependency the longest chain
// wins, so the strip shows the deepest real path to that node rather than an
// arbitrary one.
func depChain(byID map[diagnostic.ProbeID]diagnostic.Probe, id diagnostic.ProbeID) []diagnostic.ProbeID {
	p, ok := byID[id]
	if !ok {
		return nil
	}
	var best []diagnostic.ProbeID
	for _, dep := range p.Deps {
		if chain := depChain(byID, dep); len(chain) > len(best) {
			best = chain
		}
	}
	return append(best, id)
}

// pathRoot is the rung the strip marks as the root cause: the row the
// diagnosis itself focuses on, when that row is on the drawn path and did
// actually fail. Empty otherwise, and empty is a perfectly good answer.
//
// Focus, deliberately, and never Blamed. Blamed falls back to the first failed
// row so a caller always has somewhere to put a cursor, and where the cursor
// sits is not a claim about what caused anything: a diagnosis that names no row
// leaves the strip unmarked. It takes the whole diagnosis rather than reading
// one off the model so that this rule, which is the only assertion the strip
// makes, can be pinned on its own.
func pathRoot(d diagnostic.Diagnosis, res map[diagnostic.ProbeID]diagnostic.ProbeResult, path []diagnostic.ProbeID) diagnostic.ProbeID {
	focus := d.Focus()
	if focus == "" || !slices.Contains(path, focus) {
		return ""
	}
	if res[focus].Status != diagnostic.StatusFail {
		return ""
	}
	return focus
}

// pathImpaired reports whether the path holds anything the verdict has not
// already said in one sentence: a rung that failed, that is degraded, or that
// never got to run behind one of those. An end-to-end pass is not a story, and
// neither is a rung that did not apply (DNS against an IP literal), so a clean
// run keeps the one-line answer and the collapsed list it has always had
// instead of gaining a widget that agrees with it.
func pathImpaired(res map[diagnostic.ProbeID]diagnostic.ProbeResult, path []diagnostic.ProbeID) bool {
	for _, id := range path {
		switch res[id].Status {
		case diagnostic.StatusFail, diagnostic.StatusWarn, diagnostic.StatusSkip:
			return true
		}
	}
	return false
}

// pathView is the strip itself, unterminated and empty whenever there is
// nothing truthful, useful or readable to draw: an unfinished run, one with no
// target path, one whose path is intact, or a terminal too narrow to lay the
// rungs out without shredding them. It wraps only between rungs, never inside
// one, and continuation lines open with the arrow that carried them there.
func (m model) pathView() string {
	if !m.allDone() {
		return "" // the strip explains the answer, and there is no answer yet
	}
	// A single node is a rung rather than a path, and an intact path is the
	// verdict's line to deliver on its own.
	path := servicePath(m.probes)
	if len(path) < 2 || !pathImpaired(m.results, path) {
		return ""
	}
	root := pathRoot(m.diagnosis(), m.results, path)
	chips := make([]string, len(path))
	for i, id := range path {
		label, ok := pathLabels[id]
		if !ok {
			label = string(id)
		}
		if m.results[id].Status == diagnostic.StatusSkip {
			// A skipped rung is downstream of one that already failed. The
			// glyph says so, and dimming the label keeps it from reading as a
			// failure of its own.
			label = m.st.faint.Render(label)
		}
		chips[i] = m.glyph(id) + " " + label
		if id == root {
			chips[i] += " " + m.st.fail.Render(pathRootLabel)
		}
		if i > 0 {
			chips[i] = m.st.faint.Render("→ ") + chips[i]
		}
	}
	// The title rides on the first rung so line 1's width math includes it,
	// so the first label participates in the strip's width calculation.
	chips[0] = m.st.title.Render("Target path") + "  " + chips[0]
	// An unknown width puts every rung on its own line, which the row guard
	// below then drops, and no strip is the right answer for a terminal that
	// has not said how wide it is.
	strip := joinChips(m.width, " ", chips)
	if lipgloss.Height(strip) > pathMaxRows {
		return ""
	}
	return strip
}
