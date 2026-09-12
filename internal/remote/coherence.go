package remote

import (
	"encoding/json"
	"fmt"

	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// agree holds one response to the fact that its two artifacts describe one run.
//
// A successful exchange carries the report and the snapshot the remote built
// from a single pass, and the local side spends them separately: the report
// decides what is printed and what this process exits with, the snapshot is
// what --save writes to a file for a later comparison. Nothing downstream ever
// reads one against the other, so a pair that disagreed would leave a machine
// exiting 0 over a stored artifact that records a failure, and no later reader
// could tell which half was the run.
//
// Only the overlap is checked, and only the stable machine-readable part of
// it. The two formats are different contracts on purpose and neither is a
// projection of the other: the report carries remediation the snapshot does
// not, the snapshot carries observations and options the report does not, and
// the derived sentences in both are documented as never parsed back. What is
// left is what both publish about the same facts, and on those they cannot be
// allowed to differ.
//
// Unknown fields are not this function's business. Both artifacts decoded into
// this build's own structs, so anything a newer remote added is already gone,
// and refusing the response for carrying it would break the additive
// compatibility protocol 1 promises.
func agree(tool snapshot.Tool, rep report.Report, snap snapshot.Snapshot) error {
	// The snapshot has not been through Decode: it arrived as a field of the
	// response, so nothing has yet asked whether it is a snapshot at all.
	if err := snapshot.Validate(snap); err != nil {
		return fmt.Errorf("the remote sent an unusable snapshot: %w", err)
	}
	for _, pair := range []struct {
		what             string
		remote, artifact string
	}{
		{"netdoc version", tool.Version, snap.Tool.Version},
		{"operating system", tool.OS, snap.Tool.OS},
		{"architecture", tool.Arch, snap.Tool.Arch},
		{"netdoc version", rep.Version, snap.Tool.Version},
		{"verdict", rep.Verdict, snap.Diagnosis.Verdict},
		{"first failed check", rep.FailedStage, snap.Diagnosis.FailedStage},
	} {
		if pair.remote != pair.artifact {
			return disagree(pair.what, pair.remote, pair.artifact)
		}
	}
	if rep.OK != snap.OK {
		return disagree("overall result", okWord(rep.OK), okWord(snap.OK))
	}
	if err := agreeOnTarget(rep.Target, snap.Target); err != nil {
		return err
	}
	if err := agreeOnChecks(rep.Checks, snap.Checks); err != nil {
		return err
	}
	return agreeOnFindings(rep.Findings, snap.Diagnosis.Findings)
}

func agreeOnTarget(rep *report.Target, snap *snapshot.Target) error {
	// A generic run has no target in either artifact. One of them naming a
	// host is two different runs, not two readings of one.
	if (rep == nil) != (snap == nil) {
		return disagree("target", targetWord(rep != nil), targetWord(snap != nil))
	}
	if rep == nil {
		return nil
	}
	switch {
	case rep.Host != snap.Host:
		return disagree("target host", rep.Host, snap.Host)
	case rep.Port != snap.Port:
		return disagree("target port", fmt.Sprint(rep.Port), fmt.Sprint(snap.Port))
	case rep.Protocol != snap.Protocol:
		return disagree("target protocol", rep.Protocol, snap.Protocol)
	}
	return nil
}

// agreeOnChecks compares the rows as an ordered list, which is what both
// formats publish: the order is the order the run executed them in, and it is
// what makes first_failed derivable and a comparison's row matching meaningful.
func agreeOnChecks(rep []report.Check, snap []snapshot.Check) error {
	if len(rep) != len(snap) {
		return disagree("check count", fmt.Sprint(len(rep)), fmt.Sprint(len(snap)))
	}
	for i := range rep {
		switch {
		case rep[i].ID != snap[i].ID:
			return disagree(fmt.Sprintf("check %d", i+1), rep[i].ID, snap[i].ID)
		case rep[i].Status != snap[i].Status:
			return disagree("status of check "+rep[i].ID, rep[i].Status, snap[i].Status)
		case rep[i].Cause != snap[i].Cause:
			return disagree("cause of check "+rep[i].ID, rep[i].Cause, snap[i].Cause)
		}
	}
	return nil
}

// agreeOnFindings compares the conclusions both artifacts carry, in order:
// both list them most important first, and the first one is the primary
// conclusion in each.
//
// The typed evidence is compared as encoded JSON rather than field by field.
// The three evidence types are declared identically in both packages, down to
// the json tags, so their encodings are equal exactly when the values are, and
// no separator inside a value can forge a match the way a joined string can.
// TestSharedDiagnosisFieldsStayIdentical fails if the two declarations ever
// stop being the same shape, which is what keeps that reasoning true.
func agreeOnFindings(rep []report.Finding, snap []snapshot.Finding) error {
	if len(rep) != len(snap) {
		return disagree("finding count", fmt.Sprint(len(rep)), fmt.Sprint(len(snap)))
	}
	for i := range rep {
		switch {
		case rep[i].ID != snap[i].ID:
			return disagree(fmt.Sprintf("finding %d", i+1), rep[i].ID, snap[i].ID)
		case rep[i].Focus != snap[i].Focus:
			return disagree("focus of finding "+rep[i].ID, rep[i].Focus, snap[i].Focus)
		case rep[i].Confidence != snap[i].Confidence:
			return disagree("confidence of finding "+rep[i].ID, rep[i].Confidence, snap[i].Confidence)
		}
		for _, part := range []struct {
			what             string
			remote, artifact any
		}{
			{"evidence", rep[i].Evidence, snap[i].Evidence},
			{"causal evidence", rep[i].CausalEvidence, snap[i].CausalEvidence},
			{"counterfactual", rep[i].Counterfactual, snap[i].Counterfactual},
		} {
			remote, artifact := encoded(part.remote), encoded(part.artifact)
			if remote != artifact {
				return disagree(part.what+" of finding "+rep[i].ID, remote, artifact)
			}
		}
	}
	return nil
}

// encoded spells one value as the JSON both formats publish it as. Encoding
// cannot fail here: these are structs of strings, slices of them, and pointers
// to those, with no map, channel or function in reach.
func encoded(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}

// disagree words the contradiction with both halves named and both named as
// what they are, because "which file is wrong" is the first question and this
// is the only place that knows the answer is neither.
func disagree(what, rep, snap string) error {
	return fmt.Errorf("the remote report and snapshot describe different runs: %s is %q in the report and %q in the snapshot",
		what, rep, snap)
}

func okWord(ok bool) string {
	if ok {
		return "ok"
	}
	return "not ok"
}

func targetWord(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}
