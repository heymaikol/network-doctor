package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"unicode/utf8"
)

// Channel record grammar and record classes (contract 3.2, 3.3 and 3.4). This file makes no system call and has no
// build constraint, so its tests run on every GOOS.

// ErrProtocolViolation reports a channel overflow: a ninth accepted record or a ninth EINTR return in one receive or
// drain (3.4). ErrObservation reports an unexpected receive or poll failure, or the receive call ceiling (3.4). The
// two are separate sentinels (R6-3).
var (
	ErrProtocolViolation = errors.New("supervisor: channel protocol violation")
	ErrObservation       = errors.New("supervisor: channel observation error")
)

// chanWire is the decoded content of one valid record (3.2 grammar).
type chanWire struct {
	V     int
	Type  string
	Kind  string
	Value int
}

// chanParse is one payload after parsing. OK: a valid record. Cand: a status candidate (3.2), which is valid UTF-8,
// one JSON object, and exactly one member named "type" whose value is the string "status".
type chanParse struct {
	W    chanWire
	OK   bool
	Cand bool
}

// chanFacts is what the kernel reported for one received record. N is the payload length. NFds is kept after the
// descriptors are closed, because the count is evidence (R6).
type chanFacts struct {
	N        int
	Trunc    bool
	Ctrunc   bool
	NFds     int
	HasCreds bool
	CredsPid int
}

// chanState is the admission and status state of one channel. Stage 0 wants init, 1 wants producer, 2 is admitted,
// 3 has read a valid status, and 4 is closed. poison is the sticky observation or overflow error (R6): once set, no
// read yields a status.
type chanState struct {
	stage  int
	pidI   int
	poison error
}

// chanIdentity reads the pid and parent pid of the process behind a pidfd (3.3, checks 4 and 7). Slice 1 defines
// this seam only. No implementation here calls PIDFD_GET_INFO. A real implementation (slice 2) must return an error
// unless the kernel reports both the pid and the ppid. A nil chanIdentity refuses every init and producer record, so
// the seam fails closed.
type chanIdentity interface {
	pidInfo(pidfd int) (pid, ppid int, err error)
}

// parseChanRecord applies the strict grammar of 3.2 (R5, R6) to one payload. The payload must be valid UTF-8 and
// exactly one JSON object. Names must be unique after unescape and allowed for the type. Numbers must be integers
// that fit the Go int of the build target. -0 and null are rejected.
func parseChanRecord(b []byte) chanParse {
	var out chanParse
	if !utf8.Valid(b) {
		return out
	}
	members, ok := chanMembers(b)
	if !ok {
		return out
	}
	typeCount := 0
	var typeRaw json.RawMessage
	for _, m := range members {
		if m.name == "type" {
			typeCount++
			typeRaw = m.raw
		}
	}
	if typeCount == 1 {
		var s string
		if chanDecodeStr(typeRaw, &s) && s == "status" {
			out.Cand = true
		}
	}
	seen := make(map[string]bool, len(members))
	for _, m := range members {
		if seen[m.name] {
			return out
		}
		seen[m.name] = true
	}
	if typeCount != 1 {
		return out
	}
	var typ string
	if !chanDecodeStr(typeRaw, &typ) {
		return out
	}
	var allowed []string
	switch typ {
	case "init", "producer":
		allowed = []string{"v", "type"}
	case "status":
		allowed = []string{"v", "type", "kind", "value"}
	default:
		return out
	}
	if len(members) != len(allowed) {
		return out
	}
	for _, m := range members {
		if !slices.Contains(allowed, m.name) {
			return out
		}
	}
	w := chanWire{Type: typ}
	if !chanDecodeInt(chanFind(members, "v"), &w.V) {
		return out
	}
	if typ == "status" {
		if !chanDecodeStr(chanFind(members, "kind"), &w.Kind) || !chanDecodeInt(chanFind(members, "value"), &w.Value) {
			return out
		}
	}
	out.W = w
	out.OK = true
	return out
}

// chanMember is one name and raw value of a JSON object, in wire order.
type chanMember struct {
	name string
	raw  json.RawMessage
}

// chanMembers returns the members of one JSON object, or false when the bytes are not exactly one object. Duplicate
// names are returned, not merged, so the caller can reject them.
func chanMembers(b []byte) ([]chanMember, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var out []chanMember
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, ok := kt.(string)
		if !ok {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		out = append(out, chanMember{name: name, raw: raw})
	}
	tok, err = dec.Token()
	if err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return out, true
}

func chanFind(members []chanMember, name string) json.RawMessage {
	for _, m := range members {
		if m.name == name {
			return m.raw
		}
	}
	return nil
}

func chanIsNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func chanDecodeStr(raw json.RawMessage, s *string) bool {
	if raw == nil || chanIsNull(raw) {
		return false
	}
	return json.Unmarshal(raw, s) == nil
}

// chanDecodeInt reads a canonical integer (3.2, R6). The token must be a JSON integer that fits the Go int of the
// build target. -0 is rejected. Fractions and exponents do not decode as integers. Leading zeros never reach this
// function, because the object scanner rejects them.
func chanDecodeInt(raw json.RawMessage, n *int) bool {
	if raw == nil || chanIsNull(raw) || bytes.Equal(bytes.TrimSpace(raw), []byte("-0")) {
		return false
	}
	var v int64
	if json.Unmarshal(raw, &v) != nil || int64(int(v)) != v {
		return false
	}
	*n = int(v)
	return true
}

// chanStatusGate returns the close reason for a record after admission that is not a clean status from pidI, or ""
// when the gate passes (3.2, 3.4). The post-admission rule and the T2 Known rule both use it.
func chanStatusGate(f chanFacts, p chanParse, pidI int) string {
	switch {
	case f.Trunc:
		return "trunc"
	case f.Ctrunc:
		return "ctrunc"
	case f.N == 0:
		return "empty"
	case !p.Cand && !p.OK:
		return "malformed"
	case !p.Cand:
		return "late_record"
	case !f.HasCreds || f.CredsPid != pidI:
		return "creds"
	case f.NFds > 0:
		return "status_fd"
	}
	return ""
}

// chanDecide returns the action for one record (3.3, 3.4). The result is one of "ACCEPT_INIT", "ACCEPT_PRODUCER",
// "KNOWN", "UNKNOWN:<reason>", "CLOSE:<reason>" or "DISCARD". fds are the descriptors the record carried. The caller
// owns them and closes them unless the action starts with "ACCEPT_".
func chanDecide(st *chanState, f chanFacts, p chanParse, fds []int, id chanIdentity) string {
	if st.stage == 4 {
		return "DISCARD"
	}
	if st.poison != nil {
		return "UNKNOWN:observed"
	}
	if st.stage >= 2 {
		return chanDecidePost(st, f, p)
	}
	closeWith := func(reason string) string {
		st.stage = 4
		return "CLOSE:" + reason
	}
	switch {
	case f.Trunc:
		return closeWith("trunc")
	case f.Ctrunc:
		return closeWith("ctrunc")
	case !f.HasCreds:
		return closeWith("nocreds")
	case f.N == 0:
		return closeWith("empty")
	case p.Cand:
		return closeWith("early_status")
	}
	want := [...]string{"init", "producer"}[st.stage]
	if !p.OK || p.W.Type != want || p.W.V != 1 {
		return closeWith("order")
	}
	if len(fds) != 1 {
		return closeWith("count")
	}
	if id == nil {
		return closeWith("pidfd_info")
	}
	pid, ppid, err := id.pidInfo(fds[0])
	if err != nil {
		return closeWith("pidfd_info")
	}
	if st.stage == 0 {
		if pid != f.CredsPid {
			return closeWith("creds_pidfd")
		}
		st.pidI = f.CredsPid
		st.stage = 1
		return "ACCEPT_INIT"
	}
	if f.CredsPid != st.pidI {
		return closeWith("creds")
	}
	if ppid != st.pidI {
		return closeWith("ppid")
	}
	st.stage = 2
	return "ACCEPT_PRODUCER"
}

// chanDecidePost is the rule for a record after admission (D15, 3.4). A record that fails the gate closes the
// channel. A valid status is read once. A second valid status, or a malformed or unknown-kind status with the right
// credentials, is class (b): ExitStatus is Unknown and no Close starts.
func chanDecidePost(st *chanState, f chanFacts, p chanParse) string {
	if reason := chanStatusGate(f, p, st.pidI); reason != "" {
		st.stage = 4
		return "CLOSE:" + reason
	}
	if st.stage == 3 {
		return "UNKNOWN:after_terminal"
	}
	st.stage = 3
	if !p.OK {
		return "UNKNOWN:malformed"
	}
	if p.W.V == 1 && (p.W.Kind == "exit" || p.W.Kind == "signal") {
		return "KNOWN"
	}
	return "UNKNOWN:status_shape"
}
