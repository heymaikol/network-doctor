package frrospf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/heymaikol/network-doctor/internal/ospf"
)

// Interface facts. An interface record can state four facts about one OSPF
// interface: its cost, its network type, its own state, and whether it is
// passive. Each is written as a control-plane attribute. Each field is decoded
// on its own. A field that is absent writes nothing. A field that is null, has
// the wrong JSON type, or holds a value outside its vocabulary writes nothing
// and gets a note. Only the DR and BDR addresses are read for another purpose:
// to detect a record that may describe a different OSPF interface on the same
// name. They are never written.
//
// The fact fields do not touch the ownership gate, which reads ipAddress alone.

const (
	keyCost           = ospf.KeyCost
	keyNetworkType    = ospf.KeyNetworkType
	keyInterfaceState = ospf.KeyInterfaceState
	keyPassive        = ospf.KeyPassive
)

// maxCost is the largest cost an OSPF interface carries, LS infinity. FRR writes
// cost 0 for a loopback, which is a valid value.
const maxCost = 65535

// networkTypes is the closed map from the networkType FRR prints to the name the
// topology uses. It reads only networkType. ospfIfType is a different field with
// a different meaning, and it is never read. Any other value, including "Null",
// is unreadable.
var networkTypes = map[string]string{
	"POINTOPOINT":      "point-to-point",
	"BROADCAST":        "broadcast",
	"NBMA":             "nbma",
	"POINTOMULTIPOINT": "point-to-multipoint",
	"VIRTUALLINK":      "virtual-link",
	"LOOPBACK":         "loopback",
}

// interfaceStates is the closed map from the state FRR prints for an interface's
// own state machine. A neighbor's state is a different field, and it never
// reaches this map.
var interfaceStates = map[string]string{
	"DependUpon":     "dependupon",
	"Down":           "down",
	"Loopback":       "loopback",
	"Waiting":        "waiting",
	"Point-To-Point": "point-to-point",
	"DROther":        "drother",
	"Backup":         "backup",
	"DR":             "dr",
}

// fact says what one raw interface field holds.
type fact int

const (
	factAbsent    fact = iota // the key is not in the record
	factNull                  // the key holds JSON null
	factMalformed             // the value has the wrong JSON type
	factValue                 // the value decodes into the target
)

// classify decodes one raw field into v and reports what the field holds.
func classify(raw json.RawMessage, v any) fact {
	switch {
	case raw == nil:
		return factAbsent
	case bytes.Equal(bytes.TrimSpace(raw), []byte("null")):
		return factNull
	case json.Unmarshal(raw, v) != nil:
		return factMalformed
	}
	return factValue
}

// costFact reads cost. An absent key is noted only on a numbered interface,
// because FRR always writes cost there.
func costFact(name string, raw json.RawMessage, numbered bool) (string, string) {
	var n int
	switch classify(raw, &n) {
	case factAbsent:
		if numbered {
			return "", fmt.Sprintf("interface %s: cost is absent; not written", quote(name))
		}
		return "", ""
	case factNull:
		return "", fmt.Sprintf("interface %s: cost is null; not written", quote(name))
	case factMalformed:
		return "", fmt.Sprintf("interface %s: cost is not an integer; not written", quote(name))
	}
	if n < 0 || n > maxCost {
		return "", fmt.Sprintf("interface %s: cost %d is outside 0 to %d; not written", quote(name), n, maxCost)
	}
	return strconv.Itoa(n), ""
}

// vocabFact reads a field whose values come from a closed map. An absent key is
// noted only when noteAbsent is set.
func vocabFact(name, key string, raw json.RawMessage, vocab map[string]string, noteAbsent bool) (string, string) {
	var s string
	switch classify(raw, &s) {
	case factAbsent:
		if noteAbsent {
			return "", fmt.Sprintf("interface %s: %s is absent; not written", quote(name), key)
		}
		return "", ""
	case factNull:
		return "", fmt.Sprintf("interface %s: %s is null; not written", quote(name), key)
	case factMalformed:
		return "", fmt.Sprintf("interface %s: %s is not a string; not written", quote(name), key)
	}
	v, ok := vocab[s]
	if !ok {
		return "", fmt.Sprintf("interface %s: %s %s is not a known FRR value; not written", quote(name), key, quote(s))
	}
	return v, ""
}

// passiveResult is the passive reading of one record. value is "true", "false",
// or "" when no value is written. note says why none is written. mixed says the
// record holds timerPassiveIface true and a hello timer key together. A
// passive interface sends no hellos, so such a record may describe another OSPF
// interface on the same name.
type passiveResult struct {
	value string
	note  string
	mixed bool
}

// passiveFact applies the tri-state rule to one record. timerPassiveIface true
// with no hello timer is passive. A hello timer with no timerPassiveIface is
// active. Both keys together conflict, and a null or malformed key establishes
// neither state. FRR never writes timerPassiveIface false, so that value is
// malformed.
func passiveFact(name string, passive, hello json.RawMessage, numbered bool) passiveResult {
	var on bool
	pk := classify(passive, &on)
	hk := classify(hello, new(float64))
	res := passiveResult{mixed: pk == factValue && on && hk != factAbsent}
	switch {
	case pk == factValue && !on:
		res.note = "timerPassiveIface is false, which FRR does not write; no passive value is written"
	case pk == factNull || pk == factMalformed:
		res.note = "timerPassiveIface is unreadable; no passive value is written"
	case pk == factValue && on && hk == factValue:
		res.note = "passive status is reported both ways on this record, by timerPassiveIface and timerHelloInMsecs; no passive value is written"
	case pk == factValue && on && hk != factAbsent:
		res.note = "timerHelloInMsecs is unreadable beside timerPassiveIface; no passive value is written"
	case pk == factValue && on:
		res.value = "true"
	case pk == factAbsent && hk == factValue:
		res.value = "false"
	case pk == factAbsent && hk != factAbsent:
		res.note = "timerHelloInMsecs is unreadable; no passive value is written"
	case numbered:
		res.note = "neither timerPassiveIface nor timerHelloInMsecs is present; no passive value is written"
	}
	if res.note != "" {
		res.note = fmt.Sprintf("interface %s: %s", quote(name), res.note)
	}
	return res
}

// drCheck is the result of checking one DR or BDR address against the record's
// subnet. leak names the address when it lies outside the subnet. note says why
// the address was not checked, or the check was skipped.
type drCheck struct {
	leak string
	note string
}

// checkDR reads drAddress or bdrAddress. An absent or null field is not checked
// and gets no note. The address is validated as IPv4 before it is compared with
// the subnet. An unspecified address means no DR or BDR is elected, so it is not
// checked. The subnet check needs a usable prefix length, and without one the
// check is skipped.
func checkDR(name, key string, raw json.RawMessage, info ifaceInfo) drCheck {
	var s string
	switch classify(raw, &s) {
	case factAbsent, factNull:
		return drCheck{}
	case factMalformed:
		return drCheck{note: fmt.Sprintf("interface %s: %s is not a string; not checked", quote(name), key)}
	}
	addr, ok := parseIPv4(s)
	switch {
	case !ok:
		return drCheck{note: fmt.Sprintf("interface %s: %s %s is not IPv4; not checked", quote(name), key, quote(s))}
	case addr.IsUnspecified():
		return drCheck{}
	case !info.hasPrefix:
		return drCheck{note: fmt.Sprintf("interface %s: DR and BDR subnet check skipped; no usable ipAddressPrefixlen", quote(name))}
	case info.prefix.Masked().Contains(addr):
		return drCheck{}
	}
	return drCheck{leak: fmt.Sprintf("%s %s is outside %s", key, addr, info.prefix.Masked())}
}

// readFacts decodes the fact fields of one record into info, after its address
// fields are set. It returns one note per unreadable field. When D1 or D2 holds,
// it marks the name held and notes why. Clearing the held facts happens later,
// in Import, once the neighbor trigger is known.
func readFacts(name string, rec interfaceRecord, info *ifaceInfo) []string {
	var notes []string
	add := func(note string) {
		if note != "" {
			notes = append(notes, note)
		}
	}
	numbered := info.hasAddr
	var note string
	info.cost, note = costFact(name, rec.Cost, numbered)
	add(note)
	info.networkType, note = vocabFact(name, "networkType", rec.NetworkType, networkTypes, false)
	add(note)
	info.state, note = vocabFact(name, "state", rec.State, interfaceStates, numbered)
	add(note)
	p := passiveFact(name, rec.TimerPassiveIface, rec.TimerHelloInMsecs, numbered)
	info.passive = p.value
	add(p.note)
	dr := checkDR(name, "drAddress", rec.DRAddress, *info)
	bdr := checkDR(name, "bdrAddress", rec.BDRAddress, *info)
	add(dr.note)
	add(bdr.note)

	var reasons []string
	if p.mixed {
		reasons = append(reasons, "timerPassiveIface and timerHelloInMsecs both appear on this record")
	}
	for _, c := range []drCheck{dr, bdr} {
		if c.leak != "" {
			reasons = append(reasons, c.leak)
		}
	}
	if len(reasons) > 0 {
		info.held = true
		add(fmt.Sprintf("interface %s: facts withheld; the record may describe another OSPF interface on the name: %s", quote(name), strings.Join(reasons, "; ")))
	}
	return notes
}

// withhold clears the facts of a name whose record may describe another OSPF
// interface, the area included, and returns the keys it cleared. The facts are
// written only for an interface whose name holds one OSPF interface.
func (info *ifaceInfo) withhold() []string {
	var cleared []string
	for _, f := range []struct {
		key string
		val *string
	}{
		{keyEffectiveArea, &info.area},
		{keyCost, &info.cost},
		{keyNetworkType, &info.networkType},
		{keyInterfaceState, &info.state},
		{keyPassive, &info.passive},
	} {
		if *f.val != "" {
			cleared = append(cleared, f.key)
			*f.val = ""
		}
	}
	return cleared
}
