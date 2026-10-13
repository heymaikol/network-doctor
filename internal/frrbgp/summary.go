// Package frrbgp reads recorded FRRouting 10.7.0 "show ip bgp summary json"
// output: the router ID, the local AS, and the peer sessions one capture
// reports, each with the state FRR printed for it.
//
// The package reads only the transcript it is handed. It never contacts a
// router or runs a command. A state is FRR's value at the capture's collection
// time, not a health judgment: a peer that is not Established is reported as
// observed, and an empty peer collection is observed empty, not down. The
// summary carries no routes, so the package reads none.
package frrbgp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// Version is the one FRRouting release this package reads. A capture declares
// it, and the caller refuses any other version.
const Version = "10.7.0"

// CommandSummary is the one command this package reads. The transcript echoes
// it before the output.
const CommandSummary = "show ip bgp summary json"

// maxDepth bounds object nesting. The summary nests four levels, so the bound
// only stops a crafted capture from deepening the walk.
const maxDepth = 8

// errNotObject means the output does not hold one JSON object where the summary
// belongs. vtysh prints plain-text errors in that position.
var errNotObject = errors.New("output is not a JSON object")

// Summary is the BGP state one capture reports for the IPv4 unicast family of
// the default VRF. Peers are in address order. An empty Peers slice is an
// observed empty collection, not a down session.
type Summary struct {
	RouterID string
	LocalAS  uint32
	Peers    []Peer
}

// Peer is one session as the summary reported it. State is FRR's session state
// text, verbatim. peerState is not read: it holds a value such as "OK" that is
// not a session state.
type Peer struct {
	Address  netip.Addr
	LocalAS  uint32
	RemoteAS uint32
	State    string
}

// Decode reads one capture of CommandSummary taken on node. The transcript must
// be FRR's VTY framing: the command echo, one JSON object, and the node's
// prompt, with CRLF line ends and nothing after the prompt. A repeated key at
// any depth, a recognized key that differs from its name only in case, and a
// value of the wrong type are all refused.
func Decode(data []byte, node string) (Summary, error) {
	body, err := transcriptBody(data, node)
	if err != nil {
		return Summary{}, err
	}
	if err := checkObjects(body); err != nil {
		return Summary{}, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil || top == nil {
		return Summary{}, errNotObject
	}
	raw, err := member(top, "the capture", "ipv4Unicast")
	if err != nil {
		return Summary{}, err
	}
	var uni map[string]json.RawMessage
	if err := json.Unmarshal(raw, &uni); err != nil || uni == nil {
		return Summary{}, errors.New(`"ipv4Unicast" is not a JSON object`)
	}
	var s Summary
	if raw, err = member(uni, `"ipv4Unicast"`, "routerId"); err != nil {
		return Summary{}, err
	}
	if s.RouterID, err = routerIDValue(raw); err != nil {
		return Summary{}, err
	}
	if raw, err = member(uni, `"ipv4Unicast"`, "as"); err != nil {
		return Summary{}, err
	}
	if s.LocalAS, err = asNumber(raw, `"as"`); err != nil {
		return Summary{}, err
	}
	if raw, err = member(uni, `"ipv4Unicast"`, "peers"); err != nil {
		return Summary{}, err
	}
	var peers map[string]json.RawMessage
	if err := json.Unmarshal(raw, &peers); err != nil || peers == nil {
		return Summary{}, errors.New(`"peers" is not a JSON object`)
	}
	s.Peers = make([]Peer, 0, len(peers))
	// Keys are read in sorted order, so the first refusal named is the same on
	// every run.
	for _, key := range slices.Sorted(maps.Keys(peers)) {
		p, err := peer(key, peers[key])
		if err != nil {
			return Summary{}, err
		}
		s.Peers = append(s.Peers, p)
	}
	slices.SortFunc(s.Peers, func(a, b Peer) int { return a.Address.Compare(b.Address) })
	return s, nil
}

// transcriptBody checks the VTY framing and returns the bytes between the echo
// and the prompt. FRR ends each line with CRLF, and the transcript ends with the
// prompt, so nothing may follow it and only one CRLF may precede it. The body
// must be exactly one object, so a blank line at either end is refused too.
func transcriptBody(data []byte, node string) ([]byte, error) {
	echo := CommandSummary + "\r\n"
	if !bytes.HasPrefix(data, []byte(echo)) {
		return nil, fmt.Errorf("transcript does not begin with the command echo %s and CRLF", quote(CommandSummary))
	}
	rest := data[len(echo):]
	prompt := "\r\n" + node + "> "
	if !bytes.HasSuffix(rest, []byte(prompt)) {
		return nil, fmt.Errorf("transcript does not end with CRLF and the prompt %s", quote(node+"> "))
	}
	body := rest[:len(rest)-len(prompt)]
	if len(body) == 0 || body[0] != '{' || body[len(body)-1] != '}' {
		return nil, errNotObject
	}
	return body, nil
}

// checkObjects walks body once. It refuses a key that repeats in one object at
// any depth, nesting past maxDepth, a truncated object, and data after the
// object. encoding/json keeps the last of two equal keys, so a repeat would
// change the capture without any sign of it.
func checkObjects(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := walkValue(dec, 0); err != nil {
		var syntax *json.SyntaxError
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return errors.New("JSON object is truncated")
		case errors.As(err, &syntax):
			return fmt.Errorf("not valid JSON at byte %d", syntax.Offset)
		}
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data follows the JSON object")
	}
	return nil
}

// walkValue checks every object in one JSON value and returns the first problem.
func walkValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxDepth {
		return errors.New("JSON nests too deeply")
	}
	seen := map[string]bool{}
	for dec.More() {
		if d == '{' {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			if seen[key] {
				return fmt.Errorf("duplicate key %s", quote(key))
			}
			seen[key] = true
		}
		if err := walkValue(dec, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

// peer reads one session. The key is the peer's address, and the value holds
// its localAs, remoteAs, and state.
func peer(key string, raw json.RawMessage) (Peer, error) {
	addr, err := peerAddress(key)
	if err != nil {
		return Peer{}, err
	}
	where := "peer " + key
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return Peer{}, fmt.Errorf("%s is not a JSON object", where)
	}
	p := Peer{Address: addr}
	value, err := member(obj, where, "localAs")
	if err != nil {
		return Peer{}, err
	}
	if p.LocalAS, err = asNumber(value, where+` "localAs"`); err != nil {
		return Peer{}, err
	}
	if value, err = member(obj, where, "remoteAs"); err != nil {
		return Peer{}, err
	}
	if p.RemoteAS, err = asNumber(value, where+` "remoteAs"`); err != nil {
		return Peer{}, err
	}
	if value, err = member(obj, where, "state"); err != nil {
		return Peer{}, err
	}
	if p.State, err = sessionState(value, where+` "state"`); err != nil {
		return Peer{}, err
	}
	return p, nil
}

// member returns the value under name. A key that differs from name only in
// case is refused: FRR never prints one, and a reader that folded case would
// take it as the value.
func member(obj map[string]json.RawMessage, where, name string) (json.RawMessage, error) {
	for _, key := range slices.Sorted(maps.Keys(obj)) {
		if key != name && strings.EqualFold(key, name) {
			return nil, fmt.Errorf("%s key %s differs from %s only in case", where, quote(key), quote(name))
		}
	}
	raw, ok := obj[name]
	if !ok {
		return nil, fmt.Errorf("%s has no %s", where, quote(name))
	}
	return raw, nil
}

// peerAddress accepts a peer key only in the form netip.Addr prints, with no
// zone, so each peer has one spelling in the report.
func peerAddress(key string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(key)
	if err != nil || addr.Zone() != "" || addr.String() != key {
		return netip.Addr{}, fmt.Errorf("peer key %s is not an IP address in canonical form", quote(key))
	}
	return addr, nil
}

// routerIDValue reads the router ID, which must be an IPv4 address in the form
// netip.Addr prints.
func routerIDValue(raw json.RawMessage) (string, error) {
	s, err := stringValue(raw, `"routerId"`)
	if err != nil {
		return "", err
	}
	if addr, err := netip.ParseAddr(s); err != nil || !addr.Is4() || addr.String() != s {
		return "", fmt.Errorf(`"routerId" %s is not an IPv4 address`, quote(s))
	}
	return s, nil
}

// asNumber reads an AS number. It must be a plain JSON integer that fits 32
// bits. AS 0 (RFC 7607) and AS 4294967295 (RFC 7300) are reserved, so they are
// refused rather than shown as a peer's AS.
func asNumber(raw json.RawMessage, what string) (uint32, error) {
	var n uint32
	if isNull(raw) || json.Unmarshal(raw, &n) != nil {
		return 0, fmt.Errorf("%s must be an unsigned 32-bit AS number", what)
	}
	if n == 0 || n == 4294967295 {
		return 0, fmt.Errorf("%s is %d, a reserved AS number", what, n)
	}
	return n, nil
}

// sessionState reads the state text. It is shown verbatim, so only its shape is
// checked here: non-empty plain text. Its vocabulary is not checked, because the
// strings FRR 10.7.0 prints have not been verified against a capture.
func sessionState(raw json.RawMessage, what string) (string, error) {
	s, err := stringValue(raw, what)
	if err != nil {
		return "", err
	}
	if s == "" || textsafe.Clean(s) != s {
		return "", fmt.Errorf("%s is not plain session-state text", what)
	}
	return s, nil
}

// stringValue reads one JSON string. null is refused, since encoding/json would
// read it as an empty string without an error.
func stringValue(raw json.RawMessage, what string) (string, error) {
	var s string
	if isNull(raw) || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("%s must be a string", what)
	}
	return s, nil
}

// isNull reports whether a JSON value is the literal null. encoding/json reads
// null into a number, a string, or a map as the zero value without an error, so
// the readers above check for it first.
func isNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// quote renders untrusted text for an error, after sanitizing it.
func quote(s string) string {
	return fmt.Sprintf("%q", textsafe.Clean(s))
}
