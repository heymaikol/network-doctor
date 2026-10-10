package frrospf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// maxDepth bounds object and array nesting. FRR's OSPF output nests about four
// levels, so the bound only stops a crafted capture from growing the walk.
const maxDepth = 32

// errNotJSON means the output does not begin like a JSON object. vtysh prints
// plain-text errors in that position, and they are reported, not parsed.
var errNotJSON = errors.New("output is not a JSON object")

// checkStrictJSON accepts exactly one JSON object and refuses what
// encoding/json would otherwise take silently: a repeated key, which Unmarshal
// keeps the last of, any byte after the object, and an ospfInstance field, which
// marks a numbered OSPF instance. It does not decode values.
func checkStrictJSON(data []byte) error {
	type frame struct {
		object  bool
		keys    map[string]struct{}
		wantKey bool
		// mapKeys marks the neighbors or interfaces object. Its keys are router
		// IDs or interface names, not field names, so they are not checked.
		mapKeys bool
		lastKey string
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []frame
	started, done := false, false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if !started {
				return errNotJSON
			}
			return err
		}
		if done {
			return errors.New("data follows the JSON object")
		}
		if !started {
			if d, ok := tok.(json.Delim); !ok || d != '{' {
				return errNotJSON
			}
			started = true
		}
		top := len(stack) - 1
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack) >= maxDepth {
					return errors.New("JSON nests too deeply")
				}
				mapKeys := len(stack) == 1 && stack[0].object && (stack[0].lastKey == "neighbors" || stack[0].lastKey == "interfaces")
				stack = append(stack, frame{object: v == '{', keys: map[string]struct{}{}, wantKey: v == '{', mapKeys: mapKeys})
			case '}', ']':
				stack = stack[:top]
				if len(stack) == 0 {
					done = true
				} else if parent := &stack[len(stack)-1]; parent.object {
					parent.wantKey = true
				}
			}
		default:
			if top < 0 || !stack[top].object {
				continue
			}
			f := &stack[top]
			if !f.wantKey {
				f.wantKey = true
				continue
			}
			key, ok := v.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, dup := f.keys[key]; dup {
				return fmt.Errorf("duplicate key %s", quote(key))
			}
			// Presence alone refuses, whatever the value. Map keys are interface
			// or router-ID names, so they are exempt.
			if !f.mapKeys && strings.EqualFold(key, "ospfInstance") {
				return fmt.Errorf("key %s marks a numbered OSPF instance; only the default instance is read", quote(key))
			}
			if name, near := nearKnownKey(key); near && !f.mapKeys {
				return fmt.Errorf("key %s differs from %s only in case or folding", quote(key), quote(name))
			}
			f.keys[key] = struct{}{}
			f.lastKey = key
			f.wantKey = false
		}
	}
	if !started {
		return errors.New("output is empty")
	}
	if !done {
		return errors.New("JSON object is truncated")
	}
	return nil
}

// decodedKeys are the JSON keys the decoders read through encoding/json. That
// package matches keys case-insensitively and Unicode-folded, and keeps the last
// of two matches. A second spelling of one of these keys would silently replace
// the first, so each key must be spelled exactly.
var decodedKeys = []string{
	"neighbors", "interfaces",
	"ifaceAddress", "areaId", "ifaceName", "localIfaceAddress", "nbrState",
	"ipAddress", "ipAddressPrefixlen", "routerId",
}

// nearKnownKey returns the decoded key that key matches only when case and
// folding are ignored.
func nearKnownKey(key string) (string, bool) {
	for _, name := range decodedKeys {
		if key != name && strings.EqualFold(key, name) {
			return name, true
		}
	}
	return "", false
}

// quote renders untrusted text for a report or error, after sanitizing it.
func quote(s string) string {
	return fmt.Sprintf("%q", textsafe.Clean(s))
}

// firstLine returns the first line of untrusted output, sanitized and shortened,
// so a vtysh error can be shown without dumping the whole capture.
func firstLine(data []byte) string {
	line, _, _ := bytes.Cut(data, []byte("\n"))
	s := textsafe.Clean(string(bytes.TrimSpace(line)))
	const limit = 80
	if len(s) > limit {
		s = strings.ToValidUTF8(s[:limit], "") + "..."
	}
	return s
}
