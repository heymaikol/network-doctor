package frrospf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// ManifestVersion is the manifest format this build reads. It is separate from
// the topology file version, so the two can change independently.
const ManifestVersion = 1

// Manifest limits. A manifest is read whole, so its size is bounded before it is
// parsed. Each capture is bounded again by MaxCaptureBytes when it is read.
const (
	MaxManifestBytes = 1 << 20
	MaxCaptures      = 256
)

// maxManifestDepth bounds object and array nesting. A manifest needs three
// levels, so the bound only stops a crafted file from deepening the walk.
const maxManifestDepth = 16

// Manifest declares the captures of one import and the facts the caller asserts
// about each. SourceNode names the node the topology is written from. It is
// empty when the manifest names none, which is fine for a report alone.
type Manifest struct {
	Version    int
	SourceNode string
	Captures   []ManifestCapture
}

// ManifestCapture is one capture file and the facts its caller declares. File is
// relative to the manifest's directory. Nothing here is checked against the
// output itself. The importer checks the supported values later, and refuses a
// capture whose VRF, FRR version, or command it does not read.
type ManifestCapture struct {
	File        string
	Source      string
	Node        string
	VRF         string
	FRRVersion  string
	Command     string
	CollectedAt time.Time // the instant, in UTC
}

// DecodeManifest reads manifest bytes. It refuses duplicate keys at any depth,
// keys that are unknown or differ from a known key only in case, values of the
// wrong JSON type, null where a value is required, and trailing data. It checks
// that every path is local and that every source label is unique. It reads no
// file: the caller opens the captures the manifest names.
func DecodeManifest(data []byte) (Manifest, error) {
	if len(data) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("manifest exceeds %d bytes", MaxManifestBytes)
	}
	if err := checkUniqueKeys(data); err != nil {
		return Manifest{}, fmt.Errorf("invalid manifest: %w", err)
	}
	m, err := decodeManifestObject(data)
	if err != nil {
		return Manifest{}, fmt.Errorf("invalid manifest: %w", err)
	}
	return m, nil
}

func decodeManifestObject(data []byte) (Manifest, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return Manifest{}, errors.New("manifest is not a JSON object")
	}
	if err := exactKeys(top, "manifest", "version", "source_node", "captures"); err != nil {
		return Manifest{}, err
	}

	version, err := manifestVersion(top)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	m.Version = version

	if raw, ok := top["source_node"]; ok {
		node, err := plainText(raw, `"source_node"`)
		if err != nil {
			return Manifest{}, err
		}
		m.SourceNode = node
	}

	raw, ok := top["captures"]
	if !ok {
		return Manifest{}, errors.New(`manifest needs "captures"`)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return Manifest{}, errors.New(`"captures" must be an array of capture objects`)
	}
	switch {
	case len(entries) == 0:
		return Manifest{}, errors.New("manifest lists no captures")
	case len(entries) > MaxCaptures:
		return Manifest{}, fmt.Errorf("manifest lists %d captures; the limit is %d", len(entries), MaxCaptures)
	}
	for i, entry := range entries {
		c, err := decodeManifestCapture(i, entry)
		if err != nil {
			return Manifest{}, err
		}
		m.Captures = append(m.Captures, c)
	}

	if err := checkManifestLabels(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func manifestVersion(top map[string]json.RawMessage) (int, error) {
	raw, ok := top["version"]
	if !ok {
		return 0, fmt.Errorf(`manifest needs "version": %d`, ManifestVersion)
	}
	var v int
	if err := json.Unmarshal(raw, &v); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, errors.New(`manifest "version" must be an integer`)
	}
	if v != ManifestVersion {
		return 0, fmt.Errorf(`manifest version %d is not supported; this netdoc reads "version": %d`, v, ManifestVersion)
	}
	return v, nil
}

func decodeManifestCapture(i int, raw json.RawMessage) (ManifestCapture, error) {
	where := fmt.Sprintf("captures[%d]", i)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return ManifestCapture{}, fmt.Errorf("%s is not an object", where)
	}
	if err := exactKeys(obj, where, "file", "source", "node", "vrf", "frr_version", "command", "collected_at"); err != nil {
		return ManifestCapture{}, err
	}
	field := func(key string) (string, error) {
		v, ok := obj[key]
		if !ok {
			return "", fmt.Errorf("%s needs %q", where, key)
		}
		return plainText(v, fmt.Sprintf("%s %q", where, key))
	}
	var c ManifestCapture
	var err error
	if c.File, err = field("file"); err != nil {
		return ManifestCapture{}, err
	}
	// IsLocal accepts ".", which names the directory, not a file.
	if !filepath.IsLocal(c.File) || filepath.Clean(c.File) == "." {
		return ManifestCapture{}, fmt.Errorf("%s file %s must be a relative path to a file inside the manifest directory", where, quote(c.File))
	}
	if c.Source, err = field("source"); err != nil {
		return ManifestCapture{}, err
	}
	if c.Node, err = field("node"); err != nil {
		return ManifestCapture{}, err
	}
	if c.VRF, err = field("vrf"); err != nil {
		return ManifestCapture{}, err
	}
	if c.FRRVersion, err = field("frr_version"); err != nil {
		return ManifestCapture{}, err
	}
	if c.Command, err = field("command"); err != nil {
		return ManifestCapture{}, err
	}
	stamp, err := field("collected_at")
	if err != nil {
		return ManifestCapture{}, err
	}
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return ManifestCapture{}, fmt.Errorf("%s collected_at %s is not an RFC 3339 time with an offset", where, quote(stamp))
	}
	c.CollectedAt = at.UTC()
	return c, nil
}

// checkManifestLabels refuses a source label that two captures share after
// sanitizing, and a file name that two captures spell the same way. The import
// refuses such captures anyway. A manifest that repeats one is invalid.
func checkManifestLabels(m Manifest) error {
	sources := map[string]int{}
	files := map[string]int{}
	for i, c := range m.Captures {
		src := textsafe.Clean(c.Source)
		if j, ok := sources[src]; ok {
			return fmt.Errorf("captures[%d] and captures[%d] both use source label %s", j, i, quote(src))
		}
		sources[src] = i
		name := filepath.Clean(c.File)
		if j, ok := files[name]; ok {
			return fmt.Errorf("captures[%d] and captures[%d] name the same file %s", j, i, quote(c.File))
		}
		files[name] = i
	}
	if m.SourceNode != "" && !slices.ContainsFunc(m.Captures, func(c ManifestCapture) bool { return c.Node == m.SourceNode }) {
		return fmt.Errorf("source_node %s names no captured node", quote(m.SourceNode))
	}
	return nil
}

// plainText reads one JSON string that must be non-empty and free of control and
// invisible characters. null, numbers, and objects are refused, not treated as
// empty.
func plainText(raw json.RawMessage, what string) (string, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("%s is null; it must be a string", what)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%s must be a string", what)
	}
	switch {
	case s == "":
		return "", fmt.Errorf("%s is empty", what)
	case !plain(s):
		return "", fmt.Errorf("%s has control or invisible characters", what)
	}
	return s, nil
}

// exactKeys refuses any key that is not one of allowed. A key that differs from
// an allowed one only in case is named as such, since encoding/json would match
// it silently.
func exactKeys(obj map[string]json.RawMessage, where string, allowed ...string) error {
	for _, key := range slices.Sorted(maps.Keys(obj)) {
		if slices.Contains(allowed, key) {
			continue
		}
		for _, name := range allowed {
			if strings.EqualFold(key, name) {
				return fmt.Errorf("%s key %s differs from %s only in case", where, quote(key), quote(name))
			}
		}
		return fmt.Errorf("%s has unknown key %s", where, quote(key))
	}
	return nil
}

// checkUniqueKeys walks the whole document once. It refuses a repeated key in any
// object, nesting past maxManifestDepth, a truncated or empty document, and data
// after the object. encoding/json keeps the last of two equal keys, so a repeat
// would otherwise change the manifest silently.
func checkUniqueKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walkValue(dec, 0); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("manifest is empty")
		}
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data follows the manifest object")
	}
	return nil
}

func walkValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxManifestDepth {
		return errors.New("manifest nests too deeply")
	}
	seen := map[string]bool{}
	for dec.More() {
		if d == '{' {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := kt.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
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
