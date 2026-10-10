package frrospf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// manifestBytes builds a valid two-capture manifest, then applies edit. A nil
// edit keeps it valid.
func manifestBytes(t testing.TB, edit func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{
		"version":     1,
		"source_node": "r1",
		"captures": []any{
			captureEntry("r1-interface.json", "r1 interface", "r1", CommandInterface),
			captureEntry("r2-interface.json", "r2 interface", "r2", CommandInterface),
		},
	}
	if edit != nil {
		edit(m)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func captureEntry(file, source, node, command string) map[string]any {
	return map[string]any{
		"file":         file,
		"source":       source,
		"node":         node,
		"vrf":          "default",
		"frr_version":  Version,
		"command":      command,
		"collected_at": "2026-10-10T17:41:19+02:00",
	}
}

// firstCapture returns the first capture object of a manifest built by
// manifestBytes's edit callback, so a case can change one field.
func firstCapture(m map[string]any) map[string]any {
	return m["captures"].([]any)[0].(map[string]any)
}

func TestDecodeManifestReadsEveryField(t *testing.T) {
	m, err := DecodeManifest(manifestBytes(t, nil))
	if err != nil {
		t.Fatalf("DecodeManifest: %v", err)
	}
	if m.Version != ManifestVersion || m.SourceNode != "r1" || len(m.Captures) != 2 {
		t.Fatalf("manifest = version %d source_node %q captures %d", m.Version, m.SourceNode, len(m.Captures))
	}
	got := m.Captures[0]
	want := ManifestCapture{
		File:        "r1-interface.json",
		Source:      "r1 interface",
		Node:        "r1",
		VRF:         "default",
		FRRVersion:  Version,
		Command:     CommandInterface,
		CollectedAt: time.Date(2026, 10, 10, 15, 41, 19, 0, time.UTC),
	}
	if !got.CollectedAt.Equal(want.CollectedAt) {
		t.Errorf("collected_at = %v, want %v", got.CollectedAt, want.CollectedAt)
	}
	if got.CollectedAt.Location() != time.UTC {
		t.Errorf("collected_at kept location %v, want UTC", got.CollectedAt.Location())
	}
	got.CollectedAt, want.CollectedAt = time.Time{}, time.Time{}
	if got != want {
		t.Errorf("capture = %+v, want %+v", got, want)
	}
}

func TestDecodeManifestAllowsReportOnlyWithoutSourceNode(t *testing.T) {
	m, err := DecodeManifest(manifestBytes(t, func(m map[string]any) { delete(m, "source_node") }))
	if err != nil {
		t.Fatalf("DecodeManifest without source_node: %v", err)
	}
	if m.SourceNode != "" {
		t.Errorf("SourceNode = %q, want empty", m.SourceNode)
	}
}

func TestDecodeManifestRefusesMalformedManifests(t *testing.T) {
	tooMany := func(m map[string]any) {
		caps := make([]any, 0, MaxCaptures+1)
		for i := range MaxCaptures + 1 {
			caps = append(caps, captureEntry(fmt.Sprintf("c%d.json", i), fmt.Sprintf("capture %d", i), "r1", CommandInterface))
		}
		m["captures"] = caps
	}
	cases := []struct {
		name string
		raw  string // used as the whole document when set
		edit func(m map[string]any)
		want string
	}{
		{name: "empty", raw: " ", want: "manifest is empty"},
		{name: "array instead of object", raw: `[]`, want: "not a JSON object"},
		{name: "null", raw: `null`, want: "not a JSON object"},
		{name: "duplicate top-level key", raw: `{"version":1,"version":1,"captures":[]}`, want: `duplicate key "version"`},
		{name: "duplicate key inside a capture", raw: strings.Replace(string(manifestBytes(t, nil)), `"file":"r1-interface.json"`, `"file":"r1-interface.json","file":"x.json"`, 1), want: `duplicate key "file"`},
		{name: "data after the object", raw: string(manifestBytes(t, nil)) + " {}", want: "data follows"},
		{name: "nested too deeply", raw: strings.Repeat(`{"x":`, 20) + "1" + strings.Repeat("}", 20), want: "nests too deeply"},
		{name: "unknown top-level key", edit: func(m map[string]any) { m["extra"] = 1 }, want: `unknown key "extra"`},
		{name: "top-level key differs only in case", edit: func(m map[string]any) { m["Version"] = m["version"]; delete(m, "version") }, want: `"Version" differs from "version" only in case`},
		{name: "missing version", edit: func(m map[string]any) { delete(m, "version") }, want: `needs "version"`},
		{name: "unsupported version", edit: func(m map[string]any) { m["version"] = 2 }, want: "version 2 is not supported"},
		{name: "version as a string", edit: func(m map[string]any) { m["version"] = "1" }, want: `"version" must be an integer`},
		{name: "version as a fraction", edit: func(m map[string]any) { m["version"] = 1.5 }, want: `"version" must be an integer`},
		{name: "missing captures", edit: func(m map[string]any) { delete(m, "captures") }, want: `needs "captures"`},
		{name: "captures is null", edit: func(m map[string]any) { m["captures"] = nil }, want: `"captures" must be an array`},
		{name: "captures is empty", edit: func(m map[string]any) { m["captures"] = []any{} }, want: "lists no captures"},
		{name: "too many captures", edit: tooMany, want: "lists 257 captures; the limit is 256"},
		{name: "source_node empty", edit: func(m map[string]any) { m["source_node"] = "" }, want: `"source_node" is empty`},
		{name: "source_node is null", edit: func(m map[string]any) { m["source_node"] = nil }, want: `"source_node" is null`},
		{name: "source_node names no capture", edit: func(m map[string]any) { m["source_node"] = "r9" }, want: `source_node "r9" names no captured node`},
		{name: "capture is not an object", edit: func(m map[string]any) { m["captures"] = []any{"r1"} }, want: "captures[0] is not an object"},
		{name: "capture has unknown key", edit: func(m map[string]any) { firstCapture(m)["extra"] = "x" }, want: `captures[0] has unknown key "extra"`},
		{name: "capture key differs only in case", edit: func(m map[string]any) {
			firstCapture(m)["Node"] = firstCapture(m)["node"]
			delete(firstCapture(m), "node")
		}, want: `"Node" differs from "node" only in case`},
		{name: "capture misses command", edit: func(m map[string]any) { delete(firstCapture(m), "command") }, want: `captures[0] needs "command"`},
		{name: "file is null", edit: func(m map[string]any) { firstCapture(m)["file"] = nil }, want: `"file" is null`},
		{name: "file is a number", edit: func(m map[string]any) { firstCapture(m)["file"] = 7 }, want: `"file" must be a string`},
		{name: "file is empty", edit: func(m map[string]any) { firstCapture(m)["file"] = "" }, want: `"file" is empty`},
		{name: "file is absolute", edit: func(m map[string]any) { firstCapture(m)["file"] = "/etc/passwd" }, want: "must be a relative path"},
		{name: "file climbs out of the directory", edit: func(m map[string]any) { firstCapture(m)["file"] = "../r1.json" }, want: "must be a relative path"},
		{name: "file is the directory itself", edit: func(m map[string]any) { firstCapture(m)["file"] = "." }, want: "must be a relative path"},
		{name: "source has a control character", edit: func(m map[string]any) { firstCapture(m)["source"] = "r1\x1b[31m" }, want: `captures[0] "source" has control or invisible characters`},
		{name: "source has a zero-width character", edit: func(m map[string]any) { firstCapture(m)["source"] = "r1\u200b" }, want: "control or invisible characters"},
		{name: "collected_at has no offset", edit: func(m map[string]any) { firstCapture(m)["collected_at"] = "2026-10-10T17:41:19" }, want: "is not an RFC 3339 time with an offset"},
		{name: "collected_at is not a time", edit: func(m map[string]any) { firstCapture(m)["collected_at"] = "yesterday" }, want: "is not an RFC 3339 time with an offset"},
		{name: "two captures share a source label", edit: func(m map[string]any) {
			m["captures"].([]any)[1].(map[string]any)["source"] = "r1 interface"
		}, want: `both use source label "r1 interface"`},
		{name: "two captures name the same file", edit: func(m map[string]any) {
			m["captures"].([]any)[1].(map[string]any)["file"] = "./r1-interface.json"
		}, want: `name the same file "./r1-interface.json"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.raw)
			if tc.raw == "" {
				data = manifestBytes(t, tc.edit)
			}
			_, err := DecodeManifest(data)
			if err == nil {
				t.Fatalf("DecodeManifest accepted the manifest; want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestDecodeManifestRefusesAnOversizedDocument(t *testing.T) {
	data := bytes.Repeat([]byte(" "), MaxManifestBytes+1)
	if _, err := DecodeManifest(data); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("DecodeManifest over %d bytes: err = %v, want a size refusal", MaxManifestBytes, err)
	}
}

// TestDecodeManifestKeepsTheCaptureFileAsWritten checks that a manifest path is
// stored as written, so the caller opens exactly the file the manifest names.
// Cleaning happens only to compare names for duplicates.
func TestDecodeManifestKeepsTheCaptureFileAsWritten(t *testing.T) {
	m, err := DecodeManifest(manifestBytes(t, func(m map[string]any) {
		firstCapture(m)["file"] = filepath.Join("captures", "r1.json")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Captures[0].File; got != filepath.Join("captures", "r1.json") {
		t.Errorf("File = %q, want the path as written", got)
	}
}
