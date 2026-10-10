package frrospf

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// FuzzImportNeighborDetail feeds arbitrary neighbor-detail output for r1, next
// to the genuine interface captures of r1 and r2. For any input it must not
// panic, netmodel must accept what Import writes, and a neighbor may map only to
// r2's e2, the sole owner of 10.0.1.2 in the default VRF.
//
// The first seed is the genuine detail payload written compactly. The others are
// short hand-written shapes that exercise the placeholder and the empty list.
func FuzzImportNeighborDetail(f *testing.F) {
	f.Add([]byte(`{"neighbors":{"2.2.2.2":[{"ifaceAddress":"10.0.1.2","areaId":"0.0.0.0","ifaceName":"e1","localIfaceAddress":"10.0.1.1","nbrState":"Full/DR"}]}}`))
	f.Add([]byte(`{"neighbors":{"noNbrId":[{"ifaceAddress":"10.0.1.2","areaId":"0.0.0.0","ifaceName":"e1","nbrState":"Attempt/-"}]}}`))
	f.Add([]byte(`{"neighbors":{}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`% No OSPF instance found`))

	ifaces := []Capture{
		fixture(f, "bcast", "r1", CommandInterface),
		fixture(f, "bcast", "r2", CommandInterface),
	}
	meta := fixture(f, "bcast", "r1", CommandNeighborDetail)

	f.Fuzz(func(t *testing.T, data []byte) {
		caps := append(slices.Clone(ifaces), Capture{
			Node:        "r1",
			VRF:         "default",
			Source:      "fuzz r1 neighbor detail",
			CollectedAt: meta.CollectedAt,
			FRRVersion:  Version,
			Command:     CommandNeighborDetail,
			Data:        data,
		})
		res, err := Import(caps)
		if err != nil {
			t.Fatalf("netmodel refused what Import wrote: %v", err)
		}

		accepted := 0
		for _, cr := range res.Report.Captures {
			if !plain(cr.Reason) {
				t.Fatalf("capture reason repeats control text: %q", cr.Reason)
			}
			if cr.Accepted {
				accepted++
			}
		}
		for _, r := range res.Report.Records {
			if !plain(r.Reason) {
				t.Fatalf("record reason repeats control text: %q", r.Reason)
			}
		}
		if accepted != len(res.Observations) {
			t.Fatalf("%d accepted captures wrote %d observations", accepted, len(res.Observations))
		}

		written := 0
		for _, o := range res.Observations {
			written += len(o.Neighbors)
		}
		mapped := 0
		for _, r := range res.Report.Records {
			if !r.Mapped {
				continue
			}
			mapped++
			if r.RemoteNode != "r2" || r.RemoteInterface != "e2" || r.NeighborAddr != "10.0.1.2" || r.LocalInterface != "e1" {
				t.Fatalf("mapped record names a peer nothing captured: %+v", r)
			}
		}
		if mapped != written {
			t.Fatalf("%d records mapped but %d neighbors written", mapped, written)
		}
	})
}

// FuzzDecodeManifest feeds arbitrary manifest bytes. It must not panic, and every
// error must be plain text. A manifest it accepts must hold what the importer
// relies on: version 1, a bounded capture count, file paths that name a file,
// plain text, unique source labels and file names after cleaning, UTC times, and
// a source node that names a captured node.
func FuzzDecodeManifest(f *testing.F) {
	f.Add(manifestBytes(f, nil))
	f.Add([]byte(`{"version":1,"captures":[]}`))
	f.Add([]byte(`{"version":1,"version":1,"captures":[]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := DecodeManifest(data)
		if err != nil {
			if !plain(err.Error()) {
				t.Fatalf("error repeats control text: %q", err)
			}
			return
		}
		if m.Version != ManifestVersion || len(m.Captures) == 0 || len(m.Captures) > MaxCaptures {
			t.Fatalf("accepted version %d with %d captures", m.Version, len(m.Captures))
		}
		sources := map[string]bool{}
		files := map[string]bool{}
		sourceNamed := m.SourceNode == ""
		for _, c := range m.Captures {
			if !filepath.IsLocal(c.File) || filepath.Clean(c.File) == "." {
				t.Fatalf("accepted file path %q", c.File)
			}
			for _, s := range []string{c.File, c.Source, c.Node, c.VRF, c.FRRVersion, c.Command} {
				if !plain(s) {
					t.Fatalf("accepted text with control characters: %q", s)
				}
			}
			src := textsafe.Clean(c.Source)
			if sources[src] {
				t.Fatalf("accepted duplicate source label %q", src)
			}
			sources[src] = true
			name := filepath.Clean(c.File)
			if files[name] {
				t.Fatalf("accepted duplicate file %q", name)
			}
			files[name] = true
			if c.CollectedAt.Location() != time.UTC {
				t.Fatalf("collected_at location = %v, want UTC", c.CollectedAt.Location())
			}
			if c.Node == m.SourceNode {
				sourceNamed = true
			}
		}
		if !sourceNamed {
			t.Fatalf("accepted source_node %q that names no capture", m.SourceNode)
		}
	})
}
