package routepath

import (
	"slices"
	"strings"
	"testing"
)

const threeRoutersFile = `{
  "version": 1,
  "source": {"node": "r1", "vrf": "default"},
  "observations": [
    {"source": "config:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r1", "vrf": "default",
     "interfaces": [{"name": "eth1", "addresses": ["10.0.12.1/30"]}],
     "neighbors": [{"local_interface": "eth1", "remote_node": "r2", "remote_interface": "eth0", "remote_addr": "10.0.12.2"}]},
    {"source": "config:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r2", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.12.2/30"]}, {"name": "eth1", "addresses": ["10.0.23.2/30"]}]},
    {"source": "config:r3", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r3", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.23.3/30"]}, {"name": "eth1", "addresses": ["10.20.40.8/24"]}]},
    {"source": "fib:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r1", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "10.20.0.0/16", "origin": "kernel", "next_hops": [{"addr": "10.0.12.2", "interface": "eth1"}]}]},
    {"source": "fib:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r2", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "10.20.0.0/16", "origin": "kernel", "next_hops": [{"addr": "10.0.23.3", "interface": "eth1"}]}]}
  ],
  "checks": [
    {"source": "probe:r2", "collected_at": "2026-10-09T12:01:00Z", "node": "r2", "vrf": "default", "interface": "eth1", "destination": "10.20.40.8", "result": "fail"}
  ]
}`

func TestDecodedFileExplainsLikeTheInMemoryModel(t *testing.T) {
	f, err := Decode([]byte(threeRoutersFile))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	e := Explain(f, addr(dest))
	fwd := spine(e.Forwarding)
	if got := nodesOf(fwd); !slices.Equal(got, []string{"r1", "r2", "r3"}) {
		t.Fatalf("forwarding path = %v, want r1 r2 r3", got)
	}
	// r3 owns the destination address, so it is local and needs no FIB row.
	if last := fwd[2].Decision; last.Kind != KindLocal {
		t.Errorf("r3 decision = %+v, want local: the destination is r3's address", last)
	}
	if got := findings(e, FindingForwardingFailed); len(got) != 1 || got[0].Node != "r2" {
		t.Errorf("fib_forwarding_failed = %+v, want one at r2 from the recorded check", got)
	}
}

// The acceptance criteria ask that each hop name the routing evidence it used,
// so the human text has to carry the source row, not only the JSON.
func TestHumanTextNamesTheEvidenceForEachHop(t *testing.T) {
	f, err := Decode([]byte(threeRoutersFile))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	txt := Explain(f, addr(dest)).Text()
	for _, want := range []string{"evidence fib:r1 (kernel)", "evidence fib:r2 (kernel)"} {
		if !strings.Contains(txt, want) {
			t.Errorf("human text lacks %q, so a hop does not say where its route came from:\n%s", want, txt)
		}
	}
}

func TestDecodeRefusesMalformedFiles(t *testing.T) {
	base := threeRoutersFile
	cases := []struct {
		name string
		data string
		want string
	}{
		{"unknown field", strings.Replace(base, `"version": 1,`, `"version": 1, "verison_typo": 2,`, 1), "unknown field"},
		{"missing version", strings.Replace(base, `"version": 1,`, "", 1), `needs "version": 1`},
		{"future version", strings.Replace(base, `"version": 1,`, `"version": 2,`, 1), "not supported"},
		{"trailing data", base + " {}", "data follows"},
		{"empty source", strings.Replace(base, `"node": "r1", "vrf": "default"},`, `"node": "", "vrf": "default"},`, 1), "needs a node and a vrf"},
		{"bad prefix", strings.Replace(base, "10.20.0.0/16", "10.20.0.0/33", 1), "route prefix"},
		{"bad time", strings.Replace(base, "2026-10-09T12:00:00Z", "yesterday", 1), "collected_at"},
		{"bad plane", strings.Replace(base, `"plane": "fib", "node": "r2"`, `"plane": "rib", "node": "r2"`, 1), "unknown plane"},
		{"bad check result", strings.Replace(base, `"result": "fail"`, `"result": "maybe"`, 1), `not "pass" or "fail"`},
		{"hostname destination", strings.Replace(base, `"destination": "10.20.40.8"`, `"destination": "server.example"`, 1), "destination"},
		{"oversize", strings.Repeat(" ", MaxFileBytes+1), "exceeds the maximum topology size"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode([]byte(c.data))
			if err == nil {
				t.Fatalf("Decode accepted the file; want an error mentioning %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %q, want it to mention %q", err, c.want)
			}
		})
	}
}
