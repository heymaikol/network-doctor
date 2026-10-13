package frrbgp

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

// steadyDir holds the committed BGP transcripts. The tests read them and never
// write them.
const steadyDir = "../../testdata/frr/10.7.0/bgp/steady"

// oneEstablishedOneActive is a summary body with one Established and one Active
// peer. Each negative case changes a copy of it.
const oneEstablishedOneActive = `{
"ipv4Unicast":{
  "routerId":"1.1.1.1",
  "as":65001,
  "peers":{
    "10.0.1.2":{"localAs":65001,"remoteAs":65002,"state":"Established","peerState":"OK"},
    "10.0.1.3":{"localAs":65001,"remoteAs":65003,"state":"Active","peerState":"OK"}
  },
  "failedPeers":1
}
}`

// transcript frames body the way FRR's VTY prints it: the echo, the body, and the
// prompt, each line ending in CRLF, with nothing after the prompt.
func transcript(node, body string) []byte {
	body = strings.ReplaceAll(body, "\n", "\r\n")
	return []byte(CommandSummary + "\r\n" + body + "\r\n" + node + "> ")
}

// openRoot opens dir for this test. Each file the test reads in dir is named
// relative to it, so no name can leave dir. The root closes when the test ends.
func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// readFixture returns one committed summary transcript, unchanged.
func readFixture(t *testing.T, node string) []byte {
	t.Helper()
	data, err := openRoot(t, steadyDir).ReadFile(node + "-show_ip_bgp_summary_json.raw")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecodeReadsTheCommittedTranscripts(t *testing.T) {
	r1, err := Decode(readFixture(t, "r1"), "r1")
	if err != nil {
		t.Fatal(err)
	}
	if r1.RouterID != "1.1.1.1" || r1.LocalAS != 65001 {
		t.Errorf("r1 identity = %s AS %d, want 1.1.1.1 AS 65001", r1.RouterID, r1.LocalAS)
	}
	wantR1 := []Peer{
		{Address: netip.MustParseAddr("10.0.1.2"), LocalAS: 65001, RemoteAS: 65002, State: "Established"},
		{Address: netip.MustParseAddr("10.0.1.3"), LocalAS: 65001, RemoteAS: 65003, State: "Active"},
	}
	if !slices.Equal(r1.Peers, wantR1) {
		t.Errorf("r1 peers = %+v, want %+v", r1.Peers, wantR1)
	}

	r2, err := Decode(readFixture(t, "r2"), "r2")
	if err != nil {
		t.Fatal(err)
	}
	if r2.RouterID != "2.2.2.2" || r2.LocalAS != 65002 {
		t.Errorf("r2 identity = %s AS %d, want 2.2.2.2 AS 65002", r2.RouterID, r2.LocalAS)
	}
	wantR2 := []Peer{
		{Address: netip.MustParseAddr("10.0.1.1"), LocalAS: 65002, RemoteAS: 65001, State: "Established"},
	}
	if !slices.Equal(r2.Peers, wantR2) {
		t.Errorf("r2 peers = %+v, want %+v", r2.Peers, wantR2)
	}
}

func TestDecodeRefusesATranscriptForAnotherNode(t *testing.T) {
	if _, err := Decode(readFixture(t, "r1"), "r2"); err == nil || !strings.Contains(err.Error(), "prompt") {
		t.Fatalf("err = %v, want a refusal naming the prompt", err)
	}
}

func TestDecodeAcceptsEmptyAndBoundaryValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		peers int
	}{
		{"empty peer collection", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":1,"peers":{}}}`, 0},
		{"lowest and highest usable AS", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":1,"peers":{"10.0.1.2":{"localAs":1,"remoteAs":4294967294,"state":"Idle"}}}}`, 1},
		{"state text FRR prints for an administratively down peer", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"10.0.1.2":{"localAs":65001,"remoteAs":65002,"state":"Idle (Admin)"}}}}`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Decode(transcript("r1", tc.body), "r1")
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Peers) != tc.peers {
				t.Errorf("peers = %d, want %d", len(s.Peers), tc.peers)
			}
			if s.Peers == nil {
				t.Error("peers is nil; an observed empty collection must be a non-nil empty slice")
			}
		})
	}
}

func TestDecodeSortsPeersByAddressAndKeepsStateVerbatim(t *testing.T) {
	body := `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"10.0.1.10":{"localAs":65001,"remoteAs":65010,"state":"Idle (Admin)"},"10.0.1.2":{"localAs":65001,"remoteAs":65002,"state":"Established"}}}}`
	s, err := Decode(transcript("r1", body), "r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Peers) != 2 || s.Peers[0].Address.String() != "10.0.1.2" || s.Peers[1].Address.String() != "10.0.1.10" {
		t.Fatalf("peers = %+v, want 10.0.1.2 then 10.0.1.10", s.Peers)
	}
	if s.Peers[1].State != "Idle (Admin)" {
		t.Errorf("state = %q, want the text FRR printed", s.Peers[1].State)
	}
}

func TestDecodeRefusesAFramingThatIsNotFRRs(t *testing.T) {
	valid := strings.ReplaceAll(oneEstablishedOneActive, "\n", "\r\n")
	for _, tc := range []struct {
		name string
		data []byte
		node string
		want string
	}{
		{"LF after the echo", []byte("show ip bgp summary json\n" + valid + "\r\nr1> "), "r1", "command echo"},
		{"another command echoed", []byte("show ip bgp json\r\n" + valid + "\r\nr1> "), "r1", "command echo"},
		{"prompt names another node", transcript("r2", oneEstablishedOneActive), "r1", "prompt"},
		{"LF before the prompt", []byte(CommandSummary + "\r\n" + valid + "\nr1> "), "r1", "prompt"},
		{"bytes after the prompt", append(transcript("r1", oneEstablishedOneActive), 'x'), "r1", "prompt"},
		{"blank line before the prompt", []byte(CommandSummary + "\r\n" + valid + "\r\n\r\nr1> "), "r1", "not a JSON object"},
		{"blank line after the echo", []byte(CommandSummary + "\r\n\r\n" + valid + "\r\nr1> "), "r1", "not a JSON object"},
		{"prompt without its space", []byte(CommandSummary + "\r\n" + valid + "\r\nr1>"), "r1", "prompt"},
		{"no prompt, a partial capture", []byte(CommandSummary + "\r\n" + valid), "r1", "prompt"},
		{"vtysh error text", []byte(CommandSummary + "\r\n% Unknown command.\r\nr1> "), "r1", "not a JSON object"},
		{"empty file", nil, "r1", "command echo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.data, tc.node)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestDecodeRefusesMalformedSummaries(t *testing.T) {
	valid := oneEstablishedOneActive
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"duplicate top-level key", strings.Replace(valid, `"as":65001`, `"as":65001,"as":65002`, 1), "duplicate key"},
		{"duplicate peer state", strings.Replace(valid, `"state":"Active"`, `"state":"Active","state":"Active"`, 1), "duplicate key"},
		{"duplicate peer address", strings.Replace(valid, `"10.0.1.3":`, `"10.0.1.2":`, 1), "duplicate key"},
		{"routerId in another case", strings.Replace(valid, `"routerId"`, `"routerid"`, 1), "only in case"},
		{"peers in another case", strings.Replace(valid, `"peers"`, `"Peers"`, 1), "only in case"},
		{"ipv4Unicast in another case", strings.Replace(valid, `"ipv4Unicast"`, `"IPv4Unicast"`, 1), "only in case"},
		{"state in another case", strings.Replace(valid, `"state":"Active"`, `"State":"Active"`, 1), "only in case"},
		{"remoteAs in another case", strings.Replace(valid, `"remoteAs":65003`, `"RemoteAs":65003`, 1), "only in case"},
		{"state missing beside peerState", strings.Replace(valid, `"state":"Active",`, ``, 1), `has no "state"`},
		{"state empty", strings.Replace(valid, `"state":"Active"`, `"state":""`, 1), "plain session-state text"},
		{"state with a control character", strings.Replace(valid, `"state":"Active"`, `"state":"Act\u0007ive"`, 1), "plain session-state text"},
		{"state is a number", strings.Replace(valid, `"state":"Active"`, `"state":3`, 1), "must be a string"},
		{"state is null", strings.Replace(valid, `"state":"Active"`, `"state":null`, 1), "must be a string"},
		{"remoteAs is a string", strings.Replace(valid, `"remoteAs":65003`, `"remoteAs":"65003"`, 1), "unsigned 32-bit"},
		{"remoteAs is negative", strings.Replace(valid, `"remoteAs":65003`, `"remoteAs":-1`, 1), "unsigned 32-bit"},
		{"remoteAs is fractional", strings.Replace(valid, `"remoteAs":65003`, `"remoteAs":65003.5`, 1), "unsigned 32-bit"},
		{"remoteAs is past 32 bits", strings.Replace(valid, `"remoteAs":65003`, `"remoteAs":4294967296`, 1), "unsigned 32-bit"},
		{"remoteAs is null", strings.Replace(valid, `"remoteAs":65003`, `"remoteAs":null`, 1), "unsigned 32-bit"},
		{"peer localAs is zero", strings.Replace(valid, `"localAs":65001`, `"localAs":0`, 1), "reserved AS number"},
		{"as is 4294967295", strings.Replace(valid, `"as":65001`, `"as":4294967295`, 1), "reserved AS number"},
		{"routerId is not IPv4", strings.Replace(valid, `"routerId":"1.1.1.1"`, `"routerId":"1.1.1"`, 1), "not an IPv4 address"},
		{"routerId is null", strings.Replace(valid, `"routerId":"1.1.1.1"`, `"routerId":null`, 1), "must be a string"},
		{"peers is null", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":null}}`, `"peers" is not a JSON object`},
		{"peers is an array", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":[]}}`, `"peers" is not a JSON object`},
		{"peers is missing", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001}}`, `has no "peers"`},
		{"peer is null", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"10.0.1.3":null}}}`, "is not a JSON object"},
		{"peer is an array", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"10.0.1.3":[]}}}`, "is not a JSON object"},
		{"peer key is short", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"10.0.1":{"localAs":65001,"remoteAs":65003,"state":"Active"}}}}`, "canonical form"},
		{"peer key has a leading zero", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"010.0.1.3":{"localAs":65001,"remoteAs":65003,"state":"Active"}}}}`, "canonical form"},
		{"peer key has a zone", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"fe80::1%eth0":{"localAs":65001,"remoteAs":65003,"state":"Active"}}}}`, "canonical form"},
		{"peer key is not canonical", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"FE80::1":{"localAs":65001,"remoteAs":65003,"state":"Active"}}}}`, "canonical form"},
		{"peer has no localAs", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"10.0.1.3":{"remoteAs":65003,"state":"Active"}}}}`, `has no "localAs"`},
		{"peer has no remoteAs", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{"10.0.1.3":{"localAs":65001,"state":"Active"}}}}`, `has no "remoteAs"`},
		{"ipv4Unicast has no as", `{"ipv4Unicast":{"routerId":"1.1.1.1","peers":{}}}`, `has no "as"`},
		{"ipv4Unicast has no routerId", `{"ipv4Unicast":{"as":65001,"peers":{}}}`, `has no "routerId"`},
		{"ipv4Unicast is null", `{"ipv4Unicast":null}`, `"ipv4Unicast" is not a JSON object`},
		{"no ipv4Unicast", `{"vrfName":"default"}`, `has no "ipv4Unicast"`},
		{"only ipv6Unicast", `{"ipv6Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{}}}`, `has no "ipv4Unicast"`},
		{"body is an array", `[]`, "not a JSON object"},
		{"object is truncated", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{}}`, "not valid JSON"},
		{"data follows the object", `{"ipv4Unicast":{"routerId":"1.1.1.1","as":65001,"peers":{}}}{}`, "data follows"},
		{"invalid JSON", `{"ipv4Unicast":{,}}`, "not valid JSON"},
		{"nesting too deep", strings.Repeat(`{"a":`, 9) + `{}` + strings.Repeat("}", 9), "nests too deeply"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(transcript("r1", tc.body), "r1")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}
