package routepath

import (
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
)

func TestConfiguredIPIPImport(t *testing.T) {
	const device = `{"ifname":"ipip1","link":"eth0","link_type":"ipip","linkinfo":{"info_kind":"ipip","info_data":{"remote":"10.0.25.1","local":"10.0.12.1","proto":"any"}}}`
	m, err := netmodel.New(configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.12.1/30"), ifc("ipip1", "172.32.0.1/30")}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func([]TunnelCapture) []TunnelCapture
	}{
		{"proven", nil},
		{"remote any", ipipReplace(`"10.0.25.1"`, `"any"`)},
		{"IPv6 remote", ipipReplace(`"10.0.25.1"`, `"2001:db8::1"`)},
		{"mapped IPv6 remote", ipipReplace(`"10.0.25.1"`, `"::ffff:10.0.25.1"`)},
		{"unspecified remote", ipipReplace(`"10.0.25.1"`, `"0.0.0.0"`)},
		{"malformed remote", ipipReplace(`"10.0.25.1"`, `"10.0.25"`)},
		{"missing remote", ipipReplace(`"remote":"10.0.25.1",`, ``)},
		{"null remote", ipipReplace(`"10.0.25.1"`, `null`)},
		{"fwmark", ipipReplace(`"proto":"any"`, `"proto":"any","fwmark":16`)},
		{"external", ipipReplace(`"proto":"any"`, `"proto":"any","external":true`)},
		{"other namespace", ipipReplace(`"link":"eth0"`, `"link":"eth0","link_netnsid":1`)},
		{"missing underlay", ipipReplace(`"link":"eth0",`, ``)},
		{"unknown underlay", ipipReplace(`"link":"eth0"`, `"link":"eth9"`)},
		{"unknown master", ipipReplace(`"link":"eth0"`, `"link":"eth0","master":"unknown"`)},
		{"underlay VRF", ipipReplace(jsonEth0, `{"ifname":"blue","linkinfo":{"info_kind":"vrf"}},{"ifname":"eth0","master":"blue","link_type":"ether"}`)},
		{"tunnel VRF", ipipReplace(`"ifname":"ipip1"`, `"ifname":"blue","linkinfo":{"info_kind":"vrf"}},{"ifname":"ipip1","master":"blue"`)},
		{"duplicate device key", ipipReplace(`"remote":"10.0.25.1"`, `"remote":"10.0.25.1","remote":"10.0.26.1"`)},
		{"mis-cased device key", ipipReplace(`"remote"`, `"REMOTE"`)},
		{"missing rules", func(c []TunnelCapture) []TunnelCapture { return c[:1] }},
		{"malformed rules", func(c []TunnelCapture) []TunnelCapture { c[1].Data = []byte(`{`); return c }},
		{"policy steering", func(c []TunnelCapture) []TunnelCapture {
			c[1].Data = []byte(strings.Replace(defaultRules, `"table":"main"`, `"table":"100"`, 1))
			return c
		}},
		{"fwmark rule", func(c []TunnelCapture) []TunnelCapture {
			c[1].Data = []byte(strings.Replace(defaultRules, `"table":"main"`, `"table":"main","fwmark":16`, 1))
			return c
		}},
		{"duplicate rules", func(c []TunnelCapture) []TunnelCapture {
			return append(c, ruleCapture("other-rules", "r1", defaultRules))
		}},
		{"missing time", func(c []TunnelCapture) []TunnelCapture { c[0].CollectedAt = time.Time{}; return c }},
		{"missing rules time", func(c []TunnelCapture) []TunnelCapture { c[1].CollectedAt = time.Time{}; return c }},
		{"missing source", func(c []TunnelCapture) []TunnelCapture { c[0].Source = ""; return c }},
		{"contradictory capture", func(c []TunnelCapture) []TunnelCapture {
			other := c[0]
			other.Source = "other-links"
			other.Data = []byte(strings.Replace(string(other.Data), "10.0.25.1", "10.0.26.1", 1))
			return append(c, other)
		}},
		{"contradictory WireGuard dump", func(c []TunnelCapture) []TunnelCapture {
			return append(c, dumpCapture("wg-r1", "r1", wgOK("ipip1")...))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps := []TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, device), ruleCapture("ip-rule-r1", "r1", defaultRules)}
			if tc.edit != nil {
				caps = tc.edit(caps)
			}
			imp, err := ImportTunnels(m, caps)
			if tc.edit != nil {
				if err == nil && (len(imp.Tunnels) != 0 || len(imp.Refused) == 0) {
					t.Fatalf("unsafe evidence accepted: %+v", imp)
				}
				assertNoSecret(t, imp)
				return
			}
			want := []Tunnel{{Provenance: netmodel.Provenance{Source: "ip-link-r1", CollectedAt: t0}, Node: "r1", VRF: "default", Interface: "ipip1", Remote: netip.MustParseAddr("10.0.25.1"), UnderlayVRF: "default"}}
			if err != nil || !reflect.DeepEqual(imp.Tunnels, want) || len(imp.Refused) != 0 || len(imp.Unproven) != 0 || len(imp.WireGuard) != 0 {
				t.Fatalf("import = %+v, %v; want %+v without refusals", imp, err, want)
			}
			if len(imp.Rules) != 1 || imp.Rules[0].Rules.Source != "ip-rule-r1" || !imp.Rules[0].Rules.CollectedAt.Equal(t0) {
				t.Fatalf("missing rules provenance: %+v", imp.Rules)
			}
			assertImportGolden(t, filepath.Join("testdata", "tunnel_import", "golden-ipip.txt"), renderImport(imp))
		})
	}
}

func ipipReplace(old, replacement string) func([]TunnelCapture) []TunnelCapture {
	return func(c []TunnelCapture) []TunnelCapture {
		c[0].Data = []byte(strings.ReplaceAll(string(c[0].Data), old, replacement))
		return c
	}
}
