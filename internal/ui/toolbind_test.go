// How --iface reaches the drill-down tools: which option each one binds with
// per GOOS, which source family it picks, and which commands stay untouched.

package ui

import (
	"net"
	"slices"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

var (
	src4 = net.ParseIP("10.7.0.2")
	src6 = net.ParseIP("fd00::2")
	// dual is --iface wg0 on an interface holding both families.
	dual = toolBind{iface: "wg0", v4: src4, v6: src6}
	// literal is --iface 10.7.0.2: an exact address, so no interface name and
	// only that family.
	literal = toolBind{v4: src4}
	// v6Iface is an interface with no IPv4 address to bind.
	v6Iface = toolBind{iface: "wg0", v6: src6}
)

func argvFor(t *testing.T, target *diagnostic.Target, goos, key string, b toolBind, sel net.IP) []string {
	t.Helper()
	args, _, _ := toolByKey(t, toolsFor(target, goos, b), key).Build(target, sel)
	return args
}

// bindFor is the only path from --iface into the tool table, so a resolved
// selection must arrive with both its name and its addresses intact, and no
// selection at all must produce the zero value every builder treats as
// "unbound".
func TestBindForCarriesTheSelection(t *testing.T) {
	if got := bindFor(nil); got.iface != "" || got.v4 != nil || got.v6 != nil {
		t.Errorf("bindFor(nil) = %+v, want zero", got)
	}
	got := bindFor(&diagnostic.SourceAddresses{IPv4: src4, IPv6: src6, Iface: "wg0"})
	if got.iface != "wg0" || !got.v4.Equal(src4) || !got.v6.Equal(src6) {
		t.Errorf("bindFor(sources) = %+v, want wg0 with both families", got)
	}
}

// An interface name binds both families at once, so wherever a tool accepts
// one there is no family question to answer.
func TestToolsBindByInterfaceName(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	tests := []struct {
		goos, key string
		want      []string
	}{
		{"linux", "p", []string{"-c", "4", "-W", "2", "-I", "wg0", "github.com"}},
		{"linux", "t", []string{"-w", "2", "-q", "1", "-m", "20", "-i", "wg0", "github.com"}},
		{"linux", "m", []string{"--report", "--report-cycles", "5", "-I", "wg0", "github.com"}},
		// macOS ping's interface option is Apple's -b boundif; traceroute
		// matches Linux.
		{"darwin", "p", []string{"-c", "4", "-b", "wg0", "github.com"}},
		{"darwin", "t", []string{"-w", "2", "-q", "1", "-m", "20", "-i", "wg0", "github.com"}},
		{"darwin", "m", []string{"--report", "--report-cycles", "5", "-I", "wg0", "github.com"}},
	}
	for _, tt := range tests {
		if got := argvFor(t, tgt, tt.goos, tt.key, dual, nil); !slices.Equal(got, tt.want) {
			t.Errorf("%s %q argv = %q, want %q", tt.goos, tt.key, got, tt.want)
		}
	}

	// curl takes a name everywhere but Windows, and the URL must stay last.
	for _, goos := range []string{"linux", "darwin"} {
		curl := argvFor(t, tgt, goos, "c", dual, nil)
		if got := optValue(curl, "--interface"); got != "wg0" {
			t.Errorf("%s curl --interface = %q, want wg0; argv %q", goos, got, curl)
		}
		if curl[len(curl)-1] != "https://github.com" {
			t.Errorf("%s curl URL must stay last, argv %q", goos, curl)
		}
	}

	// The display string is what the user reads and pastes, so the binding has
	// to show up there too.
	_, _, display := toolByKey(t, toolsFor(tgt, "linux", dual), "t").Build(tgt, nil)
	if want := "traceroute -w 2 -q 1 -m 20 -i wg0 github.com"; display != want {
		t.Errorf("traceroute display = %q, want %q", display, want)
	}
}

// --iface given as an exact local IP has no interface name to pass, so each
// tool falls back to its source-address option.
func TestToolsBindByAddressWhenIfaceIsAnIP(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	tests := []struct {
		goos, key string
		want      []string
	}{
		{"linux", "p", []string{"-c", "4", "-W", "2", "-I", "10.7.0.2", "github.com"}},
		{"linux", "t", []string{"-w", "2", "-q", "1", "-m", "20", "-s", "10.7.0.2", "github.com"}},
		{"linux", "m", []string{"--report", "--report-cycles", "5", "-a", "10.7.0.2", "github.com"}},
		{"darwin", "p", []string{"-c", "4", "-S", "10.7.0.2", "github.com"}},
		{"darwin", "t", []string{"-w", "2", "-q", "1", "-m", "20", "-s", "10.7.0.2", "github.com"}},
		{"darwin", "m", []string{"--report", "--report-cycles", "5", "-a", "10.7.0.2", "github.com"}},
	}
	for _, tt := range tests {
		if got := argvFor(t, tgt, tt.goos, tt.key, literal, nil); !slices.Equal(got, tt.want) {
			t.Errorf("%s %q argv = %q, want %q", tt.goos, tt.key, got, tt.want)
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		if got := optValue(argvFor(t, tgt, goos, "c", literal, nil), "--interface"); got != "10.7.0.2" {
			t.Errorf("%s curl --interface = %q, want 10.7.0.2", goos, got)
		}
	}
}

// The builders replaced static commands, so their zero-binding output is
// pinned explicitly. Linux's complete table is already covered by
// TestToolsForDefinitions; these are the macOS and Windows variants.
func TestNoIfacePreservesDarwinAndWindowsToolOutput(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	posixCurl := []string{
		"-q", "-sS", "--head", "-o", "/dev/null",
		"--max-redirs", "0", "--noproxy", "*", "--proto", "=https,http",
		"--connect-timeout", "3", "--max-time", "10",
		"-w", `%{http_code} %{time_total} %{remote_ip} %{ssl_verify_result}\n`,
		"https://github.com",
	}
	windowsCurl := slices.Clone(posixCurl)
	windowsCurl[4] = "NUL"
	tests := []struct {
		goos, key string
		want      []string
	}{
		{"darwin", "p", []string{"-c", "4", "github.com"}},
		{"darwin", "c", posixCurl},
		{"darwin", "t", []string{"-w", "2", "-q", "1", "-m", "20", "github.com"}},
		{"darwin", "m", []string{"--report", "--report-cycles", "5", "github.com"}},
		{"windows", "p", []string{"-n", "4", "-w", "2000", "github.com"}},
		{"windows", "c", windowsCurl},
		{"windows", "t", []string{"-w", "2000", "-h", "20", "github.com"}},
		{"windows", "m", []string{"-h", "20", "-q", "5", "-p", "100", "-w", "500", "github.com"}},
	}
	for _, tt := range tests {
		tool := toolByKey(t, toolsFor(tgt, tt.goos, toolBind{}), tt.key)
		args, _, display := tool.Build(tgt, nil)
		if !slices.Equal(args, tt.want) {
			t.Errorf("%s %s argv = %q, want %q", tt.goos, tt.key, args, tt.want)
		}
		wantDisplay := tool.Bin + " " + quoterFor(tt.goos)(tt.want)
		if tt.goos != "windows" && tt.key == "c" {
			wantDisplay = "LC_ALL=C " + wantDisplay
		}
		if display != wantDisplay {
			t.Errorf("%s %s display = %q, want %q", tt.goos, tt.key, display, wantDisplay)
		}
	}
}

// Tools that can only bind an address must follow the family of the address
// the tool will actually reach: the literal target when there is one, else the
// address the target TCP probe selected. With no destination family known,
// only a selection that has a single family is unambiguous enough to bind.
// Driven through pathping, whose -i is the one Windows source option Microsoft
// documents without a family restriction.
func TestAddressBindingFollowsDestinationFamily(t *testing.T) {
	tests := []struct {
		name   string
		target string
		bind   toolBind
		sel    net.IP
		want   string // "" = the option must be absent
	}{
		{"hostname, probe selected IPv4", "github.com", dual, src4, "10.7.0.2"},
		{"hostname, probe selected IPv6", "github.com", dual, net.ParseIP("2001:db8::1"), "fd00::2"},
		{"IPv6 literal outranks an IPv4 selection", "[2001:db8::1]:443", dual, src4, "fd00::2"},
		{"IPv4 literal outranks an IPv6 selection", "1.1.1.1", dual, net.ParseIP("2001:db8::1"), "10.7.0.2"},
		{"IPv4 destination, IPv6-only interface", "1.1.1.1", v6Iface, nil, ""},
		{"IPv6 destination, IPv4-only interface", "2001:db8::1", literal, nil, ""},
		// Family unknown: a dual-stack interface must not be guessed at, but a
		// single-family selection leaves nothing to guess.
		{"unknown family, dual-stack interface", "github.com", dual, nil, ""},
		{"unknown family, IPv4-only selection", "github.com", literal, nil, "10.7.0.2"},
		{"unknown family, IPv6-only interface", "github.com", v6Iface, nil, "fd00::2"},
		{"no --iface at all", "github.com", toolBind{}, src4, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := mustTarget(t, tt.target)
			if got := optValue(argvFor(t, target, "windows", "m", tt.bind, tt.sel), "-i"); got != tt.want {
				t.Errorf("pathping -i = %q, want %q", got, tt.want)
			}
		})
	}
}

// A missing family must leave the command alone rather than borrow the other
// family's address: an IPv4 source in an IPv6 command binds nothing, it just
// fails differently.
func TestNoSourceForFamilyLeavesCommandUnbound(t *testing.T) {
	v6Target := mustTarget(t, "2001:db8::1")
	plain := argvFor(t, v6Target, "linux", "p", toolBind{}, nil)
	bound := argvFor(t, v6Target, "linux", "p", literal, nil)
	if !slices.Equal(plain, bound) {
		t.Errorf("IPv4-only selection on an IPv6 target changed ping argv to %q, want %q", bound, plain)
	}
	if slices.Contains(bound, "10.7.0.2") {
		t.Errorf("IPv4 source leaked into an IPv6 command: %q", bound)
	}
	// The interface name form has no such gap: it binds whichever family the
	// tool ends up using.
	named := argvFor(t, v6Target, "linux", "p", v6Iface, nil)
	if optValue(named, "-I") != "wg0" {
		t.Errorf("ping -I = %q, want wg0", named)
	}
}

// Windows has no interface-name option at all, and Microsoft documents both
// ping /S and tracert /S as IPv6-only, so those two bind for an IPv6
// destination and stay untouched otherwise. pathping and curl.exe take an
// address for either family.
func TestWindowsToolsBinding(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	v6 := mustTarget(t, "2001:db8::1")

	tests := []struct {
		name   string
		target *diagnostic.Target
		key    string
		sel    net.IP
		want   []string
	}{
		{"ping IPv6", v6, "p", nil, []string{"-n", "4", "-w", "2000", "-S", "fd00::2", "2001:db8::1"}},
		{"tracert IPv6", v6, "t", nil, []string{"-w", "2000", "-h", "20", "-S", "fd00::2", "2001:db8::1"}},
		{"ping hostname selected IPv6", tgt, "p", net.ParseIP("2001:db8::1"), []string{"-n", "4", "-w", "2000", "-S", "fd00::2", "github.com"}},
		{"tracert hostname selected IPv6", tgt, "t", net.ParseIP("2001:db8::1"), []string{"-w", "2000", "-h", "20", "-S", "fd00::2", "github.com"}},
		{"ping IPv4 stays unbound", tgt, "p", src4, []string{"-n", "4", "-w", "2000", "github.com"}},
		{"tracert IPv4 stays unbound", tgt, "t", src4, []string{"-w", "2000", "-h", "20", "github.com"}},
		{"pathping binds either family", tgt, "m", src4,
			[]string{"-h", "20", "-q", "5", "-p", "100", "-w", "500", "-i", "10.7.0.2", "github.com"}},
	}
	for _, tt := range tests {
		if got := argvFor(t, tt.target, "windows", tt.key, dual, tt.sel); !slices.Equal(got, tt.want) {
			t.Errorf("%s argv = %q, want %q", tt.name, got, tt.want)
		}
	}
	// curl cannot resolve an interface name on Windows, so it gets the address.
	if got := optValue(argvFor(t, tgt, "windows", "c", dual, src4), "--interface"); got != "10.7.0.2" {
		t.Errorf("windows curl --interface = %q, want the source address", got)
	}
	for name, b := range map[string]toolBind{
		"interface name only":          {iface: "wg0"},
		"unknown family on dual stack": dual,
	} {
		args := argvFor(t, tgt, "windows", "c", b, nil)
		if got := optValue(args, "--interface"); got != "" || slices.Contains(args, "wg0") {
			t.Errorf("windows curl %s argv = %q, want no interface binding", name, args)
		}
	}
}

// Everything that cannot meaningfully bind must come out byte-for-byte the
// same with --iface as without it. dig and nslookup query the system resolver,
// whose address is not the target and is commonly a loopback stub a source
// binding cannot reach; nmap's -S is a raw-packet spoofing option, not a
// documented connect-scan binding; the ssh and openssl checks and the local
// state tools are left alone too.
func TestUnbindableToolsAreUnchanged(t *testing.T) {
	targets := []string{"github.com", "1.1.1.1", "ssh://github.com", "smtp://mail.example.com:587"}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, target := range targets {
			tgt := mustTarget(t, target)
			plain, bound := toolsFor(tgt, goos, toolBind{}), toolsFor(tgt, goos, dual)
			keys := []string{"I", "s", "d", "n"}
			if tgt.Proto == diagnostic.ProtoSSH || tgt.Proto == diagnostic.ProtoSMTP {
				keys = append(keys, "c") // the ssh / openssl handshake checks
			}
			for _, key := range keys {
				wantArgs, wantEnv, wantDisplay := toolByKey(t, plain, key).Build(tgt, src4)
				gotArgs, gotEnv, gotDisplay := toolByKey(t, bound, key).Build(tgt, src4)
				if !slices.Equal(gotArgs, wantArgs) || !slices.Equal(gotEnv, wantEnv) || gotDisplay != wantDisplay {
					t.Errorf("%s %s %q changed with --iface: argv %q, env %q, display %q; want %q, %q, %q",
						goos, target, key, gotArgs, gotEnv, gotDisplay, wantArgs, wantEnv, wantDisplay)
				}
			}
		}
	}

	// The LAN sweep already follows the selection through the probe source its
	// CIDR is derived from; nmap -sn takes the network, not a binding.
	tool := lanDiscoveryTool(shellArgs, "10.7.0.0/24")
	args, _, _ := tool.Build(nil, nil)
	want := []string{"--unprivileged", "-sn", "-T3", "--host-timeout", "5s", "-oG", "-", "10.7.0.0/24"}
	if !slices.Equal(args, want) {
		t.Errorf("LAN scan argv = %q, want %q", args, want)
	}
}

// Build must not hand out a slice a later Build can overwrite: the binding is
// appended to captured flags, which is exactly where aliasing would bite.
func TestBoundToolArgvIndependentPerCall(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	tool := toolByKey(t, toolsFor(tgt, "linux", dual), "p")
	first, _, _ := tool.Build(tgt, nil)
	second, _, _ := tool.Build(tgt, nil)
	second[0] = "clobbered"
	if first[0] != "-c" {
		t.Errorf("Build results share backing memory: first = %q", first)
	}
}

// End to end: the selection --iface resolved has to survive into the model's
// own tool table and outlive a restart, which rebuilds it. Asserted without
// naming a flag, since the table is built for the running GOOS, and every
// platform binds curl to one or the other spelling of the selection.
func TestModelToolsCarryTheIfaceSelection(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	sources := &diagnostic.SourceAddresses{IPv4: src4, IPv6: src6, Iface: "wg0"}
	m := NewWithSelection(tgt, sources, false, false, "", "test", diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)

	bound := func(m model) bool {
		args, _, _ := toolByKey(t, m.tools, "c").Build(tgt, src4)
		return slices.Contains(args, "wg0") || slices.Contains(args, src4.String())
	}
	if !bound(m) {
		args, _, _ := toolByKey(t, m.tools, "c").Build(tgt, src4)
		t.Fatalf("curl argv = %q, want it bound to the --iface selection", args)
	}
	(&m).doRestart()
	if !bound(m) {
		args, _, _ := toolByKey(t, m.tools, "c").Build(tgt, src4)
		t.Errorf("restart dropped the binding: curl argv = %q", args)
	}

	// Without --iface the same table stays exactly as it was.
	plain := NewWithSelection(tgt, nil, false, false, "", "test", diagnostic.DefaultPublicDNS, true, diagnostic.ProbeSelection{}).(model)
	if bound(plain) {
		args, _, _ := toolByKey(t, plain.tools, "c").Build(tgt, src4)
		t.Errorf("curl argv without --iface = %q, want no binding", args)
	}
}

// optValue returns the token after flag, or "" when the flag is absent.
func optValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
