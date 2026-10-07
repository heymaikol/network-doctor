// Tool tables per GOOS: definitions, the protocol-matched c slot, display
// quoting, and availability caching.

package ui

import (
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func TestToolAvailabilityCachedUntilRestart(t *testing.T) {
	oldLookPath := toolLookPath
	t.Cleanup(func() { toolLookPath = oldLookPath })

	installed, calls := true, 0
	toolLookPath = func(bin string) (string, error) {
		calls++
		if installed {
			return bin, nil
		}
		return "", errors.New("not found")
	}

	m := newModel(mustTarget(t, "github.com"), false)
	initialCalls := calls
	installed = false
	for range 10 {
		m.actionsView(0)
		m.nextStep(diagnostic.ProbeDNS)
	}
	if calls != initialCalls {
		t.Fatalf("rendering performed %d extra LookPath calls", calls-initialCalls)
	}

	(&m).doRestart()
	if calls != initialCalls+len(m.tools) {
		t.Fatalf("restart LookPath calls = %d, want %d", calls-initialCalls, len(m.tools))
	}
	if m.tools[0].Available {
		t.Error("restart did not refresh cached availability")
	}
}

// TestToolsForDefinitions pins the complete, ordered tool list returned by
// toolsFor (Key, Name, Bin, argv, env, and display) for both the no-target and
// with-host sets, plus per-call slice independence. These are user-visible (hotkeys,
// labels, Actions menu order, exact command shapes) and frozen, so any swap, rename, or
// argv drift from the staticTool refactor must fail here.
func TestToolsForDefinitions(t *testing.T) {
	tgt := mustTarget(t, "github.com") // https default, port not explicit

	curlArgs := []string{
		"-q", "-sS", "--head", "-o", "/dev/null",
		"--max-redirs", "0", "--noproxy", "*",
		"--proto", "=https,http",
		"--connect-timeout", "3", "--max-time", "10",
		"-w", `%{http_code} %{time_total} %{remote_ip} %{ssl_verify_result}\n`,
		"https://github.com",
	}

	type want struct {
		key, name, bin string
		args           []string
		display        string
		lcAllEnv       bool // true: env ends with LC_ALL=C; false: env is nil
	}
	nmapArgs := []string{"-sT", "-Pn", "--host-timeout", "110s", "github.com"}
	wantHost := []want{
		{"I", "route table", "ip", []string{"route"}, "ip route", false},
		{"s", "open sockets", "ss", []string{"-tunp"}, "ss -tunp", false},
		{"p", "ping the host", "ping", []string{"-c", "4", "-W", "2", "github.com"}, "ping -c 4 -W 2 github.com", false},
		{"d", "DNS lookup", "dig", []string{"+time=2", "+tries=1", "github.com"}, "dig +time=2 +tries=1 github.com", false},
		{"c", "web check", "curl", curlArgs, "LC_ALL=C curl " + shellArgs(curlArgs), true},
		{"t", "trace the path", "traceroute", []string{"-w", "2", "-q", "1", "-m", "20", "github.com"}, "traceroute -w 2 -q 1 -m 20 github.com", false},
		{"m", "path quality", "mtr", []string{"--report", "--report-cycles", "5", "github.com"}, "mtr --report --report-cycles 5 github.com", false},
		{"n", "port scan", "nmap", nmapArgs, "nmap " + shellArgs(nmapArgs), false},
	}

	got := toolsFor(tgt, "linux", toolBind{})
	if len(got) != len(wantHost) {
		t.Fatalf("toolsFor(host) returned %d tools, want %d", len(got), len(wantHost))
	}
	for i, w := range wantHost {
		tool := got[i]
		if tool.Key != w.key || tool.Name != w.name || tool.Bin != w.bin {
			t.Errorf("tool[%d] = {Key:%q Name:%q Bin:%q}, want {%q %q %q}", i, tool.Key, tool.Name, tool.Bin, w.key, w.name, w.bin)
		}
		args, env, display := tool.Build(tgt, nil)
		if !slices.Equal(args, w.args) {
			t.Errorf("tool[%d] %s argv = %q, want %q", i, w.key, args, w.args)
		}
		if display != w.display {
			t.Errorf("tool[%d] %s display = %q, want %q", i, w.key, display, w.display)
		}
		if w.lcAllEnv {
			if len(env) == 0 || env[len(env)-1] != "LC_ALL=C" {
				t.Errorf("tool[%d] %s env must end with LC_ALL=C, got %q", i, w.key, env)
			}
		} else if env != nil {
			t.Errorf("tool[%d] %s env = %q, want nil", i, w.key, env)
		}
	}

	// No-target set: only the target-independent tools, same order.
	generic := toolsFor(nil, "linux", toolBind{})
	wantGeneric := []string{"I", "s"}
	if len(generic) != len(wantGeneric) {
		t.Fatalf("toolsFor(nil) returned %d tools, want %d", len(generic), len(wantGeneric))
	}
	for i, k := range wantGeneric {
		if generic[i].Key != k {
			t.Errorf("toolsFor(nil)[%d].Key = %q, want %q", i, generic[i].Key, k)
		}
	}
}

// TestToolsForProtocol pins the protocol-aware "c" slot: SSH and SMTP targets
// get a bounded handshake probe instead of an HTTPS-oriented curl.
func TestToolsForProtocol(t *testing.T) {
	findC := func(tools []Tool) Tool {
		for _, tool := range tools {
			if tool.Key == "c" {
				return tool
			}
		}
		t.Fatal("no tool with key 'c'")
		return Tool{}
	}

	ssh := mustTarget(t, "example.com:22")
	c := findC(toolsFor(ssh, "linux", toolBind{}))
	if c.Name != "SSH check" || c.Bin != "ssh" {
		t.Fatalf("ssh target c-slot = {Name:%q Bin:%q}, want SSH check/ssh", c.Name, c.Bin)
	}
	args, env, display := c.Build(ssh, nil)
	wantSSH := []string{
		"-v", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "PreferredAuthentications=none",
		"-p", "22", "example.com",
	}
	if !slices.Equal(args, wantSSH) {
		t.Errorf("ssh argv = %q, want %q", args, wantSSH)
	}
	if env != nil {
		t.Errorf("ssh env = %q, want nil", env)
	}
	if display != "ssh "+shellArgs(wantSSH) {
		t.Errorf("ssh display = %q", display)
	}

	// Windows: throwaway known-hosts file is NUL, display uses psArgs.
	cw := findC(toolsFor(ssh, "windows", toolBind{}))
	argsW, _, _ := cw.Build(ssh, nil)
	if !slices.Contains(argsW, "UserKnownHostsFile=NUL") {
		t.Errorf("windows ssh argv = %q, want UserKnownHostsFile=NUL", argsW)
	}

	smtp := mustTarget(t, "mail.example.com:587")
	c = findC(toolsFor(smtp, "linux", toolBind{}))
	if c.Name != "SMTP check" || c.Bin != "openssl" {
		t.Fatalf("smtp target c-slot = {Name:%q Bin:%q}, want SMTP check/openssl", c.Name, c.Bin)
	}
	args, _, _ = c.Build(smtp, nil)
	wantSMTP := []string{"s_client", "-starttls", "smtp", "-connect", "mail.example.com:587"}
	if !slices.Equal(args, wantSMTP) {
		t.Errorf("smtp argv = %q, want %q", args, wantSMTP)
	}

	// HTTPS and no-proto targets keep curl.
	for _, raw := range []string{"github.com", "example.com:9999"} {
		tgt := mustTarget(t, raw)
		if c := findC(toolsFor(tgt, "linux", toolBind{})); c.Bin != "curl" {
			t.Errorf("%s c-slot bin = %q, want curl", raw, c.Bin)
		}
	}
}

// The c-slot's target argument: scheme carried from the parsed proto, explicit
// ports kept, IPv6 literals bracketed.
func TestToolsCTargetArg(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"http://example.com", "http://example.com"},
		{"https://example.com:8443", "https://example.com:8443"},
		{"example.com:9999", "https://example.com:9999"}, // ProtoNone defaults to https
		{"2001:db8::1", "https://[2001:db8::1]"},
		{"[2001:db8::1]:443", "https://[2001:db8::1]:443"},
		{"[2001:db8::1]:587", "[2001:db8::1]:587"},
		{"[fe80::1%eth0]:8443", "https://[fe80::1%25eth0]:8443"},
		{"ssh://[fe80::1%eth0]", "fe80::1%eth0"},
		{"[fe80::1%eth0]:587", "[fe80::1%eth0]:587"},
	}
	for _, tt := range tests {
		target := mustTarget(t, tt.target)
		args, _, _ := toolByKey(t, toolsFor(target, "linux", toolBind{}), "c").Build(target, nil)
		if got := args[len(args)-1]; got != tt.want {
			t.Errorf("tool target for %q = %q, want %q", tt.target, got, tt.want)
		}
	}
}

func TestDigReversesLiteralTargets(t *testing.T) {
	for _, raw := range []string{"1.1.1.1", "2001:db8::1", "fe80::1%eth0"} {
		target := mustTarget(t, raw)
		raw = target.Host // a zone scopes a connection, not a name
		tool := toolByKey(t, toolsFor(target, "linux", toolBind{}), "d")
		args, _, display := tool.Build(target, nil)
		want := []string{"+time=2", "+tries=1", "-x", raw}
		if tool.Name != "reverse DNS lookup" || !slices.Equal(args, want) || display != "dig "+shellArgs(want) {
			t.Errorf("dig for %q = {Name:%q args:%q display:%q}, want reverse lookup %q", raw, tool.Name, args, display, want)
		}
	}
}

// TestNmapTool pins the advanced tool: it must be gated behind Confirm, scan
// only an explicit target port or all ports otherwise, and never carry an
// aggressive scan flag.
func TestNmapTool(t *testing.T) {
	tgt := mustTarget(t, "example.com:8443")
	var tool Tool
	for _, x := range toolsFor(tgt, "linux", toolBind{}) {
		if x.Key == "n" {
			tool = x
		}
	}
	if tool.Bin != "nmap" {
		t.Fatal("no nmap tool with key 'n'")
	}
	if !tool.Confirm {
		t.Error("nmap must set Confirm so the command is shown before running")
	}
	args, _, display := tool.Build(tgt, nil)
	want := []string{"-sT", "-Pn", "--host-timeout", "110s", "-p", "8443", "example.com"}
	if !slices.Equal(args, want) {
		t.Errorf("nmap explicit-port argv = %q, want %q", args, want)
	}
	if !strings.HasPrefix(display, "nmap ") {
		t.Errorf("nmap display = %q, want it to start with the command", display)
	}
	allTarget := mustTarget(t, "example.com")
	allArgs, _, _ := toolByKey(t, toolsFor(allTarget, "linux", toolBind{}), "n").Build(allTarget, nil)
	wantAll := []string{"-sT", "-Pn", "--host-timeout", "110s", "example.com"}
	if !slices.Equal(allArgs, wantAll) {
		t.Errorf("nmap implicit-port argv = %q, want %q", allArgs, wantAll)
	}
	v6 := mustTarget(t, "[2001:db8::1]:8443")
	v6Args, _, _ := toolByKey(t, toolsFor(v6, "linux", toolBind{}), "n").Build(v6, nil)
	wantV6 := []string{"-sT", "-Pn", "--host-timeout", "110s", "-6", "-p", "8443", "2001:db8::1"}
	if !slices.Equal(v6Args, wantV6) {
		t.Errorf("nmap IPv6 argv = %q, want %q", v6Args, wantV6)
	}
	for _, bad := range []string{"-sS", "-sV", "-sU", "-O", "-A"} {
		if slices.Contains(args, bad) {
			t.Errorf("nmap argv contains aggressive flag %q", bad)
		}
	}
}

// The family-sensitive tools follow the address the chain actually reached the
// host on: a hostname that only has an AAAA record must be scanned and looked
// up over IPv6. Literal targets pin the family themselves and ignore sel; with
// no sel the pre-existing resolver-default behaviour stands.
func TestToolsFollowSelectedFamily(t *testing.T) {
	v6, v4 := net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.7")
	tests := []struct {
		name    string
		target  string
		sel     net.IP
		wantV6  bool     // nmap carries -6
		wantDig []string // nil = don't check (literal targets get reverse lookup)
	}{
		{"hostname selected IPv6", "example.com", v6, true, []string{"+time=2", "+tries=1", "-t", "AAAA", "example.com"}},
		{"hostname selected IPv4", "example.com", v4, false, []string{"+time=2", "+tries=1", "-t", "A", "example.com"}},
		{"hostname no selection", "example.com", nil, false, []string{"+time=2", "+tries=1", "example.com"}},
		{"IPv6 literal", "[2001:db8::1]:443", nil, true, nil},
		{"IPv4 literal", "1.1.1.1", nil, false, nil},
		{"literal outranks selection", "1.1.1.1", v6, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := mustTarget(t, tt.target)
			tools := toolsFor(target, "linux", toolBind{})
			args, _, _ := toolByKey(t, tools, "n").Build(target, tt.sel)
			if got := slices.Contains(args, "-6"); got != tt.wantV6 {
				t.Errorf("nmap argv %q: -6 present = %v, want %v", args, got, tt.wantV6)
			}
			if tt.wantDig == nil {
				return
			}
			dig, _, display := toolByKey(t, tools, "d").Build(target, tt.sel)
			if !slices.Equal(dig, tt.wantDig) || display != "dig "+shellArgs(tt.wantDig) {
				t.Errorf("dig argv = %q (display %q), want %q", dig, display, tt.wantDig)
			}
		})
	}
}

func TestLANDiscoveryTool(t *testing.T) {
	tool := lanDiscoveryTool(shellArgs, "192.168.12.0/24")
	args, _, _ := tool.Build(nil, nil)
	want := []string{"--unprivileged", "-sn", "-T3", "--host-timeout", "5s", "-oG", "-", "192.168.12.0/24"}
	if !tool.Confirm || !slices.Equal(args, want) {
		t.Fatalf("LAN scan = confirm %v, argv %q; want true, %q", tool.Confirm, args, want)
	}
}

func TestShellArgsQuotes(t *testing.T) {
	got := shellArgs([]string{"-w", `%{http_code}\n`, "https://x"})
	want := `-w '%{http_code}\n' https://x`
	if got != want {
		t.Errorf("shellArgs = %q, want %q", got, want)
	}
}

// psArgs targets PowerShell: single-quote literals, embedded ' doubled, and
// %{…} quoted so curl's format string stays inert.
func TestPsArgsQuotes(t *testing.T) {
	got := psArgs([]string{"-w", `%{http_code}\n`, "it's", "https://x"})
	want := `-w '%{http_code}\n' 'it''s' https://x`
	if got != want {
		t.Errorf("psArgs = %q, want %q", got, want)
	}
}

func toolByKey(t *testing.T, tools []Tool, key string) Tool {
	t.Helper()
	for _, tl := range tools {
		if tl.Key == key {
			return tl
		}
	}
	t.Fatalf("tool %q not offered", key)
	return Tool{}
}

// The Windows table: OS built-ins (route print, netstat -ano, ping -n,
// nslookup, curl.exe, tracert, pathping), NUL instead of /dev/null, a
// PowerShell-target display without the LC_ALL prefix, and pathping's own
// 90 s timeout.
func TestToolsForWindows(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	tools := toolsFor(tgt, "windows", toolBind{})

	wantBins := map[string]string{
		"I": "route", "s": "netstat", "p": "ping", "d": "nslookup",
		"c": "curl.exe", "t": "tracert", "m": "pathping", "n": "nmap",
	}
	if len(tools) != len(wantBins) {
		t.Fatalf("windows table has %d tools, want %d", len(tools), len(wantBins))
	}
	for key, bin := range wantBins {
		if got := toolByKey(t, tools, key).Bin; got != bin {
			t.Errorf("windows %q Bin = %q, want %q", key, got, bin)
		}
	}

	if args, _, _ := toolByKey(t, tools, "p").Build(tgt, nil); !slices.Equal(args, []string{"-n", "4", "-w", "2000", "github.com"}) {
		t.Errorf("windows ping argv = %q", args)
	}

	curl := toolByKey(t, tools, "c")
	args, env, display := curl.Build(tgt, nil)
	if !slices.Contains(args, "NUL") || slices.Contains(args, "/dev/null") {
		t.Errorf("windows curl must write to NUL, argv = %q", args)
	}
	if !strings.HasPrefix(display, "curl.exe ") || strings.Contains(display, "LC_ALL") {
		t.Errorf("windows curl display = %q, want curl.exe prefix without LC_ALL", display)
	}
	if !strings.Contains(display, `'%{http_code}`) {
		t.Errorf("windows curl display must PowerShell-quote the -w format: %q", display)
	}
	if len(env) == 0 || env[len(env)-1] != "LC_ALL=C" {
		t.Errorf("curl env must still set LC_ALL=C (harmless on Windows), got tail of %d entries", len(env))
	}

	pp := toolByKey(t, tools, "m")
	if pp.Timeout != 90*time.Second {
		t.Errorf("pathping Timeout = %v, want 90s", pp.Timeout)
	}
	if args, _, _ := pp.Build(tgt, nil); !slices.Equal(args, []string{"-h", "20", "-q", "5", "-p", "100", "-w", "500", "github.com"}) {
		t.Errorf("pathping argv = %q", args)
	}

	if args, _, _ := toolByKey(t, tools, "t").Build(tgt, nil); !slices.Equal(args, []string{"-w", "2000", "-h", "20", "github.com"}) {
		t.Errorf("tracert argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "I").Build(tgt, nil); !slices.Equal(args, []string{"print", "-4"}) {
		t.Errorf("route print argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "s").Build(tgt, nil); !slices.Equal(args, []string{"-ano"}) {
		t.Errorf("netstat argv = %q", args)
	}
}

// The macOS table: netstat for routes/sockets, ping without -W (BSD ping's -W
// is milliseconds), dig/curl/traceroute/mtr as on Linux.
func TestToolsForDarwin(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	tools := toolsFor(tgt, "darwin", toolBind{})

	if args, _, _ := toolByKey(t, tools, "I").Build(tgt, nil); !slices.Equal(args, []string{"-rn"}) {
		t.Errorf("darwin routes argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "s").Build(tgt, nil); !slices.Equal(args, []string{"-an", "-p", "tcp"}) {
		t.Errorf("darwin sockets argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "p").Build(tgt, nil); !slices.Equal(args, []string{"-c", "4", "github.com"}) {
		t.Errorf("darwin ping argv = %q (BSD -W must be omitted)", args)
	}
	if bin := toolByKey(t, tools, "d").Bin; bin != "dig" {
		t.Errorf("darwin d = %q, want dig", bin)
	}
	if bin := toolByKey(t, tools, "m").Bin; bin != "mtr" {
		t.Errorf("darwin m = %q, want mtr", bin)
	}
	if bin := toolByKey(t, tools, "c").Bin; bin != "curl" {
		t.Errorf("darwin c = %q, want curl", bin)
	}
	// Report mode prints only at the end, so mtr must outlive the default
	// 12s budget or a slow path yields an empty job.
	if pt := toolByKey(t, tools, "m").Timeout; pt != 45*time.Second {
		t.Errorf("darwin mtr Timeout = %v, want 45s", pt)
	}
}

// Every table keeps the same hotkey set so muscle memory transfers across OSes.
func TestToolTablesSameHotkeys(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	want := []string{"I", "s", "p", "d", "c", "t", "m", "n"}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		var keys []string
		for _, tl := range toolsFor(tgt, goos, toolBind{}) {
			keys = append(keys, tl.Key)
		}
		if !slices.Equal(keys, want) {
			t.Errorf("%s hotkeys = %v, want %v", goos, keys, want)
		}
	}
}
