// Tool tables per GOOS: definitions, the protocol-matched c slot, display
// quoting, and availability caching.

package ui

import (
	"errors"
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
		m.toolboxView()
		m.nextStep(diagnostic.ProbeDNS)
	}
	if calls != initialCalls {
		t.Fatalf("rendering performed %d extra LookPath calls", calls-initialCalls)
	}

	(&m).doRestart()
	if calls != initialCalls+len(m.tools) {
		t.Fatalf("restart LookPath calls = %d, want %d", calls-initialCalls, len(m.tools))
	}
	if m.tools[0].Available() {
		t.Error("restart did not refresh cached availability")
	}
}

// TestToolsForDefinitions pins the complete, ordered tool list returned by
// toolsFor — Key, Name, Bin, argv, env, and display — for both the no-target and
// with-host sets, plus per-call slice independence. These are user-visible (hotkeys,
// labels, toolbox order, exact command shapes) and frozen, so any swap, rename, or
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
	nmapArgs := []string{"-sT", "-T2", "-Pn", "--host-timeout", "90s", "--top-ports", "100", "github.com"}
	wantHost := []want{
		{"i", "ip route", "ip", []string{"route"}, "ip route", false},
		{"s", "ss", "ss", []string{"-tunp"}, "ss -tunp", false},
		{"p", "ping", "ping", []string{"-c", "4", "-W", "2", "github.com"}, "ping -c 4 -W 2 github.com", false},
		{"d", "dig", "dig", []string{"+time=2", "+tries=1", "github.com"}, "dig +time=2 +tries=1 github.com", false},
		{"c", "curl", "curl", curlArgs, "LC_ALL=C curl " + shellArgs(curlArgs), true},
		{"t", "traceroute", "traceroute", []string{"-w", "2", "-q", "1", "-m", "20", "github.com"}, "traceroute -w 2 -q 1 -m 20 github.com", false},
		{"m", "mtr", "mtr", []string{"--report", "--report-cycles", "5", "github.com"}, "mtr --report --report-cycles 5 github.com", false},
		{"n", "nmap", "nmap", nmapArgs, "nmap " + shellArgs(nmapArgs), false},
	}

	got := toolsFor(tgt, "linux")
	if len(got) != len(wantHost) {
		t.Fatalf("toolsFor(host) returned %d tools, want %d", len(got), len(wantHost))
	}
	for i, w := range wantHost {
		tool := got[i]
		if tool.Purpose == "" {
			t.Errorf("tool[%d] %s has no purpose", i, tool.Key)
		}
		if tool.Key != w.key || tool.Name != w.name || tool.Bin != w.bin {
			t.Errorf("tool[%d] = {Key:%q Name:%q Bin:%q}, want {%q %q %q}", i, tool.Key, tool.Name, tool.Bin, w.key, w.name, w.bin)
		}
		args, env, display := tool.Build(tgt)
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
	generic := toolsFor(nil, "linux")
	wantGeneric := []string{"i", "s"}
	if len(generic) != len(wantGeneric) {
		t.Fatalf("toolsFor(nil) returned %d tools, want %d", len(generic), len(wantGeneric))
	}
	for i, k := range wantGeneric {
		if generic[i].Key != k {
			t.Errorf("toolsFor(nil)[%d].Key = %q, want %q", i, generic[i].Key, k)
		}
	}

	// Slice independence: two Build calls must not share a backing array (Codex r1 #3).
	a1, _, _ := got[0].Build(tgt)
	a2, _, _ := got[0].Build(tgt)
	if len(a1) > 0 && &a1[0] == &a2[0] {
		t.Error("staticTool Build returned an aliased argv slice across calls")
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
	c := findC(toolsFor(ssh, "linux"))
	if c.Name != "ssh" || c.Purpose != "SSH check" || c.Bin != "ssh" {
		t.Fatalf("ssh target c-slot = {Name:%q Purpose:%q Bin:%q}, want ssh/SSH check/ssh", c.Name, c.Purpose, c.Bin)
	}
	args, env, display := c.Build(ssh)
	wantSSH := []string{
		"-v", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "22", "example.com", "exit",
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
	cw := findC(toolsFor(ssh, "windows"))
	argsW, _, _ := cw.Build(ssh)
	if !slices.Contains(argsW, "UserKnownHostsFile=NUL") {
		t.Errorf("windows ssh argv = %q, want UserKnownHostsFile=NUL", argsW)
	}

	smtp := mustTarget(t, "mail.example.com:587")
	c = findC(toolsFor(smtp, "linux"))
	if c.Name != "openssl s_client" || c.Purpose != "SMTP check" || c.Bin != "openssl" {
		t.Fatalf("smtp target c-slot = {Name:%q Purpose:%q Bin:%q}, want openssl s_client/SMTP check/openssl", c.Name, c.Purpose, c.Bin)
	}
	args, _, _ = c.Build(smtp)
	wantSMTP := []string{"s_client", "-starttls", "smtp", "-connect", "mail.example.com:587"}
	if !slices.Equal(args, wantSMTP) {
		t.Errorf("smtp argv = %q, want %q", args, wantSMTP)
	}

	// HTTPS and no-proto targets keep curl.
	for _, raw := range []string{"github.com", "example.com:9999"} {
		tgt := mustTarget(t, raw)
		if c := findC(toolsFor(tgt, "linux")); c.Bin != "curl" {
			t.Errorf("%s c-slot bin = %q, want curl", raw, c.Bin)
		}
	}
}

func TestToolsBracketIPv6(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"2001:db8::1", "https://[2001:db8::1]"},
		{"[2001:db8::1]:443", "https://[2001:db8::1]:443"},
		{"[2001:db8::1]:587", "[2001:db8::1]:587"},
	}
	for _, tt := range tests {
		target := mustTarget(t, tt.target)
		args, _, _ := toolByKey(t, toolsFor(target, "linux"), "c").Build(target)
		if got := args[len(args)-1]; got != tt.want {
			t.Errorf("tool target for %q = %q, want %q", tt.target, got, tt.want)
		}
	}
}

func TestDigReversesLiteralTargets(t *testing.T) {
	for _, raw := range []string{"1.1.1.1", "2001:db8::1"} {
		target := mustTarget(t, raw)
		tool := toolByKey(t, toolsFor(target, "linux"), "d")
		args, _, display := tool.Build(target)
		want := []string{"+time=2", "+tries=1", "-x", raw}
		if tool.Purpose != "reverse DNS lookup" || !slices.Equal(args, want) || display != "dig "+shellArgs(want) {
			t.Errorf("dig for %q = {Purpose:%q args:%q display:%q}, want reverse lookup %q", raw, tool.Purpose, args, display, want)
		}
	}
}

// TestNmapTool pins the advanced tool: it must be gated behind Confirm, scan
// only the target's explicit port, and never carry an aggressive scan flag.
func TestNmapTool(t *testing.T) {
	tgt := mustTarget(t, "example.com:8443")
	var tool Tool
	for _, x := range toolsFor(tgt, "linux") {
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
	args, _, display := tool.Build(tgt)
	want := []string{"-sT", "-T2", "-Pn", "--host-timeout", "90s", "-p", "8443", "example.com"}
	if !slices.Equal(args, want) {
		t.Errorf("nmap explicit-port argv = %q, want %q", args, want)
	}
	if !strings.HasPrefix(display, "nmap ") {
		t.Errorf("nmap display = %q, want it to start with the command", display)
	}
	v6 := mustTarget(t, "[2001:db8::1]:8443")
	v6Args, _, _ := toolByKey(t, toolsFor(v6, "linux"), "n").Build(v6)
	wantV6 := []string{"-sT", "-T2", "-Pn", "--host-timeout", "90s", "-6", "-p", "8443", "2001:db8::1"}
	if !slices.Equal(v6Args, wantV6) {
		t.Errorf("nmap IPv6 argv = %q, want %q", v6Args, wantV6)
	}
	for _, bad := range []string{"-sS", "-sV", "-sU", "-O", "-A"} {
		if slices.Contains(args, bad) {
			t.Errorf("nmap argv contains aggressive flag %q", bad)
		}
	}
}

func TestLANDiscoveryTool(t *testing.T) {
	tool := lanDiscoveryTool(shellArgs, "192.168.12.0/24")
	args, _, _ := tool.Build(nil)
	want := []string{"--unprivileged", "-sn", "-T3", "--host-timeout", "5s", "-oG", "-", "192.168.12.0/24"}
	if !tool.Confirm || !slices.Equal(args, want) {
		t.Fatalf("LAN discovery = confirm %v, argv %q; want true, %q", tool.Confirm, args, want)
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
	tools := toolsFor(tgt, "windows")

	wantBins := map[string]string{
		"i": "route", "s": "netstat", "p": "ping", "d": "nslookup",
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

	if args, _, _ := toolByKey(t, tools, "p").Build(tgt); !slices.Equal(args, []string{"-n", "4", "-w", "2000", "github.com"}) {
		t.Errorf("windows ping argv = %q", args)
	}

	curl := toolByKey(t, tools, "c")
	args, env, display := curl.Build(tgt)
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
	if args, _, _ := pp.Build(tgt); !slices.Equal(args, []string{"-h", "20", "-q", "5", "-p", "100", "-w", "500", "github.com"}) {
		t.Errorf("pathping argv = %q", args)
	}

	if args, _, _ := toolByKey(t, tools, "t").Build(tgt); !slices.Equal(args, []string{"-w", "2000", "-h", "20", "github.com"}) {
		t.Errorf("tracert argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "i").Build(tgt); !slices.Equal(args, []string{"print", "-4"}) {
		t.Errorf("route print argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "s").Build(tgt); !slices.Equal(args, []string{"-ano"}) {
		t.Errorf("netstat argv = %q", args)
	}
}

// The macOS table: netstat for routes/sockets, ping without -W (BSD ping's -W
// is milliseconds), dig/curl/traceroute/mtr as on Linux.
func TestToolsForDarwin(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	tools := toolsFor(tgt, "darwin")

	if args, _, _ := toolByKey(t, tools, "i").Build(tgt); !slices.Equal(args, []string{"-rn"}) {
		t.Errorf("darwin routes argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "s").Build(tgt); !slices.Equal(args, []string{"-an", "-p", "tcp"}) {
		t.Errorf("darwin sockets argv = %q", args)
	}
	if args, _, _ := toolByKey(t, tools, "p").Build(tgt); !slices.Equal(args, []string{"-c", "4", "github.com"}) {
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
	if pt := toolByKey(t, tools, "m").Timeout; pt != 0 {
		t.Errorf("darwin mtr Timeout = %v, want 0 (default)", pt)
	}
}

// Every table keeps the same hotkey set so muscle memory transfers across OSes.
func TestToolTablesSameHotkeys(t *testing.T) {
	tgt := mustTarget(t, "github.com")
	want := []string{"i", "s", "p", "d", "c", "t", "m", "n"}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		var keys []string
		for _, tl := range toolsFor(tgt, goos) {
			keys = append(keys, tl.Key)
		}
		if !slices.Equal(keys, want) {
			t.Errorf("%s hotkeys = %v, want %v", goos, keys, want)
		}
	}
}
