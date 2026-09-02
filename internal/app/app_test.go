// CLI surface: flag parsing and re-parsing, usage text, the version fallback,
// and the JSON report builder.

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/peer"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
	"github.com/heymaikol/network-doctor/internal/ui"
)

func TestVersionString(t *testing.T) {
	tests := []struct {
		name, injected, module, want string
	}{
		{"injected wins", "1.2.3", "v9.9.9", "1.2.3"},
		{"module fallback", "dev", "v1.2.3", "v1.2.3"},
		{"development build", "dev", "(devel)", "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionString(tt.injected, tt.module); got != tt.want {
				t.Errorf("versionString(%q, %q) = %q, want %q", tt.injected, tt.module, got, tt.want)
			}
		})
	}
}

// Only exercises paths that return before the TUI starts.
func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		want       int
		wantStdout string
		wantStderr string
	}{
		{"version", []string{"-version"}, 0, "netdoc dev", ""},
		{"bad flag", []string{"-nope"}, 2, "", "flag provided but not defined"},
		{"extra args", []string{"example.com", "extra"}, 2, "", "unexpected arguments"},
		{"bad target", []string{"bad_host!"}, 2, "", "netdoc:"},
		{"json+toolbox", []string{"-json", "-toolbox"}, 2, "", "cannot be combined"},
		{"bad iface", []string{"-iface", "netdoc-no-such-interface"}, 2, "", "-iface:"},
		{"version ignores bad timeout", []string{"-timeout", "-1s", "-version"}, 0, "netdoc dev", ""},
		{"version overrides list checks", []string{"-list-checks", "-version"}, 0, "netdoc dev", ""},
		{"help overrides list checks", []string{"-list-checks", "-help"}, 0, "-list-checks", ""},
		{"bad timeout", []string{"-timeout", "-1s"}, 2, "", "-timeout must be positive"},
		{"help lists check", []string{"-help"}, 0, "-check", ""},
		{"help lists skip", []string{"-help"}, 0, "-skip", ""},
		{"help lists -no-history", []string{"-help"}, 0, "-no-history", ""},
		{"help lists peer listener", []string{"-help"}, 0, "-peer-listen", ""},
		{"help lists peer connector", []string{"-help"}, 0, "-peer-connect", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.want {
				t.Errorf("run(%v) = %d, want %d", tt.args, got, tt.want)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want contains %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want contains %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestRunListChecks(t *testing.T) {
	restore := runAll
	runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		t.Fatal("--list-checks ran the probe DAG")
		return nil
	}
	t.Cleanup(func() { runAll = restore })

	const want = "iface\tInterface\n" +
		"internet_tcp\tInternet (TCP egress)\n" +
		"quic_udp_443\tQUIC / UDP 443\n" +
		"proxy_connect\tInternet (env proxy)\n" +
		"dns\tDNS\n" +
		"dns_public\tDNS (public)\n" +
		"dns_encrypted\tDNS (encrypted DoH/DoT)\n" +
		"target_tcp\tTCP\n" +
		"path_mtu\tPath MTU\n" +
		"ssid\tWi-Fi network\n" +
		"tls\tTLS\n" +
		"http\tHTTP\n" +
		"https\tHTTPS\n" +
		"ssh_banner\tSSH banner\n" +
		"smtp_banner\tSMTP banner\n"
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--list-checks"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunListChecksRejectsOtherArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--list-checks", "example.com"},
		{"--list-checks", "--json"},
		{"--list-checks", "--check", "dns"},
	} {
		t.Run(strings.Join(args[1:], "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(args, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2", got)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if want := "-list-checks cannot be combined with a target or other flags"; !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr = %q, want %q", stderr.String(), want)
			}
		})
	}
}

func TestRunPeerConnectJSON(t *testing.T) {
	originalRead, originalConnect := readPeerPairing, connectPeer
	t.Cleanup(func() { readPeerPairing, connectPeer = originalRead, originalConnect })
	const secret = "temporary-pairing-secret"
	readPeerPairing = func(io.Writer) (string, error) { return secret, nil }
	connectPeer = func(_ context.Context, code string, options peer.Options) (peer.Result, error) {
		if code != secret || options.Version != version || options.Timeout != diagnostic.DefaultProbeTimeout {
			t.Fatalf("connect args = %q, %+v", code, options)
		}
		return peer.Result{
			Schema: peer.ResultSchema, Version: version, ProtocolVersion: peer.ProtocolVersion,
			Local:        peer.EndpointIdentity{Role: peer.RoleConnector, Name: "b", ListenAddresses: []string{"127.0.0.1:2"}},
			Remote:       peer.EndpointIdentity{Role: peer.RoleListener, Name: "a", ListenAddresses: []string{"127.0.0.1:1"}},
			Diagnosis:    peer.CombinedDiagnosis{ID: peer.DiagnosisBidirectionalOK, Verdict: diagnostic.VerdictOK, Summary: "works", Evidence: []string{}},
			Observations: []peer.Observation{}, OK: true,
		}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--peer-connect", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	var result peer.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("peer JSON: %v\n%s", err, stdout.String())
	}
	if result.Schema != peer.ResultSchema || strings.Contains(stdout.String(), secret) || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestRunPeerRejectsMalformedPairingWithoutEchoingIt(t *testing.T) {
	originalRead, originalConnect := readPeerPairing, connectPeer
	t.Cleanup(func() { readPeerPairing, connectPeer = originalRead, originalConnect })
	const malformed = "not-a-pairing-string"
	readPeerPairing = func(io.Writer) (string, error) { return malformed, nil }
	connectPeer = peer.Connect
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--peer-connect", "--json"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 || strings.Contains(stderr.String(), malformed) {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestPeerModeRejectsConflictingOrdinaryOptions(t *testing.T) {
	tests := [][]string{
		{"--peer-connect", "--peer-listen", "127.0.0.1:0"},
		{"--peer-connect", "example.com"},
		{"--peer-connect", "--watch"},
		{"--peer-connect", "--check", "iface"},
		{"--peer-connect", "--public-dns", "9.9.9.9"},
		{"--peer-listen", "127.0.0.1:0", "--iface", "127.0.0.1"},
		{"--peer-listen", "127.0.0.1:0", "--timeout", "31s"},
	}
	for _, args := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("run(%q) = %d, want 2; stderr: %s", args, code, stderr.String())
		}
	}
}

func TestPeerListenFlagAllowsOneAddressPerFamily(t *testing.T) {
	var addresses peerListenList
	if err := addresses.Set("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if err := addresses.Set("[::1]:0"); err != nil {
		t.Fatal(err)
	}
	if err := addresses.Set("192.0.2.1:1"); err == nil {
		t.Fatal("second IPv4 peer listener was accepted")
	}
}

// Run as ssh's askpass helper, netdoc prints the secret it was handed and
// nothing else, with no flag parsing and no TUI. Only a password or passphrase
// question earns the secret; everything else, a missing prompt included, gets
// nothing: forced askpass sees the host-key question too, and that one must not
// be answered with a secret.
func TestRunAsAskpass(t *testing.T) {
	tests := []struct {
		name       string
		prompt     string
		proxied    bool
		want       int
		wantStdout string
	}{
		{name: "password", prompt: "alice@example.com's password:", want: 0, wantStdout: "hunter2\n"},
		{name: "passphrase", prompt: "Enter passphrase for key '/home/a/.ssh/id_ed25519':", want: 0, wantStdout: "hunter2\n"},
		{
			// ProxyJump: the jump host's ssh inherits the helper and asks for its
			// own password. Same "password" prompt, different machine.
			name: "password for a host on the way", prompt: "alice@jump.example.com's password:", want: 1,
		},
		{
			// The user@ half is not the target's, so it can't stand in for it.
			name: "password for a look-alike login", prompt: "example.com@evil.example's password:", want: 1,
		},
		// Keyboard-interactive: ssh puts the machine in front of the server's
		// own wording, so a PAM question is attributable after all.
		{
			name: "keyboard-interactive for the target", prompt: "(alice@example.com) Password: ",
			want: 0, wantStdout: "hunter2\n",
		},
		{
			name: "keyboard-interactive for a host on the way", prompt: "(alice@jump.example.com) Password: ",
			want: 1,
		},
		{
			// The text after ssh's prefix is the server's, and a jump host is
			// free to write the target's name into it. The prefix decides.
			name:   "keyboard-interactive impersonating the target",
			prompt: "(alice@jump.example.com) root@example.com's password: ", want: 1,
		},
		// A PAM prompt from a client too old to prefix them names no host, and
		// refusing those outright would break the logins netdoc is there to
		// make, as long as only one machine could be asking.
		{name: "hostless PAM prompt", prompt: "Password: ", want: 0, wantStdout: "hunter2\n"},
		{
			// With a jump host in the way, either end could have sent it.
			name: "hostless PAM prompt on a proxied connection", prompt: "Password: ",
			proxied: true, want: 1,
		},
		{
			// A real key passphrase names no host either, so under a proxy it is
			// indistinguishable from the case below and goes to the terminal.
			name: "passphrase on a proxied connection", prompt: "Enter passphrase for key '/home/a/.ssh/id_ed25519':",
			proxied: true, want: 1,
		},
		{
			// Why the line above can't be relaxed: the prompt a jump host sends
			// over keyboard-interactive is text it chose, so "passphrase" in it
			// is a claim, not evidence.
			name: "jump host calling its prompt a passphrase", prompt: "Enter passphrase for key '/home/a/.ssh/id_ed25519': ",
			proxied: true, want: 1,
		},
		// A helper whose job is to refuse what it doesn't recognize has no
		// business guessing at a prompt that isn't there.
		{name: "no prompt", prompt: "", want: 1},
		{
			name:   "host key",
			prompt: "The authenticity of host 'example.com' can't be established.\nAre you sure you want to continue connecting (yes/no/[fingerprint])?",
			want:   1,
		},
		{
			// The host name rides along in the first line of the host-key
			// message, so it must not be able to answer the question.
			name:   "host key for a host named password",
			prompt: "The authenticity of host 'password-reset.example.com (192.0.2.1)' can't be established.\nAre you sure you want to continue connecting (yes/no/[fingerprint])?",
			want:   1,
		},
		{
			name:   "host key for a key stored in a passphrase directory",
			prompt: "The authenticity of host 'passphrase.example.com' can't be established.\nAre you sure you want to continue connecting (yes/no/[fingerprint])?",
			want:   1,
		},
		{
			// Trailing blank line must not read as "no prompt at all".
			name:   "host key with a trailing newline",
			prompt: "The authenticity of host 'password.example.com' can't be established.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? \n",
			want:   1,
		},
		{
			// The price of refusing anything that mentions a fingerprint: a key
			// filed under that name has its passphrase prompt turned away too,
			// and the user types it on the terminal instead. Cheap at the price.
			name:   "passphrase for a key named fingerprint",
			prompt: "Enter passphrase for key '/home/a/.ssh/fingerprint_id':",
			want:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(ui.AskpassEnv, "hunter2")
			t.Setenv(ui.AskpassHostEnv, "example.com")
			if tt.proxied {
				t.Setenv(ui.AskpassProxyEnv, "1")
			}
			var stdout, stderr bytes.Buffer
			args := []string{tt.prompt}
			if tt.prompt == "" {
				args = nil
			}
			if got := run(args, &stdout, &stderr); got != tt.want {
				t.Errorf("run = %d, want %d", got, tt.want)
			}
			if got := stdout.String(); got != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", got, tt.wantStdout)
			}
			if tt.want == 0 && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

// An extra argument is echoed back to the terminal, so it has to come back as
// inert text: no OSC 52 clipboard grab, no CSI, no bidi override.
func TestRunBadArgsAreInert(t *testing.T) {
	const payload = "\x1b]52;c;aGk=\x07\x1b[31m\u202eevil\n"
	for _, args := range [][]string{
		{"example.com", payload},
		{"-" + payload},
	} {
		var stdout, stderr bytes.Buffer
		run(args, &stdout, &stderr)
		for _, bad := range []string{"\x1b", "\x07", "\u202e"} {
			if strings.Contains(stderr.String(), bad) {
				t.Errorf("run(%q): stderr = %q, want no %q", args, stderr.String(), bad)
			}
		}
	}
}

// Pins the seams around the shared TargetForms const: the "Target forms:"
// header, the blank line before "Flags:", and no trailing newline in the
// const itself, without freezing stdlib flag formatting.
func TestPrintUsageTargetForms(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf, flag.NewFlagSet("netdoc", flag.ContinueOnError))
	want := "Target forms:\n" + diagnostic.TargetForms + "\n\nFlags:"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("usage output missing the target-forms section:\n%s", buf.String())
	}
	for _, want := range []string{
		"netdoc --two-sided --via ssh-destination [target] [--json]",
		"concurrently\nacquires side A locally and side B on the SSH host",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("usage output missing %q:\n%s", want, buf.String())
		}
	}
}

// Both convenience files are only a choice of path handed to the UI, which
// already treats "" as in-memory only, so the seam worth pinning is that path.
// -no-history still resolves to "", and both defaults still point at the
// directory the reference documentation promises.
func TestConfigFilePaths(t *testing.T) {
	if got := historyFile(true); got != "" {
		t.Errorf("historyFile(true) = %q, want the empty path", got)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("no user config dir on this host: %v", err)
	}
	want := filepath.Join(dir, "netdoc", "history")
	if got := historyFile(false); got != want {
		t.Errorf("historyFile(false) = %q, want %q", got, want)
	}
	// The theme preference sits beside it, and is deliberately not tied to
	// -no-history, which is about the targets you type.
	if got, want := themeFile(), filepath.Join(dir, "netdoc", "theme"); got != want {
		t.Errorf("themeFile() = %q, want %q", got, want)
	}
}

// A misspelled preset is rejected before anything runs, including under
// -json, where the keymap has no effect but the typo is still worth hearing
// about on the run that carries it.
func TestRunRejectsUnknownKeyPreset(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-keys", "emacs", "-json"}, &stdout, &stderr); code != 2 {
		t.Errorf("run(-keys emacs) = %d, want 2", code)
	}
	want := fmt.Sprintf("netdoc: -keys: unknown key preset %q (have: %s)\n", "emacs", strings.Join(ui.KeyPresets(), ", "))
	if stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
	if stdout.Len() > 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
}

func TestRunAcceptsVimKeyPreset(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, probe := range probes {
			results[probe.ID] = diagnostic.ProbeResult{ID: probe.ID, Status: diagnostic.StatusPass}
		}
		return results
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--keys=vim", "--json", "--check", "iface"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(--keys=vim) = %d; stderr: %s", code, stderr.String())
	}
}

// Drives the real -json path through run() with probe execution stubbed out,
// pinning the headless contract: valid JSON on stdout, exit 1 iff a check failed.
func TestRunJSON(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	tests := []struct {
		name   string
		status diagnostic.Status
		want   int
	}{
		{"all pass", diagnostic.StatusPass, 0},
		{"a failure", diagnostic.StatusFail, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
				results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
				for _, p := range probes {
					results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: tt.status}
				}
				return results
			}
			var stdout, stderr bytes.Buffer
			if got := run([]string{"-json", "example.com:443"}, &stdout, &stderr); got != tt.want {
				t.Fatalf("exit = %d, want %d; stderr: %s", got, tt.want, stderr.String())
			}
			var rep report.Report
			if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			if rep.OK != (tt.want == 0) {
				t.Errorf("ok = %v, want %v", rep.OK, tt.want == 0)
			}
			if rep.Target == nil || rep.Target.Host != "example.com" {
				t.Errorf("target = %+v", rep.Target)
			}
			if len(rep.Checks) == 0 {
				t.Error("checks empty, want the probe DAG")
			}
		})
	}
}

func TestRunProbeSelectionFlags(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
		}
		return results
	}
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"one check", []string{"--check", "tls"}, []string{"iface", "dns", "target_tcp", "tls"}},
		{"comma-separated checks", []string{"--check", "dns,target_tcp,tls"}, []string{"iface", "dns", "target_tcp", "tls"}},
		{"repeated checks", []string{"--check", "dns,target_tcp", "--check", "tls"}, []string{"iface", "dns", "target_tcp", "tls"}},
		{"equals check", []string{"--check=dns,target_tcp"}, []string{"iface", "dns", "target_tcp"}},
		{"duplicate checks", []string{"--check", "dns,dns"}, []string{"iface", "dns"}},
		{"one skip", []string{"--skip", "quic_udp_443"}, []string{"iface", "internet_tcp", "proxy_connect", "dns", "dns_public", "dns_encrypted", "target_tcp", "path_mtu", "ssid", "tls", "http", "https"}},
		{"multiple skips", []string{"--skip", "internet_tcp,quic_udp_443"}, []string{"iface", "proxy_connect", "dns", "dns_public", "dns_encrypted", "target_tcp", "path_mtu", "ssid", "tls", "http", "https"}},
		{"repeated skips", []string{"--skip", "internet_tcp", "--skip", "quic_udp_443"}, []string{"iface", "proxy_connect", "dns", "dns_public", "dns_encrypted", "target_tcp", "path_mtu", "ssid", "tls", "http", "https"}},
		{"equals repeated skips", []string{"--skip=dns", "--skip=target_tcp"}, []string{"iface", "internet_tcp", "quic_udp_443", "proxy_connect", "dns_public", "dns_encrypted", "ssid"}},
		{"combined", []string{"--check", "dns,target_tcp,tls", "--skip", "dns"}, []string{}},
		{"argument order", []string{"--check", "tls,dns,target_tcp"}, []string{"iface", "dns", "target_tcp", "tls"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"--json", "example.com"}, tt.args...)
			if got := run(args, &stdout, &stderr); got != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
			}
			var rep report.Report
			if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
			got := make([]string, len(rep.Checks))
			for i, check := range rep.Checks {
				got[i] = check.ID
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("check IDs = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunProbeSelectionPreservesDiagnosis(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			status := diagnostic.StatusPass
			if p.ID == diagnostic.ProbeTargetTCP {
				status = diagnostic.StatusFail
			}
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: status}
		}
		return results
	}
	runReport := func(args ...string) report.Report {
		var stdout, stderr bytes.Buffer
		if got := run(args, &stdout, &stderr); got != 1 {
			t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
		}
		var rep report.Report
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}

	baseline := runReport("--json", "1.1.1.1:81")
	skipped := runReport("--json", "--skip", "ssid", "1.1.1.1:81")
	if skipped.Summary != baseline.Summary || skipped.Verdict != baseline.Verdict {
		t.Fatalf("skipping SSID changed diagnosis from %q/%q to %q/%q", baseline.Summary, baseline.Verdict, skipped.Summary, skipped.Verdict)
	}
}

func TestRunKnownButInapplicableProbeSelection(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
		}
		return results
	}
	runReport := func(t *testing.T, args ...string) report.Report {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if got := run(args, &stdout, &stderr); got != 0 {
			t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
		}
		var rep report.Report
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	ids := func(rep report.Report) []string {
		got := make([]string, len(rep.Checks))
		for i, check := range rep.Checks {
			got[i] = check.ID
		}
		return got
	}

	empty := runReport(t, "--json", "--check", "tls", "host:9999")
	if len(empty.Checks) != 0 || empty.Summary != "No checks selected." || empty.Verdict != diagnostic.VerdictOK || !empty.OK {
		t.Fatalf("inapplicable check report = %+v", empty)
	}

	baseline := runReport(t, "--json", "host:9999")
	skipped := runReport(t, "--json", "--skip", "tls", "host:9999")
	if !reflect.DeepEqual(ids(skipped), ids(baseline)) {
		t.Errorf("inapplicable skip changed DAG: %v != %v", ids(skipped), ids(baseline))
	}
	if skipped.Summary != baseline.Summary || skipped.Verdict != baseline.Verdict || skipped.OK != baseline.OK {
		t.Errorf("inapplicable skip changed diagnosis: %+v != %+v", skipped, baseline)
	}

	withoutPublic := runReport(t, "--json", "--public-dns", "", "--skip", "dns_public", "host:9999")
	for _, id := range ids(withoutPublic) {
		if id == "dns_public" {
			t.Fatal("disabled public DNS probe was constructed")
		}
	}
}

func TestProbeListRejectsAtomically(t *testing.T) {
	var list probeList
	if err := list.Set("dns,"); err == nil {
		t.Fatal("trailing empty probe ID accepted")
	}
	if len(list) != 0 {
		t.Fatalf("failed parse retained IDs: %v", list)
	}
	if err := list.Set("dns"); err != nil {
		t.Fatal(err)
	}
	if err := list.Set("target_tcp,,tls"); err == nil {
		t.Fatal("later malformed probe list accepted")
	}
	if want := (probeList{diagnostic.ProbeDNS}); !reflect.DeepEqual(list, want) {
		t.Fatalf("later failed parse changed IDs: %v, want %v", list, want)
	}
}

func TestBuildReportEmptySelection(t *testing.T) {
	rep := buildReport(nil, nil, nil)
	if rep.Checks == nil || rep.Summary != "No checks selected." || rep.Verdict != diagnostic.VerdictOK || !rep.OK {
		t.Fatalf("empty report = %+v", rep)
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"checks":[]`)) {
		t.Fatalf("empty checks JSON = %s, want []", b)
	}
}

func TestRunRejectsInvalidProbeSelectionBeforeDiagnostics(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runs := 0
	runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		runs++
		return nil
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown check", []string{"--check", "bogus"}, `unknown probe ID "bogus"`},
		{"unknown skip", []string{"--skip", "bogus"}, `unknown probe ID "bogus"`},
		{"deterministic unknown", []string{"--check", "zzz,aaa"}, `unknown probe ID "aaa"`},
		{"whitespace is not normalized", []string{"--check", " dns"}, `unknown probe ID " dns"`},
		{"empty check", []string{"--check", ""}, "empty probe ID"},
		{"empty equals check", []string{"--check="}, "empty probe ID"},
		{"empty trailing check", []string{"--check", "dns,"}, "empty probe ID"},
		{"empty middle check", []string{"--check", "dns,,tls"}, "empty probe ID"},
		{"empty leading skip", []string{"--skip", ",dns"}, "empty probe ID"},
		{"empty skip", []string{"--skip", ""}, "empty probe ID"},
		{"empty equals skip", []string{"--skip="}, "empty probe ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"--json"}, tt.args...)
			args = append(args, "example.com")
			if got := run(args, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2", got)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
	if runs != 0 {
		t.Errorf("diagnostics ran %d times for rejected selections", runs)
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--json", "--check", "bogus", "example.com"}, &stdout, &stderr); got != 2 {
		t.Fatalf("global-ID error exit = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "ssh_banner") || !strings.Contains(stderr.String(), "smtp_banner") {
		t.Errorf("valid-ID list is target-specific: %q", stderr.String())
	}
	if runs != 0 {
		t.Errorf("diagnostics ran %d times while listing valid IDs", runs)
	}
}

// -public-dns is the opt-out for the one third-party resolver netdoc queries.
// Driven through run() rather than the flag set, because the value has to
// survive parsing, validation, and probe construction to reach the report.
func TestRunPublicDNSFlag(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
		}
		return results
	}
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantRow  string // "" means the row must be absent
	}{
		{"the default names no resolver", nil, 0, "DNS (public)"},
		{"auto is not a resolver anyone can type", []string{"-public-dns", "auto"}, 2, ""},
		{"explicit default address stays exact", []string{"-public-dns", "8.8.8.8"}, 0, "DNS (public 8.8.8.8)"},
		{"custom IPv4", []string{"-public-dns", "9.9.9.9"}, 0, "DNS (public 9.9.9.9)"},
		{"custom IPv6", []string{"-public-dns", "2620:fe::fe"}, 0, "DNS (public 2620:fe::fe)"},
		{"IPv6 is canonicalized", []string{"-public-dns", "2620:00fe:0000::00FE"}, 0, "DNS (public 2620:fe::fe)"},
		{"empty argument disables", []string{"-public-dns", ""}, 0, ""},
		{"empty via equals disables", []string{"-public-dns="}, 0, ""},
		{"hostname rejected", []string{"-public-dns", "dns.google"}, 2, ""},
		{"truncated address rejected", []string{"-public-dns", "8.8.8"}, 2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(append([]string{"-json"}, tt.args...), &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d; stderr: %s", code, tt.wantCode, stderr.String())
			}
			if tt.wantCode != 0 {
				if !strings.Contains(stderr.String(), "-public-dns") {
					t.Errorf("stderr = %q, want it to name the rejected flag", stderr.String())
				}
				if stdout.Len() != 0 {
					t.Errorf("stdout = %q, want no report for a rejected value", stdout.String())
				}
				return
			}
			var rep report.Report
			if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			got := ""
			for _, c := range rep.Checks {
				if c.ID == "dns_public" {
					got = c.Name
				}
			}
			if got != tt.wantRow {
				t.Errorf("dns_public row = %q, want %q", got, tt.wantRow)
			}
		})
	}
}

// -timeout is the only knob on the bounded-time contract, and rejecting a bad
// value proves nothing about a good one: a positive duration has to reach the
// probes before the run starts.
func TestRunAppliesTimeout(t *testing.T) {
	origRun := runAll
	t.Cleanup(func() { runAll = origRun })

	var applied time.Duration
	runAll = func(_ context.Context, probes []diagnostic.Probe, timeout time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		applied = timeout
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
		}
		return results
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{"-timeout", "250ms", "-json", "example.com:443"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if applied != 250*time.Millisecond {
		t.Errorf("timeout passed to the runner = %v, want 250ms", applied)
	}
}

// cancelAfter stops the watch loop once it has written n reports, standing in
// for the Ctrl-C that ends it in real use.
type cancelAfter struct {
	buf    *bytes.Buffer
	n      int
	cancel context.CancelFunc
}

func (c *cancelAfter) Write(p []byte) (int, error) {
	n, err := c.buf.Write(p)
	c.n--
	if c.n <= 0 {
		c.cancel()
	}
	return n, err
}

// The watch stream's promise is one self-contained, timestamped report per
// line, and anything indented or unterminated breaks every line-oriented reader.
func TestRunJSONWatchStreamsOnePerLine(t *testing.T) {
	origRun, origEvery := runAll, ui.WatchEvery
	t.Cleanup(func() { runAll, ui.WatchEvery = origRun, origEvery })
	ui.WatchEvery = time.Millisecond
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusFail}
		}
		return results
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf, stderr bytes.Buffer
	out := &cancelAfter{buf: &buf, n: 3, cancel: cancel}
	if got := runHeadless(ctx, headless{watch: true, json: true, publicDNS: diagnostic.DefaultPublicDNS, timeout: diagnostic.DefaultProbeTimeout}, out, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), buf.String())
	}
	for i, line := range lines {
		var rep report.Report
		if err := json.Unmarshal([]byte(line), &rep); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", i, err, line)
		}
		if rep.Ts == "" {
			t.Errorf("line %d has no ts", i)
		}
		if len(rep.Checks) == 0 {
			t.Errorf("line %d has no checks", i)
		}
	}
}

func TestRunJSONWatchHandlesEmptySelection(t *testing.T) {
	origRun, origEvery := runAll, ui.WatchEvery
	t.Cleanup(func() { runAll, ui.WatchEvery = origRun, origEvery })
	ui.WatchEvery = time.Millisecond
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		if len(probes) != 0 {
			t.Fatalf("empty selection ran probes: %v", probes)
		}
		return map[diagnostic.ProbeID]diagnostic.ProbeResult{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf, stderr bytes.Buffer
	out := &cancelAfter{buf: &buf, n: 2, cancel: cancel}
	selection := diagnostic.ProbeSelection{Check: map[diagnostic.ProbeID]struct{}{diagnostic.ProbeTLS: {}}}
	if got := runHeadless(ctx, headless{watch: true, json: true, publicDNS: diagnostic.DefaultPublicDNS, selection: selection, timeout: diagnostic.DefaultProbeTimeout}, out, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	for i, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rep report.Report
		if err := json.Unmarshal([]byte(line), &rep); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if rep.Checks == nil || len(rep.Checks) != 0 || rep.Summary != "No checks selected." || !rep.OK {
			t.Errorf("line %d empty report = %+v", i, rep)
		}
	}
}

// If the context is already cancelled before the first pass completes, there
// is no report to trust, so runHeadless must fail closed rather than default to 0.
func TestRunJSONInterruptedBeforeFirstReport(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runAll = func(ctx context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		if ctx.Err() == nil {
			t.Error("runAll called with a live context, want it already cancelled")
		}
		return nil
	}

	var stdout, stderr bytes.Buffer
	if got := runHeadless(ctx, headless{watch: true, json: true, publicDNS: diagnostic.DefaultPublicDNS, timeout: diagnostic.DefaultProbeTimeout}, &stdout, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty (no report for a cancelled pass)", stdout.String())
	}
}

// ms is the one field with an out-of-band meaning: 0 has to keep saying "never
// ran", which a sub-millisecond check would otherwise steal. Per-attempt ms
// carries the same promise, since a LAN connect lands under a millisecond often.
func TestBuildReportFloorsSubMillisecondChecks(t *testing.T) {
	probes := []diagnostic.Probe{
		{ID: diagnostic.ProbeIface, Name: "Interface"},
		{ID: diagnostic.ProbeInternet, Name: "Internet"},
		{ID: diagnostic.ProbeTargetTCP, Name: "TCP"},
	}
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface:    {ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass, Dur: 120 * time.Microsecond},
		diagnostic.ProbeInternet: {ID: diagnostic.ProbeInternet, Status: diagnostic.StatusSkip},
		diagnostic.ProbeTargetTCP: {
			ID:       diagnostic.ProbeTargetTCP,
			Status:   diagnostic.StatusPass,
			Dur:      2 * time.Millisecond,
			Attempts: []diagnostic.Attempt{{IP: net.ParseIP("192.168.1.1"), Dur: 300 * time.Microsecond}},
		},
	}
	rep := buildReport(nil, probes, results)
	if rep.Checks[0].Ms != 1 {
		t.Errorf("sub-millisecond check ms = %d, want 1", rep.Checks[0].Ms)
	}
	if rep.Checks[1].Ms != 0 {
		t.Errorf("check that never ran ms = %d, want 0", rep.Checks[1].Ms)
	}
	if got := rep.Checks[2].Attempts[0].Ms; got != 1 {
		t.Errorf("sub-millisecond attempt ms = %d, want 1", got)
	}
}

// A probe the run never reported is the absence of an observation, not an
// observation, and --json is a published format: it has to say so in its own
// value rather than inherit the Go zero of diagnostic.Status, which is PASS.
// This checks the raw JSON, because a consumer reads that and not the Go struct
// that made it; an unmarshal into report.Check would agree with whatever the
// encoder did.
func TestSerializedStatusDistinguishesReportedPassFromUnreportedCheck(t *testing.T) {
	probes := []diagnostic.Probe{
		{ID: diagnostic.ProbeIface, Name: "Interface"},
		{ID: diagnostic.ProbeInternet, Name: "Internet"},
		{ID: diagnostic.ProbeQUIC, Name: "QUIC / UDP 443"},
	}
	// The QUIC row is the one the run never reached: it is in the check set
	// and absent from the results map, which is exactly what a cancelled run
	// leaves behind.
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface:    {Status: diagnostic.StatusPass, Dur: 2 * time.Millisecond},
		diagnostic.ProbeInternet: {Status: diagnostic.StatusSkip},
	}
	blob, err := json.Marshal(buildReport(nil, probes, results))
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Checks []map[string]json.RawMessage `json:"checks"`
		OK     json.RawMessage              `json:"ok"`
	}
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatal(err)
	}
	// Literal strings on purpose. Renaming a constant must not be able to
	// change what a consumer reads without this failing.
	want := []struct{ id, status string }{
		{"iface", `"PASS"`},
		{"internet_tcp", `"SKIP"`},
		{"quic_udp_443", `"INCOMPLETE"`},
	}
	// The unreported row keeps its place in checks rather than being dropped,
	// so a reader can still see the check existed and was not reached.
	if len(raw.Checks) != len(want) {
		t.Fatalf("%d rows encoded, want %d: %s", len(raw.Checks), len(want), blob)
	}
	for i, w := range want {
		if got := string(raw.Checks[i]["id"]); got != `"`+w.id+`"` {
			t.Fatalf("row %d id = %s", i, got)
		}
		if got := string(raw.Checks[i]["status"]); got != w.status {
			t.Errorf("%s status = %s, want %s", w.id, got, w.status)
		}
	}
	// The whole point, stated as the thing a consumer would do wrong.
	if string(raw.Checks[2]["status"]) == `"PASS"` {
		t.Error("an unreported check serialized as a pass")
	}
	// And a script reads ok before it reads any row.
	if string(raw.OK) != "false" {
		t.Errorf("ok = %s, want false, with an unreported check in the report", raw.OK)
	}

	// A reported pass stays a pass: filling the same row in restores the run
	// that answered for every probe it was asked about.
	results[diagnostic.ProbeQUIC] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Dur: 3 * time.Millisecond}
	complete, err := json.Marshal(buildReport(nil, probes, results))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(complete, &raw); err != nil {
		t.Fatal(err)
	}
	if got := string(raw.Checks[2]["status"]); got != `"PASS"` {
		t.Errorf("reported quic status = %s, want \"PASS\"", got)
	}
	if string(raw.OK) != "true" {
		t.Errorf("ok = %s, want true, with every check reported", raw.OK)
	}
	if bytes.Contains(complete, []byte("INCOMPLETE")) {
		t.Errorf("a fully reported run emitted an incomplete row: %s", complete)
	}
}

func TestBuildReportAddsAddressFamilyEvidenceWithoutChangingOtherRows(t *testing.T) {
	probes := []diagnostic.Probe{{ID: diagnostic.ProbeInternet, Name: "Internet"}, {ID: diagnostic.ProbeIface, Name: "Interface"}}
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeInternet: {Status: diagnostic.StatusWarn, Families: &diagnostic.FamilyConnectivity{
			IPv4: diagnostic.FamilyReachable, IPv6: diagnostic.FamilyUnreachable,
		}},
		diagnostic.ProbeIface: {Status: diagnostic.StatusPass},
	}
	rep := buildReport(nil, probes, results)
	if rep.Checks[0].Families == nil || rep.Checks[0].Families.IPv4 != "reachable" || rep.Checks[0].Families.IPv6 != "unreachable" {
		t.Errorf("internet families = %+v", rep.Checks[0].Families)
	}
	if rep.Checks[1].Families != nil {
		t.Errorf("unrelated row gained family evidence: %+v", rep.Checks[1])
	}
	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(blob, []byte(`"address_families":{"ipv4":"reachable","ipv6":"unreachable"}`)) {
		t.Errorf("JSON missing address families: %s", blob)
	}
	results[diagnostic.ProbeInternet] = diagnostic.ProbeResult{Status: diagnostic.StatusPass, Families: &diagnostic.FamilyConnectivity{
		IPv4: diagnostic.FamilyReachable,
	}}
	availableOnly, err := json.Marshal(buildReport(nil, probes, results))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(availableOnly, []byte(`"address_families":{"ipv4":"reachable"}`)) || bytes.Contains(availableOnly, []byte(`"ipv6"`)) {
		t.Errorf("JSON did not omit the untested family: %s", availableOnly)
	}
}

func TestBuildReportPreservesCounterfactualFinding(t *testing.T) {
	target := &diagnostic.Target{Host: "example.com", Port: 443, Proto: diagnostic.ProtoNone}
	a, b := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	probes := []diagnostic.Probe{
		{ID: diagnostic.ProbeIface, Name: "Interface"},
		{ID: diagnostic.ProbeInternet, Name: "Internet"},
		{ID: diagnostic.ProbeDNS, Name: "DNS"},
		{ID: diagnostic.ProbeTargetTCP, Name: "Target TCP"},
	}
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface:    {Status: diagnostic.StatusPass},
		diagnostic.ProbeInternet: {Status: diagnostic.StatusPass},
		diagnostic.ProbeDNS:      {Status: diagnostic.StatusPass, Addrs: []net.IP{a, b}},
		diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusWarn, SelectedIP: b,
			Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyReachable}, Attempts: []diagnostic.Attempt{
				{IP: a, Err: errors.New("unreachable"), Cause: diagnostic.ConnectionCauseUnreachable}, {IP: b},
			}},
	}
	rep := buildReport(target, probes, results)
	if len(rep.Findings) != 1 || rep.Findings[0].ID != string(diagnostic.DiagnosisPartialReachability) {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	cf := rep.Findings[0].Counterfactual
	if cf == nil || cf.Variable != string(diagnostic.CounterfactualResolvedAddress) || len(cf.Alternatives) != 2 {
		t.Errorf("counterfactual = %+v", cf)
	}
	if rep.Checks[3].Attempts[0].Cause != diagnostic.ConnectionCauseUnreachable {
		t.Errorf("attempt = %+v", rep.Checks[3].Attempts[0])
	}
}

func TestBuildReportKeepsEncryptedResolverWarningFunctional(t *testing.T) {
	probes := []diagnostic.Probe{
		{ID: diagnostic.ProbeInternet, Name: "Internet"},
		{ID: diagnostic.ProbeDNS, Name: "DNS"},
		{ID: diagnostic.ProbeDNSEncrypted, Name: "DNS (encrypted DoH/DoT)"},
	}
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeInternet:     {Status: diagnostic.StatusPass},
		diagnostic.ProbeDNS:          {Status: diagnostic.StatusPass},
		diagnostic.ProbeDNSEncrypted: {Status: diagnostic.StatusWarn, Detail: "resolver answered SERVFAIL"},
	}
	rep := buildReport(nil, probes, results)
	if !rep.OK || rep.FailedStage != "" || rep.Verdict != diagnostic.VerdictDegraded ||
		rep.Checks[2].Status != "WARN" || rep.Summary == "" {
		t.Fatalf("report = %+v, want a visible WARN that remains functional and does not become a failed stage", rep)
	}
}

func TestBuildReport(t *testing.T) {
	target, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	probes := []diagnostic.Probe{
		{ID: diagnostic.ProbeIface, Name: "Interface"},
		{ID: diagnostic.ProbeDNS, Name: "DNS example.com"},
		{ID: diagnostic.ProbeTargetTCP, Name: "TCP example.com:443"},
	}
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface: {ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass, Detail: "interface eth0 is up", Iface: "eth0", Dur: 7 * time.Millisecond},
		diagnostic.ProbeDNS: {
			ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail, Detail: "cannot resolve example.com",
			Fix: "check DNS", Dur: 1200 * time.Millisecond,
			ResolverTargets: []string{"192.0.2.53:53", "[2001:db8::53]:53"},
		},
		// One row carrying every address field: buildReport stringifies them the
		// same way regardless of which probe produced them.
		diagnostic.ProbeTargetTCP: {
			ID:         diagnostic.ProbeTargetTCP,
			Status:     diagnostic.StatusPass,
			Detail:     "connected",
			Portal:     &diagnostic.Portal{RedirectURL: "https://portal.example/signin"},
			Addrs:      []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
			SelectedIP: net.ParseIP("2001:db8::1"),
			Source:     net.ParseIP("192.168.1.20"),
			Attempts: []diagnostic.Attempt{
				{IP: net.ParseIP("192.0.2.1"), Dur: 90 * time.Millisecond, Err: errors.New("connection refused")},
				{IP: net.ParseIP("2001:db8::1"), Dur: 12 * time.Millisecond},
			},
		},
	}
	rep := buildReport(target, probes, results)

	if rep.OK {
		t.Error("OK = true, want false (DNS failed)")
	}
	if rep.Target == nil || rep.Target.Host != "example.com" || rep.Target.Port != 443 || rep.Target.Protocol != "tls+http" {
		t.Errorf("target = %+v", rep.Target)
	}
	if len(rep.Checks) != 3 {
		t.Fatalf("got %d checks, want 3", len(rep.Checks))
	}
	if rep.Checks[0].Status != "PASS" || rep.Checks[0].Fix != "" {
		t.Errorf("iface check = %+v", rep.Checks[0])
	}
	if rep.Checks[1].Status != "FAIL" || rep.Checks[1].Fix != "check DNS" {
		t.Errorf("dns check = %+v", rep.Checks[1])
	}
	if got := rep.Checks[1].ResolverTargets; !reflect.DeepEqual(got, []string{"192.0.2.53:53", "[2001:db8::53]:53"}) {
		t.Errorf("dns resolver targets = %v", got)
	}
	if rep.Checks[0].Ms != 7 || rep.Checks[1].Ms != 1200 {
		t.Errorf("timings = %d, %d ms; want 7, 1200", rep.Checks[0].Ms, rep.Checks[1].Ms)
	}
	if !strings.Contains(rep.Summary, "Cannot resolve example.com") {
		t.Errorf("summary = %q", rep.Summary)
	}
	// The first failing row, not merely a failing one, since scripts route on this.
	if rep.FailedStage != string(diagnostic.ProbeDNS) {
		t.Errorf("failed_stage = %q, want %q", rep.FailedStage, diagnostic.ProbeDNS)
	}
	if rep.Verdict != diagnostic.VerdictDNS {
		t.Errorf("verdict = %q, want %q", rep.Verdict, diagnostic.VerdictDNS)
	}
	tcp := rep.Checks[2]
	if got, want := strings.Join(tcp.Addrs, ","), "192.0.2.1,2001:db8::1"; got != want {
		t.Errorf("addrs = %q, want %q", got, want)
	}
	if tcp.SelectedIP != "2001:db8::1" || tcp.Source != "192.168.1.20" {
		t.Errorf("selected_ip = %q, source = %q", tcp.SelectedIP, tcp.Source)
	}
	if tcp.Portal == nil || tcp.Portal.RedirectURL != "https://portal.example/signin" {
		t.Errorf("portal = %+v", tcp.Portal)
	}
	// Attempts keep probe order, and only a failed attempt carries an error.
	want := []report.Attempt{
		{IP: "192.0.2.1", Ms: 90, Err: "connection refused"},
		{IP: "2001:db8::1", Ms: 12},
	}
	if !reflect.DeepEqual(tcp.Attempts, want) {
		t.Errorf("attempts = %+v, want %+v", tcp.Attempts, want)
	}
}

func TestBuildReportGenericAllPass(t *testing.T) {
	probes := []diagnostic.Probe{{ID: diagnostic.ProbeIface, Name: "Interface"}}
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface: {ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass, Detail: "up"},
	}
	rep := buildReport(nil, probes, results)
	if !rep.OK {
		t.Error("OK = false, want true")
	}
	if rep.Target != nil {
		t.Errorf("target = %+v, want nil", rep.Target)
	}
	if rep.Summary == "" {
		t.Error("summary empty, want all-clear text")
	}
}

func TestReportJSONContract(t *testing.T) {
	tests := []struct {
		name string
		rep  report.Report
		want string
	}{
		{
			name: "populated",
			rep: report.Report{
				Version: "1.2.3",
				Target:  &report.Target{Host: "example.com", Port: 443, Protocol: "tls+http"},
				Checks: []report.Check{{
					ID:              "target_tcp",
					Name:            "Target TCP",
					Status:          "WARN",
					Cause:           "client_dns_failure",
					Families:        &report.Families{IPv4: "reachable", IPv6: "unreachable"},
					Ms:              46,
					Detail:          "slow",
					Fix:             "check firewall",
					Addrs:           []string{"192.0.2.1"},
					ResolverTargets: []string{"192.0.2.53:53", "[2001:db8::53]:53"},
					SelectedIP:      "192.0.2.1",
					Source:          "192.0.2.2",
					Iface:           "eth0",
					Network:         "office",
					Portal:          &report.Portal{RedirectURL: "https://portal.example/signin"},
					Attempts: []report.Attempt{
						{IP: "192.0.2.1", Ms: 12},
						{IP: "192.0.2.3", Ms: 34, Err: "timeout"},
					},
				}},
				Summary:     "degraded",
				Verdict:     "degraded",
				FailedStage: "tls",
				OK:          true,
			},
			want: `{"version":"1.2.3","target":{"host":"example.com","port":443,"protocol":"tls+http"},"checks":[{"id":"target_tcp","name":"Target TCP","status":"WARN","cause":"client_dns_failure","address_families":{"ipv4":"reachable","ipv6":"unreachable"},"ms":46,"detail":"slow","fix":"check firewall","addrs":["192.0.2.1"],"resolver_targets":["192.0.2.53:53","[2001:db8::53]:53"],"selected_ip":"192.0.2.1","source":"192.0.2.2","iface":"eth0","network":"office","portal":{"redirect_url":"https://portal.example/signin"},"attempts":[{"ip":"192.0.2.1","ms":12},{"ip":"192.0.2.3","ms":34,"error":"timeout"}]}],"summary":"degraded","verdict":"degraded","failed_stage":"tls","ok":true}`,
		},
		{
			// Findings serialize between failed_stage and ok, and an empty
			// evidence list stays absent rather than becoming []. Typed causal
			// evidence is additive beside the original row-id projection, and
			// so is confidence, which sits after focus and stays absent on a
			// finding that carries no assessment.
			name: "findings",
			rep: report.Report{
				Checks:  []report.Check{{}},
				Summary: "cert expired",
				Verdict: "service",
				Findings: []report.Finding{{
					ID: "tls_certificate_expired", Focus: "tls", Confidence: "high",
					Evidence: []string{"tls", "target_tcp"},
					CausalEvidence: []report.CausalEvidence{
						{Kind: "support", Check: "tls", Observation: "cause"},
						{Kind: "ruled_out", Check: "target_tcp", Observation: "status_pass", Candidate: "tls_tcp_unreachable"},
					},
				}, {ID: "quic_unavailable"}},
			},
			want: `{"version":"","target":null,"checks":[{"id":"","name":"","status":"","ms":0,"detail":""}],"summary":"cert expired","verdict":"service","findings":[{"id":"tls_certificate_expired","focus":"tls","confidence":"high","evidence":["tls","target_tcp"],"causal_evidence":[{"kind":"support","check":"tls","observation":"cause"},{"kind":"ruled_out","check":"target_tcp","observation":"status_pass","candidate":"tls_tcp_unreachable"}]},{"id":"quic_unavailable"}],"ok":false}`,
		},
		{
			// Remediation is additive: it serializes inside its finding, after
			// the fields findings have always carried, and every optional part
			// of it stays absent rather than becoming an empty value.
			name: "finding with remediation",
			rep: report.Report{
				Checks:  []report.Check{{}},
				Summary: "no default route",
				Verdict: "network",
				Findings: []report.Finding{{
					ID:    "offline",
					Focus: "internet_tcp",
					Remediation: &report.Remediation{
						ID:      "restore_default_route",
						Action:  "Restore a default route",
						Why:     "nothing leads off this network",
						Steps:   []string{"renew the lease"},
						Command: []string{"ip", "route"},
						Expect:  "a default route",
					},
				}, {ID: "quic_unavailable", Remediation: &report.Remediation{ID: "expect_tcp_fallback", Action: "expect TCP"}}},
			},
			want: `{"version":"","target":null,"checks":[{"id":"","name":"","status":"","ms":0,"detail":""}],"summary":"no default route","verdict":"network","findings":[{"id":"offline","focus":"internet_tcp","remediation":{"id":"restore_default_route","action":"Restore a default route","why":"nothing leads off this network","steps":["renew the lease"],"command":["ip","route"],"expect":"a default route"}},{"id":"quic_unavailable","remediation":{"id":"expect_tcp_fallback","action":"expect TCP"}}],"ok":false}`,
		},
		{
			// Routes are additive and serialize last on a check row. A metric
			// that was read and one that was not are different things: the
			// pointer keeps 0 from being written as absence, and absence from
			// being written as 0.
			name: "routes",
			rep: report.Report{
				Checks: []report.Check{{
					ID: "target_tcp",
					Routes: []report.Route{
						{
							Destination: "198.51.100.7", Family: "ipv4", Interface: "wg0", Source: "10.20.0.2",
							Prefix: "10.20.0.0/16", Metric: new(int), Table: "table 51820", InterfaceMTU: 1420,
							Tunnel: "tunnel", TunnelKind: "wireguard", Reason: "more_specific_than_default",
							Competing: []report.CompetingRoute{{Interface: "wlan0", Metric: 600}},
						},
						{Destination: "203.0.113.9", Family: "ipv4", Unreachable: true},
					},
				}},
			},
			want: `{"version":"","target":null,"checks":[{"id":"target_tcp","name":"","status":"","ms":0,"detail":"","routes":[{"destination":"198.51.100.7","family":"ipv4","interface":"wg0","source":"10.20.0.2","prefix":"10.20.0.0/16","metric":0,"table":"table 51820","interface_mtu":1420,"tunnel":"tunnel","tunnel_kind":"wireguard","reason":"more_specific_than_default","competing":[{"interface":"wlan0","metric":600}]},{"destination":"203.0.113.9","family":"ipv4","unreachable":true}]}],"summary":"","verdict":"","ok":false}`,
		},
		{
			name: "empty",
			rep:  report.Report{Checks: []report.Check{{}}},
			want: `{"version":"","target":null,"checks":[{"id":"","name":"","status":"","ms":0,"detail":""}],"summary":"","verdict":"","ok":false}`,
		},
		{
			name: "portal without redirect",
			rep:  report.Report{Checks: []report.Check{{Portal: &report.Portal{}}}},
			want: `{"version":"","target":null,"checks":[{"id":"","name":"","status":"","ms":0,"detail":"","portal":{}}],"summary":"","verdict":"","ok":false}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.rep)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("JSON = %s\nwant   %s", got, tt.want)
			}
		})
	}
}

// The TUI renders to stdout, so without a terminal there it has nowhere to
// draw. Bubble Tea would fail on its own with a /dev/tty message and exit 1,
// which callers cannot tell apart from a failed diagnosis; the guard names the
// supported non-interactive path and exits 2 instead.
func TestRunRejectsInteractiveWithoutTerminalStdout(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		t.Error("runAll called; the guard must reject before any probe runs")
		return nil
	}
	const want = "netdoc: stdout is not a terminal; use --json for non-interactive output\n"
	for _, args := range [][]string{nil, {"example.com"}, {"-toolbox"}, {"-watch"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Errorf("run(%v) = %d, want 2 (environment problem, not a failed diagnosis)", args, code)
			}
			if stderr.String() != want {
				t.Errorf("stderr = %q, want %q", stderr.String(), want)
			}
			if strings.Contains(stderr.String(), "/dev/tty") {
				t.Errorf("stderr = %q, want netdoc's own error instead of Bubble Tea's", stderr.String())
			}
			if stdout.Len() > 0 {
				t.Errorf("stdout = %q, want nothing", stdout.String())
			}
		})
	}
}

// Only stdout decides, and only through the descriptor: a real terminal is
// accepted so interactive startup still reaches the TUI, while a pipe, a file,
// and a writer with no descriptor at all are not terminals.
func TestStdoutIsTerminal(t *testing.T) {
	orig := termIsTerminal
	t.Cleanup(func() { termIsTerminal = orig })

	termIsTerminal = func(uintptr) bool { return true }
	if !stdoutIsTerminal(os.Stdout) {
		t.Error("stdoutIsTerminal(terminal) = false, want true: interactive startup must not be rejected")
	}
	if stdoutIsTerminal(&bytes.Buffer{}) {
		t.Error("stdoutIsTerminal(no file descriptor) = true, want false")
	}

	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	termIsTerminal = func(uintptr) bool { return false }
	if stdoutIsTerminal(f) {
		t.Error("stdoutIsTerminal(redirected file) = true, want false")
	}
}

// -json is the supported non-interactive path, so it has to survive the
// redirect that the TUI guard rejects: a real file as stdout, still exit 0 with
// a parseable report in it.
func TestRunJSONAllowedWithRedirectedStdout(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
		}
		return results
	}
	f, err := os.CreateTemp(t.TempDir(), "report")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close() //nolint:errcheck

	var stderr bytes.Buffer
	if code := run([]string{"-json", "-check", "iface"}, f, &stderr); code != 0 {
		t.Fatalf("run(-json) = %d, want 0; stderr: %s", code, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("stderr = %q, want nothing", stderr.String())
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	if !rep.OK {
		t.Errorf("ok = false, want true with every check passing")
	}
}

// The report's diagnostic fields all come from one interpretation, so a
// finding cannot describe a different run from the summary printed beside it.
// This checks the JSON the flag actually emits against the engine's own answer
// rather than against a copy of it.
func TestBuildReportFindingsComeFromTheDiagnosis(t *testing.T) {
	target := &diagnostic.Target{Host: "example.com", Port: 443, Proto: diagnostic.ProtoTLSHTTP}
	probes := []diagnostic.Probe{
		{ID: diagnostic.ProbeIface, Name: "Interface"},
		{ID: diagnostic.ProbeInternet, Name: "Internet (TCP egress)"},
		{ID: diagnostic.ProbeDNS, Name: "DNS example.com"},
		{ID: diagnostic.ProbeTargetTCP, Name: "TCP example.com:443"},
		{ID: diagnostic.ProbeTLS, Name: "TLS example.com"},
	}
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface:     {Status: diagnostic.StatusPass},
		diagnostic.ProbeInternet:  {Status: diagnostic.StatusPass},
		diagnostic.ProbeDNS:       {Status: diagnostic.StatusPass},
		diagnostic.ProbeTargetTCP: {Status: diagnostic.StatusPass},
		diagnostic.ProbeTLS:       {Status: diagnostic.StatusFail, Cause: diagnostic.TLSCauseHostnameMismatch},
	}
	order := []diagnostic.ProbeID{}
	for _, p := range probes {
		order = append(order, p.ID)
	}
	want := diagnostic.Interpret(target, order, results)

	rep := buildReport(target, probes, results)
	if rep.Summary != want.Summary || rep.Verdict != want.Verdict {
		t.Errorf("summary/verdict = %q/%q, want %q/%q", rep.Summary, rep.Verdict, want.Summary, want.Verdict)
	}
	if len(rep.Findings) != len(want.Findings) {
		t.Fatalf("%d findings, want %d", len(rep.Findings), len(want.Findings))
	}
	for i, f := range want.Findings {
		got := rep.Findings[i]
		if got.ID != string(f.ID) || got.Focus != string(f.Focus) {
			t.Errorf("finding %d = %+v, want id %q focus %q", i, got, f.ID, f.Focus)
		}
		// The report publishes the interpretation's own assessment rather than
		// deciding one here, so a rule change reaches automation and the app
		// together.
		if got.Confidence != string(f.Confidence) || got.Confidence == "" {
			t.Errorf("finding %d confidence = %q, want %q", i, got.Confidence, f.Confidence)
		}
		rows := f.EvidenceRows()
		if len(got.Evidence) != len(rows) {
			t.Fatalf("finding %d evidence = %v, want %v", i, got.Evidence, rows)
		}
		for j, id := range rows {
			if got.Evidence[j] != string(id) {
				t.Errorf("finding %d evidence[%d] = %q, want %q", i, j, got.Evidence[j], id)
			}
		}
		if len(got.CausalEvidence) != len(f.Evidence) {
			t.Fatalf("finding %d causal evidence = %v, want %v", i, got.CausalEvidence, f.Evidence)
		}
		for j, evidence := range f.Evidence {
			gotEvidence := got.CausalEvidence[j]
			if gotEvidence.Kind != string(evidence.Kind) || gotEvidence.Check != string(evidence.Check) ||
				gotEvidence.Observation != string(evidence.Observation) || gotEvidence.Candidate != string(evidence.Candidate) ||
				gotEvidence.Reason != string(evidence.Reason) {
				t.Errorf("finding %d causal evidence[%d] = %+v, want %+v", i, j, gotEvidence, evidence)
			}
		}
	}
	// The blamed row is where the remedy lives, so the report must carry a
	// check with that id rather than a fix copied into the finding.
	if len(rep.Findings) > 0 {
		found := false
		for _, c := range rep.Checks {
			found = found || c.ID == rep.Findings[0].Focus
		}
		if !found {
			t.Errorf("finding blames %q, which is not a check in the report", rep.Findings[0].Focus)
		}
	}

	// The advice hangs off the finding and comes from the same interpretation,
	// so automation reads what the app shows instead of parsing fix.
	wantRem, ok := diagnostic.Remediate(want, results, runtime.GOOS)
	if !ok {
		t.Fatal("a hostname mismatch should reach a remediation")
	}
	got := rep.Findings[0].Remediation
	if got == nil {
		t.Fatal("the finding carries no remediation")
	}
	if got.ID != string(wantRem.ID) || got.Action != wantRem.Action || got.Why != wantRem.Why ||
		got.Expect != wantRem.Expect || !slices.Equal(got.Steps, wantRem.Steps) || !slices.Equal(got.Command, wantRem.Command) {
		t.Errorf("remediation = %+v, want %+v", got, wantRem)
	}
	if got.ID != "match_certificate_name" {
		t.Errorf("a hostname mismatch got advice %q", got.ID)
	}

	// A run with nothing to conclude keeps the report it has always emitted:
	// no findings key at all.
	for id := range results {
		results[id] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	}
	blob, err := json.Marshal(buildReport(target, probes, results))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "findings") || strings.Contains(string(blob), "remediation") {
		t.Errorf("a healthy run emitted a findings or remediation key: %s", blob)
	}
}

// --save is the whole CLI surface for the .ndoc artifact, so these cover what
// it writes, what it refuses, and what it must leave alone.

// stubPassingRun makes every probe in the built DAG report a measured pass, so
// -save tests never touch the network.
func stubPassingRun(t *testing.T) {
	t.Helper()
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Dur: 2 * time.Millisecond}
		}
		return results
	}
}

// fixedNow pins the snapshot timestamp so a test can assert on it.
func fixedNow(t *testing.T, stamp string) {
	t.Helper()
	when, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		t.Fatal(err)
	}
	orig := timeNow
	t.Cleanup(func() { timeNow = orig })
	timeNow = func() time.Time { return when }
}

func TestRunSaveWritesSnapshot(t *testing.T) {
	stubPassingRun(t)
	fixedNow(t, "2026-03-04T05:06:07Z")
	path := filepath.Join(t.TempDir(), "incident.ndoc")

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--save", path, "--timeout", "3s", "example.com:8443"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	// Without -json the run says nothing on stdout: the artifact is the output.
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}

	// #nosec G304 -- path is this test's temporary snapshot file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	s, err := snapshot.Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if s.Schema != snapshot.Schema {
		t.Errorf("schema = %q", s.Schema)
	}
	if s.CreatedAt != "2026-03-04T05:06:07Z" {
		t.Errorf("created_at = %q", s.CreatedAt)
	}
	if s.Tool.Version != version || s.Tool.OS != runtime.GOOS || s.Tool.Arch != runtime.GOARCH {
		t.Errorf("tool = %+v", s.Tool)
	}
	if s.Target == nil || s.Target.Host != "example.com" || s.Target.Port != 8443 || !s.Target.PortExplicit {
		t.Errorf("target = %+v", s.Target)
	}
	if s.Options.ProbeTimeoutMs != 3000 || s.Options.PublicDNS != diagnostic.DefaultPublicDNS {
		t.Errorf("options = %+v", s.Options)
	}
	if len(s.Checks) == 0 || !s.OK {
		t.Errorf("snapshot = %d checks, ok=%v", len(s.Checks), s.OK)
	}
	if s.Redaction != nil {
		t.Errorf("ordinary -save snapshot has redaction metadata: %+v", s.Redaction)
	}
}

func TestRunSupportWritesSanitizedSnapshot(t *testing.T) {
	stubPassingRun(t)
	fixedNow(t, "2026-03-04T05:06:07Z")
	path := filepath.Join(t.TempDir(), "support.ndoc")

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--support", path, "unique-support-target.example"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Sanitized support snapshot written") {
		t.Errorf("stderr = %q, want sanitized confirmation", stderr.String())
	}
	// #nosec G304 -- path is this test's temporary support snapshot.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "unique-support-target.example") {
		t.Fatalf("support snapshot leaked the target hostname:\n%s", data)
	}
	s, err := snapshot.Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if s.Redaction == nil || !s.Redaction.Sanitized || s.Redaction.Policy != snapshot.SupportRedactionPolicy {
		t.Errorf("redaction = %+v", s.Redaction)
	}
	if s.Target == nil || s.Target.Host == "" || s.Target.Host == "unique-support-target.example" {
		t.Errorf("target = %+v, want a pseudonymized target", s.Target)
	}
}

// The probe selection is what makes two snapshots comparable or not, so it is
// recorded in the order it was given rather than as an unordered set.
func TestRunSaveRecordsProbeSelection(t *testing.T) {
	stubPassingRun(t)
	fixedNow(t, "2026-03-04T05:06:07Z")
	path := filepath.Join(t.TempDir(), "selected.ndoc")

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--save", path, "--skip", "quic_udp_443,proxy_connect", "--public-dns", ""}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	// #nosec G304 -- path is this test's temporary snapshot file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := []string{"quic_udp_443", "proxy_connect"}
	if !slices.Equal(s.Options.Skip, want) {
		t.Errorf("skip = %v, want %v", s.Options.Skip, want)
	}
	if len(s.Options.Check) != 0 {
		t.Errorf("check = %v, want nothing recorded", s.Options.Check)
	}
	if s.Options.PublicDNS != "" {
		t.Errorf("public_dns = %q, want the empty opt-out preserved", s.Options.PublicDNS)
	}
	if s.Target != nil {
		t.Errorf("target = %+v, want null for a generic run", s.Target)
	}
	for _, c := range s.Checks {
		if c.ID == "quic_udp_443" || c.ID == "proxy_connect" || c.ID == "dns_public" {
			t.Errorf("%s is in the snapshot, but the run left it out", c.ID)
		}
	}
}

// -save and -json are independent: asking for both gets the report on stdout
// and the artifact on disk, and the report is byte-identical to a -json run
// that saved nothing.
func TestRunSaveLeavesJSONReportUnchanged(t *testing.T) {
	stubPassingRun(t)
	fixedNow(t, "2026-03-04T05:06:07Z")

	var plain, stderr bytes.Buffer
	if got := run([]string{"--json", "example.com"}, &plain, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	path := filepath.Join(t.TempDir(), "both.ndoc")
	var withSave bytes.Buffer
	stderr.Reset()
	if got := run([]string{"--json", "--save", path, "example.com"}, &withSave, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if withSave.String() != plain.String() {
		t.Errorf("-save changed the JSON report:\n%s\nwant:\n%s", withSave.String(), plain.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("no snapshot written alongside the report: %v", err)
	}

	supportPath := filepath.Join(t.TempDir(), "support.ndoc")
	var withSupport bytes.Buffer
	stderr.Reset()
	if got := run([]string{"--json", "--support", supportPath, "example.com"}, &withSupport, &stderr); got != 0 {
		t.Fatalf("support exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if withSupport.String() != plain.String() {
		t.Errorf("-support changed the JSON report:\n%s\nwant:\n%s", withSupport.String(), plain.String())
	}
}

// A failing run still saves, and still exits 1: the artifact records the
// diagnosis, it does not change it.
func TestRunSaveKeepsExitCode(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusFail, Dur: time.Millisecond}
		}
		return results
	}
	fixedNow(t, "2026-03-04T05:06:07Z")
	path := filepath.Join(t.TempDir(), "failed.ndoc")

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--save", path, "example.com"}, &stdout, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}
	// #nosec G304 -- path is this test's temporary snapshot file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if s.OK || s.Diagnosis.FailedStage == "" {
		t.Errorf("snapshot = ok:%v failed_stage:%q, want a recorded failure", s.OK, s.Diagnosis.FailedStage)
	}
}

// A destination that cannot exist is an argument error, caught before any
// probe runs rather than after several seconds of network traffic.
func TestRunSaveRejectsMissingDirectoryBeforeProbing(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		t.Error("probes ran for a destination that cannot be written")
		return nil
	}
	path := filepath.Join(t.TempDir(), "no-such-dir", "incident.ndoc")

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--save", path, "example.com"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-save") {
		t.Errorf("stderr = %q, want it to name the flag", stderr.String())
	}
}

// A write that fails only when it is attempted is exit 2 as well: the run
// reached an answer, but the artifact it was for does not exist.
func TestRunSaveWriteFailureExitsTwo(t *testing.T) {
	stubPassingRun(t)
	fixedNow(t, "2026-03-04T05:06:07Z")
	origWrite := snapshotWriteFile
	t.Cleanup(func() { snapshotWriteFile = origWrite })
	snapshotWriteFile = func(string, snapshot.Snapshot) error {
		return errors.New("disk went away")
	}
	path := filepath.Join(t.TempDir(), "doomed.ndoc")

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--json", "--save", path, "example.com"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "disk went away") {
		t.Errorf("stderr = %q, want the write error", stderr.String())
	}
	// The report still reached stdout: a failed save does not swallow the
	// answer the run already produced.
	var rep report.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Errorf("stdout is not the usual report: %v\n%s", err, stdout.String())
	}
}

func TestRunSaveRejectsIncompatibleFlags(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		t.Error("probes ran for a rejected flag combination")
		return nil
	}
	path := filepath.Join(t.TempDir(), "rejected.ndoc")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"watch", []string{"--save", path, "--watch", "example.com"}, "-save and -watch"},
		{"toolbox", []string{"--save", path, "--toolbox"}, "-save and -toolbox"},
		{"peer mode", []string{"--save", path, "--peer-connect"}, "-save cannot be combined with peer mode"},
		{"support and save", []string{"--save", path, "--support", path, "example.com"}, "-save and -support"},
		{"support watch", []string{"--support", path, "--watch", "example.com"}, "-support and -watch"},
		{"support toolbox", []string{"--support", path, "--toolbox"}, "-support and -toolbox"},
		{"support peer mode", []string{"--support", path, "--peer-connect"}, "-support cannot be combined with peer mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to mention %q", stderr.String(), tt.want)
			}
			if _, err := os.Stat(path); err == nil {
				t.Error("a rejected run still wrote a snapshot")
			}
		})
	}
}

// Without -save nothing writes a file, and the ordinary modes are untouched.
func TestNoSaveWritesNothing(t *testing.T) {
	stubPassingRun(t)
	dir := t.TempDir()
	t.Chdir(dir)

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--json", "example.com"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a plain -json run left %d files behind", len(entries))
	}
}

// The --iface binding is recorded as an option, because a run bound to a VPN
// tunnel and a run on the default route are not comparable without knowing it.
func TestRunSaveRecordsSourceBinding(t *testing.T) {
	stubPassingRun(t)
	fixedNow(t, "2026-03-04T05:06:07Z")
	path := filepath.Join(t.TempDir(), "bound.ndoc")

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--save", path, "--iface", "127.0.0.1"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	// #nosec G304 -- path is this test's temporary snapshot file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if s.Options.Source == nil || s.Options.Source.IPv4 != "127.0.0.1" {
		t.Fatalf("source = %+v, want the exact IPv4 binding", s.Options.Source)
	}
	// An exact-IP selection names no interface, and must not invent one.
	if s.Options.Source.Interface != "" {
		t.Errorf("interface = %q, want empty for an address selection", s.Options.Source.Interface)
	}

	// And an unbound run records no source at all, rather than an empty object.
	plain := filepath.Join(t.TempDir(), "unbound.ndoc")
	stdout.Reset()
	stderr.Reset()
	if got := run([]string{"--save", plain}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	// #nosec G304 -- plain is this test's temporary snapshot file.
	data, err = os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"source"`) {
		t.Errorf("an unbound run recorded a source binding:\n%s", data)
	}
}

// writeSnapshotFile saves a snapshot for the compare tests to read back through
// the real CLI, so the artifact under test is one Encode published.
func writeSnapshotFile(t *testing.T, dir, name string, s snapshot.Snapshot) string {
	t.Helper()
	path := filepath.Join(dir, name+snapshot.Extension)
	if err := snapshot.WriteFile(path, s); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// comparableSnapshot is one finished run, written by hand so the compare tests
// depend on the format rather than on which probes the current build runs.
func comparableSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		Schema:    snapshot.Schema,
		CreatedAt: "2026-03-04T05:06:07Z",
		Tool:      snapshot.Tool{Version: "1.2.3", OS: "linux", Arch: "amd64"},
		Target: &snapshot.Target{
			Raw: "example.com", Host: "example.com", Port: 443, Protocol: "tls+http",
		},
		Options: snapshot.Options{ProbeTimeoutMs: 4000, PublicDNS: "8.8.8.8"},
		Checks: []snapshot.Check{
			{ID: "iface", Name: "Interface", Status: snapshot.StatusPass, Ran: true, DurationMs: 2,
				Observed: &snapshot.Observed{Interface: "eth0", SourceIP: "192.0.2.10"}},
			{ID: "dns", Name: "DNS example.com", Deps: []string{"iface"},
				Status: snapshot.StatusPass, Ran: true, DurationMs: 12,
				Observed: &snapshot.Observed{Addresses: []string{"93.184.216.34"}}},
		},
		Diagnosis: snapshot.Diagnosis{Verdict: "ok", Summary: "everything worked"},
		OK:        true,
	}
}

// --two-sided reads the same two artifacts as --compare and answers the other
// question about them: not what moved, but which machine a failure belongs to.
func TestRunTwoSidedPlacesTheFailure(t *testing.T) {
	dir := t.TempDir()
	here := comparableSnapshot()
	here.Checks[1].Status = snapshot.StatusFail
	here.Diagnosis.Verdict, here.OK = "dns", false
	there := comparableSnapshot()
	therePath := writeSnapshotFile(t, dir, "there", there)
	herePath := writeSnapshotFile(t, dir, "here", here)

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--two-sided", herePath, therePath}, &stdout, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"Network Doctor two-sided diagnosis", "Failure placed on: side A", "side A only"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout is missing %q:\n%s", want, out)
		}
	}
}

// Nothing failing on either machine is the healthy answer and spends the
// ordinary success code, not --compare's "the two files agree".
func TestRunTwoSidedExitsZeroWhenNothingFailed(t *testing.T) {
	dir := t.TempDir()
	path := writeSnapshotFile(t, dir, "run", comparableSnapshot())
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--two-sided", path, path}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "neither side") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestRunTwoSidedJSON(t *testing.T) {
	dir := t.TempDir()
	here := comparableSnapshot()
	here.Checks[1].Status = snapshot.StatusFail
	here.OK = false
	herePath := writeSnapshotFile(t, dir, "here", here)
	therePath := writeSnapshotFile(t, dir, "there", comparableSnapshot())

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--two-sided", "--json", herePath, therePath}, &stdout, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}
	var doc struct {
		Schema    string `json:"schema"`
		Diagnosis struct {
			ID   string `json:"id"`
			Side string `json:"side"`
		} `json:"diagnosis"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout.String())
	}
	if doc.Schema != compare.TwoSidedSchema {
		t.Errorf("schema = %q, want %q", doc.Schema, compare.TwoSidedSchema)
	}
	if doc.Diagnosis.Side != compare.SideA || doc.Diagnosis.ID != compare.TwoSidedOneSideFails {
		t.Errorf("diagnosis = %+v", doc.Diagnosis)
	}
}

// The one rule --two-sided has that --compare does not: two endpoints seen once
// each cannot be read as one endpoint seen twice, and the refusal names both.
func TestRunTwoSidedRefusesDifferentTargets(t *testing.T) {
	dir := t.TempDir()
	other := comparableSnapshot()
	other.Target.Host = "other.example"
	herePath := writeSnapshotFile(t, dir, "here", comparableSnapshot())
	otherPath := writeSnapshotFile(t, dir, "other", other)

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--two-sided", herePath, otherPath}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "other.example") || !strings.Contains(stderr.String(), "example.com") {
		t.Errorf("stderr does not name both endpoints: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("a refusal wrote to stdout: %q", stdout.String())
	}
}

func TestRunTwoSidedArgumentErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeSnapshotFile(t, dir, "run", comparableSnapshot())
	for _, args := range [][]string{
		{"--two-sided"},
		{"--two-sided", path},
		{"--two-sided", path, path, path},
		{"--two-sided", filepath.Join(dir, "missing.ndoc"), path},
	} {
		t.Run(strings.Join(args[1:], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(args, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
			}
		})
	}
}

// A reading of two finished runs performs none, so every flag that describes a
// run netdoc would perform is refused, and so is the other reading.
func TestRunTwoSidedRejectsRunFlagsAndCompare(t *testing.T) {
	dir := t.TempDir()
	path := writeSnapshotFile(t, dir, "run", comparableSnapshot())
	for _, args := range [][]string{
		{"--toolbox"}, {"--watch"}, {"--save", filepath.Join(dir, "out.ndoc")},
		{"--support", filepath.Join(dir, "out.ndoc")}, {"--check", "dns"}, {"--skip", "dns"},
		{"--iface", "lo"}, {"--public-dns", "9.9.9.9"}, {"--no-history"}, {"--keys", "vim"},
		{"--timeout", "1s"}, {"--peer-connect"}, {"--peer-listen", "127.0.0.1:0"},
		{"--compare"},
	} {
		t.Run(args[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			full := append([]string{"--two-sided"}, args...)
			full = append(full, path, path)
			if got := run(full, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
			}
			if !strings.Contains(stderr.String(), "cannot be combined") {
				t.Errorf("stderr = %q", stderr.String())
			}
		})
	}
	// -json is the one flag that does apply, and it is not refused.
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--two-sided", "--json", path, path}, &stdout, &stderr); got != 0 {
		t.Fatalf("--json exit = %d, want 0; stderr: %s", got, stderr.String())
	}
}

// Peer mode is the other two-machine answer, and it runs probes on two live
// machines. Naming a reading of saved artifacts alongside it is a request for
// two different commands at once, and it is refused rather than silently
// resolved to one of them.
func TestPeerModeAndTwoSidedCannotBeCombined(t *testing.T) {
	for _, args := range [][]string{
		{"--peer-connect", "--two-sided"},
		{"--peer-listen", "127.0.0.1:0", "--two-sided"},
	} {
		t.Run(args[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(args, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
			}
			if !strings.Contains(stderr.String(), "cannot be combined") {
				t.Errorf("stderr = %q", stderr.String())
			}
		})
	}
}

// The reading opens no socket, exactly as --compare does not: every value it
// reports came out of the two files.
func TestRunTwoSidedRunsNoProbes(t *testing.T) {
	dir := t.TempDir()
	path := writeSnapshotFile(t, dir, "run", comparableSnapshot())
	restore := runAll
	runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		t.Fatal("--two-sided ran the probe DAG")
		return nil
	}
	defer func() { runAll = restore }()
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--two-sided", path, path}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
}

func TestRunCompareReportsWhatChanged(t *testing.T) {
	dir := t.TempDir()
	before := comparableSnapshot()
	after := comparableSnapshot()
	after.CreatedAt = "2026-03-05T05:06:07Z"
	after.Checks[1].Status = snapshot.StatusFail
	after.Checks[0].Observed.Interface = "wg0"
	after.Diagnosis.Verdict = "dns"
	after.OK = false

	beforePath := writeSnapshotFile(t, dir, "before", before)
	afterPath := writeSnapshotFile(t, dir, "after", after)

	var stdout, stderr bytes.Buffer
	// Differences found, so the exit code says so.
	if got := run([]string{"--compare", beforePath, afterPath}, &stdout, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	for _, want := range []string{
		"Network Doctor snapshot comparison",
		"dns changed from PASS to FAIL (worse)",
		"iface interface changed from eth0 to wg0",
		"verdict changed from ok to dns",
		"overall result changed from ok to not ok",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, stdout.String())
		}
	}
	// The timestamps differ and are reported as context, never as a change.
	if strings.Contains(stdout.String(), "created_at changed") {
		t.Errorf("the capture time was reported as a difference:\n%s", stdout.String())
	}
}

// Two artifacts describing the same state exit 0, which is what a script asks
// this command in the first place: did anything move.
func TestRunCompareIdenticalSnapshotsExitZero(t *testing.T) {
	dir := t.TempDir()
	path := writeSnapshotFile(t, dir, "run", comparableSnapshot())

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--compare", path, path}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No meaningful differences.") {
		t.Errorf("output does not say the runs match:\n%s", stdout.String())
	}
}

func TestRunCompareJSON(t *testing.T) {
	dir := t.TempDir()
	before := comparableSnapshot()
	after := comparableSnapshot()
	after.Checks[1].Status = snapshot.StatusFail
	after.OK = false

	beforePath := writeSnapshotFile(t, dir, "before", before)
	afterPath := writeSnapshotFile(t, dir, "after", after)

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--compare", "--json", beforePath, afterPath}, &stdout, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}
	var got struct {
		Schema  string `json:"schema"`
		Changes []struct {
			Path      string `json:"path"`
			Kind      string `json:"kind"`
			Before    string `json:"before"`
			After     string `json:"after"`
			Direction string `json:"direction"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode comparison: %v\n%s", err, stdout.String())
	}
	if got.Schema != compare.Schema {
		t.Errorf("schema = %q, want %q", got.Schema, compare.Schema)
	}
	var found bool
	for _, change := range got.Changes {
		if change.Path == "checks.dns.status" {
			found = true
			if change.Before != "PASS" || change.After != "FAIL" || change.Direction != "worse" {
				t.Errorf("dns status change = %+v", change)
			}
		}
	}
	if !found {
		t.Errorf("no dns status change in %s", stdout.String())
	}
	// The machine form carries no rendered table.
	if strings.Contains(stdout.String(), "Network Doctor snapshot comparison") {
		t.Error("the JSON output carries the human report")
	}
}

// A comparison never touches the network, so nothing here may reach the DAG.
func TestRunCompareRunsNoProbes(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		t.Fatal("compare mode ran the probe DAG")
		return nil
	}
	dir := t.TempDir()
	path := writeSnapshotFile(t, dir, "run", comparableSnapshot())
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--compare", path, path}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
}

func TestRunCompareArgumentErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeSnapshotFile(t, dir, "run", comparableSnapshot())
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no files", []string{"--compare"}, "needs two snapshot files"},
		{"one file", []string{"--compare", path}, "needs two snapshot files"},
		{"three files", []string{"--compare", path, path, path}, "unexpected arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2", got)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to mention %q", stderr.String(), tt.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

// Every flag that describes a run netdoc would perform is refused: a comparison
// performs none, and accepting one would suggest it applied to something.
func TestRunCompareRejectsRunFlags(t *testing.T) {
	dir := t.TempDir()
	path := writeSnapshotFile(t, dir, "run", comparableSnapshot())
	for _, args := range [][]string{
		{"--toolbox"}, {"--watch"}, {"--save", filepath.Join(dir, "out.ndoc")},
		{"--check", "dns"}, {"--skip", "dns"}, {"--iface", "lo"},
		{"--public-dns", "9.9.9.9"}, {"--no-history"}, {"--keys", "vim"},
		{"--timeout", "1s"}, {"--peer-connect"}, {"--peer-listen", "127.0.0.1:0"},
	} {
		t.Run(args[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			full := append([]string{"--compare"}, args...)
			full = append(full, path, path)
			if got := run(full, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
			}
			if !strings.Contains(stderr.String(), "cannot be combined with -compare") {
				t.Errorf("stderr = %q", stderr.String())
			}
		})
	}
	// -json is the one flag that does apply, and it is not refused.
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--compare", "--json", path, path}, &stdout, &stderr); got != 0 {
		t.Fatalf("--json exit = %d, want 0; stderr: %s", got, stderr.String())
	}
}

// Which of the two files is unreadable is the useful half of the message.
func TestRunCompareRejectsUnusableArtifacts(t *testing.T) {
	dir := t.TempDir()
	good := writeSnapshotFile(t, dir, "good", comparableSnapshot())

	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	garbage := write("garbage.ndoc", "not json at all")
	future := write("future.ndoc", `{"schema":"netdoc.snapshot.v2","checks":[]}`)
	unlabelled := write("unlabelled.ndoc", `{"schema":"`+snapshot.Schema+`","checks":[{"id":"iface"}]}`)
	missing := filepath.Join(dir, "nothing-here.ndoc")

	tests := []struct {
		name, path, want string
	}{
		{"malformed", garbage, "not a Network Doctor snapshot"},
		{"a future schema", future, "unsupported snapshot schema"},
		{"a row with no status", unlabelled, "has no status"},
		{"a file that is not there", missing, "nothing-here"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run([]string{"--compare", good, tt.path}, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to mention %q", stderr.String(), tt.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			// The bad file is named, since two were given.
			if tt.name != "a file that is not there" && !strings.Contains(stderr.String(), filepath.Base(tt.path)) {
				t.Errorf("stderr = %q, want it to name the file", stderr.String())
			}
		})
	}
}

// Comparing two runs of different targets is allowed, because a snapshot keeps
// the typed spelling next to the parsed host exactly so this question can be
// answered. It is not allowed to be quiet about it.
func TestRunCompareDifferentTargetsIsLoudNotFatal(t *testing.T) {
	dir := t.TempDir()
	before := comparableSnapshot()
	after := comparableSnapshot()
	after.Target = &snapshot.Target{Raw: "github.com", Host: "github.com", Port: 443, Protocol: "tls+http"}

	beforePath := writeSnapshotFile(t, dir, "before", before)
	afterPath := writeSnapshotFile(t, dir, "after", after)

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--compare", beforePath, afterPath}, &stdout, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "observed different targets") {
		t.Errorf("output does not warn about the targets:\n%s", stdout.String())
	}
}

// A hand-edited snapshot reaches a terminal through this path, so the argument
// and the artifact's own text are both sanitized on the way out.
func TestRunCompareKeepsHostileTextInert(t *testing.T) {
	dir := t.TempDir()
	before := comparableSnapshot()
	after := comparableSnapshot()
	after.Target.Host = "example.com\x1b[2Jwiped"
	beforePath := writeSnapshotFile(t, dir, "before", before)
	afterPath := writeSnapshotFile(t, dir, "after", after)

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--compare", beforePath, afterPath}, &stdout, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}
	if strings.ContainsAny(stdout.String(), "\x1b\x07") {
		t.Errorf("escape bytes reached stdout: %q", stdout.String())
	}
}

// A comparison is headless: it renders no terminal UI, so it works on a pipe.
func TestRunCompareWorksWithRedirectedStdout(t *testing.T) {
	origTerm := termIsTerminal
	t.Cleanup(func() { termIsTerminal = origTerm })
	termIsTerminal = func(uintptr) bool { return false }

	dir := t.TempDir()
	path := writeSnapshotFile(t, dir, "run", comparableSnapshot())
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--compare", path, path}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
}

// The artifact end of the same distinction. options.public_dns has held a
// resolver address or the empty opt-out since v1 and still does, so an older
// reader is not handed a word where it expects an address; whether netdoc chose
// that resolver is the added field beside it. A saved run is the only place
// this is durable, which makes it the place worth pinning.
func TestRunSaveRecordsWhetherThePublicResolverWasChosen(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantDNS  string
		wantAuto bool
	}{
		{"omitted", nil, diagnostic.DefaultPublicDNS, true},
		{"the default address, typed", []string{"--public-dns", "8.8.8.8"}, "8.8.8.8", false},
		{"another resolver", []string{"--public-dns", "9.9.9.9"}, "9.9.9.9", false},
		{"disabled", []string{"--public-dns="}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubPassingRun(t)
			path := filepath.Join(t.TempDir(), "run.ndoc")
			var stdout, stderr bytes.Buffer
			args := append([]string{"--save", path}, tc.args...)
			if got := run(append(args, "example.com"), &stdout, &stderr); got != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
			}
			// #nosec G304 -- path is this test's temporary snapshot file.
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read snapshot: %v", err)
			}
			s, err := snapshot.Decode(data)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if s.Schema != snapshot.Schema {
				t.Errorf("schema = %q, want %q: an added option is not a new format", s.Schema, snapshot.Schema)
			}
			if s.Options.PublicDNS != tc.wantDNS || s.Options.PublicDNSAuto != tc.wantAuto {
				t.Errorf("options = %+v, want %q auto=%v", s.Options, tc.wantDNS, tc.wantAuto)
			}
			if got := s.Options.PublicDNS; got != "" && net.ParseIP(got) == nil {
				t.Errorf("options.public_dns = %q, want an address or empty", got)
			}
		})
	}
}
