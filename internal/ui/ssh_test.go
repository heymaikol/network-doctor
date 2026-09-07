package ui

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// resolvedSSHCommand exercises the pure argv builder, the off-loop resolver,
// and the final askpass handoff without involving the Bubble Tea model.
func resolvedSSHCommand(t *testing.T, host, login, key, password, self, goos string) (args, env []string, err error) {
	t.Helper()
	args, err = sshCommand(host, login, key)
	if err != nil || password == "" || self == "" {
		return args, nil, err
	}
	msg := resolveSSH(1, args, goos)().(sshResolvedMsg)
	if msg.err != nil {
		return nil, nil, msg.err
	}
	args, env = sshAskpass(args, password, self, msg.host, msg.proxied)
	return args, env, nil
}

func sshFormForTest(t *testing.T, host string) model {
	t.Helper()
	old := toolLookPath
	toolLookPath = func(string) (string, error) { return "ssh", nil }
	// On Windows the resolver checks the client before it reads any config, so
	// without this stub these model tests would resolve against whichever ssh
	// the host happens to have on PATH and short-circuit before the stubbed
	// config read they are actually about.
	oldVersion := sshVersion
	sshVersion = func() (string, error) { return "OpenSSH_for_Windows_8.6p1, LibreSSL 3.4.3", nil }
	t.Cleanup(func() {
		toolLookPath = old
		sshVersion = oldVersion
	})
	m := asModel(t, must(newModel(mustTarget(t, host), true).Update(keyMsg("S"))))
	if !m.sshPrompt {
		t.Fatal("S did not open the SSH form")
	}
	return m
}

func sshResult(t *testing.T, cmd tea.Cmd) sshResolvedMsg {
	t.Helper()
	if cmd == nil {
		t.Fatal("missing SSH resolver command")
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		if len(batch) == 0 {
			t.Fatal("empty SSH resolver batch")
		}
		msg = batch[0]()
	}
	resolved, ok := msg.(sshResolvedMsg)
	if !ok {
		t.Fatalf("resolver returned %T, want sshResolvedMsg", msg)
	}
	return resolved
}

func TestSSHCommand(t *testing.T) {
	// sshCommand treats the key as opaque argv text and never opens it, so a
	// synthetic nested path stands in for a real one: no home directory to
	// resolve, nothing to skip, and nothing read from disk.
	key := "/home/tester/.ssh/id_ed25519"

	tests := []struct {
		name                          string
		host, login, password, keyArg string
		want                          []string
	}{
		{name: "host only", host: "example.com", want: []string{"example.com"}},
		{name: "login", host: "example.com", login: "alice", want: []string{"-l", "alice", "example.com"}},
		{
			name: "port", host: "example.com:2222", login: "alice",
			want: []string{"-p", "2222", "-l", "alice", "example.com"},
		},
		{
			name: "port 22 is the default", host: "example.com:22", login: "alice",
			want: []string{"-l", "alice", "example.com"},
		},
		{
			// A login is free text: as an operand it would be read as an option,
			// as -l's value it cannot be.
			name: "login starting with a dash stays a login", host: "example.com", login: "-oProxyCommand=touch /tmp/pwned",
			want: []string{"-l", "-oProxyCommand=touch /tmp/pwned", "example.com"},
		},
		{
			name: "chosen key wins over the agent", host: "example.com", keyArg: key,
			want: []string{"-i", key, "-o", "IdentitiesOnly=yes", "example.com"},
		},
		{
			name: "password bounds the prompts", host: "example.com", password: "hunter2",
			want: []string{"-o", "NumberOfPasswordPrompts=1", "example.com"},
		},
	}
	stubSSHEffective(t, "example.com", false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, env, err := resolvedSSHCommand(t, tt.host, tt.login, tt.keyArg, tt.password, "/usr/bin/netdoc", "linux")
			if err != nil {
				t.Fatalf("sshCommand: %v", err)
			}
			if !slices.Equal(args, tt.want) {
				t.Errorf("args = %v, want %v", args, tt.want)
			}
			if tt.password == "" {
				if env != nil {
					t.Error("no password, yet the environment was overridden")
				}
				return
			}
			if !slices.Contains(env, AskpassEnv+"="+tt.password) ||
				!slices.Contains(env, AskpassHostEnv+"=example.com") ||
				!slices.Contains(env, "SSH_ASKPASS=/usr/bin/netdoc") ||
				!slices.Contains(env, "SSH_ASKPASS_REQUIRE=force") {
				t.Errorf("askpass environment incomplete: %v", env)
			}
			// The secret must never reach the command line.
			if slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, tt.password) }) {
				t.Errorf("password leaked into argv: %v", args)
			}
		})
	}
}

func TestSSHDisplayUsesPlatformQuoter(t *testing.T) {
	args := []string{"-i", `C:\Users\O'Brien\.ssh\id key`, "example.com"}
	if shellArgs(args) == psArgs(args) {
		t.Fatal("test argument does not distinguish POSIX and PowerShell quoting")
	}
	for _, goos := range []string{"linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			want := "ssh " + quoterFor(goos)(args)
			if got := sshDisplay(args, goos); got != want {
				t.Errorf("sshDisplay = %q, want %q", got, want)
			}
		})
	}
}

// Without a helper path there is nothing to feed the password to, so ssh must
// be left to ask on the terminal rather than told the prompt count.
func TestSSHCommandWithoutHelper(t *testing.T) {
	args, env, err := resolvedSSHCommand(t, "example.com", "alice", "", "hunter2", "", "linux")
	if err != nil {
		t.Fatalf("sshCommand: %v", err)
	}
	if !slices.Equal(args, []string{"-l", "alice", "example.com"}) {
		t.Errorf("args = %v, want [-l alice example.com]", args)
	}
	if env != nil {
		t.Errorf("env = %v, want nil", env)
	}
}

// This pins only Network Doctor's version gate. The assertion that Win32-
// OpenSSH actually honors forced askpass comes from its Windows source and
// still needs a real Windows client for end-to-end verification.
func TestWindowsForcedAskpassVersion(t *testing.T) {
	tests := []struct {
		version string
		wantErr bool
	}{
		{"OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2", true},
		{"OpenSSH_for_Windows_8.6p1, LibreSSL 3.4.3", false},
		{"OpenSSH_for_Windows_10.0p2, LibreSSL 4.0.0", false},
		{"OpenSSH_for_Windows_11.1p1, LibreSSL 4.1.0", false},
		{"OpenSSH_for_Windows_8.6p, LibreSSL 3.4.3", true},
		{"OpenSSH_9.8p1, OpenSSL 3.0.0", true},
		{"not OpenSSH", true},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if err := windowsForcedAskpass(tt.version); (err != nil) != tt.wantErr {
				t.Errorf("windowsForcedAskpass(%q) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
		})
	}
}

func TestSSHCommandAllowsBlankWindowsPassword(t *testing.T) {
	oldVersion := sshVersion
	sshVersion = func() (string, error) {
		t.Fatal("ssh -V must not run without a password to inject")
		return "", errors.New("unreachable")
	}
	t.Cleanup(func() { sshVersion = oldVersion })

	args, env, err := resolvedSSHCommand(t, "example.com", "alice", "", "", `C:\netdoc.exe`, "windows")
	if err != nil {
		t.Fatalf("sshCommand: %v", err)
	}
	if !slices.Equal(args, []string{"-l", "alice", "example.com"}) {
		t.Errorf("args = %v, want [-l alice example.com]", args)
	}
	if env != nil {
		t.Errorf("env = %v, want nil", env)
	}
}

func TestSSHCommandRejectsUnsupportedWindowsAskpass(t *testing.T) {
	oldVersion := sshVersion
	sshVersion = func() (string, error) {
		return "OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2", nil
	}
	t.Cleanup(func() { sshVersion = oldVersion })

	args, env, err := resolvedSSHCommand(t, "example.com", "alice", "", "hunter2", `C:\netdoc.exe`, "windows")
	if err == nil || !strings.Contains(err.Error(), "password field blank") {
		t.Fatalf("sshCommand error = %v, want the safe blank-field fallback", err)
	}
	if args != nil || env != nil {
		t.Errorf("args = %v, env = %v, want neither handed to ssh", args, env)
	}
}

// stubSSHEffective stands in for the `ssh -G` lookup, keeping the suite off
// the real ssh binary and off whatever the developer's own ~/.ssh/config says
// about example.com.
func stubSSHEffective(t *testing.T, host string, proxied bool) {
	t.Helper()
	old := sshEffective
	sshEffective = func([]string) (string, bool, error) { return host, proxied, nil }
	t.Cleanup(func() { sshEffective = old })
}

// stubSSHEffectiveErr stands in for an `ssh -G` that couldn't answer: no ssh on
// PATH, a config it refused to parse, a Match exec that exited nonzero.
func stubSSHEffectiveErr(t *testing.T, err error) {
	t.Helper()
	old := sshEffective
	sshEffective = func([]string) (string, bool, error) { return "", false, err }
	t.Cleanup(func() { sshEffective = old })
}

// ssh substitutes a Host alias's HostName before it asks for a password, so
// the helper has to be told the name it will actually see, since an alias would
// never match its own prompt, and the legitimate password would be refused.
func TestSSHCommandResolvesTheAlias(t *testing.T) {
	stubSSHEffective(t, "real.example.com", false)
	_, env, err := resolvedSSHCommand(t, "alias", "alice", "", "hunter2", "/usr/bin/netdoc", "linux")
	if err != nil {
		t.Fatalf("sshCommand: %v", err)
	}
	if !slices.Contains(env, AskpassHostEnv+"=real.example.com") {
		t.Errorf("env = %v, want the resolved HostName", env)
	}
	if slices.ContainsFunc(env, func(e string) bool { return strings.HasPrefix(e, AskpassProxyEnv+"=") }) {
		t.Error("a direct connection was marked as proxied")
	}
}

// A jump host runs an ssh of its own that inherits the helper, so the helper
// has to know it cannot attribute a host-less prompt to the target.
func TestSSHCommandMarksProxiedConnections(t *testing.T) {
	stubSSHEffective(t, "example.com", true)
	_, env, err := resolvedSSHCommand(t, "example.com", "alice", "", "hunter2", "/usr/bin/netdoc", "linux")
	if err != nil {
		t.Fatalf("sshCommand: %v", err)
	}
	if !slices.Contains(env, AskpassProxyEnv+"=1") {
		t.Errorf("env = %v, want the proxy marker", env)
	}
}

// An unreadable config leaves the helper unable to tell the target's prompt
// from a jump host's, and both defaults are wrong: direct spends the password
// on whoever asks, proxied silently refuses the login it was opened for. Refuse
// the login and say why, so the retry with a blank field is the user's choice.
func TestSSHCommandRefusesWhenConfigIsUnreadable(t *testing.T) {
	stubSSHEffectiveErr(t, errors.New("exit status 255"))
	args, env, err := resolvedSSHCommand(t, "example.com", "alice", "", "hunter2", "/usr/bin/netdoc", "linux")
	if err == nil {
		t.Fatal("sshCommand succeeded, want a refusal")
	}
	if !strings.Contains(err.Error(), "password field blank") {
		t.Errorf("err = %q, want it to name the way out", err)
	}
	// Nothing may be handed back on the refusal path: an argv that reached ssh
	// without the askpass env would prompt on a terminal the TUI still owns,
	// and an env would carry the secret past the check that just failed.
	if args != nil || env != nil {
		t.Errorf("args = %v, env = %v, want both nil", args, env)
	}
}

// A config read that never answers is still bounded even though it now runs
// outside Update. This uses the real sshEffective; stubbing it would bypass the
// deadline under test.
func TestSSHResolutionBoundsAStalledConfigRead(t *testing.T) {
	stallSSHOnPath(t)
	old := sshConfigTimeout
	sshConfigTimeout = 150 * time.Millisecond
	t.Cleanup(func() { sshConfigTimeout = old })

	start := time.Now()
	args, env, err := resolvedSSHCommand(t, "example.com", "alice", "", "hunter2", "/usr/bin/netdoc", "linux")
	elapsed := time.Since(start)

	// Unbounded, this waits out the fake's full sleep and then succeeds on its
	// empty output, so either check catches a missing deadline.
	if err == nil {
		t.Fatalf("sshCommand succeeded against a stalled ssh -G after %v: args = %v", elapsed, args)
	}
	if elapsed > 10*time.Second {
		t.Errorf("sshCommand took %v, want the %v deadline to cut it short", elapsed, sshConfigTimeout)
	}
	// The stall gets no UI of its own: it leaves by the existing refusal path.
	if !strings.Contains(err.Error(), "cannot read ssh config") || !strings.Contains(err.Error(), "password field blank") {
		t.Errorf("err = %q, want the unreadable-config refusal", err)
	}
	if args != nil || env != nil {
		t.Errorf("args = %v, env = %v, want both nil", args, env)
	}
}

// stallSSHOnPath puts an `ssh` on PATH that never answers, standing in for the
// Match exec or hung-mount Include that makes `ssh -G` stall. A script rather
// than the GO_HELPER re-exec the job tests use: the argv is sshEffective's to
// build, and the test binary would reject its -G and exit at once.
func stallSSHOnPath(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell to stall with")
	}
	dir := t.TempDir()
	// #nosec G306 -- this test-owned ssh stub must be executable via PATH.
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	// Prepended, not replacing: the script still needs to find sleep.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Without a password there is no secret to misroute, so the lookup is not
// consulted at all and a broken config costs the user nothing.
func TestSSHCommandWithoutPasswordIgnoresConfigFailure(t *testing.T) {
	called := false
	old := sshEffective
	sshEffective = func([]string) (string, bool, error) {
		called = true
		return "", false, errors.New("exit status 255")
	}
	t.Cleanup(func() { sshEffective = old })

	args, env, err := resolvedSSHCommand(t, "example.com", "alice", "", "", "/usr/bin/netdoc", "linux")
	if err != nil {
		t.Fatalf("sshCommand: %v", err)
	}
	if called {
		t.Error("the config lookup ran for a password-less login")
	}
	if !slices.Equal(args, []string{"-l", "alice", "example.com"}) {
		t.Errorf("args = %v, want [-l alice example.com]", args)
	}
	if env != nil {
		t.Errorf("env = %v, want nil", env)
	}
}

// The lookup is asked with the argv the session will use, since a Match block
// can key off the port or the login and answer with a different HostName.
func TestSSHCommandQueriesWithTheRealArgv(t *testing.T) {
	var got []string
	old := sshEffective
	sshEffective = func(args []string) (string, bool, error) { got = args; return "example.com", false, nil }
	t.Cleanup(func() { sshEffective = old })

	if _, _, err := resolvedSSHCommand(t, "example.com:2222", "alice", "", "hunter2", "/usr/bin/netdoc", "linux"); err != nil {
		t.Fatalf("sshCommand: %v", err)
	}
	want := []string{"-p", "2222", "-l", "alice", "example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("query args = %v, want %v", got, want)
	}
	if slices.Contains(got, "NumberOfPasswordPrompts=1") {
		t.Error("the prompt limit leaked into the config query")
	}
}

func TestParseSSHConfig(t *testing.T) {
	const direct = "user alice\nhostname real.example.com\nport 22\nproxycommand none\nproxyjump none\n"
	host, proxied := parseSSHConfig(direct)
	if host != "real.example.com" || proxied {
		t.Errorf("parseSSHConfig(direct) = %q, %v; want real.example.com, false", host, proxied)
	}
	// ssh prints the keywords in no fixed order, and an unset one still prints
	// as "none", which must not talk a set one back out of it.
	const jumped = "hostname real.example.com\nproxyjump jump.example.com\nproxycommand none\n"
	if host, proxied = parseSSHConfig(jumped); host != "real.example.com" || !proxied {
		t.Errorf("parseSSHConfig(jumped) = %q, %v; want real.example.com, true", host, proxied)
	}
	if host, proxied = parseSSHConfig(""); host != "" || proxied {
		t.Errorf("parseSSHConfig(empty) = %q, %v; want \"\", false", host, proxied)
	}
}

func TestSSHCommandNeedsHost(t *testing.T) {
	if _, err := sshCommand("", "alice", ""); err == nil {
		t.Error("empty host = nil error, want one")
	}
}

// The form's host string is written by sshHostValue and read back by
// sshCommand, so the round trip has to land on the target the run was about.
// An IPv6 literal is the case that punishes a plain host+":"+port: the result
// parses as a different, perfectly valid address, and ssh would connect there
// without anyone noticing.
func TestSSHHostValueRoundTrip(t *testing.T) {
	tests := []struct {
		target string
		want   []string
	}{
		{"example.com:2222", []string{"-p", "2222", "example.com"}},
		{"192.0.2.1:2222", []string{"-p", "2222", "192.0.2.1"}},
		{"[2001:db8::1]:2222", []string{"-p", "2222", "2001:db8::1"}},
		{"[2001:db8::1]:22", []string{"2001:db8::1"}},
		{"2001:db8::1", []string{"2001:db8::1"}},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			target, err := diagnostic.ParseTarget(tt.target)
			if err != nil {
				t.Fatalf("ParseTarget: %v", err)
			}
			args, err := sshCommand(sshHostValue(target), "", "")
			if err != nil {
				t.Fatalf("sshCommand: %v", err)
			}
			if !slices.Equal(args, tt.want) {
				t.Errorf("args = %v, want %v", args, tt.want)
			}
		})
	}
}

// sshHelpText returns the S binding's compact label and cheatsheet line from
// the keymap table itself.
func sshHelpText(t *testing.T) (bar, details string) {
	t.Helper()
	for _, def := range actionDefs {
		if def.act != actSSH {
			continue
		}
		help, ok := def.help[ctxList]
		if !ok {
			t.Fatal("the S binding has no ctxList help entry")
		}
		return help.bar, help.details
	}
	t.Fatal("actSSH is missing from actionDefs")
	return "", ""
}

// S remains off the compact footer. The Actions menu and cheatsheet expose it
// once the banner probe has found an SSH server, while the binding stays live.
func TestSSHHintFollowsTheBannerProbe(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(string) (string, error) { return "ssh", nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	m := newModel(mustTarget(t, "example.com:22"), false)
	m = asModel(t, must(m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})))
	doneResults(&m, diagnostic.ProbeSSH) // the SSH banner probe is the one that fails
	bar, details := sshHelpText(t)

	if strings.Contains(m.View(), bar) {
		t.Error("the footer hints S with no SSH server on the target")
	}
	if strings.Contains(asModel(t, must(m.Update(keyMsg("?")))).View(), details) {
		t.Error("the cheatsheet lists S with no SSH server on the target")
	}
	// Hidden, not disabled: the form still opens.
	if !asModel(t, must(m.Update(keyMsg("S")))).sshPrompt {
		t.Error("S must still open the form when the banner probe failed")
	}

	doneResults(&m, "")
	if strings.Contains(m.View(), bar) {
		t.Error("the footer hints S even though secondary actions stay compact")
	}
	if !slices.Contains(menuNames(m), "SSH login") {
		t.Error("the Actions menu drops S even though the banner probe passed")
	}
	if !strings.Contains(asModel(t, must(m.Update(keyMsg("?")))).View(), details) {
		t.Error("the cheatsheet drops S even though the banner probe passed")
	}
}

// A target with no SSH rung never gets a ProbeSSH result at all, and a missing
// map key yields the zero ProbeResult, whose Status is StatusPass, the first
// iota. Presence has to be checked alongside the status, or every HTTPS target
// advertises a login nothing has vouched for.
func TestSSHHintStaysHiddenWithoutAnSSHRung(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(string) (string, error) { return "ssh", nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	m := newModel(mustTarget(t, "example.com:443"), false)
	m = asModel(t, must(m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})))
	doneResults(&m, "") // every rung this target has passes; none of them is SSH
	bar, details := sshHelpText(t)

	if _, ok := m.results[diagnostic.ProbeSSH]; ok {
		t.Fatal("an https target grew an SSH rung: pick another target for this test")
	}
	if strings.Contains(m.View(), bar) {
		t.Error("the footer hints S on a target with no SSH rung")
	}
	if strings.Contains(asModel(t, must(m.Update(keyMsg("?")))).View(), details) {
		t.Error("the cheatsheet lists S on a target with no SSH rung")
	}
}

// The form takes its host from the target, tab moves the focus, ←/→ picks a
// key, and esc closes it.
func TestSSHFormKeys(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(string) (string, error) { return "ssh", nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	target, err := diagnostic.ParseTarget("example.com:2222")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	m := asModel(t, must(newModel(target, true).Update(keyMsg("S"))))
	if !m.sshPrompt {
		t.Fatal("S did not open the SSH form")
	}
	if got, want := m.ssh.host, "example.com:2222"; got != want {
		t.Errorf("host = %q, want %q", got, want)
	}
	if m.ssh.focus != sshUser {
		t.Errorf("focus = %d, want the username field (%d)", m.ssh.focus, sshUser)
	}
	if !strings.Contains(m.View(), "SSH login to example.com:2222") {
		t.Error("the SSH panel is not on screen")
	}

	// Typing lands in the focused field only.
	m = asModel(t, must(m.Update(keyMsg("x"))))
	if got := m.ssh.user.Value(); !strings.HasSuffix(got, "x") {
		t.Errorf("username = %q, want the typed rune appended", got)
	}
	m = asModel(t, must(m.Update(tea.KeyMsg{Type: tea.KeyTab})))
	if m.ssh.focus != sshKey {
		t.Errorf("after tab, focus = %d, want the key row (%d)", m.ssh.focus, sshKey)
	}
	m = asModel(t, must(m.Update(tea.KeyMsg{Type: tea.KeyTab})))
	m = asModel(t, must(m.Update(keyMsg("y"))))
	if got := m.ssh.pass.Value(); got != "y" {
		t.Errorf("password = %q, want %q", got, "y")
	}

	m = asModel(t, must(m.Update(tea.KeyMsg{Type: tea.KeyEsc})))
	if m.sshPrompt {
		t.Error("esc left the form open")
	}
}

// A blocked config resolver lives in the returned tea.Cmd, not Update. The
// started barrier also proves a later message is handled while that command is
// still blocked; no elapsed-time guess is involved.
func TestSSHResolutionLeavesUpdateResponsive(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	oldEffective := sshEffective
	sshEffective = func([]string) (string, bool, error) {
		close(started)
		<-release
		return "example.com", false, nil
	}
	t.Cleanup(func() { sshEffective = oldEffective })

	m := sshFormForTest(t, "example.com")
	m.toolbox = false // keep the existing spinner chain active, so Enter returns the resolver directly
	m.ssh.pass.SetValue("hunter2")
	type updateResult struct {
		m   model
		cmd tea.Cmd
	}
	updated := make(chan updateResult, 1)
	go func() {
		u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		updated <- updateResult{m: u.(model), cmd: cmd}
	}()

	var entered updateResult
	select {
	case entered = <-updated:
	case <-started:
		close(release)
		<-updated
		t.Fatal("ssh config resolution ran before Update returned")
	}
	m = entered.m
	resolved := make(chan tea.Msg, 1)
	go func() { resolved <- entered.cmd() }()
	select {
	case <-started:
	case msg := <-resolved:
		// A resolver that answers before it reads the config gave up early;
		// report its message instead of waiting out the test timeout.
		t.Fatalf("resolver finished without reading ssh config: %+v", msg)
	}

	u, _ := m.Update(tea.WindowSizeMsg{Width: 137, Height: 41})
	m = asModel(t, u)
	if m.width != 137 || m.height != 41 {
		t.Fatalf("window message was not processed while resolver blocked: %dx%d", m.width, m.height)
	}
	close(release)
	u, launch := m.Update(<-resolved)
	if m = asModel(t, u); m.sshPrompt || launch == nil {
		t.Fatal("successful resolution did not close the form and launch SSH")
	}
}

// Success constructs the askpass environment while the password is still in
// the form, then clears the form and accepts the result only once.
func TestSSHResolutionSuccessHandsOffPasswordOnce(t *testing.T) {
	stubSSHEffective(t, "real.example.com", false)
	oldRunner := runSSH
	var runs int
	var gotArgs, gotEnv []string
	runSSH = func(args, env []string) tea.Cmd {
		runs++
		gotArgs, gotEnv = slices.Clone(args), slices.Clone(env)
		return func() tea.Msg { return nil }
	}
	t.Cleanup(func() { runSSH = oldRunner })

	m := sshFormForTest(t, "example.com:2222")
	m.ssh.user.SetValue("alice")
	m.ssh.pass.SetValue("hunter2")
	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	if !m.sshPrompt || m.ssh.pending == nil || m.ssh.pass.Value() != "hunter2" {
		t.Fatal("Enter did not leave the password in the pending form")
	}
	msg := sshResult(t, cmd)
	u, launch := m.Update(msg)
	m = asModel(t, u)
	if launch == nil || runs != 1 || m.sshPrompt || m.ssh.pending != nil || m.ssh.pass.Value() != "" {
		t.Fatalf("success state: launch=%v runs=%d prompt=%v pending=%v password=%q", launch != nil, runs, m.sshPrompt, m.ssh.pending != nil, m.ssh.pass.Value())
	}
	wantArgs := []string{"-p", "2222", "-l", "alice", "-o", "NumberOfPasswordPrompts=1", "example.com"}
	if !slices.Equal(gotArgs, wantArgs) {
		t.Errorf("args = %v, want %v", gotArgs, wantArgs)
	}
	if !slices.Contains(gotEnv, AskpassEnv+"=hunter2") || !slices.Contains(gotEnv, AskpassHostEnv+"=real.example.com") {
		t.Error("accepted result did not hand the password and resolved host to askpass")
	}
	if slices.ContainsFunc(gotArgs, func(arg string) bool { return strings.Contains(arg, "hunter2") }) {
		t.Error("password leaked into SSH argv")
	}
	_, duplicate := m.Update(msg)
	if duplicate != nil || runs != 1 {
		t.Fatalf("duplicate completion launched SSH again: cmd=%v runs=%d", duplicate != nil, runs)
	}
}

func TestSSHResolutionErrorKeepsFormUsableForRetry(t *testing.T) {
	oldEffective := sshEffective
	var calls atomic.Int32
	sshEffective = func([]string) (string, bool, error) {
		if calls.Add(1) == 1 {
			return "", false, errors.New("config unavailable")
		}
		return "example.com", false, nil
	}
	t.Cleanup(func() { sshEffective = oldEffective })
	oldRunner := runSSH
	var runs int
	runSSH = func([]string, []string) tea.Cmd { runs++; return func() tea.Msg { return nil } }
	t.Cleanup(func() { runSSH = oldRunner })

	m := sshFormForTest(t, "example.com")
	m.ssh.setFocus(sshPass)
	m.ssh.pass.SetValue("hunter2")
	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	first := sshResult(t, cmd)
	u, launch := m.Update(first)
	m = asModel(t, u)
	if launch != nil || !m.sshPrompt || m.ssh.pending != nil || m.ssh.focus != sshPass || m.ssh.pass.Value() != "hunter2" || !strings.Contains(m.ssh.err, "cannot read ssh config") {
		t.Fatalf("error state: launch=%v prompt=%v pending=%v focus=%d password=%q err=%q", launch != nil, m.sshPrompt, m.ssh.pending != nil, m.ssh.focus, m.ssh.pass.Value(), m.ssh.err)
	}
	u, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	second := sshResult(t, cmd)
	if first.id == second.id {
		t.Fatal("retry reused the old request id")
	}
	u, launch = m.Update(second)
	m = asModel(t, u)
	if launch == nil || runs != 1 || m.sshPrompt {
		t.Fatalf("retry did not launch once: launch=%v runs=%d prompt=%v", launch != nil, runs, m.sshPrompt)
	}
}

func TestSSHResolutionIgnoresRepeatedEnter(t *testing.T) {
	stubSSHEffective(t, "example.com", false)
	m := sshFormForTest(t, "example.com")
	m.ssh.pass.SetValue("hunter2")
	u, first := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	id := m.ssh.pending.id
	u, second := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	if second != nil || m.ssh.pending == nil || m.ssh.pending.id != id || m.ssh.pass.Value() != "hunter2" {
		t.Fatal("repeated Enter replaced the pending request or password")
	}
	if msg := sshResult(t, first); msg.id != id {
		t.Fatalf("resolver id = %d, want %d", msg.id, id)
	}
}

// Escape abandons request A immediately. Reopening can start request B while A
// winds down, and A cannot launch with either its old password or B's new one.
func TestSSHResolutionEscapeRejectsStaleResult(t *testing.T) {
	startA, startB := make(chan struct{}), make(chan struct{})
	releaseA, releaseB := make(chan struct{}), make(chan struct{})
	oldEffective := sshEffective
	var calls atomic.Int32
	sshEffective = func([]string) (string, bool, error) {
		if calls.Add(1) == 1 {
			close(startA)
			<-releaseA
			return "old.example.com", false, nil
		}
		close(startB)
		<-releaseB
		return "new.example.com", false, nil
	}
	t.Cleanup(func() { sshEffective = oldEffective })
	oldRunner := runSSH
	var runs int
	var gotEnv []string
	runSSH = func(_ []string, env []string) tea.Cmd {
		runs++
		gotEnv = slices.Clone(env)
		return func() tea.Msg { return nil }
	}
	t.Cleanup(func() { runSSH = oldRunner })

	m := sshFormForTest(t, "example.com")
	m.toolbox = false // return each resolver directly; both are run under test-controlled barriers
	m.ssh.pass.SetValue("old-password")
	u, cmdA := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	resultA := make(chan tea.Msg, 1)
	go func() { resultA <- cmdA() }()
	<-startA
	u, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = asModel(t, u)
	if m.sshPrompt || m.ssh.pending != nil || m.ssh.pass.Value() != "" {
		t.Fatal("Escape did not immediately close and clear the pending form")
	}

	u, _ = m.Update(keyMsg("S"))
	m = asModel(t, u)
	m.ssh.pass.SetValue("new-password")
	u, cmdB := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	idB := m.ssh.pending.id
	resultB := make(chan tea.Msg, 1)
	go func() { resultB <- cmdB() }()
	<-startB

	close(releaseA)
	u, staleLaunch := m.Update(<-resultA)
	m = asModel(t, u)
	if staleLaunch != nil || runs != 0 || !m.sshPrompt || m.ssh.pending == nil || m.ssh.pending.id != idB || m.ssh.pass.Value() != "new-password" {
		t.Fatal("stale request A changed request B")
	}
	close(releaseB)
	u, launch := m.Update(<-resultB)
	m = asModel(t, u)
	if launch == nil || runs != 1 || m.sshPrompt {
		t.Fatalf("request B did not launch once: launch=%v runs=%d prompt=%v", launch != nil, runs, m.sshPrompt)
	}
	if !slices.Contains(gotEnv, AskpassEnv+"=new-password") || slices.Contains(gotEnv, AskpassEnv+"=old-password") {
		t.Error("request B did not exclusively use its own password")
	}
}

func TestSSHResolutionKeepsSpinnerAlive(t *testing.T) {
	stubSSHEffective(t, "example.com", false)
	m := sshFormForTest(t, "example.com")
	doneResults(&m, "")
	if m.spinnerActive() {
		t.Fatal("spinner active before SSH resolution")
	}
	m.ssh.pass.SetValue("hunter2")
	u, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = asModel(t, u)
	if !m.spinnerActive() || !strings.Contains(m.View(), "checking ssh config") {
		t.Fatal("pending SSH resolution did not keep and render the spinner")
	}
	if _, ok := cmd().(tea.BatchMsg); !ok {
		t.Fatal("starting from an idle spinner did not seed a new tick chain")
	}
	u, _ = m.Update(sshResolvedMsg{id: m.ssh.pending.id, err: errors.New("no config")})
	m = asModel(t, u)
	if m.spinnerActive() {
		t.Fatal("spinner remained active after SSH resolution error")
	}
}

// Without a target there is no host to log in to, so S declines rather than
// opening a form that cannot be completed.
func TestSSHFormNeedsTarget(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(string) (string, error) { return "ssh", nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	m := asModel(t, must(newModel(nil, true).Update(keyMsg("S"))))
	if m.sshPrompt {
		t.Error("S opened the form with no target")
	}
	if !strings.Contains(m.notice, "needs a target") {
		t.Errorf("notice = %q, want the missing-target hint", m.notice)
	}
}

// ←/→ walks the discovered keys and wraps, and "none" stays reachable.
func TestSSHKeyChooser(t *testing.T) {
	f := newSSHForm(defaultStyles, mustTarget(t, "example.com"))
	f.keys = []string{"", "/home/a/.ssh/id_ed25519", "/home/a/.ssh/id_rsa"}
	f.setFocus(sshKey)
	if f.keyPath() != "" {
		t.Errorf("initial key = %q, want none", f.keyPath())
	}
	f.cycleKey(1)
	if got, want := f.keyLabel(), "id_ed25519"; got != want {
		t.Errorf("label = %q, want %q", got, want)
	}
	f.cycleKey(-1)
	f.cycleKey(-1)
	if got, want := f.keyPath(), "/home/a/.ssh/id_rsa"; got != want {
		t.Errorf("wrapped to %q, want %q", got, want)
	}
}

// A password is echoed as dots, never as itself.
func TestSSHPasswordMasked(t *testing.T) {
	f := newSSHForm(defaultStyles, mustTarget(t, "example.com"))
	f.setFocus(sshPass)
	f.pass.SetValue("hunter2")
	if got := f.pass.View(); strings.Contains(got, "hunter2") {
		t.Errorf("password rendered in the clear: %q", got)
	}
}

// A failed session's stderr comes back into a job pane instead of vanishing
// with the screen ssh was using.
func TestSSHFailureLandsInJobPane(t *testing.T) {
	m := newModel(mustTarget(t, "example.com"), true)
	u, _ := m.Update(sshDoneMsg{
		err:     errors.New("exit status 255"),
		display: "ssh alice@example.com",
		output:  "alice@example.com: Permission denied (publickey,password).\n",
	})
	nm := asModel(t, u)
	if nm.cur.status != JobFailed {
		t.Errorf("status = %v, want failed", nm.cur.status)
	}
	joined := strings.Join(nm.cur.lines, "\n")
	if !strings.Contains(joined, "Permission denied") || !strings.Contains(joined, "exit status 255") {
		t.Errorf("job pane lines = %q, want ssh's stderr and the exit error", joined)
	}
	if !strings.Contains(nm.notice, "ssh failed") {
		t.Errorf("notice = %q, want the failure hint", nm.notice)
	}
}

// A hostile server's banner reaches the pane as inert text.
func TestSSHOutputSanitized(t *testing.T) {
	m := newModel(mustTarget(t, "example.com"), true)
	u, _ := m.Update(sshDoneMsg{display: "ssh example.com", output: "\x1b]52;c;aGk=\x07banner\n"})
	for _, line := range asModel(t, u).cur.lines {
		if strings.ContainsRune(line, '\x1b') {
			t.Errorf("escape survived into the pane: %q", line)
		}
	}
}

func TestCapWriter(t *testing.T) {
	var w capWriter
	big := strings.Repeat("x", capBytes+10)
	if n, err := w.Write([]byte(big)); n != len(big) || err != nil {
		t.Fatalf("Write = %d, %v, want %d, nil", n, err, len(big))
	}
	if _, err := w.Write([]byte("tail")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := w.String()
	if !strings.HasPrefix(got, strings.Repeat("x", capBytes)) {
		t.Error("the first capBytes must be kept verbatim")
	}
	if !strings.Contains(got, "14 more bytes discarded") {
		t.Errorf("String() = %q…, want the discarded count", got[max(len(got)-40, 0):])
	}
}

func must(m tea.Model, _ tea.Cmd) tea.Model { return m }
