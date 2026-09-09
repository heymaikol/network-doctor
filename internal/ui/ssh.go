// The SSH login form (S) and the interactive session it launches. Unlike the
// drill-down tools this is not a bounded job: ssh gets the real terminal, so
// the session is fully interactive and netdoc is suspended until it ends.

package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// sshDoneMsg reports an interactive ssh session's exit once the TUI has the
// terminal back, carrying what ssh said on stderr so a failure can be read
// here instead of in the scrollback the TUI paints over on its way back.
type sshDoneMsg struct {
	err     error
	display string
	output  string
}

// sshResolvedMsg carries only the non-secret result of the off-loop ssh
// configuration read. The password stays in the form until Update accepts the
// matching request and builds the askpass environment.
type sshResolvedMsg struct {
	id      uint64
	host    string
	proxied bool
	err     error
}

type sshPending struct {
	id   uint64
	args []string
	self string
}

// The form's fields, in tab order.
const (
	sshUser = iota
	sshKey
	sshPass
	sshFields
)

// AskpassEnv carries the password to the askpass helper, which is this binary
// re-executed by ssh: main reads the variable and writes the secret to stdout,
// which is where ssh expects an askpass helper's answer.
const AskpassEnv = "NETDOC_ASKPASS" // #nosec G101 -- this is an environment key, not a credential.

// AskpassHostEnv names the host the password was collected for. ssh's whole
// subtree inherits the askpass setting, so a ProxyJump child asking for the
// jump host's password reaches the same helper; the helper compares the host
// in the prompt against this one and refuses anything else.
//
// It holds the HostName ssh_config resolves the target to, not what was typed:
// ssh substitutes the real name before it asks, so an alias would never match
// its own prompt.
const AskpassHostEnv = "NETDOC_ASKPASS_HOST" // #nosec G101 -- this is an environment key, not a credential.

// AskpassProxyEnv marks a connection that goes through a jump host or a proxy
// command. Those run an ssh of their own that inherits the helper, so a prompt
// naming no host, such as an old client's keyboard-interactive PAM question, could
// be either end's. With a proxy in play the helper refuses those instead of
// guessing; without one there is only one machine it could be.
const AskpassProxyEnv = "NETDOC_ASKPASS_PROXY" // #nosec G101 -- this is an environment key, not a credential.

// sshForm is the SSH login prompt. The host is the run target, not a field:
// the form logs in to the machine the checks are about.
type sshForm struct {
	host    string
	user    textinput.Model
	pass    textinput.Model
	keys    []string // private keys found in ~/.ssh; keyIdx 0 means "none"
	keyIdx  int
	focus   int
	err     string
	pending *sshPending
}

// newSSHForm seeds the form from the run target, the local login name, and the
// keys sitting in ~/.ssh: the three answers netdoc can give on the user's
// behalf.
func newSSHForm(st styles, t *diagnostic.Target) sshForm {
	f := sshForm{host: sshHostValue(t), keys: append([]string{""}, listSSHKeys()...)}

	f.user = textinput.New()
	f.user.Prompt = "Username  "
	f.user.Placeholder = "your login name on that host"
	f.user.PromptStyle = st.key
	if u, err := user.Current(); err == nil {
		f.user.SetValue(u.Username)
	}

	f.pass = textinput.New()
	f.pass.Prompt = "Password  "
	f.pass.Placeholder = "optional"
	f.pass.PromptStyle = st.key
	// A typed password is echoed as dots; it is still held in memory, so it
	// never reaches a notice, the report, or an argv.
	f.pass.EchoMode = textinput.EchoPassword

	f.setFocus(sshUser)
	return f
}

// sshHostValue renders the target for ssh: bare host, plus the port when the
// target named a non-default one. JoinHostPort, because concatenating a port
// onto a bare IPv6 literal yields another valid address, and sshCommand would
// parse it back as a host nobody asked for and connect there on port 22.
func sshHostValue(t *diagnostic.Target) string {
	if t == nil {
		return ""
	}
	if t.PortExplicit && t.Port != 22 {
		return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	}
	return t.Host
}

// listSSHKeys returns the private keys in ~/.ssh, recognized by their public
// half sitting next to them, which costs no parsing and never opens the
// secret. Only that directory is scanned; a key kept anywhere else is what an
// IdentityFile line in ssh_config is for, and ssh will find it there without
// this list having to guess at the path.
func listSSHKeys() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return sshKeysIn(filepath.Join(home, ".ssh"))
}

// sshKeysIn is the directory scan behind listSSHKeys, with the directory as an
// argument so tests can point it at a temporary one instead of ~/.ssh.
func sshKeysIn(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var keys []string
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".pub")
		if !ok {
			continue
		}
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && info.Mode().IsRegular() {
			keys = append(keys, filepath.Join(dir, name))
		}
	}
	slices.Sort(keys)
	return keys
}

// keyLabel names the selected key for the form: the file name is what the user
// recognizes, and the directory is the same for all of them.
func (f sshForm) keyLabel() string {
	if f.keyIdx == 0 {
		if len(f.keys) == 1 {
			return "none found in ~/.ssh, so the agent or a password it is"
		}
		return "none: use the agent or a password"
	}
	return filepath.Base(f.keys[f.keyIdx])
}

func (f sshForm) keyPath() string { return f.keys[f.keyIdx] }

// cycleKey walks the key list, wrapping at both ends.
func (f *sshForm) cycleKey(delta int) {
	f.keyIdx = (f.keyIdx + delta + len(f.keys)) % len(f.keys)
}

func (f *sshForm) setFocus(i int) tea.Cmd {
	f.focus = (i + sshFields) % sshFields
	f.user.Blur()
	f.pass.Blur()
	switch f.focus {
	case sshUser:
		f.user.CursorEnd()
		return f.user.Focus()
	case sshPass:
		f.pass.CursorEnd()
		return f.pass.Focus()
	}
	return nil // the key row is a chooser, not an input
}

// handleSSHKey handles keys while the SSH form is open: tab/shift+tab (and
// up/down) move between fields, ←/→ picks a key while that row is focused,
// enter connects, esc backs out.
func (m model) handleSSHKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.sshPrompt = false
		m.ssh.pending = nil
		m.ssh.pass.SetValue("")
		return m, nil
	}
	if m.ssh.pending != nil {
		return m, nil
	}
	switch msg.String() {
	case "tab", "down":
		return m, m.ssh.setFocus(m.ssh.focus + 1)
	case "shift+tab", "up":
		return m, m.ssh.setFocus(m.ssh.focus - 1)
	case "left", "right":
		if m.ssh.focus != sshKey {
			break // a cursor move inside the focused input
		}
		delta := 1
		if msg.String() == "left" {
			delta = -1
		}
		m.ssh.cycleKey(delta)
		return m, nil
	case "enter":
		self, err := os.Executable()
		if err != nil {
			self = "" // no askpass helper; ssh falls back to asking on the tty
		}
		args, err := sshCommand(m.ssh.host, strings.TrimSpace(m.ssh.user.Value()), m.ssh.keyPath())
		if err != nil {
			m.ssh.err = textsafe.Clean(err.Error())
			return m, nil
		}
		if m.ssh.pass.Value() != "" && self != "" {
			wasTicking := m.spinnerActive()
			m.sshRequest++
			m.ssh.pending = &sshPending{id: m.sshRequest, args: args, self: self}
			m.ssh.err = ""
			cmd := resolveSSH(m.sshRequest, args, runtime.GOOS)
			if !wasTicking {
				return m, tea.Batch(cmd, m.spinner.Tick)
			}
			return m, cmd
		}
		m.sshPrompt = false
		m.ssh.pass.SetValue("")
		return m, runSSH(args, nil)
	}
	var cmd tea.Cmd
	switch m.ssh.focus {
	case sshUser:
		m.ssh.user, cmd = m.ssh.user.Update(msg)
	case sshPass:
		m.ssh.pass, cmd = m.ssh.pass.Update(msg)
	}
	m.ssh.err = ""
	return m, cmd
}

// sshCommand validates the form's non-secret answers and builds the argv that
// both `ssh -G` and the interactive session use.
func sshCommand(host, login, key string) (args []string, err error) {
	if host == "" {
		return nil, errors.New("no target host: press r to set one")
	}
	t, err := diagnostic.ParseTarget(host)
	if err != nil {
		return nil, err
	}
	if t.PortExplicit && t.Port != 22 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	if key != "" {
		// IdentitiesOnly keeps ssh from offering the agent's keys ahead of the
		// one that was picked here; otherwise a full agent can exhaust the
		// server's auth attempts before this key is ever tried.
		args = append(args, "-i", key, "-o", "IdentitiesOnly=yes")
	}
	if login != "" {
		// -l rather than login@host: the login is the one free-text field on
		// this form, and getopt takes an option's value verbatim, so a name
		// starting with "-" stays a name instead of becoming an ssh option.
		args = append(args, "-l", login)
	}
	return append(args, t.Host), nil
}

// resolveSSH performs every external configuration read in a tea.Cmd. Its
// immutable snapshot contains no password; stale results are rejected by id.
func resolveSSH(id uint64, args []string, goos string) tea.Cmd {
	args = slices.Clone(args)
	return func() tea.Msg {
		if goos == "windows" {
			version, err := sshVersion()
			if err != nil {
				return sshResolvedMsg{id: id, err: fmt.Errorf("cannot verify Windows OpenSSH forced-askpass support (%w); retry with the password field blank and let ssh ask", err)}
			}
			if err := windowsForcedAskpass(version); err != nil {
				return sshResolvedMsg{id: id, err: err}
			}
		}
		host := args[len(args)-1]
		effective, proxied, err := sshEffective(args)
		if err != nil {
			return sshResolvedMsg{id: id, err: fmt.Errorf("cannot read ssh config for %s (%w); retry with the password field blank and let ssh ask", host, err)}
		}
		if effective == "" {
			effective = host // ssh had nothing to say
		}
		return sshResolvedMsg{id: id, host: effective, proxied: proxied}
	}
}

// sshAskpass adds the password environment only after Update accepts the
// resolver result. The secret never enters a tea.Cmd or tea.Msg.
func sshAskpass(args []string, password, self, effective string, proxied bool) ([]string, []string) {
	// One prompt only: the helper would just repeat a rejected password.
	args = slices.Insert(slices.Clone(args), len(args)-1, "-o", "NumberOfPasswordPrompts=1")
	// The secret goes through the environment to the helper, never through
	// argv, which every process can read. It lives in ssh's environment for
	// the whole session and is inherited by whatever ssh_config starts.
	env := append(os.Environ(),
		"SSH_ASKPASS="+self,
		"SSH_ASKPASS_REQUIRE=force",
		AskpassEnv+"="+password,
		AskpassHostEnv+"="+effective)
	if proxied {
		env = append(env, AskpassProxyEnv+"=1")
	}
	return args, env
}

// sshConfigTimeout bounds off-loop `ssh -V` and `ssh -G` reads. ssh_config can
// genuinely stall: Match exec runs arbitrary commands and Include can touch a
// hung mount. A var so the timeout test needn't wait it out.
var sshConfigTimeout = 3 * time.Second

// sshVersion identifies the Windows client before relying on forced askpass.
// OpenSSH writes -V to stderr, so CombinedOutput is intentional.
var sshVersion = func() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshConfigTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh", "-V").CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func windowsForcedAskpass(version string) error {
	// 8.6 is the first Win32-OpenSSH project release whose Windows source
	// honors SSH_ASKPASS_REQUIRE=force; the preceding release is 8.1.
	const prefix = "OpenSSH_for_Windows_"
	rest, ok := strings.CutPrefix(version, prefix)
	if !ok {
		return errors.New("cannot verify Windows OpenSSH forced-askpass support; retry with the password field blank and let ssh ask")
	}
	var major, minor, patch int
	if _, err := fmt.Sscanf(rest, "%d.%dp%d", &major, &minor, &patch); err != nil {
		return errors.New("cannot verify Windows OpenSSH forced-askpass support; retry with the password field blank and let ssh ask")
	}
	if major < 8 || major == 8 && minor < 6 {
		return fmt.Errorf("installed Windows OpenSSH %d.%d cannot use the password field safely; version 8.6 or newer is required; retry with the password field blank and let ssh ask", major, minor)
	}
	return nil
}

// sshEffective asks ssh what the target really resolves to once ssh_config has
// had its say: the HostName a password prompt will name, and whether anything
// stands between here and there. The error is not cosmetic: without an answer
// the helper cannot tell whose prompt it is answering, so callers carrying a
// password must refuse rather than pick a default. A var so tests don't shell
// out.
var sshEffective = func(args []string) (host string, proxied bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshConfigTimeout)
	defer cancel()
	// -G prints the resolved config and connects to nothing.
	// #nosec G204 -- ssh is fixed and args remain separate argv elements, never shell text.
	cmd := exec.CommandContext(ctx, "ssh", append([]string{"-G"}, args...)...)
	cmd.WaitDelay = time.Second // don't hang on Wait if one of them holds the pipe
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	cleanup, err := startProcess(cmd)
	if err == nil {
		err = cmd.Wait()
		cleanup()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			exit.Stderr = stderr.Bytes()
		}
	}
	if err != nil {
		return "", false, err
	}
	host, proxied = parseSSHConfig(out.String())
	return host, proxied, nil
}

// parseSSHConfig reads `ssh -G` output, which is one lowercased keyword per
// line followed by its value.
func parseSSHConfig(out string) (host string, proxied bool) {
	for line := range strings.Lines(out) {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "hostname":
			host = v
		case "proxyjump", "proxycommand":
			// Both are printed even when unset, as the literal "none".
			proxied = proxied || (v != "" && v != "none")
		}
	}
	return host, proxied
}

// runSSH hands the terminal to ssh and takes it back when the session ends.
// tea.ExecProcess (not startTool) because ssh needs the real tty: that is what
// makes the session interactive, and what lets ssh ask for anything the form
// left blank: a key passphrase, a host-key confirmation, a 2FA code.
//
// stderr is teed rather than captured: it still scrolls past live during the
// session, and the copy comes back with the terminal so "Permission denied"
// survives in a job pane instead of being painted over by the restored TUI.
var runSSH = func(args, env []string) tea.Cmd {
	// #nosec G204 -- ssh is fixed and args remain separate argv elements, never shell text.
	cmd := exec.Command("ssh", args...)
	cmd.Env = env // nil inherits
	tee := &capWriter{}
	cmd.Stderr = io.MultiWriter(os.Stderr, tee)
	display := sshDisplay(args, runtime.GOOS)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return sshDoneMsg{err: err, display: display, output: tee.String()}
	})
}

func sshDisplay(args []string, goos string) string {
	return "ssh " + quoterFor(goos)(args)
}

// capWriter keeps the first capBytes it is given and counts the rest away. The
// first bytes are the useful ones: ssh reports why a login failed up front,
// while a long session's remote stderr is scrollback nobody needs a copy of.
// The exec pipe's copier is done before Wait returns, so no lock is needed.
type capWriter struct {
	b       []byte
	dropped int
}

const capBytes = 64 << 10

func (w *capWriter) Write(p []byte) (int, error) {
	kept := min(max(capBytes-len(w.b), 0), len(p))
	w.b = append(w.b, p[:kept]...)
	w.dropped += len(p) - kept
	return len(p), nil
}

func (w *capWriter) String() string {
	if w.dropped > 0 {
		return string(w.b) + "\n…[" + strconv.Itoa(w.dropped) + " more bytes discarded]"
	}
	return string(w.b)
}
