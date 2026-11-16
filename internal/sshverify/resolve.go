// Package sshverify checks SSH credentials against a server without opening a
// shell. Discovery reports which authentication methods a server offers and
// sends no credential. Verification sends exactly one credential, once, and
// reports whether the server accepted it. Host keys are checked against the
// user's known_hosts files before any credential is sent, and a host key that
// does not match is refused.
package sshverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// sshBinary is the OpenSSH client used only to read configuration. Tests
// replace resolveOutput; nothing here connects to the target.
var sshBinary = "ssh"

// Target is the SSH configuration of one destination, as OpenSSH resolves it.
type Target struct {
	Host         string // the host name ssh would dial
	Port         int
	User         string   // the login name ssh would use
	HostKeyAlias string   // the name known_hosts is keyed on, when set
	IdentityFile []string // configured key paths, with ~ expanded
	AgentSocket  string   // the agent socket from IdentityAgent, "" when none
	AgentOff     bool     // IdentityAgent none: ssh uses no agent, so neither does netdoc
	KnownHosts   []string // user known_hosts files, in ssh's order
	GlobalHosts  []string // system-wide known_hosts files, in ssh's order
	// Unsupported names the directive that routes the connection through a
	// proxy. The native client does not run proxies, so a non-empty value
	// means no verification is attempted.
	Unsupported string
}

// Resolve reads the configuration for host, as ssh would resolve it. It runs
// one `ssh -G` with a fixed argument vector. That reads configuration files
// and connects to nothing.
func Resolve(ctx context.Context, host string, port int, login string) (Target, error) {
	if host == "" {
		return Target{}, errors.New("no host given")
	}
	args := []string{"-G"}
	if port > 0 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	if login != "" {
		args = append(args, "-l", login)
	}
	args = append(args, "--", host)
	out, err := resolveOutput(ctx, args)
	if err != nil {
		return Target{}, fmt.Errorf("could not read the SSH configuration: %w", err)
	}
	home, _ := os.UserHomeDir()
	return parseConfig(out, home)
}

// resolveOutput runs ssh with args and returns its standard output. Standard
// error is returned as part of the error, so a configuration mistake reads
// the same way it does on a terminal.
var resolveOutput = func(ctx context.Context, args []string) ([]byte, error) {
	program, err := sshExecutable(sshBinary)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, program, args...) // #nosec G204 -- the resolved ssh client; args is an argv slice built from the target, never a shell string
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return nil, err
		}
		return nil, errors.New(msg)
	}
	return stdout.Bytes(), nil
}

// sshExecutable finds the OpenSSH client on PATH and refuses it when the file
// or its directory can be written by anyone but the owner. The client reads the
// user's configuration and is trusted with it, so a writable copy on PATH would
// be a way to run other code with the user's configuration in hand.
func sshExecutable(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", errors.New("the ssh client was not found on PATH")
	}
	if err := checkClientPermissions(path); err != nil {
		return "", err
	}
	return path, nil
}

// parseConfig reads the key-value listing `ssh -G` prints. Most keywords
// appear once; identityfile repeats, and the known-hosts files are one line of
// space-separated paths. home expands the ~ that ssh leaves in identity paths.
func parseConfig(out []byte, home string) (Target, error) {
	var t Target
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "hostname":
			t.Host = value
		case "port":
			p, err := strconv.Atoi(value)
			if err != nil {
				return Target{}, errors.New("the SSH configuration gave an unreadable port")
			}
			t.Port = p
		case "user":
			t.User = value
		case "hostkeyalias":
			t.HostKeyAlias = value
		case "identityfile":
			t.IdentityFile = append(t.IdentityFile, expandHome(value, home))
		case "identityagent":
			if value == "none" {
				t.AgentOff = true
			} else {
				t.AgentSocket = expandHome(value, home)
			}
		case "userknownhostsfile":
			t.KnownHosts = append(t.KnownHosts, splitPaths(value, home)...)
		case "globalknownhostsfile":
			t.GlobalHosts = append(t.GlobalHosts, splitPaths(value, home)...)
		case "proxyjump", "proxycommand":
			if value != "none" && t.Unsupported == "" {
				t.Unsupported = key
			}
		}
	}
	if t.Host == "" || t.Port == 0 || t.User == "" {
		return Target{}, errors.New("the SSH configuration did not name a host, port and user")
	}
	return t, nil
}

func splitPaths(value, home string) []string {
	var paths []string
	for _, p := range strings.Fields(value) {
		paths = append(paths, expandHome(p, home))
	}
	return paths
}

// expandHome replaces a leading ~/ with the home directory. A path that still
// holds a %-token is returned as written; the caller refuses to open it.
func expandHome(p, home string) string {
	if home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}

// ExistingIdentityFiles returns the configured key files that exist as regular
// files, in ssh's order. A path holding a %-token is left out: it names a key
// ssh would expand per connection, and netdoc does not guess at the expansion.
func ExistingIdentityFiles(t Target) []string {
	var out []string
	for _, p := range t.IdentityFile {
		if strings.Contains(p, "%") {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	return out
}
