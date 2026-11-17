package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/charmbracelet/x/term"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// verifySSHFlags are the values of the -verify-ssh family of flags.
type verifySSHFlags struct {
	auth          string
	key           string
	agentKey      string
	user          string
	trustHostKey  string
	passwordStdin bool
	jsonOut       bool
}

// verifyOnly are the flags that mean something only with -verify-ssh.
var verifyOnly = []string{"verify-auth", "verify-key", "verify-agent-key", "verify-user", "trust-host-key", "password-stdin"}

// verifyCompatible are the flags -verify-ssh accepts. Any other mode, and any
// probe setting, is refused by name rather than silently ignored, because the
// check runs no probe and reads nothing from the rest.
var verifyCompatible = map[string]bool{
	"verify-ssh": true, "verify-auth": true, "verify-key": true, "verify-agent-key": true,
	"verify-user": true, "trust-host-key": true, "password-stdin": true, "json": true,
}

// verifyFlagMisuse names a verification-only flag used without -verify-ssh.
func verifyFlagMisuse(set map[string]bool, verifySSH bool) string {
	if verifySSH {
		return ""
	}
	for _, name := range verifyOnly {
		if set[name] {
			return "-" + name + " requires -verify-ssh"
		}
	}
	return ""
}

// Test seams. Production reads the real stdin and terminal.
var (
	verifyStdin     io.Reader = os.Stdin
	verifyIsTTY               = func() bool { return termIsTerminal(os.Stdin.Fd()) }
	verifyReadPass            = func() ([]byte, error) { return term.ReadPassword(os.Stdin.Fd()) }
	verifyResolve             = sshverify.Resolve
	verifyDiscover            = sshverify.Discover
	verifyVerify              = sshverify.Verify
	verifyListAgent           = sshverify.ListAgentKeys
	verifyNeedsPass           = sshverify.KeyNeedsPassphrase
)

// maxSecretLen bounds a password or passphrase read from standard input.
const maxSecretLen = 4096

// runVerifySSH implements -verify-ssh. Without -verify-auth it lists the
// methods the server offers and sends no credential. With -verify-auth it sends
// one credential, once. Exit status: 0 for a verified credential or a listing,
// 1 when the server did not accept the credential, 2 when the check could not
// be completed or was misused.
func runVerifySSH(positional []string, set map[string]bool, f verifySSHFlags, stdout, stderr io.Writer) int {
	for name := range set {
		if !verifyCompatible[name] {
			fmt.Fprintf(stderr, "netdoc: -verify-ssh cannot be combined with -%s\n", name)
			return 2
		}
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "netdoc: -verify-ssh needs one target: netdoc -verify-ssh [user@]host[:port]")
		return 2
	}
	login, rawHost, hasLogin := strings.Cut(positional[0], "@")
	if !hasLogin {
		rawHost, login = positional[0], ""
	}
	if f.user != "" {
		login = f.user
	}
	parsed, err := diagnostic.ParseTarget(rawHost)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc:", textsafe.Clean(err.Error()))
		return 2
	}
	port := 0
	if parsed.PortExplicit {
		port = parsed.Port
	}
	ctx := context.Background()
	tgt, err := verifyResolve(ctx, parsed.ScopedHost(), port, login)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc:", textsafe.Clean(err.Error()))
		return 2
	}
	label := fmt.Sprintf("%s@%s:%d", tgt.User, tgt.Host, tgt.Port)
	opts := sshverify.Options{TrustHostKey: f.trustHostKey}

	var result sshverify.Result
	switch f.auth {
	case "":
		result = verifyDiscover(ctx, tgt, opts)
	case "password", "key", "agent":
		attempt, code, ok := buildAttempt(f, tgt, opts, stdout, stderr)
		if !ok {
			return code
		}
		result = verifyVerify(ctx, tgt, attempt, opts)
	default:
		fmt.Fprintln(stderr, "netdoc: -verify-auth must be password, key, or agent")
		return 2
	}
	writeVerifyResult(stdout, label, result, f.jsonOut)
	return verifyExitCode(result.Outcome)
}

// buildAttempt reads the one secret the chosen method needs, with the key or
// agent identity it uses. ok is false when the attempt cannot be built, and
// code is then the exit status.
func buildAttempt(f verifySSHFlags, tgt sshverify.Target, opts sshverify.Options, stdout, stderr io.Writer) (sshverify.Attempt, int, bool) {
	switch f.auth {
	case "password":
		pw, err := readVerifySecret(stderr, fmt.Sprintf("Password for %s@%s: ", tgt.User, tgt.Host), f.passwordStdin)
		if err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return sshverify.Attempt{}, 2, false
		}
		return sshverify.Attempt{Method: sshverify.MethodPassword, Password: pw}, 0, true
	case "key":
		if f.key == "" {
			fmt.Fprintln(stderr, "netdoc: -verify-auth key needs -verify-key FILE")
			return sshverify.Attempt{}, 2, false
		}
		needs, err := verifyNeedsPass(f.key)
		if err != nil {
			fmt.Fprintln(stderr, "netdoc: the key file could not be read")
			return sshverify.Attempt{}, 2, false
		}
		attempt := sshverify.Attempt{Method: sshverify.MethodKey, KeyPath: f.key}
		if needs {
			pass, err := readVerifySecret(stderr, "Passphrase for the key: ", f.passwordStdin)
			if err != nil {
				fmt.Fprintln(stderr, "netdoc:", err)
				return sshverify.Attempt{}, 2, false
			}
			attempt.Passphrase = pass
		}
		return attempt, 0, true
	default: // agent
		if f.agentKey == "" {
			keys, err := verifyListAgent(tgt, opts)
			if err != nil {
				fmt.Fprintln(stderr, "netdoc:", textsafe.Clean(err.Error()))
				return sshverify.Attempt{}, 2, false
			}
			fmt.Fprintln(stdout, "The agent holds these keys. Choose one with -verify-agent-key FINGERPRINT:")
			for _, k := range keys {
				fmt.Fprintf(stdout, "  %s  %s  %s\n", k.Fingerprint, k.Type, k.Comment)
			}
			return sshverify.Attempt{}, 2, false
		}
		return sshverify.Attempt{Method: sshverify.MethodAgent, AgentFingerprint: f.agentKey}, 0, true
	}
}

// readVerifySecret returns one password or passphrase. With -password-stdin it
// takes one line of standard input. Otherwise it needs a terminal and reads
// with echo off. It is never taken from argv or the environment.
func readVerifySecret(stderr io.Writer, prompt string, fromStdin bool) ([]byte, error) {
	var value []byte
	if fromStdin {
		reader := bufio.NewReaderSize(io.LimitReader(verifyStdin, maxSecretLen+1), maxSecretLen+1)
		line, err := reader.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, errors.New("could not read the secret from standard input")
		}
		value = bytes.TrimRight(line, "\r\n")
	} else {
		if !verifyIsTTY() {
			return nil, errors.New("a password or passphrase needs a terminal, or -password-stdin")
		}
		read, err := readTerminalSecret(stderr, prompt)
		if err != nil {
			return nil, errors.New("could not read the secret from the terminal")
		}
		value = read
	}
	if len(value) == 0 || len(value) > maxSecretLen {
		clear(value)
		return nil, errors.New("the secret is empty or too long")
	}
	return value, nil
}

// readTerminalSecret reads a secret with echo off, and it puts the terminal back
// whether the read ends normally or the process is interrupted. ReadPassword
// restores echo in a defer, and a defer does not run when an interrupt ends the
// process, so the state saved here is restored by an interrupt handler instead.
func readTerminalSecret(stderr io.Writer, prompt string) ([]byte, error) {
	fd := os.Stdin.Fd()
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-interrupts:
			_ = term.Restore(fd, state)
			fmt.Fprintln(stderr)
			os.Exit(130)
		case <-finished:
		}
	}()
	fmt.Fprint(stderr, prompt)
	value, err := verifyReadPass()
	fmt.Fprintln(stderr)
	return value, err
}

// writeVerifyResult prints one result. Every server-supplied string has been
// sanitized already; the label is built from the resolved target, not the
// secret, and no field carries a credential.
func writeVerifyResult(w io.Writer, label string, r sshverify.Result, jsonOut bool) {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Target string `json:"target"`
			sshverify.Result
		}{Target: label, Result: r})
		return
	}
	fmt.Fprintf(w, "SSH check for %s\n", textsafe.Clean(label))
	fmt.Fprintf(w, "  outcome:   %s\n", r.Outcome.Describe())
	if r.Method != "" {
		fmt.Fprintf(w, "  method:    %s\n", r.Method)
	}
	if r.HostKey != "" {
		fmt.Fprintf(w, "  host key:  %s\n", textsafe.Clean(r.HostKey))
	}
	if len(r.Methods) > 0 {
		fmt.Fprintf(w, "  methods:   %s\n", textsafe.Clean(strings.Join(r.Methods, ", ")))
	}
	if len(r.Remaining) > 0 {
		fmt.Fprintf(w, "  remaining: %s\n", textsafe.Clean(strings.Join(r.Remaining, ", ")))
	}
	if r.Detail != "" {
		fmt.Fprintf(w, "  detail:    %s\n", textsafe.Clean(r.Detail))
	}
}

// verifyExitCode maps an outcome to the exit status documented for the mode.
func verifyExitCode(o sshverify.Outcome) int {
	switch o {
	case sshverify.Discovered, sshverify.Verified:
		return 0
	case sshverify.Refused, sshverify.Partial, sshverify.NotOffered, sshverify.NoCredentialAccepted:
		return 1
	default:
		return 2
	}
}
