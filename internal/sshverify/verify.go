package sshverify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// DefaultTimeout bounds one check from the TCP dial to the end of the
// handshake, so a silent server cannot hold a check open.
const DefaultTimeout = 20 * time.Second

// Method names the kind of credential an attempt uses.
type Method string

const (
	MethodPassword Method = "password"
	MethodKey      Method = "key"   // a private key file, with its passphrase if encrypted
	MethodAgent    Method = "agent" // a key the ssh-agent holds, chosen by fingerprint
)

// Outcome is what a check concluded. Only Verified means the server accepted a
// credential. Discovered means the server listed its methods and no credential
// was sent.
type Outcome string

const (
	Discovered           Outcome = "discovered"
	Verified             Outcome = "verified"
	Refused              Outcome = "refused"
	Partial              Outcome = "partial"
	NotOffered           Outcome = "not_offered"
	NoCredentialAccepted Outcome = "no_credential_accepted" // #nosec G101 -- an outcome label, not a credential
	HostKeyUnknown       Outcome = "host_key_unknown"
	HostKeyChanged       Outcome = "host_key_changed"
	Unsupported          Outcome = "unsupported"
	LocalFailure         Outcome = "local_failure"
	TransportFailure     Outcome = "transport_failure"
)

// Result is one check's conclusion. It never carries a secret. Methods and
// Remaining come from the server and are sanitized before they are stored.
type Result struct {
	Outcome   Outcome  `json:"outcome"`
	Method    Method   `json:"method,omitempty"`
	Methods   []string `json:"methods,omitempty"`
	Remaining []string `json:"remaining,omitempty"`
	HostKey   string   `json:"host_key_sha256,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// Options tunes a check. The zero value dials TCP, uses the target's agent and
// known_hosts files, and trusts no unknown host key.
type Options struct {
	Timeout time.Duration
	// Dial replaces the TCP dial. Tests use it to run against an in-memory
	// server; the production default is a plain TCP connection.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// Agent replaces the connection to the ssh-agent.
	Agent func() (io.ReadWriteCloser, error)
	// TrustHostKey is the SHA256 fingerprint of an unknown host key the user
	// has confirmed. It is accepted for this check only; nothing is written.
	TrustHostKey string
}

// Attempt is one credential, chosen by the user for one check.
type Attempt struct {
	User             string // login name; empty uses the target's
	Method           Method
	Password         []byte // MethodPassword
	KeyPath          string // MethodKey
	Passphrase       []byte // MethodKey, when the key file is encrypted
	AgentFingerprint string // MethodAgent: SHA256 fingerprint of the key to offer
}

// AgentKey is one identity the ssh-agent holds, for the user to choose from.
type AgentKey struct {
	Fingerprint string
	Type        string
	Comment     string
}

// Discover lists the authentication methods the target's server offers. It
// sends no credential: the handshake stops at the server's first method list.
func Discover(ctx context.Context, t Target, opts Options) Result {
	if r, stop := unsupported(t); stop {
		return r
	}
	return handshake(ctx, t, opts, nil, t.User)
}

// Verify sends one credential, once, and reports whether the server accepted
// it. The byte slices in a are cleared before Verify returns; a Go string made
// from a password cannot be cleared and is a residual the docs state.
func Verify(ctx context.Context, t Target, a Attempt, opts Options) Result {
	defer clear(a.Password)
	defer clear(a.Passphrase)
	if r, stop := unsupported(t); stop {
		return r
	}
	cred, r := prepare(t, a, opts)
	if cred == nil {
		return r
	}
	defer cred.close()
	user := a.User
	if user == "" {
		user = t.User
	}
	return handshake(ctx, t, opts, cred, user)
}

// ListAgentKeys returns the keys the ssh-agent holds. Listing sends nothing to
// the server.
func ListAgentKeys(t Target, opts Options) ([]AgentKey, error) {
	conn, err := agentConnection(t, opts)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return nil, errors.New("the ssh-agent did not list its keys")
	}
	var out []AgentKey
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		out = append(out, AgentKey{
			Fingerprint: ssh.FingerprintSHA256(pub),
			Type:        pub.Type(),
			Comment:     textsafe.Clean(k.Comment),
		})
	}
	return out, nil
}

// unsupported refuses a route netdoc does not run itself. The check never
// dials the resolved host around a proxy.
func unsupported(t Target) (Result, bool) {
	if t.Unsupported == "" {
		return Result{}, false
	}
	return Result{
		Outcome: Unsupported,
		Detail:  "the SSH configuration routes the connection through " + t.Unsupported + ", which netdoc does not run; nothing was sent",
	}, true
}

// credential is the one method an attempt offers, prepared before any network
// activity so that a missing key or passphrase fails without contacting the
// server.
type credential struct {
	method  Method
	offered []string // protocol method names that can carry it, in preference order
	use     func(name string) ssh.AuthMethod
	kb      *keyboardAnswer // set for password over keyboard-interactive
	closer  io.Closer       // the agent connection, if any
	once    sync.Once
}

func (c *credential) close() {
	c.once.Do(func() {
		if c.closer != nil {
			_ = c.closer.Close()
		}
	})
}

// prepare builds the credential or returns the local failure that stopped it.
// A key that will not unlock means nothing was sent, so it is reported as a
// local failure and never as a refusal by the server.
func prepare(t Target, a Attempt, opts Options) (*credential, Result) {
	local := func(detail string) (*credential, Result) {
		return nil, Result{Outcome: LocalFailure, Method: a.Method, Detail: detail}
	}
	switch a.Method {
	case MethodPassword:
		if len(a.Password) == 0 {
			return local("no password was given; nothing was sent")
		}
		secret := string(a.Password)
		kb := &keyboardAnswer{secret: secret}
		return &credential{
			method:  MethodPassword,
			offered: []string{"password", "keyboard-interactive"},
			kb:      kb,
			use: func(name string) ssh.AuthMethod {
				if name == "password" {
					return ssh.Password(secret)
				}
				return ssh.KeyboardInteractive(kb.challenge)
			},
		}, Result{}
	case MethodKey:
		if a.KeyPath == "" {
			return local("no key file was chosen; nothing was sent")
		}
		if strings.Contains(a.KeyPath, "%") {
			return local("the key path holds an unexpanded %-token; choose the key file directly; nothing was sent")
		}
		data, err := os.ReadFile(a.KeyPath) // #nosec G304 -- the user names the key file to verify
		if err != nil {
			return local("the key file could not be read; nothing was sent")
		}
		defer clear(data)
		signer, err := ssh.ParsePrivateKey(data)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			if len(a.Passphrase) == 0 {
				return local("the key file is encrypted and needs its passphrase; nothing was sent")
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, a.Passphrase)
		}
		if err != nil {
			return local("the key could not be unlocked: a wrong passphrase, or a key type netdoc does not support; nothing was sent")
		}
		return &credential{
			method:  MethodKey,
			offered: []string{"publickey"},
			use:     func(string) ssh.AuthMethod { return ssh.PublicKeys(signer) },
		}, Result{}
	case MethodAgent:
		if a.AgentFingerprint == "" {
			return local("choose a key the agent holds by its fingerprint; nothing was sent")
		}
		conn, err := agentConnection(t, opts)
		if err != nil {
			return local(textsafe.Clean(err.Error()) + "; nothing was sent")
		}
		signers, err := agent.NewClient(conn).Signers()
		if err != nil {
			_ = conn.Close()
			return local("the ssh-agent did not list its keys; nothing was sent")
		}
		var chosen ssh.Signer
		for _, s := range signers {
			if ssh.FingerprintSHA256(s.PublicKey()) == a.AgentFingerprint {
				chosen = s
				break
			}
		}
		if chosen == nil {
			_ = conn.Close()
			return local("the agent holds no key with that fingerprint; nothing was sent")
		}
		return &credential{
			method:  MethodAgent,
			offered: []string{"publickey"},
			use:     func(string) ssh.AuthMethod { return ssh.PublicKeys(chosen) },
			closer:  conn,
		}, Result{}
	default:
		return local("unknown method; nothing was sent")
	}
}

// agentConnection opens the ssh-agent. The target's IdentityAgent wins, then
// SSH_AUTH_SOCK. IdentityAgent none means no agent is used at all.
func agentConnection(t Target, opts Options) (io.ReadWriteCloser, error) {
	if opts.Agent != nil {
		return opts.Agent()
	}
	if t.AgentOff {
		return nil, errors.New("the SSH configuration disables the agent (IdentityAgent none)")
	}
	socket := t.AgentSocket
	if socket == "" {
		socket = os.Getenv("SSH_AUTH_SOCK")
	}
	if socket == "" {
		return nil, errors.New("no ssh-agent is configured: SSH_AUTH_SOCK is not set")
	}
	return dialAgent(socket)
}

// keyboardAnswer answers a keyboard-interactive server exactly once, and only
// with a single prompt that does not echo. Any other prompt is declined and
// recorded, so the password is never sent to a question netdoc does not
// understand. Nothing here reads the prompt's wording.
type keyboardAnswer struct {
	secret   string
	answered bool
	declined bool
}

func (k *keyboardAnswer) challenge(_, _ string, questions []string, echos []bool) ([]string, error) {
	if len(questions) == 0 {
		return []string{}, nil
	}
	if k.answered || len(questions) != 1 || len(echos) != 1 || echos[0] {
		k.declined = true
		return nil, errDeclined
	}
	k.answered = true
	return []string{k.secret}, nil
}

var errDeclined = errors.New("netdoc: declined a prompt it does not answer")

// errStop ends the handshake after the one attempt or after discovery. It never
// reaches the user: classify reads the recorded state instead.
var errStop = errors.New("netdoc: stop after the one attempt")

// authState records what the server told the callback, so the result comes
// from what happened and not from the text of an error.
type authState struct {
	cred       *credential // nil for discovery
	calls      int
	allowed    []string
	partial    []string
	attempted  bool
	notOffered bool
}

// callback is the ssh.ClientAuthCallback. It runs after the server's "none"
// reply and before every attempt. It offers the credential on the first call
// only when the server advertises a method that can carry it, and stops the
// handshake on every later call. Nothing is retried or cycled.
func (s *authState) callback(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	s.calls++
	s.allowed = slices.Clone(ctx.AllowedMethods)
	s.partial = slices.Clone(ctx.PartialSuccessMethods)
	if s.cred == nil || s.calls > 1 {
		return nil, errStop
	}
	name := ""
	for _, offer := range s.cred.offered {
		if slices.Contains(ctx.AllowedMethods, offer) {
			name = offer
			break
		}
	}
	if name == "" {
		s.notOffered = true
		return nil, errStop
	}
	s.attempted = true
	return s.cred.use(name), nil
}

// round is one handshake on one connection.
type round struct {
	hosts *hostCheck
	auth  *authState
}

// handshake runs the check on the target: one retry at most, for a
// negotiation mismatch, and never a second credential.
func handshake(ctx context.Context, t Target, opts Options, cred *credential, user string) Result {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if cred != nil {
		// A stop, or the deadline, must also release an agent waiting on a
		// touch or a PIN, which the TCP close cannot reach.
		stop := context.AfterFunc(ctx, cred.close)
		defer stop()
	}
	files := append(slices.Clone(t.GlobalHosts), t.KnownHosts...)
	var algos []string
	for {
		res, again, wants := attemptOnce(ctx, t, opts, cred, user, files, algos)
		if !again {
			return res
		}
		algos = hostKeyAlgorithms(wants)
	}
}

// attemptOnce makes one connection and one handshake. It reports again, with
// the key types known for the host, when the first handshake may have failed
// only because the server negotiated a key type the known_hosts file lacks.
func attemptOnce(ctx context.Context, t Target, opts Options, cred *credential, user string, files []string, algos []string) (Result, bool, []string) {
	hosts, err := newHostCheck(files, opts.TrustHostKey)
	if err != nil {
		return Result{Outcome: LocalFailure, Detail: err.Error() + "; nothing was sent"}, false, nil
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	conn, err := dial(ctx, addr, opts)
	if err != nil {
		return transport(ctx, "could not connect to "+addr+": "+textsafe.Clean(err.Error())), false, nil
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	r := round{hosts: hosts, auth: &authState{cred: cred}}
	name := net.JoinHostPort(hostKeyName(t), strconv.Itoa(t.Port))
	cfg := &ssh.ClientConfig{
		User:              user,
		HostKeyCallback:   hosts.callback,
		HostKeyAlgorithms: algos,
		AuthCallback:      r.auth.callback,
	}
	client, chans, reqs, err := ssh.NewClientConn(conn, name, cfg)
	if err == nil {
		// The server accepted the connection. Close it without opening a
		// session, a channel, or a remote command.
		go ssh.DiscardRequests(reqs)
		go rejectChannels(chans)
		_ = client.Close()
		return r.result(ctx, nil, cred == nil), false, nil
	}
	if hosts.needsRetry(algos != nil) {
		return Result{}, true, hosts.wants
	}
	return r.result(ctx, err, cred == nil), false, nil
}

func dial(ctx context.Context, addr string, opts Options) (net.Conn, error) {
	if opts.Dial != nil {
		return opts.Dial(ctx, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// hostKeyName is the name known_hosts is keyed on. A HostKeyAlias changes it,
// as it does for ssh itself.
func hostKeyName(t Target) string {
	if t.HostKeyAlias != "" {
		return t.HostKeyAlias
	}
	return t.Host
}

// rejectChannels turns away any channel the server opens. netdoc never asks
// for one, so an unexpected channel is refused rather than served.
func rejectChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		_ = ch.Reject(ssh.Prohibited, "netdoc opens no channels")
	}
}

// result turns what the handshake and the callback recorded into one outcome.
// discovery marks a check that sends no credential.
func (r round) result(ctx context.Context, err error, discovery bool) Result {
	h, s := r.hosts, r.auth
	fingerprint := ""
	if h.presented != nil {
		fingerprint = ssh.FingerprintSHA256(h.presented)
	}
	switch h.state {
	case hostChanged:
		return Result{Outcome: HostKeyChanged, HostKey: fingerprint, Detail: "the host key differs from the one in known_hosts; nothing was sent"}
	case hostRevoked:
		return Result{Outcome: HostKeyChanged, HostKey: fingerprint, Detail: "the host key is revoked in known_hosts; nothing was sent"}
	case hostUnknown:
		return Result{Outcome: HostKeyUnknown, HostKey: fingerprint, Detail: "the host key is not in known_hosts; nothing was sent"}
	case hostFailed:
		return transport(ctx, "the host key check failed: "+textsafe.Clean(h.err.Error()))
	}
	note := ""
	if h.state == hostTrustedForCheck {
		note = "; host key trusted for this check only, nothing written"
	}
	if err == nil {
		if s.attempted {
			return Result{Outcome: Verified, Method: s.cred.method, HostKey: fingerprint, Detail: "the server accepted the credential; no session was opened" + note}
		}
		return Result{Outcome: NoCredentialAccepted, HostKey: fingerprint, Detail: "the server accepted the connection without a credential; netdoc treats this as a finding and opened no session"}
	}
	if discovery && s.calls >= 1 {
		return Result{Outcome: Discovered, HostKey: fingerprint, Methods: sanitize(s.allowed), Detail: "no credential was sent" + note}
	}
	if s.notOffered {
		return Result{Outcome: NotOffered, Method: r.method(), HostKey: fingerprint, Methods: sanitize(s.allowed), Detail: "the server does not offer this method; nothing was sent" + note}
	}
	if s.cred != nil && s.cred.kb != nil && s.cred.kb.declined {
		return Result{Outcome: Unsupported, Method: r.method(), HostKey: fingerprint, Methods: sanitize(s.allowed), Detail: "the server asked for more than a password; netdoc answers only a single password prompt"}
	}
	if s.attempted {
		if s.calls >= 2 {
			if len(s.partial) > 0 {
				return Result{Outcome: Partial, Method: s.cred.method, HostKey: fingerprint, Methods: sanitize(s.partial), Remaining: sanitize(s.allowed), Detail: "the server accepted this method and requires more before it lets you in" + note}
			}
			return Result{Outcome: Refused, Method: s.cred.method, HostKey: fingerprint, Detail: "the server refused this credential" + note}
		}
		return transport(ctx, "the connection ended during authentication, so whether the server accepted the credential is unknown")
	}
	return transport(ctx, "the handshake failed before authentication")
}

func (r round) method() Method {
	if r.auth.cred == nil {
		return ""
	}
	return r.auth.cred.method
}

// transport reports a failure to reach or finish the handshake. A cancelled or
// expired check says so rather than naming the closed connection it caused.
func transport(ctx context.Context, detail string) Result {
	switch ctx.Err() {
	case context.Canceled:
		detail = "the check was cancelled"
	case context.DeadlineExceeded:
		detail = "the check timed out"
	}
	return Result{Outcome: TransportFailure, Detail: detail + "; nothing else was learned"}
}

// sanitize cleans server-supplied names before they reach a report or a screen.
func sanitize(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, textsafe.Clean(n))
	}
	return out
}

// Describe is the one-line label for a result, shared by the CLI and the TUI.
func (o Outcome) Describe() string {
	switch o {
	case Discovered:
		return "methods listed"
	case Verified:
		return "verified"
	case Refused:
		return "refused"
	case Partial:
		return "partial: more methods required"
	case NotOffered:
		return "method not offered"
	case NoCredentialAccepted:
		return "accepted with no credential"
	case HostKeyUnknown:
		return "host key unknown"
	case HostKeyChanged:
		return "host key changed"
	case Unsupported:
		return "unsupported"
	case LocalFailure:
		return "not sent"
	case TransportFailure:
		return "not completed"
	}
	return fmt.Sprintf("unknown outcome %q", string(o))
}

// KeyNeedsPassphrase reports whether the key file at path is encrypted, so a
// caller knows to ask for its passphrase. It reads the file and sends nothing.
func KeyNeedsPassphrase(path string) (bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the user names the key file to verify
	if err != nil {
		return false, err
	}
	defer clear(data)
	_, err = ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	return errors.As(err, &missing), nil
}
