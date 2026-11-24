package sshverify

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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

// Options tunes a check. The zero value dials TCP and uses the target's agent. Trust in
// the host key is OpenSSH's decision, read by the probe; no option overrides it.
type Options struct {
	Timeout time.Duration
	// Dial replaces the TCP dial. Tests use it to run against an in-memory
	// server; the production default is a plain TCP connection.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// Agent replaces the connection to the ssh-agent.
	Agent func() (io.ReadWriteCloser, error)
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
	trust, ok, r := openSSHProbe(ctx, t, opts)
	if !ok {
		return r
	}
	return handshake(ctx, t, opts, nil, t.User, trust)
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
	// The host key is checked under the target's login: its configuration, its known_hosts and
	// its trust all belong to that login. A credential for another login is refused first.
	if a.User != "" && a.User != t.User {
		return Result{Outcome: LocalFailure, Detail: "the login for the credential is not the one whose SSH configuration and host key were checked; nothing was sent"}
	}
	cred, r := prepare(ctx, t, a, opts)
	if cred == nil {
		return r
	}
	defer cred.close()
	trust, ok, r := openSSHProbe(ctx, t, opts)
	if !ok {
		return r
	}
	return handshake(ctx, t, opts, cred, t.User, trust)
}

// ListAgentKeys returns the keys the ssh-agent holds. Listing sends nothing to
// the server. The listing ends when ctx ends or the check's timeout passes, so
// a silent agent cannot hold it.
func ListAgentKeys(ctx context.Context, t Target, opts Options) ([]AgentKey, error) {
	conn, err := agentConnection(t, opts)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := boundAgent(ctx, conn, opts)
	defer stop()
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
func prepare(ctx context.Context, t Target, a Attempt, opts Options) (*credential, Result) {
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
		stop := boundAgent(ctx, conn, opts)
		signers, err := agent.NewClient(conn).Signers()
		stop()
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

// boundAgent closes an agent connection when ctx ends or the check's timeout
// passes, and closing unblocks any request waiting on the agent. The returned
// stop releases the watch and the timer, so a connection kept for a later step
// is not closed by them.
func boundAgent(ctx context.Context, conn io.Closer, opts Options) (stop func()) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	watch := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return func() {
		watch()
		cancel()
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

// authState records what the server told the callback, so the result comes
// from what happened and not from the text of an error.
type authState struct {
	cred       *credential // nil for discovery
	calls      int
	allowed    []string
	partial    []string
	attempted  bool
	notOffered bool
	// name is the protocol method the credential was offered as: password or
	// keyboard-interactive.
	name string
}

// callback is the ssh.ClientAuthCallback. It runs after the server's "none"
// reply and before every attempt. It offers the credential on the first call
// only when the server advertises a method that can carry it. Otherwise it
// offers nothing. The configuration lists no methods, so the library then ends
// the handshake itself, and its error says whether the server answered (see
// libraryRefusal). Nothing is retried or cycled.
func (s *authState) callback(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	s.calls++
	s.allowed = slices.Clone(ctx.AllowedMethods)
	s.partial = slices.Clone(ctx.PartialSuccessMethods)
	if s.cred == nil || s.calls > 1 {
		return nil, nil
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
		return nil, nil
	}
	s.attempted = true
	s.name = name
	return s.cred.use(name), nil
}

// replyTracker wraps the connection of one handshake. After an I/O error the
// library calls the callback again, just as it does after a refusal, so the
// callback cannot tell the two apart. The server answered only if it sent bytes
// after the client's last write.
// libraryRefusal is the text of the library's own error when a complete reply
// leaves no method to try (golang.org/x/crypto v0.59.0, client_auth.go). Every
// other handshake error, such as the end of the connection or a reply cut short,
// means no complete reply arrived. The library has no typed error for this, so a
// test pins the text. If the text changes, refusals become transport failures,
// which is the safe direction, and that test fails.
const libraryRefusal = "ssh: unable to authenticate"

// handshakeFailed is the prefix the library gives every error that ends a handshake
// (golang.org/x/crypto v0.59.0, client.go).
const handshakeFailed = "ssh: handshake failed: "

// isRefusal reports whether err is the library's own refusal, which ends the handshake as
// "ssh: handshake failed: ssh: unable to authenticate". A server's disconnect also ends a
// handshake, and the server writes its text, so the phrase can appear there. The check
// therefore anchors to the start of the whole error. A disconnect starts with its own prefix.
func isRefusal(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), handshakeFailed+libraryRefusal)
}

// round is one handshake on one connection.
type round struct {
	pin  *pinCheck
	auth *authState
}

// handshake runs the check on one connection. It offers only the host key algorithm OpenSSH
// negotiated and accepts only the key OpenSSH trusted, so it sends a credential only to that
// key. It never retries.
func handshake(ctx context.Context, t Target, opts Options, cred *credential, user string, trust hostTrust) Result {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if cred != nil {
		// A stop, or the deadline, must also release an agent waiting on a touch or a PIN,
		// which the TCP close cannot reach.
		stop := context.AfterFunc(ctx, cred.close)
		defer stop()
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	conn, err := dial(ctx, addr, opts)
	if err != nil {
		return transport(ctx, "could not connect to "+addr+": "+textsafe.Clean(err.Error()))
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	r := round{pin: &pinCheck{fingerprint: trust.fingerprint, certificate: trust.certificate, keyID: trust.keyID}, auth: &authState{cred: cred}}
	cfg := &ssh.ClientConfig{
		User:              user,
		HostKeyCallback:   r.pin.callback,
		HostKeyAlgorithms: []string{trust.algorithm},
		AuthCallback:      r.auth.callback,
	}
	client, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err == nil {
		// The server accepted the connection. Close it without opening a session, a channel,
		// or a remote command.
		go ssh.DiscardRequests(reqs)
		go rejectChannels(chans)
		_ = client.Close()
		return r.result(ctx, nil, cred == nil)
	}
	return r.result(ctx, err, cred == nil)
}

func dial(ctx context.Context, addr string, opts Options) (net.Conn, error) {
	if opts.Dial != nil {
		return opts.Dial(ctx, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
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
	s, fingerprint := r.auth, r.pin.presented
	if r.pin.refused || (r.pin.presented != "" && r.pin.presented != r.pin.fingerprint) {
		return Result{Outcome: HostKeyChanged, HostKey: fingerprint, Detail: "the server presented a host key that OpenSSH did not trust; nothing was sent"}
	}
	note := ""
	if err == nil {
		// A keyboard-interactive exchange that asks no question is accepted without the
		// password, so only an answered challenge counts as sending it.
		if s.attempted && (s.name != "keyboard-interactive" || s.cred.kb != nil && s.cred.kb.answered) {
			return Result{Outcome: Verified, Method: s.cred.method, HostKey: fingerprint, Detail: "the server accepted the credential; no session was opened" + note}
		}
		return Result{Outcome: NoCredentialAccepted, HostKey: fingerprint, Detail: "the server accepted the connection without a credential; netdoc treats this as a finding and opened no session"}
	}
	complete := isRefusal(err)
	if discovery && complete && len(s.allowed) > 0 {
		return Result{Outcome: Discovered, HostKey: fingerprint, Methods: sanitize(s.allowed), Detail: "no credential was sent" + note}
	}
	if s.notOffered && complete {
		return Result{Outcome: NotOffered, Method: r.method(), HostKey: fingerprint, Methods: sanitize(s.allowed), Detail: "the server does not offer this method; nothing was sent" + note}
	}
	if s.cred != nil && s.cred.kb != nil && s.cred.kb.declined {
		return Result{Outcome: Unsupported, Method: r.method(), HostKey: fingerprint, Methods: sanitize(s.allowed), Detail: "the server asked for more than a password; netdoc answers only a single password prompt"}
	}
	if s.attempted {
		if complete {
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
	switch {
	case ctx.Err() == context.Canceled:
		detail = "the check was cancelled"
	case ctx.Err() == context.DeadlineExceeded || pastDeadline(ctx):
		detail = "the check timed out"
	}
	return Result{Outcome: TransportFailure, Detail: detail + "; nothing else was learned"}
}

// pastDeadline reports whether the check's deadline has passed. The socket
// deadline is set to the same instant, and it can fire before the context's own
// timer marks the context done, so the context's error alone is not enough.
func pastDeadline(ctx context.Context) bool {
	d, ok := ctx.Deadline()
	return ok && !time.Now().Before(d)
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

// Problems with a key file that KeyNeedsPassphrase can report. A missing or
// unreadable file is reported as the os error it is.
var (
	ErrKeyNotRegular = errors.New("not a regular file")
	ErrKeyNotPrivate = errors.New("not a private key netdoc can read")
)

// KeyNeedsPassphrase reports whether the key file at path is encrypted, so a
// caller knows to ask for its passphrase. It reads the file and sends nothing.
func KeyNeedsPassphrase(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, ErrKeyNotRegular
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the user names the key file to verify
	if err != nil {
		return false, err
	}
	defer clear(data)
	_, err = ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return true, nil
	}
	if err != nil {
		return false, ErrKeyNotPrivate
	}
	return false, nil
}

// ValidFingerprint reports whether fp has the form ssh-keygen prints for a host
// key: SHA256: followed by the unpadded base64 of a 32-byte digest. A value in
// any other form can never match a presented key, so it is refused before use.
func ValidFingerprint(fp string) bool {
	rest, ok := strings.CutPrefix(fp, "SHA256:")
	if !ok {
		return false
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(rest)
	return err == nil && len(raw) == sha256.Size
}
