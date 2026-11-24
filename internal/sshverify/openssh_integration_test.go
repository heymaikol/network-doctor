//go:build integration && unix

package sshverify

// Real OpenSSH checks. Each test starts an unprivileged sshd on loopback and runs the installed
// ssh against it, with the configuration and known_hosts files in a private directory. The
// server accepts one client key, so a credential that reaches it is counted in its log. A test
// that expects a refusal checks that no credential, session, forward or command reached the
// server, and that known_hosts is unchanged. Every refusal is paired with a control on the same
// server, so a refusal cannot be the harness failing. The tests skip when ssh, ssh-keygen or
// sshd is not installed.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// oshOpts shapes one lab server.
type oshOpts struct {
	hostKinds   []string // host key types the server presents, in order
	certificate bool     // certify the first host key with a CA made for the test
	keyID       string   // the certificate's key ID; a default when empty
	extra       string   // more sshd configuration
}

// oshLab is one sshd on loopback and the files that configure a client for it.
type oshLab struct {
	t         *testing.T
	dir       string
	port      int
	login     string
	keygen    string
	sshd      string
	clientKey string   // the private key the credential check offers; the server accepts it
	otherKey  string   // a key the server does not accept
	hostKeys  []string // private host keys, in the order the server presents them
	caKey     string   // the CA that signed the host certificate, when there is one
	keyID     string   // the key ID the host certificate carries
	known     string   // the known_hosts file the client reads for this lab
	cfg       string   // the sshd configuration
	logPath   string   // the sshd log
}

func newOSHLab(t *testing.T, o oshOpts) *oshLab {
	t.Helper()
	keygen := oshTool(t, "ssh-keygen")
	oshTool(t, "ssh")
	sshd := oshTool(t, "sshd")
	who, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	dir := t.TempDir()
	l := &oshLab{
		t: t, dir: dir, login: who.Username, keygen: keygen, sshd: sshd,
		port:    oshFreePort(t),
		known:   filepath.Join(dir, "known_hosts"),
		cfg:     filepath.Join(dir, "sshd_config"),
		logPath: filepath.Join(dir, "sshd.log"),
	}
	l.clientKey = l.makeKey("client", "ed25519")
	l.otherKey = l.makeKey("other", "ed25519")
	authKeys := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authKeys, []byte(l.pubLine(l.clientKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, kind := range o.hostKinds {
		l.hostKeys = append(l.hostKeys, l.makeKey(fmt.Sprintf("host%d", i), kind))
	}
	extra := o.extra
	l.keyID = o.keyID
	if l.keyID == "" {
		l.keyID = "hostcert"
	}
	if o.certificate {
		l.caKey = l.makeKey("ca", "ed25519")
		extra += "HostCertificate " + l.certify(l.hostKeys[0]) + "\n"
	}
	var hostLines strings.Builder
	for _, k := range l.hostKeys {
		hostLines.WriteString("HostKey " + k + "\n")
	}
	body := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
%sAuthorizedKeysFile %s
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PerSourcePenalties no
PidFile %s
ForceCommand touch %s
LogLevel DEBUG1
%s`, l.port, hostLines.String(), authKeys, filepath.Join(dir, "sshd.pid"), filepath.Join(dir, "command-ran"), extra)
	if err := os.WriteFile(l.cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.known, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(l.logPath)
	if err != nil {
		t.Fatal(err)
	}
	daemon := exec.Command(sshd, "-D", "-e", "-f", l.cfg) // #nosec G204 -- the test's own sshd and configuration
	daemon.Stdout, daemon.Stderr = logFile, logFile
	if err := daemon.Start(); err != nil {
		t.Fatalf("start sshd: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
		_ = logFile.Close()
	})
	oshWaitForPort(t, l.port)
	return l
}

// oshTool returns the path of an installed tool, or skips the test when it is missing.
func oshTool(t *testing.T, name string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if name == "sshd" {
		if _, err := os.Stat("/usr/sbin/sshd"); err == nil {
			return "/usr/sbin/sshd"
		}
	}
	missingOpenSSH(t, "needs "+name+" on this host")
	return ""
}

func oshFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func oshWaitForPort(t *testing.T, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshd did not listen on %s: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// makeKey creates a key of the given type under the test's directory and returns its private path.
func (l *oshLab) makeKey(name, kind string) string {
	l.t.Helper()
	path := filepath.Join(l.dir, name)
	args := []string{"-q", "-t", kind, "-N", "", "-f", path}
	switch kind {
	case "ecdsa":
		args = append(args, "-b", "256")
	case "rsa":
		args = append(args, "-b", "2048")
	}
	if out, err := exec.Command(l.keygen, args...).CombinedOutput(); err != nil { // #nosec G204 -- fixed arguments and a test-owned path
		l.t.Fatalf("ssh-keygen %s: %v: %s", kind, err, out)
	}
	return path
}

// certify signs the public half of key with the lab's CA for the test host, and returns the
// certificate path. The certificate names the loopback address.
func (l *oshLab) certify(key string) string {
	l.t.Helper()
	args := []string{"-q", "-s", l.caKey, "-I", l.keyID, "-h", "-n", "127.0.0.1", "-V", "always:forever", key + ".pub"}
	if out, err := exec.Command(l.keygen, args...).CombinedOutput(); err != nil { // #nosec G204 -- fixed arguments and test-owned paths
		l.t.Fatalf("ssh-keygen -s: %v: %s", err, out)
	}
	return key + "-cert.pub"
}

// pubLine returns the type and key of a private key's public half, as one authorized_keys line.
func (l *oshLab) pubLine(key string) string {
	l.t.Helper()
	return strings.TrimSpace(oshReadFile(l.t, key+".pub"))
}

// pubKey parses the public half of a private key.
func (l *oshLab) pubKey(key string) ssh.PublicKey {
	l.t.Helper()
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(oshReadFile(l.t, key+".pub")))
	if err != nil {
		l.t.Fatal(err)
	}
	return pk
}

// names is the known_hosts name for the lab's server on a non-default port.
func (l *oshLab) names() string { return "[127.0.0.1]:" + strconv.Itoa(l.port) }

// record returns a known_hosts line for key under marker (such as "@revoked ") and names.
func (l *oshLab) record(key, marker, names string) string {
	f := strings.Fields(l.pubLine(key))
	return marker + names + " " + f[0] + " " + f[1] + "\n"
}

func (l *oshLab) writeKnown(t *testing.T, lines ...string) {
	t.Helper()
	if err := os.WriteFile(l.known, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// useConfig writes the client configuration and points the probe and Resolve at it with -F.
func (l *oshLab) useConfig(t *testing.T, body string) {
	t.Helper()
	cfg := filepath.Join(l.dir, "ssh_config")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := sshTestArgs
	sshTestArgs = []string{"-F", cfg}
	t.Cleanup(func() { sshTestArgs = saved })
}

// baseConfig is the client configuration for the lab's host, with the given known_hosts files.
func (l *oshLab) baseConfig(files, extra string) string {
	return fmt.Sprintf("Host 127.0.0.1\n  Port %d\n  User %s\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile none\n%s", l.port, l.login, files, extra)
}

func (l *oshLab) resolve(t *testing.T, host string) Target {
	t.Helper()
	tg, err := Resolve(context.Background(), host, 0, l.login)
	if err != nil {
		t.Fatalf("resolve %s: %v", host, err)
	}
	return tg
}

func oshOptions() Options { return Options{Timeout: 30 * time.Second} }

// discover and verify run the two netdoc steps with the lab's client.
func (l *oshLab) discover(t *testing.T, tg Target) Result {
	t.Helper()
	return Discover(context.Background(), tg, oshOptions())
}

func (l *oshLab) verify(t *testing.T, tg Target) Result {
	t.Helper()
	return Verify(context.Background(), tg, Attempt{Method: MethodKey, KeyPath: l.clientKey}, oshOptions())
}

// The server's log counts. A credential is an accepted or failed public-key request. A session
// or forward is a channel the client opened. The forced command leaves a file when it runs.
func (l *oshLab) credentials() int {
	return l.logCount("Accepted publickey", "Failed publickey", "Accepted password", "Failed password")
}

func (l *oshLab) channels() int {
	return l.logCount("Starting session", "new [client-session]", "new [direct-tcpip]", "new [forwarded-tcpip]")
}

func (l *oshLab) logCount(needles ...string) int {
	n := 0
	for _, line := range strings.Split(oshReadFile(l.t, l.logPath), "\n") {
		for _, needle := range needles {
			if strings.Contains(line, needle) {
				n++
				break
			}
		}
	}
	return n
}

func (l *oshLab) commandRan() bool {
	_, err := os.Stat(filepath.Join(l.dir, "command-ran"))
	return err == nil
}

// oshSnap is the state a check is measured against: the credentials the server has logged and
// the hash of known_hosts, taken just before the check.
type oshSnap struct {
	creds int
	known string
}

func (l *oshLab) snap(t *testing.T) oshSnap {
	t.Helper()
	return oshSnap{creds: l.credentials(), known: oshFileState(t, l.known)}
}

// expectRefusal checks a refusal: the outcome, that no credential reached the server, that
// known_hosts was not written, and that no session, forward or command ran.
func (l *oshLab) expectRefusal(t *testing.T, s oshSnap, r Result, want Outcome) {
	t.Helper()
	if r.Outcome != want {
		t.Fatalf("outcome = %q (%s), want %q", r.Outcome, r.Detail, want)
	}
	if got := l.credentials() - s.creds; got != 0 {
		t.Errorf("the server saw %d credential attempts after a refusal", got)
	}
	if after := oshFileState(t, l.known); after != s.known {
		t.Error("known_hosts changed during a refused check")
	}
	if n := l.channels(); n != 0 {
		t.Errorf("the server saw %d session or forward channels", n)
	}
	if l.commandRan() {
		t.Error("a command ran on the server")
	}
}

// expectVerified checks a verification: one credential, and nothing else.
func (l *oshLab) expectVerified(t *testing.T, s oshSnap, r Result) {
	t.Helper()
	if r.Outcome != Verified {
		t.Fatalf("outcome = %q (%s), want verified", r.Outcome, r.Detail)
	}
	if got := l.credentials() - s.creds; got != 1 {
		t.Errorf("credential attempts = %d, want exactly one", got)
	}
	if n := l.channels(); n != 0 {
		t.Errorf("the server saw %d session or forward channels", n)
	}
	if l.commandRan() {
		t.Error("a command ran on the server")
	}
}

// oshFileState is a hash of a file's contents, or "absent", so a test can show that a file
// was not written.
func oshFileState(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a test-owned path
	if errors.Is(err, fs.ErrNotExist) {
		return "absent"
	}
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func oshReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a test-owned path
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestOpenSSHTrustedKeyVerifiesWithOneCredential is the positive path: OpenSSH records the key,
// so discovery trusts it, and the credential check sends exactly one credential.
func TestOpenSSHTrustedKeyVerifiesWithOneCredential(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")
	before := oshFileState(t, l.known)
	fp := ssh.FingerprintSHA256(l.pubKey(l.hostKeys[0]))

	d := l.discover(t, tg)
	if d.Outcome != Discovered || d.HostKey != fp {
		t.Fatalf("discover = %q with key %q, want discovered with %q (%s)", d.Outcome, d.HostKey, fp, d.Detail)
	}
	trust, ok, _ := probeHostKey(context.Background(), tg, oshOptions())
	if !ok || trust.algorithm != "ssh-ed25519" || trust.fingerprint != fp {
		t.Fatalf("probe = %+v, trusted %v, want ssh-ed25519 with %q", trust, ok, fp)
	}
	snap := l.snap(t)
	l.expectVerified(t, snap, l.verify(t, tg))
	if after := oshFileState(t, l.known); after != before {
		t.Error("known_hosts changed during a check that only reads it")
	}
}

// TestOpenSSHUnknownKeyIsRefusedBeforeAnyCredential refuses a key OpenSSH has no record of, and
// shows the same server verifies once the key is recorded.
func TestOpenSSHUnknownKeyIsRefusedBeforeAnyCredential(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t)
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")
	before := oshFileState(t, l.known)
	fp := ssh.FingerprintSHA256(l.pubKey(l.hostKeys[0]))

	d := l.discover(t, tg)
	if d.Outcome != HostKeyUnknown || d.HostKey != fp || !strings.Contains(d.Detail, "establish trust with your normal SSH client first") {
		t.Fatalf("discover = %q key %q (%s), want unknown with the fingerprint and the advice", d.Outcome, d.HostKey, d.Detail)
	}
	snap := l.snap(t)
	l.expectRefusal(t, snap, l.verify(t, tg), HostKeyUnknown)
	if after := oshFileState(t, l.known); after != before {
		t.Error("known_hosts was written for an unknown key")
	}

	// Control: the same server verifies once OpenSSH has the key.
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	snap = l.snap(t)
	l.expectVerified(t, snap, l.verify(t, tg))
}

// TestOpenSSHQuotedPairIsOneNameNotTwoFiles is the collision that was reported: a quoted pair
// is one file name to OpenSSH, so a key in the second file is unknown to it. The bare pair is
// the control.
func TestOpenSSHQuotedPairIsOneNameNotTwoFiles(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	kh1 := filepath.Join(l.dir, "kh1")
	kh2 := filepath.Join(l.dir, "kh2")
	l.writeKnown(t) // the first file does not hold the key
	if err := os.WriteFile(kh1, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kh2, []byte(l.record(l.hostKeys[0], "", l.names())), 0o600); err != nil {
		t.Fatal(err)
	}

	l.useConfig(t, l.baseConfig(`"`+kh1+" "+kh2+`"`, ""))
	tg := l.resolve(t, "127.0.0.1")
	snap := l.snap(t)
	l.expectRefusal(t, snap, l.verify(t, tg), HostKeyUnknown)

	l.useConfig(t, l.baseConfig(kh1+" "+kh2, ""))
	tg = l.resolve(t, "127.0.0.1")
	snap = l.snap(t)
	l.expectVerified(t, snap, l.verify(t, tg))
}

// TestOpenSSHKeyInAnyOfSeveralFilesIsTrusted checks the bare list of files: the key in the
// second one is trusted.
func TestOpenSSHKeyInAnyOfSeveralFilesIsTrusted(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	kh1 := filepath.Join(l.dir, "kh1")
	kh2 := filepath.Join(l.dir, "kh2")
	if err := os.WriteFile(kh1, []byte(l.record(l.otherKey, "", "elsewhere.example")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kh2, []byte(l.record(l.hostKeys[0], "", l.names())), 0o600); err != nil {
		t.Fatal(err)
	}
	l.useConfig(t, l.baseConfig(kh1+" "+kh2, ""))
	tg := l.resolve(t, "127.0.0.1")
	snap := l.snap(t)
	l.expectVerified(t, snap, l.verify(t, tg))
}

// TestOpenSSHChangedKeyIsRefusedBeforeAnyCredential records a different key for the host, so
// OpenSSH reports a changed key. The control records the server's key.
func TestOpenSSHChangedKeyIsRefusedBeforeAnyCredential(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.otherKey, "", l.names()))
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")
	fp := ssh.FingerprintSHA256(l.pubKey(l.hostKeys[0]))

	snap := l.snap(t)
	r := l.verify(t, tg)
	l.expectRefusal(t, snap, r, HostKeyChanged)
	if r.HostKey != fp {
		t.Errorf("the refusal names %q, want the key the server presented %q", r.HostKey, fp)
	}

	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	snap = l.snap(t)
	l.expectVerified(t, snap, l.verify(t, tg))
}

// TestOpenSSHRevokedMarkerIsRefusedBeforeAnyCredential records the server's key under @revoked.
// The control records the same key without the marker.
func TestOpenSSHRevokedMarkerIsRefusedBeforeAnyCredential(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "@revoked ", l.names()))
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")

	snap := l.snap(t)
	l.expectRefusal(t, snap, l.verify(t, tg), HostKeyRevoked)

	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	snap = l.snap(t)
	l.expectVerified(t, snap, l.verify(t, tg))
}

// TestOpenSSHRevocationListIsAppliedByTheProbe refuses a configured RevokedHostKeys at the route
// read, and shows that the probe alone refuses the revoked key too: OpenSSH applies the list.
func TestOpenSSHRevocationListIsAppliedByTheProbe(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	krl := filepath.Join(l.dir, "revoked.krl")
	if out, err := exec.Command(l.keygen, "-q", "-k", "-f", krl, l.hostKeys[0]+".pub").CombinedOutput(); err != nil { // #nosec G204 -- fixed arguments and test-owned paths
		t.Fatalf("ssh-keygen -k: %v: %s", err, out)
	}
	revoking := l.baseConfig(l.known, "  RevokedHostKeys "+krl+"\n")
	l.useConfig(t, revoking)
	if _, err := Resolve(context.Background(), "127.0.0.1", 0, l.login); err == nil {
		t.Fatal("a configured RevokedHostKeys is not refused at the route read")
	}

	// The probe, given the same configuration directly, refuses the revoked key.
	cfg := filepath.Join(l.dir, "ssh_config_revoked")
	if err := os.WriteFile(cfg, []byte(revoking), 0o600); err != nil {
		t.Fatal(err)
	}
	tg := Target{Host: "127.0.0.1", Port: l.port, User: l.login, dest: []string{"-F", cfg, "-p", strconv.Itoa(l.port), "-l", l.login, "--", "127.0.0.1"}}
	snap := l.snap(t)
	if _, ok, r := probeHostKey(context.Background(), tg, oshOptions()); ok || r.Outcome != HostKeyRevoked {
		t.Fatalf("the probe trusted a revoked key: trusted %v, %+v", ok, r)
	}
	if got := l.credentials() - snap.creds; got != 0 {
		t.Errorf("the probe sent %d credentials", got)
	}

	// Control: the same key without the list is trusted by the probe.
	plain := filepath.Join(l.dir, "ssh_config_plain")
	if err := os.WriteFile(plain, []byte(l.baseConfig(l.known, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	tg.dest = []string{"-F", plain, "-p", strconv.Itoa(l.port), "-l", l.login, "--", "127.0.0.1"}
	if _, ok, r := probeHostKey(context.Background(), tg, oshOptions()); !ok {
		t.Fatalf("the control was not trusted: %+v", r)
	}
}

// TestOpenSSHCertificateIsTrustedBySubjectKey records the CA. The probe reports the certified
// key, and the credential is sent once.
func TestOpenSSHCertificateIsTrustedBySubjectKey(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}, certificate: true})
	ca := strings.Fields(l.pubLine(l.caKey))
	l.writeKnown(t, "@cert-authority "+l.names()+" "+ca[0]+" "+ca[1]+"\n")
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")
	fp := ssh.FingerprintSHA256(l.pubKey(l.hostKeys[0]))

	trust, ok, _ := probeHostKey(context.Background(), tg, oshOptions())
	if !ok || trust.algorithm != "ssh-ed25519-cert-v01@openssh.com" || trust.fingerprint != fp {
		t.Fatalf("probe = %+v trusted %v, want the certificate type and the subject key %q", trust, ok, fp)
	}
	snap := l.snap(t)
	l.expectVerified(t, snap, l.verify(t, tg))
}

// TestOpenSSHCertificateFromAnUntrustedCA checks the two cases without the CA: with the plain
// key recorded, OpenSSH falls back to it; with nothing recorded, the key is unknown.
func TestOpenSSHCertificateFromAnUntrustedCA(t *testing.T) {
	t.Run("plain key recorded", func(t *testing.T) {
		l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}, certificate: true})
		l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
		l.useConfig(t, l.baseConfig(l.known, ""))
		tg := l.resolve(t, "127.0.0.1")
		snap := l.snap(t)
		l.expectVerified(t, snap, l.verify(t, tg))
	})
	t.Run("nothing recorded", func(t *testing.T) {
		l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}, certificate: true})
		l.writeKnown(t)
		l.useConfig(t, l.baseConfig(l.known, ""))
		tg := l.resolve(t, "127.0.0.1")
		snap := l.snap(t)
		l.expectRefusal(t, snap, l.verify(t, tg), HostKeyUnknown)
	})
}

// TestOpenSSHNegotiatedAlgorithmIsPinned gives the server three host key types and records one
// or two. The probe reports the algorithm OpenSSH negotiated, and the credential connection
// offers only that one.
func TestOpenSSHNegotiatedAlgorithmIsPinned(t *testing.T) {
	cases := []struct {
		name      string
		record    []int // indexes of the host keys recorded
		algorithm string
	}{
		{"rsa only", []int{2}, "rsa-sha2-512"},
		{"ecdsa only", []int{1}, "ecdsa-sha2-nistp256"},
		{"two recorded", []int{0, 1}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519", "ecdsa", "rsa"}})
			var lines []string
			for _, i := range c.record {
				lines = append(lines, l.record(l.hostKeys[i], "", l.names()))
			}
			l.writeKnown(t, lines...)
			l.useConfig(t, l.baseConfig(l.known, ""))
			tg := l.resolve(t, "127.0.0.1")
			trust, ok, r := probeHostKey(context.Background(), tg, oshOptions())
			if !ok {
				t.Fatalf("the probe refused a recorded key: %+v", r)
			}
			if c.algorithm != "" && trust.algorithm != c.algorithm {
				t.Errorf("negotiated %q, want %q", trust.algorithm, c.algorithm)
			}
			snap := l.snap(t)
			l.expectVerified(t, snap, l.verify(t, tg))
		})
	}
}

// TestOpenSSHHostKeyAliasOnANonDefaultPort checks a HostKeyAlias: OpenSSH looks the key up under
// the alias, not under the port. The control records the key under the host and port only.
func TestOpenSSHHostKeyAliasOnANonDefaultPort(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	alias := fmt.Sprintf("Host myalias\n  HostName 127.0.0.1\n  Port %d\n  User %s\n  HostKeyAlias keyname\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile none\n", l.port, l.login, l.known)
	l.useConfig(t, alias)

	l.writeKnown(t, l.record(l.hostKeys[0], "", "keyname"))
	tg := l.resolve(t, "myalias")
	snap := l.snap(t)
	l.expectVerified(t, snap, l.verify(t, tg))

	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	tg = l.resolve(t, "myalias")
	snap = l.snap(t)
	l.expectRefusal(t, snap, l.verify(t, tg), HostKeyUnknown)
}

// TestOpenSSHRoutesNetdocDoesNotRunAreRefused checks that a route netdoc cannot follow is refused
// at the route read, before any connection: no credential, and no command from the configuration.
func TestOpenSSHRoutesNetdocDoesNotRunAreRefused(t *testing.T) {
	cases := []struct {
		name  string
		extra func(sentinel string) string
	}{
		{"KnownHostsCommand", func(s string) string { return "  KnownHostsCommand touch " + s + "\n" }},
		{"GSSAPIKeyExchange", func(string) string { return "  GSSAPIKeyExchange yes\n" }},
		{"ProxyJump", func(string) string { return "  ProxyJump 127.0.0.1\n" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
			l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
			sentinel := filepath.Join(l.dir, "ran-by-config")
			l.useConfig(t, l.baseConfig(l.known, c.extra(sentinel)))
			snap := l.snap(t)
			if _, err := Resolve(context.Background(), "127.0.0.1", 0, l.login); err == nil {
				t.Fatal("the route was not refused")
			}
			if got := l.credentials() - snap.creds; got != 0 {
				t.Errorf("the server saw %d credentials on a refused route", got)
			}
			if _, err := os.Stat(sentinel); err == nil {
				t.Error("the configuration ran a command")
			}
		})
	}
}

// TestOpenSSHKeyThatMovedAfterTheProbeIsRefused runs the real server with a key that OpenSSH did
// not trust. The probe is stubbed to trust a different key, which stands for a key that
// changed between the probe and the credential. The pin refuses it. The control trusts the
// server's own key and verifies.
func TestOpenSSHKeyThatMovedAfterTheProbeIsRefused(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")

	trustOpenSSH(t, l.pubKey(l.otherKey))
	snap := l.snap(t)
	r := Verify(context.Background(), tg, Attempt{Method: MethodKey, KeyPath: l.clientKey}, oshOptions())
	l.expectRefusal(t, snap, r, HostKeyChanged)
	if want := ssh.FingerprintSHA256(l.pubKey(l.hostKeys[0])); r.HostKey != want {
		t.Errorf("the refusal names %q, want the key the server presented %q", r.HostKey, want)
	}

	trustOpenSSH(t, l.pubKey(l.hostKeys[0]))
	snap = l.snap(t)
	l.expectVerified(t, snap, Verify(context.Background(), tg, Attempt{Method: MethodKey, KeyPath: l.clientKey}, oshOptions()))
}

// TestOpenSSHLabSeesASessionWhenThereIsOne is the control for the zero counts above: a real ssh
// session with a command must show a channel and run the forced command. Without it, the
// "no channel, no command" checks could pass for a log that never matches.
func TestOpenSSHLabSeesASessionWhenThereIsOne(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	cfg := filepath.Join(l.dir, "ssh_config_session")
	body := l.baseConfig(l.known, "  IdentityFile "+l.clientKey+"\n  IdentitiesOnly yes\n")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPath := oshTool(t, "ssh")
	if out, err := exec.Command(sshPath, "-F", cfg, "-o", "BatchMode=yes", "127.0.0.1", "true").CombinedOutput(); err != nil { // #nosec G204 -- the test's own client and configuration
		t.Fatalf("the control session failed: %v: %s", err, out)
	}
	if l.channels() == 0 {
		t.Error("the log shows no channel for a real session: the no-channel check could not fail")
	}
	if !l.commandRan() {
		t.Error("the forced command did not run for a real session: the no-command check could not fail")
	}
	if l.credentials() == 0 {
		t.Error("the log shows no credential for a real session")
	}
}

// TestOpenSSHMLDSAHostKeyIsNotAgreedByTheDefaultClient records a hybrid ML-DSA host key on a
// server that offers it. OpenSSH 10.5 does not agree that key type with the default client, so
// the probe names the failed agreement and netdoc sends no credential. Enabling the type on both
// sides did not produce an agreement in this lab either, so that case is not tested here.
func TestOpenSSHMLDSAHostKeyIsNotAgreedByTheDefaultClient(t *testing.T) {
	const mldsa = "ssh-mldsa44-ed25519@openssh.com"
	l := newOSHLab(t, oshOpts{hostKinds: []string{"mldsa44-ed25519"}, extra: "HostKeyAlgorithms +" + mldsa + "\n"})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")

	snap := l.snap(t)
	r := l.discover(t, tg)
	if r.Outcome == Discovered || r.Outcome == Verified || !strings.Contains(r.Detail, "could not agree") {
		t.Fatalf("discover = %q (%s), want a refusal that says no algorithm was agreed", r.Outcome, r.Detail)
	}
	if got := l.credentials() - snap.creds; got != 0 {
		t.Errorf("the server saw %d credential attempts", got)
	}
}

// The probe's own argument list must not run a KnownHostsCommand the configuration names. The
// route read and the re-read refuse such a configuration first, so this checks the override alone:
// the probe is run directly, with the same arguments it would use, and the command must not run.
func TestOpenSSHProbeDoesNotRunAKnownHostsCommand(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	sentinel := filepath.Join(l.dir, "khc-ran")
	cfg := filepath.Join(l.dir, "ssh_config_khc")
	if err := os.WriteFile(cfg, []byte(l.baseConfig(l.known, "  KnownHostsCommand /usr/bin/touch "+sentinel+"\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	program := oshTool(t, "ssh")
	dest := []string{"-F", cfg, "-p", strconv.Itoa(l.port), "-l", l.login, "--", "127.0.0.1"}

	if _, _, err := runHostKeyProbe(context.Background(), program, probeArgs(dest)); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(sentinel); err == nil {
		t.Error("the probe ran the configured KnownHostsCommand")
	}
}

// A server that accepts no authentication is not verified. OpenSSH authenticates with "none" and
// holds the connection for -N, so the probe reads no decision it can trust and ends at its timeout.
// The check fails closed: it trusts no key, sends no credential, and opens no session. There is no
// early end on the acceptance line, because a line that a forged transcript could print must not
// end the check or decide it.
func TestOpenSSHRefusesAServerThatAcceptsNone(t *testing.T) {
	host, _ := newEd25519(t)
	s := newServer(host)
	s.cfg.NoClientAuth = true
	port := listenLoopback(t, s)
	dir := t.TempDir()
	known := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(known, []byte(knownhosts.Line([]string{"[127.0.0.1]:" + strconv.Itoa(port)}, host.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(cfg, []byte("Host 127.0.0.1\n  Port "+strconv.Itoa(port)+"\n  UserKnownHostsFile "+known+"\n  GlobalKnownHostsFile none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tg := Target{Host: "127.0.0.1", Port: port, User: testUser, dest: []string{"-F", cfg, "-p", strconv.Itoa(port), "-l", testUser, "--", "127.0.0.1"}}
	opts := Options{Timeout: 3 * time.Second}

	if _, ok, r := probeHostKey(context.Background(), tg, opts); ok {
		t.Fatalf("the probe trusted a server that accepted none: %+v", r)
	}
	got := Verify(context.Background(), tg, Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)
	if got.Outcome == Verified || got.Outcome == NoCredentialAccepted {
		t.Fatalf("outcome = %q (%s), want a refusal", got.Outcome, got.Detail)
	}
	if n := s.opens.Load(); n != 0 {
		t.Errorf("the server saw %d channel opens", n)
	}
}

// A Match exec in the configuration runs a command during the probe, and that command's standard
// error reaches the probe's transcript. The probe must refuse a check that ran a configured
// command, because the transcript is then not the record of OpenSSH's decision alone.
func TestOpenSSHRefusesAProbeThatRanAConfiguredCommand(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	cfg := filepath.Join(l.dir, "ssh_config_match")
	body := l.baseConfig(l.known, "  Match exec \"/usr/bin/true\"\n")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	tg := Target{Host: "127.0.0.1", Port: l.port, User: l.login, dest: []string{"-F", cfg, "-p", strconv.Itoa(l.port), "-l", l.login, "--", "127.0.0.1"}}

	_, ok, r := probeHostKey(context.Background(), tg, oshOptions())

	if ok {
		t.Fatalf("the probe trusted a key after a configured command ran: %+v", r)
	}
}

// A configuration read clean can change before the check. A KnownHostsCommand written after the
// read must not be silently overridden and then trusted: the check reads the configuration again
// under the same rules, and refuses before any credential if it is no longer one netdoc verifies.
func TestOpenSSHRefusesAConfigurationThatChangedAfterItWasRead(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")

	sentinel := filepath.Join(l.dir, "drift-khc-ran")
	cfg := filepath.Join(l.dir, "ssh_config")
	if err := os.WriteFile(cfg, []byte(l.baseConfig(l.known, "  KnownHostsCommand /usr/bin/touch "+sentinel+"\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	snap := l.snap(t)
	r := l.verify(t, tg)

	if r.Outcome == Verified || l.credentials() != snap.creds {
		t.Fatalf("a credential was sent after the configuration changed: outcome %q (%s)", r.Outcome, r.Detail)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Error("the changed configuration's command ran")
	}
}

// A key ID can carry line breaks, and OpenSSH prints it raw. Here the key ID forges the decision
// (a match, an authentication step and a fake certificate tail) in front of a host key that is not
// trusted, so OpenSSH's own refusal follows. The refusal must stand, and no credential may be sent.
func TestOpenSSHForgedKeyIDDecisionAgainstAnUntrustedCA(t *testing.T) {
	forged := "x\" CA ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"debug1: SSH2_MSG_NEWKEYS sent\n" +
		"debug1: SSH2_MSG_SERVICE_ACCEPT received\n" +
		"debug1: Host '[127.0.0.1]:2622' is known and matches the ED25519-CERT host certificate.\n" +
		"debug1: Authentications that can continue: password,publickey\n" +
		"debug1: No more authentication methods to try.\n" +
		"debug1: x"
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}, certificate: true, keyID: forged})
	l.writeKnown(t)
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")

	snap := l.snap(t)
	r := l.verify(t, tg)

	if r.Outcome == Verified || l.credentials() != snap.creds {
		t.Fatalf("a forged key ID authorized a credential: outcome %q (%s)", r.Outcome, r.Detail)
	}
}

// A key ID of more than a kilobyte makes OpenSSH cut its debug line short, and the cut line loses
// the certificate's authority text. A check must refuse that line, even when the CA is trusted.
func TestOpenSSHPaddedKeyIDIsRefused(t *testing.T) {
	padded := "x" + strings.Repeat("p", 1500)
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}, certificate: true, keyID: padded})
	ca := strings.Fields(l.pubLine(l.caKey))
	l.writeKnown(t, "@cert-authority "+l.names()+" "+ca[0]+" "+ca[1]+"\n")
	l.useConfig(t, l.baseConfig(l.known, ""))
	tg := l.resolve(t, "127.0.0.1")

	snap := l.snap(t)
	r := l.verify(t, tg)

	if r.Outcome == Verified || l.credentials() != snap.creds {
		t.Fatalf("a padded key ID was accepted: outcome %q (%s)", r.Outcome, r.Detail)
	}
}

// A server that accepts no authentication is reported as such, and the check ends when OpenSSH
// says so. A key ID that carries that acceptance line must not end the check or produce the
// result: the probe refuses the forged line's certificate, and no session opens.
func TestOpenSSHForgedAcceptanceInKeyIDDoesNotEndTheCheck(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	keyID := "x\nAuthenticated to " + testHost + " ([127.0.0.1]:1) using \"none\".\ndebug1: x"
	s := newServer(certifiedSigner(t, ca, host, keyID))
	s.cfg.NoClientAuth = true
	port := listenLoopback(t, s)
	dir := t.TempDir()
	known := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(known, []byte("@cert-authority "+"[127.0.0.1]:"+strconv.Itoa(port)+" "+ca.PublicKey().Type()+" "+strings.Fields(string(ssh.MarshalAuthorizedKey(ca.PublicKey())))[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(cfg, []byte("Host 127.0.0.1\n  Port "+strconv.Itoa(port)+"\n  UserKnownHostsFile "+known+"\n  GlobalKnownHostsFile none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := sshTestArgs
	sshTestArgs = []string{"-F", cfg}
	t.Cleanup(func() { sshTestArgs = saved })
	tg, err := Resolve(context.Background(), "127.0.0.1", 0, testUser)
	if err != nil {
		t.Fatal(err)
	}

	r := Verify(context.Background(), tg, Attempt{Method: MethodPassword, Password: []byte(testPassword)}, Options{Timeout: 8 * time.Second})

	if r.Outcome == NoCredentialAccepted || r.Outcome == Verified {
		t.Fatalf("a forged acceptance line in the key ID produced %q (%s)", r.Outcome, r.Detail)
	}
	if n := s.opens.Load(); n != 0 {
		t.Errorf("the server saw %d channel opens", n)
	}
}

// An explicit IdentityFile makes OpenSSH print the key it loaded, before the key exchange. A host
// trusted by OpenSSH must still be discovered, and a credential with that key must still verify.
func TestOpenSSHExplicitIdentityFileIsTrusted(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	l.useConfig(t, l.baseConfig(l.known, "  IdentityFile "+l.clientKey+"\n  IdentitiesOnly yes\n"))
	tg := l.resolve(t, "127.0.0.1")

	if d := l.discover(t, tg); d.Outcome != Discovered {
		t.Fatalf("discovery with an explicit IdentityFile = %q (%s), want discovered", d.Outcome, d.Detail)
	}
	snap := l.snap(t)
	l.expectVerified(t, snap, Verify(context.Background(), tg, Attempt{Method: MethodKey, KeyPath: l.clientKey}, oshOptions()))
}
