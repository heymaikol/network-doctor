//go:build integration

package app

// A profile pass against real OpenSSH. When the noninteractive acquisition is refused, the pass
// must not start an interactive ssh for that destination. Each case below configures a refusal
// that the interactive transport would answer: a host key it would ask about, a changed key it
// would accept under StrictHostKeyChecking no, or a passphrase it would unlock through askpass.
// Each case also sets a LocalCommand, forwardings, and an agent, which a re-run would enable.
//
// The ssh the pass runs is a wrapper on PATH. It logs each invocation and then runs the real ssh
// with a lab configuration. The remote command is a stand-in worker, given through
// NETDOC_VIA_COMMAND, so a session that reaches it leaves a record.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/remote"
	"golang.org/x/crypto/ssh"
)

// profileLabCase is one configuration. Placeholders {port}, {user}, {client}, {enc}, {known},
// {dir}, {localcommand}, and {askpass} are filled in by the lab.
type profileLabCase struct {
	name    string
	known   string // "empty", "trusted", or "changed"
	config  string
	askpass bool
}

const profileLabCanary = "stand-in worker answered"

func TestProfileNeverRetriesARefusedBatchInteractively(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the lab's ssh wrapper and stand-in worker are POSIX shell scripts, which Windows cannot run")
	}
	forwardings := "  ForwardAgent yes\n  ForwardX11 yes\n  LocalForward 127.0.0.1:5999 127.0.0.1:9\n  DynamicForward 127.0.0.1:5998\n"
	local := "  PermitLocalCommand yes\n  LocalCommand {localcommand}\n"
	for _, c := range []profileLabCase{
		{
			name:  "unknown host key",
			known: "empty",
			config: `Host lab
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {client}
  IdentitiesOnly yes
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
`,
		},
		{
			name:  "changed host key under StrictHostKeyChecking no",
			known: "changed",
			config: `Host lab
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {client}
  IdentitiesOnly yes
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking no
`,
		},
		{
			name:    "encrypted key, askpass, LocalCommand and forwardings",
			known:   "trusted",
			askpass: true,
			config: `Host lab
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {enc}
  IdentitiesOnly yes
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
` + local + forwardings,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			lab := newProfileLab(t, c)
			var stdout, stderr bytes.Buffer
			code := run([]string{"--via", "lab", "--profile", "github", "--json"}, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("exit 0: a refused destination must fail the pass; stdout %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), "no question was asked") {
				t.Errorf("the refusal does not say that no question was asked: %q", stderr.String())
			}
			// The -profile failure is one line. ssh's own text can contain spaces, so the check is
			// only for the line break that the sanitizer used to remove, gluing ssh's lines together.
			if line := strings.TrimSuffix(stderr.String(), "\n"); strings.Contains(line, "\n") {
				t.Errorf("the -profile failure spans lines: %q", stderr.String())
			}
			invocations := lab.invocations(t)
			var batch, interactive int
			for _, line := range invocations {
				switch {
				case strings.Contains(" "+line+" ", " -G "):
					// A configuration read: the route check, or a canary probe with -v. It connects to nothing.
				case strings.Contains(line, "BatchMode=yes"):
					batch++
				default:
					interactive++
				}
			}
			if batch == 0 {
				t.Fatalf("no batch acquisition ran, so the refusal proves nothing: %q", invocations)
			}
			if interactive != 0 {
				t.Errorf("%d interactive ssh invocations after the batch refusal: %q", interactive, invocations)
			}
			for _, canary := range []string{"askpass-ran", "localcommand-ran", "worker-ran"} {
				if _, err := os.Stat(filepath.Join(lab.dir, canary)); err == nil {
					t.Errorf("%s exists: the interactive path ran after the refusal", canary)
				}
			}
			if c.known == "empty" {
				if b, _ := os.ReadFile(lab.known); len(b) != 0 {
					t.Errorf("known_hosts was written after the refusal: %q", b)
				}
			}
		})
	}
}

type profileLabFixture struct {
	dir, port, known, client, enc, askpassCmd, cfg string
	invocationsFile, real                          string
}

// newProfileLab starts a loopback sshd, writes the keys, the known_hosts variant, the user
// configuration, and the wrapper on PATH, and points NETDOC_VIA_COMMAND at the stand-in worker.
func newProfileLab(t *testing.T, c profileLabCase) *profileLabFixture {
	t.Helper()
	sshd := profileLabTool(t, "sshd", "/usr/sbin/sshd")
	realSSH := profileLabTool(t, "ssh", "")
	who, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	dir, err := os.MkdirTemp("", "via-profile-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &profileLabFixture{dir: dir, real: realSSH}
	f.known = filepath.Join(dir, "known_hosts")
	f.client = filepath.Join(dir, "client")
	f.enc = filepath.Join(dir, "enc")
	hostKey, other := filepath.Join(dir, "hostkey"), filepath.Join(dir, "other")
	profileLabKey(t, hostKey, "")
	profileLabKey(t, f.client, "")
	profileLabKey(t, f.enc, "pw")
	profileLabKey(t, other, "")
	clientPub, _ := os.ReadFile(f.client + ".pub")
	encPub, _ := os.ReadFile(f.enc + ".pub")
	profileLabWrite(t, filepath.Join(dir, "authorized_keys"), string(clientPub)+string(encPub), 0o600)

	port := profileLabFreePort(t)
	f.port = strconv.Itoa(port)
	sshdCfg := filepath.Join(dir, "sshd_config")
	profileLabWrite(t, sshdCfg, fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
AuthorizedKeysFile %s
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PerSourcePenalties no
LogLevel ERROR
`, port, hostKey, filepath.Join(dir, "authorized_keys")), 0o600)
	logFile, err := os.Create(filepath.Clean(filepath.Join(dir, "sshd.log")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	daemon := exec.Command(sshd, "-D", "-e", "-f", sshdCfg)
	daemon.Stdout, daemon.Stderr = logFile, logFile
	if err := daemon.Start(); err != nil {
		t.Fatalf("start sshd: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_, _ = daemon.Process.Wait()
	})
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if conn, err := net.DialTimeout("tcp", "127.0.0.1:"+f.port, 200*time.Millisecond); err == nil {
			_ = conn.Close()
			break
		} else if time.Now().After(deadline) {
			t.Fatal("sshd did not listen")
		}
	}

	hostPub, _ := os.ReadFile(filepath.Clean(hostKey + ".pub"))
	hostFields := strings.Fields(string(hostPub))
	otherPub, _ := os.ReadFile(filepath.Clean(other + ".pub"))
	otherFields := strings.Fields(string(otherPub))
	switch c.known {
	case "empty":
		profileLabWrite(t, f.known, "", 0o600)
	case "trusted":
		profileLabWrite(t, f.known, fmt.Sprintf("[127.0.0.1]:%s %s %s\n", f.port, hostFields[0], hostFields[1]), 0o600)
	case "changed":
		profileLabWrite(t, f.known, fmt.Sprintf("[127.0.0.1]:%s %s %s\n", f.port, otherFields[0], otherFields[1]), 0o600)
	default:
		t.Fatalf("unknown known_hosts variant %q", c.known)
	}

	f.invocationsFile = filepath.Join(dir, "invocations")
	f.askpassCmd = filepath.Join(dir, "askpass")
	localcommand := filepath.Join(dir, "localcommand")
	profileLabWrite(t, localcommand, "#!/bin/sh\necho ran > "+filepath.Join(dir, "localcommand-ran")+"\n", 0o755)
	profileLabWrite(t, f.askpassCmd, "#!/bin/sh\necho ran > "+filepath.Join(dir, "askpass-ran")+"\necho pw\n", 0o755)

	f.cfg = filepath.Join(dir, "config")
	config := strings.NewReplacer(
		"{port}", f.port, "{user}", who.Username, "{client}", f.client, "{enc}", f.enc,
		"{known}", f.known, "{localcommand}", localcommand, "{dir}", dir,
	).Replace(c.config)
	profileLabWrite(t, f.cfg, config, 0o600)

	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	profileLabWrite(t, filepath.Join(bin, "ssh"), fmt.Sprintf("#!/bin/sh\necho \"$*\" >> %s\nexec %s -F %s \"$@\"\n",
		f.invocationsFile, realSSH, f.cfg), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	worker := filepath.Join(dir, "worker")
	profileLabWrite(t, worker, "#!/bin/sh\necho ran > "+filepath.Join(dir, "worker-ran")+"\ncat "+filepath.Join(dir, "response.json")+"\n", 0o755)
	reply, err := json.Marshal(remote.Response{Protocol: remote.Protocol, Error: profileLabCanary})
	if err != nil {
		t.Fatal(err)
	}
	profileLabWrite(t, filepath.Join(dir, "response.json"), string(reply), 0o600)
	t.Setenv(remote.CommandEnv, worker)

	if c.askpass {
		t.Setenv("SSH_ASKPASS", f.askpassCmd)
		t.Setenv("SSH_ASKPASS_REQUIRE", "force")
	}
	return f
}

// invocations returns the ssh command lines the wrapper recorded, one per run.
func (f *profileLabFixture) invocations(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(f.invocationsFile)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func profileLabTool(t *testing.T, name, fallback string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if _, err := os.Stat(fallback); fallback != "" && err == nil {
		return fallback
	}
	t.Skipf("needs %s on this host", name)
	return ""
}

func profileLabFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// profileLabKey writes an ed25519 key pair in OpenSSH's formats. The private key is encrypted with
// passphrase when one is given. The keys are made in process, so no ssh-keygen runs.
func profileLabKey(t *testing.T, path, passphrase string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	profileLabWrite(t, path, string(pem.EncodeToMemory(block)), 0o600)
	profileLabWrite(t, path+".pub", string(ssh.MarshalAuthorizedKey(pub)), 0o644)
}

// profileLabWrite writes path inside its own directory, through a root that refuses any name that
// would leave it.
func profileLabWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	err = root.WriteFile(filepath.Base(path), []byte(content), mode)
	if cerr := root.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
}
