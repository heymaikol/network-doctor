//go:build integration

package remote

// The request that batch writes to ssh's stdin is the worker's only input. Nothing ssh
// starts on the user's account may read it first. These tests run the production RunBatch
// and Run against a loopback sshd and the real ssh.
//
// The user's configuration comes from a fixture. sshProgram is a wrapper that adds -F and
// nothing else, because OpenSSH reads the user's configuration directory from the passwd
// entry, not from HOME.
//
// Each helper is a canary that records what it reads from stdin. The remote command is a
// stand-in worker: it saves exactly the request bytes it receives and answers with a canned
// error, which comes back through the production decoder. The worker implements no protocol.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	batchCanned    = "stand-in worker received the request"
	batchTimeoutMs = 1000
	batchTarget    = "via-batch-test"
)

// batchCanarySource is a PKCS#11 module. ssh loads it only if its bytes contain the
// marker. The constructor runs when it loads, and records what fd 0 holds.
const batchCanarySource = `#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
static const char pkcs11_marker[] __attribute__((used)) = "C_GetFunctionList";
__attribute__((constructor)) static void canary(void) {
	char buf[512];
	ssize_t n = 0;
	struct pollfd p = {0, POLLIN, 0};
	if (poll(&p, 1, 3000) > 0 && (p.revents & POLLIN)) n = read(0, buf, sizeof buf);
	int fd = open(OUT, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd >= 0) { if (n > 0) write(fd, buf, (size_t)n); close(fd); }
}
`

type batchLab struct {
	dir      string
	port     int
	user     string
	client   string // identity for the lab user
	hostKey  string // ed25519 host key trusted by known_hosts
	hostKey2 string // ecdsa host key the lab sshd also offers
	known    string // known_hosts trusting every lab sshd
	sshd     string
	ssh      string
	worker   string // saves the request, then answers
	quick    string // answers without reading stdin; for interactive controls
	body     []byte // the bytes the transport writes to stdin
	wrap     int
}

// newBatchLab starts a loopback sshd that accepts only the lab key. It skips where
// OpenSSH is not installed.
func newBatchLab(t *testing.T) *batchLab {
	t.Helper()
	keygen := lookTool(t, "ssh-keygen", "")
	who, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	dir, err := os.MkdirTemp("", "via-batch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l := &batchLab{dir: dir, user: who.Username, ssh: lookTool(t, "ssh", ""), sshd: lookTool(t, "sshd", "/usr/sbin/sshd")}

	hostKey, hostKey2, client := filepath.Join(dir, "hostkey"), filepath.Join(dir, "hostkey2"), filepath.Join(dir, "client")
	for _, key := range [][2]string{{"ed25519", hostKey}, {"ecdsa", hostKey2}, {"ed25519", client}} {
		if out, err := exec.Command(keygen, "-q", "-t", key[0], "-N", "", "-f", key[1]).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
	}
	l.client, l.hostKey, l.hostKey2 = client, hostKey, hostKey2
	pub, _ := os.ReadFile(client + ".pub")
	batchWrite(t, filepath.Join(dir, "authorized_keys"), string(pub), 0o600)
	l.known = filepath.Join(dir, "known_hosts")
	batchWrite(t, l.known, "", 0o600)

	l.port = l.startSSHD(t)

	reply, err := json.Marshal(Response{Protocol: Protocol, Error: batchCanned})
	if err != nil {
		t.Fatal(err)
	}
	batchWrite(t, filepath.Join(dir, "response.json"), string(reply), 0o600)
	l.body, err = marshalRequest(batchRequest())
	if err != nil {
		t.Fatal(err)
	}
	l.worker = l.workerWith(t, "worker", "")
	l.quick = l.script(t, "quick", fmt.Sprintf("cat %s/response.json\n", dir))
	return l
}

// startSSHD starts another loopback sshd on the lab keys, trusts its host key in known_hosts,
// and returns its port.
func (l *batchLab) startSSHD(t *testing.T) int {
	t.Helper()
	port := freeLoopbackPort(t)
	cfg := filepath.Join(l.dir, fmt.Sprintf("sshd_%d.config", port))
	batchWrite(t, cfg, fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
HostKey %s
AuthorizedKeysFile %s
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PerSourcePenalties no
LogLevel ERROR
`, port, l.hostKey, l.hostKey2, filepath.Join(l.dir, "authorized_keys")), 0o600)
	logFile, err := os.Create(cfg + ".log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	daemon := exec.Command(l.sshd, "-D", "-e", "-f", cfg)
	daemon.Stdout, daemon.Stderr = logFile, logFile
	if err := daemon.Start(); err != nil {
		t.Fatalf("start sshd: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_, _ = daemon.Process.Wait()
	})
	waitForPort(t, port)

	hostPub, _ := os.ReadFile(l.hostKey + ".pub")
	fields := strings.Fields(string(hostPub))
	f, err := os.OpenFile(l.known, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "[127.0.0.1]:%d %s %s\n", port, fields[0], fields[1]); err != nil {
		t.Fatal(err)
	}
	return port
}

func batchRequest() Request {
	return Request{Protocol: Protocol, Target: batchTarget, TimeoutMs: batchTimeoutMs}
}

// configure writes the user configuration ssh reads through the wrapper. before holds
// global lines, and inHost holds lines inside the lab host block.
func (l *batchLab) configure(t *testing.T, known, before, inHost string) {
	t.Helper()
	cfg := filepath.Join(l.dir, fmt.Sprintf("config-%d", l.wrap))
	batchWrite(t, cfg, fmt.Sprintf(`%s
Host lab
  HostName 127.0.0.1
  Port %d
  User %s
  IdentityFile %s
  IdentitiesOnly yes
  UserKnownHostsFile %s
  GlobalKnownHostsFile /dev/null
%s
`, before, l.port, l.user, l.client, known, inHost), 0o600)
	wrapper := l.script(t, fmt.Sprintf("ssh-%d", l.wrap), fmt.Sprintf("exec %s -F %s \"$@\"\n", l.ssh, cfg))
	l.wrap++
	previous := sshProgram
	sshProgram = wrapper
	t.Cleanup(func() { sshProgram = previous })
}

func (l *batchLab) script(t *testing.T, name, body string) string {
	return l.scriptWith(t, name, "/bin/sh", body)
}

// scriptWith writes an executable script run by interpreter, and returns its absolute path.
func (l *batchLab) scriptWith(t *testing.T, name, interpreter, body string) string {
	t.Helper()
	path := filepath.Join(l.dir, name)
	batchWrite(t, path, "#!"+interpreter+"\n"+body, 0o755)
	return path
}

// workerWith is the stand-in worker. prelude runs first, then it saves the request bytes.
func (l *batchLab) workerWith(t *testing.T, name, prelude string) string {
	return l.script(t, name, prelude+fmt.Sprintf("dd bs=1 count=%d of=%s 2>/dev/null\ncat %s\n",
		len(l.body), filepath.Join(l.dir, "worker-request"), filepath.Join(l.dir, "response.json")))
}

// run sends the request through batch or interactive transport to the given command.
func (l *batchLab) run(t *testing.T, batch bool, command string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var err error
	if batch {
		_, err = RunBatch(ctx, "lab", command, batchRequest())
	} else {
		_, err = Run(ctx, "lab", command, batchRequest())
	}
	return err
}

// requireWorkerGotRequest fails unless the worker received every request byte and the
// decoder returned the worker's answer.
func (l *batchLab) requireWorkerGotRequest(t *testing.T, err error) {
	t.Helper()
	got, readErr := os.ReadFile(filepath.Join(l.dir, "worker-request"))
	if readErr != nil || !bytes.Equal(got, l.body) {
		t.Fatalf("worker received %q (%v); want the %d request bytes intact", got, readErr, len(l.body))
	}
	if err == nil || !strings.Contains(err.Error(), batchCanned) {
		t.Fatalf("the production decoder did not return the worker's answer: %v", err)
	}
}

// requireNoRead fails if the canary read anything from stdin. A canary that never ran
// passes, so a control must show the same configuration does run it.
func requireNoRead(t *testing.T, canary string) {
	t.Helper()
	if b, err := os.ReadFile(canary); err == nil && len(b) > 0 {
		t.Fatalf("read %d bytes of the request from stdin: %q", len(b), b)
	}
}

// requireRead fails unless the canary ran and read the request.
func requireRead(t *testing.T, canary string) {
	t.Helper()
	b, err := os.ReadFile(canary)
	if err != nil || len(b) == 0 {
		t.Fatalf("control: the canary did not read stdin (%v, %d bytes)", err, len(b))
	}
}

// TestBatchStdinIsNotReadByHelpers: each configured helper that ssh can start under batch
// must not take the request from stdin, and the worker must still get it intact.
func TestBatchStdinIsNotReadByHelpers(t *testing.T) {
	t.Run("LocalCommand", func(t *testing.T) {
		lab := newBatchLab(t)
		canary := filepath.Join(lab.dir, "localcommand-stdin")
		lc := lab.script(t, "localcommand", "cat > "+canary+"\n")
		lab.configure(t, lab.known, "", "  PermitLocalCommand yes\n  LocalCommand "+lc)
		err := lab.run(t, true, lab.worker)
		requireNoRead(t, canary)
		lab.requireWorkerGotRequest(t, err)

		// Control: the interactive transport runs this LocalCommand, and it reads the request.
		os.Remove(canary)
		_ = lab.run(t, false, lab.quick)
		requireRead(t, canary)
	})

	// The next two subtests guard OpenSSH's own behaviour, not a pin: Match exec and
	// KnownHostsCommand run with /dev/null as stdin. No batch pin changes that, so they pass
	// with or without the pins, and they fail only if OpenSSH stops doing it.
	t.Run("MatchExec", func(t *testing.T) {
		lab := newBatchLab(t)
		canary := filepath.Join(lab.dir, "match-stdin")
		match := lab.script(t, "match", "cat > "+canary+"\nexit 0\n")
		lab.configure(t, lab.known, fmt.Sprintf("Match exec %q", match), "")
		err := lab.run(t, true, lab.worker)
		// Match exec runs during the connection, so the canary must exist: that shows it ran.
		if _, statErr := os.Stat(canary); statErr != nil {
			t.Fatalf("Match exec did not run: %v", statErr)
		}
		requireNoRead(t, canary)
		lab.requireWorkerGotRequest(t, err)
	})

	t.Run("KnownHostsCommand", func(t *testing.T) {
		lab := newBatchLab(t)
		canary := filepath.Join(lab.dir, "knownhosts-stdin")
		khc := lab.script(t, "knownhosts", fmt.Sprintf("cat > %s\ncat %s\n", canary, lab.known))
		lab.configure(t, "none", "", "  KnownHostsCommand "+khc+" %H")
		err := lab.run(t, true, lab.worker)
		if _, statErr := os.Stat(canary); statErr != nil {
			t.Fatalf("KnownHostsCommand did not run: %v", statErr)
		}
		requireNoRead(t, canary)
		lab.requireWorkerGotRequest(t, err)
	})

	t.Run("PKCS11Provider", func(t *testing.T) {
		lab := newBatchLab(t)
		cc, err := exec.LookPath("cc")
		if err != nil {
			t.Skip("needs a C compiler to build the PKCS#11 canary")
		}
		out := filepath.Join(lab.dir, "pkcs11-stdin")
		src := filepath.Join(lab.dir, "canary.c")
		batchWrite(t, src, fmt.Sprintf("#define OUT %q\n%s", out, batchCanarySource), 0o600)
		module := filepath.Join(lab.dir, "libcanary.so")
		if b, err := exec.Command(cc, "-shared", "-fPIC", "-o", module, src).CombinedOutput(); err != nil {
			t.Fatalf("build canary: %v %s", err, b)
		}
		lab.configure(t, lab.known, "", "  PKCS11Provider "+module)
		err = lab.run(t, true, lab.worker)
		requireNoRead(t, out)
		lab.requireWorkerGotRequest(t, err)

		// Control: the interactive transport loads the module and reads the request.
		os.Remove(out)
		_ = lab.run(t, false, lab.quick)
		requireRead(t, out)
	})
}

func lookTool(t *testing.T, name, fallback string) string {
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

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForPort(t *testing.T, port int) {
	t.Helper()
	addr := "127.0.0.1:" + strconv.Itoa(port)
	waitUntil(t, 10*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, "sshd did not listen on "+addr)
}

// waitUntil polls cond until it holds, and fails the test with what if timeout passes first.
func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func batchWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
