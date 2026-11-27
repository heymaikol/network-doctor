//go:build integration

package remote

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBatchNeverForwardsTheAgent: the user's configuration can ask for agent forwarding
// (ForwardAgent yes). The diagnosed host then gets a socket to the user's agent for the
// length of the session, and can sign with any key the agent holds. Batch must not give
// the remote that socket. The control shows the interactive transport does forward it.
//
// On OpenSSH 10.5, IdentityAgent=none already stops forwarding, so this passes without the
// ForwardAgent pin. The pin is guarded by TestBatchPinsWinOverUserConfiguration, which reads
// the effective value.
func TestBatchNeverForwardsTheAgent(t *testing.T) {
	lab := newBatchLab(t)
	lab.startAgent(t)
	list := filepath.Join(lab.dir, "agent-list")
	worker := lab.workerWith(t, "agent-worker", "ssh-add -l > "+list+" 2>&1\n")
	lab.configure(t, lab.known, "", "  ForwardAgent yes")

	// Control: the interactive transport forwards the agent, so the remote lists the key.
	_ = lab.run(t, false, worker)
	if b, _ := os.ReadFile(list); !strings.Contains(string(b), agentKeyComment) {
		t.Fatalf("control: the remote did not see the forwarded agent: %q", b)
	}
	os.Remove(list)

	err := lab.run(t, true, worker)
	lab.requireWorkerGotRequest(t, err)
	if b, _ := os.ReadFile(list); strings.Contains(string(b), agentKeyComment) {
		t.Fatalf("batch forwarded the agent: the remote listed the key: %q", b)
	}
}

const agentKeyComment = "via-agent-test"

// startAgent runs a private ssh-agent holding one key, and points SSH_AUTH_SOCK at it for
// the rest of the test, which is what a batch run inherits.
func (l *batchLab) startAgent(t *testing.T) {
	t.Helper()
	agent := lookTool(t, "ssh-agent", "")
	add := lookTool(t, "ssh-add", "")
	keygen := lookTool(t, "ssh-keygen", "")
	sock := filepath.Join(l.dir, "agent.sock")
	key := filepath.Join(l.dir, "agentkey")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", agentKeyComment, "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	daemon := exec.Command(agent, "-D", "-a", sock)
	if err := daemon.Start(); err != nil {
		t.Fatalf("start ssh-agent: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_, _ = daemon.Process.Wait()
	})
	waitUntil(t, 5*time.Second, func() bool {
		_, err := os.Stat(sock)
		return err == nil
	}, "ssh-agent did not create its socket")
	t.Setenv("SSH_AUTH_SOCK", sock)
	if out, err := exec.Command(add, "-q", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v %s", err, out)
	}
}
