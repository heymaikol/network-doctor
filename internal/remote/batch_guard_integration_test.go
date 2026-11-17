//go:build integration

package remote

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestBatchNeverUsesTheAgentForIdentity: an agent that holds an authorized key can
// authenticate an interactive session. Batch must not use it: IdentityAgent=none leaves the
// batch session with no identity to offer, so it cannot connect at all.
func TestBatchNeverUsesTheAgentForIdentity(t *testing.T) {
	lab := newBatchLab(t)
	lab.startAgent(t)
	pub, err := os.ReadFile(filepath.Join(lab.dir, agentKeyName+".pub"))
	if err != nil {
		t.Fatal(err)
	}
	batchWrite(t, filepath.Join(lab.dir, "authorized_keys"), string(pub), 0o600)
	lab.configure(t, lab.known, "IdentitiesOnly no", "")
	ran := filepath.Join(lab.dir, "agent-session")
	worker := lab.script(t, "agent-worker", "echo ran > "+ran+"\n"+
		"dd bs=1 count="+strconv.Itoa(len(lab.body))+" of="+filepath.Join(lab.dir, "worker-request")+" 2>/dev/null\n"+
		"cat "+filepath.Join(lab.dir, "response.json")+"\n")

	// Control: the interactive transport authenticates with the agent's key and runs the session.
	_ = lab.run(t, false, worker)
	if _, err := os.Stat(ran); err != nil {
		t.Fatalf("control: the agent did not authenticate the interactive session: %v", err)
	}
	os.Remove(ran)

	os.Remove(filepath.Join(lab.dir, "worker-request"))
	err = lab.run(t, true, worker)
	lab.requireNoSession(t, err)
}

// TestBatchNeverRunsAskpass: an encrypted identity needs a passphrase. With SSH_ASKPASS set
// and SSH_ASKPASS_REQUIRE=force inherited from the environment, the interactive transport asks
// the askpass helper for it. Batch must not run the helper at all (BatchMode refuses the question).
func TestBatchNeverRunsAskpass(t *testing.T) {
	lab := newBatchLab(t)
	enc := filepath.Join(lab.dir, "enc")
	if out, err := exec.Command(lookTool(t, "ssh-keygen", ""), "-q", "-t", "ed25519", "-N", "pw", "-f", enc).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	pub, _ := os.ReadFile(enc + ".pub")
	f, err := os.OpenFile(filepath.Join(lab.dir, "authorized_keys"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(pub); err != nil {
		t.Fatal(err)
	}
	f.Close()
	ran := filepath.Join(lab.dir, "askpass-ran")
	ask := lab.script(t, "askpass", "echo ran >> "+ran+"\necho pw\n")
	t.Setenv("SSH_ASKPASS", ask)
	t.Setenv("SSH_ASKPASS_REQUIRE", "force")
	lab.configure(t, lab.known, "IdentityFile "+enc+"\nIdentitiesOnly yes", "")

	// Control: the interactive transport asks for the passphrase.
	_ = lab.run(t, false, lab.quick)
	if b, _ := os.ReadFile(ran); len(b) == 0 {
		t.Fatal("control: the interactive transport never asked askpass for the passphrase")
	}
	os.Remove(ran)

	err = lab.run(t, true, lab.worker)
	lab.requireWorkerGotRequest(t, err)
	if _, statErr := os.Stat(ran); statErr == nil {
		t.Fatal("batch ran the askpass helper")
	}
}

const agentKeyName = "agentkey"
