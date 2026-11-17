//go:build integration

package remote

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestBatchNeverWritesOrAcceptsAHostKey: the user's configuration can tell ssh to write an
// unknown host key without asking (accept-new), or to connect to a host whose key changed
// (no). Batch cannot answer either question, so it must refuse both before a session starts.
func TestBatchNeverWritesOrAcceptsAHostKey(t *testing.T) {
	t.Run("accept-new writes nothing", func(t *testing.T) {
		lab := newBatchLab(t)
		empty := filepath.Join(lab.dir, "empty_known_hosts")
		batchWrite(t, empty, "", 0o600)
		lab.configure(t, empty, "", "  StrictHostKeyChecking accept-new")
		err := lab.run(t, true, lab.worker)
		if b, _ := os.ReadFile(empty); len(b) > 0 {
			t.Fatalf("batch wrote a host key to known_hosts: %q", b)
		}
		lab.requireNoSession(t, err)
	})

	t.Run("no accepts nothing changed", func(t *testing.T) {
		lab := newBatchLab(t)
		changed := filepath.Join(lab.dir, "changed_known_hosts")
		batchWrite(t, changed, lab.otherHostKeyLine(t), 0o600)
		lab.configure(t, changed, "", "  StrictHostKeyChecking no")
		err := lab.run(t, true, lab.worker)
		lab.requireNoSession(t, err)
	})
}

// requireNoSession fails if a session ran. The stand-in worker writes the request when it runs.
func (l *batchLab) requireNoSession(t *testing.T, err error) {
	t.Helper()
	if _, statErr := os.Stat(filepath.Join(l.dir, "worker-request")); statErr == nil {
		t.Fatalf("a session ran on a host key batch should refuse (transport: %v)", err)
	}
}

// otherHostKeyLine returns a known_hosts line that trusts a different key for the lab server.
func (l *batchLab) otherHostKeyLine(t *testing.T) string {
	t.Helper()
	keygen := lookTool(t, "ssh-keygen", "")
	key := filepath.Join(l.dir, "other")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(pub))
	return "[127.0.0.1]:" + strconv.Itoa(l.port) + " " + fields[0] + " " + fields[1] + "\n"
}
