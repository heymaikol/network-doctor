//go:build integration

package remote

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBatchNeverRidesAControlMaster: the user's configuration names a live control master on
// another server. The control shows the ordinary transport rides it. Batch must not: its
// request would reach a server this acquisition did not choose, under authentication it did
// not make. The worker records SSH_CONNECTION, whose last field is its session's server port.
func TestBatchNeverRidesAControlMaster(t *testing.T) {
	lab := newBatchLab(t)
	other := lab.startSSHD(t)
	sock := filepath.Join(lab.dir, "master.sock")
	conn := filepath.Join(lab.dir, "connection")
	worker := lab.script(t, "conn-worker", fmt.Sprintf(
		"printf '%%s' \"$SSH_CONNECTION\" > %s\ndd bs=1 count=%d of=%s 2>/dev/null\ncat %s/response.json\n",
		conn, len(lab.body), filepath.Join(lab.dir, "worker-request"), lab.dir))
	lab.configure(t, lab.known, "", fmt.Sprintf("  ControlMaster auto\n  ControlPath %s", sock))

	// The master: a real connection to the other server, kept alive by ControlPersist.
	// The command-line Port overrides the configuration's.
	master := exec.Command(sshProgram, "-M", "-N", "-f", "-o", "ControlPersist=60",
		"-o", fmt.Sprintf("Port=%d", other), "lab")
	if out, err := master.CombinedOutput(); err != nil {
		t.Fatalf("start control master: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(sshProgram, "-O", "exit", "lab").Run() })
	waitForMaster(t, sshProgram)

	// The control: the ordinary transport reuses the master, so its session is on the other server.
	if err := lab.run(t, false, worker); err != nil && !strings.Contains(err.Error(), batchCanned) {
		t.Fatalf("control run: %v", err)
	}
	if got := serverPort(t, conn); got != other {
		t.Fatalf("control session on port %d, want the master's server %d: the test would prove nothing", got, other)
	}

	// The invariant: batch never rides the master. Its session is on the lab server.
	os.Remove(conn)
	err := lab.run(t, true, worker)
	lab.requireWorkerGotRequest(t, err)
	if got := serverPort(t, conn); got != lab.port {
		t.Fatalf("batch session ran on port %d (the control master's server), want %d", got, lab.port)
	}
}

// serverPort reads the server port from a recorded SSH_CONNECTION: client address, client
// port, server address, server port.
func serverPort(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no connection record: %v", err)
	}
	fields := strings.Fields(string(b))
	if len(fields) != 4 {
		t.Fatalf("SSH_CONNECTION = %q", b)
	}
	port, err := strconv.Atoi(fields[3])
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// waitForMaster polls the control socket until ssh reports the master is up.
func waitForMaster(t *testing.T, ssh string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if exec.Command(ssh, "-O", "check", "lab").Run() == nil {
			return
		}
	}
	t.Fatal("control master did not come up")
}
