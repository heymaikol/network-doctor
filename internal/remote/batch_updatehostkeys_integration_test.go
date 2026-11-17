//go:build integration

package remote

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBatchNeverUpdatesKnownHosts: after authentication the server offers its other host keys,
// and UpdateHostKeys yes in the user's configuration adds them to known_hosts without asking.
// The interactive control shows the server offers them and ssh writes them, so the batch
// result is not vacuous. Batch must not write them.
func TestBatchNeverUpdatesKnownHosts(t *testing.T) {
	lab := newBatchLab(t)
	before, err := os.ReadFile(lab.known)
	if err != nil {
		t.Fatal(err)
	}

	control := filepath.Join(lab.dir, "control_known_hosts")
	batchWrite(t, control, string(before), 0o600)
	lab.configure(t, control, "", "  UpdateHostKeys yes")
	_ = lab.run(t, false, lab.worker)
	if got, _ := os.ReadFile(control); string(got) == string(before) {
		t.Fatal("control: the interactive transport did not add the server's other host keys")
	}

	os.Remove(filepath.Join(lab.dir, "worker-request"))
	lab.configure(t, lab.known, "", "  UpdateHostKeys yes")
	err = lab.run(t, true, lab.worker)
	lab.requireWorkerGotRequest(t, err)
	after, err := os.ReadFile(lab.known)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("batch changed known_hosts after authentication: %q", after)
	}
}
