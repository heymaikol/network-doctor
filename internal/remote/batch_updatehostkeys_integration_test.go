//go:build integration

package remote

import (
	"os"
	"testing"
)

// TestBatchNeverUpdatesKnownHosts: after authentication the server offers its other host keys,
// and UpdateHostKeys yes in the user's configuration adds them to known_hosts without asking.
// Batch must not write that trust. The session must run, so the update had its chance.
func TestBatchNeverUpdatesKnownHosts(t *testing.T) {
	lab := newBatchLab(t)
	lab.configure(t, lab.known, "", "  UpdateHostKeys yes")
	before, err := os.ReadFile(lab.known)
	if err != nil {
		t.Fatal(err)
	}
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
