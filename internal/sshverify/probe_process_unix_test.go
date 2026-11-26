//go:build unix

package sshverify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A descendant of the probe must not outlive it. The probe is cancelled at its deadline, and its
// whole process group goes with it, so a child that would write a file a few seconds later never
// does. The probe also returns at once, although the child held its output open.
func TestProbeProcessGroupEndsWithItsDescendants(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "descendant-ran")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	script := "(sleep 2; touch " + marker + ") & sleep 30"
	_, _, err := runHostKeyProbe(ctx, "/bin/sh", []string{"-c", script})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the probe waited %v for a descendant that holds its output (err %v)", elapsed, err)
	}
	time.Sleep(3 * time.Second)
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("a descendant of the probe kept running after the probe was cancelled")
	}
}

// A descendant left holding standard error open when the probe exits normally must be killed with
// the probe's process group instead of surviving past WaitDelay.
func TestProbeProcessGroupEndsOnNormalExit(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "normal-exit-descendant-ran")
	start := time.Now()
	script := "(sleep 2; touch " + marker + ") & exit 255"
	_, _, err := runHostKeyProbe(context.Background(), "/bin/sh", []string{"-c", script})
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("the probe waited %v after normal exit for a descendant holding stderr (err %v)", elapsed, err)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("a descendant of the probe kept running after normal exit")
	}
}

// terminateProcessGroup ends the group it is given and no other. The leader exits at once and leaves a
// member in its group, which the cleanup must end. A process in another group must survive it.
func TestTerminateProcessGroupLeavesOtherProcessesAlone(t *testing.T) {
	leader := exec.Command("/bin/sh", "-c", "sleep 30 & exit 0")
	leader.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := leader.Start(); err != nil {
		t.Fatal(err)
	}
	pid := leader.Process.Pid
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
	if err := leader.Wait(); err != nil {
		t.Fatal(err)
	}
	bystander := exec.Command("/bin/sh", "-c", "exec sleep 30")
	bystander.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(bystander.Process.Pid, syscall.SIGKILL)
		_ = bystander.Wait()
	})
	if syscall.Kill(-pid, 0) != nil {
		t.Fatal("the leader left no member in its group, so the cleanup had nothing to end")
	}
	terminateProcessGroup(pid)
	var status syscall.WaitStatus
	if reaped, err := syscall.Wait4(bystander.Process.Pid, &status, syscall.WNOHANG, nil); reaped != 0 || err != nil {
		t.Fatalf("a process in another group was ended: reaped %d, status %v, err %v", reaped, status, err)
	}
}
