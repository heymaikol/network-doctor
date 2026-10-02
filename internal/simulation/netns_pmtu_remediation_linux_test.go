//go:build netns_integration && linux

package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"golang.org/x/sys/unix"
)

// pmtuRemediationNetdoc is set only on the copy of this test binary that
// TestPMTUBlackholeRemediatedByMSSClamp launches as its director.
var pmtuRemediationNetdoc = flag.String("pmtu-remediation-netdoc", "", "internal: run the PMTU remediation director with this netdoc")

// pmtuRemediationRun is one pass over the black-holed network, with the
// simulator's own bulk-write reading taken from inside the client namespace.
type pmtuRemediationRun struct {
	Report *Report
	MSS    int
	Acked  int
	Err    string
}

const pmtuRemediationPayload = 24 << 10

// pmtu-blackhole proves netdoc detects the black hole. This proves the fix its
// path_mtu row recommends, clamping MSS on the router, actually resolves it:
// the same network, with only the clamp added, must move path_mtu from WARN to
// PASS, and an independent socket must see a smaller MSS and its whole payload
// acknowledged. Without it a fix hint that stopped working would go unnoticed.
//
// The two passes are separate runs because a run measures once between its
// faults and its cleanup. The clamp is installed through Env.Exec from a
// director this test re-executes, so the scenario schema gains nothing.
func TestPMTUBlackholeRemediatedByMSSClamp(t *testing.T) {
	if *pmtuRemediationNetdoc != "" {
		directPMTURemediation(t, *pmtuRemediationNetdoc)
		return
	}
	t.Parallel()
	requireBackend(t)
	netdoc, _ := buildBinaries(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	code, err := LaunchDirector(context.Background(), self, []string{
		"-test.run=^TestPMTUBlackholeRemediatedByMSSClamp$", "-test.v", "-pmtu-remediation-netdoc=" + netdoc,
	}, nil, &log, &log)
	if err != nil || code != 0 {
		t.Fatalf("director exit %d (%v):\n%s", code, err, log.String())
	}
	blob, err := os.ReadFile(filepath.Join(filepath.Dir(netdoc), "remediation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var runs [2]pmtuRemediationRun
	if err := json.Unmarshal(blob, &runs); err != nil {
		t.Fatal(err)
	}
	before, after := runs[0], runs[1]
	for _, run := range runs {
		if run.Report.Error != "" || run.Err != "" || len(run.Report.Tests) != 1 {
			t.Fatalf("run error %q, probe error %q, tests %+v", run.Report.Error, run.Err, run.Report.Tests)
		}
		assertCleanedUp(t, *run.Report)
	}
	assertHostMTUAndFirewallUntouched(t)
	t.Logf("before: MSS %d, %d bytes acknowledged; after: MSS %d, %d bytes acknowledged", before.MSS, before.Acked, after.MSS, after.Acked)

	// The baseline is the existing black hole, measured by both sides.
	warn := diagnosisCheck(before.Report.Tests[0], string(diagnostic.ProbePMTU))
	if warn.Status != "WARN" || !strings.Contains(warn.Detail, "none of it acknowledged") {
		t.Errorf("before clamp: path_mtu = %+v, want WARN with nothing acknowledged", warn)
	}
	if before.Acked != 0 {
		t.Errorf("before clamp: %d bytes acknowledged, want none across the black hole", before.Acked)
	}

	// The clamp has to be what changed: a smaller MSS that fits the 576-byte
	// hop, read off a socket netdoc did not open, and the same MSS in netdoc's
	// own row.
	if after.MSS <= 0 || after.MSS >= before.MSS || after.MSS > 576-40 {
		t.Errorf("MSS before %d, after %d: want the clamp to bring it under the hop's %d-byte MTU", before.MSS, after.MSS, 576)
	}
	pass := diagnosisCheck(after.Report.Tests[0], string(diagnostic.ProbePMTU))
	if pass.Status != "PASS" || !strings.Contains(pass.Detail, fmt.Sprintf("at a %d-byte TCP MSS", after.MSS)) {
		t.Errorf("after clamp: path_mtu = %+v, want PASS at the clamped %d-byte MSS", pass, after.MSS)
	}
	// netdoc stops at the first acknowledged byte; the whole payload is what
	// separates a fixed path from one that lets the odd segment through.
	if after.Acked != pmtuRemediationPayload {
		t.Errorf("after clamp: %d of %d bytes acknowledged, want all of it", after.Acked, pmtuRemediationPayload)
	}
}

// directPMTURemediation runs inside the director's namespaces. It runs the
// bulk-transfer test of pmtu-blackhole twice, the second time with MSS
// clamped on both routers, and leaves both reports beside netdoc.
func directPMTURemediation(t *testing.T, netdoc string) {
	var runs [2]pmtuRemediationRun
	for i, clamp := range []bool{false, true} {
		s, err := LibraryScenario("pmtu-blackhole")
		if err != nil {
			t.Fatal(err)
		}
		s.Tests = s.Tests[:1]
		b := &mssClampBackend{Backend: DefaultBackend(false, nil), clamp: clamp, run: &runs[i]}
		runs[i].Report = Run(context.Background(), s, b, Options{Netdoc: netdoc})
	}
	blob, err := json.Marshal(runs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(netdoc), "remediation.json"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

// mssClampBackend builds the ordinary network, optionally applies the
// remediation once the faults are in, and takes the independent bulk-write
// reading after netdoc has run and before the namespaces go away.
type mssClampBackend struct {
	Backend
	clamp bool
	run   *pmtuRemediationRun
}

func (b *mssClampBackend) Prepare(ctx context.Context, s *Scenario, id string) (Env, error) {
	env, err := b.Backend.Prepare(ctx, s, id)
	if env == nil {
		return nil, err
	}
	return &mssClampEnv{Env: env, b: b}, err
}

type mssClampEnv struct {
	Env
	b *mssClampBackend
}

// ApplyFaults adds, on both black-holed routers, the nftables form of the
// `iptables ... -j TCPMSS --clamp-mss-to-pmtu` netdoc recommends, in the
// simulator's own table that the fault already created.
func (e *mssClampEnv) ApplyFaults(ctx context.Context, faults []Fault) ([]FaultInfo, error) {
	info, err := e.Env.ApplyFaults(ctx, faults)
	if err != nil || !e.b.clamp {
		return info, err
	}
	for _, router := range []string{"edge", "core"} {
		for _, argv := range [][]string{
			{"nft", "add", "chain", "inet", nftTable, "mssclamp", "{ type filter hook forward priority mangle; }"},
			{"nft", "add", "rule", "inet", nftTable, "mssclamp", "tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", "rt", "mtu"},
		} {
			if res := e.Exec(ctx, router, argv, nil); res.Err != nil || res.ExitCode != 0 {
				return info, execResultError(res)
			}
		}
	}
	return info, nil
}

func (e *mssClampEnv) Cleanup(ctx context.Context, keep bool) CleanupInfo {
	if np := e.Env.(*netnsEnv).byName["client"]; np != nil {
		mss, acked, err := bulkWriteFrom(np.pid, "10.77.3.30:80")
		e.b.run.MSS, e.b.run.Acked = mss, acked
		if err != nil {
			e.b.run.Err = err.Error()
		}
	}
	return e.Env.Cleanup(ctx, keep)
}

// bulkWriteFrom repeats the manual experiment behind this test from inside the
// namespace of pid: connect, read the MSS, write 24 KiB of an HTTP request body
// the server discards, and count what the peer acknowledges within 2 seconds.
func bulkWriteFrom(pid int, addr string) (mss, acked int, err error) {
	// The thread is put back before it is unlocked. Letting it exit instead
	// would kill any holder it forked, since holders set Pdeathsig.
	runtime.LockOSThread()
	home, err := os.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
	if err != nil {
		return 0, 0, err
	}
	defer home.Close()
	ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return 0, 0, err
	}
	defer ns.Close()
	if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET); err != nil {
		return 0, 0, err
	}
	defer func() {
		if unix.Setns(int(home.Fd()), unix.CLONE_NEWNET) == nil {
			runtime.UnlockOSThread()
		}
	}()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	sockopt := func(read func(fd int) (int, error)) (n int, err error) {
		if ctrlErr := raw.Control(func(fd uintptr) { n, err = read(int(fd)) }); ctrlErr != nil {
			return 0, ctrlErr
		}
		return n, err
	}
	mss, err = sockopt(func(fd int) (int, error) { return unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG) })
	if err != nil {
		return 0, 0, err
	}
	header := fmt.Sprintf("POST / HTTP/1.1\r\nHost: target\r\nContent-Length: %d\r\n\r\n", pmtuRemediationPayload)
	payload := append([]byte(header), bytes.Repeat([]byte{'x'}, pmtuRemediationPayload-len(header))...)
	deadline := time.Now().Add(2 * time.Second)
	_ = conn.SetWriteDeadline(deadline)
	written, err := conn.Write(payload)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return 0, 0, err
	}
	for {
		queued, err := sockopt(func(fd int) (int, error) { return unix.IoctlGetInt(fd, unix.SIOCOUTQ) })
		if err != nil {
			return 0, 0, err
		}
		if queued == 0 || !time.Now().Before(deadline) {
			return mss, written - queued, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}
