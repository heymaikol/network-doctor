//go:build linux

package simulation

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestAwaitReadsHolderLogsSafely drives the setup-failure path: a holder that
// answers the wrong line is still running and still writing to stderr while
// await reads that stderr to explain itself. The assertions are deterministic;
// the concurrency is the point, so run it under -race, where dropping safeLog's
// lock reports a data race on a good fraction of runs.
func TestAwaitReadsHolderLogsSafely(t *testing.T) {
	// Answers the wrong line, then keeps stderr busy while await explains itself.
	cmd := exec.Command("sh", "-c", `echo wrong; i=0; while [ $i -lt 20000 ]; do echo noise >&2; i=$((i+1)); done`)
	np := &nodeProc{node: &Node{Name: "n"}, logs: new(safeLog)}
	cmd.Stderr = np.logs
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	np.cmd, np.stdout, np.pid = cmd, bufio.NewReader(stdout), cmd.Process.Pid

	if err := np.await(context.Background(), holderNSReady); err == nil {
		t.Error("await must reject a holder that said the wrong thing")
	}
	if err := np.stop(context.Background()); err != nil {
		t.Errorf("stop: %v", err)
	}
	if err := np.stop(context.Background()); err != nil {
		t.Errorf("stop is called from every exit path, so it has to be idempotent: %v", err)
	}
}

func TestFinishEvidenceRecordingReturnsCloseFailure(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "evidence-")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	err = finishEvidenceRecording(nil, &evidenceRecorder{node: "client", file: f})
	if !errors.Is(err, os.ErrClosed) || !strings.Contains(err.Error(), `finalize evidence recording for node "client"`) {
		t.Fatalf("close error = %v", err)
	}
}

func TestFinishEvidenceRecordingJoinsExecutionAndCloseFailures(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "evidence-")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	primary := errors.New("service execution failed")

	err = finishEvidenceRecording(primary, &evidenceRecorder{node: "client", file: f})
	if !errors.Is(err, primary) || !errors.Is(err, os.ErrClosed) || !strings.Contains(err.Error(), "finalize evidence recording") {
		t.Fatalf("joined error = %v", err)
	}
}

func TestCloseServicesReturnsCloseFailure(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "service-")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := closeServices([]io.Closer{f}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("close services error = %v", err)
	}
}

func TestNodeStopReturnsHolderFailure(t *testing.T) {
	cmd := exec.Command("sh", "-c", `echo 'record evidence for node client: broken pipe' >&2; exit 7`)
	np := &nodeProc{node: &Node{Name: "client"}, logs: new(safeLog)}
	cmd.Stderr = np.logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	np.cmd, np.pid = cmd, cmd.Process.Pid

	err := np.stop(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exit status 7") || !strings.Contains(err.Error(), "record evidence") {
		t.Fatalf("stop error = %v", err)
	}
}

// startFailedHolder starts a child that explains itself on stderr and exits
// nonzero without ever answering, the shape of a holder whose services could
// not come up.
func startFailedHolder(t *testing.T) *nodeProc {
	t.Helper()
	cmd := exec.Command("sh", "-c", `echo 'bind 127.0.0.1:53: address already in use' >&2; exit 9`)
	np := &nodeProc{node: &Node{Name: "client"}, logs: new(safeLog)}
	cmd.Stderr = np.logs
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	np.cmd, np.stdout, np.pid = cmd, bufio.NewReader(stdout), cmd.Process.Pid
	return np
}

// A holder that dies during setup fails setup, and await says so. Cleanup then
// reaps it, which is not a second failure: the exit it finds is the one the
// caller already has. Reporting it again claimed teardown had failed on an
// environment whose resources were all released.
func TestNodeStopIgnoresAlreadyReportedHolderExit(t *testing.T) {
	np := startFailedHolder(t)

	err := np.await(context.Background(), holderServicesReady)
	if err == nil {
		t.Fatal("await must report a holder that died instead of answering")
	}
	// The primary error is the one that has to carry the diagnosis.
	if !strings.Contains(err.Error(), holderServicesReady) || !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("await error = %v, want the expected reply and the holder's stderr", err)
	}

	if err := np.stop(context.Background()); err != nil {
		t.Errorf("stop reported an exit await had already reported: %v", err)
	}
	if np.cmd.ProcessState == nil {
		t.Error("stop returned without reaping the holder")
	}
	if err := np.stop(context.Background()); err != nil {
		t.Errorf("stop is called from every exit path, so it has to be idempotent: %v", err)
	}
}

// The same holder death, with nothing having read its stdout, is cleanup's own
// discovery and stays cleanup's error.
func TestNodeStopReportsUnobservedHolderExit(t *testing.T) {
	np := startFailedHolder(t)

	err := np.stop(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exit status 9") || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("stop error = %v, want the unobserved holder exit", err)
	}
}

// Cleanup releases what the simulator owns. A setup failure the caller already
// holds must not come back as a teardown failure, or a run that cleaned up
// perfectly reports that it did not.
func TestCleanupSucceedsAfterReportedHolderFailure(t *testing.T) {
	np := startFailedHolder(t)
	if err := np.await(context.Background(), holderServicesReady); err == nil {
		t.Fatal("await must report a holder that died instead of answering")
	}
	work := t.TempDir()
	env := &netnsEnv{backend: &netnsBackend{}, id: "sim", work: work, nodes: []*nodeProc{np}}

	info := env.Cleanup(context.Background(), false)
	if !info.Done || len(info.Errors) != 0 {
		t.Fatalf("cleanup = %+v, want a clean release", info)
	}
	if _, err := os.Stat(work); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("workspace %s survived cleanup: %v", work, err)
	}
}

func TestNodeStopReturnsForcedKillFailure(t *testing.T) {
	cmd := exec.Command("sleep", "10")
	np := &nodeProc{node: &Node{Name: "client"}, logs: new(safeLog)}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	np.cmd, np.pid = cmd, cmd.Process.Pid
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := np.stop(ctx); err == nil {
		t.Fatal("forced holder termination was reported as successful cleanup")
	}
}

func TestStartServicesStartsHolderWithoutServices(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	np := &nodeProc{node: &Node{Name: "client"}, stdin: writer,
		stdout: bufio.NewReader(strings.NewReader(holderServicesReady + "\n")), logs: new(safeLog)}

	err = (&netnsEnv{backend: &netnsBackend{}}).startServices(context.Background(), np)
	if closeErr := writer.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != holderStart+"\n" {
		t.Fatalf("holder command = %q, want %q", got, holderStart+"\n")
	}
}

func TestNetemFaultArgvIsGeneratedAndSeeded(t *testing.T) {
	logical := &Interface{Segment: "upstream"}
	np := &nodeProc{pid: 42, node: &Node{Name: "gateway"}, ifaces: []*interfaceProc{{logical: logical, iface: "neabc1230"}}}
	env := &netnsEnv{}
	steps, _, err := env.faultSteps(Fault{Type: FaultNetem, Node: "gateway", Segment: "upstream",
		Delay: "40ms", Jitter: "20ms", Loss: "15.25%", Seed: 12345}, np)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(steps[0], " ")
	for _, want := range []string{"tc qdisc replace", "dev neabc1230 root netem", "delay 40ms 20ms", "loss 15.25%", "seed 12345"} {
		if !strings.Contains(got, want) {
			t.Errorf("argv %q does not contain %q", got, want)
		}
	}
}

// A drop rule has to feed a counter, or the run ends with no way to tell a rule
// that swallowed traffic from one that never saw any. The counter's name comes
// from the fault, so the evidence collector can find it again from the scenario.
func TestDropFaultArgvCountsWhatItDrops(t *testing.T) {
	np := &nodeProc{pid: 42, node: &Node{Name: "internet"}}
	env := &netnsEnv{tables: map[string]bool{}}
	fault := Fault{Type: FaultDrop, Node: "internet", Direction: DirectionInbound, Protocol: "udp", Port: 443}
	steps, _, err := env.faultSteps(fault, np)
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, step := range steps {
		all += strings.Join(step, " ") + "\n"
	}
	counter := dropCounterName(fault)
	for _, want := range []string{
		"nft add counter inet " + nftTable + " " + counter,
		"udp dport 443 counter name " + counter + " drop",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("steps do not contain %q:\n%s", want, all)
		}
	}
	// Distinct faults must not share a counter, or one rule's traffic would
	// stand as evidence for another's.
	outbound := dropCounterName(Fault{Type: FaultDrop, Node: "internet", Direction: DirectionOutbound, Family: "ipv4"})
	if outbound == counter {
		t.Errorf("inbound and outbound drops share counter %q", counter)
	}
	for _, name := range []string{counter, outbound, dropCounterName(Fault{To: "2001:db8::1"})} {
		if strings.IndexFunc(name, func(r rune) bool { return !isNftNameRune(r) }) >= 0 {
			t.Errorf("counter name %q is not an nft identifier", name)
		}
	}
}

// A drop scoped to both a destination and a port has to carry both matches in
// one rule. Either half missing widens the fault: without the address it takes
// out every host on that port, and without the port it takes out every service
// on that host. The encrypted-DNS isolation scenario is built entirely out of
// that narrowness, since the address it blocks on 443 is one the direct-egress
// row is expected to keep reaching on another address.
func TestDropFaultArgvScopesDestinationAndPort(t *testing.T) {
	np := &nodeProc{pid: 42, node: &Node{Name: "client"}}
	env := &netnsEnv{tables: map[string]bool{}}
	doh := Fault{Type: FaultDrop, Node: "client", Direction: DirectionOutbound, Protocol: "tcp", Port: 443, To: "1.1.1.1"}
	dot := Fault{Type: FaultDrop, Node: "client", Direction: DirectionOutbound, Protocol: "tcp", Port: 853, To: "1.1.1.1"}
	all := ""
	for _, fault := range []Fault{doh, dot} {
		steps, summary, err := env.faultSteps(fault, np)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			all += strings.Join(step, " ") + "\n"
		}
		if want := "client refuses tcp traffic to 1.1.1.1 port " + strconv.Itoa(fault.Port); summary != want {
			t.Errorf("summary = %q, want %q", summary, want)
		}
	}
	for _, want := range []string{
		"ip daddr 1.1.1.1 tcp dport 443 counter name " + dropCounterName(doh) + " drop",
		"ip daddr 1.1.1.1 tcp dport 853 counter name " + dropCounterName(dot) + " drop",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("steps do not contain %q:\n%s", want, all)
		}
	}
	// One counter per transport, or a run could not say which of the two
	// blocked ports actually swallowed anything.
	if dropCounterName(doh) == dropCounterName(dot) {
		t.Errorf("both encrypted-DNS drops feed counter %q", dropCounterName(doh))
	}
}

// The black hole is two commands that have to arrive together: narrowing the
// hop without suppressing the report produces ordinary PMTU discovery, and
// suppressing without narrowing produces nothing at all. The suppression must
// also be narrow, the output hook and one ICMP code per family, or the fault
// stops being a black hole and becomes a dead control plane.
func TestPMTUBlackholeFaultArgv(t *testing.T) {
	logical := &Interface{Segment: "transit"}
	np := &nodeProc{pid: 42, node: &Node{Name: "edge"}, ifaces: []*interfaceProc{{logical: logical, iface: "neabc1230"}}}
	env := &netnsEnv{tables: map[string]bool{}}
	steps, summary, err := env.faultSteps(Fault{Type: FaultPMTUBlackhole, Node: "edge", Segment: "transit", MTU: 576}, np)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(steps[0], " ")
	if !strings.Contains(got, "ip link set neabc1230 mtu 576") {
		t.Errorf("first step %q does not narrow the interface", got)
	}
	all := ""
	for _, step := range steps {
		all += strings.Join(step, " ") + "\n"
	}
	for _, want := range []string{
		"hook output priority 0",
		"icmp type destination-unreachable icmp code frag-needed drop",
		"icmpv6 type packet-too-big drop",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("steps do not contain %q:\n%s", want, all)
		}
	}
	// Anything broader would drop traffic the fault is not modelling.
	for _, unwanted := range []string{"hook forward", "hook postrouting", "meta l4proto icmp drop"} {
		if strings.Contains(all, unwanted) {
			t.Errorf("steps contain over-broad rule %q:\n%s", unwanted, all)
		}
	}
	if !strings.Contains(summary, "576") {
		t.Errorf("summary = %q, want it to name the MTU", summary)
	}
}

// The version gate decides whether seeded loss and jitter scenarios can run at
// all, and it reads a string from another project, so pin the shapes it sees.
func TestParseNetemSeedSupport(t *testing.T) {
	for _, c := range []struct {
		out     string
		want    bool
		version string
	}{
		{"tc utility, iproute2-6.17.0\n", true, "6.17.0"},
		{"tc utility, iproute2-6.6.0", true, "6.6.0"},
		{"tc utility, iproute2-6.5.0", false, "6.5.0"},
		{"tc utility, iproute2-6.1.0", false, "6.1.0"},
		{"tc utility, iproute2-7.0.0", true, "7.0.0"},
		{"tc utility, iproute2-5.15.0", false, "5.15.0"},
		// Pre-6.x releases named a snapshot, not a version.
		{"tc utility, iproute2-ss200127", false, "ss200127"},
		{"something else entirely", false, "something else entirely"},
	} {
		got, version := parseNetemSeedSupport(c.out)
		if got != c.want || version != c.version {
			t.Errorf("parseNetemSeedSupport(%q) = %t %q, want %t %q", c.out, got, version, c.want, c.version)
		}
	}
}
