//go:build linux && netns_integration

package diagnostic

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A veth pair whose two ends sit in different namespaces is one link, so the
// link-local address on each end is a real peer on the link the other end is
// on. The client binds its source through the interface --iface selects and
// dials the peer through that same interface's zone. The client namespace also
// holds a second link, to show a destination zone that names another interface
// is refused rather than sent out of the selected one.
const (
	linkLocalClientEnv = "NETDOC_LINKLOCAL_CLIENT"
	linkLocalServerEnv = "NETDOC_LINKLOCAL_SERVER"
	linkLocalTCPPort   = 9000
	linkLocalUDPPort   = 9001
	linkLocalPeerLine  = "LINKLOCAL PEER ADDR "
	linkLocalDoneLine  = "LINKLOCAL SOURCE OK"
)

func TestLinkLocalSourceBindsThroughItsInterface(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		skipOrRequireNetns(t, "ip(8) is needed to build the veth link")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLinkLocalSourceClientHelper$", "-test.v", "-test.timeout=90s") //nolint:gosec // G204: re-runs this test binary with a fixed helper name.
	cmd.Env = append(os.Environ(), linkLocalClientEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	out, err := cmd.CombinedOutput()
	if errors.Is(err, syscall.EPERM) {
		skipOrRequireNetns(t, fmt.Sprintf("unprivileged user namespaces are not available: %v", err))
	}
	if err != nil {
		t.Fatalf("namespace client failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), linkLocalDoneLine) {
		t.Fatalf("namespace client did not finish its checks:\n%s", out)
	}
}

// TestLinkLocalSourceClientHelper runs only inside the client namespace.
func TestLinkLocalSourceClientHelper(t *testing.T) {
	if os.Getenv(linkLocalClientEnv) == "" {
		t.Skip("runs in its own user and network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Both ends must be up before the link has carrier, or no link-local
	// address is configured on either end.
	llIP(t, "link", "add", "v0", "type", "veth", "peer", "name", "v1")
	llIP(t, "link", "set", "v0", "up")
	server, peer := startLinkLocalPeer(t)
	defer server()
	local := llSettledAddr(t, "v0")

	// --iface v0 selects the interface, and the peer is reached through v0's zone.
	sources, err := ResolveSource("v0")
	if err != nil {
		t.Fatalf("ResolveSource(v0): %v", err)
	}
	ops := probeOps(mustTarget(t, fmt.Sprintf("[%s%%v0]:%d", peer, linkLocalTCPPort)), opsFromSources(sources))

	// The TCP caller a probe uses: the happy-eyeballs dialer over tcp6.
	conn, _, attempts, _ := ops.dialIPs(ctx, []net.IP{peer}, linkLocalTCPPort)
	if conn == nil {
		t.Fatalf("dialIPs over the selected interface failed: %+v", attempts)
	}
	_ = conn.Close()
	if sources.Zone != "v0" || sources.Iface != "v0" {
		t.Fatalf("ResolveSource(v0) zone %q iface %q, want both v0", sources.Zone, sources.Iface)
	}

	// The generic network reaches the same bind through dialContext.
	conn, err = ops.dialContext(ctx, "tcp", ops.hostPort(peer, linkLocalTCPPort))
	if err != nil {
		t.Fatalf("tcp dial over the selected interface: %v", err)
	}
	_ = conn.Close()

	// A datagram round trip proves the UDP bind carries traffic, not just a
	// connected socket that never reached the peer.
	pc, err := ops.dialContext(ctx, "udp", ops.hostPort(peer, linkLocalUDPPort))
	if err != nil {
		t.Fatalf("udp dial over the selected interface: %v", err)
	}
	defer func() { _ = pc.Close() }()
	if _, err := pc.Write([]byte("ping")); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	reply := make([]byte, 16)
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := pc.Read(reply); err != nil || string(reply[:n]) != "ping" {
		t.Fatalf("udp reply = %q, %v; want ping", reply[:n], err)
	}

	// An exact link-local address selects the same interface, by its zone.
	byIP, err := ResolveSource(local.String())
	if err != nil {
		t.Fatalf("ResolveSource(%s): %v", local, err)
	}
	if byIP.Zone != "v0" || byIP.Iface != "" {
		t.Fatalf("ResolveSource(%s) zone %q iface %q, want zone v0 and no iface name", local, byIP.Zone, byIP.Iface)
	}
	ops = probeOps(mustTarget(t, fmt.Sprintf("[%s%%v0]:%d", peer, linkLocalTCPPort)), opsFromSources(byIP))
	conn, _, attempts, _ = ops.dialIPs(ctx, []net.IP{peer}, linkLocalTCPPort)
	if conn == nil {
		t.Fatalf("exact-address selection failed: %+v", attempts)
	}
	_ = conn.Close()

	// No --iface: the kernel picks the source, and the destination zone alone
	// names the link. This must keep working.
	ops = probeOps(mustTarget(t, fmt.Sprintf("[%s%%v0]:%d", peer, linkLocalTCPPort)), opsFromSources(nil))
	conn, err = ops.dialContext(ctx, "tcp", ops.hostPort(peer, linkLocalTCPPort))
	if err != nil {
		t.Fatalf("unbound dial to the scoped peer: %v", err)
	}
	_ = conn.Close()

	// The same interface named by its index is the same link, so it connects.
	v0Index, err := net.InterfaceByName("v0")
	if err != nil {
		t.Fatal(err)
	}
	ops = probeOps(mustTarget(t, fmt.Sprintf("[%s%%%d]:%d", peer, v0Index.Index, linkLocalTCPPort)), opsFromSources(sources))
	conn, err = ops.dialContext(ctx, "tcp", ops.hostPort(peer, linkLocalTCPPort))
	if err != nil {
		t.Fatalf("numeric zone %d for v0: %v", v0Index.Index, err)
	}
	_ = conn.Close()

	// A zone that names no interface is refused before the dial. Without that,
	// Go sends it as scope 0 and the socket bound to v0 reaches the peer anyway.
	ops = probeOps(mustTarget(t, fmt.Sprintf("[%s%%nosuch]:%d", peer, linkLocalTCPPort)), opsFromSources(sources))
	if conn, err := ops.dialContext(ctx, "tcp", ops.hostPort(peer, linkLocalTCPPort)); err == nil {
		_ = conn.Close()
		t.Fatal("a destination zone that names no interface connected through v0")
	} else if !strings.Contains(err.Error(), "names no interface") {
		t.Fatalf("unknown destination zone error = %v, want a refusal naming no interface", err)
	}

	// A second link in this namespace. Its end gets the same MAC as v0 so that
	// its link-local address is the same address on two interfaces.
	v0MAC := llInterfaceMAC(t, "v0")
	llIP(t, "link", "add", "x0", "type", "veth", "peer", "name", "x1")
	llIP(t, "link", "set", "x1", "address", v0MAC)
	llIP(t, "link", "set", "x0", "up")
	llIP(t, "link", "set", "x1", "up")
	other := llSettledAddr(t, "x0")

	// Source on v0, destination zone x0: the bind succeeds and the kernel refuses
	// the pair at connect. A bind failure would be the pre-fix error instead.
	ops = probeOps(mustTarget(t, fmt.Sprintf("[%s%%x0]:%d", other, linkLocalTCPPort)), opsFromSources(sources))
	conn, err = ops.dialContext(ctx, "tcp", ops.hostPort(other, linkLocalTCPPort))
	if err == nil {
		_ = conn.Close()
		t.Fatal("source on v0 connected to a destination zoned to x0")
	}
	var sysErr *os.SyscallError
	if !errors.As(err, &sysErr) || sysErr.Syscall != "connect" || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("mismatched scopes error = %v, want connect failing with EINVAL", err)
	}

	// The same address on two interfaces cannot say which link to bind to, so
	// an exact-address selection is refused rather than guessed.
	if _, err := ResolveSource(local.String()); err == nil || !strings.Contains(err.Error(), "2 interfaces") {
		t.Fatalf("ResolveSource(%s) with two holders = %v, want a refusal naming 2 interfaces", local, err)
	}

	fmt.Println(linkLocalDoneLine)
}

// startLinkLocalPeer starts the peer in a namespace of its own, moves the far
// end of the veth into it, and returns the peer's settled link-local address.
// The returned func stops the peer.
func startLinkLocalPeer(t *testing.T) (stop func(), peer net.IP) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLinkLocalSourcePeerHelper$") //nolint:gosec // G204: re-runs this test binary with a fixed helper name.
	cmd.Env = append(os.Environ(), linkLocalServerEnv+"=1")
	// Same user namespace as this process, so this process may move the veth
	// end into the new network namespace.
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start peer namespace: %v", err)
	}
	stop = func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	llIP(t, "link", "set", "v1", "netns", strconv.Itoa(cmd.Process.Pid))

	// The peer's test output and its address share stdout, so keep every line
	// for the failure message.
	var seen bytes.Buffer
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		seen.WriteString(scanner.Text() + "\n")
		if addr, ok := strings.CutPrefix(scanner.Text(), linkLocalPeerLine); ok {
			peer = net.ParseIP(addr)
			break
		}
	}
	if peer == nil {
		stop()
		t.Fatalf("peer namespace did not report an address:\n%s%s", seen.String(), stderr.String())
	}
	// Keep draining so the peer never blocks on a full pipe.
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
	return stop, peer
}

// TestLinkLocalSourcePeerHelper runs only inside the peer namespace.
func TestLinkLocalSourcePeerHelper(t *testing.T) {
	if os.Getenv(linkLocalServerEnv) == "" {
		t.Skip("runs in the peer namespace")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := net.InterfaceByName("v1"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the far end of the veth never arrived")
		}
		time.Sleep(20 * time.Millisecond)
	}
	llIP(t, "link", "set", "v1", "up")
	addr := llSettledAddr(t, "v1")
	scope := addr.String() + "%v1"

	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp6", net.JoinHostPort(scope, strconv.Itoa(linkLocalTCPPort)))
	if err != nil {
		t.Fatalf("listen tcp6 on %s: %v", scope, err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	pc, err := net.ListenPacket("udp6", net.JoinHostPort(scope, strconv.Itoa(linkLocalUDPPort)))
	if err != nil {
		t.Fatalf("listen udp6 on %s: %v", scope, err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()

	fmt.Println(linkLocalPeerLine + addr.String())
	// The client closes stdin when it is finished, which ends the peer.
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// llIP runs ip(8) in the current namespace.
func llIP(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput() //nolint:gosec // G204: ip(8) with fixed test arguments.
	if err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// llSettledAddr waits for dev's link-local address to leave DAD. A tentative
// address cannot be bound, so the test would race the kernel without the wait.
func llSettledAddr(t *testing.T, dev string) net.IP {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		out := llIP(t, "-o", "-6", "addr", "show", "dev", dev, "scope", "link")
		for line := range strings.SplitSeq(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && !strings.Contains(line, "tentative") {
				if ip, _, err := net.ParseCIDR(fields[3]); err == nil {
					return ip
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no settled link-local address on %s:\n%s", dev, out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// llInterfaceMAC returns dev's hardware address in ip(8) spelling.
func llInterfaceMAC(t *testing.T, dev string) string {
	t.Helper()
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		t.Fatal(err)
	}
	return ifi.HardwareAddr.String()
}
