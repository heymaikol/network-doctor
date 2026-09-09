//go:build linux

package simulation

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// This backend builds the simulated network out of unprivileged Linux
// namespaces. The shape is:
//
//	launcher (netdoc-sim run)          host namespaces, no privileges
//	  └── director                     new user + net + mount namespace
//	        ├── bridge nb<id><n> ×N     one per logical L2 segment
//	        ├── node holder ×N         each in its own net + mount namespace
//	        └── nsenter … netdoc       diagnostics, inside a node
//
// The user namespace is what makes this rootless: inside it the director holds
// CAP_NET_ADMIN and CAP_NET_BIND_SERVICE, so it can create bridges, veths,
// routes, nftables rules, tc qdiscs and privileged listeners, all of which
// exist only inside namespaces it owns. It has no capabilities in the host
// namespaces at all, so the safety rules this package promises (never touch the
// host's routes, resolver, or firewall) are enforced by the kernel rather than
// by this code being careful.
//
// Nothing is registered under /run/netns or /etc/netns either: the namespaces
// are held open by the holder processes and are reclaimed by the kernel when
// they exit. Cleanup is therefore "kill the tree", and a crashed or killed run
// leaks nothing.

// requiredTools are the executables the backend shells out to. Command
// arguments are always passed as argv slices; no string ever reaches a shell.
var requiredTools = []string{"ip", "nsenter"}

// optionalTools are needed only by the fault types that use them.
var optionalTools = map[string]string{"tc": FaultNetem, "nft": FaultDrop + " and " + FaultPMTUBlackhole}

// DefaultBackend returns the backend for this platform. With dry set, Prepare
// prints the commands it would run to log instead of running them, and creates
// nothing.
func DefaultBackend(dry bool, log io.Writer) Backend {
	return &netnsBackend{dry: dry, log: log}
}

type netnsBackend struct {
	dry bool
	log io.Writer
}

func (b *netnsBackend) Capabilities(ctx context.Context) Capabilities {
	c := Capabilities{
		Backend: "linux-netns",
		Privileged: []string{
			"create a user namespace mapping your uid to root inside it (no host privileges are gained)",
			"create network and mount namespaces, a bridge, and veth pairs inside them",
			"set addresses, routes, nftables rules and tc qdiscs inside those namespaces only",
			"bind-mount a generated resolv.conf over /etc/resolv.conf inside a simulated node's private mount namespace",
			"run the netdoc binary inside a simulated node",
		},
	}
	var missingRequired []string
	for _, tool := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			missingRequired = append(missingRequired, tool)
			c.Missing = append(c.Missing, tool+" (required; from "+toolPackage(tool)+")")
		}
	}
	for _, tool := range slices.Sorted(maps.Keys(optionalTools)) {
		if _, err := exec.LookPath(tool); err != nil {
			c.Missing = append(c.Missing, tool+" (only needed for "+optionalTools[tool]+" faults; from "+toolPackage(tool)+")")
		}
	}
	switch {
	case len(missingRequired) > 0:
		c.Reason = "cannot simulate: " + strings.Join(missingRequired, " and ") +
			" not found in $PATH. Install iproute2 (ip) and util-linux (nsenter)."
	default:
		c.Reason = userNamespaceReason()
		c.Supported = c.Reason == ""
	}
	return c
}

func toolPackage(tool string) string {
	if tool == "ip" || tool == "tc" {
		return "iproute2"
	}
	if tool == "nft" {
		return "nftables"
	}
	return "util-linux"
}

// linkTagLen is how much of a run id fits in a kernel link name.
const linkTagLen = 6

func isRunID(id string) bool {
	if len(id) != 2*runIDBytes {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

// kernelLinkName is the only generator for bridges and veth ends. A whole run
// id would blow past Linux's 15-byte IFNAMSIZ payload, so only its first
// linkTagLen bytes go in: these links live in the director's own network
// namespace, where the base-36 index is what keeps them apart, and the id
// fragment is there so `ip link` output can be traced back to a run.
func kernelLinkName(prefix, id string, index int) string {
	return prefix + id[:min(len(id), linkTagLen)] + strconv.FormatInt(int64(index), 36)
}

// userNamespaceReason explains why this host will not hand out an unprivileged
// user namespace, or "" when it will. It names the specific knob that is off,
// because "namespaces are disabled" is not something a user can act on and
// "user.max_user_namespaces is 0" is.
//
// There is no fallback to look for. Without a user namespace the simulator
// would have to run privileged against the host's real network stack, which is
// exactly the thing this design exists to make impossible, so an unsupported
// host is reported and the run stops.
func userNamespaceReason() string {
	// Root can always unshare, and still does: running as root does not switch
	// the simulator to host networking, it just means the user namespace is
	// entered from an account that already had the capabilities.
	if os.Geteuid() == 0 {
		return ""
	}
	type knob struct {
		path, wants, why string
	}
	// Each of these independently blocks clone(CLONE_NEWUSER) for an
	// unprivileged process, and distributions disagree about which they ship.
	for _, k := range []knob{
		{"/proc/sys/user/max_user_namespaces", "a count above 0",
			"raise it with `sudo sysctl -w user.max_user_namespaces=15000`"},
		{"/proc/sys/kernel/unprivileged_userns_clone", "1",
			"enable it with `sudo sysctl -w kernel.unprivileged_userns_clone=1`"},
		{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "0",
			"AppArmor is restricting unprivileged user namespaces (Ubuntu 24.04 and later); " +
				"allow this binary in an AppArmor profile, or clear the restriction with " +
				"`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`"},
	} {
		raw, err := os.ReadFile(k.path)
		if err != nil {
			// An absent knob is a kernel that does not have that restriction.
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil {
			continue
		}
		blocked := n == 0
		if k.path == "/proc/sys/kernel/apparmor_restrict_unprivileged_userns" {
			blocked = n != 0
		}
		if blocked {
			return fmt.Sprintf(
				"cannot simulate: unprivileged user namespaces are unavailable, %s is %d, wanted %s. %s. "+
					"netdoc-sim will not fall back to the host network stack or ask for elevated privileges.",
				k.path, n, k.wants, k.why)
		}
	}
	return ""
}

// directorTeardownGrace bounds how long an interrupted director gets to release
// its namespaces and remove its workspace before it is killed outright.
const directorTeardownGrace = 10 * time.Second

// LaunchDirector re-executes this binary with argv inside a fresh user,
// network and mount namespace, and returns its exit code. The child is where
// the backend actually runs; the parent keeps no privileges and no namespaces.
//
// stdin is nil for every automated command, since a simulation reads nothing
// from the terminal, and is the caller's terminal only for Challenge Mode, where a
// person is the one being asked.
func LaunchDirector(ctx context.Context, self string, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	// #nosec G204 -- self comes from os.Executable and argv is built as discrete arguments.
	cmd := exec.CommandContext(ctx, self, argv...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = stdout, stderr, stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		// uid 0 inside the namespace is this user outside it. That is the whole
		// privilege story: root here, nobody out there.
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// Mounts made inside must not propagate back to the host.
		Unshareflags: syscall.CLONE_NEWNS,
		// A director orphaned by a killed launcher must not keep namespaces
		// (and listeners) alive behind the user's back.
		Pdeathsig: syscall.SIGKILL,
	}
	// Interrupt, not kill: the director's own teardown is what removes the
	// workspace and the state record, and SIGKILL would leave both behind for
	// a user who only pressed Ctrl-C. The delay is the backstop for a director
	// that will not go, after which exec kills it.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = directorTeardownGrace
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		// Reached only when the capability check passed and the kernel still
		// refused: a container seccomp profile, an LSM, or a knob that changed
		// underneath us. Say what was attempted; never retry without the
		// namespace, which would put the simulation on the host's real stack.
		return 1, fmt.Errorf(
			"cannot create the user, network and mount namespaces a simulation runs in: %w. "+
				"Run `netdoc-sim capabilities` for this host's state; netdoc-sim will not run without them", err)
	}
	return 0, nil
}

// netnsEnv is one live simulated network, owned by the director process.
type netnsEnv struct {
	backend   *netnsBackend
	id        string
	scenario  *Scenario
	work      string
	bridges   []*segmentProc
	bySegment map[string]*segmentProc
	nodes     []*nodeProc
	byName    map[string]*nodeProc
	// tables records the nodes that already have the simulator's nftables table,
	// so repeated faults on one node do not re-add it.
	tables map[string]bool
	// holderCtx bounds the holder processes. It is deliberately detached from
	// the context Prepare was called with: that one is cancelled the moment
	// setup finishes, and it would take the namespaces with it. Cleanup is what
	// ends the holders, on every exit path.
	holderCtx  context.Context
	endHolders context.CancelFunc
	// cleaned caches the outcome of a completed teardown. Cleanup is called
	// from a defer that fires on every exit path, and a partially built
	// environment can reach it more than once; releasing twice must report the
	// same thing rather than inventing errors about resources already gone.
	cleaned *CleanupInfo
}

// nodeProc is a holder process: it exists to own a network namespace and to run
// that node's test services inside it.
type nodeProc struct {
	node   *Node
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	logs   *safeLog
	pid    int
	ifaces []*interfaceProc
	// mu serializes the holder's request/response pipe. Setup uses it from the
	// director's goroutine, the fault scheduler from its own, and stop closes it.
	mu      sync.Mutex
	stopped bool
}

type segmentProc struct {
	segment *Segment
	bridge  string
}

type interfaceProc struct {
	logical *Interface
	iface   string // interface name inside the node
	peer    string // veth end enslaved to the segment bridge
}

func (b *netnsBackend) Prepare(ctx context.Context, s *Scenario, id string) (Env, error) {
	if !isRunID(id) {
		return nil, fmt.Errorf("invalid simulation run id %q", id)
	}
	// Deterministic, not MkdirTemp: derived from the run id so `netdoc-sim
	// cleanup <id>` can rebuild the workspace path of a run whose process is
	// gone, rather than trusting the one written into its record. Exclusive, and
	// done before there is an Env to hand back, so e.work only ever names a
	// directory this call created, and Cleanup can only ever remove that one.
	work, err := createWorkspace(id)
	if err != nil {
		return nil, err
	}
	e := &netnsEnv{
		backend: b, id: id, scenario: s, work: work,
		bySegment: make(map[string]*segmentProc, len(s.Topology.Segments)),
		byName:    make(map[string]*nodeProc, len(s.Topology.Nodes)),
		tables:    map[string]bool{},
	}
	e.holderCtx, e.endHolders = context.WithCancel(context.WithoutCancel(ctx))
	// Every failure past this point still returns e: partially built namespaces
	// and half-started holders are exactly what has to be cleaned up.
	if err := e.build(ctx); err != nil {
		return e, err
	}
	return e, nil
}

func (e *netnsEnv) build(ctx context.Context) error {
	for i := range e.scenario.Topology.Segments {
		segment := &e.scenario.Topology.Segments[i]
		sp := &segmentProc{segment: segment, bridge: kernelLinkName("nb", e.id, i)}
		e.bridges = append(e.bridges, sp)
		e.bySegment[segment.Name] = sp
		if err := e.run(ctx, "ip", "link", "add", sp.bridge, "type", "bridge"); err != nil {
			return fmt.Errorf("segment %s: %w", segment.Name, err)
		}
		if err := e.run(ctx, "ip", "link", "set", sp.bridge, "up"); err != nil {
			return fmt.Errorf("segment %s: %w", segment.Name, err)
		}
	}
	interfaceIndex := 0
	for i := range e.scenario.Topology.Nodes {
		n := &e.scenario.Topology.Nodes[i]
		np := &nodeProc{node: n}
		for ii := range n.Interfaces {
			np.ifaces = append(np.ifaces, &interfaceProc{
				logical: &n.Interfaces[ii],
				iface:   kernelLinkName("ne", e.id, interfaceIndex),
				peer:    kernelLinkName("np", e.id, interfaceIndex),
			})
			interfaceIndex++
		}
		e.nodes = append(e.nodes, np)
		e.byName[n.Name] = np
		if err := e.startHolder(ctx, np); err != nil {
			return fmt.Errorf("node %s: %w", n.Name, err)
		}
		if err := e.wireNode(ctx, np); err != nil {
			return fmt.Errorf("node %s: %w", n.Name, err)
		}
	}
	if err := e.installRoutes(ctx); err != nil {
		return err
	}
	// Services come last: a listener must not be reachable before every node is
	// addressed, or an early probe could race the topology into existence.
	for _, np := range e.nodes {
		if err := e.startServices(ctx, np); err != nil {
			return fmt.Errorf("node %s: %w", np.node.Name, err)
		}
	}
	return nil
}

// startHolder spawns the process that owns the node's namespaces. It reports
// readiness once its mount namespace is set up, then waits to be told the
// network is configured.
func (e *netnsEnv) startHolder(ctx context.Context, np *nodeProc) error {
	cfg := nodeConfig{
		Name: np.node.Name, Resolver: np.node.Resolver, Services: np.node.Services,
		Addresses:        np.node.addresses(),
		Evidence:         filepath.Join(e.work, np.node.Name+"-evidence.jsonl"),
		TrustDir:         e.work,
		ForwardIPv4:      np.node.Role == "router" && np.node.forwardsFamily("ipv4"),
		ForwardIPv6:      np.node.Role == "router" && np.node.forwardsFamily("ipv6"),
		EnableIPv6:       np.node.hasFamily("ipv6"),
		ForwardingStatus: filepath.Join(e.work, np.node.Name+"-forwarding"),
	}
	path := filepath.Join(e.work, np.node.Name+".json")
	blob, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	e.record("spawn node holder %q in a new net + mount namespace", np.node.Name)
	if e.backend.dry {
		return nil
	}
	// #nosec G204 -- self comes from os.Executable and path is this run's private config.
	cmd := exec.CommandContext(e.holderCtx, self, NodeCommand, path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:   syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		Unshareflags: syscall.CLONE_NEWNS,
		Pdeathsig:    syscall.SIGKILL,
	}
	np.logs = new(safeLog)
	cmd.Stderr = np.logs
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	np.cmd, np.stdin, np.stdout, np.pid = cmd, stdin, bufio.NewReader(stdout), cmd.Process.Pid
	return np.await(ctx, holderNSReady)
}

// wireNode gives the node one veth per logical interface and its addresses.
func (e *netnsEnv) wireNode(ctx context.Context, np *nodeProc) error {
	n := np.node
	pid := strconv.Itoa(np.pid)
	steps := [][]string{{"nsenter", "-t", pid, "-n", "--", "ip", "link", "set", "lo", "up"}}
	for _, iface := range np.ifaces {
		bridge := e.bySegment[iface.logical.Segment]
		steps = append(steps,
			[]string{"ip", "link", "add", iface.peer, "type", "veth", "peer", "name", iface.iface},
			[]string{"ip", "link", "set", iface.peer, "master", bridge.bridge},
			[]string{"ip", "link", "set", iface.peer, "up"},
			[]string{"ip", "link", "set", iface.iface, "netns", pid},
		)
		for _, prefix := range iface.logical.prefixes() {
			family := "-6"
			if prefix.Addr().Is4() {
				family = "-4"
			}
			addrStep := []string{"nsenter", "-t", pid, "-n", "--", "ip", family, "addr", "add", prefix.String(), "dev", iface.iface}
			if prefix.Addr().Is6() {
				// Scenario validation already rejects duplicate addresses. Skipping
				// DAD avoids a race where services bind while a fresh veth address
				// is still tentative.
				addrStep = append(addrStep, "nodad")
			}
			steps = append(steps, addrStep)
		}
		steps = append(steps,
			[]string{"nsenter", "-t", pid, "-n", "--", "ip", "link", "set", iface.iface, "up"},
		)
	}
	// Aliases go on loopback: an address on lo is answered for on every
	// interface, which is how one node can be "the internet" at 1.1.1.1 and
	// 8.8.8.8 without a second link.
	for _, a := range n.Aliases {
		bits := "/32"
		if addr, err := netip.ParseAddr(a); err == nil && addr.Is6() {
			bits = "/128"
		}
		steps = append(steps, []string{"nsenter", "-t", pid, "-n", "--", "ip", "addr", "add", a + bits, "dev", "lo"})
	}
	for _, argv := range steps {
		if err := e.run(ctx, argv...); err != nil {
			return err
		}
	}
	return nil
}

func (e *netnsEnv) installRoutes(ctx context.Context) error {
	for _, route := range e.scenario.Topology.Routes {
		np := e.byName[route.Node]
		segment, _ := nodeSegmentForAddress(np.node, netip.MustParseAddr(route.Via))
		iface := np.interfaceForSegment(segment)
		family := "-6"
		if route.Family == "ipv4" {
			family = "-4"
		}
		argv := []string{"nsenter", "-t", strconv.Itoa(np.pid), "-n", "--", "ip", family, "route", "add", route.Destination,
			"via", route.Via, "dev", iface.iface}
		if route.Metric != 0 {
			argv = append(argv, "metric", strconv.Itoa(route.Metric))
		}
		if err := e.run(ctx, argv...); err != nil {
			return fmt.Errorf("route %s on %s: %w", route.Destination, route.Node, err)
		}
	}
	return nil
}

func (np *nodeProc) interfaceForSegment(segment string) *interfaceProc {
	for _, iface := range np.ifaces {
		if iface.logical.Segment == segment {
			return iface
		}
	}
	return nil
}

func (e *netnsEnv) startServices(ctx context.Context, np *nodeProc) error {
	if len(np.node.Services) > 0 {
		e.record("start %d service(s) in node %q", len(np.node.Services), np.node.Name)
	}
	if e.backend.dry {
		return nil
	}
	if _, err := io.WriteString(np.stdin, holderStart+"\n"); err != nil {
		return err
	}
	return np.await(ctx, holderServicesReady)
}

// safeLog collects a holder's stderr. os/exec copies into it from a goroutine
// of its own for as long as the holder runs, while await reads it to explain a
// holder that answered wrongly, so two goroutines share one buffer and it needs the
// lock.
type safeLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *safeLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *safeLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// await waits for one line from the holder. A holder that died instead of
// answering reports its own stderr, which is where a bind failure shows up.
func (np *nodeProc) await(ctx context.Context, want string) error {
	got, err := np.reply(ctx, want)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("holder said %q, want %q: %s", got, want, strings.TrimSpace(np.logs.String()))
	}
	return nil
}

// reply reads one line from the holder. want names what the director asked for
// and appears only in the error a dead holder produces.
func (np *nodeProc) reply(ctx context.Context, want string) (string, error) {
	type line struct {
		s   string
		err error
	}
	ch := make(chan line, 1)
	go func() {
		s, err := np.stdout.ReadString('\n')
		ch <- line{strings.TrimSpace(s), err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case got := <-ch:
		if got.err != nil {
			return "", fmt.Errorf("holder exited before %q: %s", want, strings.TrimSpace(np.logs.String()))
		}
		return got.s, nil
	}
}

func (e *netnsEnv) Nodes() []NodeInfo {
	out := make([]NodeInfo, 0, len(e.nodes))
	for _, np := range e.nodes {
		primaryInterface := ""
		if len(np.ifaces) > 0 {
			primaryInterface = np.ifaces[0].iface
		}
		info := NodeInfo{
			Name: np.node.Name, Role: np.node.Role, Address: np.node.Address,
			Aliases: np.node.Aliases, Interface: primaryInterface, Gateway: np.node.Gateway,
			Resolver: np.node.Resolver, PID: np.pid,
		}
		for _, iface := range np.ifaces {
			address := iface.logical.Address
			if address == "" {
				address = iface.logical.IPv4
				if address == "" {
					address = iface.logical.IPv6
				}
			}
			info.Interfaces = append(info.Interfaces, InterfaceInfo{Segment: iface.logical.Segment, Address: address,
				IPv4: iface.logical.IPv4, IPv6: iface.logical.IPv6})
		}
		for _, route := range e.scenario.Topology.Routes {
			if route.Node == np.node.Name {
				segment, _ := nodeSegmentForAddress(np.node, netip.MustParseAddr(route.Via))
				info.Routes = append(info.Routes, RouteInfo{Destination: route.Destination, Via: route.Via, Segment: segment, Metric: route.Metric, Family: route.Family})
			}
		}
		for _, s := range np.node.Services {
			info.Services = append(info.Services, fmt.Sprintf("%s/%d", s.Type, s.Port))
		}
		out = append(out, info)
	}
	return out
}

func (e *netnsEnv) ApplyFaults(ctx context.Context, faults []Fault) ([]FaultInfo, error) {
	var out []FaultInfo
	for _, f := range faults {
		switch f.Type {
		case FaultScheduledNetem, FaultScheduledDNS, FaultScheduledLink:
			// Scheduled faults are the fault scheduler's business; the topology
			// starts in whatever state their first event asks for.
			continue
		}
		np, ok := e.byName[f.Node]
		if !ok {
			return out, fmt.Errorf("fault targets unknown node %q", f.Node)
		}
		steps, summary, err := e.faultSteps(f, np)
		if err != nil {
			return out, err
		}
		for _, argv := range steps {
			if err := e.run(ctx, argv...); err != nil {
				return out, fmt.Errorf("fault %s on %s: %w", f.Type, f.Node, err)
			}
		}
		info := FaultInfo{Type: f.Type, Node: f.Node, Family: f.Family, Protocol: f.Protocol, Port: f.Port,
			Direction: f.Direction, Summary: summary, Command: steps[len(steps)-1], Seed: f.Seed}
		if f.Type == FaultNetem {
			info.Latency, _ = time.ParseDuration(f.Delay)
			info.Jitter, _ = time.ParseDuration(f.Jitter)
			if raw, ok := strings.CutSuffix(f.Loss, "%"); ok {
				info.LossPercent, _ = strconv.ParseFloat(raw, 64)
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// ApplyTimedEvent moves the live topology into one scheduled state. The argv it
// builds is generated here from the logical node and segment; nothing in a
// scenario file reaches a command line.
func (e *netnsEnv) ApplyTimedEvent(ctx context.Context, event TimedEvent) (string, error) {
	np, ok := e.byName[event.Node]
	if !ok {
		return "", fmt.Errorf("scheduled event targets unknown node %q", event.Node)
	}
	if event.Type == FaultScheduledDNS {
		// Nothing was observed unless the holder confirmed it: a failed event
		// must not carry an observation that says the opposite of its result.
		if err := np.setDNSOutcome(ctx, event.Service, event.Outcome, event.Delay); err != nil {
			return "", err
		}
		return holderDNSApplied, nil
	}
	iface := np.interfaceForSegment(event.Segment)
	if iface == nil {
		return "", fmt.Errorf("node %q has no interface on segment %q", event.Node, event.Segment)
	}
	in := func(argv ...string) []string {
		return append([]string{"nsenter", "-t", strconv.Itoa(np.pid), "-n", "--"}, argv...)
	}
	switch event.Type {
	case FaultScheduledNetem:
		// replace, not add: a scheduled timeline moves between states on an
		// interface that may already carry a netem qdisc from an earlier event.
		argv := in("tc", "qdisc", "replace", "dev", iface.iface, "root", "netem")
		if event.Latency > 0 {
			argv = append(argv, "delay", tcDuration(event.Latency))
			if event.Jitter > 0 {
				argv = append(argv, tcDuration(event.Jitter))
			}
		}
		if event.LossPercent > 0 {
			argv = append(argv, "loss", strconv.FormatFloat(event.LossPercent, 'f', 2, 64)+"%")
		}
		if event.NetemSeed != 0 {
			argv = append(argv, "seed", strconv.FormatUint(uint64(event.NetemSeed), 10))
		}
		if err := e.run(ctx, argv...); err != nil {
			return "", err
		}
		return e.observeNetem(ctx, event.Node, iface), nil
	case FaultScheduledLink:
		if err := e.run(ctx, in("ip", "link", "set", iface.iface, event.State)...); err != nil {
			return "", err
		}
		res := e.Exec(ctx, event.Node, []string{"ip", "-o", "link", "show", "dev", iface.iface}, nil)
		if res.Err != nil || res.ExitCode != 0 {
			return "", execResultError(res)
		}
		up := parseLinkUp(string(res.Stdout))
		if up != (event.State == LinkStateUp) {
			return "", fmt.Errorf("kernel link state did not become %s", event.State)
		}
		return "kernel link up=" + strconv.FormatBool(up), nil
	}
	return "", fmt.Errorf("unknown scheduled event type %q", event.Type)
}

// observeNetem reads the qdisc back so the report proves what the kernel holds,
// not merely what the simulator asked for. Best effort: an unreadable qdisc is
// worth saying so about, not worth failing an applied event over.
func (e *netnsEnv) observeNetem(ctx context.Context, node string, iface *interfaceProc) string {
	res := e.Exec(ctx, node, []string{"tc", "qdisc", "show", "dev", iface.iface}, nil)
	if res.Err != nil || res.ExitCode != 0 {
		return "kernel netem: unreadable"
	}
	return "kernel netem: " + netemParameters(res.Stdout)
}

// netemParameters extracts the shaping parameters tc reports, dropping the
// qdisc handle, refcnt and queue limit: implementation detail on one side, and
// on the other a generated name this package never exposes.
func netemParameters(raw []byte) string {
	line, _, _ := strings.Cut(string(raw), "\n")
	if !strings.Contains(line, "qdisc netem ") {
		return "absent"
	}
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "limit" {
			if rest := strings.Join(fields[i+2:], " "); rest != "" {
				return rest
			}
			return "unimpaired"
		}
	}
	return "unimpaired"
}

// setDNSOutcome asks the node holder to move one of its DNS services into a new
// response state. The holder owns the service; the director owns the clock.
func (np *nodeProc) setDNSOutcome(ctx context.Context, service, outcome string, delay time.Duration) error {
	if np.stdin == nil || np.stdout == nil {
		return errors.New("node holder is not running")
	}
	np.mu.Lock()
	defer np.mu.Unlock()
	if np.stopped {
		return errors.New("node holder has already stopped")
	}
	request := strings.Join([]string{holderDNSCommand, service, outcome, strconv.FormatInt(delay.Milliseconds(), 10)}, " ")
	if _, err := io.WriteString(np.stdin, request+"\n"); err != nil {
		return err
	}
	return np.await(ctx, holderDNSApplied)
}

// probeTCP asks the node holder to open one TCP connection from inside its own
// namespace. The holder is simulator-owned and never sees netdoc's report, so
// what it answers is an observation of the simulated network rather than a
// restatement of the diagnosis.
// It answers with one of FamilyStateReachable, TargetStateRefused or
// FamilyStateUnreachable, the three outcomes a TCP connection attempt can
// actually have, kept apart because a reset and a timeout are different faults.
func (np *nodeProc) probeTCP(ctx context.Context, address string, port int, timeout time.Duration) (string, error) {
	if np.stdin == nil || np.stdout == nil {
		return "", errors.New("node holder is not running")
	}
	np.mu.Lock()
	defer np.mu.Unlock()
	if np.stopped {
		return "", errors.New("node holder has already stopped")
	}
	request := strings.Join([]string{holderProbeCommand, address, strconv.Itoa(port),
		strconv.FormatInt(timeout.Milliseconds(), 10)}, " ")
	if _, err := io.WriteString(np.stdin, request+"\n"); err != nil {
		return "", err
	}
	got, err := np.reply(ctx, holderProbeResult)
	if err != nil {
		return "", err
	}
	switch got {
	case holderProbeResult + " " + holderProbeReached:
		return FamilyStateReachable, nil
	case holderProbeResult + " " + holderProbeRefused:
		return TargetStateRefused, nil
	case holderProbeResult + " " + holderProbeFailed:
		return FamilyStateUnreachable, nil
	}
	return "", fmt.Errorf("holder answered %q to a reachability probe", got)
}

func (np *nodeProc) checkEvidence(ctx context.Context) error {
	if np.stdin == nil || np.stdout == nil {
		return errors.New("node holder is not running")
	}
	np.mu.Lock()
	defer np.mu.Unlock()
	if np.stopped {
		return errors.New("node holder has already stopped")
	}
	if _, err := io.WriteString(np.stdin, holderEvidenceCheck+"\n"); err != nil {
		return fmt.Errorf("ask holder to confirm evidence: %w: %s", err, strings.TrimSpace(np.logs.String()))
	}
	return np.await(ctx, holderEvidenceReady)
}

// faultSteps turns one fault into the commands that inject it, plus a one-line
// description for the report.
func (e *netnsEnv) faultSteps(f Fault, np *nodeProc) ([][]string, string, error) {
	pid := strconv.Itoa(np.pid)
	in := func(argv ...string) []string {
		return append([]string{"nsenter", "-t", pid, "-n", "--"}, argv...)
	}
	switch f.Type {
	case FaultDrop:
		// Outbound drops on the way out, which the kernel reports back to the
		// local sender as EPERM, a refusal, the way a host firewall behaves.
		// Inbound drops on arrival at this node, so the sender is told nothing
		// and waits out its timeout, the way a black hole in the path behaves.
		chain, hook, where := "out", "postrouting", "refuses"
		if f.Direction == DirectionInbound {
			chain, hook, where = "in", "input", "swallows"
		}
		var steps [][]string
		key := f.Node + "/" + chain
		if !e.tables[key] {
			steps = append(steps,
				in("nft", "add", "table", "inet", nftTable),
				in("nft", "add", "chain", "inet", nftTable, chain, "{ type filter hook "+hook+" priority 0; }"))
			e.tables[key] = true
		}
		// A named counter, so the rule's match count can be read back on its own
		// after the run rather than parsed out of the chain listing. Its name is
		// derived from the fault, which is what the evidence collector has.
		counter := dropCounterName(f)
		if counterKey := f.Node + "/counter/" + counter; !e.tables[counterKey] {
			steps = append(steps, in("nft", "add", "counter", "inet", nftTable, counter))
			e.tables[counterKey] = true
		}
		rule := in("nft", "add", "rule", "inet", nftTable, chain)
		what := "all traffic"
		if f.To == "" && f.Family != "" {
			nfproto := "ipv4"
			if f.Family == "ipv6" {
				nfproto = "ipv6"
			}
			rule = append(rule, "meta", "nfproto", nfproto)
			what = f.Family + " traffic"
		}
		if f.To != "" {
			family := "ip"
			if addr, err := netip.ParseAddr(f.To); err == nil && addr.Is6() {
				family = "ip6"
			}
			rule = append(rule, family, "daddr", f.To)
			what = "traffic to " + f.To
		}
		if f.Protocol != "" {
			rule = append(rule, f.Protocol)
			what = f.Protocol + " " + what
			if f.Port != 0 {
				rule = append(rule, "dport", strconv.Itoa(f.Port))
				what += " port " + strconv.Itoa(f.Port)
			}
		}
		rule = append(rule, "counter", "name", counter, "drop")
		return append(steps, rule), np.node.Name + " " + where + " " + what, nil
	case FaultNetem:
		iface := np.interfaceForSegment(f.Segment)
		argv := in("tc", "qdisc", "replace", "dev", iface.iface, "root", "netem")
		var parts []string
		if f.Delay != "" {
			d, _ := time.ParseDuration(f.Delay)
			argv = append(argv, "delay", tcDuration(d))
			parts = append(parts, "delay "+f.Delay)
			if f.Jitter != "" {
				j, _ := time.ParseDuration(f.Jitter)
				argv = append(argv, tcDuration(j))
				parts = append(parts, "jitter "+f.Jitter)
			}
		}
		if f.Loss != "" {
			argv = append(argv, "loss", f.Loss)
			parts = append(parts, "loss "+f.Loss)
		}
		if f.Seed != 0 {
			argv = append(argv, "seed", strconv.FormatUint(uint64(f.Seed), 10))
			parts = append(parts, "seed "+strconv.FormatUint(uint64(f.Seed), 10))
		}
		return [][]string{argv}, np.node.Name + " link: " + strings.Join(parts, ", "), nil
	case FaultNoDefaultRoute:
		flag := "-4"
		if f.Family == "ipv6" {
			flag = "-6"
		}
		return [][]string{in("ip", flag, "route", "del", "default")}, np.node.Name + " has no " + f.Family + " default route", nil
	case FaultReplaceDefaultRoute:
		segment, _ := nodeSegmentForAddress(np.node, netip.MustParseAddr(f.Via))
		iface := np.interfaceForSegment(segment)
		flag := "-4"
		if f.Family == "ipv6" {
			flag = "-6"
		}
		add := in("ip", flag, "route", "add", "default", "via", f.Via, "dev", iface.iface)
		if f.Metric != 0 {
			add = append(add, "metric", strconv.Itoa(f.Metric))
		}
		return [][]string{in("ip", flag, "route", "flush", "default"), add},
			fmt.Sprintf("%s default route now uses %s on %s", np.node.Name, f.Via, segment), nil
	case FaultLinkDown:
		iface := np.interfaceForSegment(f.Segment)
		return [][]string{in("ip", "link", "set", iface.iface, "down")},
			fmt.Sprintf("%s link to %s is down", np.node.Name, f.Segment), nil
	case FaultPMTUBlackhole:
		iface := np.interfaceForSegment(f.Segment)
		steps := [][]string{in("ip", "link", "set", iface.iface, "mtu", strconv.Itoa(f.MTU))}
		key := f.Node + "/" + pmtuChain
		if !e.tables[key] {
			steps = append(steps,
				in("nft", "add", "table", "inet", nftTable),
				in("nft", "add", "chain", "inet", nftTable, pmtuChain, "{ type filter hook output priority 0; }"))
			e.tables[key] = true
		}
		// Output, not forward: the only packets suppressed are the PMTU errors
		// this router itself generates about the narrowed hop. ICMP it merely
		// forwards, and every other type it originates, still flow. A black
		// hole is one missing signal, not a dead control plane.
		steps = append(steps,
			in("nft", "add", "rule", "inet", nftTable, pmtuChain,
				"icmp", "type", "destination-unreachable", "icmp", "code", "frag-needed", "drop"),
			in("nft", "add", "rule", "inet", nftTable, pmtuChain,
				"icmpv6", "type", "packet-too-big", "drop"))
		return steps, fmt.Sprintf("%s carries %s at a %d-byte MTU and swallows its own fragmentation-needed replies",
			np.node.Name, f.Segment, f.MTU), nil
	}
	return nil, "", fmt.Errorf("unknown fault type %q", f.Type)
}

// dropCounterName names the nftables counter one drop fault's rule feeds. It is
// derived from the fault alone so that the collector, which sees the scenario
// rather than the applied commands, can ask for the same counter by name. Two
// identical faults share one counter, which is the honest total for a rule that
// was installed twice.
func dropCounterName(f Fault) string {
	parts := []string{"drop", f.Direction, f.Family, f.Protocol, strconv.Itoa(f.Port), f.To}
	for i, part := range parts {
		if part == "" {
			part = "any"
		}
		parts[i] = strings.Map(func(r rune) rune {
			if isNftNameRune(r) {
				return r
			}
			return '_'
		}, part)
	}
	return strings.Join(parts, "_")
}

// isNftNameRune reports whether r may appear in an nftables object name.
func isNftNameRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_'
}

// nftTable is the simulator's own table name. Rules only ever go here, and only
// ever inside a simulated node's namespace; the host ruleset is unreachable
// from the director's user namespace in the first place.
const nftTable = "netdocsim"

// pmtuChain holds the PMTU black hole's suppression rules. Its own chain, so
// the hook it needs, locally originated traffic only, cannot be confused with
// the drop fault's chains.
const pmtuChain = "pmtu"

// tcDuration renders a Go duration the way tc wants it.
func tcDuration(d time.Duration) string {
	if d%time.Millisecond == 0 {
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	}
	return strconv.FormatInt(d.Microseconds(), 10) + "us"
}

func (e *netnsEnv) Exec(ctx context.Context, node string, argv, env []string) ExecResult {
	np, ok := e.byName[node]
	if !ok {
		return ExecResult{Err: fmt.Errorf("unknown node %q", node)}
	}
	if len(argv) == 0 {
		return ExecResult{Err: errors.New("empty command")}
	}
	// -m as well as -n: the node's private mount namespace is where its
	// /etc/resolv.conf lives, and a resolver test that read the host's would be
	// measuring the wrong machine.
	full := append([]string{"nsenter", "-t", strconv.Itoa(np.pid), "-n", "-m", "--"}, argv...)
	start := time.Now()
	// #nosec G204 -- full[0] is fixed nsenter; argv stays an argument vector after --.
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	cmd.Env = append(simEnv(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := ExecResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Duration: time.Since(start)}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.ExitCode = exit.ExitCode()
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			res.Signal = status.Signal().String()
		}
	case err != nil:
		res.Err = err
	}
	res.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	res.Cancelled = ctx.Err() != nil && !res.TimedOut
	return res
}

// ExecInteractive runs argv inside a node with the caller's terminal attached,
// for the one case where a person rather than a probe is doing the looking. It
// enters the same namespaces Exec does, through the same nsenter argument
// slice, and adds nothing to what the director can already do: the child holds
// no privilege the simulator did not already have, and owns nothing on the host.
//
// No process group is set. An interactive shell puts itself in one and claims
// the terminal, which is what keeps the reader's Ctrl-C inside the node instead
// of on the process holding the simulation open.
func (e *netnsEnv) ExecInteractive(ctx context.Context, node string, argv, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	np, ok := e.byName[node]
	if !ok {
		return fmt.Errorf("unknown node %q", node)
	}
	if len(argv) == 0 {
		return errors.New("empty command")
	}
	full := append([]string{"nsenter", "-t", strconv.Itoa(np.pid), "-n", "-m", "--"}, argv...)
	// #nosec G204 -- full[0] is fixed nsenter; argv stays an argument vector after --.
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	cmd.Env = append(simEnv(), env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	// A shell exiting non-zero is how shells exit; it is not a simulator error.
	var exit *exec.ExitError
	if err := cmd.Run(); err != nil && !errors.As(err, &exit) {
		return err
	}
	return nil
}

func (e *netnsEnv) TrustAnchor(service string) (string, error) {
	if !isSafeName(service) {
		return "", fmt.Errorf("invalid tls service %q", service)
	}
	for _, node := range e.scenario.Topology.Nodes {
		for _, svc := range node.Services {
			if svc.Name != service {
				continue
			}
			if svc.Type == ServiceTLS {
				return filepath.Join(e.work, service+"-ca.pem"), nil
			}
			if svc.Type == ServiceQUIC || svc.Type == ServiceEncryptedDNS {
				return probeTrustAnchorPath(e.work, service), nil
			}
		}
	}
	return "", fmt.Errorf("unknown tls service %q", service)
}

// simEnv is the environment commands run with inside a node. The host's proxy
// variables are stripped: a simulation must not inherit the operator's proxy
// configuration, or a scenario's result would depend on whose laptop ran it.
// A scenario that wants a proxy sets one on its own node.
func simEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR":
			continue
		}
		out = append(out, kv)
	}
	return out
}

func (e *netnsEnv) Cleanup(ctx context.Context, keep bool) CleanupInfo {
	if e.cleaned != nil {
		return *e.cleaned
	}
	if keep {
		var pids []string
		for _, np := range e.nodes {
			pids = append(pids, fmt.Sprintf("%s=%d", np.node.Name, np.pid))
		}
		return CleanupInfo{Kept: true, Workspace: e.work, Detail: fmt.Sprintf(
			"simulation %s left running (workspace %s, node pids %s); enter one with `nsenter -t PID -n -m -- sh`, release it with `netdoc-sim cleanup %s`",
			e.id, e.work, strings.Join(pids, " "), e.id)}
	}
	info := CleanupInfo{}
	if e.endHolders != nil {
		defer e.endHolders()
	}
	for _, np := range e.nodes {
		if err := np.stop(ctx); err != nil {
			info.Errors = append(info.Errors, fmt.Sprintf("node %s: %v", np.node.Name, err))
		}
	}
	// Bridges live in the director namespace. Delete each independently so a
	// partially created later segment cannot prevent earlier cleanup.
	if !e.backend.dry {
		for i := len(e.bridges) - 1; i >= 0; i-- {
			if err := e.run(ctx, "ip", "link", "del", e.bridges[i].bridge); err != nil && !isMissingLink(err) {
				info.Errors = append(info.Errors, err.Error())
			}
		}
	}
	if e.work != "" {
		if err := os.RemoveAll(e.work); err != nil {
			info.Errors = append(info.Errors, err.Error())
		}
	}
	info.Done = len(info.Errors) == 0
	e.cleaned = &info
	return info
}

// stop ends a holder: closing its stdin is the polite request, SIGKILL is the
// answer to one that will not go. Idempotent, and it has to be, since a holder may
// already have exited on its own, been killed with the process group, or been
// stopped by an earlier Cleanup.
func (np *nodeProc) stop(ctx context.Context) error {
	np.mu.Lock()
	if np.cmd == nil || np.cmd.Process == nil || np.stopped {
		np.mu.Unlock()
		return nil
	}
	np.stopped = true
	np.mu.Unlock()
	if np.stdin != nil {
		_ = np.stdin.Close()
	}
	done := make(chan error, 1)
	go func() { done <- np.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("holder exited: %w: %s", err, strings.TrimSpace(np.logs.String()))
		}
		return nil
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
	}
	if err := np.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	if err := <-done; err != nil {
		return fmt.Errorf("holder exited: %w: %s", err, strings.TrimSpace(np.logs.String()))
	}
	return nil
}

// netem learned the seed keyword in iproute2 6.6. Older tc reads it as a stray
// argument and answers with its whole usage text, which says nothing about the
// version being the problem.
const netemSeedIproute2 = "6.6"

// tcSupportsNetemSeed reports whether tc accepts `netem seed`, along with the
// version it named, for messages. An unparseable version counts as too old:
// every release that predates the modern scheme also predates the keyword.
func tcSupportsNetemSeed(ctx context.Context) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "tc", "-V").Output()
	if err != nil {
		return false, "no tc"
	}
	return parseNetemSeedSupport(string(out))
}

// parseNetemSeedSupport reads tc -V output, e.g. "tc utility, iproute2-6.17.0".
func parseNetemSeedSupport(out string) (bool, string) {
	out = strings.TrimSpace(out)
	_, version, ok := strings.Cut(out, "iproute2-")
	if !ok {
		return false, out
	}
	major, rest, ok := strings.Cut(version, ".")
	if !ok {
		return false, version
	}
	haveMajor, err := strconv.Atoi(major)
	if err != nil {
		return false, version
	}
	minor, _, _ := strings.Cut(rest, ".")
	haveMinor, err := strconv.Atoi(minor)
	if err != nil {
		return false, version
	}
	const wantMajor, wantMinor = 6, 6
	return haveMajor > wantMajor || (haveMajor == wantMajor && haveMinor >= wantMinor), version
}

// run executes one setup command and records it. In dry mode it only records.
func (e *netnsEnv) run(ctx context.Context, argv ...string) error {
	e.record("%s", strings.Join(argv, " "))
	if e.backend.dry {
		return nil
	}
	// #nosec G204 -- validated simulator operations build argv; no shell interprets it.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if strings.Contains(msg, `What is "seed"?`) && slices.Contains(argv, "seed") {
			_, version := tcSupportsNetemSeed(ctx)
			msg = "this tc (" + version + ") has no `netem seed`, which needs iproute2 " +
				netemSeedIproute2 + " or newer; upgrade iproute2 to run seeded loss or jitter"
		}
		return fmt.Errorf("%s: %s", strings.Join(argv, " "), msg)
	}
	return nil
}

func (e *netnsEnv) record(format string, a ...any) {
	if e.backend.log != nil {
		fmt.Fprintf(e.backend.log, "  "+format+"\n", a...)
	}
}

func isMissingLink(err error) bool {
	return strings.Contains(err.Error(), "Cannot find device")
}
