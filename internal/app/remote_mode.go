package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/remote"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// remoteRun is stubbed in tests, which have no SSH server to talk to.
var remoteRun = remote.Run

// workerStdin is the protocol's inbound channel, stubbed in tests.
var workerStdin io.Reader = os.Stdin

func requestForRemote(h headless) remote.Request {
	req := remote.Request{
		Iface: h.iface, PublicDNS: h.publicDNS, PublicDNSAuto: h.publicDNSAuto,
		TimeoutMs: h.timeout.Milliseconds(),
		Check:     h.check.strings(), Skip: h.skip.strings(),
	}
	if h.target != nil {
		// The remote parses the same validated spelling again, so a build that
		// resolves it differently records that difference in its snapshot.
		req.Target = h.target.Raw
	}
	return req
}

// runVia performs the diagnosis on another machine and presents it here.
//
// Nothing about the answer is re-derived locally. The report and the snapshot
// that come back were built and interpreted on the machine that ran the
// probes, which is the only machine that can interpret them: the remediation
// for a finding is chosen by operating system, and a Windows laptop's advice is
// not this Linux box's to rewrite. What is decided here is what a local run
// decides for itself, which is how the answer is presented and what the process
// exits with.
//
// Exit code is the ordinary contract, and deliberately: a remote network that
// fails a check is exit 1, exactly as a local one is, while a connection that
// never delivered a diagnosis is exit 2, the environment-is-wrong code. Those
// two must not be confusable, because "the network you asked about is broken"
// and "I could not reach the machine to ask" are opposite conclusions.
func runVia(parent context.Context, h headless, stdout, stderr io.Writer) int {
	// The same interruption path a headless run uses. Cancelling kills the ssh
	// process, which drops the channel, which is the EOF the remote worker
	// stops on, so a Ctrl-C here does not leave probes running over there.
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	resp, err := remoteRun(ctx, h.via, h.viaCommand, requestForRemote(h))
	if err != nil {
		fmt.Fprintln(stderr, "netdoc: -via:", err)
		// An interrupted run is exit 1, the code quitting before the chain
		// finished already spends locally. Only a transport that failed on its
		// own is the environment-is-wrong 2, and the difference is whether this
		// process was the one that stopped it.
		if ctx.Err() != nil {
			return 1
		}
		return 2
	}
	// Provenance on stderr, never stdout: with -json, stdout stays the report
	// and nothing else, byte for byte what a local run leaves in a pipe.
	fmt.Fprintf(stderr, "Diagnosed on %s by netdoc %s (%s/%s)\n", textsafe.Clean(h.via),
		textsafe.Clean(resp.Tool.Version), textsafe.Clean(resp.Tool.OS), textsafe.Clean(resp.Tool.Arch))

	rep := *resp.Report
	switch {
	case h.json:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return 1
		}
	case h.save == "":
		// The one presentation --via adds. A local run with neither -json nor
		// an artifact has the TUI; a remote one has no live run to draw, so the
		// finished report is written out instead. A run asked for an artifact
		// stays silent on stdout, the same as a local -save does.
		fmt.Fprint(stdout, reportText(rep))
	}
	if h.save != "" {
		if err := saveSnapshot(h, *resp.Snapshot); err != nil {
			flagName := "-save"
			if h.support {
				flagName = "-support"
			}
			fmt.Fprintln(stderr, "netdoc:", flagName+":", textsafe.Clean(err.Error()))
			return 2
		}
		if h.support {
			fmt.Fprintf(stderr, "Sanitized support snapshot written to %q\n", textsafe.Clean(h.save))
		}
	}
	if rep.OK {
		return 0
	}
	return 1
}

// runRemoteWorker is the other end of --via, running on the machine being
// diagnosed. It reads one request, runs it, and writes one response.
//
// Its exit status is about the protocol and not about the network: a completed
// exchange is 0 even when every check failed, because the diagnosis travels
// inside the response and the local side spends the exit code for it. ssh
// hands the remote status back to the local process, and a worker that failed
// the exchange for a bad connection would be indistinguishable from one that
// answered "this network is broken".
func runRemoteWorker(parent context.Context, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	tool := snapshot.Tool{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH}
	if err := remote.Serve(ctx, workerStdin, stdout, tool, diagnoseRemote); err != nil {
		// The response never landed, so there is nothing structured to say it
		// with. stderr is all that is left, and ssh delivers it to the caller.
		fmt.Fprintln(stderr, "netdoc:", textsafe.Clean(err.Error()))
		return 1
	}
	return 0
}

// diagnoseRemote turns one remote request into the same headless run netdoc
// performs for itself, using the same parsers, the same probe graph, and the
// same report and snapshot builders. There is no remote-only diagnosis path,
// and that is the point: --via cannot drift from a local run, because there is
// nothing for it to drift from.
//
// Every field of the request is untrusted text that arrived over a pipe, so
// every field goes through the validation the CLI applies to the same flag.
// A rejection is returned rather than printed: the local side is the one with a
// terminal, and it prints what comes back.
func diagnoseRemote(ctx context.Context, req remote.Request) (*report.Report, *snapshot.Snapshot, error) {
	h := headless{
		iface:     req.Iface,
		publicDNS: req.PublicDNS,
		// Absent from a netdoc that predates the automatic default, and absent
		// means false: an old local side named this resolver as far as it knew,
		// and reinterpreting its request would answer a question it never asked.
		publicDNSAuto: req.PublicDNSAuto,
		timeout:       time.Duration(req.TimeoutMs) * time.Millisecond,
	}
	if h.timeout <= 0 {
		return nil, nil, errors.New("-timeout must be positive")
	}
	if req.Target != "" {
		t, err := diagnostic.ParseTarget(req.Target)
		if err != nil {
			return nil, nil, err
		}
		h.target = t
	}
	// Validated exactly as the local flag is: an address or empty, which is
	// what every protocol 1 netdoc has ever put in this field. Whether the
	// caller named it is the separate bit above, and it is the far end that
	// turns that into candidates, so a dual-stack caller cannot pin this
	// machine to a family it does not have.
	if req.PublicDNS != "" {
		ip := net.ParseIP(req.PublicDNS)
		if ip == nil {
			return nil, nil, fmt.Errorf("-public-dns: %q is not an IP address", textsafe.Clean(req.PublicDNS))
		}
		// Canonicalized here for the same reason a local run canonicalizes it,
		// and it has to be the same reason: the row label has to match the
		// probe, and the snapshot records this text for a later comparison to
		// read. A remote run that kept the user's spelling would differ from a
		// local one over a setting neither of them changed.
		h.publicDNS = ip.String()
	}
	for _, list := range []struct {
		dst *probeList
		ids []string
	}{{&h.check, req.Check}, {&h.skip, req.Skip}} {
		for _, id := range list.ids {
			if err := list.dst.Set(id); err != nil {
				return nil, nil, err
			}
		}
	}
	h.selection = diagnostic.ProbeSelection{Check: h.check.set(), Skip: h.skip.set()}
	if err := h.selection.Validate(); err != nil {
		return nil, nil, err
	}
	// Resolved here and nowhere else: -iface names an interface on this
	// machine, and this is the machine the probes run on.
	if req.Iface != "" {
		sources, err := diagnostic.ResolveSource(req.Iface)
		if err != nil {
			return nil, nil, fmt.Errorf("-iface: %s", textsafe.Clean(err.Error()))
		}
		h.sources = sources
	}

	probes := h.selection.Apply(diagnostic.BuildProbesFromSources(h.target, h.sources, h.publicDNS, h.publicDNSAuto))
	results := runAll(ctx, probes, h.timeout)
	if ctx.Err() != nil {
		// Cancelled mid-pass, which for a worker means the local side went
		// away. Every probe failed because we stopped it, so reporting that
		// pass would be a lie, the same judgement a local interrupted run makes.
		return nil, nil, errors.New("the run was interrupted before it finished")
	}
	rep := buildReport(h.target, probes, results)
	s := buildSnapshotArtifact(h, probes, results)
	return &rep, &s, nil
}
