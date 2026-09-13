// Package remote runs one Network Doctor diagnosis on another machine over the
// user's own OpenSSH client, and defines the wire contract the two netdoc
// processes speak while doing it.
//
// The split is deliberate. The remote side runs the diagnosis and interprets
// it, because a diagnosis reads differently per platform: the remediation for
// a finding is chosen by operating system, and only the machine the probes ran
// on can choose it correctly. The local side transports, presents, and decides
// the exit code, because that is what a local run does with its own results.
// Nothing here re-implements a probe, a diagnosis, or a report.
//
// What crosses the wire is the two artifacts netdoc already publishes: the
// --json report and the .ndoc snapshot. Both are versioned external contracts
// in their own right, so the SSH protocol is not a third schema tracking the
// probe structs. This envelope adds only what neither of them says: which
// protocol is being spoken, which build answered, and whether the remote could
// run at all.
package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// Protocol is the version of the request/response exchange in this file.
//
// It moves for a change an existing peer would misread, the same rule the
// snapshot schema follows. Adding an optional field is not that; neither side
// rejects unknown keys. What never moves, at any version, is the envelope's
// own protocol and error fields: a netdoc that cannot speak version N still
// has to be able to say so in a way version N understands, which is only true
// if those two keys mean the same thing forever.
const Protocol = 1

// WorkerFlag is the argument that puts netdoc in worker mode on the remote
// machine. It is deliberately the entire remote command line: no target, no
// timeout, no user text of any kind is spelled into the string SSH hands to
// the remote shell, so no remote quoting rule (POSIX, cmd.exe, PowerShell) can
// be got wrong. Everything the run needs travels as JSON on stdin instead.
const WorkerFlag = "--remote-worker"

// DefaultCommand is the remote program name, resolved on the remote PATH by
// the remote shell. CommandEnv overrides it for an installation that is not on
// the PATH of a non-interactive SSH session.
const DefaultCommand = "netdoc"

// CommandEnv names the local environment variable that overrides
// DefaultCommand. It is read on the machine that runs --via, never sent
// anywhere: it decides which program SSH is asked to start.
const CommandEnv = "NETDOC_VIA_COMMAND"

// Size limits. Both sides are talking to a process they did not start on a
// machine they do not control, so neither reads until it runs out of memory.
// The request is a handful of short strings; the response is one run's report
// and snapshot, which is tens of kilobytes for a real diagnosis.
const (
	MaxRequestBytes  = 64 << 10
	MaxResponseBytes = 8 << 20
)

// Request is what the local netdoc asks the remote one to do. Every field is
// the user's own spelling, unparsed: the remote validates it with the same
// parsers a local run uses, so --via cannot accept a target the machine that
// probes it would reject. Iface especially: it names an interface on the
// remote machine, which the local one has no way to resolve.
type Request struct {
	Protocol int `json:"protocol"`
	// Target is empty for a generic run, the same absence a local netdoc means
	// when it is given no positional argument.
	Target string `json:"target,omitempty"`
	Iface  string `json:"iface,omitempty"`
	// PublicDNS carries no omitempty: empty is a deliberate opt-out from the
	// second-opinion resolver, and it must not read as "unset, use the
	// default" on the far side. It is an address or empty, which is all any
	// protocol 1 netdoc has ever accepted here.
	PublicDNS string `json:"public_dns"`
	// PublicDNSAuto says nobody named that resolver, so the remote may cross to
	// the other address family when it cannot be reached. Additive and omitted
	// when false, which is what keeps both mixed pairs working on protocol 1: a
	// remote too old to know the field ignores it and does what it has always
	// done with the address beside it, and a local side that never sends it is
	// read here as the exact resolver an old netdoc meant. Neither is a
	// protocol break, so the version does not move; bumping it would refuse
	// every mixed pair over a setting neither side changed.
	PublicDNSAuto bool     `json:"public_dns_auto,omitempty"`
	TimeoutMs     int64    `json:"timeout_ms"`
	Check         []string `json:"check,omitempty"`
	Skip          []string `json:"skip,omitempty"`
}

// Response is one finished exchange. A response that carries a report and a
// snapshot is a diagnosis, whatever that diagnosis concluded: a remote network
// that is broken is a successful exchange, and the local side spends the
// ordinary failed-check exit code for it. Error is the other outcome, the one
// where the remote netdoc could not run the request at all.
type Response struct {
	Protocol int `json:"protocol"`
	// Tool is the remote build. It is repeated outside the snapshot because an
	// Error response has no snapshot to carry it, and naming the version that
	// refused is most of what makes a version error actionable.
	Tool     snapshot.Tool      `json:"tool"`
	Report   *report.Report     `json:"report,omitempty"`
	Snapshot *snapshot.Snapshot `json:"snapshot,omitempty"`
	// Error is a finished sentence from the remote netdoc, present only when
	// no diagnosis was produced.
	Error string `json:"error,omitempty"`
}

// Diagnose runs one request on the machine the worker is running on. It is
// supplied by the caller rather than implemented here so that this package
// stays a protocol and a transport: the orchestration it calls into is the
// same one an ordinary headless run uses, not a second copy of it.
//
// A returned error means the request could not be run, which is a bad request
// or an environment the probes cannot start in, never a failed check.
type Diagnose func(context.Context, Request) (*report.Report, *snapshot.Snapshot, error)

// Serve is the remote worker: it reads one request from in, runs it, and
// writes exactly one response to out.
//
// out is the protocol channel and carries one JSON object and nothing else,
// which is why this function, and not its caller, owns every byte written
// there. Anything that wants to say something to a human says it on stderr.
//
// The returned error is a failure to speak the protocol at all, a broken pipe
// on the way out. A request this build cannot honor is not that: it is a
// response with Error set, because the local side can print that and the local
// side cannot print a remote process's return value.
func Serve(ctx context.Context, in io.Reader, out io.Writer, tool snapshot.Tool, diagnose Diagnose) error {
	resp := Response{Protocol: Protocol, Tool: tool}
	var req Request
	// LimitReader, not a read of everything available: the request is small
	// and known, and a peer that streams forever must not be able to grow this
	// process instead of being refused.
	switch err := json.NewDecoder(io.LimitReader(in, MaxRequestBytes)).Decode(&req); {
	case err != nil:
		resp.Error = "could not read the remote request: " + clean(err.Error())
	case req.Protocol != Protocol:
		resp.Error = fmt.Sprintf("this netdoc speaks remote protocol %d, not %d", Protocol, req.Protocol)
	default:
		ctx, stop := context.WithCancel(ctx)
		defer stop()
		// The rest of stdin is the local side's liveness signal, not data. It
		// reaches EOF when the SSH channel is torn down, which is what a
		// cancelled or killed local netdoc leaves behind, and cancelling on it
		// is what keeps a probe run from outliving the session that asked for
		// it. A local side that is still there simply never closes it.
		go func() {
			_, _ = io.Copy(io.Discard, in)
			stop()
		}()
		rep, snap, err := diagnose(ctx, req)
		switch {
		case err != nil:
			resp.Error = clean(err.Error())
		case rep == nil || snap == nil:
			resp.Error = "the remote run produced no diagnosis"
		default:
			resp.Report, resp.Snapshot = rep, snap
		}
	}
	// SetEscapeHTML stays on (the default): the local decoder is encoding/json
	// either way, and turning it off would only widen what a hostile detail
	// string looks like in transit.
	return json.NewEncoder(out).Encode(resp)
}

// ErrNoResponse is what the local side gets when the remote produced no
// protocol output at all, which is the shape of a netdoc that is not installed
// and of one too old to know the worker flag.
var ErrNoResponse = errors.New("no response")

// decodeResponse reads the one JSON object the worker writes, and refuses
// anything else. Trailing bytes are a protocol violation and not ignored: a
// second object, or prose after the first one, means the stream was not what
// this build thinks it was talking to.
func decodeResponse(r io.Reader) (Response, error) {
	// One byte of headroom over the cap, so a response of exactly the limit is
	// accepted and the one past it is detectably truncated rather than
	// silently short.
	dec := json.NewDecoder(io.LimitReader(r, MaxResponseBytes+1))
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		if errors.Is(err, io.EOF) {
			return Response{}, ErrNoResponse
		}
		return Response{}, fmt.Errorf("could not read the remote response: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return Response{}, errors.New("the remote sent more than one response")
	}
	if resp.Protocol != Protocol {
		return Response{}, unsupportedProtocol(resp)
	}
	if resp.Error == "" {
		if resp.Report == nil || resp.Snapshot == nil {
			return Response{}, errors.New("the remote response carried no diagnosis and no error")
		}
		// Both artifacts are about to be spent separately by the caller, one
		// for what it prints and exits with and one for what it stores, so
		// this is the last point at which anything can still ask whether they
		// are two readings of one run.
		if err := agree(resp.Tool, *resp.Report, *resp.Snapshot); err != nil {
			return Response{}, err
		}
	}
	return resp, nil
}

// unsupportedProtocol words the version mismatch with both builds named, since
// "upgrade" is only actionable once the reader knows which end is behind.
func unsupportedProtocol(resp Response) error {
	remoteVersion := "unknown"
	if v := clean(resp.Tool.Version); v != "" {
		remoteVersion = v
	}
	return errors.New(strings.Join([]string{
		fmt.Sprintf("the remote netdoc speaks remote protocol %d, not %d", resp.Protocol, Protocol),
		"  remote netdoc: " + remoteVersion,
		fmt.Sprintf("  local netdoc:  speaks protocol %d", Protocol),
		"Upgrade whichever end is older so both speak the same protocol.",
	}, "\n"))
}

// clean makes external text safe to print on a terminal. Clean is single-line
// by contract, so a multi-line message is cleaned line by line rather than
// collapsed into one.
func clean(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = textsafe.Clean(line)
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// IsWorkerFlag reports whether arg selects worker mode. Both spellings are
// accepted because Go's flag package treats them as one flag everywhere else
// in netdoc, and a mode that answered to only one of them would be a trap for
// anyone who reaches for it by hand.
func IsWorkerFlag(arg string) bool {
	return arg == WorkerFlag || arg == strings.TrimPrefix(WorkerFlag, "-")
}
